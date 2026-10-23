package traefik_cloudflare_plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Overridable in tests.
var cloudflareIPsAPIURL = "https://api.cloudflare.com/client/v4/ips"

// Overridable in tests.
var timeNow = time.Now

// cloudflareRangesCacheTTL is how long a fetched list is reused across New calls.
const cloudflareRangesCacheTTL = time.Hour

// cloudflareRangesRetryInterval is how long a failed fetch is remembered before the API is tried again.
const cloudflareRangesRetryInterval = time.Minute

// embeddedCloudflareCIDRs is a snapshot of Cloudflare’s published ranges (fallback when fetch fails).
// Operators can merge fresh ranges via trustedProxyRanges or enable fetch at runtime.
var embeddedCloudflareCIDRs = []string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
}

type cfIPsAPIResponse struct {
	Result struct {
		IPv4CIDRs []string `json:"ipv4_cidrs"`
		IPv6CIDRs []string `json:"ipv6_cidrs"`
	} `json:"result"`
	Success bool `json:"success"`
}

type cloudflareRangesCacheEntry struct {
	cidrs     []string
	fetchedAt time.Time
	err       error
	failedAt  time.Time
}

var (
	cloudflareRangesMu    sync.Mutex
	cloudflareRangesCache = map[string]cloudflareRangesCacheEntry{}
)

// newCloudflareHTTPClient returns a client for the Cloudflare IPs API that does not follow redirects.
func newCloudflareHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// loadCloudflareCIDRs returns Cloudflare's ranges, reusing a list fetched from the same URL within
// cloudflareRangesCacheTTL. When a refresh fails, the last good list for that URL is returned, and the
// API is not tried again for cloudflareRangesRetryInterval.
func loadCloudflareCIDRs(ctx context.Context, httpClient *http.Client) ([]string, error) {
	url := cloudflareIPsAPIURL

	cloudflareRangesMu.Lock()
	defer cloudflareRangesMu.Unlock()

	entry := cloudflareRangesCache[url]
	hasList := len(entry.cidrs) > 0
	now := timeNow()
	if hasList && now.Sub(entry.fetchedAt) < cloudflareRangesCacheTTL {
		return copyStrings(entry.cidrs), nil
	}
	if entry.err != nil && now.Sub(entry.failedAt) < cloudflareRangesRetryInterval {
		if hasList {
			return copyStrings(entry.cidrs), nil
		}
		return nil, entry.err
	}

	fetched, err := fetchCloudflareCIDRs(ctx, httpClient, url)
	if err != nil {
		entry.err = err
		entry.failedAt = now
		cloudflareRangesCache[url] = entry
		if hasList {
			warnOnce("staleCloudflareRanges:"+url,
				"traefik_cloudflare_plugin: cloudflare ranges refresh failed, using list fetched at %s: %v",
				entry.fetchedAt.Format(time.RFC3339), err)
			return copyStrings(entry.cidrs), nil
		}
		return nil, err
	}
	cloudflareRangesCache[url] = cloudflareRangesCacheEntry{cidrs: copyStrings(fetched), fetchedAt: timeNow()}
	return fetched, nil
}

func fetchCloudflareCIDRs(ctx context.Context, httpClient *http.Client, url string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cloudflare ips api: status %d", resp.StatusCode)
	}
	var parsed cfIPsAPIResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("cloudflare ips api json: %w", err)
	}
	if !parsed.Success {
		return nil, fmt.Errorf("cloudflare ips api: success=false")
	}
	out := append(append([]string{}, parsed.Result.IPv4CIDRs...), parsed.Result.IPv6CIDRs...)
	if len(out) == 0 {
		return nil, fmt.Errorf("cloudflare ips api: empty cidrs")
	}
	if err := validateCloudflareCIDRs(out); err != nil {
		return nil, err
	}
	return out, nil
}

// validateCloudflareCIDRs requires every entry to be a CIDR no wider than an IPv4 /8 or an IPv6 /16.
func validateCloudflareCIDRs(cidrs []string) error {
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(strings.TrimSpace(c))
		if err != nil {
			return fmt.Errorf("cloudflare ips api: invalid cidr %q: %w", c, err)
		}
		if isBroadCIDR(n) {
			return fmt.Errorf("cloudflare ips api: cidr %q is too broad", c)
		}
	}
	return nil
}

func copyStrings(in []string) []string {
	return append([]string(nil), in...)
}

func mergeUniqueCIDRStrings(parts ...[]string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, p := range parts {
		for _, s := range p {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

func defaultHTTPTimeout(d string) (time.Duration, error) {
	if strings.TrimSpace(d) == "" {
		return 5 * time.Second, nil
	}
	return time.ParseDuration(d)
}
