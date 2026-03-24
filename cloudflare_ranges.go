package traefik_cloudflare_plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Overridable in tests.
var cloudflareIPsAPIURL = "https://api.cloudflare.com/client/v4/ips"

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

func fetchCloudflareCIDRs(ctx context.Context, httpClient *http.Client) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cloudflareIPsAPIURL, nil)
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
	return out, nil
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
