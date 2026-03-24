package traefik_cloudflare_plugin

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
)

const (
	headerForwardedFor   = "X-Forwarded-For"
	headerRealIP         = "X-Real-IP"
	headerCFConnectingIP = "CF-Connecting-IP"
)

// Config holds the plugin configuration.
//
// trustedProxyRanges – CIDR blocks trusted to set forwarded client headers (e.g. Cloudflare, your LB).
// fetchCloudflareRanges – if true, merge Cloudflare’s public IP ranges from the Cloudflare API at startup.
// cloudflareRangesHTTPTimeout – HTTP client timeout for that fetch (e.g. "5s"); default 5s.
// cloudflareRangesFetchRequired – if true with fetchCloudflareRanges, New fails when the fetch fails.
// preserveForwardedForWhenTrusted – if true, v1 behavior: do not rewrite headers when the peer is trusted.
// directRanges – parsed for forward compatibility (currently unused at runtime).
// header – legacy: when set to a header other than X-Forwarded-For / X-Real-IP, that header is also set when normalizing.
type Config struct {
	TrustedProxyRanges              []string `json:"trustedProxyRanges,omitempty" yaml:"trustedProxyRanges,omitempty"`
	FetchCloudflareRanges           bool     `json:"fetchCloudflareRanges,omitempty" yaml:"fetchCloudflareRanges,omitempty"`
	CloudflareRangesHTTPTimeout     string   `json:"cloudflareRangesHTTPTimeout,omitempty" yaml:"cloudflareRangesHTTPTimeout,omitempty"`
	CloudflareRangesFetchRequired   bool     `json:"cloudflareRangesFetchRequired,omitempty" yaml:"cloudflareRangesFetchRequired,omitempty"`
	PreserveForwardedForWhenTrusted bool     `json:"preserveForwardedForWhenTrusted,omitempty" yaml:"preserveForwardedForWhenTrusted,omitempty"`
	DirectRanges                    []string `json:"directRanges,omitempty" yaml:"directRanges,omitempty"`
	Header                          string   `json:"header,omitempty" yaml:"header,omitempty"`
}

// CreateConfig provides the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Header: headerForwardedFor,
	}
}

type middleware struct {
	next                            http.Handler
	header                          string
	trustedProxies                  []*net.IPNet
	directRanges                    []*net.IPNet
	preserveForwardedForWhenTrusted bool
}

// New is called by Traefik during the initialization of the middleware.
func New(ctx context.Context, next http.Handler, cfg *Config, _ string) (http.Handler, error) {
	m := &middleware{
		next:                            next,
		header:                          defaultHeader(cfg.Header),
		preserveForwardedForWhenTrusted: cfg.PreserveForwardedForWhenTrusted,
	}

	timeout, err := defaultHTTPTimeout(cfg.CloudflareRangesHTTPTimeout)
	if err != nil {
		return nil, fmt.Errorf("invalid cloudflareRangesHTTPTimeout: %w", err)
	}

	var cidrStrings []string
	cidrStrings = append(cidrStrings, cfg.TrustedProxyRanges...)

	if cfg.FetchCloudflareRanges {
		client := &http.Client{Timeout: timeout}
		fetched, fetchErr := fetchCloudflareCIDRs(ctx, client)
		if fetchErr != nil {
			if cfg.CloudflareRangesFetchRequired {
				return nil, fmt.Errorf("cloudflare ranges fetch: %w", fetchErr)
			}
			log.Printf("traefik_cloudflare_plugin: cloudflare ranges fetch failed, using embedded snapshot: %v", fetchErr)
			cidrStrings = mergeUniqueCIDRStrings(cidrStrings, embeddedCloudflareCIDRs)
		} else {
			cidrStrings = mergeUniqueCIDRStrings(cidrStrings, fetched)
		}
	}

	if m.trustedProxies, err = parseCIDRs(cidrStrings); err != nil {
		return nil, fmt.Errorf("invalid trusted proxy CIDRs: %w", err)
	}
	if m.directRanges, err = parseCIDRs(cfg.DirectRanges); err != nil {
		return nil, fmt.Errorf("invalid directRanges: %w", err)
	}
	if len(m.directRanges) == 0 {
		if m.directRanges, err = parseCIDRs([]string{"0.0.0.0/0", "::/0"}); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// ServeHTTP implements the http.Handler interface.
func (m *middleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	remoteIP := clientIP(req.RemoteAddr)

	if m.isTrustedProxy(remoteIP) {
		if m.preserveForwardedForWhenTrusted {
			m.next.ServeHTTP(rw, req)
			return
		}
		client := m.resolveTrustedClientIP(req)
		if client == "" {
			m.next.ServeHTTP(rw, req)
			return
		}
		m.applyNormalizedClientIP(req, client)
		m.next.ServeHTTP(rw, req)
		return
	}

	// Untrusted peer: spoof-safe client is the TCP remote address.
	if remoteIP == nil {
		m.next.ServeHTTP(rw, req)
		return
	}
	client := remoteIP.String()
	m.applyNormalizedClientIP(req, client)
	m.next.ServeHTTP(rw, req)
}

func (m *middleware) resolveTrustedClientIP(req *http.Request) string {
	if v := strings.TrimSpace(req.Header.Get(headerCFConnectingIP)); v != "" {
		if ip := net.ParseIP(v); ip != nil {
			return ip.String()
		}
	}
	if v := strings.TrimSpace(req.Header.Get(headerForwardedFor)); v != "" {
		if ip := firstForwardedForIP(v); ip != nil {
			return ip.String()
		}
	}
	return ""
}

func firstForwardedForIP(xff string) net.IP {
	for _, part := range strings.Split(xff, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if ip := net.ParseIP(part); ip != nil {
			return ip
		}
	}
	return nil
}

func (m *middleware) applyNormalizedClientIP(req *http.Request, client string) {
	req.Header.Set(headerForwardedFor, client)
	req.Header.Set(headerRealIP, client)
	if m.header != "" &&
		!strings.EqualFold(m.header, headerForwardedFor) &&
		!strings.EqualFold(m.header, headerRealIP) {
		req.Header.Set(m.header, client)
	}
}

// ----------------------------------------------------------------------------
// Helper functions
// ----------------------------------------------------------------------------

func defaultHeader(h string) string {
	if strings.TrimSpace(h) == "" {
		return headerForwardedFor
	}
	return h
}

func parseCIDRs(raw []string) ([]*net.IPNet, error) {
	var list []*net.IPNet
	for _, cidr := range raw {
		// Allow single IPs as well as CIDRs.
		if ip := net.ParseIP(cidr); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			mask := net.CIDRMask(bits, bits)
			list = append(list, &net.IPNet{IP: ip, Mask: mask})
			continue
		}
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", cidr, err)
		}
		list = append(list, n)
	}
	return list, nil
}

func clientIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	return net.ParseIP(host)
}

func (m *middleware) isTrustedProxy(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range m.trustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
