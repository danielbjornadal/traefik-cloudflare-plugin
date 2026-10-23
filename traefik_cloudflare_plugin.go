package traefik_cloudflare_plugin

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
)

const (
	headerForwardedFor     = "X-Forwarded-For"
	headerRealIP           = "X-Real-IP"
	headerCFConnectingIP   = "CF-Connecting-IP"
	headerCFConnectingIPv6 = "CF-Connecting-IPv6"
	headerTrueClientIP     = "True-Client-IP"
	headerForwarded        = "Forwarded"
	headerCFWorker         = "CF-Worker"
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
// legacyClientIPResolution – if true, use the v1.1.0 resolution: CF-Connecting-IP from any trusted peer, else the
// leftmost X-Forwarded-For entry, and headers pass through when nothing resolves. Client IP headers can then be
// spoofed through trusted proxies.
// allowedWorkerZones – optional list of zones whose Cloudflare Workers may set CF-Connecting-IP. When set, a request
// from a Cloudflare IP carrying a CF-Worker header for any other zone resolves to that Cloudflare IP. Requests
// without CF-Worker are unaffected. Empty disables the check.
type Config struct {
	TrustedProxyRanges              []string `json:"trustedProxyRanges,omitempty" yaml:"trustedProxyRanges,omitempty"`
	FetchCloudflareRanges           bool     `json:"fetchCloudflareRanges,omitempty" yaml:"fetchCloudflareRanges,omitempty"`
	CloudflareRangesHTTPTimeout     string   `json:"cloudflareRangesHTTPTimeout,omitempty" yaml:"cloudflareRangesHTTPTimeout,omitempty"`
	CloudflareRangesFetchRequired   bool     `json:"cloudflareRangesFetchRequired,omitempty" yaml:"cloudflareRangesFetchRequired,omitempty"`
	PreserveForwardedForWhenTrusted bool     `json:"preserveForwardedForWhenTrusted,omitempty" yaml:"preserveForwardedForWhenTrusted,omitempty"`
	DirectRanges                    []string `json:"directRanges,omitempty" yaml:"directRanges,omitempty"`
	Header                          string   `json:"header,omitempty" yaml:"header,omitempty"`
	LegacyClientIPResolution        bool     `json:"legacyClientIPResolution,omitempty" yaml:"legacyClientIPResolution,omitempty"`
	AllowedWorkerZones              []string `json:"allowedWorkerZones,omitempty" yaml:"allowedWorkerZones,omitempty"`
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
	cloudflare                      []*net.IPNet
	directRanges                    []*net.IPNet
	preserveForwardedForWhenTrusted bool
	legacyClientIPResolution        bool
	allowedWorkerZones              []string
}

// New is called by Traefik during the initialization of the middleware.
func New(ctx context.Context, next http.Handler, cfg *Config, _ string) (http.Handler, error) {
	m := &middleware{
		next:                            next,
		header:                          defaultHeader(cfg.Header),
		preserveForwardedForWhenTrusted: cfg.PreserveForwardedForWhenTrusted,
		legacyClientIPResolution:        cfg.LegacyClientIPResolution,
		allowedWorkerZones:              normalizeWorkerZones(cfg.AllowedWorkerZones),
	}

	timeout, err := defaultHTTPTimeout(cfg.CloudflareRangesHTTPTimeout)
	if err != nil {
		return nil, fmt.Errorf("invalid cloudflareRangesHTTPTimeout: %w", err)
	}

	var cidrStrings []string
	cidrStrings = append(cidrStrings, cfg.TrustedProxyRanges...)

	cloudflareCIDRs := embeddedCloudflareCIDRs
	if cfg.FetchCloudflareRanges {
		client := newCloudflareHTTPClient(timeout)
		fetched, fetchErr := loadCloudflareCIDRs(ctx, client)
		if fetchErr != nil {
			if cfg.CloudflareRangesFetchRequired {
				return nil, fmt.Errorf("cloudflare ranges fetch: %w", fetchErr)
			}
			log.Printf("traefik_cloudflare_plugin: cloudflare ranges fetch failed, using embedded snapshot: %v", fetchErr)
			cidrStrings = mergeUniqueCIDRStrings(cidrStrings, embeddedCloudflareCIDRs)
		} else {
			cidrStrings = mergeUniqueCIDRStrings(cidrStrings, fetched)
			cloudflareCIDRs = fetched
		}
	}

	if m.trustedProxies, err = parseCIDRs(cidrStrings); err != nil {
		return nil, fmt.Errorf("invalid trusted proxy CIDRs: %w", err)
	}
	if m.cloudflare, err = parseCIDRs(mergeUniqueCIDRStrings(cloudflareCIDRs)); err != nil {
		return nil, fmt.Errorf("invalid cloudflare CIDRs: %w", err)
	}
	if m.directRanges, err = parseCIDRs(cfg.DirectRanges); err != nil {
		return nil, fmt.Errorf("invalid directRanges: %w", err)
	}
	if len(m.directRanges) == 0 {
		if m.directRanges, err = parseCIDRs([]string{"0.0.0.0/0", "::/0"}); err != nil {
			return nil, err
		}
	}
	m.warnRiskyConfig()
	return m, nil
}

func (m *middleware) warnRiskyConfig() {
	if m.legacyClientIPResolution {
		warnOnce("legacyClientIPResolution",
			"traefik_cloudflare_plugin: legacyClientIPResolution is enabled; client IP headers can be spoofed through trusted proxies")
	}
	if m.preserveForwardedForWhenTrusted {
		warnOnce("preserveForwardedForWhenTrusted",
			"traefik_cloudflare_plugin: preserveForwardedForWhenTrusted is enabled; client IP headers from trusted peers pass through unchecked")
	}
	for _, n := range m.trustedProxies {
		if isBroadCIDR(n) {
			warnOnce("broadTrustedRange:"+n.String(),
				"traefik_cloudflare_plugin: trusted proxy range %s is very broad; every client inside it can set client IP headers", n.String())
		}
	}
}

// ServeHTTP implements the http.Handler interface.
func (m *middleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if m.legacyClientIPResolution {
		m.serveLegacy(rw, req)
		return
	}

	peer := clientIP(req.RemoteAddr)
	if peer == nil {
		req.Header.Del(headerForwardedFor)
		req.Header.Del(headerRealIP)
		m.deleteClientIPHeaders(req)
		req.Header.Del(m.header)
		m.next.ServeHTTP(rw, req)
		return
	}

	if !m.isTrustedProxy(peer) {
		m.deleteClientIPHeaders(req)
		m.applyNormalizedClientIP(req, peer.String())
		m.next.ServeHTTP(rw, req)
		return
	}

	if m.preserveForwardedForWhenTrusted {
		m.next.ServeHTTP(rw, req)
		return
	}

	ip, viaCloudflare := m.resolveClientIP(req, peer)
	client := ip.String()
	req.Header.Set(headerForwardedFor, client)
	req.Header.Set(headerRealIP, client)
	if len(req.Header.Values(headerTrueClientIP)) > 0 {
		req.Header.Set(headerTrueClientIP, client)
	}
	if !viaCloudflare {
		if len(req.Header.Values(headerCFConnectingIP)) > 0 {
			req.Header.Set(headerCFConnectingIP, client)
		}
		req.Header.Del(headerCFConnectingIPv6)
	}
	m.setCustomHeader(req, client)
	m.next.ServeHTTP(rw, req)
}

// deleteClientIPHeaders removes client IP headers that only Cloudflare or a trusted proxy may set.
func (m *middleware) deleteClientIPHeaders(req *http.Request) {
	req.Header.Del(headerCFConnectingIP)
	req.Header.Del(headerCFConnectingIPv6)
	req.Header.Del(headerTrueClientIP)
	req.Header.Del(headerForwarded)
}

// resolveClientIP walks the hops from the trusted peer through X-Forwarded-For right to left and returns the
// first address that is not a trusted proxy. A Cloudflare hop hands over to CF-Connecting-IP when it is valid.
// When every hop is a trusted proxy, a valid CF-Connecting-IP set by those proxies is the client; otherwise the
// leftmost trusted hop is. The boolean reports whether the result came from CF-Connecting-IP.
func (m *middleware) resolveClientIP(req *http.Request, peer net.IP) (net.IP, bool) {
	hops := forwardedForEntries(req)
	last := peer
	for i := len(hops); i >= 0; i-- {
		ip := peer
		if i < len(hops) {
			ip = parseHopIP(hops[i])
			if ip == nil {
				return last, false
			}
		}
		if m.isCloudflare(ip) {
			if !m.workerAllowed(req) {
				return ip, false
			}
			if cf := net.ParseIP(strings.TrimSpace(req.Header.Get(headerCFConnectingIP))); cf != nil {
				return cf, true
			}
			last = ip
			continue
		}
		if m.isTrustedProxy(ip) {
			last = ip
			continue
		}
		return ip, false
	}
	if m.workerAllowed(req) {
		if cf := net.ParseIP(strings.TrimSpace(req.Header.Get(headerCFConnectingIP))); cf != nil {
			if len(hops) == 0 {
				warnOnce("trustedPeerWithoutForwardedFor",
					"traefik_cloudflare_plugin: trusted proxy %s sent CF-Connecting-IP without X-Forwarded-For; "+
						"add it to the entryPoint forwardedHeaders.trustedIPs and make it append X-Forwarded-For, "+
						"otherwise clients connecting through it can set CF-Connecting-IP", peer.String())
			}
			return cf, true
		}
	}
	return last, false
}

// forwardedForEntries returns the non-empty X-Forwarded-For entries across all header lines, in order.
func forwardedForEntries(req *http.Request) []string {
	var entries []string
	for _, part := range strings.Split(strings.Join(req.Header.Values(headerForwardedFor), ","), ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			entries = append(entries, part)
		}
	}
	return entries
}

// parseHopIP parses an X-Forwarded-For entry: a bare IPv4/IPv6 address, or one with a port
// ("192.0.2.1:5678", "[2001:db8::1]:443") as appended by some load balancers.
func parseHopIP(entry string) net.IP {
	if ip := net.ParseIP(entry); ip != nil {
		return ip
	}
	host, _, err := net.SplitHostPort(entry)
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

// workerAllowed reports whether a CF-Worker header, if any, names an allowed zone.
func (m *middleware) workerAllowed(req *http.Request) bool {
	if len(m.allowedWorkerZones) == 0 {
		return true
	}
	zone := strings.ToLower(strings.TrimSpace(req.Header.Get(headerCFWorker)))
	if zone == "" {
		return true
	}
	for _, allowed := range m.allowedWorkerZones {
		if zone == allowed {
			return true
		}
	}
	return false
}

func (m *middleware) serveLegacy(rw http.ResponseWriter, req *http.Request) {
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
	m.setCustomHeader(req, client)
}

func (m *middleware) setCustomHeader(req *http.Request, client string) {
	if m.header != "" &&
		!strings.EqualFold(m.header, headerForwardedFor) &&
		!strings.EqualFold(m.header, headerRealIP) {
		req.Header.Set(m.header, client)
	}
}

// ----------------------------------------------------------------------------
// Helper functions
// ----------------------------------------------------------------------------

var (
	warnedMu sync.Mutex
	warned   = map[string]bool{}
)

// warnOnce logs a message the first time key is seen in this process.
func warnOnce(key, format string, args ...interface{}) {
	warnedMu.Lock()
	defer warnedMu.Unlock()
	if warned[key] {
		return
	}
	warned[key] = true
	log.Printf(format, args...)
}

func defaultHeader(h string) string {
	if strings.TrimSpace(h) == "" {
		return headerForwardedFor
	}
	return h
}

func normalizeWorkerZones(zones []string) []string {
	var out []string
	for _, z := range zones {
		z = strings.ToLower(strings.TrimSpace(z))
		if z != "" {
			out = append(out, z)
		}
	}
	return out
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

// isBroadCIDR reports whether n is wider than an IPv4 /8 or an IPv6 /16.
func isBroadCIDR(n *net.IPNet) bool {
	ones, bits := n.Mask.Size()
	if bits == 8*net.IPv4len {
		return ones < 8
	}
	return ones < 16
}

func clientIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	return net.ParseIP(host)
}

func (m *middleware) isTrustedProxy(ip net.IP) bool {
	return containsIP(m.trustedProxies, ip)
}

func (m *middleware) isCloudflare(ip net.IP) bool {
	return containsIP(m.cloudflare, ip)
}

func containsIP(nets []*net.IPNet, ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
