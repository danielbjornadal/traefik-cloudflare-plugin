package traefik_cloudflare_plugin

import (
	"net/http"
	"testing"
)

// TestCompat_legitimateTraffic checks that legitimate topologies resolve to the same client with the
// default resolution and with legacyClientIPResolution (the v1.1.0 behavior).
func TestCompat_legitimateTraffic(t *testing.T) {
	var hits, failing int32
	srv := newCloudflareAPIServer(t, cloudflareAPIBody(t, embeddedCloudflareCIDRs), &hits, &failing)
	useCloudflareAPI(t, srv.URL)

	v102Static := &Config{
		TrustedProxyRanges: append([]string{}, embeddedCloudflareCIDRs...),
		DirectRanges:       []string{"0.0.0.0/0"},
		Header:             "X-Forwarded-For",
	}
	v110README := &Config{
		FetchCloudflareRanges:       true,
		CloudflareRangesHTTPTimeout: "5s",
		TrustedProxyRanges:          []string{"198.51.100.0/29"},
		DirectRanges:                []string{"0.0.0.0/0", "::/0"},
		Header:                      "X-Forwarded-For",
	}
	onlyLB := &Config{TrustedProxyRanges: []string{"198.51.100.0/29"}}
	cloudflareAndLB := &Config{TrustedProxyRanges: append([]string{"198.51.100.0/29"}, embeddedCloudflareCIDRs...)}
	preserve := &Config{
		TrustedProxyRanges:              append([]string{}, embeddedCloudflareCIDRs...),
		PreserveForwardedForWhenTrusted: true,
	}

	viaLB := http.Header{
		headerForwardedFor:   {"203.0.113.9, 162.158.1.1"},
		headerCFConnectingIP: {"203.0.113.9"},
	}
	viaL4LB := http.Header{
		headerForwardedFor:   {"203.0.113.9"},
		headerCFConnectingIP: {"203.0.113.9"},
	}

	tests := []struct {
		desc       string
		cfg        *Config
		remoteAddr string
		headers    http.Header
		want       map[string][]string
	}{
		{
			desc:       "v1.0.2 static list: Cloudflare peer",
			cfg:        v102Static,
			remoteAddr: "162.158.1.1:443",
			headers: http.Header{
				headerForwardedFor:   {"203.0.113.9"},
				headerCFConnectingIP: {"203.0.113.9"},
			},
			want: clientIs("203.0.113.9"),
		},
		{
			desc:       "v1.0.2 static list: Cloudflare IPv6 peer",
			cfg:        v102Static,
			remoteAddr: "[2606:4700::1]:443",
			headers:    http.Header{headerCFConnectingIP: {"2001:db8::9"}},
			want:       clientIs("2001:db8::9"),
		},
		{
			desc:       "v1.0.2 static list: direct client",
			cfg:        v102Static,
			remoteAddr: "203.0.113.9:5555",
			headers:    http.Header{headerForwardedFor: {"10.0.0.5"}},
			want:       clientIs("203.0.113.9"),
		},
		{
			desc:       "v1.1.0 README config: Cloudflare peer",
			cfg:        v110README,
			remoteAddr: "172.64.1.1:443",
			headers: http.Header{
				headerForwardedFor:   {"203.0.113.9"},
				headerCFConnectingIP: {"203.0.113.9"},
			},
			want: clientIs("203.0.113.9"),
		},
		{
			desc:       "v1.1.0 README config: direct client",
			cfg:        v110README,
			remoteAddr: "192.0.2.10:5555",
			headers:    http.Header{headerForwardedFor: {"10.0.0.5"}},
			want:       clientIs("192.0.2.10"),
		},
		{
			desc:       "v1.1.0 README config: Cloudflare -> LB -> Traefik",
			cfg:        v110README,
			remoteAddr: "198.51.100.2:443",
			headers:    viaLB,
			want:       clientIs("203.0.113.9"),
		},
		{
			desc:       "Cloudflare -> LB -> Traefik with only the LB listed",
			cfg:        onlyLB,
			remoteAddr: "198.51.100.2:443",
			headers:    viaLB,
			want:       clientIs("203.0.113.9"),
		},
		{
			desc:       "Cloudflare -> LB -> Traefik with Cloudflare and the LB listed",
			cfg:        cloudflareAndLB,
			remoteAddr: "198.51.100.2:443",
			headers:    viaLB,
			want:       clientIs("203.0.113.9"),
		},
		{
			desc:       "Cloudflare -> L4 LB (no XFF append) -> Traefik with only the LB listed",
			cfg:        onlyLB,
			remoteAddr: "198.51.100.2:443",
			headers:    viaL4LB,
			want:       clientIs("203.0.113.9"),
		},
		{
			desc:       "Cloudflare -> L4 LB (no XFF append) -> Traefik with Cloudflare and the LB listed",
			cfg:        cloudflareAndLB,
			remoteAddr: "198.51.100.2:443",
			headers:    viaL4LB,
			want:       clientIs("203.0.113.9"),
		},
		{
			desc:       "Cloudflare -> LB that strips X-Forwarded-For -> Traefik with only the LB listed",
			cfg:        onlyLB,
			remoteAddr: "198.51.100.2:443",
			headers:    http.Header{headerCFConnectingIP: {"203.0.113.9"}},
			want:       clientIs("203.0.113.9"),
		},
		{
			desc:       "Cloudflare -> LB that replaces X-Forwarded-For with a trusted hop -> Traefik with only the LB listed",
			cfg:        onlyLB,
			remoteAddr: "198.51.100.2:443",
			headers: http.Header{
				headerForwardedFor:   {"198.51.100.3"},
				headerCFConnectingIP: {"203.0.113.9"},
			},
			want: clientIs("203.0.113.9"),
		},
		{
			desc:       "Cloudflare -> Azure Application Gateway (XFF entry with port) -> Traefik",
			cfg:        onlyLB,
			remoteAddr: "198.51.100.2:443",
			headers: http.Header{
				headerForwardedFor:   {"203.0.113.9, 162.158.1.1:443"},
				headerCFConnectingIP: {"203.0.113.9"},
			},
			want: clientIs("203.0.113.9"),
		},
		{
			desc:       "preserveForwardedForWhenTrusted passes trusted headers through",
			cfg:        preserve,
			remoteAddr: "162.158.1.1:443",
			headers: http.Header{
				headerForwardedFor:   {"203.0.113.9, 10.0.0.1"},
				headerCFConnectingIP: {"203.0.113.9"},
			},
			want: map[string][]string{
				headerForwardedFor:   {"203.0.113.9, 10.0.0.1"},
				headerRealIP:         nil,
				headerCFConnectingIP: {"203.0.113.9"},
			},
		},
		{
			desc:       "preserveForwardedForWhenTrusted still normalizes untrusted peers",
			cfg:        preserve,
			remoteAddr: "203.0.113.9:5555",
			headers:    http.Header{headerForwardedFor: {"10.0.0.5"}},
			want:       clientIs("203.0.113.9"),
		},
	}

	modes := []struct {
		name   string
		legacy bool
	}{
		{"default", false},
		{"legacy", true},
	}
	for _, test := range tests {
		for _, mode := range modes {
			t.Run(test.desc+"/"+mode.name, func(t *testing.T) {
				cfg := *test.cfg
				cfg.LegacyClientIPResolution = mode.legacy
				got := serveRequest(t, &cfg, test.remoteAddr, test.headers)
				assertHeaders(t, got, test.want)
			})
		}
	}
}

// TestCompat_legacyResolution checks that legacyClientIPResolution reproduces the v1.1.0 results,
// including the spoofable ones.
func TestCompat_legacyResolution(t *testing.T) {
	cloudflareOnly := []string{"173.245.48.0/20"}
	cloudflareAndLB := []string{"173.245.48.0/20", "198.51.100.0/29"}
	spoofed := http.Header{
		headerForwardedFor:     {"10.0.0.5"},
		headerRealIP:           {"10.0.0.5"},
		headerCFConnectingIP:   {"10.0.0.5"},
		headerCFConnectingIPv6: {"2001:db8::5"},
		headerTrueClientIP:     {"10.0.0.5"},
		headerForwarded:        {"for=10.0.0.5"},
	}

	tests := []struct {
		desc       string
		cfg        *Config
		remoteAddr string
		headers    http.Header
		want       map[string][]string
	}{
		{
			desc:       "trusted proxy - normalizes to first XFF when no CF-Connecting-IP",
			cfg:        &Config{TrustedProxyRanges: cloudflareOnly, Header: "X-Forwarded-For"},
			remoteAddr: "173.245.48.1:12345",
			headers:    http.Header{headerForwardedFor: {"203.0.113.1, 192.0.2.1"}},
			want:       clientIs("203.0.113.1"),
		},
		{
			desc:       "trusted proxy - CF-Connecting-IP wins over XFF",
			cfg:        &Config{TrustedProxyRanges: cloudflareOnly, Header: "X-Forwarded-For"},
			remoteAddr: "173.245.48.1:12345",
			headers: http.Header{
				headerForwardedFor:   {"192.0.2.1, 192.0.2.2"},
				headerCFConnectingIP: {"203.0.113.50"},
			},
			want: clientIs("203.0.113.50"),
		},
		{
			desc: "trusted preserveForwardedForWhenTrusted leaves headers unchanged",
			cfg: &Config{
				TrustedProxyRanges:              cloudflareOnly,
				Header:                          "X-Forwarded-For",
				PreserveForwardedForWhenTrusted: true,
			},
			remoteAddr: "173.245.48.1:12345",
			headers:    http.Header{headerForwardedFor: {"203.0.113.1, 192.0.2.1"}},
			want: map[string][]string{
				headerForwardedFor: {"203.0.113.1, 192.0.2.1"},
				headerRealIP:       nil,
			},
		},
		{
			desc:       "untrusted proxy - override XFF",
			cfg:        &Config{TrustedProxyRanges: cloudflareOnly, Header: "X-Forwarded-For"},
			remoteAddr: "192.168.1.100:12345",
			headers:    http.Header{headerForwardedFor: {"10.0.0.1"}},
			want:       clientIs("192.168.1.100"),
		},
		{
			desc:       "untrusted proxy with empty XFF - set XFF",
			cfg:        &Config{TrustedProxyRanges: cloudflareOnly, Header: "X-Forwarded-For"},
			remoteAddr: "192.168.1.100:12345",
			headers:    http.Header{},
			want:       clientIs("192.168.1.100"),
		},
		{
			desc:       "custom legacy header also set when not XFF or Real-IP",
			cfg:        &Config{TrustedProxyRanges: cloudflareOnly, Header: "True-Client-IP"},
			remoteAddr: "192.168.1.100:12345",
			headers:    http.Header{headerTrueClientIP: {"10.0.0.1"}},
			want: map[string][]string{
				headerForwardedFor: {"192.168.1.100"},
				headerRealIP:       {"192.168.1.100"},
				headerTrueClientIP: {"192.168.1.100"},
			},
		},
		{
			desc:       "IPv6 trusted proxy normalizes from XFF",
			cfg:        &Config{TrustedProxyRanges: []string{"2400:cb00::/32"}, Header: "X-Forwarded-For"},
			remoteAddr: "[2400:cb00::1]:12345",
			headers:    http.Header{headerForwardedFor: {"192.168.1.100"}},
			want:       clientIs("192.168.1.100"),
		},
		{
			desc:       "IPv6 untrusted proxy",
			cfg:        &Config{TrustedProxyRanges: cloudflareOnly, Header: "X-Forwarded-For"},
			remoteAddr: "[2001:db8::1]:12345",
			headers:    http.Header{headerForwardedFor: {"10.0.0.1"}},
			want:       clientIs("2001:db8::1"),
		},
		{
			desc:       "single IP trusted proxy normalizes",
			cfg:        &Config{TrustedProxyRanges: []string{"173.245.48.1"}, Header: "X-Forwarded-For"},
			remoteAddr: "173.245.48.1:12345",
			headers:    http.Header{headerForwardedFor: {"192.168.1.100"}},
			want:       clientIs("192.168.1.100"),
		},
		{
			desc:       "empty trusted proxy ranges - treat all as untrusted",
			cfg:        &Config{TrustedProxyRanges: []string{}, Header: "X-Forwarded-For"},
			remoteAddr: "173.245.48.1:12345",
			headers:    http.Header{headerForwardedFor: {"192.168.1.100"}},
			want:       clientIs("173.245.48.1"),
		},
		{
			desc:       "trusted cannot resolve client - pass through",
			cfg:        &Config{TrustedProxyRanges: cloudflareOnly, Header: "X-Forwarded-For"},
			remoteAddr: "173.245.48.1:12345",
			headers:    http.Header{headerCFConnectingIP: {"not-an-ip"}},
			want: map[string][]string{
				headerForwardedFor:   nil,
				headerRealIP:         nil,
				headerCFConnectingIP: {"not-an-ip"},
			},
		},
		{
			desc:       "spoofable: CF-Connecting-IP from a non-Cloudflare trusted peer",
			cfg:        &Config{TrustedProxyRanges: cloudflareAndLB},
			remoteAddr: "198.51.100.2:443",
			headers: http.Header{
				headerCFConnectingIP: {"10.0.0.5"},
				headerForwardedFor:   {"203.0.113.9"},
			},
			want: map[string][]string{
				headerForwardedFor:   {"10.0.0.5"},
				headerRealIP:         {"10.0.0.5"},
				headerCFConnectingIP: {"10.0.0.5"},
			},
		},
		{
			desc:       "spoofable: leftmost XFF entry from a trusted LB",
			cfg:        &Config{TrustedProxyRanges: cloudflareAndLB},
			remoteAddr: "198.51.100.2:443",
			headers:    http.Header{headerForwardedFor: {"10.0.0.5, 203.0.113.9"}},
			want:       clientIs("10.0.0.5"),
		},
		{
			desc:       "spoofable: leftmost XFF entry from a Cloudflare peer",
			cfg:        &Config{TrustedProxyRanges: cloudflareAndLB},
			remoteAddr: "173.245.48.10:443",
			headers:    http.Header{headerForwardedFor: {"10.0.0.5,203.0.113.9"}},
			want:       clientIs("10.0.0.5"),
		},
		{
			desc:       "spoofable: only the first XFF header line is read",
			cfg:        &Config{TrustedProxyRanges: cloudflareAndLB},
			remoteAddr: "198.51.100.2:443",
			headers:    http.Header{headerForwardedFor: {"10.0.0.5", "203.0.113.9"}},
			want:       clientIs("10.0.0.5"),
		},
		{
			desc:       "spoofable: untrusted peer passes Cloudflare and Forwarded headers",
			cfg:        &Config{TrustedProxyRanges: cloudflareAndLB},
			remoteAddr: "203.0.113.9:5555",
			headers:    spoofed,
			want: map[string][]string{
				headerForwardedFor:     {"203.0.113.9"},
				headerRealIP:           {"203.0.113.9"},
				headerCFConnectingIP:   {"10.0.0.5"},
				headerCFConnectingIPv6: {"2001:db8::5"},
				headerTrueClientIP:     {"10.0.0.5"},
				headerForwarded:        {"for=10.0.0.5"},
			},
		},
		{
			desc:       "spoofable: trusted LB with unparseable XFF passes headers through",
			cfg:        &Config{TrustedProxyRanges: cloudflareAndLB},
			remoteAddr: "198.51.100.2:443",
			headers: http.Header{
				headerRealIP:       {"10.0.0.5"},
				headerForwardedFor: {"unknown"},
			},
			want: map[string][]string{
				headerForwardedFor: {"unknown"},
				headerRealIP:       {"10.0.0.5"},
			},
		},
		{
			desc:       "spoofable: unparseable RemoteAddr passes every header through",
			cfg:        &Config{TrustedProxyRanges: cloudflareAndLB},
			remoteAddr: "[fe80::1%eth0]:5555",
			headers:    spoofed,
			want: map[string][]string{
				headerForwardedFor:     {"10.0.0.5"},
				headerRealIP:           {"10.0.0.5"},
				headerCFConnectingIP:   {"10.0.0.5"},
				headerCFConnectingIPv6: {"2001:db8::5"},
				headerTrueClientIP:     {"10.0.0.5"},
				headerForwarded:        {"for=10.0.0.5"},
			},
		},
		{
			desc:       "spoofable: allowedWorkerZones is not applied",
			cfg:        &Config{TrustedProxyRanges: cloudflareAndLB, AllowedWorkerZones: []string{"example.com"}},
			remoteAddr: "173.245.48.10:443",
			headers: http.Header{
				headerCFWorker:       {"attacker.net"},
				headerCFConnectingIP: {"10.0.0.5"},
			},
			want: clientIs("10.0.0.5"),
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			cfg := *test.cfg
			cfg.LegacyClientIPResolution = true
			got := serveRequest(t, &cfg, test.remoteAddr, test.headers)
			assertHeaders(t, got, test.want)
		})
	}
}

func clientIs(ip string) map[string][]string {
	return map[string][]string{
		headerForwardedFor: {ip},
		headerRealIP:       {ip},
	}
}
