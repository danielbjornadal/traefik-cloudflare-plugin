package traefik_cloudflare_plugin

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreateConfig(t *testing.T) {
	cfg := CreateConfig()
	if cfg == nil {
		t.Fatal("CreateConfig() returned nil")
	}
	if cfg.Header != "X-Forwarded-For" {
		t.Errorf("Expected default header 'X-Forwarded-For', got '%s'", cfg.Header)
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		desc    string
		cfg     *Config
		wantErr bool
	}{
		{
			desc: "valid config with trusted proxy ranges",
			cfg: &Config{
				TrustedProxyRanges: []string{"173.245.48.0/20", "103.21.244.0/22"},
				Header:             "X-Forwarded-For",
			},
			wantErr: false,
		},
		{
			desc: "valid config with custom header",
			cfg: &Config{
				TrustedProxyRanges: []string{"173.245.48.0/20"},
				Header:             "X-Real-IP",
			},
			wantErr: false,
		},
		{
			desc: "valid config with direct ranges",
			cfg: &Config{
				TrustedProxyRanges: []string{"173.245.48.0/20"},
				DirectRanges:       []string{"192.168.1.0/24"},
				Header:             "X-Forwarded-For",
			},
			wantErr: false,
		},
		{
			desc: "invalid trusted proxy range",
			cfg: &Config{
				TrustedProxyRanges: []string{"invalid-cidr"},
				Header:             "X-Forwarded-For",
			},
			wantErr: true,
		},
		{
			desc: "invalid direct range",
			cfg: &Config{
				TrustedProxyRanges: []string{"173.245.48.0/20"},
				DirectRanges:       []string{"invalid-cidr"},
				Header:             "X-Forwarded-For",
			},
			wantErr: true,
		},
		{
			desc:    "empty config (should use defaults)",
			cfg:     &Config{},
			wantErr: false,
		},
		{
			desc: "single IP as trusted proxy",
			cfg: &Config{
				TrustedProxyRanges: []string{"173.245.48.1"},
				Header:             "X-Forwarded-For",
			},
			wantErr: false,
		},
		{
			desc: "IPv6 trusted proxy range",
			cfg: &Config{
				TrustedProxyRanges: []string{"2400:cb00::/32"},
				Header:             "X-Forwarded-For",
			},
			wantErr: false,
		},
		{
			desc: "invalid cloudflareRangesHTTPTimeout",
			cfg: &Config{
				TrustedProxyRanges:          []string{"173.245.48.0/20"},
				CloudflareRangesHTTPTimeout: "not-a-duration",
			},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			handler, err := New(context.Background(), next, test.cfg, "test")

			if test.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
				if handler == nil {
					t.Error("Expected handler but got nil")
				}
			}
		})
	}
}

func TestMiddleware_ServeHTTP(t *testing.T) {
	tests := []struct {
		desc                string
		cfg                 *Config
		remoteAddr          string
		initialXFF          string
		initialRealIP       string
		cfConnectingIP      string
		expectedXFF         string
		expectedRealIP      string
		expectedStatus      int
		shouldPreserveXFF   bool
		spoofOnLegacyHeader string // set this header name to initialXFF when testing legacy spoof path
	}{
		{
			desc: "trusted proxy - normalizes to first XFF when no CF-Connecting-IP",
			cfg: &Config{
				TrustedProxyRanges: []string{"173.245.48.0/20"},
				Header:             "X-Forwarded-For",
			},
			remoteAddr:        "173.245.48.1:12345",
			initialXFF:        "203.0.113.1, 192.0.2.1",
			expectedXFF:       "203.0.113.1",
			expectedRealIP:    "203.0.113.1",
			expectedStatus:    http.StatusOK,
			shouldPreserveXFF: false,
		},
		{
			desc: "trusted proxy - CF-Connecting-IP wins over XFF",
			cfg: &Config{
				TrustedProxyRanges: []string{"173.245.48.0/20"},
				Header:             "X-Forwarded-For",
			},
			remoteAddr:        "173.245.48.1:12345",
			initialXFF:        "192.0.2.1, 192.0.2.2",
			cfConnectingIP:    "203.0.113.50",
			expectedXFF:       "203.0.113.50",
			expectedRealIP:    "203.0.113.50",
			expectedStatus:    http.StatusOK,
			shouldPreserveXFF: false,
		},
		{
			desc: "trusted preserveForwardedForWhenTrusted leaves headers unchanged",
			cfg: &Config{
				TrustedProxyRanges:              []string{"173.245.48.0/20"},
				Header:                          "X-Forwarded-For",
				PreserveForwardedForWhenTrusted: true,
			},
			remoteAddr:        "173.245.48.1:12345",
			initialXFF:        "203.0.113.1, 192.0.2.1",
			expectedXFF:       "203.0.113.1, 192.0.2.1",
			expectedRealIP:    "",
			expectedStatus:    http.StatusOK,
			shouldPreserveXFF: true,
		},
		{
			desc: "untrusted proxy - override XFF",
			cfg: &Config{
				TrustedProxyRanges: []string{"173.245.48.0/20"},
				Header:             "X-Forwarded-For",
			},
			remoteAddr:        "192.168.1.100:12345",
			initialXFF:        "10.0.0.1",
			expectedXFF:       "192.168.1.100",
			expectedRealIP:    "192.168.1.100",
			expectedStatus:    http.StatusOK,
			shouldPreserveXFF: false,
		},
		{
			desc: "untrusted proxy with empty XFF - set XFF",
			cfg: &Config{
				TrustedProxyRanges: []string{"173.245.48.0/20"},
				Header:             "X-Forwarded-For",
			},
			remoteAddr:        "192.168.1.100:12345",
			initialXFF:        "",
			expectedXFF:       "192.168.1.100",
			expectedRealIP:    "192.168.1.100",
			expectedStatus:    http.StatusOK,
			shouldPreserveXFF: false,
		},
		{
			desc: "custom legacy header also set when not XFF or Real-IP",
			cfg: &Config{
				TrustedProxyRanges: []string{"173.245.48.0/20"},
				Header:             "True-Client-IP",
			},
			remoteAddr:          "192.168.1.100:12345",
			initialXFF:          "10.0.0.1",
			spoofOnLegacyHeader: "True-Client-IP",
			expectedXFF:         "192.168.1.100",
			expectedRealIP:      "192.168.1.100",
			expectedStatus:      http.StatusOK,
			shouldPreserveXFF:   false,
		},
		{
			desc: "IPv6 trusted proxy normalizes from XFF",
			cfg: &Config{
				TrustedProxyRanges: []string{"2400:cb00::/32"},
				Header:             "X-Forwarded-For",
			},
			remoteAddr:        "[2400:cb00::1]:12345",
			initialXFF:        "192.168.1.100",
			expectedXFF:       "192.168.1.100",
			expectedRealIP:    "192.168.1.100",
			expectedStatus:    http.StatusOK,
			shouldPreserveXFF: false,
		},
		{
			desc: "IPv6 untrusted proxy",
			cfg: &Config{
				TrustedProxyRanges: []string{"173.245.48.0/20"},
				Header:             "X-Forwarded-For",
			},
			remoteAddr:        "[2001:db8::1]:12345",
			initialXFF:        "10.0.0.1",
			expectedXFF:       "2001:db8::1",
			expectedRealIP:    "2001:db8::1",
			expectedStatus:    http.StatusOK,
			shouldPreserveXFF: false,
		},
		{
			desc: "single IP trusted proxy normalizes",
			cfg: &Config{
				TrustedProxyRanges: []string{"173.245.48.1"},
				Header:             "X-Forwarded-For",
			},
			remoteAddr:        "173.245.48.1:12345",
			initialXFF:        "192.168.1.100",
			expectedXFF:       "192.168.1.100",
			expectedRealIP:    "192.168.1.100",
			expectedStatus:    http.StatusOK,
			shouldPreserveXFF: false,
		},
		{
			desc: "empty trusted proxy ranges - treat all as untrusted",
			cfg: &Config{
				TrustedProxyRanges: []string{},
				Header:             "X-Forwarded-For",
			},
			remoteAddr:        "173.245.48.1:12345",
			initialXFF:        "192.168.1.100",
			expectedXFF:       "173.245.48.1",
			expectedRealIP:    "173.245.48.1",
			expectedStatus:    http.StatusOK,
			shouldPreserveXFF: false,
		},
		{
			desc: "trusted cannot resolve client - pass through",
			cfg: &Config{
				TrustedProxyRanges: []string{"173.245.48.0/20"},
				Header:             "X-Forwarded-For",
			},
			remoteAddr:        "173.245.48.1:12345",
			initialXFF:        "",
			cfConnectingIP:    "not-an-ip",
			expectedXFF:       "",
			expectedRealIP:    "",
			expectedStatus:    http.StatusOK,
			shouldPreserveXFF: true,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			// Create a test handler that records the request
			var recordedReq *http.Request
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				recordedReq = r
				w.WriteHeader(test.expectedStatus)
			})

			// Create the middleware
			handler, err := New(context.Background(), next, test.cfg, "test")
			if err != nil {
				t.Fatalf("Failed to create middleware: %v", err)
			}

			// Create test request
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = test.remoteAddr
			if test.initialXFF != "" {
				if test.spoofOnLegacyHeader != "" {
					req.Header.Set(test.spoofOnLegacyHeader, test.initialXFF)
				} else {
					req.Header.Set(headerForwardedFor, test.initialXFF)
				}
			}
			if test.initialRealIP != "" {
				req.Header.Set(headerRealIP, test.initialRealIP)
			}
			if test.cfConnectingIP != "" {
				req.Header.Set(headerCFConnectingIP, test.cfConnectingIP)
			}

			// Create response recorder
			rr := httptest.NewRecorder()

			// Serve the request
			handler.ServeHTTP(rr, req)

			// Check status code
			if status := rr.Code; status != test.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v", status, test.expectedStatus)
			}

			actualXFF := recordedReq.Header.Get(headerForwardedFor)
			if actualXFF != test.expectedXFF {
				t.Errorf("X-Forwarded-For mismatch: got %q want %q", actualXFF, test.expectedXFF)
			}
			actualRealIP := recordedReq.Header.Get(headerRealIP)
			if test.expectedRealIP != "" && actualRealIP != test.expectedRealIP {
				t.Errorf("X-Real-IP mismatch: got %q want %q", actualRealIP, test.expectedRealIP)
			}
			if test.cfg.Header == "True-Client-IP" {
				if got := recordedReq.Header.Get("True-Client-IP"); got != test.expectedXFF {
					t.Errorf("True-Client-IP mismatch: got %q want %q", got, test.expectedXFF)
				}
			}

			// Additional check for preservation behavior
			if test.shouldPreserveXFF && test.initialXFF != "" {
				wantXFF := test.initialXFF
				if actualXFF != wantXFF {
					t.Errorf("XFF should have been preserved but was changed: original %v, got %v", wantXFF, actualXFF)
				}
			}
		})
	}
}

func TestDefaultHeader(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"X-Forwarded-For", "X-Forwarded-For"},
		{"X-Real-IP", "X-Real-IP"},
		{"", "X-Forwarded-For"},
		{"   ", "X-Forwarded-For"},
		{"  X-Real-IP  ", "  X-Real-IP  "}, // Function doesn't trim, only checks if trimmed is empty
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result := defaultHeader(test.input)
			if result != test.expected {
				t.Errorf("defaultHeader(%q) = %q, want %q", test.input, result, test.expected)
			}
		})
	}
}

func TestParseCIDRs(t *testing.T) {
	tests := []struct {
		desc     string
		input    []string
		wantErr  bool
		expected int // number of parsed CIDRs
	}{
		{
			desc:     "valid CIDR ranges",
			input:    []string{"173.245.48.0/20", "103.21.244.0/22"},
			wantErr:  false,
			expected: 2,
		},
		{
			desc:     "single IP addresses",
			input:    []string{"173.245.48.1", "103.21.244.1"},
			wantErr:  false,
			expected: 2,
		},
		{
			desc:     "mixed IPs and CIDRs",
			input:    []string{"173.245.48.0/20", "103.21.244.1"},
			wantErr:  false,
			expected: 2,
		},
		{
			desc:     "IPv6 addresses",
			input:    []string{"2400:cb00::/32", "2001:db8::1"},
			wantErr:  false,
			expected: 2,
		},
		{
			desc:     "invalid CIDR",
			input:    []string{"invalid-cidr"},
			wantErr:  true,
			expected: 0,
		},
		{
			desc:     "empty input",
			input:    []string{},
			wantErr:  false,
			expected: 0,
		},
		{
			desc:     "valid and invalid mixed",
			input:    []string{"173.245.48.0/20", "invalid-cidr"},
			wantErr:  true,
			expected: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			result, err := parseCIDRs(test.input)

			if test.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
				if len(result) != test.expected {
					t.Errorf("Expected %d CIDRs, got %d", test.expected, len(result))
				}
			}
		})
	}
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"192.168.1.100:12345", "192.168.1.100"},
		{"173.245.48.1:80", "173.245.48.1"},
		{"[2001:db8::1]:12345", "2001:db8::1"}, // IPv6 with port needs brackets
		{"192.168.1.100", "192.168.1.100"},     // No port
		{"invalid", "<nil>"},                   // Invalid format returns nil
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result := clientIP(test.input)
			if result == nil {
				if test.expected != "<nil>" {
					t.Errorf("clientIP(%q) = nil, want %q", test.input, test.expected)
				}
			} else if result.String() != test.expected {
				t.Errorf("clientIP(%q) = %q, want %q", test.input, result.String(), test.expected)
			}
		})
	}
}

func TestIsTrustedProxy(t *testing.T) {
	// Create a middleware with test configuration
	m := &middleware{
		trustedProxies: []*net.IPNet{
			{IP: net.ParseIP("173.245.48.0"), Mask: net.CIDRMask(20, 32)},
			{IP: net.ParseIP("103.21.244.0"), Mask: net.CIDRMask(22, 32)},
		},
	}

	tests := []struct {
		desc     string
		ip       string
		expected bool
	}{
		{"trusted proxy IP", "173.245.48.1", true},
		{"trusted proxy IP range", "173.245.48.255", true},
		{"untrusted proxy IP", "192.168.1.100", false},
		{"another trusted range", "103.21.244.1", true},
		{"IPv6 untrusted", "2001:db8::1", false},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			ip := net.ParseIP(test.ip)
			if ip == nil {
				t.Fatalf("Invalid IP address: %s", test.ip)
			}

			result := m.isTrustedProxy(ip)
			if result != test.expected {
				t.Errorf("isTrustedProxy(%s) = %v, want %v", test.ip, result, test.expected)
			}
		})
	}
}

func TestIsTrustedProxy_nilIP(t *testing.T) {
	m := &middleware{trustedProxies: []*net.IPNet{{IP: net.IPv4(173, 245, 48, 0), Mask: net.CIDRMask(20, 32)}}}
	if m.isTrustedProxy(nil) {
		t.Fatal("expected false for nil IP")
	}
}

func TestMergeUniqueCIDRStrings(t *testing.T) {
	got := mergeUniqueCIDRStrings([]string{"10.0.0.0/8", " 10.0.0.0/8 "}, []string{"192.168.0.0/16"})
	if len(got) != 2 {
		t.Fatalf("want 2 entries, got %v", got)
	}
}

func TestNew_fetchCloudflareRanges_merge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":{"ipv4_cidrs":["198.51.100.0/24"],"ipv6_cidrs":[]},"success":true}`))
	}))
	defer srv.Close()

	old := cloudflareIPsAPIURL
	cloudflareIPsAPIURL = srv.URL
	defer func() { cloudflareIPsAPIURL = old }()

	cfg := &Config{
		FetchCloudflareRanges:       true,
		TrustedProxyRanges:          []string{"10.0.0.0/8"},
		CloudflareRangesHTTPTimeout: "2s",
	}

	t.Run("fetchedCIDR", func(t *testing.T) {
		var recorded *http.Request
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { recorded = r })
		h, err := New(context.Background(), inner, cfg, "test")
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "198.51.100.1:9999"
		req.Header.Set(headerCFConnectingIP, "203.0.113.1")
		h.ServeHTTP(httptest.NewRecorder(), req)
		if got := recorded.Header.Get(headerForwardedFor); got != "203.0.113.1" {
			t.Errorf("X-Forwarded-For got %q want 203.0.113.1", got)
		}
	})

	t.Run("manualCIDR", func(t *testing.T) {
		var recorded *http.Request
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { recorded = r })
		h, err := New(context.Background(), inner, cfg, "test")
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.5.5.5:9999"
		req.Header.Set(headerForwardedFor, "198.51.100.99")
		h.ServeHTTP(httptest.NewRecorder(), req)
		if got := recorded.Header.Get(headerForwardedFor); got != "198.51.100.99" {
			t.Errorf("X-Forwarded-For got %q want 198.51.100.99", got)
		}
	})
}

func TestNew_fetchCloudflareRanges_strictFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	old := cloudflareIPsAPIURL
	cloudflareIPsAPIURL = srv.URL
	defer func() { cloudflareIPsAPIURL = old }()

	cfg := &Config{
		FetchCloudflareRanges:         true,
		CloudflareRangesFetchRequired: true,
		CloudflareRangesHTTPTimeout:   "2s",
		TrustedProxyRanges:            nil,
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	_, err := New(context.Background(), next, cfg, "test")
	if err == nil {
		t.Fatal("expected error when fetch required and API fails")
	}
}

func TestNew_fetchCloudflareRanges_fallbackEmbedded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	old := cloudflareIPsAPIURL
	cloudflareIPsAPIURL = srv.URL
	defer func() { cloudflareIPsAPIURL = old }()

	cfg := &Config{
		FetchCloudflareRanges:       true,
		CloudflareRangesHTTPTimeout: "2s",
		TrustedProxyRanges:          nil,
	}
	var recorded *http.Request
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { recorded = r })
	h, err := New(context.Background(), inner, cfg, "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "173.245.48.1:12345"
	req.Header.Set(headerCFConnectingIP, "198.51.100.77")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if got := recorded.Header.Get(headerForwardedFor); got != "198.51.100.77" {
		t.Errorf("embedded fallback trust: XFF got %q", got)
	}
}

func TestIntegration_CloudflareExample(t *testing.T) {
	// Test the complete Cloudflare example from the documentation
	cfg := &Config{
		TrustedProxyRanges: []string{
			"173.245.48.0/20", // Cloudflare IPv4
			"103.21.244.0/22", // Cloudflare IPv4
			"2400:cb00::/32",  // Cloudflare IPv6
		},
		DirectRanges: []string{"0.0.0.0/0"}, // allow any non-Cloudflare source
		Header:       "X-Forwarded-For",
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler, err := New(context.Background(), next, cfg, "test")
	if err != nil {
		t.Fatalf("Failed to create middleware: %v", err)
	}

	testCases := []struct {
		desc           string
		remoteAddr     string
		initialXFF     string
		cfConnectingIP string
		expectedXFF    string
		expectedRealIP string
	}{
		{
			desc:           "Cloudflare proxy - normalize from CF-Connecting-IP",
			remoteAddr:     "173.245.48.1:12345",
			initialXFF:     "192.0.2.1, 192.0.2.2",
			cfConnectingIP: "192.168.1.100",
			expectedXFF:    "192.168.1.100",
			expectedRealIP: "192.168.1.100",
		},
		{
			desc:           "Direct client - set XFF to remote",
			remoteAddr:     "192.168.1.100:12345",
			initialXFF:     "10.0.0.1",
			expectedXFF:    "192.168.1.100",
			expectedRealIP: "192.168.1.100",
		},
		{
			desc:           "Direct client with empty XFF",
			remoteAddr:     "192.168.1.100:12345",
			initialXFF:     "",
			expectedXFF:    "192.168.1.100",
			expectedRealIP: "192.168.1.100",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tc.remoteAddr
			if tc.initialXFF != "" {
				req.Header.Set(headerForwardedFor, tc.initialXFF)
			}
			if tc.cfConnectingIP != "" {
				req.Header.Set(headerCFConnectingIP, tc.cfConnectingIP)
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			actualXFF := req.Header.Get(headerForwardedFor)
			if actualXFF != tc.expectedXFF {
				t.Errorf("XFF header mismatch: got %v want %v", actualXFF, tc.expectedXFF)
			}
			if tc.expectedRealIP != "" {
				if got := req.Header.Get(headerRealIP); got != tc.expectedRealIP {
					t.Errorf("X-Real-IP mismatch: got %v want %v", got, tc.expectedRealIP)
				}
			}
		})
	}
}
