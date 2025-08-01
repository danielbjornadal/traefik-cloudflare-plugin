package main

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
			desc: "empty config (should use defaults)",
			cfg: &Config{},
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
		desc              string
		cfg               *Config
		remoteAddr        string
		initialXFF        string
		expectedXFF       string
		expectedStatus    int
		shouldPreserveXFF bool
	}{
		{
			desc: "trusted proxy - preserve XFF",
			cfg: &Config{
				TrustedProxyRanges: []string{"173.245.48.0/20"},
				Header:             "X-Forwarded-For",
			},
			remoteAddr:        "173.245.48.1:12345",
			initialXFF:        "192.168.1.100",
			expectedXFF:       "192.168.1.100", // Should be preserved
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
			expectedXFF:       "192.168.1.100", // Should be overridden
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
			expectedXFF:       "192.168.1.100", // Should be set
			expectedStatus:    http.StatusOK,
			shouldPreserveXFF: false,
		},
		{
			desc: "custom header",
			cfg: &Config{
				TrustedProxyRanges: []string{"173.245.48.0/20"},
				Header:             "X-Real-IP",
			},
			remoteAddr:        "192.168.1.100:12345",
			initialXFF:        "10.0.0.1",
			expectedXFF:       "192.168.1.100",
			expectedStatus:    http.StatusOK,
			shouldPreserveXFF: false,
		},
		{
			desc: "IPv6 trusted proxy",
			cfg: &Config{
				TrustedProxyRanges: []string{"2400:cb00::/32"},
				Header:             "X-Forwarded-For",
			},
			remoteAddr:        "[2400:cb00::1]:12345",
			initialXFF:        "192.168.1.100",
			expectedXFF:       "192.168.1.100", // Should be preserved
			expectedStatus:    http.StatusOK,
			shouldPreserveXFF: true,
		},
		{
			desc: "IPv6 untrusted proxy",
			cfg: &Config{
				TrustedProxyRanges: []string{"173.245.48.0/20"},
				Header:             "X-Forwarded-For",
			},
			remoteAddr:        "[2001:db8::1]:12345",
			initialXFF:        "10.0.0.1",
			expectedXFF:       "2001:db8::1", // Should be overridden
			expectedStatus:    http.StatusOK,
			shouldPreserveXFF: false,
		},
		{
			desc: "single IP trusted proxy",
			cfg: &Config{
				TrustedProxyRanges: []string{"173.245.48.1"},
				Header:             "X-Forwarded-For",
			},
			remoteAddr:        "173.245.48.1:12345",
			initialXFF:        "192.168.1.100",
			expectedXFF:       "192.168.1.100", // Should be preserved
			expectedStatus:    http.StatusOK,
			shouldPreserveXFF: true,
		},
		{
			desc: "empty trusted proxy ranges - treat all as untrusted",
			cfg: &Config{
				TrustedProxyRanges: []string{},
				Header:             "X-Forwarded-For",
			},
			remoteAddr:        "173.245.48.1:12345",
			initialXFF:        "192.168.1.100",
			expectedXFF:       "173.245.48.1", // Should be overridden
			expectedStatus:    http.StatusOK,
			shouldPreserveXFF: false,
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
				req.Header.Set(test.cfg.Header, test.initialXFF)
			}

			// Create response recorder
			rr := httptest.NewRecorder()

			// Serve the request
			handler.ServeHTTP(rr, req)

			// Check status code
			if status := rr.Code; status != test.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v", status, test.expectedStatus)
			}

			// Check XFF header
			actualXFF := recordedReq.Header.Get(test.cfg.Header)
			if actualXFF != test.expectedXFF {
				t.Errorf("XFF header mismatch: got %v want %v", actualXFF, test.expectedXFF)
			}

			// Additional check for preservation behavior
			if test.shouldPreserveXFF && actualXFF != test.initialXFF {
				t.Errorf("XFF should have been preserved but was changed: original %v, got %v", test.initialXFF, actualXFF)
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
		{"invalid", "<nil>"},                    // Invalid format returns nil
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

func TestIntegration_CloudflareExample(t *testing.T) {
	// Test the complete Cloudflare example from the documentation
	cfg := &Config{
		TrustedProxyRanges: []string{
			"173.245.48.0/20",   // Cloudflare IPv4
			"103.21.244.0/22",   // Cloudflare IPv4
			"2400:cb00::/32",    // Cloudflare IPv6
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

	// Test cases based on the Cloudflare example
	testCases := []struct {
		desc        string
		remoteAddr  string
		initialXFF  string
		expectedXFF string
	}{
		{
			desc:        "Cloudflare proxy - preserve XFF",
			remoteAddr:  "173.245.48.1:12345",
			initialXFF:  "192.168.1.100",
			expectedXFF: "192.168.1.100", // Should be preserved
		},
		{
			desc:        "Direct client - set XFF to remote",
			remoteAddr:  "192.168.1.100:12345",
			initialXFF:  "10.0.0.1",
			expectedXFF: "192.168.1.100", // Should be overridden
		},
		{
			desc:        "Direct client with empty XFF",
			remoteAddr:  "192.168.1.100:12345",
			initialXFF:  "",
			expectedXFF: "192.168.1.100", // Should be set
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tc.remoteAddr
			if tc.initialXFF != "" {
				req.Header.Set("X-Forwarded-For", tc.initialXFF)
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			actualXFF := req.Header.Get("X-Forwarded-For")
			if actualXFF != tc.expectedXFF {
				t.Errorf("XFF header mismatch: got %v want %v", actualXFF, tc.expectedXFF)
			}
		})
	}
} 