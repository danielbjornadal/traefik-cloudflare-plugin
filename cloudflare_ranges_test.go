package traefik_cloudflare_plugin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// useCloudflareAPI points the Cloudflare IPs API at url for the rest of the test, starting without a
// cached list for url.
func useCloudflareAPI(t *testing.T, url string) {
	t.Helper()
	old := cloudflareIPsAPIURL
	cloudflareIPsAPIURL = url
	clearCloudflareRangesCache(url)
	t.Cleanup(func() {
		cloudflareIPsAPIURL = old
		clearCloudflareRangesCache(url)
	})
}

func clearCloudflareRangesCache(url string) {
	cloudflareRangesMu.Lock()
	defer cloudflareRangesMu.Unlock()
	delete(cloudflareRangesCache, url)
}

// cloudflareAPIBody renders a successful Cloudflare IPs API response listing cidrs.
func cloudflareAPIBody(t *testing.T, cidrs []string) string {
	t.Helper()
	var resp cfIPsAPIResponse
	resp.Success = true
	resp.Result.IPv4CIDRs = []string{}
	resp.Result.IPv6CIDRs = []string{}
	for _, c := range cidrs {
		if strings.Contains(c, ":") {
			resp.Result.IPv6CIDRs = append(resp.Result.IPv6CIDRs, c)
		} else {
			resp.Result.IPv4CIDRs = append(resp.Result.IPv4CIDRs, c)
		}
	}
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// newCloudflareAPIServer serves body with status 200, or status 500 while *failing is non-zero, and counts
// requests in *hits.
func newCloudflareAPIServer(t *testing.T, body string, hits, failing *int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		if atomic.LoadInt32(failing) != 0 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newFetchingMiddleware(t *testing.T, required bool) (http.Handler, error) {
	t.Helper()
	cfg := &Config{
		FetchCloudflareRanges:         true,
		CloudflareRangesFetchRequired: required,
		CloudflareRangesHTTPTimeout:   "2s",
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	return New(context.Background(), next, cfg, "test")
}

func TestFetchCloudflareRanges_invalidListFallsBackToEmbedded(t *testing.T) {
	tests := []struct {
		desc  string
		cidrs []string
	}{
		{"match-all IPv4 range", []string{"173.245.48.0/20", "0.0.0.0/0"}},
		{"match-all IPv6 range", []string{"173.245.48.0/20", "::/0"}},
		{"IPv4 range wider than /8", []string{"0.0.0.0/7"}},
		{"malformed entry", []string{"173.245.48.0/20", "not-a-cidr"}},
		{"bare IP instead of CIDR", []string{"203.0.113.9"}},
	}
	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			var hits, failing int32
			srv := newCloudflareAPIServer(t, cloudflareAPIBody(t, test.cidrs), &hits, &failing)
			useCloudflareAPI(t, srv.URL)

			cfg := &Config{FetchCloudflareRanges: true, CloudflareRangesHTTPTimeout: "2s"}
			got := serveRequest(t, cfg, "203.0.113.9:5555", httpHeader(headerCFConnectingIP, "10.0.0.5"))
			assertHeaders(t, got, map[string][]string{
				headerForwardedFor:   {"203.0.113.9"},
				headerCFConnectingIP: nil,
			})

			got = serveRequest(t, cfg, "103.21.244.1:443", httpHeader(headerCFConnectingIP, "198.51.100.77"))
			assertHeaders(t, got, map[string][]string{headerForwardedFor: {"198.51.100.77"}})

			if _, err := newFetchingMiddleware(t, true); err == nil {
				t.Error("expected New to fail when the fetch is required and the list is invalid")
			}
		})
	}
}

func TestFetchCloudflareRanges_redirectIsFailure(t *testing.T) {
	var targetHits, targetFailing int32
	target := newCloudflareAPIServer(t, cloudflareAPIBody(t, []string{"203.0.113.0/24"}), &targetHits, &targetFailing)

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()
	useCloudflareAPI(t, redirector.URL)

	cfg := &Config{FetchCloudflareRanges: true, CloudflareRangesHTTPTimeout: "2s"}
	got := serveRequest(t, cfg, "203.0.113.9:5555", httpHeader(headerCFConnectingIP, "10.0.0.5"))
	assertHeaders(t, got, map[string][]string{headerForwardedFor: {"203.0.113.9"}})

	if _, err := newFetchingMiddleware(t, true); err == nil {
		t.Error("expected New to fail when the fetch is required and the API redirects")
	}
	if n := atomic.LoadInt32(&targetHits); n != 0 {
		t.Errorf("redirect target was requested %d times", n)
	}
}

func TestFetchCloudflareRanges_cachedAcrossNewCalls(t *testing.T) {
	var hits, failing int32
	srv := newCloudflareAPIServer(t, cloudflareAPIBody(t, embeddedCloudflareCIDRs), &hits, &failing)
	useCloudflareAPI(t, srv.URL)

	for i := 0; i < 2; i++ {
		if _, err := newFetchingMiddleware(t, true); err != nil {
			t.Fatalf("New: %v", err)
		}
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Errorf("API requested %d times, want 1", n)
	}
}

func TestFetchCloudflareRanges_concurrentNewCallsFetchOnce(t *testing.T) {
	var hits, failing int32
	srv := newCloudflareAPIServer(t, cloudflareAPIBody(t, embeddedCloudflareCIDRs), &hits, &failing)
	useCloudflareAPI(t, srv.URL)

	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := newFetchingMiddleware(t, true)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("New: %v", err)
		}
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Errorf("API requested %d times, want 1", n)
	}
}

func TestFetchCloudflareRanges_expiredCacheUsesLastGoodList(t *testing.T) {
	var hits, failing int32
	srv := newCloudflareAPIServer(t, cloudflareAPIBody(t, []string{"198.51.100.0/24"}), &hits, &failing)
	useCloudflareAPI(t, srv.URL)

	if _, err := newFetchingMiddleware(t, true); err != nil {
		t.Fatalf("New: %v", err)
	}

	atomic.StoreInt32(&failing, 1)
	oldNow := timeNow
	later := time.Now().Add(2 * cloudflareRangesCacheTTL)
	timeNow = func() time.Time { return later }
	defer func() { timeNow = oldNow }()

	if _, err := newFetchingMiddleware(t, true); err != nil {
		t.Fatalf("New with expired cache and failing API: %v", err)
	}
	if n := atomic.LoadInt32(&hits); n != 2 {
		t.Errorf("API requested %d times, want 2", n)
	}

	cfg := &Config{FetchCloudflareRanges: true, CloudflareRangesFetchRequired: true, CloudflareRangesHTTPTimeout: "2s"}
	got := serveRequest(t, cfg, "198.51.100.1:443", httpHeader(headerCFConnectingIP, "203.0.113.1"))
	assertHeaders(t, got, map[string][]string{headerForwardedFor: {"203.0.113.1"}})
}

func TestFetchCloudflareRanges_failedFetchRetriedAfterInterval(t *testing.T) {
	var hits int32
	failing := int32(1)
	srv := newCloudflareAPIServer(t, cloudflareAPIBody(t, embeddedCloudflareCIDRs), &hits, &failing)
	useCloudflareAPI(t, srv.URL)

	start := time.Now()
	oldNow := timeNow
	now := start
	timeNow = func() time.Time { return now }
	defer func() { timeNow = oldNow }()

	for i := 0; i < 3; i++ {
		if _, err := newFetchingMiddleware(t, true); err == nil {
			t.Fatal("expected New to fail while the API is failing and nothing is cached")
		}
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Errorf("API requested %d times within the retry interval, want 1", n)
	}

	atomic.StoreInt32(&failing, 0)
	now = start.Add(cloudflareRangesRetryInterval + time.Second)
	if _, err := newFetchingMiddleware(t, true); err != nil {
		t.Fatalf("New after the retry interval: %v", err)
	}
	if n := atomic.LoadInt32(&hits); n != 2 {
		t.Errorf("API requested %d times, want 2", n)
	}
}

func TestFetchCloudflareRanges_fetchedListClassifiesCloudflareHops(t *testing.T) {
	var hits, failing int32
	srv := newCloudflareAPIServer(t, cloudflareAPIBody(t, []string{"198.51.100.0/24"}), &hits, &failing)
	useCloudflareAPI(t, srv.URL)

	cfg := &Config{FetchCloudflareRanges: true, CloudflareRangesHTTPTimeout: "2s"}
	got := serveRequest(t, cfg, "173.245.48.1:443", httpHeader(headerCFConnectingIP, "203.0.113.1"))
	assertHeaders(t, got, map[string][]string{headerForwardedFor: {"173.245.48.1"}})
}

func httpHeader(name, value string) http.Header {
	h := http.Header{}
	h.Set(name, value)
	return h
}
