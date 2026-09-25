package auth_test

// wave4_conformance_test.go: upstream conformance (Better Auth v1.7.5).

import (
	"net/http"
	"strings"
	"sync"
	"testing"

	auth "github.com/brick-org/brick/auth/src"
)

func doWithOriginAndCookie(t *testing.T, method, url, origin, cookie string) int {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// Upstream: "should work with GET requests" — safe methods are never origin
func TestOriginTrust_OriginMiddleware_GETNeverGated(t *testing.T) {
	srv := newOriginTestServer(t, []string{"https://trusted.com"}, "http://localhost", auth.AdvancedOptions{})
	status := doWithOriginAndCookie(t, http.MethodGet, srv.URL+"/api/auth/session", "https://evil.com", "session=abc")
	if status == http.StatusForbidden {
		t.Fatalf("GET must not be origin gated, got %d", status)
	}
}

// Upstream: mutating methods with an untrusted Origin + cookie are rejected.
func TestOriginTrust_OriginMiddleware_MutatingMethodsGated(t *testing.T) {
	srv := newOriginTestServer(t, []string{"https://trusted.com"}, "http://localhost", auth.AdvancedOptions{})
	for _, method := range []string{http.MethodPost} {
		status := doWithOriginAndCookie(t, method, srv.URL+"/api/auth/sign-in/email", "https://evil.com", "session=abc")
		if status != http.StatusForbidden {
			t.Errorf("%s with untrusted origin must return 403, got %d", method, status)
		}
		status = doWithOriginAndCookie(t, method, srv.URL+"/api/auth/sign-in/email", "https://trusted.com", "session=abc")
		if status == http.StatusForbidden {
			t.Errorf("%s with trusted origin must not return 403, got %d", method, status)
		}
	}
}

// Upstream: "should reject untrusted origin headers" — a scheme-less Origin
func TestOriginTrust_OriginMiddleware_SchemeLessAndSubdomain(t *testing.T) {
	srv := newOriginTestServer(t, []string{"https://trusted.com"}, "http://localhost", auth.AdvancedOptions{})
	for _, origin := range []string{"malicious.com", "http://sub-domain.trusted.com", "trusted.com", "//trusted.com"} {
		status := doWithOriginAndCookie(t, http.MethodPost, srv.URL+"/api/auth/sign-in/email", origin, "session=abc")
		if status != http.StatusForbidden {
			t.Errorf("origin %q must return 403, got %d", origin, status)
		}
	}
}

// Upstream: "should work with list of trusted origins" and "should work
func TestOriginTrust_OriginMiddleware_OriginLists(t *testing.T) {
	srv := newOriginTestServer(t,
		[]string{"http://localhost:5000", "https://trusted.com", "*.my-site.com"},
		"http://localhost", auth.AdvancedOptions{})
	for _, origin := range []string{"http://localhost:5000", "https://trusted.com", "https://sub-domain.my-site.com"} {
		status := doWithOriginAndCookie(t, http.MethodPost, srv.URL+"/api/auth/sign-in/email", origin, "session=abc")
		if status == http.StatusForbidden {
			t.Errorf("listed origin %q must pass, got %d", origin, status)
		}
	}
	status := doWithOriginAndCookie(t, http.MethodPost, srv.URL+"/api/auth/sign-in/email", "https://my-site.com", "session=abc")
	if status != http.StatusForbidden {
		t.Errorf("bare wildcard parent must return 403, got %d", status)
	}
}

// Upstream: disableOriginCheck skips origin validation (with the backward
func TestOriginTrust_OriginMiddleware_DisableOriginCheck(t *testing.T) {
	srv := newOriginTestServer(t, []string{"https://trusted.com"}, "http://localhost", auth.AdvancedOptions{
		DisableOriginCheck: true,
	})
	status := doWithOriginAndCookie(t, http.MethodPost, srv.URL+"/api/auth/sign-in/email", "https://evil.com", "session=abc")
	if status == http.StatusForbidden {
		t.Fatalf("DisableOriginCheck should bypass origin validation, got %d", status)
	}
}

// Cross-language golden vectors
// want) triples transcribed from the pinned upstream origin-check and

func TestOriginTrust_TrustedOriginGoldenVectors(t *testing.T) {
	vectors := []struct {
		name   string
		opts   auth.Options
		origin string
		want   bool
	}{
		{"base origin", auth.Options{BaseURL: "http://localhost:3000/api/auth"}, "http://localhost:3000", true},
		{"base origin path", auth.Options{BaseURL: "http://localhost:3000/api/auth"}, "http://localhost:3000/some/path", true},
		{"prefix attack", auth.Options{TrustedOrigins: []string{"https://trusted.com"}}, "https://trusted.com.malicious.com", false},
		{"subdomain untrusted", auth.Options{TrustedOrigins: []string{"https://trusted.com"}}, "http://sub-domain.trusted.com", false},
		{"exact trusted", auth.Options{TrustedOrigins: []string{"https://trusted.com"}}, "https://trusted.com", true},
		{"exact trusted path", auth.Options{TrustedOrigins: []string{"https://trusted.com"}}, "https://trusted.com/some/path", true},
		{"wildcard", auth.Options{TrustedOrigins: []string{"*.my-site.com"}}, "https://sub-domain.my-site.com", true},
		{"wildcard callback", auth.Options{TrustedOrigins: []string{"*.my-site.com"}}, "https://another-sub.my-site.com/callback", true},
		{"protocol wildcard ok", auth.Options{TrustedOrigins: []string{"https://*.protocol-site.com"}}, "https://api.protocol-site.com", true},
		{"protocol wildcard wrong scheme", auth.Options{TrustedOrigins: []string{"https://*.protocol-site.com"}}, "http://api.protocol-site.com", false},
		{"expo wildcard", auth.Options{TrustedOrigins: []string{"exp://192.168.*.*:*/*"}}, "exp://192.168.1.100:8081/--/", true},
		{"expo wildcard miss", auth.Options{TrustedOrigins: []string{"exp://192.168.*.*:*/*"}}, "exp://10.0.0.1:8081/--/", false},
		{"custom exact", auth.Options{TrustedOrigins: []string{"myapp://callback"}}, "myapp://callback/path", true},
		{"custom extension", auth.Options{TrustedOrigins: []string{"myapp://callback"}}, "myapp://callback.attacker.tld/path", false},
		{"unknown", auth.Options{TrustedOrigins: []string{"https://trusted.com"}}, "https://unknown.com", false},
		{"empty", auth.Options{TrustedOrigins: []string{"https://trusted.com"}}, "", false},
	}
	for _, v := range vectors {
		if got := auth.IsTrustedOrigin(v.origin, v.opts, nil); got != v.want {
			t.Errorf("%s: IsTrustedOrigin(%q) = %v, want %v", v.name, v.origin, got, v.want)
		}
	}
}

// Malformed-input limits

func TestOriginTrust_IsTrustedOriginLimits(t *testing.T) {
	opts := auth.Options{BaseURL: "https://app.example.com", TrustedOrigins: []string{"https://*.example.com"}}
	huge := strings.Repeat("a", 1<<20)
	for _, raw := range []string{huge, "https://" + huge, huge + "://x", "\x00", "http://x\x7fy"} {
		if auth.IsTrustedOrigin(raw, opts, nil) {
			t.Errorf("hostile origin %q... must fail closed", raw[:min(16, len(raw))])
		}
	}
	if auth.IsTrustedRedirect("//evil.example", opts, nil) {
		t.Error("protocol-relative redirect must fail closed")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Race tests

func TestOriginTrust_IsTrustedOriginConcurrentUse(t *testing.T) {
	opts := auth.Options{
		BaseURL:        "https://app.example.com",
		TrustedOrigins: []string{"https://*.example.com", "myapp://callback"},
		TrustedOriginsFunc: func(r *http.Request) []string {
			return []string{"https://dynamic.example.com"}
		},
	}
	origins := []string{
		"https://a.example.com", "https://evil.com", "myapp://callback/path",
		"https://dynamic.example.com/cb", "https://app.example.com/x",
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				for _, o := range origins {
					_ = auth.IsTrustedOrigin(o, opts, nil)
					_ = auth.IsTrustedRedirect(o, opts, nil)
				}
			}
		}()
	}
	wg.Wait()
}

// Fuzz target: trusted-origin matching at the Options level

func FuzzIsTrustedOrigin(f *testing.F) {
	for _, s := range []string{
		"https://trusted.com",
		"https://trusted.com.evil.com",
		"https://sub.my-site.com/cb",
		"/dashboard",
		"myapp://host/cb/../evil",
		"javascript:alert(1)",
		"",
		"malicious.com",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, origin string) {
		static := auth.Options{TrustedOrigins: []string{"https://trusted.com", "*.my-site.com", "myapp://host/cb"}}
		got := auth.IsTrustedOrigin(origin, static, nil)
		if origin == "" && got {
			t.Fatal("empty origin must never be trusted")
		}
		if strings.HasPrefix(origin, "/") && got {
			t.Fatalf("relative origin %q must never match IsTrustedOrigin", origin)
		}
		if again := auth.IsTrustedOrigin(origin, static, nil); again != got {
			t.Fatalf("nondeterministic match for %q", origin)
		}
	})
}
