package auth_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auth "github.com/brick-org/brick/auth/src"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

// --- Cycle 1: exact origin match ---

func TestIsTrustedOrigin_ExactMatch(t *testing.T) {
	opts := auth.Options{TrustedOrigins: []string{"https://trusted.com"}}
	if !auth.IsTrustedOrigin("https://trusted.com", opts, nil) {
		t.Fatal("exact trusted origin must be accepted")
	}
}

// --- Cycle 2: path under trusted origin ---

func TestIsTrustedOrigin_PathUnderTrusted(t *testing.T) {
	opts := auth.Options{TrustedOrigins: []string{"https://trusted.com"}}
	if !auth.IsTrustedOrigin("https://trusted.com/some/path", opts, nil) {
		t.Fatal("path under trusted origin must be accepted")
	}
}

// --- Cycle 3: reject similar-looking domain ---

func TestIsTrustedOrigin_RejectsSimilarDomain(t *testing.T) {
	opts := auth.Options{TrustedOrigins: []string{"https://trusted.com"}}
	if auth.IsTrustedOrigin("https://trusted.com.evil.com", opts, nil) {
		t.Fatal("domain that starts with trusted origin must be rejected")
	}
}

// --- Cycle 4: wildcard host pattern ---

func TestIsTrustedOrigin_WildcardHost(t *testing.T) {
	opts := auth.Options{TrustedOrigins: []string{"*.my-site.com"}}
	if !auth.IsTrustedOrigin("https://sub.my-site.com", opts, nil) {
		t.Fatal("wildcard *.my-site.com must match sub.my-site.com")
	}
	if !auth.IsTrustedOrigin("https://another.my-site.com/callback", opts, nil) {
		t.Fatal("wildcard *.my-site.com must match path under another subdomain")
	}
	if auth.IsTrustedOrigin("https://my-site.com", opts, nil) {
		t.Fatal("wildcard *.my-site.com must not match bare my-site.com")
	}
}

// --- Cycle 5: protocol-specific wildcard ---

func TestIsTrustedOrigin_ProtocolWildcard(t *testing.T) {
	opts := auth.Options{TrustedOrigins: []string{"https://*.example.com"}}
	if !auth.IsTrustedOrigin("https://api.example.com", opts, nil) {
		t.Fatal("https wildcard must match https subdomain")
	}
	if auth.IsTrustedOrigin("http://api.example.com", opts, nil) {
		t.Fatal("https wildcard must NOT match http subdomain")
	}
}

// --- Cycle 6: BaseURL origin always trusted ---

func TestIsTrustedOrigin_BaseURLAlwaysTrusted(t *testing.T) {
	opts := auth.Options{BaseURL: "http://localhost:8080/api/auth"}
	if !auth.IsTrustedOrigin("http://localhost:8080/dashboard", opts, nil) {
		t.Fatal("BaseURL origin must always be trusted")
	}
}

func TestIsTrustedRedirect_RelativeURLSecurity(t *testing.T) {
	opts := auth.Options{BaseURL: "https://app.example.com"}
	for _, trusted := range []string{
		"/", "/dashboard", "/dashboard?next=%2Faccount", "https://app.example.com/callback",
	} {
		if !auth.IsTrustedRedirect(trusted, opts, nil) {
			t.Errorf("expected trusted redirect %q", trusted)
		}
	}
	for _, untrusted := range []string{
		"//evil.example", `/\\evil.example`, "/safe%2fevil", "/safe%5cevil",
		"https://app.example.com.evil.test", "https://evil.test", "/safe\nheader",
	} {
		if auth.IsTrustedRedirect(untrusted, opts, nil) {
			t.Errorf("expected untrusted redirect %q", untrusted)
		}
	}
}

// --- helpers for middleware tests ---

func newOriginTestServer(t *testing.T, trustedOrigins []string, baseURL string, advanced auth.AdvancedOptions) *httptest.Server {
	t.Helper()
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	mustBetterAuth(t, auth.Options{
		Secret:         "test-secret",
		Adapter:        api.Adapter(),
		BaseURL:        baseURL,
		TrustedOrigins: trustedOrigins,
		Advanced:       advanced,
	})
	srv := httptest.NewServer(api.Adapter())
	t.Cleanup(srv.Close)
	return srv
}

func postWithOriginAndCookie(t *testing.T, url, origin, cookie string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(`{}`))
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

// --- Cycle 7: middleware passes trusted origin with cookie ---

func TestOriginMiddleware_TrustedOriginWithCookie(t *testing.T) {
	srv := newOriginTestServer(t, []string{"https://trusted.com"}, "http://localhost", auth.AdvancedOptions{})
	// 422 = Huma validation error (empty body) — route exists, origin check passed
	status := postWithOriginAndCookie(t, srv.URL+"/api/auth/sign-in/email", "https://trusted.com", "session=abc")
	if status == http.StatusForbidden {
		t.Fatalf("trusted origin with cookie must not be rejected, got %d", status)
	}
}

// --- Cycle 8: middleware rejects untrusted origin with cookie ---

func TestOriginMiddleware_UntrustedOriginWithCookie(t *testing.T) {
	srv := newOriginTestServer(t, []string{"https://trusted.com"}, "http://localhost", auth.AdvancedOptions{})
	status := postWithOriginAndCookie(t, srv.URL+"/api/auth/sign-in/email", "https://evil.com", "session=abc")
	if status != http.StatusForbidden {
		t.Fatalf("untrusted origin with cookie must return 403, got %d", status)
	}
}

// --- Cycle 9: middleware allows request without cookie (server-to-server) ---

func TestOriginMiddleware_NoCookieAllowed(t *testing.T) {
	srv := newOriginTestServer(t, []string{"https://trusted.com"}, "http://localhost", auth.AdvancedOptions{})
	status := postWithOriginAndCookie(t, srv.URL+"/api/auth/sign-in/email", "https://evil.com", "")
	if status == http.StatusForbidden {
		t.Fatalf("request without cookie must not be blocked by origin check, got %d", status)
	}
}

func TestOriginMiddleware_DisableCSRFCheckBypassesOriginValidation(t *testing.T) {
	srv := newOriginTestServer(t, []string{"https://trusted.com"}, "http://localhost", auth.AdvancedOptions{
		DisableCSRFCheck: true,
	})
	status := postWithOriginAndCookie(t, srv.URL+"/api/auth/sign-in/email", "https://evil.com", "session=abc")
	if status == http.StatusForbidden {
		t.Fatalf("disableCSRFCheck should bypass origin validation, got %d", status)
	}
}
