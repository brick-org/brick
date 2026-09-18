package types

// AUTH-V10-02 — adversarial and cross-language conformance (tests only).
//
// This file owns the types package's Wave 10 adversarial coverage for the
// trust boundary: open-redirect rejection, origin-pattern fuzzing, and
// concurrent trust evaluation.
//
// Upstream references (pinned Better Auth v1.7.5 at 5468e6bf):
//   - packages/better-auth/src/utils/trusted-origins.ts (origin matching,
//     wildcard shapes, custom-scheme authority + path pinning)
//   - packages/better-auth/src/context/helpers.ts (getTrustedOrigins)
//   - vendor trusted-origins.test.ts cases (exact origins, wildcards,
//     relative allowRelativePaths mode, control-character and encoded-
//     separator rejection)
//
// The evil/safe redirect matrix below is additionally checked into
// auth/testdata/wave10_redirects.json and consumed by
// auth/testutil/wave10_vectors_test.go so the same vectors pin both the Go
// implementation here and any cross-language reader. Work limits pinned for
// this file: fuzz URLs/patterns are capped at 2KiB; larger inputs skip. No
// production code is changed here.

import (
	"net/http"
	"strings"
	"sync"
	"testing"
)

func wave10RedirectOpts() Options {
	return Options{
		BaseURL:        "https://app.example.com",
		TrustedOrigins: []string{"https://trusted.example.com", "https://*.wildcard.example.com"},
	}
}

// Open-redirect matrix: attacker-controlled URLs must never be trusted as
// redirects under the default configuration, while first-party URLs are.
// Every row mirrors a class from the upstream trusted-origins tests.
func TestWave10_OpenRedirectEvilMatrix(t *testing.T) {
	opts := wave10RedirectOpts()
	evil := []string{
		// Scheme confusion.
		"javascript:alert(1)",
		"JaVaScRiPt:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"vbscript:msgbox(1)",
		"file:///etc/passwd",
		// Authority confusion.
		"https://app.example.com.attacker.com/",
		"https://attacker.com/?x=https://app.example.com",
		"https://trusted.example.com.attacker.com/",
		"//evil.com/phish",
		"https:///evil.com",
		// Backslash / separator smuggling.
		`https://app.example.com\evil.com`,
		`/\\evil.com`,
		`/\evil.com`,
		// Encoded separators in the path.
		"/%2f/evil.com",
		"/%2Fevil.com",
		"/%5cevil.com",
		"https://app.example.com/%2f..%2f..%2fetc",
		// Control characters.
		"/dash\x00board",
		"/dash\x1fboard",
		"/dash\x7fboard",
		"https://app.example.com/\nSet-Cookie: x=1",
		// Custom-scheme authority escape.
		"myapp://callback.attacker.tld",
		// Wildcard escape: the *.wildcard pattern must not match siblings.
		"https://wildcard.example.com.evil.com/",
		"https://evilwildcard.example.com/",
		// Non-URL garbage.
		"",
		"not a url",
		"::::",
	}
	for _, raw := range evil {
		if IsTrustedRedirect(raw, opts, nil) {
			t.Errorf("evil redirect %q must not be trusted", raw)
		}
	}
	safe := []string{
		"/dashboard",
		"/callback?next=%2Fdashboard",
		"/oauth2/callback?x=1#frag",
		"https://app.example.com/any/path?q=1",
		"https://app.example.com:443/explicit-default-port",
		"https://trusted.example.com/x",
		"https://a.wildcard.example.com/x",
	}
	for _, raw := range safe {
		if !IsTrustedRedirect(raw, opts, nil) {
			t.Errorf("safe redirect %q must be trusted", raw)
		}
	}
}

// Trust evaluation is pure and race-clean under burst: static lists plus
// per-request resolvers compose deterministically across goroutines.
func TestWave10_TrustEvaluationConcurrentUse(t *testing.T) {
	base := wave10RedirectOpts()
	base.TrustedOriginsFunc = func(r *http.Request) []string {
		if r != nil && r.Header.Get("X-Tenant") == "acme" {
			return []string{"https://acme.example.com"}
		}
		return nil
	}
	urls := []string{
		"/dashboard",
		"https://app.example.com/x",
		"https://acme.example.com/x",
		"https://evil.com/x",
		"javascript:alert(1)",
		"https://a.wildcard.example.com/x",
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				req, _ := http.NewRequest("GET", "https://app.example.com/", nil)
				if g%2 == 0 {
					req.Header.Set("X-Tenant", "acme")
				}
				for _, u := range urls {
					_ = IsTrustedOrigin(u, base, req)
					_ = IsTrustedRedirect(u, base, req)
					_ = MatchesOriginPattern(u, "https://*.wildcard.example.com")
					_ = CollectTrustedOrigins(base.TrustedOrigins, req, base.TrustedOriginsFunc)
				}
			}
		}(g)
	}
	wg.Wait()

	// The resolver result is tenant-scoped: acme origins trust only on acme
	// requests, even under concurrency.
	acmeReq, _ := http.NewRequest("GET", "https://app.example.com/", nil)
	acmeReq.Header.Set("X-Tenant", "acme")
	if !IsTrustedOrigin("https://acme.example.com/x", base, acmeReq) {
		t.Error("tenant resolver origin must trust on tenant requests")
	}
	plainReq, _ := http.NewRequest("GET", "https://app.example.com/", nil)
	if IsTrustedOrigin("https://acme.example.com/x", base, plainReq) {
		t.Error("tenant resolver origin must not trust off-tenant requests")
	}
}

// FuzzWave10_MatchesOriginPattern fuzzes the origin matcher: it never
// panics, empty inputs never match, decoding is deterministic, and
// non-http(s) URLs never match web wildcard patterns (no scheme confusion
// through the wildcard path).
func FuzzWave10_MatchesOriginPattern(f *testing.F) {
	f.Add("https://app.example.com/cb", "https://app.example.com")
	f.Add("https://a.wildcard.example.com/x", "https://*.wildcard.example.com")
	f.Add("javascript:alert(1)", "https://*.example.com")
	f.Add("/relative", "https://app.example.com")
	f.Add("myapp://callback/a", "myapp://callback")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, rawURL, pattern string) {
		if len(rawURL) > 2048 || len(pattern) > 2048 {
			t.Skip("over wave10 2KiB cap")
		}
		got := MatchesOriginPattern(rawURL, pattern)
		if again := MatchesOriginPattern(rawURL, pattern); again != got {
			t.Fatalf("nondeterministic match of %q against %q", rawURL, pattern)
		}
		if rawURL == "" || pattern == "" {
			if got {
				t.Fatalf("empty input must never match: %q against %q", rawURL, pattern)
			}
			return
		}
		if got && isWebWildcardPattern(pattern) && !isHTTPURL(rawURL) {
			t.Fatalf("non-http URL %q matched web wildcard %q", rawURL, pattern)
		}
	})
}

// FuzzWave10_RelativeRedirectSafety fuzzes the allowRelativePaths gate:
// every trusted "/" URL must satisfy the safe-relative shape (no "//"
// prefix, no backslash, no control characters, no encoded path separator in
// the path slice).
func FuzzWave10_RelativeRedirectSafety(f *testing.F) {
	f.Add("/dashboard")
	f.Add("//evil.com")
	f.Add("/%2Fevil.com")
	f.Add("/ok?next=%2Ffine#frag")
	f.Add("/bad\\slash")
	f.Fuzz(func(t *testing.T, path string) {
		if len(path) > 2048 {
			t.Skip("over wave10 2KiB cap")
		}
		raw := path
		if !strings.HasPrefix(raw, "/") {
			raw = "/" + raw
		}
		opts := Options{BaseURL: "https://app.example.com"}
		if !IsTrustedRedirect(raw, opts, nil) {
			return
		}
		if strings.HasPrefix(raw, "//") {
			t.Fatalf("protocol-relative %q trusted", raw)
		}
		if strings.Contains(raw, "\\") {
			t.Fatalf("backslash URL %q trusted", raw)
		}
		for _, r := range raw {
			if r <= 0x1f || (r >= 0x7f && r <= 0x9f) {
				t.Fatalf("control-char URL %q trusted", raw)
			}
		}
		slice := raw
		if i := strings.IndexAny(slice, "?#"); i >= 0 {
			slice = slice[:i]
		}
		if lower := strings.ToLower(slice); strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
			t.Fatalf("encoded-separator path %q trusted", raw)
		}
	})
}

func isWebWildcardPattern(pattern string) bool {
	lower := strings.ToLower(pattern)
	if !strings.ContainsAny(pattern, "*?") {
		return false
	}
	idx := strings.Index(lower, "://")
	if idx <= 0 {
		return false
	}
	scheme := lower[:idx]
	return scheme == "http" || scheme == "https"
}

func isHTTPURL(rawURL string) bool {
	lower := strings.ToLower(rawURL)
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}
