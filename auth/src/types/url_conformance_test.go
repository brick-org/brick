package types

// wave4_conformance_test.go: upstream conformance (Better Auth v1.7.5).

import (
	"net/http"
	"strings"
	"sync"
	"testing"
)


// Upstream: "should reject relative paths with tildes when relative paths
func TestURLConformance_RelativeTildePaths(t *testing.T) {
	allowed := []string{"/my-team/~settings/account", "/~settings?next=/~account"}
	for _, raw := range allowed {
		if !MatchesOriginPatternAllowRelative(raw, "https://app.example.com", true) {
			t.Errorf("tilde path %q must be trusted with allowRelativePaths=true", raw)
		}
		if MatchesOriginPatternAllowRelative(raw, "https://app.example.com", false) {
			t.Errorf("tilde path %q must be rejected with allowRelativePaths=false", raw)
		}
		if MatchesOriginPattern(raw, "https://app.example.com") {
			t.Errorf("tilde path %q must be rejected by the default matcher", raw)
		}
	}
}

// Upstream: "should allow standards-compliant relative URLs". These exercise
func TestURLConformance_StandardsCompliantRelativeURLs(t *testing.T) {
	allowed := []string{
		"/docs/!$&'()*+,;=:@~",
		"/café#profile",
		"/search?next=/settings?tab=security",
		"/callback?next=%2Fdashboard",
		"/profile#section?tab=security",
		"/#%2f%2fevil.com",
	}
	for _, raw := range allowed {
		if !MatchesOriginPatternAllowRelative(raw, "https://app.example.com", true) {
			t.Errorf("standards-compliant relative URL %q must be trusted", raw)
		}
	}
}

// Upstream: "should reject urls with malicious domain with wildcard trusted
func TestURLConformance_MaliciousWildcardQueryHost(t *testing.T) {
	if MatchesOriginPattern("malicious.com?.example.com", "*.example.com") {
		t.Fatal("query-embedded wildcard suffix must not match")
	}
	if MatchesOriginPattern("https://malicious.com?.example.com/", "https://*.example.com") {
		t.Fatal("query-embedded wildcard suffix must not match (protocol wildcard)")
	}
}

// Upstream: "should reject urls with encoded malicious content" (non-web
func TestURLConformance_NonWebSchemesRejected(t *testing.T) {
	for _, raw := range []string{
		"javascript:alert('xss')",
		"data:text/html,<script>alert('xss')</script>",
	} {
		if MatchesOriginPattern(raw, "https://app.example.com") {
			t.Errorf("non-web URL %q must be rejected", raw)
		}
		if MatchesOriginPatternAllowRelative(raw, "https://app.example.com", true) {
			t.Errorf("non-web URL %q must be rejected even with allowRelativePaths", raw)
		}
	}
}

// Upstream: "should reject control characters in custom-scheme URLs" — a
func TestURLConformance_CustomSchemeLongControlFragment(t *testing.T) {
	raw := "myapp://callback?" + strings.Repeat("#", 10000) + "\n\n"
	if MatchesOriginPattern(raw, "myapp://callback") {
		t.Fatal("custom-scheme URL with control characters must be rejected")
	}
}

// Upstream: "should trust any host for a host-less custom-scheme pattern"
func TestURLConformance_HostlessCustomSchemeTrustsAnyHost(t *testing.T) {
	for _, raw := range []string{
		"exp://192.168.1.5:8081/--/",
		"exp://localhost:8081/--/",
		"myapp://callback",
		"myapp://other-host/path",
	} {
		pattern := "exp://"
		if strings.HasPrefix(raw, "myapp://") {
			pattern = "myapp://"
		}
		if !MatchesOriginPattern(raw, pattern) {
			t.Errorf("host-less pattern %q must trust %q", pattern, raw)
		}
	}
	if MatchesOriginPattern("evil://anything", "exp://") {
		t.Fatal("host-less pattern must not cross schemes")
	}
}

// Upstream: "should still allow hosts with explicit protocol in the host
func TestURLConformance_DefaultPortCanonicalization(t *testing.T) {
	cases := []struct{ raw, pattern string }{
		{"http://example.com:80/", "http://example.com"},
		{"https://example.com:443/cb", "https://example.com"},
		{"http://example.com:8080/", "http://example.com"},
	}
	for _, c := range cases[:2] {
		if !MatchesOriginPattern(c.raw, c.pattern) {
			t.Errorf("default port must canonicalize: %q vs %q", c.raw, c.pattern)
		}
	}
	if MatchesOriginPattern(cases[2].raw, cases[2].pattern) {
		t.Errorf("non-default port must not canonicalize: %q vs %q", cases[2].raw, cases[2].pattern)
	}
}

// Cross-language golden vectors

var wave4OriginGoldenVectors = []struct {
	name    string
	raw     string
	pattern string
	allow   bool
	want    bool
}{
	{"app origin exact", "http://localhost:3000", "http://localhost:3000", false, true},
	{"app origin path", "http://localhost:3000/some/path", "http://localhost:3000", false, true},
	{"prefix attack", "https://trusted.com.malicious.com", "https://trusted.com", false, false},
	{"untrusted subdomain", "http://sub-domain.trusted.com", "https://trusted.com", false, false},
	{"direct match", "https://trusted.com", "https://trusted.com", false, true},
	{"direct match path", "https://trusted.com/some/path", "https://trusted.com", false, true},
	{"relative default reject root", "/", "https://app.example.com", false, false},
	{"relative default reject path", "/some-absolute-url", "https://app.example.com", false, false},
	{"relative allow root", "/", "https://app.example.com", true, true},
	{"relative allow dashboard", "/dashboard", "https://app.example.com", true, true},
	{"relative allow query", "/dashboard?email=123@email.com", "https://app.example.com", true, true},
	{"relative allow plus", "/dashboard+page?test=123+456", "https://app.example.com", true, true},
	{"ambiguous double slash", "//evil.com", "https://app.example.com", true, false},
	{"ambiguous triple slash", "///evil.com", "https://app.example.com", true, false},
	{"ambiguous backslash", `/\evil.com`, "https://app.example.com", true, false},
	{"encoded sep %2f", "/%2f/evil.com", "https://app.example.com", true, false},
	{"encoded sep %2F", "/%2F/evil.com", "https://app.example.com", true, false},
	{"encoded sep %5c", "/%5c/evil.com", "https://app.example.com", true, false},
	{"encoded traversal", "/..%2F..%2Fevil.com", "https://app.example.com", true, false},
	{"null byte", "/\x00evil.com", "https://app.example.com", true, false},
	{"del char", "/\x7fevil.com", "https://app.example.com", true, false},
	{"wildcard sub", "https://sub-domain.my-site.com", "*.my-site.com", false, true},
	{"wildcard sub callback", "https://sub-domain.my-site.com/callback", "*.my-site.com", false, true},
	{"wildcard malicious query", "malicious.com?.example.com", "*.example.com", false, false},
	{"protocol wildcard https", "https://api.protocol-site.com", "https://*.protocol-site.com", false, true},
	{"protocol wildcard http rejected", "http://api.protocol-site.com", "https://*.protocol-site.com", false, false},
	{"expo wildcard", "exp://10.0.0.29:8081/--/", "exp://10.0.0.*:*/*", false, true},
	{"expo wildcard no match", "exp://203.0.113.0:8081/--/", "exp://10.0.0.*:*/*", false, false},
	{"custom exact", "myapp://callback", "myapp://callback", false, true},
	{"custom exact trailing slash", "myapp://callback/", "myapp://callback", false, true},
	{"custom exact path", "myapp://callback/path", "myapp://callback", false, true},
	{"custom exact query", "myapp://callback?token=x", "myapp://callback", false, true},
	{"custom exact fragment", "myapp://callback#frag", "myapp://callback", false, true},
	{"custom host extension", "myapp://callback.attacker.tld", "myapp://callback", false, false},
	{"custom host extension path", "myapp://callback.attacker.tld/path", "myapp://callback", false, false},
	{"custom empty host", "myapp:/auth/callback", "myapp:/", false, true},
	{"custom scheme mismatch", "otherapp://callback", "myapp://callback", false, false},
	{"custom case insensitive", "MyApp://Callback", "myapp://callback", false, true},
	{"custom path pin", "myapp://host/cb/extra", "myapp://host/cb", false, true},
	{"custom path pin sibling", "myapp://host/cbx", "myapp://host/cb", false, false},
	{"custom path pin other", "myapp://host/other", "myapp://host/cb", false, false},
	{"custom traversal", "myapp://host/cb/../evil", "myapp://host/cb", false, false},
	{"custom traversal encoded", "myapp://host/cb/%2e%2e/evil", "myapp://host/cb", false, false},
}

func TestURLConformance_OriginGoldenVectors(t *testing.T) {
	for _, v := range wave4OriginGoldenVectors {
		var got bool
		if v.allow {
			got = MatchesOriginPatternAllowRelative(v.raw, v.pattern, true)
		} else {
			got = MatchesOriginPattern(v.raw, v.pattern)
		}
		if got != v.want {
			t.Errorf("%s: MatchesOriginPattern(%q, %q) = %v, want %v",
				v.name, v.raw, v.pattern, got, v.want)
		}
	}
}

// Malformed-input limits

func TestURLConformance_MatcherMalformedInputLimits(t *testing.T) {
	huge := strings.Repeat("a", 1<<20)
	starBomb := strings.Repeat("*a", 20000) + strings.Repeat("b", 20000)
	cases := []struct {
		name    string
		raw     string
		pattern string
		want    bool
	}{
		{"empty raw", "", "https://example.com", false},
		{"empty pattern", "https://example.com", "", false},
		{"both empty", "", "", false},
		{"1MB raw", huge, "https://example.com", false},
		{"1MB pattern", "https://example.com", huge, false},
		{"wildcard bomb", starBomb, strings.Repeat("a*b", 20000), false},
		{"null bytes", "https://exam\x00ple.com", "https://example.com", false},
		{"invalid utf8 raw", "https://\xff\xfe.example.com", "https://example.com", false},
		{"backslash absolute", `https://example.com\evil`, "https://example.com", false},
		{"whitespace pattern", "https://example.com", "  https://example.com  ", false},
	}
	for _, c := range cases {
		if got := MatchesOriginPattern(c.raw, c.pattern); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// Race tests

func TestURLConformance_MatcherConcurrentUse(t *testing.T) {
	opts := Options{
		BaseURL:        "https://app.example.com",
		TrustedOrigins: []string{"https://*.example.com", "myapp://callback", "*.my-site.com"},
		TrustedOriginsFunc: func(r *http.Request) []string {
			return nil
		},
	}
	_ = opts
	vectors := wave4OriginGoldenVectors
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				for _, v := range vectors {
					_ = MatchesOriginPattern(v.raw, v.pattern)
					_ = MatchesOriginPatternAllowRelative(v.raw, v.pattern, v.allow)
					_ = WildcardMatch(v.pattern, v.raw)
					_ = IsTrustedOrigin(v.raw, opts, nil)
				}
				_ = ResolveTrustedOrigins(opts, nil)
				_ = ParseTrustedOriginsEnv("https://a.example, https://b.example,,")
				_ = FilterTrustedOrigins([]string{"https://a.example", ""})
			}
		}(g)
	}
	wg.Wait()
}

// Fuzz targets

func FuzzMatchesOriginPattern(f *testing.F) {
	seeds := [][2]string{
		{"https://trusted.com", "https://trusted.com"},
		{"https://trusted.com.evil.com", "https://trusted.com"},
		{"https://sub.my-site.com/cb", "*.my-site.com"},
		{"malicious.com?.example.com", "*.example.com"},
		{"/dashboard", "https://app.example.com"},
		{"myapp://host/cb/../evil", "myapp://host/cb"},
		{"exp://192.168.1.100:8081/--/", "exp://192.168.*.*:*/*"},
		{"javascript:alert(1)", "https://app.example.com"},
		{"", ""},
	}
	for _, s := range seeds {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, rawURL, pattern string) {
		got := MatchesOriginPattern(rawURL, pattern)
		if rawURL == "" || pattern == "" {
			if got {
				t.Fatalf("empty input must never match: %q %q", rawURL, pattern)
			}
			return
		}
		if strings.HasPrefix(rawURL, "/") && got {
			t.Fatalf("relative URL must never match without allowRelativePaths: %q", rawURL)
		}
		if again := MatchesOriginPattern(rawURL, pattern); again != got {
			t.Fatalf("nondeterministic match for %q %q", rawURL, pattern)
		}
	})
}

// naiveWildcardMatch is a memoized reference implementation of *-and-?
// glob matching used to differentially test the greedy WildcardMatch.
func naiveWildcardMatch(pattern, str string) bool {
	memo := map[[2]int]bool{}
	vis := map[[2]int]bool{}
	var rec func(p, s int) bool
	rec = func(p, s int) bool {
		key := [2]int{p, s}
		if v, ok := memo[key]; ok {
			return v
		}
		if vis[key] {
			return false
		}
		vis[key] = true
		defer delete(vis, key)
		var res bool
		switch {
		case p == len(pattern):
			res = s == len(str)
		case pattern[p] == '*':
			res = rec(p+1, s) || (s < len(str) && rec(p, s+1))
		case s < len(str) && (pattern[p] == '?' || pattern[p] == str[s]):
			res = rec(p+1, s+1)
		}
		memo[key] = res
		return res
	}
	return rec(0, 0)
}

func FuzzWildcardMatch(f *testing.F) {
	seeds := [][2]string{
		{"*.example.com", "a.example.com"},
		{"https://*.example.com", "https://a.example.com"},
		{"exp://192.168.*.*:*/*", "exp://192.168.1.100:8081/--/"},
		{"a?c", "abc"},
		{"*", ""},
		{"", ""},
		{"**", "anything"},
	}
	for _, s := range seeds {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, pattern, str string) {
		got := WildcardMatch(pattern, str)
		if len(pattern)+len(str) <= 96 {
			if want := naiveWildcardMatch(pattern, str); got != want {
				t.Fatalf("WildcardMatch(%q, %q) = %v, reference = %v", pattern, str, got, want)
			}
		}
	})
}

func TestURLConformance_WildcardLiteralStarBacktrack(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"*|*0":       true, // pattern "*", input "*0"
		"*|*":        true,
		"a*b|a*b":    true,
		"*a|*a":      true,
		"app*|app*0": true,
		"a?c|a*c":    true,
		"a*c|abc":    true,
		"*|abc":      true,
		"abc|abd":    false,
		"a*d|abc":    false,
	}
	for k, want := range cases {
		parts := strings.SplitN(k, "|", 2)
		if got := WildcardMatch(parts[0], parts[1]); got != want {
			t.Errorf("WildcardMatch(%q, %q) = %v, want %v", parts[0], parts[1], got, want)
		}
	}
}
