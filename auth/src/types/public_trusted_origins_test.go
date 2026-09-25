package types

import (
	"net/http"
	"reflect"
	"testing"
)

func mustMatch(t *testing.T, rawURL, pattern string, want bool) {
	t.Helper()
	if got := MatchesOriginPattern(rawURL, pattern); got != want {
		t.Errorf("MatchesOriginPattern(%q, %q) = %v, want %v", rawURL, pattern, got, want)
	}
}

func mustTrusted(t *testing.T, rawURL string, opts Options, r *http.Request, want bool) {
	t.Helper()
	if got := IsTrustedOrigin(rawURL, opts, r); got != want {
		t.Errorf("IsTrustedOrigin(%q) = %v, want %v", rawURL, got, want)
	}
}

func mustRedirect(t *testing.T, rawURL string, opts Options, want bool) {
	t.Helper()
	if got := IsTrustedRedirect(rawURL, opts, nil); got != want {
		t.Errorf("IsTrustedRedirect(%q) = %v, want %v", rawURL, got, want)
	}
}

// Upstream: trusted origins list support

func TestPublicTrustedOrigins_AppOriginAlwaysTrusted(t *testing.T) {
	opts := Options{BaseURL: "http://localhost:3000"}
	mustTrusted(t, "http://localhost:3000", opts, nil, true)
	mustTrusted(t, "http://localhost:3000/some/path", opts, nil, true)
}

func TestPublicTrustedOrigins_RejectPrefixAndSubdomain(t *testing.T) {
	opts := Options{TrustedOrigins: []string{"https://trusted.com"}}
	mustTrusted(t, "https://trusted.com", opts, nil, true)
	mustTrusted(t, "https://trusted.com/some/path", opts, nil, true)
	mustTrusted(t, "https://trusted.com.malicious.com", opts, nil, false)
	mustTrusted(t, "http://sub-domain.trusted.com", opts, nil, false)
}

// Upstream: relative paths support

func TestPublicTrustedOrigins_RelativeDefaultReject(t *testing.T) {
	opts := Options{BaseURL: "http://localhost:3000"}
	mustMatch(t, "/", "http://localhost:3000", false)
	mustMatch(t, "/some-absolute-url", "http://localhost:3000", false)
	mustTrusted(t, "/", opts, nil, false)
	mustTrusted(t, "/my-team/~settings/account", opts, nil, false)
}

func TestPublicTrustedOrigins_RelativeAllowList(t *testing.T) {
	opts := Options{BaseURL: "http://localhost:3000"}
	for _, u := range []string{
		"/",
		"/dashboard",
		"/dashboard?email=123@email.com",
		"/dashboard+page?test=123+456",
		"/my-team/~settings/account",
		"/~settings?next=/~account",
		"/docs/!$&'()*+,;=:@~",
		"/café#profile",
		"/search?next=/settings?tab=security",
		"/callback?next=%2Fdashboard",
		"/profile#section?tab=security",
		"/#%2f%2fevil.com",
	} {
		mustRedirect(t, u, opts, true)
		if got := MatchesOriginPatternAllowRelative(u, "http://localhost:3000", true); !got {
			t.Errorf("allow-relative MatchesOriginPattern(%q) = false, want true", u)
		}
		if got := MatchesOriginPatternAllowRelative(u, "http://localhost:3000", false); got {
			t.Errorf("deny-relative MatchesOriginPattern(%q) = true, want false", u)
		}
	}
}

func TestPublicTrustedOrigins_RelativeAmbiguousAndEncoded(t *testing.T) {
	opts := Options{BaseURL: "http://localhost:3000"}
	for _, u := range []string{
		"//evil.com",
		"///evil.com",
		`/\\evil.com`,
		"/%2f/evil.com",
		"/%2F/evil.com",
		"/%5c/evil.com",
		"/%5C/evil.com",
		"/safe/%2f/evil.com",
		"/safe/%2F/evil.com",
		"/safe/%5c/evil.com",
		"/safe/%5C/evil.com",
		"/%2f/evil.com#section",
		`/\\/\\/evil.com`,
		"/..%2F..%2Fevil.com",
		"/\u0000evil.com",
		"/\u007fevil.com",
		"/\u0085evil.com",
		"/\t/evil.com",
		"/\n/evil.com",
		"/\r/evil.com",
	} {
		mustRedirect(t, u, opts, false)
		if got := MatchesOriginPatternAllowRelative(u, "http://localhost:3000", true); got {
			t.Errorf("allow-relative MatchesOriginPattern(%q) = true, want false", u)
		}
	}
	mustMatch(t, "javascript:alert('xss')", "https://trusted.com", false)
	mustMatch(t, "data:text/html,<script>alert('xss')</script>", "https://trusted.com", false)
}

// Upstream: wildcards support

func TestPublicTrustedOrigins_HostWildcard(t *testing.T) {
	opts := Options{TrustedOrigins: []string{"*.my-site.com"}}
	mustTrusted(t, "https://sub-domain.my-site.com", opts, nil, true)
	mustTrusted(t, "https://sub-domain.my-site.com/callback", opts, nil, true)
	mustTrusted(t, "https://another-sub.my-site.com", opts, nil, true)
	mustTrusted(t, "https://another-sub.my-site.com/callback", opts, nil, true)
	mustTrusted(t, "https://my-site.com", opts, nil, false)
}

func TestPublicTrustedOrigins_MaliciousWildcardHost(t *testing.T) {
	opts := Options{TrustedOrigins: []string{"*.example.com"}}
	mustTrusted(t, "malicious.com?.example.com", opts, nil, false)
}

func TestPublicTrustedOrigins_ProtocolWildcard(t *testing.T) {
	opts := Options{TrustedOrigins: []string{"https://*.protocol-site.com"}}
	mustTrusted(t, "https://api.protocol-site.com", opts, nil, true)
	mustTrusted(t, "http://api.protocol-site.com", opts, nil, false)
}

func TestPublicTrustedOrigins_CustomSchemeWildcards(t *testing.T) {
	opts := Options{TrustedOrigins: []string{
		"exp://10.0.0.*:*/*",
		"exp://192.168.*.*:*/*",
		"exp://172.*.*.*:*/*",
	}}
	mustTrusted(t, "exp://10.0.0.29:8081/--/", opts, nil, true)
	mustTrusted(t, "exp://192.168.1.100:8081/--/", opts, nil, true)
	mustTrusted(t, "exp://172.16.0.1:8081/--/", opts, nil, true)
	mustTrusted(t, "exp://203.0.113.0:8081/--/", opts, nil, false)
}

// Upstream: custom-scheme origin matching

func TestPublicTrustedOrigins_CustomSchemeExact(t *testing.T) {
	opts := Options{TrustedOrigins: []string{"myapp://callback"}}
	mustTrusted(t, "myapp://callback", opts, nil, true)
	mustTrusted(t, "myapp://callback/", opts, nil, true)
	mustTrusted(t, "myapp://callback/path", opts, nil, true)
	mustTrusted(t, "myapp://callback?token=x", opts, nil, true)
	mustTrusted(t, "myapp://callback#frag", opts, nil, true)
	mustTrusted(t, "myapp://callback.attacker.tld", opts, nil, false)
	mustTrusted(t, "myapp://callback.attacker.tld/path", opts, nil, false)
	mustTrusted(t, "otherapp://callback", opts, nil, false)
}

func TestPublicTrustedOrigins_CustomSchemeControlChars(t *testing.T) {
	opts := Options{TrustedOrigins: []string{"myapp://callback"}}
	mustTrusted(t, "myapp://callback?##########\n\n", opts, nil, false)
}

func TestPublicTrustedOrigins_CustomSchemeEmptyHost(t *testing.T) {
	opts := Options{TrustedOrigins: []string{"myapp:/"}}
	mustTrusted(t, "myapp:/", opts, nil, true)
	mustTrusted(t, "myapp://", opts, nil, true)
	mustTrusted(t, "myapp:/auth/callback", opts, nil, true)
}

func TestPublicTrustedOrigins_CustomSchemeHostlessTrustsAnyHost(t *testing.T) {
	opts := Options{TrustedOrigins: []string{"exp://", "myapp://"}}
	mustTrusted(t, "exp://192.168.1.5:8081/--/", opts, nil, true)
	mustTrusted(t, "exp://localhost:8081/--/", opts, nil, true)
	mustTrusted(t, "myapp://callback", opts, nil, true)
	mustTrusted(t, "myapp://other-host/path", opts, nil, true)
	mustTrusted(t, "evil://anything", opts, nil, false)
}

func TestPublicTrustedOrigins_CustomSchemeCaseInsensitive(t *testing.T) {
	opts := Options{TrustedOrigins: []string{"myapp://callback"}}
	mustTrusted(t, "myapp://CALLBACK", opts, nil, true)
	mustTrusted(t, "MyApp://Callback", opts, nil, true)
}

func TestPublicTrustedOrigins_CustomSchemePathPinning(t *testing.T) {
	opts := Options{TrustedOrigins: []string{"myapp://host/cb"}}
	mustTrusted(t, "myapp://host/cb", opts, nil, true)
	mustTrusted(t, "myapp://host/cb/extra", opts, nil, true)
	mustTrusted(t, "myapp://host/cbx", opts, nil, false)
	mustTrusted(t, "myapp://host/other", opts, nil, false)
}

func TestPublicTrustedOrigins_CustomSchemeTraversalBypass(t *testing.T) {
	opts := Options{TrustedOrigins: []string{"myapp://host/cb"}}
	mustTrusted(t, "myapp://host/cb/../evil", opts, nil, false)
	mustTrusted(t, "myapp://host/cb/%2e%2e/evil", opts, nil, false)
	mustTrusted(t, "myapp://host/cb%2f..%2fevil", opts, nil, false)
}

func TestPublicTrustedOrigins_CustomSchemeWildcardStillWorks(t *testing.T) {
	opts := Options{TrustedOrigins: []string{"exp://192.168.*.*:*/*"}}
	mustTrusted(t, "exp://192.168.1.100:8081/--/", opts, nil, true)
	mustTrusted(t, "exp://10.0.0.1:8081/--/", opts, nil, false)
}

// Canonicalization

func TestPublicTrustedOrigins_Canonicalization(t *testing.T) {
	opts := Options{TrustedOrigins: []string{"https://example.com"}}
	mustTrusted(t, "https://EXAMPLE.com", opts, nil, true)
	mustTrusted(t, "https://example.com.", opts, nil, true)
	mustTrusted(t, "https://example.com:443", opts, nil, true)
	mustTrusted(t, "https://example.com:8443", opts, nil, false)

	httpOpts := Options{TrustedOrigins: []string{"http://example.com"}}
	mustTrusted(t, "http://example.com:80", httpOpts, nil, true)
	mustTrusted(t, "http://example.com:8080", httpOpts, nil, false)

	baseOpts := Options{BaseURL: "https://Example.COM:443/api/auth"}
	mustTrusted(t, "https://example.com/dashboard", baseOpts, nil, true)
}

// Absolute hardening: backslash / control / encoded separators

func TestPublicTrustedOrigins_AbsoluteHardening(t *testing.T) {
	opts := Options{TrustedOrigins: []string{"https://trusted.com"}}
	mustTrusted(t, "https://trusted.com/ok/path", opts, nil, true)
	mustTrusted(t, `https://trusted.com\evil`, opts, nil, false)
	mustTrusted(t, "https://trusted.com/\u0000evil", opts, nil, false)
	mustTrusted(t, "https://trusted.com/safe%2famd", opts, nil, false)
	mustTrusted(t, "https://trusted.com/safe%5cAMD", opts, nil, false)
	mustTrusted(t, "https://trusted.com/callback?next=%2Fdashboard", opts, nil, true)
	mustTrusted(t, "https://trusted.com@evil.com", opts, nil, false)
	mustTrusted(t, "https://trusted.com.evil.com", opts, nil, false)
}

// Request-aware resolution + env

func TestPublicTrustedOrigins_RequestAwareResolver(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://app.example.com/", nil)
	opts := Options{
		TrustedOrigins: []string{"https://static.example.com", ""},
		TrustedOriginsFunc: func(r *http.Request) []string {
			if r == nil {
				return nil
			}
			return []string{"https://dynamic.example.com", ""}
		},
	}
	mustTrusted(t, "https://static.example.com", opts, req, true)
	mustTrusted(t, "https://dynamic.example.com/x", opts, req, true)
	mustTrusted(t, "https://dynamic.example.com/x", opts, nil, false)
	mustTrusted(t, "https://unknown.example.com", opts, req, false)

	got := ResolveTrustedOrigins(opts, req)
	for _, origin := range got {
		if origin == "" {
			t.Fatal("ResolveTrustedOrigins must filter empty entries")
		}
	}
}

func TestPublicTrustedOrigins_ResolverTypeCompatible(t *testing.T) {
	var resolver TrustedOriginsResolver = func(r *http.Request) []string {
		return []string{"https://via-type.example.com"}
	}
	got := CollectTrustedOrigins([]string{"https://static.example.com"}, nil, nil, resolver)
	want := []string{"https://static.example.com", "https://via-type.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("CollectTrustedOrigins = %#v, want %#v", got, want)
	}
}

func TestPublicTrustedOrigins_EnvParsingPure(t *testing.T) {
	if TrustedOriginsEnvVar != "BETTER_AUTH_TRUSTED_ORIGINS" {
		t.Fatalf("TrustedOriginsEnvVar = %q", TrustedOriginsEnvVar)
	}
	got := ParseTrustedOriginsEnv("http://app1.com,http://app2.com")
	want := []string{"http://app1.com", "http://app2.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseTrustedOriginsEnv = %#v, want %#v", got, want)
	}
	if got := ParseTrustedOriginsEnv(""); len(got) != 0 {
		t.Fatalf("empty env must parse to empty, got %#v", got)
	}
	if got := ParseTrustedOriginsEnv(" , http://a.com ,,http://b.com, "); !reflect.DeepEqual(got, []string{"http://a.com", "http://b.com"}) {
		t.Fatalf("env whitespace/empties must be filtered, got %#v", got)
	}

	opts := Options{BaseURL: "http://localhost:3000", TrustedOrigins: []string{"", "http://valid.com"}}
	resolved := ResolveTrustedOriginsWithEnv(opts, nil, "http://app1.com,,http://app2.com")
	for _, wantOrigin := range []string{"http://localhost:3000", "http://valid.com", "http://app1.com", "http://app2.com"} {
		found := false
		for _, origin := range resolved {
			if origin == wantOrigin {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("resolved origins %#v missing %q", resolved, wantOrigin)
		}
	}
	if got := IsTrustedOriginWithEnv("http://app2.com/x", opts, nil, "http://app1.com,http://app2.com"); !got {
		t.Error("IsTrustedOriginWithEnv must trust env-listed origins")
	}
	if got := IsTrustedOriginWithEnv("http://evil.com", opts, nil, "http://app1.com,http://app2.com"); got {
		t.Error("IsTrustedOriginWithEnv must reject unlisted origins")
	}
}

func TestPublicTrustedOrigins_FilterNeverMutatesInput(t *testing.T) {
	in := []string{"", "https://a.example.com", ""}
	got := FilterTrustedOrigins(in)
	if !reflect.DeepEqual(got, []string{"https://a.example.com"}) {
		t.Fatalf("FilterTrustedOrigins = %#v", got)
	}
	if !reflect.DeepEqual(in, []string{"", "https://a.example.com", ""}) {
		t.Fatalf("FilterTrustedOrigins mutated input: %#v", in)
	}
}

func TestPublicTrustedOrigins_IDNADecision(t *testing.T) {
	// Upstream's WHATWG URL parser would emit punycode for both sides and
	mustMatch(t, "https://münchen.example.com/cb", "https://münchen.example.com", true)
	mustMatch(t, "https://xn--mnchen-3ya.example.com/cb", "https://xn--mnchen-3ya.example.com", true)
	mustMatch(t, "https://münchen.example.com/cb", "https://xn--mnchen-3ya.example.com", false)
	mustMatch(t, "https://xn--mnchen-3ya.example.com/cb", "https://münchen.example.com", false)
	mustMatch(t, "https://MÜNCHEN.example.com/cb", "https://münchen.example.com", true)
}
