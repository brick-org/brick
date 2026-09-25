package api

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/brick-org/brick/auth/src/types"
)

func resolverTestContext(path string) *stubRateLimitContext {
	return &stubRateLimitContext{
		remoteAddr: "127.0.0.1:1234",
		url:        url.URL{Path: "/api/auth" + path},
	}
}

func enabledOptions() types.Options {
	opts := testRateLimitOptions()
	enabled := true
	opts.RateLimit.Enabled = &enabled
	return opts
}

func TestCustomRuleResolvers_OverrideStaticRule(t *testing.T) {
	opts := enabledOptions()
	opts.RateLimit.CustomRuleResolvers = map[string]types.RateLimitRuleResolver{
		"/sign-in/email": func(_ *http.Request, current types.RateLimitRule) (types.RateLimitRule, bool) {
			if current.Max != 3 {
				t.Errorf("resolver must receive the special rule as current, got %+v", current)
			}
			return types.RateLimitRule{Window: 60, Max: 1}, true
		},
	}
	config, ok := resolveRateLimit(resolverTestContext("/sign-in/email"), "/api/auth", opts)
	if !ok {
		t.Fatal("resolver must keep rate limiting enabled")
	}
	if config.Max != 1 || int(config.Window.Seconds()) != 60 {
		t.Fatalf("resolver override not applied, got %+v", config)
	}
}

func TestCustomRuleResolvers_FalseDisablesPath(t *testing.T) {
	opts := enabledOptions()
	opts.RateLimit.CustomRuleResolvers = map[string]types.RateLimitRuleResolver{
		"/get-session": func(_ *http.Request, _ types.RateLimitRule) (types.RateLimitRule, bool) {
			return types.RateLimitRule{}, false
		},
	}
	if _, ok := resolveRateLimit(resolverTestContext("/get-session"), "/api/auth", opts); ok {
		t.Fatal("resolver returning false must disable rate limiting for the path")
	}
}

func TestCustomRuleResolvers_WildcardMatch(t *testing.T) {
	opts := enabledOptions()
	opts.RateLimit.CustomRuleResolvers = map[string]types.RateLimitRuleResolver{
		"/sign-in/*": func(_ *http.Request, _ types.RateLimitRule) (types.RateLimitRule, bool) {
			return types.RateLimitRule{Window: 10, Max: 2}, true
		},
	}
	config, ok := resolveRateLimit(resolverTestContext("/sign-in/email"), "/api/auth", opts)
	if !ok {
		t.Fatal("wildcard resolver must match")
	}
	if config.Max != 2 {
		t.Fatalf("wildcard resolver max not applied, got %+v", config)
	}
}

func TestCustomRuleResolvers_ReceiveRequest(t *testing.T) {
	opts := enabledOptions()
	var seenPath string
	opts.RateLimit.CustomRuleResolvers = map[string]types.RateLimitRuleResolver{
		"/dynamic": func(r *http.Request, current types.RateLimitRule) (types.RateLimitRule, bool) {
			seenPath = r.URL.Path
			return current, true
		},
	}
	if _, ok := resolveRateLimit(resolverTestContext("/dynamic"), "/api/auth", opts); !ok {
		t.Fatal("resolver must keep rate limiting enabled")
	}
	if seenPath != "/api/auth/dynamic" {
		t.Fatalf("resolver must receive the request, saw path %q", seenPath)
	}
}

func TestCustomRuleResolvers_ExactBeatsWildcard(t *testing.T) {
	opts := enabledOptions()
	opts.RateLimit.CustomRuleResolvers = map[string]types.RateLimitRuleResolver{
		"/sign-in/*": func(_ *http.Request, _ types.RateLimitRule) (types.RateLimitRule, bool) {
			return types.RateLimitRule{Window: 10, Max: 9}, true
		},
		"/sign-in/email": func(_ *http.Request, _ types.RateLimitRule) (types.RateLimitRule, bool) {
			return types.RateLimitRule{Window: 10, Max: 7}, true
		},
	}
	config, ok := resolveRateLimit(resolverTestContext("/sign-in/email"), "/api/auth", opts)
	if !ok {
		t.Fatal("resolver must match")
	}
	if config.Max != 7 {
		t.Fatalf("exact resolver must win over wildcard, got %+v", config)
	}
}

func TestDefaultSpecialRules_CoverUpstreamPaths(t *testing.T) {
	for _, path := range []string{
		"/forget-password",
		"/forget-password/callback",
		"/email-otp/send-verification-otp",
		"/email-otp/request-password-reset",
	} {
		rule, ok := defaultRateLimitRule(path)
		if !ok {
			t.Fatalf("special rule must cover upstream path %q", path)
		}
		if rule.Window != 60 || rule.Max != 3 {
			t.Fatalf("path %q rule = %+v, want 60s/3", path, rule)
		}
	}
}
