package api

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/brick-org/brick/auth/src/types"
)

// stubRateLimitPlugin implements types.Plugin plus the rate-limit provider
type stubRateLimitPlugin struct {
	id    string
	rules []types.PluginRateLimitRule
}

func (p *stubRateLimitPlugin) ID() string                   { return p.id }
func (p *stubRateLimitPlugin) Init(types.AuthContext) error { return nil }
func (p *stubRateLimitPlugin) Endpoints() []types.Endpoint  { return nil }
func (p *stubRateLimitPlugin) Schema() types.PluginSchema   { return nil }
func (p *stubRateLimitPlugin) Hooks() types.DBHooks         { return nil }
func (p *stubRateLimitPlugin) RouteHooks() types.PluginRouteHooks {
	return types.PluginRouteHooks{}
}
func (p *stubRateLimitPlugin) ErrorCodes() map[string]string { return nil }
func (p *stubRateLimitPlugin) RateLimitRules() []types.PluginRateLimitRule {
	return p.rules
}

func TestRateLimitEnabled_ProductionDefault(t *testing.T) {
	t.Setenv("NODE_ENV", "production")
	if !rateLimitEnabled(testRateLimitOptions()) {
		t.Fatal("nil Enabled must default to enabled in production (upstream enabled ?? isProduction)")
	}
}

func TestRateLimitEnabled_NonProductionDefault(t *testing.T) {
	t.Setenv("NODE_ENV", "")
	if rateLimitEnabled(testRateLimitOptions()) {
		t.Fatal("nil Enabled must default to disabled outside production")
	}
}

func TestRateLimitEnabled_ExplicitWins(t *testing.T) {
	t.Setenv("NODE_ENV", "production")
	opts := testRateLimitOptions()
	disabled := false
	opts.RateLimit.Enabled = &disabled
	if rateLimitEnabled(opts) {
		t.Fatal("explicit Enabled=false must win over the production default")
	}

	t.Setenv("NODE_ENV", "development")
	enabled := true
	opts.RateLimit.Enabled = &enabled
	if !rateLimitEnabled(opts) {
		t.Fatal("explicit Enabled=true must win outside production")
	}
}

func TestResolveRateLimit_ProductionDefaultEnforces(t *testing.T) {
	t.Setenv("NODE_ENV", "production")
	ctx := &stubRateLimitContext{
		remoteAddr: "127.0.0.1:1234",
		url:        url.URL{Path: "/api/auth/get-session"},
	}
	if _, ok := resolveRateLimit(ctx, "/api/auth", testRateLimitOptions()); !ok {
		t.Fatal("production default must enforce rate limiting without explicit opt-in")
	}
}

func TestPluginRateLimit_DisabledByDefault(t *testing.T) {
	t.Setenv("NODE_ENV", "")
	opts := testRateLimitOptions()
	opts.Plugins = []types.Plugin{
		&stubRateLimitPlugin{
			id: "test-plugin",
			rules: []types.PluginRateLimitRule{
				{Window: 60, Max: 1, PathMatcher: func(path string) bool { return path == "/ok" }},
			},
		},
	}
	ctx := &stubRateLimitContext{
		remoteAddr: "127.0.0.1:1234",
		url:        url.URL{Path: "/api/auth/ok"},
	}
	if _, ok := resolvePluginRateLimit(ctx, "/api/auth", opts); ok {
		t.Fatal("plugin rules must not apply when rate limiting is disabled (upstream enabled gate)")
	}
}

func TestPluginRateLimit_ProxyAwareIPResolution(t *testing.T) {
	opts := enabledOptions()
	opts.Advanced.IPAddress.TrustedProxies = []string{"10.0.0.0/8"}
	opts.Plugins = []types.Plugin{
		&stubRateLimitPlugin{
			id: "test-plugin",
			rules: []types.PluginRateLimitRule{
				{Window: 60, Max: 5, PathMatcher: func(path string) bool { return path == "/ok" }},
			},
		},
	}
	headers := http.Header{"X-Forwarded-For": []string{"203.0.113.7, 10.0.0.5"}}
	ctx := &stubRateLimitContext{
		headers:    headers,
		remoteAddr: "10.0.0.5:1234",
		url:        url.URL{Path: "/api/auth/ok"},
	}
	config, ok := resolvePluginRateLimit(ctx, "/api/auth", opts)
	if !ok {
		t.Fatal("plugin rule must match")
	}
	want := "203.0.113.7|plugin|test-plugin|/ok"
	if config.Key != want {
		t.Fatalf("plugin key = %q, want %q (proxy-aware IP)", config.Key, want)
	}
}

func TestRateLimitNoIP_FailsClosedToSharedBucket(t *testing.T) {
	opts := enabledOptions()
	ctx := &stubRateLimitContext{
		url: url.URL{Path: "/api/auth/get-session"},
	}
	config, ok := resolveRateLimit(ctx, "/api/auth", opts)
	if !ok {
		t.Fatal("missing client IP must fail closed to a shared bucket, not skip limiting")
	}
	want := "no-trusted-ip|/get-session"
	if config.Key != want {
		t.Fatalf("shared-bucket key = %q, want %q", config.Key, want)
	}
}
