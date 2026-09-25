package api

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

// F10 routes-infra coverage (P09-GAP-1..7 + P05-GAP-3 wiring notes).
//
// Upstream refs (pinned Better Auth v1.7.5 at 5468e6bf):
//   - packages/better-auth/src/api/middlewares/origin-check.ts (validateOrigin,
//     validateFormCsrf, shouldSkipOriginCheck, shouldSkipCSRFForBackwardCompat)
//   - packages/better-auth/src/api/rate-limiter/index.ts (single-step consume,
//     wildcardMatch custom-rule lookup)
//   - packages/better-auth/src/utils/wildcard.ts (glob semantics)
//   - packages/better-auth/src/context/create-context.ts:318-351 (refreshCache)
//
// Harness: POST /api/auth/sign-out carries no body and answers 200 without a
// session, so origin/rate-limit decisions are observable without fixtures.

func f10OriginOptions(baseURL string) types.Options {
	return types.Options{BaseURL: baseURL, BasePath: "/api/auth"}
}

// P09-GAP-1: Router must fall back to Referer when Origin is absent
// (upstream `headers.get("origin") || headers.get("referer") || ""`).
func TestF10_OriginRefererFallback_UntrustedRefererRejected(t *testing.T) {
	opts := f10OriginOptions("https://app.example")
	api := Router(humatest.NewAdapter(), "/api/auth", opts)
	resp := humatest.Wrap(t, api).Post("/api/auth/sign-out",
		"Referer: https://evil.example/phish",
		"Cookie: session_token=abc",
	)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("untrusted referer + cookie must be 403, got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestF10_OriginRefererFallback_TrustedRefererPasses(t *testing.T) {
	opts := f10OriginOptions("https://app.example")
	api := Router(humatest.NewAdapter(), "/api/auth", opts)
	resp := humatest.Wrap(t, api).Post("/api/auth/sign-out",
		"Referer: https://app.example/dashboard",
		"Cookie: session_token=abc",
	)
	if resp.Code == http.StatusForbidden {
		t.Fatalf("trusted referer + cookie must pass origin, got 403: %s", resp.Body.String())
	}
}

// P09-GAP-1: `Origin: null` + `Sec-Fetch-Site: same-origin` (same-origin form
// with a no-referrer policy) infers the origin from the request target
// instead of rejecting (upstream validateOrigin inferredOrigin).
func TestF10_NullOrigin_SameOriginInferencePasses(t *testing.T) {
	opts := f10OriginOptions("http://app.example")
	api := Router(humatest.NewAdapter(), "/api/auth", opts)
	resp := humatest.Wrap(t, api).Post("/api/auth/sign-out",
		"Host: app.example",
		"Origin: null",
		"Sec-Fetch-Site: same-origin",
		"Cookie: session_token=abc",
	)
	if resp.Code == http.StatusForbidden {
		t.Fatalf("null origin with same-origin fetch metadata must infer the request origin, got 403: %s", resp.Body.String())
	}
}

func TestF10_NullOrigin_WithoutInferenceRejected(t *testing.T) {
	opts := f10OriginOptions("https://app.example")
	api := Router(humatest.NewAdapter(), "/api/auth", opts)
	resp := humatest.Wrap(t, api).Post("/api/auth/sign-out",
		"Origin: null",
		"Cookie: session_token=abc",
	)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("bare null origin + cookie must be 403, got %d: %s", resp.Code, resp.Body.String())
	}
}

// P09-GAP-2: Fetch-Metadata first-login gate (upstream validateFormCsrf).
// Cross-site navigations are blocked even without cookies.
func TestF10_FormCsrf_CrossSiteNavigateBlocked(t *testing.T) {
	opts := f10OriginOptions("https://app.example")
	api := Router(humatest.NewAdapter(), "/api/auth", opts)
	resp := humatest.Wrap(t, api).Post("/api/auth/sign-out",
		"Sec-Fetch-Site: cross-site",
		"Sec-Fetch-Mode: navigate",
	)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("cross-site navigation must be 403, got %d: %s", resp.Code, resp.Body.String())
	}
}

// P09-GAP-2: cookie-less requests carrying an Origin are force-validated
// (no permissive fallback for browser evidence).
func TestF10_FormCsrf_CookieLessOriginForceValidated(t *testing.T) {
	opts := f10OriginOptions("https://app.example")
	api := Router(humatest.NewAdapter(), "/api/auth", opts)
	resp := humatest.Wrap(t, api).Post("/api/auth/sign-out",
		"Origin: https://evil.example",
	)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("cookie-less untrusted origin must be 403, got %d: %s", resp.Code, resp.Body.String())
	}
}

// P09-GAP-2: non-browser clients (no cookies, no origin, no fetch metadata)
// keep the permissive fallback (curl / server-to-server still work).
func TestF10_FormCsrf_ServerToServerPasses(t *testing.T) {
	opts := f10OriginOptions("https://app.example")
	api := Router(humatest.NewAdapter(), "/api/auth", opts)
	resp := humatest.Wrap(t, api).Post("/api/auth/sign-out")
	if resp.Code == http.StatusForbidden {
		t.Fatalf("server-to-server request must pass, got 403: %s", resp.Body.String())
	}
}

// f10SkipPlugin contributes skip-origin-check paths without any other
// plugin surface (mirrors upstream ctx.skipOriginCheck string[] branch,
// populated upstream by SSO plugin init).
type f10SkipPlugin struct {
	id    string
	paths []string
}

func (p *f10SkipPlugin) ID() string                   { return p.id }
func (p *f10SkipPlugin) Init(types.AuthContext) error { return nil }
func (p *f10SkipPlugin) Endpoints() []types.Endpoint  { return nil }
func (p *f10SkipPlugin) Schema() types.PluginSchema   { return nil }
func (p *f10SkipPlugin) Hooks() types.DBHooks         { return nil }
func (p *f10SkipPlugin) RouteHooks() types.PluginRouteHooks {
	return types.PluginRouteHooks{}
}
func (p *f10SkipPlugin) ErrorCodes() map[string]string  { return nil }
func (p *f10SkipPlugin) SkipOriginCheckPaths() []string { return p.paths }

// P09-GAP-3: skipOriginCheck path-array exempts the listed path from origin
// validation (upstream shouldSkipOriginCheck array branch).
func TestF10_SkipOriginCheckPaths_ArrayHonored(t *testing.T) {
	opts := f10OriginOptions("https://app.example")
	opts.Plugins = []types.Plugin{&f10SkipPlugin{id: "f10-skip", paths: []string{"/sign-out"}}}
	api := Router(humatest.NewAdapter(), "/api/auth", opts)
	resp := humatest.Wrap(t, api).Post("/api/auth/sign-out",
		"Origin: https://evil.example",
		"Cookie: session_token=abc",
	)
	if resp.Code == http.StatusForbidden {
		t.Fatalf("skip-listed path must bypass origin validation, got 403: %s", resp.Body.String())
	}
}

// P09-GAP-3: slash-boundary — skipping "/sign" must not skip "/sign-out".
func TestF10_SkipOriginCheckPaths_SlashBoundary(t *testing.T) {
	opts := f10OriginOptions("https://app.example")
	opts.Plugins = []types.Plugin{&f10SkipPlugin{id: "f10-skip", paths: []string{"/sign"}}}
	api := Router(humatest.NewAdapter(), "/api/auth", opts)
	resp := humatest.Wrap(t, api).Post("/api/auth/sign-out",
		"Origin: https://evil.example",
		"Cookie: session_token=abc",
	)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("prefix sibling must stay validated (403), got %d: %s", resp.Code, resp.Body.String())
	}
}

// P09-GAP-3: skipCSRFCheck granularity — DisableCSRFCheck skips CSRF
// validation while DisableOriginCheck keeps its backward-compat warning path.
func TestF10_SkipCSRFCheck_GranularityPinned(t *testing.T) {
	opts := f10OriginOptions("https://app.example")
	opts.Advanced.DisableCSRFCheck = true
	api := Router(humatest.NewAdapter(), "/api/auth", opts)
	resp := humatest.Wrap(t, api).Post("/api/auth/sign-out",
		"Origin: https://evil.example",
		"Cookie: session_token=abc",
	)
	if resp.Code == http.StatusForbidden {
		t.Fatalf("DisableCSRFCheck must skip CSRF validation, got 403: %s", resp.Body.String())
	}
}

// f10TracePlugin exposes a TRACE endpoint so the origin middleware's widened
// mutating set is observable end to end: core routes are GET/POST-only and
// the test stack answers 404/405 before middleware for unrouted methods.
type f10TracePlugin struct{ id string }

func (p *f10TracePlugin) ID() string                   { return p.id }
func (p *f10TracePlugin) Init(types.AuthContext) error { return nil }
func (p *f10TracePlugin) Schema() types.PluginSchema   { return nil }
func (p *f10TracePlugin) Hooks() types.DBHooks         { return nil }
func (p *f10TracePlugin) RouteHooks() types.PluginRouteHooks {
	return types.PluginRouteHooks{}
}
func (p *f10TracePlugin) ErrorCodes() map[string]string { return nil }
func (p *f10TracePlugin) Endpoints() []types.Endpoint {
	return []types.Endpoint{{
		Method:      "TRACE",
		Path:        "/f10-trace",
		OperationID: "f10Trace",
		Register: func(api any, basePath string, opts types.Options) {
			humaAPI := api.(huma.API)
			type traceOutput struct {
				Body struct {
					OK bool `json:"ok"`
				}
			}
			huma.Register(humaAPI, huma.Operation{
				Method:      "TRACE",
				Path:        basePath + "/f10-trace",
				OperationID: "f10Trace",
			}, func(ctx context.Context, _ *struct{}) (*traceOutput, error) {
				out := &traceOutput{}
				out.Body.OK = true
				return out, nil
			})
		},
	}}
}

// P09-GAP-4: TRACE is outside GET/OPTIONS/HEAD so it is origin-validated
// upstream; an untrusted TRACE + cookie must be 403 (not a pass-through to
// the handler).
func TestF10_TraceMethod_OriginValidated(t *testing.T) {
	opts := f10OriginOptions("https://app.example")
	opts.Plugins = []types.Plugin{&f10TracePlugin{id: "f10-trace"}}
	api := Router(humatest.NewAdapter(), "/api/auth", opts)
	testAPI := humatest.Wrap(t, api)
	resp := testAPI.Do("TRACE", "/api/auth/f10-trace",
		"Origin: https://evil.example",
		"Cookie: session_token=abc",
	)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("untrusted TRACE + cookie must be 403, got %d: %s", resp.Code, resp.Body.String())
	}
	// A trusted TRACE still reaches the handler.
	resp = testAPI.Do("TRACE", "/api/auth/f10-trace",
		"Origin: https://app.example",
		"Cookie: session_token=abc",
	)
	if resp.Code != http.StatusOK {
		t.Fatalf("trusted TRACE must reach the handler, got %d: %s", resp.Code, resp.Body.String())
	}
}

// P09-GAP-5: the default (memory) backend must enforce atomically — a
// concurrent burst admits exactly max, never overshooting via a two-phase
// check-then-record. /sign-in/email carries the 10s/3 special rule.
func TestF10_MemoryBackendBurst_AtomicConsume(t *testing.T) {
	rateLimitMu.Lock()
	original := rateLimitMemory
	rateLimitMemory = map[string]memoryRateLimitEntry{}
	rateLimitMu.Unlock()
	t.Cleanup(func() {
		rateLimitMu.Lock()
		rateLimitMemory = original
		rateLimitMu.Unlock()
	})

	opts := testRateLimitOptions()
	enabled := true
	opts.RateLimit.Enabled = &enabled
	api := Router(humatest.NewAdapter(), "/api/auth", opts)
	testAPI := humatest.Wrap(t, api)

	const racers = 24
	const max = 3
	var allowed atomic.Int64
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			resp := testAPI.Post("/api/auth/sign-in/email",
				"X-Forwarded-For: 198.51.100.7",
			)
			if resp.Code != http.StatusTooManyRequests {
				allowed.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if allowed.Load() != max {
		t.Fatalf("memory burst allowed = %d, want exactly %d (atomic consume, no overshoot)", allowed.Load(), max)
	}
}

// P09-GAP-6: custom-rule globs follow upstream wildcardMatch — `**` crosses
// `/` separators while `*` stays within one segment.
func TestF10_CustomRule_DoubleStarMatchesUpstream(t *testing.T) {
	rules := map[string]types.RateLimitRule{
		"/ok/**": {Window: 60, Max: 1},
	}
	if _, ok := customRateLimitRule("/ok/a/b", rules); !ok {
		t.Fatal("`/ok/**` must match `/ok/a/b` (upstream wildcardMatch)")
	}
	if _, ok := customRateLimitRule("/other/a", rules); ok {
		t.Fatal("`/ok/**` must not match `/other/a`")
	}
	single := map[string]types.RateLimitRule{
		"/sign-in/*": {Window: 60, Max: 1},
	}
	if _, ok := customRateLimitRule("/sign-in/email", single); !ok {
		t.Fatal("`/sign-in/*` must match `/sign-in/email`")
	}
	if _, ok := customRateLimitRule("/sign-in/a/b", single); ok {
		t.Fatal("`/sign-in/*` must not cross `/` (single star stays in-segment)")
	}
	if rule, ok := customRateLimitRule("/exact", map[string]types.RateLimitRule{
		"/exact": {Window: 60, Max: 2},
		"/ex*":   {Window: 60, Max: 9},
	}); !ok || rule.Max != 2 {
		t.Fatalf("exact key must win over wildcard, got %+v %v", rule, ok)
	}
}

// P09-GAP-6: function resolvers share the same glob lookup.
func TestF10_CustomResolver_DoubleStarMatchesUpstream(t *testing.T) {
	key := fmt.Sprintf("/f10deep-%d/**", time.Now().UnixNano())
	resolvers := map[string]types.RateLimitRuleResolver{
		key: func(_ *http.Request, current types.RateLimitRule) (types.RateLimitRule, bool) {
			return current, true
		},
	}
	prefix := key[:len(key)-3]
	resolver, ok := customRuleResolver(prefix+"/a/b", resolvers)
	if !ok || resolver == nil {
		t.Fatal("`**` resolver must match a deep path")
	}
	if _, apply := resolver(nil, types.RateLimitRule{Window: 10, Max: 3}); !apply {
		t.Fatal("matched resolver must apply")
	}
}

// P09-GAP-7: a plugin contributing ONLY rate-limit rules (no hooks) still has
// its buckets consumed — consumption is not gated on other middleware.
func TestF10_PluginBucket_OnlyRulesConsume(t *testing.T) {
	// The default memory backend is process-global: isolate the bucket so
	// repeated runs (go test -count=N) start from a fresh window.
	rateLimitMu.Lock()
	original := rateLimitMemory
	rateLimitMemory = map[string]memoryRateLimitEntry{}
	rateLimitMu.Unlock()
	t.Cleanup(func() {
		rateLimitMu.Lock()
		rateLimitMemory = original
		rateLimitMu.Unlock()
	})

	enabled := true
	opts := testRateLimitOptions()
	opts.RateLimit.Enabled = &enabled
	opts.Plugins = []types.Plugin{
		&stubRateLimitPlugin{
			id: "f10-only-rules",
			rules: []types.PluginRateLimitRule{
				{Window: 60, Max: 1, PathMatcher: func(path string) bool { return path == "/ok" }},
			},
		},
	}
	api := Router(humatest.NewAdapter(), "/api/auth", opts)
	testAPI := humatest.Wrap(t, api)
	if resp := testAPI.Get("/api/auth/ok"); resp.Code != http.StatusOK {
		t.Fatalf("first request must pass, got %d: %s", resp.Code, resp.Body.String())
	}
	if resp := testAPI.Get("/api/auth/ok"); resp.Code != http.StatusTooManyRequests {
		t.Fatalf("second request must be 429 (bucket consumed without hooks), got %d: %s", resp.Code, resp.Body.String())
	}
}
