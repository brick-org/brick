package api

// framework_wave2_test.go: upstream conformance (Better Auth v1.7.5).

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

// wave2StubPlugin implements types.Plugin plus the optional named-endpoint
type wave2StubPlugin struct {
	id        string
	endpoints []types.Endpoint
	named     map[string]types.Endpoint
	tsHooks   types.PluginTSRouteHooks
}

func (p *wave2StubPlugin) ID() string                   { return p.id }
func (p *wave2StubPlugin) Init(types.AuthContext) error { return nil }
func (p *wave2StubPlugin) Endpoints() []types.Endpoint  { return p.endpoints }
func (p *wave2StubPlugin) Schema() types.PluginSchema   { return nil }
func (p *wave2StubPlugin) Hooks() types.DBHooks         { return nil }
func (p *wave2StubPlugin) RouteHooks() types.PluginRouteHooks {
	return types.PluginRouteHooks{}
}
func (p *wave2StubPlugin) ErrorCodes() map[string]string { return nil }
func (p *wave2StubPlugin) NamedEndpoints() map[string]types.Endpoint {
	return p.named
}
func (p *wave2StubPlugin) TSRouteHooks() types.PluginTSRouteHooks { return p.tsHooks }

func wave2PingEndpoint(path, operationID string) types.Endpoint {
	return types.Endpoint{
		Method:      http.MethodGet,
		Path:        path,
		OperationID: operationID,
		Summary:     operationID,
		Register: func(api any, basePath string, _ types.Options) {
			humaAPI := api.(huma.API)
			type pingOutput struct {
				Body struct {
					Pong bool `json:"pong"`
				}
			}
			huma.Register(humaAPI, huma.Operation{
				Method:      http.MethodGet,
				Path:        basePath + path,
				OperationID: operationID,
			}, func(_ context.Context, _ *struct{}) (*pingOutput, error) {
				out := &pingOutput{}
				out.Body.Pong = true
				return out, nil
			})
		},
	}
}

func wave2BaseOptions() types.Options {
	return types.Options{BaseURL: "https://app.example.com"}
}

func TestWave2NamedPluginEndpointsRegister(t *testing.T) {
	plugin := &wave2StubPlugin{
		id:        "ping",
		endpoints: []types.Endpoint{wave2PingEndpoint("/legacy-ping", "legacyPing")},
		named: map[string]types.Endpoint{
			"named": wave2PingEndpoint("/named-ping", "namedPing"),
		},
	}
	opts := wave2BaseOptions()
	opts.Plugins = []types.Plugin{plugin}
	api := Router(humatest.NewAdapter(), "/api/auth", opts)
	testAPI := humatest.Wrap(t, api)
	if resp := testAPI.Get("/api/auth/legacy-ping"); resp.Code != http.StatusOK {
		t.Fatalf("legacy endpoint status = %d, want 200: %s", resp.Code, resp.Body.String())
	}
	if resp := testAPI.Get("/api/auth/named-ping"); resp.Code != http.StatusOK {
		t.Fatalf("named endpoint status = %d, want 200: %s", resp.Code, resp.Body.String())
	}
}

func TestWave2TSRouteHooksRunWithHeaderApply(t *testing.T) {
	var order []string
	plugin := &wave2StubPlugin{
		id: "hooks",
		tsHooks: types.PluginTSRouteHooks{
			Before: []types.PluginTSRouteBeforeHook{
				{
					Handler: func(hctx types.PluginHookContext) error {
						order = append(order, "before")
						hctx.ResponseHeaders.Set("X-TS-Before", "yes")
						return nil
					},
				},
			},
			After: []types.PluginTSRouteAfterHook{
				{
					Handler: func(hctx types.PluginHookContext) error {
						order = append(order, "after")
						hctx.ResponseHeaders.Set("X-TS-After", "yes")
						return nil
					},
				},
			},
		},
	}
	opts := wave2BaseOptions()
	opts.Plugins = []types.Plugin{plugin}
	api := Router(humatest.NewAdapter(), "/api/auth", opts)
	testAPI := humatest.Wrap(t, api)
	resp := testAPI.Get("/api/auth/ok")
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", resp.Code, resp.Body.String())
	}
	if resp.Header().Get("X-TS-Before") != "yes" {
		t.Fatalf("before-hook response header must reach the wire, got %v", resp.Header())
	}
	if resp.Header().Get("X-TS-After") != "yes" {
		t.Fatalf("after-hook response header must reach the wire, got %v", resp.Header())
	}
	if len(order) != 2 || order[0] != "before" || order[1] != "after" {
		t.Fatalf("hook order = %v, want [before after]", order)
	}
}

func TestWave2TSBeforeHookAbortsRoute(t *testing.T) {
	boom := errors.New("stop the route")
	ranHandler := false
	plugin := &wave2StubPlugin{
		id: "aborter",
		tsHooks: types.PluginTSRouteHooks{
			Before: []types.PluginTSRouteBeforeHook{
				{Handler: func(types.PluginHookContext) error { return boom }},
			},
		},
	}
	opts := wave2BaseOptions()
	opts.Plugins = []types.Plugin{plugin}
	opts.Hooks.Before = func(ctx huma.Context) (huma.Context, error) {
		ranHandler = true
		return ctx, nil
	}
	api := Router(humatest.NewAdapter(), "/api/auth", opts)
	testAPI := humatest.Wrap(t, api)
	resp := testAPI.Get("/api/auth/ok")
	if resp.Code == http.StatusOK {
		t.Fatalf("aborted route must not succeed: %s", resp.Body.String())
	}
	if !ranHandler {
		t.Fatal("user global before hook must still run before the TS abort")
	}
}

func TestWave2TSAfterHookErrorsDoNotFailRoute(t *testing.T) {
	reported := false
	plugin := &wave2StubPlugin{
		id: "after-fail",
		tsHooks: types.PluginTSRouteHooks{
			After: []types.PluginTSRouteAfterHook{
				{Handler: func(types.PluginHookContext) error { return errors.New("after failed") }},
			},
		},
	}
	opts := wave2BaseOptions()
	opts.Plugins = []types.Plugin{plugin}
	opts.Logger.Log = func(level, message string, args ...any) { reported = true }
	api := Router(humatest.NewAdapter(), "/api/auth", opts)
	testAPI := humatest.Wrap(t, api)
	resp := testAPI.Get("/api/auth/ok")
	if resp.Code != http.StatusOK {
		t.Fatalf("after-hook failure must not fail the route, status = %d", resp.Code)
	}
	if !reported {
		t.Fatal("after-hook failure must be reported via Options.Logger")
	}
}

func TestWave2ApplyTSResponseHeadersMergeSemantics(t *testing.T) {
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	api.UseMiddleware(func(ctx huma.Context, next func(huma.Context)) {
		ctx.SetHeader("X-Replace", "old")
		ctx.AppendHeader("Set-Cookie", "a=1")
		applyTSResponseHeaders(ctx, map[string][]string{
			"X-Replace":  {"new"},
			"Set-Cookie": {"b=2"},
		})
		next(ctx)
	})
	huma.Register(api, huma.Operation{OperationID: "merge", Method: http.MethodGet, Path: "/merge"}, func(ctx context.Context, input *struct{}) (*struct{}, error) {
		return nil, nil
	})
	resp := api.Get("/merge")
	if got := resp.Header().Get("X-Replace"); got != "new" {
		t.Fatalf("non-cookie headers must replace, got %q (full %v)", got, resp.Header())
	}
	cookies := resp.Header().Values("Set-Cookie")
	if len(cookies) != 2 {
		t.Fatalf("set-cookie must accumulate, got %v", cookies)
	}
}

func TestWave2EndpointConflicts(t *testing.T) {
	mk := func(id, path, method string) *wave2StubPlugin {
		return &wave2StubPlugin{
			id:        id,
			endpoints: []types.Endpoint{{Method: method, Path: path, OperationID: id + "-ep"}},
		}
	}
	conflicts := FindEndpointConflicts("/api/auth", []types.Plugin{
		mk("p1", "/shared", http.MethodGet),
		mk("p2", "/shared", http.MethodGet),
	})
	if len(conflicts) != 1 {
		t.Fatalf("conflicts = %+v, want exactly one", conflicts)
	}
	if conflicts[0].Path != "/api/auth/shared" {
		t.Fatalf("conflict path = %q", conflicts[0].Path)
	}
	if len(conflicts[0].Plugins) != 2 {
		t.Fatalf("conflict plugins = %v", conflicts[0].Plugins)
	}
	if out := FindEndpointConflicts("/api/auth", []types.Plugin{
		mk("p1", "/shared", http.MethodGet),
		mk("p2", "/shared", http.MethodPost),
	}); len(out) != 0 {
		t.Fatalf("different methods must not conflict, got %+v", out)
	}
	if out := FindEndpointConflicts("/api/auth", []types.Plugin{
		mk("p1", "/wild", ""),
		mk("p2", "/wild", http.MethodGet),
	}); len(out) != 1 {
		t.Fatalf("wildcard must conflict, got %+v", out)
	}
	// Reporting reaches the logger as an error diagnostic.
	var reported []string
	CheckEndpointConflicts("/api/auth", []types.Plugin{
		mk("p1", "/shared", http.MethodGet),
		mk("p2", "/shared", http.MethodGet),
	}, func(msg string, args ...any) { reported = append(reported, msg) })
	if len(reported) != 1 || !strings.Contains(reported[0], "Endpoint path conflicts detected") {
		t.Fatalf("conflict report = %v", reported)
	}
	if !strings.Contains(reported[0], "p1, p2") {
		t.Fatalf("report must name plugins, got %q", reported[0])
	}
}

func TestWave2TrailingSlashVariants(t *testing.T) {
	opts := wave2BaseOptions()
	opts.Advanced.SkipTrailingSlashes = true
	api := Router(humatest.NewAdapter(), "/api/auth", opts)
	testAPI := humatest.Wrap(t, api)
	if resp := testAPI.Get("/api/auth/ok"); resp.Code != http.StatusOK {
		t.Fatalf("canonical status = %d", resp.Code)
	}
	if resp := testAPI.Get("/api/auth/ok/"); resp.Code != http.StatusOK {
		t.Fatalf("slash variant status = %d, want 200", resp.Code)
	}
	plain := Router(humatest.NewAdapter(), "/api/auth", wave2BaseOptions())
	plainTest := humatest.Wrap(t, plain)
	if resp := plainTest.Get("/api/auth/ok/"); resp.Code != http.StatusNotFound {
		t.Fatalf("without the flag the slash spelling must 404, got %d", resp.Code)
	}
}

func TestWave2SchemaCheckGate(t *testing.T) {
	boom := errors.New("schema mismatch")
	opts := wave2BaseOptions()
	opts.SchemaCheck = func() error { return boom }
	api := Router(humatest.NewAdapter(), "/api/auth", opts)
	testAPI := humatest.Wrap(t, api)
	if resp := testAPI.Get("/api/auth/ok"); resp.Code != http.StatusInternalServerError {
		t.Fatalf("failing schema check must fail closed, got %d: %s", resp.Code, resp.Body.String())
	}
	okOpts := wave2BaseOptions()
	okAPI := Router(humatest.NewAdapter(), "/api/auth", okOpts)
	if resp := humatest.Wrap(t, okAPI).Get("/api/auth/ok"); resp.Code != http.StatusOK {
		t.Fatalf("nil schema check must pass, got %d", resp.Code)
	}
}

func TestWave2RequestStatePerRequest(t *testing.T) {
	if state := GetRequestState(nil); state != nil {
		t.Fatalf("nil context must yield nil state, got %v", state)
	}
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	var observed map[any]any
	api.UseMiddleware(func(ctx huma.Context, next func(huma.Context)) {
		withState := WithRequestState(ctx, NewRequestState())
		SetRequestState(withState, "k", "v")
		observed = GetRequestState(withState)
		next(withState)
	})
	huma.Register(api, huma.Operation{OperationID: "state", Method: http.MethodGet, Path: "/state"}, func(ctx context.Context, input *struct{}) (*struct{}, error) {
		return nil, nil
	})
	if resp := api.Get("/state"); resp.Code != http.StatusOK && resp.Code != 204 {
		t.Fatalf("status = %d", resp.Code)
	}
	if observed == nil || observed["k"] != "v" {
		t.Fatalf("request state must round-trip, got %v", observed)
	}
}

func TestWave2LifecycleInstallsRequestState(t *testing.T) {
	var observed map[any]any
	opts := wave2BaseOptions()
	opts.Hooks.Before = func(ctx huma.Context) (huma.Context, error) {
		observed = GetRequestState(ctx)
		return ctx, nil
	}
	api := Router(humatest.NewAdapter(), "/api/auth", opts)
	testAPI := humatest.Wrap(t, api)
	if resp := testAPI.Get("/api/auth/ok"); resp.Code != http.StatusOK {
		t.Fatalf("status = %d", resp.Code)
	}
	if observed == nil {
		t.Fatal("lifecycle middleware must install a request-state store before hooks run")
	}
}

func TestWave2DynamicBaseURLResolution(t *testing.T) {
	newReq := func(host, rawURL string) *http.Request {
		r, _ := http.NewRequest(http.MethodGet, rawURL, nil)
		r.Host = host
		return r
	}
	staticOpts := wave2BaseOptions()
	if got, err := ResolveDynamicBaseURLForRequest(newReq("example.com", "https://example.com/x"), staticOpts); err != nil || got != "" {
		t.Fatalf("static mode must resolve nothing, got %q (%v)", got, err)
	}
	dynOpts := wave2BaseOptions()
	dynOpts.BaseURL = ""
	dynOpts.DynamicBaseURL = &types.DynamicBaseURLConfig{AllowedHosts: []string{"example.com"}}
	if got, err := ResolveDynamicBaseURLForRequest(newReq("example.com", "https://example.com/x"), dynOpts); err != nil || got != "https://example.com/api/auth" {
		t.Fatalf("allowed host must resolve, got %q (%v)", got, err)
	}
	loopOpts := wave2BaseOptions()
	loopOpts.BaseURL = ""
	loopOpts.DynamicBaseURL = &types.DynamicBaseURLConfig{AllowedHosts: []string{"localhost"}}
	loopReq, _ := http.NewRequest(http.MethodGet, "http://localhost:3000/api/auth/ok", nil)
	loopReq.Host = "localhost:3000"
	if got, err := ResolveDynamicBaseURLForRequest(loopReq, loopOpts); err != nil || got != "http://localhost:3000/api/auth" {
		t.Fatalf("loopback must resolve to http, got %q (%v)", got, err)
	}
	if _, err := ResolveDynamicBaseURLForRequest(newReq("evil.com", "https://evil.com/x"), dynOpts); err == nil {
		t.Fatal("unlisted host without fallback must fail")
	}
	fallbackOpts := wave2BaseOptions()
	fallbackOpts.BaseURL = ""
	fallbackOpts.DynamicBaseURL = &types.DynamicBaseURLConfig{
		AllowedHosts: []string{"example.com"},
		Fallback:     "https://fallback.example.com",
	}
	if got, err := ResolveDynamicBaseURLForRequest(newReq("evil.com", "https://evil.com/x"), fallbackOpts); err != nil || got != "https://fallback.example.com/api/auth" {
		t.Fatalf("fallback must cover unlisted hosts, got %q (%v)", got, err)
	}
	proxyOpts := wave2BaseOptions()
	proxyOpts.BaseURL = ""
	proxyOpts.DynamicBaseURL = &types.DynamicBaseURLConfig{AllowedHosts: []string{"public.example.com"}}
	proxyReq, _ := http.NewRequest(http.MethodGet, "http://internal:3000/api/auth/ok", nil)
	proxyReq.Host = "internal:3000"
	proxyReq.Header.Set("X-Forwarded-Host", "public.example.com")
	if _, err := ResolveDynamicBaseURLForRequest(proxyReq, proxyOpts); err == nil {
		t.Fatal("forwarded host must not apply without the opt-in")
	}
	trusted := true
	proxyOpts.Advanced.TrustedProxyHeaders = &trusted
	proxyReq.Header.Set("X-Forwarded-Proto", "https")
	if got, err := ResolveDynamicBaseURLForRequest(proxyReq, proxyOpts); err != nil || got != "https://public.example.com/api/auth" {
		t.Fatalf("forwarded host must apply with the opt-in, got %q (%v)", got, err)
	}
}
