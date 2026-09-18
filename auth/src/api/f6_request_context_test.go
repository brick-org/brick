package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	authroutes "github.com/brick-org/brick/auth/src/api/routes"
	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

// F6-01 middleware pipeline tests (upstream: api/index.ts router onRequest,
// to-auth-endpoints.ts resolveDynamicContext + runWithRequestState,
// dispatch.ts hook pipeline + mergeResponseHeaders, core instrumentation +
// request-state tests).
//
// These fail before implementation and pass after: the resolved per-request
// BaseURL must be authoritative for handlers, and the pipeline must carry
// request state, endpoint metadata, response mutation, logger/instrumentation
// and background tasks on every request (not only when hooks are configured).

type f6EchoPlugin struct {
	id string
}

func (p *f6EchoPlugin) ID() string                   { return p.id }
func (p *f6EchoPlugin) Init(types.AuthContext) error { return nil }
func (p *f6EchoPlugin) Endpoints() []types.Endpoint  { return nil }
func (p *f6EchoPlugin) Schema() types.PluginSchema   { return nil }
func (p *f6EchoPlugin) Hooks() types.DBHooks         { return nil }
func (p *f6EchoPlugin) RouteHooks() types.PluginRouteHooks {
	return types.PluginRouteHooks{}
}
func (p *f6EchoPlugin) ErrorCodes() map[string]string { return nil }
func (p *f6EchoPlugin) NamedEndpoints() map[string]types.Endpoint {
	return map[string]types.Endpoint{
		"echo": {
			Method:      http.MethodGet,
			Path:        "/f6-echo",
			OperationID: "f6Echo",
			Register: func(api any, basePath string, opts types.Options) {
				humaAPI := api.(huma.API)
				type echoOutput struct {
					Body struct {
						BaseURL   string `json:"baseURL"`
						FullURL   string `json:"fullURL"`
						HasState  bool   `json:"hasState"`
						Method    string `json:"method"`
						Path      string `json:"path"`
						Operation string `json:"operation"`
					}
				}
				huma.Register(humaAPI, huma.Operation{
					Method:      http.MethodGet,
					Path:        basePath + "/f6-echo",
					OperationID: "f6Echo",
				}, func(ctx context.Context, _ *struct{}) (*echoOutput, error) {
					out := &echoOutput{}
					out.Body.BaseURL = authroutes.EffectiveBaseURL(ctx, opts)
					out.Body.FullURL = authroutes.EffectiveFullBaseURL(ctx, opts)
					out.Body.HasState = authroutes.RequestStateFromStd(ctx) != nil
					md := authroutes.EndpointMetadataFromStd(ctx)
					out.Body.Method = md.Method
					out.Body.Path = md.Path
					out.Body.Operation = md.OperationID
					return out, nil
				})
			},
		},
	}
}

func f6DynamicOptions() types.Options {
	return types.Options{
		BasePath:       "/api/auth",
		DynamicBaseURL: &types.DynamicBaseURLConfig{AllowedHosts: []string{"tenant-a.example.com", "tenant-b.example.com"}},
	}
}

func TestF6DynamicBaseURLAuthoritativeTwoHosts(t *testing.T) {
	opts := f6DynamicOptions()
	opts.Plugins = []types.Plugin{&f6EchoPlugin{id: "f6-echo"}}
	api := Router(humatest.NewAdapter(), "/api/auth", opts)
	testAPI := humatest.Wrap(t, api)

	decode := func(resp *httptest.ResponseRecorder) map[string]any {
		var body struct {
			BaseURL   string `json:"baseURL"`
			FullURL   string `json:"fullURL"`
			HasState  bool   `json:"hasState"`
			Method    string `json:"method"`
			Path      string `json:"path"`
			Operation string `json:"operation"`
		}
		// humatest writes the huma envelope; decode the body JSON.
		raw := resp.Body.String()
		var envelope map[string]any
		if err := json.Unmarshal([]byte(raw), &envelope); err != nil {
			t.Fatalf("decode envelope: %v (%s)", err, raw)
		}
		// The echo handler returns the struct directly; re-marshal the whole
		// body and decode the known fields via a second pass on raw.
		_ = envelope
		if err := json.Unmarshal([]byte(raw), &body); err != nil {
			// Fall back: huma may wrap; try nested.
			t.Fatalf("decode body: %v (%s)", err, raw)
		}
		return map[string]any{
			"baseURL": body.BaseURL, "fullURL": body.FullURL,
			"hasState": body.HasState, "method": body.Method,
			"path": body.Path, "operation": body.Operation,
		}
	}

	var wg sync.WaitGroup
	results := make([]map[string]any, 2)
	hosts := []string{"tenant-a.example.com", "tenant-b.example.com"}
	for i, host := range hosts {
		wg.Add(1)
		go func(idx int, h string) {
			defer wg.Done()
			resp := testAPI.Get("/api/auth/f6-echo", "Host: "+h)
			if resp.Code != http.StatusOK {
				t.Errorf("host %s status = %d: %s", h, resp.Code, resp.Body.String())
				return
			}
			results[idx] = decode(resp)
		}(i, host)
	}
	wg.Wait()
	for i, host := range hosts {
		if results[i] == nil {
			t.Fatalf("missing result for %s", host)
		}
		if results[i]["fullURL"] != "https://"+host+"/api/auth" {
			t.Fatalf("host %s fullURL = %v", host, results[i]["fullURL"])
		}
		if results[i]["baseURL"] != "https://"+host {
			t.Fatalf("host %s baseURL = %v", host, results[i]["baseURL"])
		}
		if results[i]["hasState"] != true {
			t.Fatalf("host %s must carry request state, got %v", host, results[i])
		}
	}
	// The two concurrent hosts must not leak into each other.
	if results[0]["fullURL"] == results[1]["fullURL"] {
		t.Fatalf("concurrent hosts leaked: %v", results)
	}
}

func TestF6RequestStateAlwaysInstalledWithoutHooks(t *testing.T) {
	// No hooks/plugins that would previously trigger the lifecycle
	// middleware: request state + endpoint metadata must still be present.
	opts := types.Options{BaseURL: "https://app.example", BasePath: "/api/auth"}
	opts.Plugins = []types.Plugin{&f6EchoPlugin{id: "f6-echo-plain"}}
	api := Router(humatest.NewAdapter(), "/api/auth", opts)
	resp := humatest.Wrap(t, api).Get("/api/auth/f6-echo", "Host: app.example")
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", resp.Code, resp.Body.String())
	}
	var body struct {
		HasState  bool   `json:"hasState"`
		Method    string `json:"method"`
		Path      string `json:"path"`
		Operation string `json:"operation"`
	}
	if err := json.Unmarshal([]byte(resp.Body.String()), &body); err != nil {
		t.Fatalf("decode: %v (%s)", err, resp.Body.String())
	}
	if !body.HasState {
		t.Fatal("request state must be installed even without hooks")
	}
	if body.Method != http.MethodGet {
		t.Fatalf("endpoint method = %q, want GET", body.Method)
	}
	if body.Operation != "f6Echo" {
		t.Fatalf("endpoint operation = %q, want f6Echo", body.Operation)
	}
}

func TestF6MiddlewareResponseMutationAndLogger(t *testing.T) {
	var reported bool
	opts := types.Options{BaseURL: "https://app.example", BasePath: "/api/auth"}
	opts.Logger.Log = func(level, message string, args ...any) { reported = true }
	opts.Plugins = []types.Plugin{&f6HookPlugin{}}
	api := Router(humatest.NewAdapter(), "/api/auth", opts)
	resp := humatest.Wrap(t, api).Get("/api/auth/ok")
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d", resp.Code)
	}
	if resp.Header().Get("X-F6-Before") != "yes" {
		t.Fatalf("before-hook header must reach the wire, got %v", resp.Header())
	}
	if resp.Header().Get("X-F6-After") != "yes" {
		t.Fatalf("after-hook header must reach the wire, got %v", resp.Header())
	}
	if !reported {
		t.Fatal("after-hook failure must be reported via Options.Logger")
	}
}

type f6HookPlugin struct{}

func (p *f6HookPlugin) ID() string                   { return "f6-hooks" }
func (p *f6HookPlugin) Init(types.AuthContext) error { return nil }
func (p *f6HookPlugin) Endpoints() []types.Endpoint  { return nil }
func (p *f6HookPlugin) Schema() types.PluginSchema   { return nil }
func (p *f6HookPlugin) Hooks() types.DBHooks         { return nil }
func (p *f6HookPlugin) RouteHooks() types.PluginRouteHooks {
	return types.PluginRouteHooks{}
}
func (p *f6HookPlugin) ErrorCodes() map[string]string { return nil }
func (p *f6HookPlugin) TSRouteHooks() types.PluginTSRouteHooks {
	return types.PluginTSRouteHooks{
		Before: []types.PluginTSRouteBeforeHook{
			{Handler: func(hctx types.PluginHookContext) error {
				hctx.ResponseHeaders.Set("X-F6-Before", "yes")
				return nil
			}},
		},
		After: []types.PluginTSRouteAfterHook{
			{Handler: func(hctx types.PluginHookContext) error {
				hctx.ResponseHeaders.Set("X-F6-After", "yes")
				return errors.New("f6 after failed")
			}},
		},
	}
}

func TestF6BackgroundTasksAndInstrumentation(t *testing.T) {
	// Handler dispatch through RunInBackground (upstream ctx.runInBackground).
	var handled [][]string
	opts := types.Options{BaseURL: "https://app.example", BasePath: "/api/auth"}
	opts.Advanced.BackgroundTasks.Handler = func(task func()) {
		handled = append(handled, []string{"handled"})
		task()
	}
	ran := false
	authroutes.RunInBackground(opts, func() { ran = true })
	if !ran || len(handled) != 1 {
		t.Fatalf("handler must run the task inline, ran=%v handled=%v", ran, handled)
	}
	// Instrumentation passthrough preserves name/attrs and returns fn values.
	out, err := authroutes.WithSpan(opts, "f6-op", map[string]string{"k": "v"}, func() (string, error) {
		return "ok", nil
	})
	if err != nil || out != "ok" {
		t.Fatalf("WithSpan = %v %v, want ok nil", out, err)
	}
}
