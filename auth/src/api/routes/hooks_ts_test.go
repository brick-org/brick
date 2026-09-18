package routes

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

func TestPluginHookContextFromHuma(t *testing.T) {
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	var got types.PluginHookContext
	api.UseMiddleware(func(ctx huma.Context, next func(huma.Context)) {
		got = PluginHookContextFromHuma(ctx, types.AuthContext{})
		next(ctx)
	})
	huma.Register(api, huma.Operation{OperationID: "probe", Method: http.MethodGet, Path: "/probe"}, func(ctx context.Context, input *struct{}) (*struct{}, error) {
		return nil, nil
	})
	resp := api.Get("/probe")
	if resp.Code != 200 && resp.Code != 204 {
		t.Fatalf("status = %d", resp.Code)
	}
	if got.Method != http.MethodGet {
		t.Fatalf("method = %q", got.Method)
	}
	if got.Path != "/probe" {
		t.Fatalf("path = %q", got.Path)
	}
	if got.ResponseHeaders == nil {
		t.Fatal("response headers map must be non-nil for mutation")
	}
}

func TestNewPluginHookContextCarriesReturned(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "https://example.com/x", nil)
	req.Header.Set("X-Test", "1")
	hdr := http.Header{}
	ctx := NewPluginHookContext(req, types.AuthContext{}, 42, hdr)
	if ctx.Method != http.MethodPost || ctx.Path != "/x" {
		t.Fatalf("method/path = %q/%q", ctx.Method, ctx.Path)
	}
	if ctx.Headers.Get("X-Test") != "1" {
		t.Fatalf("headers = %v", ctx.Headers)
	}
	if ctx.Returned != 42 {
		t.Fatalf("returned = %v", ctx.Returned)
	}
	if ctx.ResponseHeaders == nil {
		t.Fatal("response headers must be non-nil")
	}
}

func TestRunTSRouteBeforeHooksAbort(t *testing.T) {
	boom := errors.New("stop")
	var ran []string
	hooks := []types.PluginTSRouteBeforeHook{
		{Handler: func(ctx types.PluginHookContext) error { ran = append(ran, "first"); return nil }},
		{Handler: func(ctx types.PluginHookContext) error { return boom }},
		{Handler: func(ctx types.PluginHookContext) error { ran = append(ran, "third"); return nil }},
		{Matcher: func(ctx types.PluginHookContext) bool { return false }, Handler: func(ctx types.PluginHookContext) error {
			ran = append(ran, "skipped")
			return nil
		}},
	}
	err := RunTSRouteBeforeHooks(types.PluginHookContext{Path: "/x"}, hooks)
	if !errors.Is(err, boom) {
		t.Fatalf("first error must abort, got: %v", err)
	}
	if len(ran) != 1 || ran[0] != "first" {
		t.Fatalf("hooks after the failure must not run; non-matching must be skipped: %v", ran)
	}
	// Nil handlers and nil matchers are no-ops / always-run.
	if err := RunTSRouteBeforeHooks(types.PluginHookContext{}, []types.PluginTSRouteBeforeHook{{}}); err != nil {
		t.Fatalf("zero hook must be a no-op, got: %v", err)
	}
}

func TestRunTSRouteAfterHooksReportAll(t *testing.T) {
	boom := errors.New("after failed")
	var ran int
	var reported []error
	hooks := []types.PluginTSRouteAfterHook{
		{Handler: func(ctx types.PluginHookContext) error { ran++; return boom }},
		{Handler: func(ctx types.PluginHookContext) error { ran++; return nil }},
	}
	RunTSRouteAfterHooks(types.PluginHookContext{}, hooks, func(err error) { reported = append(reported, err) })
	if ran != 2 {
		t.Fatalf("all after hooks must run, ran %d", ran)
	}
	if len(reported) != 1 || !errors.Is(reported[0], boom) {
		t.Fatalf("errors must be reported, got %v", reported)
	}
	// Nil reporter discards.
	RunTSRouteAfterHooks(types.PluginHookContext{}, hooks, nil)
}

func TestApplyPluginResponseHeaders(t *testing.T) {
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	api.UseMiddleware(func(ctx huma.Context, next func(huma.Context)) {
		ApplyPluginResponseHeaders(ctx, map[string][]string{"X-Plugin": {"yes"}})
		next(ctx)
	})
	huma.Register(api, huma.Operation{OperationID: "hdr", Method: http.MethodGet, Path: "/hdr"}, func(ctx context.Context, input *struct{}) (*struct{}, error) {
		return nil, nil
	})
	resp := api.Get("/hdr")
	if resp.Header().Get("X-Plugin") != "yes" {
		t.Fatalf("plugin response header must reach the wire, got %v", resp.Header())
	}
}
