package types

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

// stubPlugin implements the legacy Plugin interface plus every new OPTIONAL
// provider, proving the additive surface composes without breaking legacy
// shapes.
type stubPlugin struct{}

func (stubPlugin) ID() string                    { return "stub" }
func (stubPlugin) Init(AuthContext) error        { return nil }
func (stubPlugin) Endpoints() []Endpoint         { return nil }
func (stubPlugin) Schema() PluginSchema          { return nil }
func (stubPlugin) Hooks() DBHooks                { return nil }
func (stubPlugin) RouteHooks() PluginRouteHooks  { return PluginRouteHooks{} }
func (stubPlugin) ErrorCodes() map[string]string { return nil }
func (stubPlugin) Version() string               { return "1.0.0" }
func (stubPlugin) PluginOptions() map[string]any { return map[string]any{"k": "v"} }
func (stubPlugin) Infer() map[string]any         { return map[string]any{"user": "shape"} }
func (stubPlugin) Migrations() map[string]PluginMigration {
	return map[string]PluginMigration{"001_init": {}}
}
func (stubPlugin) AdapterOverrides() PluginAdapterOverrides {
	return PluginAdapterOverrides{
		"create": func(ctx context.Context, args ...any) (any, error) { return nil, nil },
	}
}
func (stubPlugin) NamedEndpoints() map[string]Endpoint { return map[string]Endpoint{} }
func (stubPlugin) TSRouteHooks() PluginTSRouteHooks    { return PluginTSRouteHooks{} }
func (stubPlugin) OnRequest() PluginOnRequestHandler {
	return func(request *http.Request, ctx AuthContext) (*PluginOnRequestResult, error) {
		return &PluginOnRequestResult{Request: request}, nil
	}
}
func (stubPlugin) OnResponse() PluginOnResponseHandler {
	return func(response *http.Response, ctx AuthContext) (*PluginOnResponseResult, error) {
		return &PluginOnResponseResult{Response: response}, nil
	}
}
func (stubPlugin) Middlewares() []PluginMiddleware       { return nil }
func (stubPlugin) RateLimitRules() []PluginRateLimitRule { return nil }

func TestStubPluginSatisfiesLegacyAndOptionalProviders(t *testing.T) {
	var legacy Plugin = stubPlugin{}
	if legacy.ID() != "stub" {
		t.Fatalf("stub plugin ID = %q", legacy.ID())
	}
	// Every new surface must be discoverable via type assertion while the
	// legacy interface keeps working.
	if _, ok := legacy.(PluginVersionProvider); !ok {
		t.Error("stub should satisfy PluginVersionProvider")
	}
	if _, ok := legacy.(PluginOptionsProvider); !ok {
		t.Error("stub should satisfy PluginOptionsProvider")
	}
	if _, ok := legacy.(PluginInferProvider); !ok {
		t.Error("stub should satisfy PluginInferProvider")
	}
	if _, ok := legacy.(PluginMigrationsProvider); !ok {
		t.Error("stub should satisfy PluginMigrationsProvider")
	}
	if _, ok := legacy.(PluginAdapterOverridesProvider); !ok {
		t.Error("stub should satisfy PluginAdapterOverridesProvider")
	}
	if _, ok := legacy.(PluginNamedEndpointsProvider); !ok {
		t.Error("stub should satisfy PluginNamedEndpointsProvider")
	}
	if _, ok := legacy.(PluginTSRouteHooksProvider); !ok {
		t.Error("stub should satisfy PluginTSRouteHooksProvider")
	}
	if _, ok := legacy.(PluginOnRequestProvider); !ok {
		t.Error("stub should satisfy PluginOnRequestProvider")
	}
	if _, ok := legacy.(PluginOnResponseProvider); !ok {
		t.Error("stub should satisfy PluginOnResponseProvider")
	}
	if _, ok := legacy.(PluginMiddlewareProvider); !ok {
		t.Error("stub should satisfy PluginMiddlewareProvider")
	}
	if _, ok := legacy.(PluginRateLimitProvider); !ok {
		t.Error("stub should satisfy PluginRateLimitProvider")
	}
	if _, ok := legacy.(PluginSchemaProvider); ok {
		// Plugin.Schema() has the same signature, so a full Plugin also
		// satisfies the schema-only provider — document the overlap.
		t.Log("full Plugin satisfies PluginSchemaProvider via Schema()")
	}
}

func TestLegacyPluginWithoutNewProvidersKeepsWorking(t *testing.T) {
	var legacy Plugin = minimalPlugin{}
	if legacy.ID() != "minimal" {
		t.Fatalf("minimal plugin ID = %q", legacy.ID())
	}
	if _, ok := legacy.(PluginVersionProvider); ok {
		t.Error("minimal plugin must not satisfy PluginVersionProvider")
	}
	if _, ok := legacy.(PluginAdapterOverridesProvider); ok {
		t.Error("minimal plugin must not satisfy PluginAdapterOverridesProvider")
	}
	if _, ok := legacy.(PluginTSRouteHooksProvider); ok {
		t.Error("minimal plugin must not satisfy PluginTSRouteHooksProvider")
	}
}

type minimalPlugin struct{}

func (minimalPlugin) ID() string                    { return "minimal" }
func (minimalPlugin) Init(AuthContext) error        { return nil }
func (minimalPlugin) Endpoints() []Endpoint         { return nil }
func (minimalPlugin) Schema() PluginSchema          { return nil }
func (minimalPlugin) Hooks() DBHooks                { return nil }
func (minimalPlugin) RouteHooks() PluginRouteHooks  { return PluginRouteHooks{} }
func (minimalPlugin) ErrorCodes() map[string]string { return nil }

func TestModelNameConstants(t *testing.T) {
	cases := map[string]string{
		"ModelUser":         ModelUser,
		"ModelAccount":      ModelAccount,
		"ModelSession":      ModelSession,
		"ModelVerification": ModelVerification,
		"ModelRateLimit":    ModelRateLimit,
	}
	want := map[string]string{
		"ModelUser":         "user",
		"ModelAccount":      "account",
		"ModelSession":      "session",
		"ModelVerification": "verification",
		"ModelRateLimit":    "rate-limit",
	}
	for name, got := range cases {
		if got != want[name] {
			t.Errorf("%s = %q, want %q", name, got, want[name])
		}
	}
}

func TestFieldValidatorFuncValidate(t *testing.T) {
	var nilFn FieldValidatorFunc
	if err := nilFn.Validate("anything"); err != nil {
		t.Errorf("nil FieldValidatorFunc must accept everything, got %v", err)
	}
	boom := errors.New("boom")
	reject := FieldValidatorFunc(func(value any) error {
		if value == "bad" {
			return boom
		}
		return nil
	})
	if err := reject.Validate("good"); err != nil {
		t.Errorf("accepting value rejected: %v", err)
	}
	if err := reject.Validate("bad"); !errors.Is(err, boom) {
		t.Errorf("rejecting value err = %v, want boom", err)
	}
}

func TestNewFieldValidatorNilSafe(t *testing.T) {
	v := NewFieldValidator(nil, nil)
	if v == nil {
		t.Fatal("NewFieldValidator must never return nil")
	}
	if v.Input != nil || v.Output != nil {
		t.Error("nil funcs must leave sides nil (unvalidated)")
	}
	if err := v.Input.Validate(1); err != nil {
		t.Errorf("nil input side must accept everything, got %v", err)
	}

	boom := errors.New("nope")
	v = NewFieldValidator(
		FieldValidatorFunc(func(value any) error { return nil }),
		FieldValidatorFunc(func(value any) error { return boom }),
	)
	if err := v.Input.Validate("x"); err != nil {
		t.Errorf("input side should accept, got %v", err)
	}
	if err := v.Output.Validate("x"); !errors.Is(err, boom) {
		t.Errorf("output side err = %v, want boom", err)
	}

	// The struct form stays assignable from plain func literals (back-compat
	// with the pre-FIELDVALIDATORFUNC field type).
	legacy := &FieldValidator{
		Input:  func(value any) error { return nil },
		Output: func(value any) error { return boom },
	}
	if err := legacy.Input.Validate("x"); err != nil {
		t.Errorf("legacy literal input should accept, got %v", err)
	}
}

func TestNewFieldTransformNilSafe(t *testing.T) {
	tr := NewFieldTransform(nil, nil)
	if tr == nil {
		t.Fatal("NewFieldTransform must never return nil")
	}
	if tr.Input != nil || tr.Output != nil {
		t.Error("nil funcs must leave sides nil (identity)")
	}
	tr = NewFieldTransform(
		FieldTransformFunc(func(value any) (any, error) { return value, nil }),
		nil,
	)
	out, err := tr.Input("v")
	if err != nil || out != "v" {
		t.Errorf("input transform = (%v, %v), want (v, nil)", out, err)
	}
}

func TestErrHookAbortSentinel(t *testing.T) {
	if ErrHookAbort == nil {
		t.Fatal("ErrHookAbort must be non-nil")
	}
	wrapped := errors.Join(errors.New("ctx"), ErrHookAbort)
	if !errors.Is(wrapped, ErrHookAbort) {
		t.Error("ErrHookAbort must be detectable via errors.Is when wrapped")
	}
	if errors.Is(errors.New("other"), ErrHookAbort) {
		t.Error("unrelated errors must not match ErrHookAbort")
	}
}

func TestPluginHookContextZeroValue(t *testing.T) {
	var ctx PluginHookContext
	if ctx.Request != nil || ctx.Headers != nil || ctx.ResponseHeaders != nil {
		t.Error("zero PluginHookContext should leave request/headers nil")
	}
	if ctx.Method != "" || ctx.Path != "" || ctx.Returned != nil {
		t.Error("zero PluginHookContext should leave method/path/returned unset")
	}
}

func TestTSRouteHookNilHandlersAreNoOps(t *testing.T) {
	hooks := PluginTSRouteHooks{
		Before: []PluginTSRouteBeforeHook{{}},
		After:  []PluginTSRouteAfterHook{{}},
	}
	ctx := PluginHookContext{Path: "/x"}
	for _, h := range hooks.Before {
		if h.Matcher != nil && !h.Matcher(ctx) {
			t.Error("non-nil matcher unexpectedly rejected")
		}
		if h.Handler != nil {
			t.Error("zero before hook handler should be nil")
		}
	}
	for _, h := range hooks.After {
		if h.Matcher != nil && !h.Matcher(ctx) {
			t.Error("non-nil matcher unexpectedly rejected")
		}
		if h.Handler != nil {
			t.Error("zero after hook handler should be nil")
		}
	}
}
