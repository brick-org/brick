package auth_test

// Wave 2 Agent C (framework context and options) tests.
//
// Each test pins upstream behavior from the pinned Better Auth v1.7.5 source
// before the implementation runs (failing-first workflow):
//   - HookedAdapter construction through NewHookedAdapterWithOptions: plugin
//     adapter overrides apply, FieldSchemas populate from the resolved
//     schema, and Options.OnAfterCommitHookError reports post-commit
//     failures (vendor/.../src/db/with-hooks.ts, core/src/context/transaction.ts).
//   - Full context services on AuthContext (create-context.ts).
//   - Logger level filtering (core/src/env/logger.ts shouldPublishLog).
//   - Secret entropy + default-secret production diagnostics
//     (context/secret-utils.ts, create-context.ts validateSecret).
//   - Per-request dynamic baseURL resolution (utils/url.ts
//     resolveDynamicBaseURL, context/helpers.ts resolveRequestContext).
//   - ID-generation overrides (create-context.ts generateIdFunc).
//   - Nested defu option-patch merging (context/helpers.ts runPluginInit).

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	auth "github.com/brick-org/brick/auth/src"
	"github.com/brick-org/brick/auth/src/types"
)

// wave2Plugin is a configurable stub implementing auth.Plugin plus the
// optional Wave 1/2 provider surfaces (adapter overrides, named endpoints,
// TS route hooks, init patches).
type wave2Plugin struct {
	id        string
	overrides types.PluginAdapterOverrides
	named     map[string]auth.Endpoint
	tsHooks   types.PluginTSRouteHooks
	schema    auth.PluginSchema
	hooks     auth.DBHooks
	patch     *types.PluginInitPatch
	patchErr  error
}

func (p *wave2Plugin) ID() string                  { return p.id }
func (p *wave2Plugin) Init(auth.AuthContext) error { return nil }
func (p *wave2Plugin) Endpoints() []auth.Endpoint  { return nil }
func (p *wave2Plugin) Schema() auth.PluginSchema {
	if p.schema != nil {
		return p.schema
	}
	return nil
}
func (p *wave2Plugin) Hooks() auth.DBHooks {
	if p.hooks != nil {
		return p.hooks
	}
	return nil
}
func (p *wave2Plugin) RouteHooks() auth.PluginRouteHooks { return auth.PluginRouteHooks{} }
func (p *wave2Plugin) ErrorCodes() map[string]string     { return nil }
func (p *wave2Plugin) AdapterOverrides() types.PluginAdapterOverrides {
	return p.overrides
}
func (p *wave2Plugin) NamedEndpoints() map[string]auth.Endpoint { return p.named }
func (p *wave2Plugin) TSRouteHooks() types.PluginTSRouteHooks   { return p.tsHooks }
func (p *wave2Plugin) InitPatches(auth.AuthContext) (types.PluginInitPatch, error) {
	if p.patchErr != nil {
		return types.PluginInitPatch{}, p.patchErr
	}
	if p.patch != nil {
		return *p.patch, nil
	}
	return types.PluginInitPatch{}, nil
}

func TestWave2PluginAdapterOverrideViaBetterAuth(t *testing.T) {
	adapter, srv := newTestAdapter(t)
	db := newMemoryAdapter()
	called := false
	plugin := &wave2Plugin{
		id: "override-plugin",
		overrides: types.PluginAdapterOverrides{
			"create": func(ctx context.Context, args ...any) (any, error) {
				called = true
				return map[string]any{"id": "custom", "from": "override"}, nil
			},
		},
	}
	a := mustBetterAuth(t, auth.Options{
		Secret:  "test-secret-that-is-long-enough-1234",
		Adapter: adapter,
		DB:      db,
		Plugins: []auth.Plugin{plugin},
	})
	_ = srv
	got, err := a.Context.Options.DB.Create(context.Background(), "user", map[string]any{"id": "1"}, nil)
	if err != nil {
		t.Fatalf("wrapped create: %v", err)
	}
	if !called {
		t.Fatal("plugin adapter override must be consulted through BetterAuth's HookedAdapter")
	}
	if got["from"] != "override" {
		t.Fatalf("override result must pass through, got %#v", got)
	}
	if n, _ := db.Count(context.Background(), "user", nil); n != 0 {
		t.Fatalf("inner adapter must be skipped when an override handles create, rows = %d", n)
	}
}

func TestWave2FieldSchemasPopulateFromResolvedSchema(t *testing.T) {
	adapter, _ := newTestAdapter(t)
	db := newMemoryAdapter()
	plugin := &wave2Plugin{
		id: "transform-plugin",
		schema: auth.PluginSchema{
			"user": auth.TableSchema{
				Fields: map[string]auth.FieldAttribute{
					"nick": {
						Type: auth.FieldTypeString,
						Transform: &types.FieldTransform{
							Input: func(v any) (any, error) {
								s, _ := v.(string)
								return strings.ToUpper(s), nil
							},
						},
					},
				},
			},
		},
	}
	a := mustBetterAuth(t, auth.Options{
		Secret:  "test-secret-that-is-long-enough-1234",
		Adapter: adapter,
		DB:      db,
		Plugins: []auth.Plugin{plugin},
	})
	if _, err := a.Context.Options.DB.Create(context.Background(), "user", map[string]any{"id": "1", "nick": "bob"}, nil); err != nil {
		t.Fatalf("create: %v", err)
	}
	raw, err := db.FindOne(context.Background(), "user", []auth.Where{{Field: "id", Value: "1"}}, nil)
	if err != nil {
		t.Fatalf("inner read: %v", err)
	}
	if raw["nick"] != "BOB" {
		t.Fatalf("resolved-schema input transform must apply before storage, got %#v", raw["nick"])
	}
}

func TestWave2OnAfterCommitHookErrorOption(t *testing.T) {
	adapter, _ := newTestAdapter(t)
	hookErr := errors.New("post-commit after failed")
	newAuth := func(t *testing.T, handler func(error)) auth.Auth {
		db := newMemoryAdapter()
		return mustBetterAuth(t, auth.Options{
			Secret:  "test-secret-that-is-long-enough-1234",
			Adapter: adapter,
			DB:      db,
			DatabaseHooks: auth.DBHooks{
				"user": {Create: auth.OperationHooks{
					After: func(_ context.Context, _ map[string]any) error { return hookErr },
				}},
			},
			OnAfterCommitHookError: handler,
		})
	}
	// Without a handler the first flush failure fails the call.
	a := newAuth(t, nil)
	err := a.Context.Options.DB.Transaction(context.Background(), func(tx auth.Adapter) error {
		_, err := tx.Create(context.Background(), "user", map[string]any{"id": "1"}, nil)
		return err
	})
	if !errors.Is(err, hookErr) {
		t.Fatalf("unhandled post-commit error must propagate, got: %v", err)
	}
	// With a handler the call succeeds and the error is reported.
	var handled []error
	a2 := newAuth(t, func(err error) { handled = append(handled, err) })
	if err := a2.Context.Options.DB.Transaction(context.Background(), func(tx auth.Adapter) error {
		_, err := tx.Create(context.Background(), "user", map[string]any{"id": "1"}, nil)
		return err
	}); err != nil {
		t.Fatalf("handled post-commit error must not fail the call, got: %v", err)
	}
	if len(handled) != 1 || !errors.Is(handled[0], hookErr) {
		t.Fatalf("handler must observe the hook error, got %v", handled)
	}
}

func TestWave2InitPatchHooksKeepPluginSource(t *testing.T) {
	adapter, _ := newTestAdapter(t)
	db := newMemoryAdapter()
	var order []string
	legacy := &wave2Plugin{
		id: "patcher",
		hooks: auth.DBHooks{
			"user": {Create: auth.OperationHooks{
				Before: func(_ context.Context, data map[string]any) (map[string]any, error) {
					order = append(order, "legacy")
					return map[string]any{"legacy": true}, nil
				},
			}},
		},
		patch: &types.PluginInitPatch{
			Options: &types.Options{
				DatabaseHooks: types.DBHooks{
					"user": types.ModelHooks{
						Create: types.OperationHooks{
							Before: func(_ context.Context, data map[string]any) (map[string]any, error) {
								order = append(order, "patch")
								return map[string]any{"patched": true}, nil
							},
							After: func(_ context.Context, _ map[string]any) error {
								return errors.New("patch after failed")
							},
						},
					},
				},
			},
		},
	}
	a := mustBetterAuth(t, auth.Options{
		Secret:  "test-secret-that-is-long-enough-1234",
		Adapter: adapter,
		DB:      db,
		Plugins: []auth.Plugin{legacy},
	})
	// Merge order: legacy hooks run before init-patch hooks, both merge.
	// AUTH-S6-01 D05 (aligned to throw): the failing patch after-hook
	// propagates without rolling back, so the call fails AND the merged
	// write persists.
	row, err := a.Context.Options.DB.Create(context.Background(), "user", map[string]any{"id": "1"}, nil)
	if err == nil || !strings.Contains(err.Error(), "patch after failed") {
		t.Fatalf("after-hook error must propagate (D05 throw), got row=%v err=%v", row, err)
	}
	if len(order) != 2 || order[0] != "legacy" || order[1] != "patch" {
		t.Fatalf("hook order = %v, want [legacy patch]", order)
	}
	raw, _ := db.FindOne(context.Background(), "user", []auth.Where{{Field: "id", Value: "1"}}, nil)
	if raw["legacy"] != true || raw["patched"] != true {
		t.Fatalf("both hook payloads must merge, got %#v", raw)
	}
	// The patch failure must carry the plugin:<id> source label, proving the
	// patch traveled as a sourced entry rather than a generic user hook.
	err = a.Context.Options.DB.Transaction(context.Background(), func(tx auth.Adapter) error {
		_, err := tx.Create(context.Background(), "user", map[string]any{"id": "2"}, nil)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "source plugin:patcher") {
		t.Fatalf("post-commit error must carry the patch source label, got: %v", err)
	}
}

func TestWave2FullContextServices(t *testing.T) {
	adapter, _ := newTestAdapter(t)
	db := newMemoryAdapter()
	a := mustBetterAuth(t, auth.Options{
		Secret:  "test-secret-that-is-long-enough-1234",
		Adapter: adapter,
		DB:      db,
		BaseURL: "https://app.example.com",
	})
	ctx := a.Context
	if ctx.Version != "1.7.5" {
		t.Fatalf("context version = %q, want 1.7.5", ctx.Version)
	}
	if ctx.BaseURL != "https://app.example.com" {
		t.Fatalf("context baseURL = %q", ctx.BaseURL)
	}
	if _, ok := ctx.Tables["user"]; !ok {
		t.Fatalf("resolved tables must include user, got %v", ctx.Tables)
	}
	found := false
	for _, origin := range ctx.TrustedOrigins {
		if origin == "https://app.example.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("trusted origins must include the baseURL origin, got %v", ctx.TrustedOrigins)
	}
	if ctx.IsTrustedOrigin == nil || !ctx.IsTrustedOrigin("https://app.example.com/ok") {
		t.Fatal("IsTrustedOrigin must accept the baseURL origin")
	}
	if ctx.GenerateID == nil {
		t.Fatal("GenerateID resolver must be attached")
	}
	id, ok := ctx.GenerateID("user", nil)
	if !ok || len(id) != 32 {
		t.Fatalf("default GenerateID must mint 32 chars, got %q (%v)", id, ok)
	}
	if ctx.SessionConfig.ExpiresIn != 60*60*24*7 || ctx.SessionConfig.UpdateAge != 24*60*60 || ctx.SessionConfig.FreshAge != 60*60*24 {
		t.Fatalf("session defaults wrong: %+v", ctx.SessionConfig)
	}
	if ctx.OAuthStateStrategy != "database" {
		t.Fatalf("state strategy with a database must be database, got %q", ctx.OAuthStateStrategy)
	}
	if ctx.RateLimit.Window != 10 || ctx.RateLimit.Max != 100 || ctx.RateLimit.Storage != types.RateLimitStorageMemory {
		t.Fatalf("rate-limit triple wrong: %+v", ctx.RateLimit)
	}
	if ctx.CheckSchema == nil {
		t.Fatal("CheckSchema must be attached by default")
	}
	if ctx.PublishTelemetry == nil {
		t.Fatal("PublishTelemetry must be attached")
	}
	ctx.PublishTelemetry(types.TelemetryEvent{Type: "test", Payload: map[string]any{}})
	// Explicit opt-out removes the validator.
	a2 := mustBetterAuth(t, auth.Options{
		Secret:  "test-secret-that-is-long-enough-1234",
		Adapter: adapter,
		Advanced: types.AdvancedOptions{
			Database: types.AdvancedDatabaseOptions{ValidateSchema: boolPtr(false)},
		},
	})
	if a2.Context.CheckSchema != nil {
		t.Fatal("CheckSchema must be nil when ValidateSchema is false")
	}
}

func TestWave2GenerateIDOverrides(t *testing.T) {
	adapter, _ := newTestAdapter(t)
	newID := func(t *testing.T, opt types.GenerateIDOption) (string, bool) {
		t.Helper()
		a := mustBetterAuth(t, auth.Options{
			Secret:  "test-secret-that-is-long-enough-1234",
			Adapter: adapter,
			Advanced: types.AdvancedOptions{
				Database: types.AdvancedDatabaseOptions{GenerateID: opt},
			},
		})
		return a.Context.GenerateID("user", nil)
	}
	if id, ok := newID(t, types.GenerateIDOption{Mode: types.GenerateIDModeUUID}); !ok || len(id) != 36 || strings.Count(id, "-") != 4 {
		t.Fatalf("uuid mode must mint a UUID, got %q (%v)", id, ok)
	}
	if id, ok := newID(t, types.GenerateIDOption{Mode: types.GenerateIDModeSerial}); ok || id != "" {
		t.Fatalf("serial mode must resolve to database-issued (\"\", false), got %q (%v)", id, ok)
	}
	custom := types.GenerateIDOption{Func: func(model string, size *int) (string, bool) {
		return "custom-" + model, true
	}}
	if id, ok := newID(t, custom); !ok || id != "custom-user" {
		t.Fatalf("custom func must win, got %q (%v)", id, ok)
	}
	size := 10
	a := mustBetterAuth(t, auth.Options{
		Secret:  "test-secret-that-is-long-enough-1234",
		Adapter: adapter,
	})
	if id, ok := a.Context.GenerateID("user", &size); !ok || len(id) != 10 {
		t.Fatalf("size hint must flow to the default minter, got %q (%v)", id, ok)
	}
}

func TestWave2DynamicRequestContext(t *testing.T) {
	adapter, _ := newTestAdapter(t)
	a := mustBetterAuth(t, auth.Options{
		Secret:  "test-secret-that-is-long-enough-1234",
		Adapter: adapter,
		DynamicBaseURL: &types.DynamicBaseURLConfig{
			AllowedHosts: []string{"example.com"},
		},
	})
	if a.Context.BaseURL != "" {
		t.Fatalf("shared context baseURL must stay empty in dynamic mode, got %q", a.Context.BaseURL)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/api/auth/get-session", nil)
	req.Host = "example.com"
	resolved, err := auth.ResolveRequestContext(a.Context, req, a.Context.Options)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved.BaseURL != "https://example.com/api/auth" {
		t.Fatalf("resolved baseURL = %q", resolved.BaseURL)
	}
	if !resolved.IsTrustedOrigin("https://example.com/ok") {
		t.Fatal("resolved context must trust the resolved origin")
	}
	// Unlisted hosts fail closed without a fallback.
	bad, _ := http.NewRequest(http.MethodGet, "https://evil.com/api/auth/get-session", nil)
	bad.Host = "evil.com"
	if _, err := auth.ResolveRequestContext(a.Context, bad, a.Context.Options); err == nil {
		t.Fatal("unlisted host without fallback must fail")
	}
	// Fallback covers unlisted hosts.
	a2 := mustBetterAuth(t, auth.Options{
		Secret:  "test-secret-that-is-long-enough-1234",
		Adapter: adapter,
		DynamicBaseURL: &types.DynamicBaseURLConfig{
			AllowedHosts: []string{"example.com"},
			Fallback:     "https://fallback.example.com",
		},
	})
	resolved2, err := auth.ResolveRequestContext(a2.Context, bad, a2.Context.Options)
	if err != nil {
		t.Fatalf("fallback resolve: %v", err)
	}
	if resolved2.BaseURL != "https://fallback.example.com/api/auth" {
		t.Fatalf("fallback baseURL = %q", resolved2.BaseURL)
	}
	// Static configurations return the input unchanged.
	a3 := mustBetterAuth(t, auth.Options{
		Secret:  "test-secret-that-is-long-enough-1234",
		Adapter: adapter,
		BaseURL: "https://app.example.com",
	})
	same, err := auth.ResolveRequestContext(a3.Context, req, a3.Context.Options)
	if err != nil || same.BaseURL != "https://app.example.com" {
		t.Fatalf("static resolve must pass through, got %q (%v)", same.BaseURL, err)
	}
}

func TestWave2LoggerLevelFiltering(t *testing.T) {
	adapter, _ := newTestAdapter(t)
	var got []string
	levels := func(level types.LogLevel) auth.Options {
		return auth.Options{
			Secret:  "test-secret-that-is-long-enough-1234",
			Adapter: adapter,
			Logger: types.LoggerOptions{
				Level: level,
				Log:   func(level, message string, args ...any) { got = append(got, level+":"+message) },
			},
			Telemetry: types.TelemetryOptions{Enabled: true},
			Advanced: types.AdvancedOptions{
				IPAddress: types.IPAddressOptions{TrustedProxies: []string{"not-an-ip"}},
			},
		}
	}
	// At level error, info notes (telemetry) and warnings (proxies) stay quiet.
	got = nil
	mustBetterAuth(t, levels(types.LogLevelError))
	if len(got) != 0 {
		t.Fatalf("level=error must suppress info/warn notes, got %v", got)
	}
	// At level debug everything publishes.
	got = nil
	mustBetterAuth(t, levels(types.LogLevelDebug))
	if len(got) == 0 {
		t.Fatal("level=debug must publish parity notes")
	}
}

func TestWave2SecretsEntropyAndDefaultSecret(t *testing.T) {
	var warnings []string
	warnf := func(format string, args ...any) {
		warnings = append(warnings, format)
	}
	// 32 repeated chars pass the length floor but carry ~0 entropy.
	if err := auth.ValidateSecretsArray([]auth.Secret{{Version: 0, Value: strings.Repeat("a", 32)}}, warnf); err != nil {
		t.Fatalf("length-ok secret must validate: %v", err)
	}
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "low-entropy") {
		t.Fatalf("low-entropy secret must warn, got %v", warnings)
	}
	warnings = nil
	if err := auth.ValidateSecretsArray([]auth.Secret{{Version: 0, Value: "test-secret-that-is-long-enough-1234"}}, warnf); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if strings.Contains(strings.Join(warnings, "\n"), "low-entropy") {
		t.Fatalf("high-entropy secret must not warn entropy, got %v", warnings)
	}
	// The documented default secret is rejected in production.
	t.Setenv("NODE_ENV", "production")
	adapter, _ := newTestAdapter(t)
	if _, err := auth.BetterAuth(auth.Options{Secret: auth.DefaultSecret, Adapter: adapter}); err == nil {
		t.Fatal("default secret in production must fail")
	}
}

func TestWave2DefuMergesPointerStructs(t *testing.T) {
	adapter, _ := newTestAdapter(t)
	plugin := &wave2Plugin{
		id: "defu-merger",
		patch: &types.PluginInitPatch{
			Options: &types.Options{
				DynamicBaseURL: &types.DynamicBaseURLConfig{
					Fallback: "https://fallback.example.com",
				},
			},
		},
	}
	a := mustBetterAuth(t, auth.Options{
		Secret:  "test-secret-that-is-long-enough-1234",
		Adapter: adapter,
		DynamicBaseURL: &types.DynamicBaseURLConfig{
			AllowedHosts: []string{"example.com"},
			Protocol:     types.BaseURLProtocolHTTPS,
		},
		Plugins: []auth.Plugin{plugin},
	})
	cfg := a.Context.Options.DynamicBaseURL
	if cfg == nil {
		t.Fatal("dynamic config must survive init patches")
	}
	if len(cfg.AllowedHosts) != 1 || cfg.AllowedHosts[0] != "example.com" {
		t.Fatalf("base wins on conflict: hosts = %v", cfg.AllowedHosts)
	}
	if cfg.Protocol != types.BaseURLProtocolHTTPS {
		t.Fatalf("base wins on conflict: protocol = %q", cfg.Protocol)
	}
	if cfg.Fallback != "https://fallback.example.com" {
		t.Fatalf("patch-only nested fields must fill in, got %+v", cfg)
	}
}

func TestWave2ShouldPublishLogLevels(t *testing.T) {
	cases := []struct {
		current, msg types.LogLevel
		want         bool
	}{
		{"", "warn", true},
		{"", "info", false},
		{"debug", "debug", true},
		{"warn", "info", false},
		{"warn", "error", true},
		{"error", "warn", false},
		{"info", "success", true},
		{"warn", "success", false},
		{"bogus", "error", false},
		{"warn", "bogus", false},
	}
	for _, c := range cases {
		if got := types.ShouldPublishLog(c.current, c.msg); got != c.want {
			t.Fatalf("ShouldPublishLog(%q, %q) = %v, want %v", c.current, c.msg, got, c.want)
		}
	}
	if got := types.NormalizeLogLevelForHandler(types.LogLevelSuccess); got != "info" {
		t.Fatalf("success must normalize to info, got %q", got)
	}
}

func TestWave2MatchesHostPattern(t *testing.T) {
	cases := []struct {
		host, pattern string
		want          bool
	}{
		{"example.com", "example.com", true},
		{"EXAMPLE.com", "example.com", true},
		{"a.example.com", "*.example.com", true},
		{"example.com", "*.example.com", false},
		{"preview-1.myapp.com", "preview-*.myapp.com", true},
		{"evil.com", "example.com", false},
		{"", "example.com", false},
		{"example.com", "", false},
		{"example.com", "https://example.com", true},
	}
	for _, c := range cases {
		if got := types.MatchesHostPattern(c.host, c.pattern); got != c.want {
			t.Fatalf("MatchesHostPattern(%q, %q) = %v, want %v", c.host, c.pattern, got, c.want)
		}
	}
}

// REMOVED (AUTH-F6-03): TestWave2ValidateDBHints was deleted with the
// DatabaseHints surface. Upstream `database` object-form selectors have no
// Go adapter consumer, so the validated-but-inert fields were removed (see
// the REMOVED note on types/auth.go); callers configure their adapter
// directly.
