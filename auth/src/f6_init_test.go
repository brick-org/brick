package auth_test

// AUTH-F6-03 focused fixtures: initialization (defu merge, plugin context
// overwrite order, nested patches, dynamic trusted-origin composition),
// secrets (lookup precedence, versioned env parsing/validation, warnings,
// rotation), and telemetry/instrumentation (event shape, disable controls).
//
// Pinned upstream (Better Auth v1.7.5 @ 5468e6bf):
//   - packages/better-auth/src/context/helpers.ts (runPluginInit: defu merge,
//     context overwrite order, trusted-origin composition)
//   - packages/better-auth/src/context/secret-utils.ts (parse/validate/build)
//   - packages/better-auth/src/context/create-context.ts (lookup precedence,
//     validateSecret diagnostics)
//   - packages/telemetry/src/index.ts (createTelemetry enablement/publish)
//   - packages/core/src/instrumentation (createWithSpan/withSpan)
//
// Workflow: these tests were added BEFORE the AUTH-F6-03 implementation
// changes; the subset marked NEEDS-FIX failed against the pre-fix code for
// the reason stated, then passed after the fix without weakening.

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	auth "github.com/brick-org/brick/auth/src"
	"github.com/brick-org/brick/auth/src/types"
)

// f6MockProvider is a minimal OAuthProvider stub for init-plumbing tests
// (defu slice concatenation). It carries an ID only; all operations fail.
type f6MockProvider struct{ id string }

func (p *f6MockProvider) ID() string   { return p.id }
func (p *f6MockProvider) Name() string { return p.id }

func (p *f6MockProvider) CreateAuthorizationURL(types.AuthorizationURLParams) (string, error) {
	return "", fmt.Errorf("f6mock: no authorization URL")
}

func (p *f6MockProvider) ExchangeCode(types.CodeExchangeParams) (*types.OAuthTokens, error) {
	return nil, fmt.Errorf("f6mock: no code exchange")
}

func (p *f6MockProvider) GetUserInfo(*types.OAuthTokens) (*types.OAuthUserInfo, error) {
	return nil, fmt.Errorf("f6mock: no user info")
}

// f6ObserverPlugin is a minimal PluginInitPatches stub that records the
// context AppName visible at InitPatches time (proving inter-plugin
// visibility and overwrite order) and returns fixed patches.
type f6ObserverPlugin struct {
	id           string
	optionsPatch *types.Options
	contextPatch *types.AuthContext
	seenAppName  *string
}

func (p *f6ObserverPlugin) ID() string                  { return p.id }
func (p *f6ObserverPlugin) Init(auth.AuthContext) error { return nil }
func (p *f6ObserverPlugin) Endpoints() []auth.Endpoint  { return nil }
func (p *f6ObserverPlugin) Schema() auth.PluginSchema   { return nil }
func (p *f6ObserverPlugin) Hooks() auth.DBHooks         { return nil }
func (p *f6ObserverPlugin) RouteHooks() auth.PluginRouteHooks {
	return auth.PluginRouteHooks{}
}
func (p *f6ObserverPlugin) ErrorCodes() map[string]string { return nil }
func (p *f6ObserverPlugin) InitPatches(ctx auth.AuthContext) (types.PluginInitPatch, error) {
	if p.seenAppName != nil {
		*p.seenAppName = ctx.AppName
	}
	out := types.PluginInitPatch{}
	if p.optionsPatch != nil {
		out.Options = p.optionsPatch
	}
	if p.contextPatch != nil {
		out.Context = p.contextPatch
	}
	return out, nil
}

const f6Secret = "f6-test-secret-that-is-long-enough-1234567890"

func f6CaptureLogger(level types.LogLevel) (*[]string, types.LoggerOptions) {
	var got []string
	return &got, types.LoggerOptions{
		Level: level,
		Log: func(lvl, msg string, args ...any) {
			got = append(got, lvl+":"+msg)
		},
	}
}

// NEEDS-FIX (pre-fix: pre-loop AppName default blocked defu fill):
// upstream runPluginInit `options = defu(options, restOpts)` fills values the
// main config left unset (create-context.test.ts "should allow plugins to set
// config values"). The options patch must land on ctx.Options; ctx.AppName
// itself keeps the "Better Auth" default unless a context patch sets it
// (upstream ctx.appName is built pre-init from the unpatched options).
func TestF6DefuPatchFillsUnsetAppName(t *testing.T) {
	adapter, _ := newTestAdapter(t)
	a := mustBetterAuth(t, auth.Options{
		Secret:  f6Secret,
		Adapter: adapter,
		Plugins: []auth.Plugin{
			&f6ObserverPlugin{
				id:           "app-setter",
				optionsPatch: &types.Options{AppName: "Plugin App"},
			},
		},
	})
	if a.Context.Options.AppName != "Plugin App" {
		t.Fatalf("defu must fill unset AppName from plugin patch, got %q", a.Context.Options.AppName)
	}
	if a.Context.AppName != "Better Auth" {
		t.Fatalf("ctx.AppName keeps the construction default without a context patch, got %q", a.Context.AppName)
	}
}

func TestF6DefuBaseWinsOnConflict(t *testing.T) {
	adapter, _ := newTestAdapter(t)
	a := mustBetterAuth(t, auth.Options{
		Secret:  f6Secret,
		Adapter: adapter,
		AppName: "Base App",
		Plugins: []auth.Plugin{
			&f6ObserverPlugin{
				id:           "app-override",
				optionsPatch: &types.Options{AppName: "Patch App"},
			},
		},
	})
	if a.Context.Options.AppName != "Base App" {
		t.Fatalf("defu base wins on conflict, got %q", a.Context.Options.AppName)
	}
}

func TestF6DefuNestedStructMerge(t *testing.T) {
	adapter, _ := newTestAdapter(t)
	a := mustBetterAuth(t, auth.Options{
		Secret:  f6Secret,
		Adapter: adapter,
		Session: types.SessionOptions{UpdateAge: intPtr(100)},
		Plugins: []auth.Plugin{
			&f6ObserverPlugin{
				id:           "session-merger",
				optionsPatch: &types.Options{Session: types.SessionOptions{ExpiresIn: 999}},
			},
		},
	})
	sess := a.Context.Options.Session
	if sess.UpdateAge == nil || *sess.UpdateAge != 100 || sess.ExpiresIn != 999 {
		t.Fatalf("nested defu must merge both sides, got %+v", sess)
	}
}

func TestF6DefuSliceConcatBaseFirst(t *testing.T) {
	adapter, _ := newTestAdapter(t)
	a := mustBetterAuth(t, auth.Options{
		Secret:          f6Secret,
		Adapter:         adapter,
		SocialProviders: []auth.OAuthProvider{&f6MockProvider{id: "mock-a"}},
		Plugins: []auth.Plugin{
			&f6ObserverPlugin{
				id: "provider-adder",
				optionsPatch: &types.Options{
					SocialProviders: []auth.OAuthProvider{&f6MockProvider{id: "mock-b"}},
				},
			},
		},
	})
	got := a.Context.Options.SocialProviders
	if len(got) != 2 || got[0].ID() != "mock-a" || got[1].ID() != "mock-b" {
		ids := []string{}
		for _, p := range got {
			ids = append(ids, p.ID())
		}
		t.Fatalf("defu must concatenate slices base-first, got %v", ids)
	}
}

// NEEDS-FIX (pre-fix: map values kept wholesale, no deep merge):
// upstream defu recurses into plain-object values, so per-key option objects
// merge deeply with base winning. Map entries present on both sides must
// merge field-wise, not keep the base value outright.
func TestF6DefuMapValuesMergeDeeply(t *testing.T) {
	adapter, _ := newTestAdapter(t)
	a := mustBetterAuth(t, auth.Options{
		Secret:  f6Secret,
		Adapter: adapter,
		RateLimit: types.RateLimitOptions{
			CustomRules: map[string]types.RateLimitRule{"x": {Window: 5}},
		},
		Plugins: []auth.Plugin{
			&f6ObserverPlugin{
				id: "rules-merger",
				optionsPatch: &types.Options{
					RateLimit: types.RateLimitOptions{
						CustomRules: map[string]types.RateLimitRule{
							"x": {Window: 9, Max: 7},
							"y": {Window: 1},
						},
					},
				},
			},
		},
	})
	rules := a.Context.Options.RateLimit.CustomRules
	if rules["x"].Window != 5 || rules["x"].Max != 7 {
		t.Fatalf("map values must deep-merge base-wins, got %+v", rules["x"])
	}
	if rules["y"].Window != 1 {
		t.Fatalf("patch-only map keys must fill in, got %+v", rules["y"])
	}
}

// Documents a structural Go deviation from defu: upstream skips only
// null/undefined base values, so an explicit `false` beats a patch `true`
// (create-context.test.ts "should not allow plugins to set config values if
// they are set in the main config"). Go zero values conflate "unset" with an
// explicit falsy, so patch fill wins here. Presence-tracked kinds (pointers,
// slices, maps, strings set non-empty) honor base-wins exactly; plain scalar
// falsy values do not. This pins the actual behavior so the gap stays loud.
func TestF6DefuScalarZeroValueDeviation(t *testing.T) {
	adapter, _ := newTestAdapter(t)
	a := mustBetterAuth(t, auth.Options{
		Secret:           f6Secret,
		Adapter:          adapter,
		EmailAndPassword: types.EmailAndPasswordOptions{Enabled: false},
		Session:          types.SessionOptions{},
		TrustedOrigins:   nil,
		Plugins: []auth.Plugin{
			&f6ObserverPlugin{
				id: "bool-setter",
				optionsPatch: &types.Options{
					EmailAndPassword: types.EmailAndPasswordOptions{Enabled: true},
				},
			},
		},
	})
	if !a.Context.Options.EmailAndPassword.Enabled {
		t.Fatal("documents Go deviation: zero-value base cannot preserve explicit falsy against a patch")
	}
}

func TestF6ContextPatchOverwriteOrder(t *testing.T) {
	adapter, _ := newTestAdapter(t)
	var seen1, seen2 string
	a := mustBetterAuth(t, auth.Options{
		Secret:  f6Secret,
		Adapter: adapter,
		Plugins: []auth.Plugin{
			&f6ObserverPlugin{
				id:           "first",
				contextPatch: &types.AuthContext{AppName: "one"},
				seenAppName:  &seen1,
			},
			&f6ObserverPlugin{
				id:           "second",
				contextPatch: &types.AuthContext{AppName: "two"},
				seenAppName:  &seen2,
			},
		},
	})
	if seen1 != "Better Auth" {
		t.Fatalf("first plugin must see the construction default, saw %q", seen1)
	}
	if seen2 != "one" {
		t.Fatalf("second plugin must see the first plugin's context patch, saw %q", seen2)
	}
	if a.Context.AppName != "two" {
		t.Fatalf("later context patches win (Object.assign order), got %q", a.Context.AppName)
	}
}

func TestF6ContextPatchSecretOrder(t *testing.T) {
	adapter, _ := newTestAdapter(t)
	a := mustBetterAuth(t, auth.Options{
		Secret:  f6Secret,
		Adapter: adapter,
		Plugins: []auth.Plugin{
			&f6ObserverPlugin{
				id:           "s1",
				contextPatch: &types.AuthContext{Secret: "secret-one-that-is-long-enough-1234"},
			},
			&f6ObserverPlugin{
				id:           "s2",
				contextPatch: &types.AuthContext{Secret: "secret-two-that-is-long-enough-1234"},
			},
		},
	})
	if a.Context.Secret != "secret-two-that-is-long-enough-1234" {
		t.Fatalf("later secret context patches win, got %q", a.Context.Secret)
	}
}

func TestF6TrustedOriginComposition(t *testing.T) {
	adapter, _ := newTestAdapter(t)
	a := mustBetterAuth(t, auth.Options{
		Secret:         f6Secret,
		Adapter:        adapter,
		TrustedOrigins: []string{"https://base.example"},
		TrustedOriginsFunc: func(r *http.Request) []string {
			return []string{"https://dyn-base.example", ""}
		},
		Plugins: []auth.Plugin{
			&f6ObserverPlugin{
				id: "p1",
				optionsPatch: &types.Options{
					TrustedOrigins: []string{"", "https://p1.example"},
					TrustedOriginsFunc: func(r *http.Request) []string {
						return []string{"https://dyn-p1.example"}
					},
				},
			},
			&f6ObserverPlugin{
				id: "p2",
				optionsPatch: &types.Options{
					TrustedOrigins: []string{"https://p2.example"},
				},
			},
		},
	})
	wantStatics := []string{"https://base.example", "https://p1.example", "https://p2.example"}
	gotStatics := a.Context.Options.TrustedOrigins
	if len(gotStatics) != len(wantStatics) {
		t.Fatalf("statics must compose base-first with empties dropped, got %v", gotStatics)
	}
	for i := range wantStatics {
		if gotStatics[i] != wantStatics[i] {
			t.Fatalf("static order = %v, want %v", gotStatics, wantStatics)
		}
	}
	fn := a.Context.Options.TrustedOriginsFunc
	if fn == nil {
		t.Fatal("dynamic resolvers must combine into one func")
	}
	var dyn []string
	for _, o := range fn(nil) {
		if o != "" {
			dyn = append(dyn, o)
		}
	}
	if len(dyn) != 2 || dyn[0] != "https://dyn-base.example" || dyn[1] != "https://dyn-p1.example" {
		t.Fatalf("dynamics must compose in order, got %v", dyn)
	}
	if !a.Context.IsTrustedOrigin("https://p2.example/cb") {
		t.Fatal("composed statics must be trusted")
	}
	if !a.Context.IsTrustedOrigin("https://dyn-p1.example/cb") {
		t.Fatal("composed dynamics must be trusted")
	}
}

func TestF6ParseSecretsEnvValid(t *testing.T) {
	got, err := auth.ParseSecretsEnv("2:new-secret-value,1:old-secret-value")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 2 || got[0].Version != 2 || got[0].Value != "new-secret-value" ||
		got[1].Version != 1 || got[1].Value != "old-secret-value" {
		t.Fatalf("unexpected parse result: %+v", got)
	}
	if got, err := auth.ParseSecretsEnv(""); err != nil || got != nil {
		t.Fatalf("empty env must yield nil,nil, got %+v, %v", got, err)
	}
}

func TestF6ParseSecretsEnvFailures(t *testing.T) {
	for name, tc := range map[string]struct {
		in   string
		want string
	}{
		"missing colon": {in: "no-colon-here", want: "Invalid BETTER_AUTH_SECRETS entry"},
		"negative":      {in: "-1:x", want: "Invalid version"},
		"non-numeric":   {in: "abc:x", want: "Invalid version"},
		"empty value":   {in: "1:", want: "Empty secret value"},
		"blank value":   {in: "1:   ", want: "Empty secret value"},
		// NEEDS-FIX (pre-fix: whitespace-only returned nil,nil): upstream
		// parseSecretsEnv throws on any truthy non-empty input that is not a
		// valid entry; only ""/unset yields null.
		"whitespace": {in: "   ", want: "Invalid BETTER_AUTH_SECRETS entry"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := auth.ParseSecretsEnv(tc.in); err == nil {
				t.Fatalf("input %q must fail", tc.in)
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("input %q error %q must contain %q", tc.in, err.Error(), tc.want)
			}
		})
	}
}

// Documents a strictness deviation from JS parseInt leniency: upstream
// parseInt("1abc", 10) === 1 (accepted, normalized), while Go rejects
// trailing-garbage versions fail-closed.
func TestF6ParseSecretsEnvStrictVersion(t *testing.T) {
	if _, err := auth.ParseSecretsEnv("1abc:some-secret-value"); err == nil {
		t.Fatal("trailing-garbage versions must fail closed in Go (deviation from parseInt leniency)")
	}
}

// NEEDS-FIX (pre-fix: messages lacked upstream's trailing periods):
// validateSecretsArray error bodies must match secret-utils.ts exactly
// (modulo the Go "auth: " prefix).
func TestF6ValidateSecretsArrayFailures(t *testing.T) {
	cases := []struct {
		name    string
		secrets []auth.Secret
		want    string
	}{
		{"empty", nil, "`secrets` array must contain at least one entry."},
		{"duplicate", []auth.Secret{{Version: 1, Value: "a"}, {Version: 1, Value: "b"}}, "Duplicate version 1 in `secrets`. Each version must be unique."},
		{"empty value", []auth.Secret{{Version: 1, Value: ""}}, "Empty secret value for version 1 in `secrets`."},
		{"negative", []auth.Secret{{Version: -1, Value: "x"}}, "Invalid version -1 in `secrets`. Version must be a non-negative integer."},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := auth.ValidateSecretsArray(c.secrets, nil)
			if err == nil {
				t.Fatal("must fail")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q must contain %q", err.Error(), c.want)
			}
			if !strings.HasSuffix(err.Error(), ".") {
				t.Fatalf("error %q must end with upstream's period", err.Error())
			}
		})
	}
}

func TestF6ValidateSecretsArrayWarnings(t *testing.T) {
	var warnings []string
	warnf := func(format string, args ...any) {
		if len(args) > 0 {
			warnings = append(warnings, fmt.Sprintf(format, args...))
		} else {
			warnings = append(warnings, format)
		}
	}
	if err := auth.ValidateSecretsArray([]auth.Secret{{Version: 3, Value: "short"}}, warnf); err != nil {
		t.Fatalf("validate: %v", err)
	}
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "version 3") || !strings.Contains(joined, "32 characters") {
		t.Fatalf("short current secret must warn with version, got %v", warnings)
	}
	warnings = nil
	if err := auth.ValidateSecretsArray([]auth.Secret{{Version: 0, Value: strings.Repeat("a", 32)}}, warnf); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !strings.Contains(strings.Join(warnings, "\n"), "low-entropy") {
		t.Fatalf("low-entropy current secret must warn, got %v", warnings)
	}
}

func TestF6SecretPrecedence(t *testing.T) {
	adapter, _ := newTestAdapter(t)
	newAuth := func(t *testing.T) auth.Auth {
		t.Helper()
		return mustBetterAuth(t, auth.Options{Secret: "", Adapter: adapter})
	}
	_ = newAuth
	t.Run("option wins over env", func(t *testing.T) {
		t.Setenv("BETTER_AUTH_SECRET", "env-secret-that-is-long-enough-12345678")
		t.Setenv("BETTER_AUTH_SECRETS", "")
		a := mustBetterAuth(t, auth.Options{Secret: "option-secret-that-is-long-enough-12", Adapter: adapter})
		if a.Context.Secret != "option-secret-that-is-long-enough-12" {
			t.Fatalf("option secret must win, got %q", a.Context.Secret)
		}
	})
	t.Run("BETTER_AUTH_SECRET over AUTH_SECRET", func(t *testing.T) {
		t.Setenv("BETTER_AUTH_SECRET", "better-auth-secret-that-is-long-enough")
		t.Setenv("AUTH_SECRET", "auth-secret-that-is-long-enough-123456")
		t.Setenv("BETTER_AUTH_SECRETS", "")
		a := mustBetterAuth(t, auth.Options{Adapter: adapter})
		if a.Context.Secret != "better-auth-secret-that-is-long-enough" {
			t.Fatalf("BETTER_AUTH_SECRET must win, got %q", a.Context.Secret)
		}
	})
	t.Run("AUTH_SECRET fallback", func(t *testing.T) {
		t.Setenv("BETTER_AUTH_SECRET", "")
		t.Setenv("AUTH_SECRET", "auth-secret-that-is-long-enough-123456")
		t.Setenv("BETTER_AUTH_SECRETS", "")
		// os.LookupEnv sees "" as set-but-empty; resolveSecrets must treat it
		// as unset (upstream falsy), falling through to AUTH_SECRET.
		a := mustBetterAuth(t, auth.Options{Adapter: adapter})
		if a.Context.Secret != "auth-secret-that-is-long-enough-123456" {
			t.Fatalf("AUTH_SECRET must be the fallback, got %q", a.Context.Secret)
		}
	})
}

// NEEDS-FIX (pre-fix: missing the trailing period): documents the intentional
// fail-closed deviation — upstream falls back to the public DEFAULT_SECRET
// outside production, Go errors in every environment.
func TestF6MissingSecretFailsClosed(t *testing.T) {
	t.Setenv("BETTER_AUTH_SECRET", "")
	t.Setenv("AUTH_SECRET", "")
	t.Setenv("BETTER_AUTH_SECRETS", "")
	adapter, _ := newTestAdapter(t)
	_, err := auth.BetterAuth(auth.Options{Adapter: adapter})
	if err == nil {
		t.Fatal("empty resolved secret must fail (fail-closed deviation from DEFAULT_SECRET fallback)")
	}
	if !strings.Contains(err.Error(), "BETTER_AUTH_SECRET is missing.") {
		t.Fatalf("error %q must match upstream validateSecret body", err.Error())
	}
}

// NEEDS-FIX (pre-fix: wording diverged): upstream validateSecret rejects the
// default secret in production with an exact message.
func TestF6DefaultSecretProduction(t *testing.T) {
	t.Setenv("NODE_ENV", "production")
	adapter, _ := newTestAdapter(t)
	_, err := auth.BetterAuth(auth.Options{Secret: auth.DefaultSecret, Adapter: adapter})
	if err == nil {
		t.Fatal("default secret in production must fail")
	}
	if !strings.Contains(err.Error(), "You are using the default secret.") {
		t.Fatalf("error %q must match upstream validateSecret body", err.Error())
	}
}

// NEEDS-FIX (pre-fix: warning lacked the generation hint): upstream
// validateSecret appends a generation hint to the <32 warning.
func TestF6LegacyShortSecretWarning(t *testing.T) {
	t.Setenv("BETTER_AUTH_SECRET", "")
	t.Setenv("AUTH_SECRET", "")
	t.Setenv("BETTER_AUTH_SECRETS", "")
	got, logger := f6CaptureLogger(types.LogLevelDebug)
	adapter, _ := newTestAdapter(t)
	mustBetterAuth(t, auth.Options{Secret: "short", Adapter: adapter, Logger: logger})
	joined := strings.Join(*got, "\n")
	if !strings.Contains(joined, "should be at least 32 characters long") {
		t.Fatalf("short legacy secret must warn, got %v", *got)
	}
	if !strings.Contains(joined, "openssl rand -base64 32") {
		t.Fatalf("short-secret warning must carry upstream's generation hint, got %v", *got)
	}
}

func TestF6VersionedRotation(t *testing.T) {
	adapter, _ := newTestAdapter(t)
	a := mustBetterAuth(t, auth.Options{
		Secret:  "legacy-secret-that-is-long-enough-12345678",
		Secrets: []auth.Secret{{Version: 2, Value: "new-secret-that-is-long-enough-1234567"}, {Version: 1, Value: "old-secret-that-is-long-enough-1234567"}},
		Adapter: adapter,
	})
	if a.Context.Secret != "new-secret-that-is-long-enough-1234567" {
		t.Fatalf("current secret must be the first entry, got %q", a.Context.Secret)
	}
	cfg := a.Context.SecretConfig
	if cfg.CurrentVersion != 2 || cfg.Keys[2] != "new-secret-that-is-long-enough-1234567" || cfg.Keys[1] != "old-secret-that-is-long-enough-1234567" {
		t.Fatalf("config must honor numeric versions, got %+v", cfg)
	}
	if cfg.LegacySecret != "legacy-secret-that-is-long-enough-12345678" {
		t.Fatalf("non-default legacy secret must be retained, got %q", cfg.LegacySecret)
	}
	if a.Context.Options.Secret != "new-secret-that-is-long-enough-1234567" {
		t.Fatalf("resolved secret must surface on options, got %q", a.Context.Options.Secret)
	}
}

func TestF6RotationDuplicateVersionsFail(t *testing.T) {
	adapter, _ := newTestAdapter(t)
	_, err := auth.BetterAuth(auth.Options{
		Secret:  f6Secret,
		Secrets: []auth.Secret{{Version: 1, Value: "a-secret-value"}, {Version: 1, Value: "b-secret-value"}},
		Adapter: adapter,
	})
	if err == nil || !strings.Contains(err.Error(), "Duplicate version 1") {
		t.Fatalf("duplicate rotation versions must fail, got %v", err)
	}
}

// NEEDS-FIX (pre-fix: whitespace env fell through to the missing-secret
// error): upstream parseSecretsEnv throws on whitespace-only input instead of
// treating it as unset.
func TestF6WhitespaceSecretsEnvFails(t *testing.T) {
	t.Setenv("BETTER_AUTH_SECRETS", "   ")
	t.Setenv("BETTER_AUTH_SECRET", "")
	t.Setenv("AUTH_SECRET", "")
	adapter, _ := newTestAdapter(t)
	_, err := auth.BetterAuth(auth.Options{Adapter: adapter})
	if err == nil || !strings.Contains(err.Error(), "Invalid BETTER_AUTH_SECRETS entry") {
		t.Fatalf("whitespace BETTER_AUTH_SECRETS must raise the parse error, got %v", err)
	}
}

func TestF6TelemetryDisabledSilent(t *testing.T) {
	t.Setenv("BETTER_AUTH_TELEMETRY", "")
	t.Setenv("BETTER_AUTH_TELEMETRY_DEBUG", "")
	got, logger := f6CaptureLogger(types.LogLevelDebug)
	adapter, _ := newTestAdapter(t)
	a := mustBetterAuth(t, auth.Options{Secret: f6Secret, Adapter: adapter, Logger: logger, BaseURL: "https://app.example.com"})
	if len(*got) != 0 {
		t.Fatalf("disabled telemetry must stay silent, got %v", *got)
	}
	if a.Context.PublishTelemetry == nil {
		t.Fatal("PublishTelemetry must be attached even when disabled")
	}
	a.Context.PublishTelemetry(types.TelemetryEvent{Type: "test", Payload: map[string]any{"k": "v"}})
	if len(*got) != 0 {
		t.Fatalf("disabled publish must be a noop, got %v", *got)
	}
}

// NEEDS-FIX (pre-fix: debug log omitted AnonymousID): the publish path must
// preserve the full upstream event shape {type, anonymousId, payload}.
func TestF6TelemetryDebugPreservesEventShape(t *testing.T) {
	t.Setenv("BETTER_AUTH_TELEMETRY", "")
	t.Setenv("BETTER_AUTH_TELEMETRY_DEBUG", "")
	got, logger := f6CaptureLogger(types.LogLevelDebug)
	adapter, _ := newTestAdapter(t)
	a := mustBetterAuth(t, auth.Options{
		Secret:    f6Secret,
		Adapter:   adapter,
		Logger:    logger,
		Telemetry: types.TelemetryOptions{Enabled: true, Debug: true},
	})
	*got = nil
	a.Context.PublishTelemetry(types.TelemetryEvent{Type: "evt", AnonymousID: "anon-1", Payload: map[string]any{"k": "v"}})
	joined := strings.Join(*got, "\n")
	for _, want := range []string{"evt", "anon-1", "k"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("debug publish must preserve full event shape, want %q in %v", want, *got)
		}
	}
}

func TestF6TelemetryNonDebugHidesPayload(t *testing.T) {
	t.Setenv("BETTER_AUTH_TELEMETRY", "")
	t.Setenv("BETTER_AUTH_TELEMETRY_DEBUG", "")
	got, logger := f6CaptureLogger(types.LogLevelDebug)
	adapter, _ := newTestAdapter(t)
	a := mustBetterAuth(t, auth.Options{
		Secret:    f6Secret,
		Adapter:   adapter,
		Logger:    logger,
		Telemetry: types.TelemetryOptions{Enabled: true},
	})
	*got = nil
	a.Context.PublishTelemetry(types.TelemetryEvent{Type: "evt", Payload: map[string]any{"super": "secret-payload-value"}})
	joined := strings.Join(*got, "\n")
	if !strings.Contains(joined, "evt") {
		t.Fatalf("publish must note the event type, got %v", *got)
	}
	if strings.Contains(joined, "secret-payload-value") {
		t.Fatalf("non-debug publish must not log payloads, got %v", *got)
	}
}

// NEEDS-FIX (pre-fix: only 1/true/yes enabled): enablement parsing must match
// upstream getBooleanEnvVar (any non-empty value except "0"/"false").
func TestF6TelemetryEnvTruthiness(t *testing.T) {
	t.Setenv("BETTER_AUTH_TELEMETRY_DEBUG", "")
	for _, tc := range []struct {
		value   string
		enabled bool
	}{
		{"2", true},
		{"TRUE", true},
		{"yes", true},
		{"1", true},
		{"false", false},
		{"FALSE", false},
		{"0", false},
		{"", false},
	} {
		t.Run("env="+tc.value, func(t *testing.T) {
			t.Setenv("BETTER_AUTH_TELEMETRY", tc.value)
			got, logger := f6CaptureLogger(types.LogLevelDebug)
			adapter, _ := newTestAdapter(t)
			mustBetterAuth(t, auth.Options{Secret: f6Secret, Adapter: adapter, Logger: logger})
			found := false
			for _, line := range *got {
				if strings.Contains(line, "telemetry") {
					found = true
				}
			}
			if found != tc.enabled {
				t.Fatalf("env %q: telemetry diagnostic present = %v, want %v (got %v)", tc.value, found, tc.enabled, *got)
			}
		})
	}
}

func TestF6TelemetryInitDiagnostic(t *testing.T) {
	t.Setenv("BETTER_AUTH_TELEMETRY", "")
	t.Setenv("BETTER_AUTH_TELEMETRY_DEBUG", "")
	got, logger := f6CaptureLogger(types.LogLevelDebug)
	adapter, _ := newTestAdapter(t)
	mustBetterAuth(t, auth.Options{
		Secret:    f6Secret,
		Adapter:   adapter,
		Logger:    logger,
		Telemetry: types.TelemetryOptions{Enabled: true},
	})
	joined := strings.Join(*got, "\n")
	if !strings.Contains(joined, `"init"`) {
		t.Fatalf("construction must publish the init diagnostic, got %v", *got)
	}
}

func TestF6WithSpanPassthrough(t *testing.T) {
	adapter, _ := newTestAdapter(t)
	a := mustBetterAuth(t, auth.Options{Secret: f6Secret, Adapter: adapter})
	out, err := auth.WithSpan(a.Context.Options, "f6-op", map[string]string{"k": "v"}, func() (string, error) {
		return "ok", nil
	})
	if err != nil || out != "ok" {
		t.Fatalf("WithSpan must pass values through, got %q, %v", out, err)
	}
	boom := &f6SentinelError{msg: "boom"}
	if _, err := auth.WithSpan(a.Context.Options, "f6-fail", nil, func() (string, error) {
		return "", boom
	}); err != boom {
		t.Fatalf("WithSpan must propagate errors, got %v", err)
	}
	// Explicitly disabled instrumentation still executes inline (upstream
	// noopWithSpan calls fn directly).
	disabled := false
	ran := false
	if _, err := auth.WithSpan(auth.Options{
		Experimental: types.ExperimentalOptions{
			Instrumentation: types.InstrumentationOptions{Enabled: &disabled},
		},
	}, "f6-off", nil, func() (bool, error) {
		ran = true
		return true, nil
	}); err != nil || !ran {
		t.Fatalf("disabled instrumentation must still execute, ran=%v err=%v", ran, err)
	}
}

type f6SentinelError struct{ msg string }

func (e *f6SentinelError) Error() string { return e.msg }

func TestF6AppNameDefaults(t *testing.T) {
	adapter, _ := newTestAdapter(t)
	a := mustBetterAuth(t, auth.Options{Secret: f6Secret, Adapter: adapter})
	if a.Context.AppName != "Better Auth" || a.Context.Options.AppName != "Better Auth" {
		t.Fatalf("unset AppName must default, got ctx=%q opts=%q", a.Context.AppName, a.Context.Options.AppName)
	}
}
