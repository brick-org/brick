# Adding a plugin

Core stays core: plugins live outside `auth/src`, implement `types.Plugin`,
and are passed via `Options.Plugins`. No core file changes needed.

## 1. Skeleton

```go
type MyPlugin struct{ /* config */ }

func (p *MyPlugin) ID() string { return "my-plugin" }

func (p *MyPlugin) Init(ctx types.AuthContext) error {
    // Validate config. Return non-nil to abort BetterAuth construction.
    return nil
}

func (p *MyPlugin) Endpoints() []types.Endpoint {
    return []types.Endpoint{{
        Method: "POST", Path: "/my-action", OperationID: "myAction",
        Summary: "One-line summary",
        Register: func(api any, basePath string, opts types.Options) {
            // Mirror a core registrar: huma.Operation + registerAuthOperation.
            // See routes/sign-out.go (smallest full example).
        },
    }}
}

func (p *MyPlugin) Schema() types.PluginSchema      { return nil }   // or tables/fields
func (p *MyPlugin) Hooks() types.DBHooks            { return nil }   // model lifecycle
func (p *MyPlugin) RouteHooks() types.PluginRouteHooks { return nil } // path matchers
func (p *MyPlugin) ErrorCodes() map[string]string   { return nil }   // code -> message
```

```go
auth.BetterAuth(auth.Options{
    // ... core options ...
    Plugins: []types.Plugin{&MyPlugin{}},
})
```

## 2. What each piece does

- **Endpoints**: `Path` appends to `basePath`. `OperationID` must be unique —
  `checkEndpointConflicts` errors at startup on same-path multi-owner clashes.
  `DisabledPaths` also gates plugin routes (they 404 like core).
- **Schema**: extra tables or fields on core tables merge via `ResolveSchema`.
  Generate migrations with `cmd/generate-schema -plugins my-plugin`.
- **Hooks**: `DBHooks` keys are model names (`user`, `session`, `account`,
  `verification`, custom). Return the sentinel abort to skip a write silently.
- **RouteHooks**: fire around endpoint execution, matched by path.
- **ErrorCodes**: merged into `$ERROR_CODES` — on key conflict BASE wins,
  so prefix codes (`MY_PLUGIN_CODE`).
- **Optional interfaces** (assert at runtime, all optional):
  `PluginInitPatches` (defu option/context patch, applied post-`Init`),
  `PluginNamedEndpointsProvider` (map form, sorted registration),
  `PluginRateLimitProvider` (path-scoped rules),
  `PluginVersion` / `PluginInferProvider` / migration + adapter-override providers.

## 3. Rate limits behave differently for plugins

Core rules fold into the shared `ip|path` bucket. Plugin rules consume a
**second** bucket (`ip|plugin|<id>|path`) pre-handler — strictly stricter
(two decrements on matched paths). Design plugin rules knowing both fire.

## 4. Rules

- Never edit core route files for plugin needs — use `Endpoints`/`RouteHooks`.
- Never touch frozen `src/utils/boolean.go`, `constants.go`, `hide-metadata.go`.
- Trust: validate `callbackURL`-style inputs with `types.IsTrustedRedirect`;
  resolve the request with `trustRequest`/`trustRequestFromHuma` helpers.
- Consume single-use values with `db.ConsumeOneWithFallback`, never FindOne+Delete.
- Tests: humatest + mem adapter pattern (see `routes/redirect_trust_test.go`);
  descriptive file/func names, one-line upstream refs, failure strings intact.
