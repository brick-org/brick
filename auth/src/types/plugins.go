package types

import (
	"context"
	"fmt"
	"net/http"
	"sort"

	"github.com/danielgtaylor/huma/v2"
)

// Plugin extends auth with additional routes, schema, hooks, and error codes.
// Plugins are passed to BetterAuth via options.Plugins.
// Init is called in declaration order during BetterAuth.
type Plugin interface {
	// ID returns a unique identifier for this plugin.
	ID() string

	// Init is called once during auth.BetterAuth with the resolved AuthContext.
	// Plugins may use this to validate configuration or set up state.
	// Return a non-nil error to abort auth initialisation.
	Init(AuthContext) error

	// Endpoints returns the list of HTTP endpoints this plugin provides.
	// Each endpoint's Handler is called during router setup to register routes.
	Endpoints() []Endpoint

	// Schema returns additional DB tables or field extensions on core tables.
	// Plugins that extend the "user" or "session" table add fields here.
	Schema() PluginSchema

	// Hooks returns DB lifecycle hooks (before/after create/update/delete)
	// keyed by model name (e.g. "user", "session").
	Hooks() DBHooks

	// RouteHooks returns route-level before/after hooks with path matchers.
	// These are distinct from DB lifecycle hooks and fire around HTTP endpoint execution.
	RouteHooks() PluginRouteHooks

	// ErrorCodes returns plugin-specific error code constants.
	// Keys are constant names, values are the error message strings.
	ErrorCodes() map[string]string
}

// PluginInitPatch carries upstream plugin-init option/context returns.
//
// Upstream TypeScript name: the `{ options?, context? }` object returned
// from `plugin.init()`. Options patches are merged defu-style (existing
// values win; databaseHooks/trustedOrigins are collected separately with
// `plugin:<id>` source labels). Context patches are assigned over the
// resolved context (patch wins).
type PluginInitPatch struct {
	// Options patches BetterAuthOptions. Nil means no option patch.
	// DatabaseHooks and TrustedOrigins/TrustedOriginsFunc are extracted
	// for sourced collection; the remainder merges defu-style.
	Options *Options
	// Context patches AuthContext. Nil means no context patch.
	// Non-zero fields overwrite the resolved context.
	Context *AuthContext
}

// PluginInitPatches is an OPTIONAL interface for plugins that return
// option/context patches from init, mirroring upstream `init` returns.
//
// Checked via type assertion after the legacy Init call; legacy
// Init(AuthContext) error keeps working. If a plugin implements both, Init
// runs first (validation/setup), then InitPatches (patches). A non-nil error
// from either aborts BetterAuth with a wrapped error.
//
// Upstream TypeScript name: the `init()` return value.
type PluginInitPatches interface {
	// InitPatches returns option/context patches for the resolved context.
	InitPatches(AuthContext) (PluginInitPatch, error)
}

// PluginOnRequestResult mirrors better-auth's plugin onRequest return shape.
// A response short-circuits the remaining plugin chain; otherwise request may
// be replaced and passed to the next plugin and the route handler.
type PluginOnRequestResult struct {
	Request  *http.Request
	Response *http.Response
}

// PluginOnResponseResult mirrors better-auth's plugin onResponse return shape.
type PluginOnResponseResult struct {
	Response *http.Response
}

// PluginOnRequestHandler runs before auth routing for a request.
type PluginOnRequestHandler func(request *http.Request, ctx AuthContext) (*PluginOnRequestResult, error)

// PluginOnResponseHandler runs after an auth response is produced.
type PluginOnResponseHandler func(response *http.Response, ctx AuthContext) (*PluginOnResponseResult, error)

// PluginMiddleware is a plugin-declared path-scoped request middleware.
//
// Upstream TypeScript name: BetterAuthPlugin["middlewares"] entry
// ({ path, middleware } in vendor/better-auth/packages/core/src/types/plugin.ts).
type PluginMiddleware struct {
	Path    string
	Handler RequestBeforeHookFunc
}

// PluginRateLimitRule is a plugin-declared path matcher with rate limit settings.
//
// Upstream TypeScript name: BetterAuthPlugin["rateLimit"] entry
// ({ window, max, pathMatcher } in vendor/better-auth/packages/core/src/types/plugin.ts).
type PluginRateLimitRule struct {
	Window      int
	Max         int
	PathMatcher func(path string) bool
}

// PluginOnRequestProvider declares better-auth style plugin onRequest behavior.
//
// Upstream TypeScript name: BetterAuthPlugin["onRequest"].
type PluginOnRequestProvider interface {
	OnRequest() PluginOnRequestHandler
}

// PluginOnResponseProvider declares better-auth style plugin onResponse behavior.
//
// Upstream TypeScript name: BetterAuthPlugin["onResponse"].
type PluginOnResponseProvider interface {
	OnResponse() PluginOnResponseHandler
}

// PluginMiddlewareProvider declares path-scoped plugin middlewares.
//
// Upstream TypeScript name: BetterAuthPlugin["middlewares"].
type PluginMiddlewareProvider interface {
	Middlewares() []PluginMiddleware
}

// PluginRateLimitProvider declares path-scoped plugin rate limit rules.
//
// Upstream TypeScript name: BetterAuthPlugin["rateLimit"].
type PluginRateLimitProvider interface {
	RateLimitRules() []PluginRateLimitRule
}

// PluginRouteBeforeHook is a route-level before hook declared by a plugin.
// Matcher is called for every request; Handler fires only when Matcher returns true.
type PluginRouteBeforeHook struct {
	Matcher func(ctx huma.Context) bool
	Handler RequestBeforeHookFunc
}

// PluginRouteAfterHook is a route-level after hook declared by a plugin.
// Matcher is called for every request; Handler fires only when Matcher returns true.
type PluginRouteAfterHook struct {
	Matcher func(ctx huma.Context) bool
	Handler RequestAfterHookFunc
}

// PluginRouteHooks groups route-level before/after hooks for a plugin.
type PluginRouteHooks struct {
	Before []PluginRouteBeforeHook
	After  []PluginRouteAfterHook
}

// EndpointContext is a portable subset of better-auth's
// GenericEndpointContext for hook and callback authors: the incoming HTTP
// request plus the resolved auth context and basic routing metadata. It
// deliberately omits the full upstream endpoint surface (context services,
// response helpers, inferred session payloads, client-type inference),
// which remains Huma-shaped in this port via huma.Context handlers.
type EndpointContext struct {
	Request     *http.Request
	AuthContext AuthContext
	Method      string
	Path        string
	Headers     http.Header
}

// RequestEndpointContext builds an EndpointContext from a request and auth
// context. Method and Path default to the request's values when empty.
func RequestEndpointContext(r *http.Request, ctx AuthContext, method, path string) EndpointContext {
	out := EndpointContext{Request: r, AuthContext: ctx, Method: method, Path: path}
	if r != nil {
		if out.Method == "" {
			out.Method = r.Method
		}
		if out.Path == "" {
			out.Path = r.URL.Path
		}
		out.Headers = r.Header
	}
	return out
}

// PluginSchema describes the DB schema a plugin requires.
// Keys are model names (e.g. "user", "session", or a new table like "organization").
type PluginSchema map[string]TableSchema

// TableSchema describes a single table's fields.
type TableSchema struct {
	// ModelName is the physical table name. Empty means the logical model
	// name. Mirrors better-auth's schema modelName.
	ModelName string
	Fields    map[string]FieldAttribute
	// Indexes declares table-level indexes, including compound indexes.
	// Mirrors better-auth's DBTableIndex entries. Types only; index
	// creation is adapter-dependent.
	Indexes []TableIndex
	// DisableMigration skips migration for this table (legacy bool).
	// Deprecated: use DisableMigrations for presence-safe last-wins
	// merging (explicit false wins). When DisableMigrations is non-nil it
	// determines the effective value and DisableMigration is synced to it;
	// otherwise DisableMigration OR-accumulates for backwards compatibility
	// (true sticks, explicit false inexpressible). New code must use
	// DisableMigrations.
	DisableMigration bool
	// DisableMigrations is the presence-safe migration flag mirroring
	// upstream `disableMigrations` (`disableMigration ?? previous`
	// last-wins, `in`-presence check for index skipping). Nil means absent
	// (inherit previous); non-nil (including explicit false) wins. When set,
	// MergeSchemas syncs DisableMigration to *DisableMigrations for legacy
	// readers. Upstream TypeScript name: disableMigrations.
	DisableMigrations *bool
	// Order hints migration/creation ordering. Mirrors better-auth's
	// schema order field.
	Order int
}

// DisableMigrationsEffective reports the effective migration skip: when
// DisableMigrations is non-nil its value wins (presence-safe last-wins);
// otherwise the legacy DisableMigration bool applies.
func (t TableSchema) DisableMigrationsEffective() bool {
	if t.DisableMigrations != nil {
		return *t.DisableMigrations
	}
	return t.DisableMigration
}

// PluginSchemaProvider supplies plugin schemas without implementing the full
// Plugin interface (endpoints/hooks/etc.). It unblocks out-of-module plugins
// that only need schema generation (e.g. via generate-schema's arbitrary
// schema support): any auth.Plugin already satisfies it via Schema(), and
// schema-only providers can implement just Schema().
//
// Upstream has no such interface (schemas come from full plugin objects);
// this is Go-only infrastructure for the generator.
type PluginSchemaProvider interface {
	Schema() PluginSchema
}

// TableIndex describes a database index spanning one or more logical schema
// fields, in index order. Mirrors better-auth's DBTableIndex: one to sixteen
// field names, a portable index name of at most 63 UTF-8 bytes, and an
// optional uniqueness constraint. Types only; enforcement is
// adapter-dependent.
type TableIndex struct {
	Fields []string
	Name   string
	Unique bool
}

// FieldType mirrors better-auth's DBFieldType.
type FieldType string

const (
	FieldTypeString  FieldType = "string"
	FieldTypeNumber  FieldType = "number"
	FieldTypeBoolean FieldType = "boolean"
	FieldTypeDate    FieldType = "date"
	FieldTypeJSON    FieldType = "json"
)

// FieldTransform mirrors better-auth's DBFieldAttribute transform hooks:
// it converts a value before storage (Input) and after retrieval (Output).
// Upstream transforms are async value-to-value functions; the Go form
// additionally reports errors, which abort the operation.
type FieldTransform struct {
	Input  func(value any) (any, error)
	Output func(value any) (any, error)
}

// FieldValidator mirrors better-auth's DBFieldAttribute validator hooks.
//
// Upstream accepts any Standard Schema object (Zod, Valibot, ArkType — see
// DBFieldAttributeConfig["validator"] in
// vendor/better-auth/packages/core/src/db/type.ts); the portable Go
// equivalent is a pair of synchronous validation functions for stored
// (Input) and returned (Output) values. A non-nil error rejects the write.
//
// Manual adaptation is required: port each Standard Schema to a
// FieldValidatorFunc (see NewFieldValidator) — there is no automatic
// Zod/Valibot/ArkType bridge, no async support, and no TypeScript-style
// type inference (upstream InferDBFieldInput/InferDBFieldsInput and friends
// have no Go equivalent; field types stay dynamic `any`). Async validators
// must be made synchronous by the caller; returning an async-not-supported
// error surfaces upstream code ASYNC_VALIDATION_NOT_SUPPORTED
// (see ErrAsyncValidationNotSupported).
type FieldValidator struct {
	Input  FieldValidatorFunc
	Output FieldValidatorFunc
}

// FieldAttribute describes a single DB field, mirroring better-auth's DBFieldAttribute.
type FieldAttribute struct {
	Type         FieldType
	Required     *bool // nil = default true
	Returned     *bool // nil = default true
	Input        *bool // nil = default true
	Unique       bool
	DefaultValue any
	References   *FieldReference
	// OnUpdate produces the value written on record updates for supported
	// adapters. Mirrors better-auth's onUpdate hook. Nil means no trigger.
	OnUpdate func() any
	// Transform converts values on the storage round-trip. Executed by
	// HookedAdapter when field schemas are provided (input side on writes,
	// output side on reads); without schemas the adapter leaves values
	// untouched.
	Transform *FieldTransform
	// BigInt stores the field as a bigint instead of an integer.
	BigInt bool
	// Validator validates stored and returned values. HookedAdapter executes
	// the Input side on writes (a rejection aborts the operation); the
	// Output side is not executed by the runtime, mirroring upstream (which
	// validates inputs in parseInputData and never validates outputs). See
	// FieldValidator for the manual Standard Schema adaptation contract
	// (sync only; async maps to ASYNC_VALIDATION_NOT_SUPPORTED, see
	// ErrAsyncValidationNotSupported).
	Validator *FieldValidator
	// FieldName overrides the physical column name. Mirrors better-auth's
	// fieldName. Accepted and preserved; route-level decoding is incomplete
	// (see the PARITY row-key contract note).
	FieldName string
	// Sortable marks text fields for varchar-style sorting. Mirrors
	// better-auth's sortable flag.
	Sortable bool
	// Index marks the field as indexed. Upstream default: false. Types
	// only; index creation is adapter-dependent.
	Index bool
}

// FieldReference describes a foreign key relationship.
type FieldReference struct {
	Model    string
	Field    string
	OnDelete string // "cascade" | "set null" | "restrict" | "no action" | "set default"
}

// DBHooks maps model names to their lifecycle hooks.
// Example keys: "user", "session", "account", "verification", or any plugin-defined model.
// See ModelUser/ModelAccount/ModelSession/ModelVerification/ModelRateLimit
// for the upstream BaseModelNames/ModelNames spellings.
//
// Behavior (payloads, abort, timing) is owned by auth/hooked_adapter.go
// (HookedAdapter, read-only reference — do not duplicate its logic here):
//   - Create/Update/UpdateMany before hooks receive the pending write
//     payload; Delete/DeleteMany/ConsumeOne before hooks receive the
//     pre-read row(s) (see OperationHooks.Before).
//   - UpdateMany reuses the Update hooks; the row-typed after hook still
//     receives nil while AfterBulk carries the bulk result count (upstream
//     passes the count to the shared update.after hook).
//   - ConsumeOne fires the Delete hooks around the atomic consume.
//   - IncrementOne, FindOne, FindMany, and Count have no hooks.
//   - After hooks run synchronously outside transactions and defer past a
//     successful Transaction commit inside them (skipped on rollback);
//     after-hook errors are logged, never fatal.
type DBHooks map[string]ModelHooks

// ModelHooks groups lifecycle hooks for a single model.
//
// Only Create, Update, and Delete hook groups exist: there are no separate
// UpdateMany/DeleteMany/ConsumeOne groups. UpdateMany shares the Update
// group and DeleteMany/ConsumeOne share the Delete group (mirroring
// upstream updateManyWithHooks/deleteManyWithHooks/consumeOneWithHooks in
// vendor/better-auth/packages/better-auth/src/db/with-hooks.ts, as wired by
// auth/hooked_adapter.go).
type ModelHooks struct {
	Create OperationHooks
	Update OperationHooks
	Delete OperationHooks
}

// OperationHooks holds before/after callbacks for a single operation.
//
// Per-operation payload shapes as wired by auth/hooked_adapter.go
// (HookedAdapter; upstream with-hooks.ts):
//
//	Create:      before receives the pending create payload; after receives
//	             the created row.
//	Update:      before receives the update payload (not the where clause);
//	             after receives the updated row.
//	UpdateMany:  shares the Update group. Before receives the bulk update
//	             payload (merged, never replaced). ErrHookAbort resolves to
//	             (0, nil). The row-typed After hook still fires with nil for
//	             backwards compatibility; AfterBulk carries the bulk result
//	             count (upstream passes it to the shared update.after hook,
//	             which the row-typed AfterHookFunc cannot carry).
//	Delete:      the row is pre-read first. No match skips before hooks, the
//	             write, and after hooks. A pre-read failure fails closed (the
//	             error is returned, no hooks or write run). Before receives
//	             the fetched row (its return map is ignored — only the error
//	             matters); after receives the fetched row.
//	DeleteMany:  all matching rows are pre-read first. A pre-read failure is
//	             logged (when a logger is configured) and deletion proceeds
//	             with zero hooks; an empty match fires zero hooks while the
//	             write still runs. Before runs per row (any error aborts the
//	             whole operation; ErrHookAbort resolves to (0, nil)); after
//	             runs per pre-read row.
//	ConsumeOne:  shares the Delete group. A best-effort snapshot feeds the
//	             before hooks (skipped when no row is visible); ErrHookAbort
//	             skips the consume with (nil, nil). Atomic-race losers
//	             resolve to (nil, nil) without firing after hooks; after
//	             receives the consumed row.
//	IncrementOne: has no hooks and delegates directly (no before/after fire).
//
// Field validators/transforms (FieldAttribute.Validator/Transform) execute
// around the hooked writes when the adapter carries field schemas (see
// auth.HookedAdapterOptions.FieldSchemas): Validator.Input then
// Transform.Input run on the pending payload before before-hooks; a
// rejection aborts the operation. Transform.Output runs on rows returned
// from Create/Update/FindOne/FindMany/IncrementOne/ConsumeOne.
// Validator.Output is never executed, mirroring upstream.
//
// Abort and timing rules (all operations):
//   - Before may return:
//   - (mutatedData, nil) to proceed with mutated data. The non-nil map is
//     MERGED over the pending payload (mutated keys win, omitted keys
//     survive), mirroring upstream's {...actualData, ...result.data} in
//     with-hooks.ts (see auth/hooked_adapter.go).
//   - (nil, err) to abort the operation with an error (no write, no afters).
//   - (nil, ErrHookAbort) to abort silently with null and no write
//     (no error surfaced; upstream `return false` equivalent). Detect with
//     errors.Is (the sentinel may be wrapped).
//   - (nil, nil) to proceed with original data unchanged.
//   - After is called after the DB operation succeeds. Errors returned from
//     After are logged but do not roll back the operation. Inside
//     transactions, afters defer past successful commit (flushed on success,
//     skipped on rollback) and post-commit failures propagate from
//     Transaction unless the adapter carries an after-commit error handler;
//     outside transactions they run synchronously.
//     Post-commit flush failures propagate from Transaction (failing the
//     call without rolling back committed work) unless an
//     onAfterCommitHookError-style handler is installed on the adapter.
type OperationHooks struct {
	// Before is called before the DB operation.
	// It receives the data about to be written. It may return:
	//   - (mutatedData, nil) to proceed with mutated data (MERGED over the
	//     pending payload: mutated keys win, omitted keys survive)
	//   - (nil, err) to abort the operation with an error
	//   - (nil, ErrHookAbort) to abort silently with null and no write
	//     (no error surfaced; upstream `return false` equivalent)
	//   - (nil, nil) to proceed with original data unchanged
	Before BeforeHookFunc

	// After is called after the DB operation succeeds.
	// Errors returned from After are logged but do not roll back the operation.
	// Inside transactions, afters defer past successful commit (flush on
	// success, skipped on rollback); outside transactions they run
	// synchronously. Post-commit failures propagate from Transaction unless
	// the adapter carries an after-commit error handler.
	After AfterHookFunc

	// AfterBulk is an OPTIONAL bulk-result hook fired for UpdateMany (which
	// shares the Update group) with the affected-row count, mirroring
	// upstream updateManyWithHooks passing the bulk result to update.after.
	// The row-typed After hook keeps firing with nil for backwards
	// compatibility; AfterBulk carries what After cannot. Nil means no bulk
	// notification. Errors follow the same log/propagate rules as After.
	AfterBulk AfterBulkHookFunc
}

// BeforeHookFunc is called before a DB operation.
//
// Payload by operation (see OperationHooks and auth/hooked_adapter.go):
// Create/Update/UpdateMany receive the pending write payload (UpdateMany
// shares the Update hooks); Delete/DeleteMany/ConsumeOne receive the
// pre-read row (DeleteMany/ConsumeOne share the Delete hooks).
// Return non-nil map to MERGE over the pending payload (mutated keys win,
// omitted keys survive), mirroring upstream's {...actualData, ...result.data};
// return nil map with nil error to keep original. Return (nil, ErrHookAbort)
// to abort silently with null and no write.
type BeforeHookFunc func(ctx context.Context, data map[string]any) (map[string]any, error)

// AfterHookFunc is called after a DB operation succeeds.
//
// Payload by operation (see OperationHooks and auth/hooked_adapter.go):
// Create/Update receive the written row; UpdateMany receives nil (the bulk
// count goes to the AfterBulk hook instead); Delete/DeleteMany/ConsumeOne
// receive the pre-read/consumed row. Runs synchronously outside transactions
// and post-commit inside them (skipped on rollback); errors from synchronous
// runs are logged, never fatal; post-commit failures propagate from
// Transaction unless the adapter carries an after-commit error handler.
type AfterHookFunc func(ctx context.Context, data map[string]any) error

// AfterBulkHookFunc is called after an UpdateMany bulk write succeeds with
// the affected-row count, mirroring upstream updateManyWithHooks passing the
// bulk result to the shared update.after hook (which the row-typed
// AfterHookFunc cannot carry in Go). It fires alongside After (which keeps
// receiving nil for backwards compatibility). Inside transactions it defers
// past successful commit like After; errors follow the same log/propagate
// rules as After.
type AfterBulkHookFunc func(ctx context.Context, count int) error

// ErrHookAbort aborts a hooked write silently with null and no error.
//
// Return (nil, ErrHookAbort) from a Before hook to skip the write and all
// after hooks without surfacing an error, mirroring upstream's literal
// `false` return in with-hooks.ts. Per-operation resolution is owned by
// auth/hooked_adapter.go (HookedAdapter, read-only reference):
// Create/Update resolve to (nil, nil); UpdateMany/DeleteMany resolve to
// (0, nil); Delete resolves to nil; ConsumeOne resolves to (nil, nil).
// Always match with errors.Is (the sentinel may be wrapped).
var ErrHookAbort error = errHookAbortSentinel{}

type errHookAbortSentinel struct{}

func (errHookAbortSentinel) Error() string { return "auth: hook abort" }

// Endpoint describes an HTTP endpoint provided by a plugin.
type Endpoint struct {
	// Method is the HTTP method (GET, POST, etc.).
	Method string
	// Path is the route path suffix (e.g. "/test-ping"), appended to basePath.
	Path string
	// OperationID for the OpenAPI spec.
	OperationID string
	// Summary for the OpenAPI spec.
	Summary string
	// Register is called during router setup to register this endpoint on the Huma API.
	// It receives the Huma API, basePath, and auth options.
	Register EndpointRegisterFunc
}

// EndpointRegisterFunc registers a plugin endpoint on the Huma API.
// It is the same signature pattern used by core route registration functions.
type EndpointRegisterFunc func(api any, basePath string, opts Options)

// Model name constants for DBHooks keys and plugin schema tables.
//
// Upstream TypeScript names: BaseModelNames ("user" | "account" | "session" |
// "verification") plus the "rate-limit" member of ModelNames in
// vendor/better-auth/packages/core/src/db/type.ts. Custom plugin models
// remain free-form strings.
const (
	// ModelUser is the "user" model key.
	ModelUser = "user"
	// ModelAccount is the "account" model key.
	ModelAccount = "account"
	// ModelSession is the "session" model key.
	ModelSession = "session"
	// ModelVerification is the "verification" model key.
	ModelVerification = "verification"
	// ModelRateLimit is the "rate-limit" model key (a ModelNames member
	// outside BaseModelNames upstream).
	ModelRateLimit = "rate-limit"
)

// PluginVersionProvider is an OPTIONAL plugin capability mirroring
// upstream's `version?: string` field (BetterAuthPlugin in
// vendor/better-auth/packages/core/src/types/plugin.ts).
//
// Discovered via type assertion alongside the legacy Plugin interface;
// plugins that do not implement it keep working unchanged.
type PluginVersionProvider interface {
	// Version returns the plugin version. Empty means unversioned.
	Version() string
}

// PluginOptionsProvider is an OPTIONAL plugin capability mirroring
// upstream's `options?: Record<string, any>` field (BetterAuthPlugin in
// vendor/better-auth/packages/core/src/types/plugin.ts).
//
// Discovered via type assertion alongside the legacy Plugin interface;
// plugins that do not implement it keep working unchanged.
type PluginOptionsProvider interface {
	// PluginOptions returns the plugin's own option bag. Nil means none.
	PluginOptions() map[string]any
}

// PluginInferProvider is an OPTIONAL plugin capability mirroring upstream's
// `$Infer?: Record<string, any>` field (BetterAuthPlugin in
// vendor/better-auth/packages/core/src/types/plugin.ts). The Go identifier
// drops the `$` prefix, which is not expressible in Go.
//
// Type-inference adaptation stays manual: upstream derives client and
// session types from $Infer at compile time, which has no Go equivalent.
// This provider only carries the declared shape for documentation and
// generator consumers; nothing infers types from it.
type PluginInferProvider interface {
	// Infer returns the plugin's declared inference shape. Nil means none.
	Infer() map[string]any
}

// PluginMigration mirrors a kysely Migration entry carried by upstream's
// `migrations?: Record<string, Migration>` plugin field (BetterAuthPlugin in
// vendor/better-auth/packages/core/src/types/plugin.ts). Only use this when
// bypassing the schema option with per-table migration control; schema
// driven tables migrate automatically.
type PluginMigration struct {
	// Up applies the migration. Nil means no-op.
	Up func(ctx context.Context) error
	// Down reverts the migration. Nil means irreversible.
	Down func(ctx context.Context) error
}

// PluginMigrationsProvider is an OPTIONAL plugin capability mirroring
// upstream's `migrations?: Record<string, Migration>` field
// (BetterAuthPlugin in vendor/better-auth/packages/core/src/types/plugin.ts).
//
// Collected by CollectPluginMigrations (later plugins win on name
// collisions) and executed in sorted order by RunPluginMigrationsUp.
// Schema-driven tables still migrate automatically; manual migrations are
// the escape hatch for tables that bypass the schema option, exactly as
// upstream documents. Discovered via type assertion alongside the legacy
// Plugin interface.
type PluginMigrationsProvider interface {
	// Migrations returns manual migrations keyed by migration name.
	// Nil means none.
	Migrations() map[string]PluginMigration
}

// PluginAdapterOverrideFunc overrides a single database operation for a
// plugin, mirroring one entry of upstream's
// `adapter?: { [key: string]: (...args: any[]) => Awaitable<any> }` field
// (BetterAuthPlugin in vendor/better-auth/packages/core/src/types/plugin.ts).
// Upstream operations are async; the Go form is synchronous and reports
// errors directly.
type PluginAdapterOverrideFunc func(ctx context.Context, args ...any) (any, error)

// PluginAdapterOverrides maps operation names (e.g. "create", "findOne") to
// plugin-supplied database operation overrides.
//
// Upstream TypeScript name: BetterAuthPlugin["adapter"].
type PluginAdapterOverrides map[string]PluginAdapterOverrideFunc

// PluginAdapterOverridesProvider is an OPTIONAL plugin capability mirroring
// upstream's `adapter?` field (BetterAuthPlugin in
// vendor/better-auth/packages/core/src/types/plugin.ts).
//
// Collected by CollectAdapterOverrides (later plugins win per operation)
// and consulted by HookedAdapter for the hooked write operations,
// mirroring the custom*Fn parameters of with-hooks.ts (hooks still wrap the
// override). Discovered via type assertion alongside the legacy Plugin
// interface.
type PluginAdapterOverridesProvider interface {
	// AdapterOverrides returns database operation overrides keyed by
	// operation name. Nil means none.
	AdapterOverrides() PluginAdapterOverrides
}

// PluginNamedEndpointsProvider is an OPTIONAL plugin capability mirroring
// the upstream map form of `endpoints?: { [key: string]: Endpoint }`
// (BetterAuthPlugin in vendor/better-auth/packages/core/src/types/plugin.ts).
//
// The legacy Endpoints() []Endpoint slice keeps working and remains the
// registration surface; this map form exists for upstream-faithful
// keying (endpoint key -> Endpoint) and is discovered via type assertion.
// CollectPluginEndpoints merges both forms for registration.
type PluginNamedEndpointsProvider interface {
	// NamedEndpoints returns endpoints keyed by upstream endpoint key.
	// Nil means none.
	NamedEndpoints() map[string]Endpoint
}

// PluginHookContext is the TypeScript-faithful route-hook context,
// mirroring upstream's HookEndpointContext
// (vendor/better-auth/packages/core/src/types/plugin.ts): a partial
// endpoint/input context plus the auth context carrying the returned value
// and response headers.
//
// It sits alongside the legacy Huma-shaped route hooks
// (PluginRouteBeforeHook/PluginRouteAfterHook over huma.Context), which keep
// working unchanged. Handlers over this context are OPTIONAL and discovered
// via type assertion (see PluginTSRouteHooksProvider); the routes package
// runs them around handlers (see RunTSRouteBeforeHooks/RunTSRouteAfterHooks
// in auth/api/routes).
type PluginHookContext struct {
	// Request is the incoming HTTP request. May be nil, mirroring upstream
	// hooks invoked without one.
	Request *http.Request
	// Method is the HTTP method. Empty when unknown.
	Method string
	// Path is the request path. Empty when unknown.
	Path string
	// Headers are the request headers. May be nil.
	Headers http.Header
	// AuthContext is the resolved auth context.
	AuthContext AuthContext
	// Returned carries the endpoint's returned value (upstream
	// context.returned), set for after hooks.
	Returned any
	// ResponseHeaders carries mutable response headers (upstream
	// context.responseHeaders). May be nil.
	ResponseHeaders http.Header
}

// PluginTSRouteBeforeHook is a TypeScript-faithful route-level before hook,
// mirroring one entry of upstream's `hooks.before` array
// ({ matcher, handler: AuthMiddleware } in
// vendor/better-auth/packages/core/src/types/plugin.ts) over
// PluginHookContext instead of huma.Context.
//
// OPTIONAL: the legacy Huma-shaped PluginRouteBeforeHook keeps working;
// this shape is discovered via type assertion, collected by
// CollectTSRouteHooks, and run by the routes package around handlers.
type PluginTSRouteBeforeHook struct {
	// Matcher reports whether the hook applies to the request.
	// Nil means always.
	Matcher func(ctx PluginHookContext) bool
	// Handler runs when Matcher accepts. A non-nil error aborts the route.
	// Nil means no-op.
	Handler func(ctx PluginHookContext) error
}

// PluginTSRouteAfterHook is a TypeScript-faithful route-level after hook,
// mirroring one entry of upstream's `hooks.after` array
// ({ matcher, handler: AuthMiddleware } in
// vendor/better-auth/packages/core/src/types/plugin.ts) over
// PluginHookContext instead of huma.Context.
//
// OPTIONAL: the legacy Huma-shaped PluginRouteAfterHook keeps working;
// this shape is discovered via type assertion, collected by
// CollectTSRouteHooks, and run by the routes package around handlers.
type PluginTSRouteAfterHook struct {
	// Matcher reports whether the hook applies to the request.
	// Nil means always.
	Matcher func(ctx PluginHookContext) bool
	// Handler runs when Matcher accepts. Errors are reported, never fatal.
	// Nil means no-op.
	Handler func(ctx PluginHookContext) error
}

// PluginTSRouteHooks groups TypeScript-faithful route-level before/after
// hooks for a plugin.
//
// Upstream TypeScript name: BetterAuthPlugin["hooks"].
type PluginTSRouteHooks struct {
	Before []PluginTSRouteBeforeHook
	After  []PluginTSRouteAfterHook
}

// PluginTSRouteHooksProvider declares TypeScript-faithful route-level hooks
// over PluginHookContext.
//
// Upstream TypeScript name: BetterAuthPlugin["hooks"]. Discovered via type
// assertion alongside the legacy RouteHooks() PluginRouteHooks Huma surface,
// which keeps working unchanged. CollectTSRouteHooks merges providers in
// plugin declaration order; the routes package runs them around handlers.
type PluginTSRouteHooksProvider interface {
	// TSRouteHooks returns the upstream-faithful route hooks.
	TSRouteHooks() PluginTSRouteHooks
}

// FieldValidatorFunc is the Go-faithful field validator function: a
// synchronous check returning nil on success or a non-nil error rejecting
// the value. It is one side (input or output) of FieldValidator.
//
// Manual adaptation contract: each upstream Standard Schema (Zod, Valibot,
// ArkType) must be hand-ported to this func shape. Async schemas have no
// equivalent — make them synchronous or reject async values with an error
// carrying the ASYNC_VALIDATION_NOT_SUPPORTED code (see
// ErrAsyncValidationNotSupported). No type inference is derived from
// validators (upstream InferDB* types have no Go equivalent).
type FieldValidatorFunc func(value any) error

// Validate runs the validator. A nil func accepts every value.
func (fn FieldValidatorFunc) Validate(value any) error {
	if fn == nil {
		return nil
	}
	return fn(value)
}

// NewFieldValidator builds a *FieldValidator from input/output funcs. Nil
// funcs leave the corresponding side nil (unvalidated). A nil result is
// never returned: both-nil input yields a non-nil validator whose sides
// accept everything.
func NewFieldValidator(input, output FieldValidatorFunc) *FieldValidator {
	return &FieldValidator{Input: input, Output: output}
}

// FieldTransformFunc is the Go-faithful field transform function,
// converting a value across the storage round-trip (input: before storage,
// output: after retrieval), mirroring one side of upstream's
// `transform?: { input?, output? }` (DBFieldAttributeConfig in
// vendor/better-auth/packages/core/src/db/type.ts). Upstream transforms are
// async value-to-value functions; the Go form is synchronous and reports
// errors, which abort the operation.
type FieldTransformFunc func(value any) (any, error)

// NewFieldTransform builds a *FieldTransform from input/output funcs. Nil
// funcs leave the corresponding side nil (identity). A nil result is never
// returned: both-nil input yields a non-nil transform whose sides must be
// nil-checked by the caller before use.
func NewFieldTransform(input, output FieldTransformFunc) *FieldTransform {
	return &FieldTransform{Input: input, Output: output}
}

// CollectPluginEndpoints merges plugin endpoints for registration, in
// plugin declaration order: each plugin's legacy Endpoints() slice first,
// then its named endpoints (PluginNamedEndpointsProvider) sorted by key for
// determinism. Nil plugins and nil entries are skipped. Same-path conflicts
// across plugins are left to endpoint-conflict detection at the router
// layer; this helper only concatenates.
func CollectPluginEndpoints(plugins []Plugin) []Endpoint {
	var out []Endpoint
	for _, p := range plugins {
		if p == nil {
			continue
		}
		out = append(out, p.Endpoints()...)
		if named, ok := p.(PluginNamedEndpointsProvider); ok {
			endpoints := named.NamedEndpoints()
			keys := make([]string, 0, len(endpoints))
			for key := range endpoints {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				out = append(out, endpoints[key])
			}
		}
	}
	return out
}

// CollectTSRouteHooks concatenates TypeScript-faithful route hooks across
// plugins in declaration order, mirroring how upstream fans out
// `plugin.hooks.before/after` around endpoints. Plugins without the
// provider (or nil plugins) contribute nothing. The routes package runs the
// result around handlers.
func CollectTSRouteHooks(plugins []Plugin) PluginTSRouteHooks {
	var out PluginTSRouteHooks
	for _, p := range plugins {
		if p == nil {
			continue
		}
		provider, ok := p.(PluginTSRouteHooksProvider)
		if !ok {
			continue
		}
		hooks := provider.TSRouteHooks()
		out.Before = append(out.Before, hooks.Before...)
		out.After = append(out.After, hooks.After...)
	}
	return out
}

// CollectAdapterOverrides merges plugin database-operation overrides across
// plugins: later plugins win per operation key, mirroring upstream's
// per-plugin `adapter` record keyed by operation name
// (BetterAuthPlugin["adapter"]). Nil plugins and nil maps contribute
// nothing. HookedAdapter consults the merged map for the hooked write
// operations (see the override contract in auth/hooked_adapter.go).
func CollectAdapterOverrides(plugins []Plugin) PluginAdapterOverrides {
	out := PluginAdapterOverrides{}
	for _, p := range plugins {
		if p == nil {
			continue
		}
		provider, ok := p.(PluginAdapterOverridesProvider)
		if !ok {
			continue
		}
		for op, fn := range provider.AdapterOverrides() {
			if fn == nil {
				continue
			}
			out[op] = fn
		}
	}
	return out
}

// CollectPluginMigrations merges manual plugin migrations across plugins.
// Later plugins win on migration-name collisions (upstream never merges
// these records — each plugin carries its own — so collisions are a Go
// collection concern; the last declaration wins and the earlier entry is
// dropped). Nil plugins and nil maps contribute nothing. Schema-driven
// tables still migrate automatically; these run via RunPluginMigrationsUp.
func CollectPluginMigrations(plugins []Plugin) map[string]PluginMigration {
	out := map[string]PluginMigration{}
	for _, p := range plugins {
		if p == nil {
			continue
		}
		provider, ok := p.(PluginMigrationsProvider)
		if !ok {
			continue
		}
		for name, migration := range provider.Migrations() {
			out[name] = migration
		}
	}
	return out
}

// RunPluginMigrationsUp executes manual plugin migrations in sorted name
// order (deterministic across runs). A nil Up is a documented no-op and is
// skipped. The first failing Up aborts the run; the error wraps the
// migration name (errors.Is/As still reach the cause). Down migrations are
// never run by this helper.
func RunPluginMigrationsUp(ctx context.Context, migrations map[string]PluginMigration) error {
	names := make([]string, 0, len(migrations))
	for name := range migrations {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		up := migrations[name].Up
		if up == nil {
			continue
		}
		if err := up(ctx); err != nil {
			return fmt.Errorf("auth: plugin migration %q up failed: %w", name, err)
		}
	}
	return nil
}
