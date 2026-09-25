package auth

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	authapi "github.com/brick-org/brick/auth/src/api"
	authroutes "github.com/brick-org/brick/auth/src/api/routes"
	"github.com/brick-org/brick/auth/src/cookies"
	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
)

// Re-export public types so callers only import this package.
type Options = types.Options
type Auth = types.Auth
type Plugin = types.Plugin
type User = types.User
type Session = types.Session
type EmailAndPasswordOptions = types.EmailAndPasswordOptions
type EmailVerificationOptions = types.EmailVerificationOptions
type SessionOptions = types.SessionOptions
type SessionCookieCacheOptions = types.SessionCookieCacheOptions
type UserOptions = types.UserOptions
type ChangeEmailOptions = types.ChangeEmailOptions
type DeleteUserOptions = types.DeleteUserOptions
type AccountOptions = types.AccountOptions
type AccountLinkingOptions = types.AccountLinkingOptions
type LoggerOptions = types.LoggerOptions
type TelemetryOptions = types.TelemetryOptions
type RateLimitOptions = types.RateLimitOptions
type RateLimitRule = types.RateLimitRule
type AdvancedOptions = types.AdvancedOptions
type CookieAttributes = types.CookieAttributes
type CookieConfig = types.CookieConfig
type CrossSubDomainCookiesOptions = types.CrossSubDomainCookiesOptions
type IPAddressOptions = types.IPAddressOptions
type LogLevel = types.LogLevel
type Secret = types.Secret
type PasswordOptions = types.PasswordOptions
type PasswordVerifyData = types.PasswordVerifyData
type HooksOptions = types.HooksOptions
type APIErrorOptions = types.APIErrorOptions
type DefaultErrorPageOptions = types.DefaultErrorPageOptions
type ErrorPageColors = types.ErrorPageColors
type ErrorPageSize = types.ErrorPageSize
type ErrorPageFont = types.ErrorPageFont
type ResetPasswordData = types.ResetPasswordData
type PasswordResetData = types.PasswordResetData
type ExistingUserSignUpData = types.ExistingUserSignUpData
type SyntheticUserCoreFields = types.SyntheticUserCoreFields
type SyntheticUserData = types.SyntheticUserData
type VerificationEmailData = types.VerificationEmailData
type ChangeEmailData = types.ChangeEmailData
type DeleteAccountVerificationData = types.DeleteAccountVerificationData
type OAuthProvider = types.OAuthProvider
type OAuthTokens = types.OAuthTokens
type OAuthUserInfo = types.OAuthUserInfo
type AuthorizationURLParams = types.AuthorizationURLParams
type CodeExchangeParams = types.CodeExchangeParams

// Plugin system types.
type PluginSchema = types.PluginSchema
type TableSchema = types.TableSchema
type PluginSchemaProvider = types.PluginSchemaProvider
type FieldAttribute = types.FieldAttribute
type FieldReference = types.FieldReference
type FieldType = types.FieldType
type DBHooks = types.DBHooks
type ModelHooks = types.ModelHooks
type OperationHooks = types.OperationHooks
type BeforeHookFunc = types.BeforeHookFunc
type AfterHookFunc = types.AfterHookFunc
type RequestBeforeHookFunc = types.RequestBeforeHookFunc
type RequestAfterHookFunc = types.RequestAfterHookFunc
type PluginOnRequestResult = types.PluginOnRequestResult
type PluginOnResponseResult = types.PluginOnResponseResult
type PluginOnRequestHandler = types.PluginOnRequestHandler
type PluginOnResponseHandler = types.PluginOnResponseHandler
type PluginMiddleware = types.PluginMiddleware
type PluginRateLimitRule = types.PluginRateLimitRule
type PluginRouteHooks = types.PluginRouteHooks
type PluginRouteBeforeHook = types.PluginRouteBeforeHook
type PluginRouteAfterHook = types.PluginRouteAfterHook
type APIErrorHandler = types.APIErrorHandler
type Endpoint = types.Endpoint
type Adapter = types.Adapter
type AuthContext = types.AuthContext
type RawError = types.RawError

// ErrHookAbort aborts a hooked write silently with null and no error.
// Re-exported from types for plugin authors; see types.ErrHookAbort.
var ErrHookAbort = types.ErrHookAbort

const (
	LogLevelDebug = types.LogLevelDebug
	LogLevelInfo  = types.LogLevelInfo
	LogLevelWarn  = types.LogLevelWarn
	LogLevelError = types.LogLevelError

	FieldTypeString  = types.FieldTypeString
	FieldTypeNumber  = types.FieldTypeNumber
	FieldTypeBoolean = types.FieldTypeBoolean
	FieldTypeDate    = types.FieldTypeDate
	FieldTypeJSON    = types.FieldTypeJSON
)

// PluginErrorCodes holds merged error messages from the most recent
// BetterAuth() call, kept in sync with the returned Auth.ErrorCodes for
// backward compatibility.
//
// Deprecated: read Auth.ErrorCodes (map[string]RawError{code,message},
// merged {plugin..., BASE...} in upstream order) from the BetterAuth return
// value instead. This global is reset-and-repopulated on every BetterAuth()
// call under pluginErrorCodesMu so entries never leak across calls.
var PluginErrorCodes = map[string]string{}

// pluginErrorCodesMu guards PluginErrorCodes.
var pluginErrorCodesMu sync.RWMutex

// IsTrustedOrigin re-exports types.IsTrustedOrigin for convenience.
// r is passed to TrustedOriginsFunc; may be nil when no request is available.
func IsTrustedOrigin(rawURL string, opts Options, r *http.Request) bool {
	return types.IsTrustedOrigin(rawURL, opts, r)
}

// IsTrustedRedirect accepts trusted absolute URLs and safe root-relative URLs.
func IsTrustedRedirect(rawURL string, opts Options, r *http.Request) bool {
	return types.IsTrustedRedirect(rawURL, opts, r)
}

// RouterAdapter is a Huma-compatible HTTP router adapter (humachi, humagin, …).
type RouterAdapter = huma.Adapter

// DBAdapter is the database adapter interface all ORM adapters must implement.
type DBAdapter = types.Adapter

// Where is a filter clause used in DBAdapter queries.
type Where = types.Where

// SortBy configures ordering in FindMany calls.
type SortBy = types.SortBy

// AdapterConfig holds optional model/field name overrides for a DBAdapter.
type AdapterConfig = types.AdapterConfig

// Where operator constants mirroring better-auth's operator names.
const (
	OpEq         = types.OpEq
	OpNe         = types.OpNe
	OpLt         = types.OpLt
	OpLte        = types.OpLte
	OpGt         = types.OpGt
	OpGte        = types.OpGte
	OpIn         = types.OpIn
	OpNotIn      = types.OpNotIn
	OpContains   = types.OpContains
	OpStartsWith = types.OpStartsWith
	OpEndsWith   = types.OpEndsWith
)

// Error codes mirroring better-auth BASE_ERROR_CODES.
const (
	ErrUserNotFound                         = types.ErrUserNotFound
	ErrFailedToCreateUser                   = types.ErrFailedToCreateUser
	ErrFailedToCreateSession                = types.ErrFailedToCreateSession
	ErrFailedToUpdateUser                   = types.ErrFailedToUpdateUser
	ErrFailedToGetSession                   = types.ErrFailedToGetSession
	ErrInvalidPassword                      = types.ErrInvalidPassword
	ErrInvalidEmail                         = types.ErrInvalidEmail
	ErrInvalidEmailOrPassword               = types.ErrInvalidEmailOrPassword
	ErrInvalidUser                          = types.ErrInvalidUser
	ErrSocialAccountAlreadyLinked           = types.ErrSocialAccountAlreadyLinked
	ErrProviderNotFound                     = types.ErrProviderNotFound
	ErrInvalidToken                         = types.ErrInvalidToken
	ErrTokenExpired                         = types.ErrTokenExpired
	ErrIDTokenNotSupported                  = types.ErrIDTokenNotSupported
	ErrFailedToGetUserInfo                  = types.ErrFailedToGetUserInfo
	ErrUserEmailNotFound                    = types.ErrUserEmailNotFound
	ErrEmailNotVerified                     = types.ErrEmailNotVerified
	ErrPasswordTooShort                     = types.ErrPasswordTooShort
	ErrPasswordTooLong                      = types.ErrPasswordTooLong
	ErrUserAlreadyExists                    = types.ErrUserAlreadyExists
	ErrUserAlreadyExistsUseAnotherEmail     = types.ErrUserAlreadyExistsUseAnotherEmail
	ErrEmailCanNotBeUpdated                 = types.ErrEmailCanNotBeUpdated
	ErrChangeEmailDisabled                  = types.ErrChangeEmailDisabled
	ErrCredentialAccountNotFound            = types.ErrCredentialAccountNotFound
	ErrSessionExpired                       = types.ErrSessionExpired
	ErrFailedToUnlinkLastAccount            = types.ErrFailedToUnlinkLastAccount
	ErrAccountNotFound                      = types.ErrAccountNotFound
	ErrUserAlreadyHasPassword               = types.ErrUserAlreadyHasPassword
	ErrCrossSiteNavigationLoginBlocked      = types.ErrCrossSiteNavigationLoginBlocked
	ErrVerificationEmailNotEnabled          = types.ErrVerificationEmailNotEnabled
	ErrEmailAlreadyVerified                 = types.ErrEmailAlreadyVerified
	ErrEmailMismatch                        = types.ErrEmailMismatch
	ErrSessionNotFresh                      = types.ErrSessionNotFresh
	ErrLinkedAccountAlreadyExists           = types.ErrLinkedAccountAlreadyExists
	ErrInvalidOrigin                        = types.ErrInvalidOrigin
	ErrInvalidCallbackURL                   = types.ErrInvalidCallbackURL
	ErrInvalidRedirectURL                   = types.ErrInvalidRedirectURL
	ErrInvalidErrorCallbackURL              = types.ErrInvalidErrorCallbackURL
	ErrInvalidNewUserCallbackURL            = types.ErrInvalidNewUserCallbackURL
	ErrMissingOrNullOrigin                  = types.ErrMissingOrNullOrigin
	ErrCallbackURLRequired                  = types.ErrCallbackURLRequired
	ErrFailedToCreateVerification           = types.ErrFailedToCreateVerification
	ErrFieldNotAllowed                      = types.ErrFieldNotAllowed
	ErrAsyncValidationNotSupported          = types.ErrAsyncValidationNotSupported
	ErrValidationError                      = types.ErrValidationError
	ErrMissingField                         = types.ErrMissingField
	ErrMethodNotAllowedDeferSessionRequired = types.ErrMethodNotAllowedDeferSessionRequired
	ErrBodyMustBeAnObject                   = types.ErrBodyMustBeAnObject
	ErrPasswordAlreadySet                   = types.ErrPasswordAlreadySet
)

// SignCookie signs value with secret using HMAC-SHA256, returns "value.sig".
func SignCookie(secret, value string) (string, error) {
	return cookies.Sign(secret, value)
}

// VerifyCookie verifies the signature and returns the original value and true on success.
func VerifyCookie(secret, signed string) (string, bool) {
	return cookies.Verify(secret, signed)
}

// VerifyCookieWithSecrets verifies a signed cookie against multiple candidate secrets.
func VerifyCookieWithSecrets(secrets []Secret, signed string) (string, bool) {
	values := make([]string, 0, len(secrets))
	for _, secret := range secrets {
		values = append(values, secret.Value)
	}
	return cookies.VerifyAny(values, signed)
}

// GetSessionFromRequest extracts the session and user from the HTTP request.
// Returns session, user, optional refresh cookies, and error.
// The session and user are nil if the request is unauthenticated or token is invalid.
func GetSessionFromRequest(r *http.Request, opts Options) (*Session, *User, []http.Cookie, error) {
	return authroutes.GetSessionFromRequest(r, opts)
}

// defaultAppName resolves the construction display-name default, mirroring
// upstream `appName: options.appName || "Better Auth"` at context build
// (create-context.ts:284). It applies to the context reference only; the
// Options field itself defaults after plugin init so option patches can
// still fill an unset AppName defu-style.
func defaultAppName(appName string) string {
	if appName == "" {
		return "Better Auth"
	}
	return appName
}

// BetterAuth registers all auth routes on the provided adapter and returns an Auth instance.
// The caller owns the HTTP handler — mount it on their router as usual.
//
// BREAKING: returns (Auth, error) instead of panicking. Misconfigured
// secondary-storage flags (session persistence flags without a backend,
// rate-limit storage without its backend) and plugin-init failures are
// returned as wrapped errors; callers must check err.
//
// BREAKING (behavior change): secrets resolve from env when Options are
// empty, mirroring upstream create-context.ts precedence:
//
//	secretsArray = Options.Secrets ?? BETTER_AUTH_SECRETS
//	legacy = Options.Secret || BETTER_AUTH_SECRET || AUTH_SECRET
//
// An empty resolved secret is now an error (previously accepted as-is).
// Short (<32 char) secrets warn via Options.Logger when configured, quiet
// otherwise. Versioned configs honor numeric Version (first entry issues
// new state); the resolved Secret/SecretConfig surface on Auth.Context.
//
// Plugin init may return option/context patches via the OPTIONAL
// PluginInitPatches interface (checked via type assertion), merged
// defu-style (existing values win; databaseHooks/trustedOrigins collected
// with `plugin:<id>` source labels). Legacy Init(AuthContext) error keeps
// working (runs first; either error aborts).
//
// The following Options fields are accepted for parity but remain inactive
// in this runtime: cookie-cache strategies beyond compact (Session.CookieCache
// Strategy "jwt"/"jwe", RefreshCache, and VersionFunc are accepted but only
// compact/Version are enforced). Per-request baseURL rewriting is active:
// Options.DynamicBaseURL allowedHosts/protocol/fallback expand into
// TrustedOrigins at construction, resolve per request via
// ResolveRequestContext/api.ResolveDynamicBaseURLForRequest, drive middleware
// origin derivation, and are authoritative for route URL builders
// (callbacks, callback URIs, error URLs, cookie secure/domain) through the
// request-scoped helpers in auth/api/routes.
//
// Secondary storage (Options.SecondaryStorage) is wired: session reads,
// refreshes, revokes, lists, and updates consult it with
// Session.StoreSessionInDatabase / Session.PreserveSessionInDatabase
// selecting database mirroring and preserve-on-revoke semantics (see the
// secondary-storage runtime in auth/api/routes/session.go); verification
// rows honor Verification.StoreInDatabase, Verification.StoreIdentifier, and
// Verification.DisableCleanup (see auth/api/routes/email_verification.go);
// rate limiting consumes Storage "secondary-storage" via
// SecondaryStorage.Increment and Storage "database" via the atomic adapter
// backend (see auth/api.ValidateRateLimitStorage). Creation paths that still
// write database rows directly without mirroring (sign-up/sign-in session
// issuance, change-email verification issuance) fall back to the database on
// a secondary miss and backfill it — see the transitional notes on
// writeSecondarySession and findChangeEmailVerificationRow.
//
// Telemetry publishes no network traffic in this runtime (there is no
// telemetry endpoint or custom-track plumbing — upstream createTelemetry
// returns a noop without one): when Options.Telemetry.Enabled (or
// BETTER_AUTH_TELEMETRY=1/true) is set, construction publishes a local
// "init" diagnostic and AuthContext.PublishTelemetry reports per-event
// diagnostics via Options.Logger (level-gated; Debug logs payloads).
// Instrumentation (Experimental.Instrumentation, default enabled) runs
// WithSpan as a direct passthrough preserving name/attribute plumbing.
//
// Framework runtime knobs honored by this constructor and the api
// middleware: DynamicBaseURL expansion + validation + per-request
// resolution (ResolveRequestContext), rate-limit storage selection
// (ValidateRateLimitStorage), trusted-proxy validation (invalid
// Advanced.IPAddress.TrustedProxies entries warn and are ignored;
// resolution with IPv6-subnet collapsing lives in api.RequestClientIP),
// DisableOriginCheck (skips the origin middleware, with the upstream
// backward-compatible CSRF skip), SkipTrailingSlashes (slash-variant route
// registration in api.Router plus middleware path normalization),
// endpoint-conflict detection (logged error via Options.Logger, mirroring
// upstream checkEndpointConflicts), and schema checks (opts.SchemaCheck
// attached when Advanced.Database.ValidateSchema is not explicitly false;
// the api middleware runs it per request, mirroring upstream checkSchema).
// Background tasks (Advanced.BackgroundTasks) dispatch through
// RunInBackground: the configured Handler receives the task thunk, otherwise
// the task runs fire-and-forget in its own goroutine (panics contained).
// Each honored-or-deferred option is noted once at construction via
// Options.Logger when logging is configured; the quiet default is unchanged.
//
// Plugins are initialised in declaration order before routes are registered.
//
// Error codes: the returned Auth.ErrorCodes merges plugin $ERROR_CODES with
// BASE_ERROR_CODES in upstream order ({...pluginCodes, ...BASE...}),
// mirroring `$ERROR_CODES` in vendor/.../src/auth/base.ts. The global
// PluginErrorCodes is kept in sync (code->message strings) as a deprecated
// wrapper for old readers.
func BetterAuth(opts Options) (Auth, error) {
	if opts.BasePath == "" {
		opts.BasePath = "/api/auth"
	}
	// NOTE: AppName intentionally stays unset here so plugin option patches
	// can fill it defu-style (upstream ctx.options.appName is unset until a
	// patch fills it). The construction default applies to ctx.AppName below
	// and to opts.AppName after plugin init.
	// Resolve secrets first so plugin init sees the final context.
	var secret string
	var secretCfg SecretConfig
	var err error
	if opts, secret, secretCfg, err = resolveSecrets(opts); err != nil {
		return Auth{}, err
	}
	opts.Schema = ResolveSchema(opts)
	if opts.SecondaryStorage == nil && (opts.Session.StoreSessionInDatabase || opts.Session.PreserveSessionInDatabase) {
		return Auth{}, fmt.Errorf("auth: secondary storage session persistence requires options.SecondaryStorage when Session.StoreSessionInDatabase or Session.PreserveSessionInDatabase is set (no backend configured): " +
			"set Options.SecondaryStorage to persist sessions outside the database, or leave both Session flags false to stay on database-backed sessions")
	}

	ctx := types.AuthContext{
		Options:      opts,
		AppName:      defaultAppName(opts.AppName),
		Secret:       secret,
		SecretConfig: secretCfg,
	}

	// --- Plugin init with optional patches ---
	merged := make(map[string]RawError)
	// Init-patch databaseHooks keep their `plugin:<id>` source label by
	// traveling through NewHookedAdapterWithOptions as synthetic plugins
	// (see patchHooksPlugin); collecting them here in declaration order
	// preserves upstream's interleaving (each plugin's legacy hooks, then
	// its init-returned hooks).
	var patchEntries []patchHookEntry
	allStatic := append([]string(nil), opts.TrustedOrigins...)
	var allDyn []func(*http.Request) []string
	if opts.TrustedOriginsFunc != nil {
		allDyn = append(allDyn, opts.TrustedOriginsFunc)
	}
	for _, p := range opts.Plugins {
		if err := p.Init(ctx); err != nil {
			return Auth{}, fmt.Errorf("auth: plugin %q init failed: %w", p.ID(), err)
		}
		// Merge error codes in plugin declaration order (BASE applied last below).
		for k, v := range p.ErrorCodes() {
			merged[k] = RawError{Code: k, Message: v}
		}
		// Legacy plugin Hooks() are collected by NewHookedAdapterWithOptions
		// below with `plugin:<id>` source labels; nothing to merge here.
		// Optional init patches (upstream init returns).
		if patcher, ok := p.(PluginInitPatches); ok {
			patch, err := patcher.InitPatches(ctx)
			if err != nil {
				return Auth{}, fmt.Errorf("auth: plugin %q init patches failed: %w", p.ID(), err)
			}
			if patch.Options != nil {
				dbHooks, statics, dyn, rest := splitPatchOptions(*patch.Options)
				if len(dbHooks) > 0 {
					patchEntries = append(patchEntries, patchHookEntry{pluginID: p.ID(), hooks: dbHooks})
				}
				allStatic = append(allStatic, statics...)
				if dyn != nil {
					allDyn = append(allDyn, dyn)
				}
				defuOptions(&opts, rest)
				// Keep context options in sync for subsequent plugins.
				ctx.Options = opts
				// NOTE: a defu-filled AppName stays on ctx.Options only.
				// ctx.AppName keeps its construction default unless a context
				// patch sets it, mirroring upstream (ctx.appName is built
				// pre-init from unpatched options; option patches land on
				// context.options).
			}
			if patch.Context != nil {
				if patch.Context.AppName != "" {
					ctx.AppName = patch.Context.AppName
				}
				if patch.Context.Secret != "" {
					ctx.Secret = patch.Context.Secret
				}
				if patch.Context.SecretConfig.Keys != nil {
					ctx.SecretConfig = patch.Context.SecretConfig
				}
				// Context Options patches win (Object.assign semantics):
				// overwrite non-zero fields in both ctx and opts.
				if !isOptionsZero(patch.Context.Options) {
					overwriteOptions(&opts, patch.Context.Options)
					ctx.Options = opts
				}
			}
		}
		// Keep context options current for the next plugin.
		ctx.Options = opts
	}
	// Finalize trusted origins collection (upstream merges after the loop).
	opts.TrustedOrigins = filterNonEmpty(allStatic)
	opts.TrustedOriginsFunc = combineTrustedOriginsFuncs(allDyn)
	ctx.Options = opts
	// Default the display name after plugin init so option patches could
	// fill an unset AppName defu-style (see defaultAppName).
	if opts.AppName == "" {
		opts.AppName = "Better Auth"
		ctx.Options = opts
	}
	// Framework runtime validation for options that only take effect here
	// (BetterAuth keeps its (Auth, error) signature: misconfiguration is a
	// wrapped descriptive error, never a panic).
	if err := validateDynamicBaseURL(opts); err != nil {
		return Auth{}, err
	}
	if err := authapi.ValidateRateLimitStorage(opts); err != nil {
		return Auth{}, err
	}
	// Expand dynamic allowedHosts/fallback into the finalized static origins
	// (mirrors upstream getTrustedOrigins' dynamic branch; see
	// auth/api.ExpandDynamicBaseURLOrigins). Static BaseURL behavior is
	// unchanged when DynamicBaseURL is nil.
	if opts.DynamicBaseURL != nil {
		opts.TrustedOrigins = append(opts.TrustedOrigins, authapi.ExpandDynamicBaseURLOrigins(opts.DynamicBaseURL)...)
		ctx.Options = opts
	}
	// Upstream getTrustedOrigins also merges BETTER_AUTH_TRUSTED_ORIGINS env
	// (comma-separated); the api middleware re-derives it per request for
	// direct Router callers via the same helper.
	opts.TrustedOrigins = append(opts.TrustedOrigins, types.ParseTrustedOriginsEnv(os.Getenv(types.TrustedOriginsEnvVar))...)
	ctx.Options = opts
	// One construction-time parity note per honored-or-deferred framework
	// option (level-gated on Options.Logger; quiet by default).
	noteFrameworkRuntimeOptions(opts)
	// Telemetry init publish (no-network local diagnostic when enabled).
	publish := newTelemetryPublisher(opts)
	publish(types.TelemetryEvent{Type: "init", Payload: telemetryInitPayload(opts)})
	// Apply BASE codes last so they win on collision, in upstream order.
	for _, code := range types.BaseErrorCodeOrder {
		if raw, ok := types.BaseErrorCodes[code]; ok {
			merged[code] = raw
		}
	}
	// Reset-and-repopulate the deprecated global so codes neither race nor
	// leak across calls; old readers keep seeing code->message strings.
	pluginErrorCodesMu.Lock()
	clear(PluginErrorCodes)
	for k, v := range merged {
		PluginErrorCodes[k] = v.Message
	}
	pluginErrorCodesMu.Unlock()

	// Resolve the full framework context services (mirroring upstream
	// createAuthContext's ctx fields that this layer owns).
	finalizeAuthContext(&ctx, opts, secret, secretCfg, publish)

	// Wrap the adapter with lifecycle hooks via NewHookedAdapterWithOptions
	// (upstream getWithHooks): legacy plugin Hooks() plus init-patch hooks
	// (as synthetic plugins preserving `plugin:<id>` sources) run before
	// user databaseHooks; plugin adapter overrides apply unless an explicit
	// entry wins (none are set explicitly here — collection is
	// plugin-driven); field validator/transform schemas come from the
	// resolved tables; post-commit failures report to
	// Options.OnAfterCommitHookError when set. When nothing applies the
	// inner adapter is returned unwrapped.
	// After-hook failures are reported to opts.Logger when configured;
	// the default (disabled or nil Log) stays quiet.
	if opts.DB != nil {
		opts.DB = NewHookedAdapterWithOptions(
			opts.DB,
			expandPluginsWithPatchHooks(opts.Plugins, patchEntries),
			opts.DatabaseHooks,
			HookedAdapterOptions{
				Logger:                 loggerFromOptions(opts),
				OnAfterCommitHookError: AfterCommitHookErrorHandler(opts.OnAfterCommitHookError),
				FieldSchemas:           fieldSchemasFromTables(ctx.Tables),
			},
		)
		ctx.Options = opts
	}

	// Attach the per-request schema validator (nil when
	// Advanced.Database.ValidateSchema is explicitly false). Construction
	// never awaits the verdict (mirroring upstream: migration tooling can
	// still use a context whose schema needs repair); the api middleware
	// runs it per request via opts.SchemaCheck.
	opts.SchemaCheck = buildSchemaCheck(opts)
	ctx.Options = opts

	api := authapi.Router(opts.Adapter, opts.BasePath, opts)

	return Auth{
		API:        api,
		Context:    ctx,
		ErrorCodes: merged,
	}, nil
}

// loggerFromOptions adapts Options.Logger to HookLogger for DB after-hook
// error reporting. It returns nil (quiet, no output) when logging is
// disabled or no Log callback is configured, preserving the historical
// default. Error reports are level-gated like any other log (upstream levels
// order debug < info < success < warn < error, so error passes unless the
// configured level is unknown).
func loggerFromOptions(opts Options) HookLogger {
	if opts.Logger.Disabled || opts.Logger.Log == nil {
		return nil
	}
	if !types.ShouldPublishLog(opts.Logger.Level, types.LogLevelError) {
		return nil
	}
	log := opts.Logger.Log
	return HookLogFunc(func(msg string, args ...any) {
		log("error", msg, args...)
	})
}

// authNotef reports a framework parity note via Options.Logger. It stays
// quiet when logging is disabled or no Log callback is configured, and
// honors the configured minimum level (types.ShouldPublishLog, default
// "warn" — mirroring upstream createLogger filtering), preserving the
// historical quiet default (mirrors context secretWarnf gating). Levels follow the
// upstream logger levels ("debug", "info", "success", "warn", "error");
// "success" is normalized to "info" for custom handlers.
func authNotef(opts Options, level, format string, args ...any) {
	if opts.Logger.Disabled || opts.Logger.Log == nil {
		return
	}
	msgLevel := types.LogLevel(level)
	if msgLevel == types.LogLevelSuccess {
		msgLevel = types.LogLevelInfo
	}
	if !types.ShouldPublishLog(opts.Logger.Level, msgLevel) {
		return
	}
	opts.Logger.Log(types.NormalizeLogLevelForHandler(types.LogLevel(level)), fmt.Sprintf(format, args...))
}

// validateDynamicBaseURL enforces the DynamicBaseURL contract at
// construction (mirroring upstream createAuthContext's allowedHosts check
// plus the mutual-exclusion and literal rules pinned by ValidateOptions in
// package types, which BetterAuth cannot call wholesale because secret env
// fallback resolves separately in resolveSecrets):
//
//   - BaseURL and DynamicBaseURL are mutually exclusive (upstream baseURL is
//     `string | DynamicBaseURLConfig`);
//   - AllowedHosts must be non-empty;
//   - Protocol must be "http", "https", or "auto" (empty means upstream's
//     unset behavior — https required, http only for loopback hosts — see
//     auth/api.ExpandDynamicBaseURLOrigins);
//   - Fallback, when set, must be an absolute http(s) URL.
//
// Upstream TypeScript names: createAuthContext (allowedHosts throw),
// isDynamicBaseURLConfig.
func validateDynamicBaseURL(opts Options) error {
	cfg := opts.DynamicBaseURL
	if cfg == nil {
		return nil
	}
	if opts.BaseURL != "" {
		return fmt.Errorf("auth: options.BaseURL and options.DynamicBaseURL are mutually exclusive: upstream baseURL is string | DynamicBaseURLConfig (init-options.ts:189), set exactly one")
	}
	if len(cfg.AllowedHosts) == 0 {
		return fmt.Errorf("auth: options.DynamicBaseURL.AllowedHosts cannot be empty: provide at least one allowed host pattern (e.g. [\"myapp.com\", \"*.vercel.app\"])")
	}
	if p := cfg.Protocol; p != "" && p != types.BaseURLProtocolHTTP && p != types.BaseURLProtocolHTTPS && p != types.BaseURLProtocolAuto {
		return fmt.Errorf("auth: options.DynamicBaseURL.Protocol must be %q, %q, or %q, got %q", types.BaseURLProtocolHTTP, types.BaseURLProtocolHTTPS, types.BaseURLProtocolAuto, p)
	}
	if cfg.Fallback != "" {
		if err := checkAbsoluteHTTPURL(cfg.Fallback); err != nil {
			return fmt.Errorf("auth: options.DynamicBaseURL.Fallback is invalid: %w", err)
		}
	}
	return nil
}

// checkAbsoluteHTTPURL requires a parseable absolute http(s) URL (local
// mirror of the types-level check so BetterAuth validates Fallback without
// importing unexported helpers).
func checkAbsoluteHTTPURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("expected an absolute http(s) URL, got %q", raw)
	}
	return nil
}

// noteFrameworkRuntimeOptions emits one construction-time parity note per
// honored-or-deferred framework option via authNotef (level-gated on
// Options.Logger; quiet by default, so default-config construction stays
// silent):
//
//   - Options.Telemetry.Enabled (or BETTER_AUTH_TELEMETRY env) → local
//     no-network publish note (the Go runtime publishes an "init"
//     diagnostic via Options.Logger, never over the network — upstream
//     createTelemetry POSTs to a telemetry endpoint or custom track
//     function, neither of which exists here).
//   - Advanced.BackgroundTasks.Handler → dispatch note (honored by
//     RunInBackground; without a handler tasks run fire-and-forget).
//   - Options.DynamicBaseURL → expansion note (allowedHosts/protocol/
//     fallback expanded into TrustedOrigins; middleware derives the request
//     origin per request).
//   - Options.RateLimit non-default storage → selection note (memory is the
//     default with a production-default enabled gate; custom, secondary, and
//     database backends are named when active).
//   - Invalid Advanced.IPAddress.TrustedProxies entries → warning (ignored
//     by resolution, mirroring upstream's "Ignoring invalid
//     trustedProxies" warning).
//   - Advanced.DisableOriginCheck → warning (middleware origin validation
//     skipped, with upstream's backward-compatible CSRF skip).
//   - Options.OnAfterCommitHookError → note (post-commit failures report to
//     the handler instead of failing the Transaction call).
//   - Endpoint conflicts across plugins → error diagnostic via the api
//     layer (checkEndpointConflicts runs at Router start; see
//     auth/api.FindEndpointConflicts).
func noteFrameworkRuntimeOptions(opts Options) {
	if invalid := authapi.FindInvalidTrustedProxies(opts.Advanced.IPAddress.TrustedProxies); len(invalid) > 0 {
		authNotef(opts, "warn", "auth: ignoring invalid `advanced.ipAddress.trustedProxies` entries: %s. Each entry must be an IP address or CIDR range.", strings.Join(invalid, ", "))
	}
	if telemetryEnabled(opts) {
		authNotef(opts, "info", "auth: telemetry is enabled; the Go runtime publishes a local init diagnostic via Options.Logger only (no network telemetry endpoint is configured)")
	} else if opts.Telemetry.Debug {
		authNotef(opts, "info", "auth: telemetry debug is set without telemetry enabled; per-event payload logging stays off until telemetry is enabled")
	}
	if opts.Advanced.BackgroundTasks.Handler != nil {
		authNotef(opts, "info", "auth: background tasks dispatch through Advanced.BackgroundTasks.Handler via auth.RunInBackground; without a handler tasks run fire-and-forget")
	}
	if cfg := opts.DynamicBaseURL; cfg != nil {
		authNotef(opts, "info", "auth: dynamic base URL active (%d allowed host(s), protocol %q): expansions merged into trusted origins and the api middleware derives the request origin per request", len(cfg.AllowedHosts), dynamicProtocolName(cfg.Protocol))
	}
	switch effectiveRateLimitStorageName(opts) {
	case "custom":
		authNotef(opts, "info", "auth: rate limiting uses the custom storage backend (Options.RateLimit.Storage is ignored, mirroring upstream)")
	case "secondary-storage":
		authNotef(opts, "info", "auth: rate limiting uses secondary storage via SecondaryStorage.Increment (mirroring upstream)")
	case "database":
		authNotef(opts, "info", "auth: rate limiting uses the database backend via adapter IncrementOne (mirroring upstream)")
	}
	if opts.Advanced.DisableOriginCheck {
		authNotef(opts, "warn", "auth: Advanced.DisableOriginCheck is set: api middleware origin validation is skipped, and CSRF origin checks are skipped as well for backward compatibility with better-auth")
	}
	if opts.OnAfterCommitHookError != nil {
		authNotef(opts, "info", "auth: post-commit DB after-hook failures report to Options.OnAfterCommitHookError instead of failing the Transaction call")
	}
}

// dynamicProtocolName names the effective dynamic protocol for log lines
// (empty means upstream's unset behavior, not "auto").
func dynamicProtocolName(p types.BaseURLProtocol) string {
	if p == "" {
		return "unset (https required, http for loopback only)"
	}
	return string(p)
}

// effectiveRateLimitStorageName names the enforced rate-limit backend for
// log lines: "custom" when CustomStorage is set (Storage ignored, mirroring
// upstream precedence), otherwise the explicit Storage, defaulting to
// "memory" — or "secondary-storage" when Storage is unset but a secondary
// backend is present (mirroring upstream's default).
func effectiveRateLimitStorageName(opts Options) string {
	if opts.RateLimit.CustomStorage != nil {
		return "custom"
	}
	if opts.RateLimit.Storage != "" {
		return string(opts.RateLimit.Storage)
	}
	if opts.SecondaryStorage != nil {
		return string(types.RateLimitStorageSecondary)
	}
	return string(types.RateLimitStorageMemory)
}

// RunInBackground dispatches a unit of deferred work to run after the
// response is sent, mirroring upstream ctx.runInBackground
// (vendor/.../src/context/create-context.ts:404-408):
//
//   - with Advanced.BackgroundTasks.Handler configured, the handler receives
//     the task thunk (upstream receives the pending promise; Go has no
//     promise value, so the thunk stands in — see the DEVIATION note on
//     types.BackgroundTaskHandler). Handler panics propagate to the caller,
//     mirroring upstream's logger.error-and-continue only in spirit: prefer
//     non-panicking handlers.
//   - without a handler, the task runs fire-and-forget in its own goroutine
//     (upstream: the promise is floated with a no-op catch). A deferred
//     recover contains task panics so a background task can never crash the
//     process, mirroring upstream's .catch(()=>{}) containment.
//
// A nil task is a no-op. There is no await variant: upstream's
// runInBackgroundOrAwait awaits the promise when no handler is set, which
// has no meaningful Go equivalent at the call sites that matter here;
// callers that must wait should invoke the work synchronously instead.
//
// Upstream TypeScript name: runInBackground.
func RunInBackground(opts Options, task func()) {
	if task == nil {
		return
	}
	if handler := opts.Advanced.BackgroundTasks.Handler; handler != nil {
		handler(task)
		return
	}
	go func() {
		defer func() { _ = recover() }()
		task()
	}()
}

// --- Wave 2 framework context services ---

// patchHookEntry carries one plugin's init-patch databaseHooks with its
// source plugin ID so NewHookedAdapterWithOptions can preserve the
// `plugin:<id>` source label via synthetic plugins.
type patchHookEntry struct {
	pluginID string
	hooks    DBHooks
}

// patchHooksPlugin is a synthetic Plugin carrying init-patch databaseHooks
// through NewHookedAdapterWithOptions so they keep their `plugin:<id>`
// source label (mirroring upstream runPluginInit's dbHooks entries in
// vendor/.../src/context/helpers.ts:44-53). Only ID and Hooks carry data;
// every other method preserves the surrounding plugin's behavior by
// contributing nothing.
type patchHooksPlugin struct {
	id    string
	hooks DBHooks
}

func (p patchHooksPlugin) ID() string                    { return p.id }
func (p patchHooksPlugin) Init(AuthContext) error        { return nil }
func (p patchHooksPlugin) Endpoints() []Endpoint         { return nil }
func (p patchHooksPlugin) Schema() PluginSchema          { return nil }
func (p patchHooksPlugin) Hooks() DBHooks                { return p.hooks }
func (p patchHooksPlugin) RouteHooks() PluginRouteHooks  { return PluginRouteHooks{} }
func (p patchHooksPlugin) ErrorCodes() map[string]string { return nil }

// expandPluginsWithPatchHooks interleaves each plugin's init-patch hooks
// after its legacy entry (upstream declaration order): the final plugin
// list (including defu-added plugins) is walked, and every collected patch
// entry for that plugin ID is inserted immediately after it. Patch entries
// for IDs absent from the final list are appended at the end so none are
// silently dropped.
func expandPluginsWithPatchHooks(plugins []Plugin, patches []patchHookEntry) []Plugin {
	if len(patches) == 0 {
		return plugins
	}
	byID := make(map[string][]DBHooks, len(patches))
	for _, entry := range patches {
		if len(entry.hooks) == 0 {
			continue
		}
		byID[entry.pluginID] = append(byID[entry.pluginID], entry.hooks)
	}
	if len(byID) == 0 {
		return plugins
	}
	used := make(map[string]struct{}, len(byID))
	out := make([]Plugin, 0, len(plugins)+len(patches))
	for _, p := range plugins {
		out = append(out, p)
		if p == nil {
			continue
		}
		for _, hooks := range byID[p.ID()] {
			out = append(out, patchHooksPlugin{id: p.ID(), hooks: hooks})
		}
		used[p.ID()] = struct{}{}
	}
	for _, entry := range patches {
		if _, ok := used[entry.pluginID]; ok || len(entry.hooks) == 0 {
			continue
		}
		out = append(out, patchHooksPlugin{id: entry.pluginID, hooks: entry.hooks})
	}
	return out
}

// fieldSchemasFromTables builds HookedAdapterOptions.FieldSchemas from the
// resolved tables: every model's field attributes (validators/transforms)
// execute around hooked writes/reads. Models without fields are skipped; a
// schema without any fields yields nil (adapter untouched).
//
// Upstream TypeScript name: the schema-derived field metadata consumed by
// parseInputData/output filtering in with-hooks.ts.
func fieldSchemasFromTables(tables PluginSchema) map[string]map[string]types.FieldAttribute {
	if len(tables) == 0 {
		return nil
	}
	out := make(map[string]map[string]types.FieldAttribute, len(tables))
	for model, table := range tables {
		if len(table.Fields) == 0 {
			continue
		}
		fields := make(map[string]types.FieldAttribute, len(table.Fields))
		for name, attr := range table.Fields {
			fields[name] = attr
		}
		out[model] = fields
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// finalizeAuthContext resolves the framework-owned AuthContext services from
// the finalized options (mirroring the ctx fields built by upstream
// createAuthContext in vendor/.../src/context/create-context.ts:283-430
// that this layer owns). Cookie stores, password hashing, and the internal
// adapter remain with their owning packages.
func finalizeAuthContext(ctx *types.AuthContext, opts Options, secret string, secretCfg SecretConfig, publish func(types.TelemetryEvent)) {
	ctx.Options = opts
	// AppName/Secret/Config keep init-patch overwrites from the plugin loop:
	// they are only filled when still zero (upstream Object.assign keeps the
	// patched context reference; construction defaults guarantee non-zero
	// for unpatched instances, so this never blanks a resolved value).
	if ctx.AppName == "" {
		ctx.AppName = opts.AppName
	}
	if ctx.Secret == "" {
		ctx.Secret = secret
	}
	if ctx.SecretConfig.Keys == nil {
		ctx.SecretConfig = secretCfg
	}
	ctx.Version = BetterAuthVersion
	if opts.DynamicBaseURL == nil && opts.BaseURL != "" {
		ctx.BaseURL = originOfBaseURL(opts.BaseURL)
	}
	ctx.Tables = FullSchema(opts)
	// Resolved trust mirrors upstream ctx.trustedOrigins (baseURL origin
	// first, then collected statics including dynamic expansion and env,
	// then the dynamic resolver evaluated without a request).
	ctx.TrustedOrigins = types.ResolveTrustedOrigins(opts, nil)
	ctx.TrustedProviders = resolveTrustedProviders(opts, nil)
	snapshot := opts
	ctx.IsTrustedOrigin = func(rawURL string) bool {
		return types.IsTrustedOrigin(rawURL, snapshot, nil)
	}
	ctx.GenerateID = ResolveGenerateID(opts)
	ctx.RateLimit = resolveRateLimitContext(opts)
	ctx.SessionConfig = resolveSessionConfig(opts)
	ctx.OAuthStateStrategy = opts.Account.ResolvedStateStrategy(opts.DB != nil || opts.SecondaryStorage != nil)
	ctx.SkipCSRFCheck = opts.Advanced.DisableCSRFCheck
	ctx.SkipOriginCheck = opts.Advanced.DisableOriginCheck
	ctx.PublishTelemetry = publish
	if schemaCheckEnabled(opts) {
		tables := ctx.Tables
		ctx.CheckSchema = func() error {
			return ValidateSchemaIndexes(tables, AdapterConfig{})
		}
	}
}

// originOfBaseURL returns the scheme://host origin of a configured BaseURL,
// falling back to the raw value when it does not parse (validation rejects
// such values at construction; this stays total for context consumers).
func originOfBaseURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return raw
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return raw
	}
	return scheme + "://" + u.Host
}

// resolveTrustedProviders returns the account-linking trust list, mirroring
// upstream getTrustedProviders (vendor/.../src/context/helpers.ts:292-305):
// static entries filtered for empties, plus the function resolver evaluated
// with the given request (nil at construction, mirroring upstream
// context-init invocations — resolvers must tolerate nil).
func resolveTrustedProviders(opts Options, r *http.Request) []string {
	static := make([]string, 0, len(opts.Account.AccountLinking.TrustedProviders))
	for _, provider := range opts.Account.AccountLinking.TrustedProviders {
		if provider != "" {
			static = append(static, provider)
		}
	}
	if fn := opts.Account.AccountLinking.TrustedProvidersFunc; fn != nil {
		for _, provider := range fn(r) {
			if provider != "" {
				static = append(static, provider)
			}
		}
	}
	return static
}

// resolveRateLimitContext resolves the rate-limit triple, mirroring
// upstream ctx.rateLimit (create-context.ts:354-362): explicit Enabled wins,
// otherwise production-gated (NODE_ENV=production); window/max fall back to
// 10/100; storage falls back to secondary-storage with a secondary backend,
// else memory.
func resolveRateLimitContext(opts Options) types.ResolvedRateLimit {
	enabled := false
	if opts.RateLimit.Enabled != nil {
		enabled = *opts.RateLimit.Enabled
	} else {
		enabled = os.Getenv("NODE_ENV") == "production"
	}
	storage := opts.RateLimit.Storage
	if storage == "" {
		if opts.SecondaryStorage != nil {
			storage = types.RateLimitStorageSecondary
		} else {
			storage = types.RateLimitStorageMemory
		}
	}
	return types.ResolvedRateLimit{
		Enabled: enabled,
		Window:  opts.RateLimit.WindowOrDefault(),
		Max:     opts.RateLimit.MaxOrDefault(),
		Storage: storage,
	}
}

// resolveSessionConfig resolves the session lifetime knobs, mirroring
// upstream ctx.sessionConfig defaults (create-context.ts:308-317): updateAge
// 86400 (1 day), expiresIn 604800 (7 days), freshAge 86400 unless explicitly
// set (an explicit 0 disables the freshness check).
func resolveSessionConfig(opts Options) types.ResolvedSessionConfig {
	updateAge := types.ResolveUpdateAgeSeconds(opts.Session.UpdateAge)
	expiresIn := opts.Session.ExpiresIn
	if expiresIn == 0 {
		expiresIn = 60 * 60 * 24 * 7
	}
	freshAge := 60 * 60 * 24
	if opts.Session.FreshAge != nil {
		freshAge = *opts.Session.FreshAge
	}
	return types.ResolvedSessionConfig{UpdateAge: updateAge, ExpiresIn: expiresIn, FreshAge: freshAge}
}

// schemaCheckEnabled reports whether the per-request schema validator
// applies, mirroring upstream checksSchema
// (vendor/.../core/src/db/schema-check.ts:16-18): enabled in every
// environment unless explicitly disabled.
func schemaCheckEnabled(opts Options) bool {
	return opts.Advanced.Database.ValidateSchema == nil || *opts.Advanced.Database.ValidateSchema
}

// buildSchemaCheck returns the per-request schema validator attached as
// opts.SchemaCheck (nil when disabled). The closure captures the resolved
// tables snapshot so requests share one immutable view; a mismatch fails
// closed with a descriptive error, mirroring upstream's SchemaMismatchError
// failure mode without any database I/O (index validation is pure).
func buildSchemaCheck(opts Options) func() error {
	if !schemaCheckEnabled(opts) {
		return nil
	}
	tables := FullSchema(opts)
	return func() error {
		return ValidateSchemaIndexes(tables, AdapterConfig{})
	}
}

// ResolveGenerateID resolves the model ID minter honoring
// Advanced.Database.GenerateID, mirroring upstream generateIdFunc
// (create-context.ts:248-263). It delegates to types.MintModelID — the single
// minter shared by the context service and every model-row creation site —
// so custom/serial/UUID behavior is identical at construction and at creation:
//
//   - a custom Func wins (receives model + optional size hint, may return
//     false for database-issued IDs);
//   - Mode "uuid" mints a random UUID (crypto.randomUUID upstream);
//   - Mode "serial" resolves to ("", false) so the database issues the ID
//     (upstream generateId:false);
//   - otherwise the default random identifier applies (upstream generateId;
//     size hint <= 0 falls back to the 32-character default).
//
// Callers must treat ("", false) as "omit the ID and let the database
// generate it".
//
// Upstream TypeScript name: generateId.
func ResolveGenerateID(opts Options) types.GenerateIDFunc {
	return func(model string, size *int) (string, bool) {
		return types.MintModelID(opts, model, size)
	}
}

// ResolveRequestContext returns the per-request auth context for a dynamic
// baseURL configuration, mirroring upstream resolveRequestContext
// (vendor/.../src/context/helpers.ts:210-276): the baseURL is resolved from
// the request (or Fallback), trusted origins re-expand for the dynamic
// config, trusted providers re-resolve with the request, and the returned
// shallow clone leaves the shared context untouched. Static configurations
// return the input context unchanged. Resolution failures are descriptive
// errors (direct-API callers without a request or fallback surface them as
// 500s upstream via APIError).
//
// Route URL builders consume the same resolution through the request-scoped
// helpers in auth/api/routes (EffectiveBaseURL/EffectiveFullBaseURL), which
// the api middleware installs per request; this helper serves direct-API
// callers that never pass through HTTP middleware.
//
// Upstream TypeScript name: resolveRequestContext.
func ResolveRequestContext(ctx types.AuthContext, r *http.Request, opts Options) (types.AuthContext, error) {
	if opts.DynamicBaseURL == nil {
		return ctx, nil
	}
	baseURL, err := authapi.ResolveDynamicBaseURLForRequest(r, opts)
	if err != nil {
		return types.AuthContext{}, err
	}
	out := ctx
	out.BaseURL = baseURL
	out.TrustedProviders = resolveTrustedProviders(opts, r)
	dynamicOpts := opts
	dynamicOpts.BaseURL = ""
	out.TrustedOrigins = append(
		append([]string(nil), opts.TrustedOrigins...),
		authapi.ExpandDynamicBaseURLOrigins(opts.DynamicBaseURL)...,
	)
	out.Options = dynamicOpts
	out.Options.TrustedOrigins = append([]string(nil), out.TrustedOrigins...)
	snapshot := out.Options
	out.IsTrustedOrigin = func(rawURL string) bool {
		return types.IsTrustedOrigin(rawURL, snapshot, r)
	}
	return out, nil
}
