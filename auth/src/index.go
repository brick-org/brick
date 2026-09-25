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
	authstate "github.com/brick-org/brick/auth/src/api/state"
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
// BetterAuth() call for backward compatibility.
//
// Deprecated: read Auth.ErrorCodes from the BetterAuth return value instead.
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

// defaultAppName resolves the construction display-name default.
// It applies to the context reference only; the
// Options field itself defaults after plugin init so option patches can
// still fill an unset AppName defu-style.
func defaultAppName(appName string) string {
	if appName == "" {
		return "Better Auth"
	}
	return appName
}

// applyStatelessDefaults applies upstream's stateless defu defaults at
// construction.
// Go zero-value deviation (pinned by TestInitDefuScalarZeroValueDeviation):
// plain bool falsy values cannot distinguish "unset" from explicit false,
// so a false Enabled/StoreAccountCookie is treated as unset and filled.
// Presence-tracked kinds honor base-wins exactly. Stateful stays opt-in.
//
// Call before plugin init so plugins see the final options (base wins in
// defuOptions). RefreshCache threshold resolution stays in
// applyCookieRefreshCacheConstruction (called after plugin init, before
// finalizeAuthContext) via authstate.ResolveCookieRefreshCache.
//
// Upstream TypeScript names: createAuthContext (defu blocks).
func applyStatelessDefaults(opts *Options) {
	if opts == nil {
		return
	}
	hasServerStore := opts.DB != nil || opts.SecondaryStorage != nil
	if !hasServerStore {
		if !opts.Session.CookieCache.Enabled {
			opts.Session.CookieCache.Enabled = true
		}
		if opts.Session.CookieCache.Strategy == "" {
			opts.Session.CookieCache.Strategy = types.SessionCookieCacheJWE
		}
		rc := opts.Session.CookieCache.RefreshCache
		configured := rc.Enabled || rc.UpdateAge != 0 || rc.ShouldRefresh != nil
		if !configured {
			opts.Session.CookieCache.RefreshCache.Enabled = true
		}
		if opts.Session.CookieCache.MaxAge == 0 {
			if opts.Session.ExpiresIn != 0 {
				opts.Session.CookieCache.MaxAge = opts.Session.ExpiresIn
			} else {
				opts.Session.CookieCache.MaxAge = 60 * 60 * 24 * 7
			}
		}
	}
	if opts.DB == nil {
		if !opts.Account.StoreAccountCookie {
			opts.Account.StoreAccountCookie = true
		}
	}
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
// Stateless defaults: when neither Options.DB nor Options.SecondaryStorage
// is configured, Session.CookieCache and Account.StoreAccountCookie default
// defu-style (see applyStatelessDefaults); stateful stays opt-in.
// DynamicBaseURL expands into TrustedOrigins at construction and resolves
// per request via ResolveRequestContext.
// Secondary storage is wired for sessions, verifications, and rate limiting.
// Telemetry publishes a local "init" diagnostic only (no network);
// Instrumentation runs WithSpan as a direct passthrough.
// Framework knobs (rate-limit storage, trusted proxies, origin checks,
// schema checks, background tasks) are honored; each is noted once via
// Options.Logger when configured.
//
// Plugins are initialised in declaration order before routes are registered.
//
// Error codes: the returned Auth.ErrorCodes merges plugin $ERROR_CODES with
// BASE_ERROR_CODES in upstream order. The global
// PluginErrorCodes is kept in sync as a deprecated wrapper.
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
	// Stateless defu defaults: applied
	// before plugin init so plugins see the final options. See applyStatelessDefaults.
	applyStatelessDefaults(&opts)
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
	// Init-patch databaseHooks keep their `plugin:<id>` source label in
	// declaration order.
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
		// Optional init patches.
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
	// Expand dynamic origins into static origins.
	if opts.DynamicBaseURL != nil {
		opts.TrustedOrigins = append(opts.TrustedOrigins, authapi.ExpandDynamicBaseURLOrigins(opts.DynamicBaseURL)...)
		ctx.Options = opts
	}
	// Merge trusted-origins env.
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

	applyCookieRefreshCacheConstruction(&opts)
	finalizeAuthContext(&ctx, opts, secret, secretCfg, publish)

	// Wrap the adapter with lifecycle hooks.
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

	// Attach the per-request schema validator.
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
// error reporting. It returns nil (quiet) when logging is disabled.
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
// quiet when logging is disabled or no Log callback is configured.
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
// construction:
//   - BaseURL and DynamicBaseURL are mutually exclusive;
//   - AllowedHosts must be non-empty;
//   - Protocol must be "http", "https", or "auto";
//   - Fallback, when set, must be an absolute http(s) URL.
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

// checkAbsoluteHTTPURL requires a parseable absolute http(s) URL.
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
// Options.Logger; quiet by default).
func noteFrameworkRuntimeOptions(opts Options) {
	if opts.BaseURL == "" && opts.DynamicBaseURL == nil {
		authNotef(opts, "warn", "[better-auth] Base URL is not set. Set the baseURL option or BETTER_AUTH_URL env, or use a dynamic baseURL with allowedHosts for multi-host setups. Without it the origin is derived from the incoming request, and callbacks and redirects may not work correctly.")
	}
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

// dynamicProtocolName names the effective dynamic protocol for log lines.
func dynamicProtocolName(p types.BaseURLProtocol) string {
	if p == "" {
		return "unset (https required, http for loopback only)"
	}
	return string(p)
}

// effectiveRateLimitStorageName names the enforced rate-limit backend for
// log lines.
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
// response is sent. A nil task is a no-op.
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

// patchHookEntry carries one plugin's init-patch databaseHooks with its
// source plugin ID so NewHookedAdapterWithOptions can preserve the
// `plugin:<id>` source label via synthetic plugins.
type patchHookEntry struct {
	pluginID string
	hooks    DBHooks
}

// patchHooksPlugin is a synthetic Plugin carrying init-patch databaseHooks
// so they keep their `plugin:<id>` source label. Only ID and Hooks carry data.
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
// after its legacy entry in declaration order.
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
// resolved tables.
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
// the finalized options.
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

// originOfBaseURL returns the scheme://host origin of a configured BaseURL.
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

// resolveTrustedProviders returns the account-linking trust list.
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

// resolveRateLimitContext resolves the rate-limit triple.
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

// resolveSessionConfig resolves the session lifetime knobs.
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

// applyCookieRefreshCacheConstruction wires the stateless cookie-cache
// refresh decision into BetterAuth construction.
// Call after plugin init so the final options are resolved, before
// finalizeAuthContext so the context and router carry the effective state.
func applyCookieRefreshCacheConstruction(opts *Options) {
	if opts == nil {
		return
	}
	rc := opts.Session.CookieCache.RefreshCache
	configured := rc.Enabled || rc.UpdateAge != 0 || rc.ShouldRefresh != nil
	if !configured {
		return
	}
	hasServerStore := opts.DB != nil || opts.SecondaryStorage != nil
	enabled, effectiveUpdateAge, warnDisable := authstate.ResolveCookieRefreshCache(
		configured, rc.UpdateAge, opts.Session.CookieCache.MaxAge, hasServerStore,
	)
	if warnDisable {
		authNotef(*opts, "warn", "[better-auth] `session.cookieCache.refreshCache` is enabled while `database` or `secondaryStorage` is configured. `refreshCache` is meant for stateless (DB-less) setups. Disabling `refreshCache` — remove it from your config to silence this warning.")
	}
	if !enabled {
		opts.Session.CookieCache.RefreshCache.Enabled = false
		opts.Session.CookieCache.RefreshCache.UpdateAge = 0
		opts.Session.CookieCache.RefreshCache.ShouldRefresh = nil
		return
	}
	opts.Session.CookieCache.RefreshCache.Enabled = true
	opts.Session.CookieCache.RefreshCache.UpdateAge = effectiveUpdateAge
}

// schemaCheckEnabled reports whether the per-request schema validator applies.
func schemaCheckEnabled(opts Options) bool {
	return opts.Advanced.Database.ValidateSchema == nil || *opts.Advanced.Database.ValidateSchema
}

// buildSchemaCheck returns the per-request schema validator attached as
// opts.SchemaCheck (nil when disabled). A mismatch fails
// closed with a descriptive error.
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
// Advanced.Database.GenerateID. It delegates to types.MintModelID.
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
// baseURL configuration. Static configurations return the input unchanged.
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
