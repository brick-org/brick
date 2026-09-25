package types

import (
	"fmt"
	"net/http"
	"net/url"
	stdpath "path"
	"strings"

	"github.com/danielgtaylor/huma/v2"
)

type LogLevel string

const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"

	// LogLevelSuccess mirrors better-auth's "success" publish level.
	// It is emitted by the internal logger but is not accepted by the
	// `level` option (upstream: level defaults to "warn" and excludes
	// "success"; a success log is published as "info" to custom handlers).
	LogLevelSuccess LogLevel = "success"
)

// LoggerOptions mirrors better-auth's top-level logger config surface
// (core/src/env/logger.ts).
//
// Upstream defaults (documented, not applied by the Go runtime): disabled
// is false, disableColors follows TTY detection, and level defaults to
// "warn".
type LoggerOptions struct {
	// Disabled gates all logging. When true, no log callback fires.
	// Runtime: wired:auth/index.go (loggerFromOptions gate + level filtering).
	Disabled bool
	// DisableColors suppresses ANSI colors in the default console output.
	// Custom Log callbacks receive the plain message either way.
	// Runtime: wired:auth/context/secret-utils.go + auth/index.go (level-gated notes honor it for default output).
	DisableColors bool
	// Level selects the minimum published level ("debug" < "info" <
	// "success" < "warn" < "error"; a "success" log is published as "info"
	// to custom handlers, mirroring upstream). Filtering is applied by the
	// Go runtime before invoking Log; the default when empty is "warn".
	// Runtime: wired:auth/index.go + auth/api/index.go (ShouldPublishLog gate).
	Level LogLevel
	// Log receives log reports. Hook after-error reporting, construction
	// parity notes, telemetry debug events, and conflict diagnostics flow
	// through it (all level-gated).
	// Runtime: wired:auth/index.go (hook after-error + parity notes).
	Log func(level, message string, args ...any)
}

// LogLevels in ascending verbosity order, mirroring upstream `levels`
// (vendor/.../core/src/env/logger.ts). Success sorts between info and
// warn; custom handlers receive it as "info".
var logLevelOrder = []LogLevel{LogLevelDebug, LogLevelInfo, LogLevelSuccess, LogLevelWarn, LogLevelError}

// ShouldPublishLog reports whether a message at msgLevel passes the
// configured current level, mirroring upstream shouldPublishLog
// (vendor/.../core/src/env/logger.ts): a message publishes when its
// order index meets or exceeds the current level's. Empty current means
// upstream's "warn" default. Unknown levels fail closed (do not publish).
func ShouldPublishLog(current, msgLevel LogLevel) bool {
	if current == "" {
		current = LogLevelWarn
	}
	if msgLevel == "" {
		return false
	}
	currentIdx, msgIdx := -1, -1
	for i, level := range logLevelOrder {
		if level == current {
			currentIdx = i
		}
		if level == msgLevel {
			msgIdx = i
		}
	}
	if currentIdx == -1 || msgIdx == -1 {
		return false
	}
	return msgIdx >= currentIdx
}

// NormalizeLogLevelForHandler maps upstream levels to the custom-handler
// contract: "success" is published as "info" (upstream createLogger calls
// options.log with "info" for success). All other levels pass through.
func NormalizeLogLevelForHandler(level LogLevel) string {
	if level == LogLevelSuccess {
		return string(LogLevelInfo)
	}
	return string(level)
}

// MatchesHostPattern reports whether host matches an upstream dynamic
// allowedHosts pattern, mirroring matchesHostPattern
// (vendor/.../src/utils/url.ts): case-insensitive, with "*" and "?"
// wildcards. A pattern carrying "://" or a path matches against its host
// part only; empty inputs never match.
func MatchesHostPattern(host, pattern string) bool {
	if host == "" || pattern == "" {
		return false
	}
	normalizedHost := normalizeHostPatternPart(host)
	normalizedPattern := normalizeHostPatternPart(pattern)
	if normalizedHost == "" || normalizedPattern == "" {
		return false
	}
	if !strings.ContainsAny(normalizedPattern, "*?") {
		return normalizedHost == normalizedPattern
	}
	matched, err := stdpath.Match(normalizedPattern, normalizedHost)
	return err == nil && matched
}

// normalizeHostPatternPart lowercases a host or pattern and strips any
// scheme prefix and path suffix, mirroring the upstream normalization in
// matchesHostPattern.
func normalizeHostPatternPart(value string) string {
	v := strings.TrimSpace(value)
	if i := strings.Index(v, "://"); i != -1 {
		v = v[i+3:]
	}
	if i := strings.Index(v, "/"); i != -1 {
		v = v[:i]
	}
	return strings.ToLower(v)
}

// TelemetryOptions mirrors better-auth's top-level telemetry config surface
//
// The Go runtime publishes no network telemetry (there is no telemetry
// endpoint or custom-track plumbing to POST to — upstream createTelemetry
// returns a noop without one). When Enabled, construction publishes a local
// "init" diagnostic via Options.Logger (level-gated, quiet by default) and
// AuthContext.PublishTelemetry reports per-event diagnostics the same way;
// Debug enables per-event payload logging. This is the explicit,
// documented no-network parity point.
// Runtime: wired:auth/telemetry.go (enabled/env gate + init publish + PublishTelemetry).
type TelemetryOptions struct {
	// Enabled toggles telemetry collection. Accepted and preserved.
	// Runtime: wired:auth/telemetry.go (explicit no-network publish + construction-time note; RunInBackground dispatches handlers).
	Enabled bool
	// Debug toggles telemetry debug output. Accepted and preserved.
	// Runtime: wired:auth/telemetry.go (per-event payload logging when enabled).
	Debug bool
}

// TelemetryEvent mirrors the publishTelemetry event shape from upstream
// context (core/src/types/context.ts):
// a type tag, an optional anonymous ID, and an event payload. The Go runtime
// publishes no network telemetry: PublishTelemetry reports local Logger
// diagnostics only.
// Runtime: wired:auth/telemetry.go (PublishTelemetry + construction-time note).
type TelemetryEvent struct {
	Type        string
	AnonymousID string
	Payload     map[string]any
}

// InstrumentationOptions mirrors better-auth's experimental.instrumentation
// config surface
// The Go runtime has no OpenTelemetry tracer; WithSpan executes the function
// directly while preserving name/attribute plumbing for future wiring.
//
// Upstream default (documented, not applied by the Go runtime): enabled is
// true. The pointer preserves the current inactive behavior when nil.
// Runtime: wired:auth/instrumentation.go (WithSpan passthrough honoring the flag).
type InstrumentationOptions struct {
	// Enabled toggles Better Auth spans upstream. Accepted and preserved.
	// Runtime: wired:auth/instrumentation.go (WithSpan passthrough).
	Enabled *bool
}

// ExperimentalOptions mirrors better-auth's top-level experimental config
// surface
// Instrumentation is honored as a tracing passthrough (see WithSpan);
// unknown future flags stay preserved-but-inactive.
// Runtime: wired:auth/instrumentation.go (instrumentation passthrough).
type ExperimentalOptions struct {
	// Instrumentation carries the OpenTelemetry span toggle.
	// Runtime: wired:auth/instrumentation.go (WithSpan passthrough).
	Instrumentation InstrumentationOptions
}

// RateLimitRule configures request limits for a single window
// (upstream BetterAuthRateLimitRule).
type RateLimitRule struct {
	// Window is the rolling window in seconds.
	// Runtime: wired:auth/api/rate_limiter.go:153 (resolveRateLimit).
	Window int
	// Max is the maximum requests allowed within Window.
	// Runtime: wired:auth/api/rate_limiter.go:153 (resolveRateLimit).
	Max int

	// Disabled mirrors better-auth's `false` custom rule value for a path.
	// Runtime: wired:auth/api/rate_limiter.go:172 (static customRules).
	Disabled bool
}

// RateLimitStorage selects the rate-limit storage backend.
// Mirrors better-auth's rateLimit.storage value.
type RateLimitStorage string

const (
	// RateLimitStorageMemory stores rate limits in process memory.
	// Upstream default (documented): "memory".
	RateLimitStorageMemory RateLimitStorage = "memory"
	// RateLimitStorageDatabase stores rate limits in the database.
	RateLimitStorageDatabase RateLimitStorage = "database"
	// RateLimitStorageSecondary stores rate limits in secondary storage.
	RateLimitStorageSecondary RateLimitStorage = "secondary-storage"
)

// RateLimitConsumeResult mirrors the result of better-auth's
// BetterAuthRateLimitStorage.consume call.
type RateLimitConsumeResult struct {
	Allowed    bool
	RetryAfter *int
}

// RateLimitCustomStorage mirrors better-auth's BetterAuthRateLimitStorage
// contract: a single atomic check-and-increment operation. Separate get/set
// shapes are intentionally not accepted upstream because they cannot enforce
// a distributed limit under concurrent requests. When set on
// RateLimitOptions.CustomStorage it is routed by the api middleware
// (Storage is then ignored, mirroring upstream).
// Runtime: wired:auth/api/index.go (custom-storage routing).
type RateLimitCustomStorage interface {
	Consume(key string, rule RateLimitRule) (RateLimitConsumeResult, error)
}

// RateLimitRuleResolver mirrors better-auth's per-path function rule variant
// for customRules: it receives the request and the currently applicable rule.
// The bool result reports whether rate limiting applies; false disables rate
// limiting for that request (mirrors returning `false` upstream). Resolvers
// are matched per request before static CustomRules.
// Runtime: wired:auth/api/rate_limiter.go (customRuleResolver probe).
type RateLimitRuleResolver func(r *http.Request, current RateLimitRule) (RateLimitRule, bool)

// RateLimitOptions configures top-level auth route rate limiting
// (upstream BetterAuthRateLimitOptions).
type RateLimitOptions struct {
	// Enabled is a pointer so nil can mean "use the default behaviour".
	// Upstream default (documented, behavior unchanged here): enabled only
	// in production.
	// Runtime: wired:auth/api/rate_limiter.go:153 (resolveRateLimit gate).
	Enabled *bool
	// Window is the default rolling window in seconds.
	// Runtime: wired:auth/api/rate_limiter.go:153 (WindowOrDefault).
	Window int
	// Max is the default maximum requests within Window.
	// Runtime: wired:auth/api/rate_limiter.go:153 (MaxOrDefault).
	Max int

	// CustomRules applies per-path overrides such as "/sign-in/*" or
	// "/get-session". Use Disabled=true to skip rate limiting for a path.
	// Static entries only; function-valued upstream entries belong in
	// CustomRuleResolvers.
	// Runtime: wired:auth/api/rate_limiter.go:172 (static customRules).
	CustomRules map[string]RateLimitRule

	// CustomRuleResolvers mirrors better-auth's function-valued customRules
	// entries, resolved per request.
	// Runtime: wired:auth/api/rate_limiter.go (customRuleResolver probe).
	CustomRuleResolvers map[string]RateLimitRuleResolver

	// Storage selects the rate-limit storage backend.
	// Upstream default (documented, behavior unchanged here): "memory".
	// The api middleware routes it: database selects the atomic adapter
	// backend, secondary-storage selects SecondaryStorage.Increment.
	// Runtime: wired:auth/api/index.go (storage routing).
	Storage RateLimitStorage

	// CustomStorage provides a custom atomic rate-limit backend.
	// When set, Storage is ignored (mirrors upstream). Routed by the api
	// middleware.
	// Runtime: wired:auth/api/index.go (custom-storage routing).
	CustomStorage RateLimitCustomStorage

	// ModelName customizes the rate-limit table name for database storage.
	// Mirrors better-auth's BetterAuthDBOptions<"rateLimit"> modelName.
	// Runtime: wired:auth/api/index.go (ValidateRateLimitStorage + storage middleware).
	ModelName string

	// Fields maps rate-limit model fields to database columns (excluding
	// "id"). Mirrors better-auth's BetterAuthDBOptions<"rateLimit"> fields.
	// Runtime: wired:auth/api/index.go (ValidateRateLimitStorage + storage middleware).
	Fields map[string]string
}

func (o RateLimitOptions) EnabledValue() bool {
	if o.Enabled != nil {
		return *o.Enabled
	}
	return false
}

func (o RateLimitOptions) WindowOrDefault() int {
	if o.Window > 0 {
		return o.Window
	}
	return 10
}

func (o RateLimitOptions) MaxOrDefault() int {
	if o.Max > 0 {
		return o.Max
	}
	return 100
}

// RequestBeforeHookFunc runs before an auth request is processed.
// It may replace the request context by returning a wrapped huma.Context.
type RequestBeforeHookFunc func(ctx huma.Context) (huma.Context, error)

// RequestAfterHookFunc runs after an auth request has been processed.
type RequestAfterHookFunc func(ctx huma.Context)

// HooksOptions mirrors better-auth's top-level hooks option
type HooksOptions struct {
	// Before runs before auth routing; it may replace the request context.
	// Runtime: wired:auth/api/index.go:68.
	Before RequestBeforeHookFunc
	// After runs after an auth response is produced.
	// Runtime: wired:auth/api/index.go:68.
	After RequestAfterHookFunc
}

// APIErrorHandler mirrors better-auth's onAPIError.onError callback.
type APIErrorHandler func(err huma.StatusError, ctx huma.Context)

// ErrorPageColors configures the default error page colors
// (upstream onAPIError.customizeDefaultErrorPage.colors).
type ErrorPageColors struct {
	Background        string
	Foreground        string
	Primary           string
	PrimaryForeground string
	MutedForeground   string
	Border            string
	Destructive       string
	TitleBorder       string
	TitleColor        string
	GridColor         string
	CardBackground    string
	CornerBorder      string
}

// ErrorPageSize configures the default error page sizing tokens
// (upstream onAPIError.customizeDefaultErrorPage.size).
type ErrorPageSize struct {
	RadiusSm string
	RadiusMd string
	RadiusLg string
	TextSm   string
	Text2xl  string
	Text4xl  string
	Text6xl  string
}

// ErrorPageFont configures the default error page font families
// (upstream onAPIError.customizeDefaultErrorPage.font).
type ErrorPageFont struct {
	DefaultFamily string
	MonoFamily    string
}

// DefaultErrorPageOptions mirrors better-auth's customizeDefaultErrorPage option
type DefaultErrorPageOptions struct {
	Colors                   ErrorPageColors
	Size                     ErrorPageSize
	Font                     ErrorPageFont
	DisableTitleBorder       bool
	DisableCornerDecorations bool
	DisableBackgroundGrid    bool
}

// APIErrorOptions mirrors better-auth's top-level onAPIError option
//
// DEVIATION (loud, intentional): upstream onError is
// `(error: unknown, ctx: AuthContext) => void | Promise<void>`; the Go
// handler is `func(err huma.StatusError, ctx huma.Context)` so it can write
// HTTP responses inline (see auth/api/routes/hooks.go:41). Do not "fix" the
// signature toward AuthContext without also rewiring the middleware.
type APIErrorOptions struct {
	// Throw rethrows API errors instead of rendering them.
	// Runtime: wired:auth/api/index.go:68 (needsMiddleware gate).
	Throw bool
	// OnError handles API errors after hooks/middleware.
	// Runtime: wired:auth/api/routes/hooks.go:41 (callAPIErrorHandler).
	OnError APIErrorHandler
	// ErrorURL redirects error responses (query carries the error).
	// Runtime: wired:auth/api/routes/social.go:185 (OAuth default error
	// URL) and auth/api/routes/password_extra.go:93.
	ErrorURL string
	// CustomizeDefaultErrorPage themes the built-in error page.
	// Nil (unset) means upstream undefined: production bounces to /;
	// non-nil (even empty) renders. Pointer preserves the
	// !customizeDefaultErrorPage distinction (upstream error.ts:430).
	// Runtime: wired:auth/api/routes/error.go:38.
	CustomizeDefaultErrorPage *DefaultErrorPageOptions
}

// ChangeEmailOptions mirrors better-auth's user.changeEmail config block
type ChangeEmailOptions struct {
	// Enabled gates the change-email flow. Upstream default: false.
	// Runtime: wired:auth/api/routes/account.go:198 (update gate).
	Enabled bool

	// SendChangeEmailConfirmation delivers the confirmation link.
	// Runtime: wired:auth/api/routes/account.go:268.
	SendChangeEmailConfirmation func(data ChangeEmailData) error

	// SendChangeEmailConfirmationRequest mirrors upstream's
	// sendChangeEmailConfirmation(data, request?) signature. When set, it
	// takes precedence over SendChangeEmailConfirmation; current routes
	// invoke it with the rebuilt request.
	// Runtime: wired:auth/api/routes/account.go (change-email delivery).
	SendChangeEmailConfirmationRequest func(data ChangeEmailData, r *http.Request) error

	// UpdateEmailWithoutVerification applies the new email without a
	// confirmation round-trip when the current email is unverified.
	// Upstream default: false.
	// Runtime: wired:auth/api/routes/account.go:198.
	UpdateEmailWithoutVerification bool
}

// DeleteUserOptions mirrors better-auth's user.deleteUser config block
type DeleteUserOptions struct {
	// Enabled gates the delete-user flow.
	// Runtime: wired:auth/api/routes/account.go:390.
	Enabled bool

	// SendDeleteAccountVerification delivers the delete confirmation link;
	// without it the user is deleted immediately.
	// Runtime: wired:auth/api/routes/account.go:390.
	SendDeleteAccountVerification func(data DeleteAccountVerificationData) error

	// SendDeleteAccountVerificationRequest mirrors upstream's
	// sendDeleteAccountVerification(data, request?) signature. When set, it
	// takes precedence over SendDeleteAccountVerification; current routes
	// invoke it with the rebuilt request.
	// Runtime: wired:auth/api/routes/account.go (delete-user delivery).
	SendDeleteAccountVerificationRequest func(data DeleteAccountVerificationData, r *http.Request) error

	// BeforeDelete runs before the user row is deleted.
	// Runtime: wired:auth/api/routes/account.go:497.
	BeforeDelete func(user *User) error
	// AfterDelete runs after the user row is deleted.
	// Runtime: wired:auth/api/routes/account.go:519.
	AfterDelete func(user *User) error

	// BeforeDeleteRequest mirrors upstream's beforeDelete(user, request?)
	// signature. When set, it takes precedence over BeforeDelete; current
	// routes invoke it with the rebuilt request.
	// Runtime: wired:auth/api/routes/account.go (delete-user gate).
	BeforeDeleteRequest func(user *User, r *http.Request) error

	// AfterDeleteRequest mirrors upstream's afterDelete(user, request?)
	// signature. When set, it takes precedence over AfterDelete; current
	// routes invoke it with the rebuilt request.
	// Runtime: wired:auth/api/routes/account.go (delete-user completion).
	AfterDeleteRequest func(user *User, r *http.Request) error

	// DeleteTokenExpiresIn is the delete-token TTL in seconds.
	// Upstream default (documented): 86400 (1 day).
	// Runtime: wired:auth/api/routes/account.go:479.
	DeleteTokenExpiresIn int
}

// DBModelOptions mirrors better-auth's BetterAuthDBOptions per-model block
// (modelName, fields, additionalFields) that is
// spread into the user, session, account, and verification option blocks.
//
// Upstream defaults (documented, behavior unchanged here): the model name
// defaults to the model name ("user", "session", "account", "verification")
// with no column remapping and no additional fields. Column remapping is
// honored by the adapter's physical mapping (routes stay on logical keys);
// additional fields are honored for input/output filtering via the schema
// declaration.
type DBModelOptions struct {
	// ModelName overrides the table name. Empty means the default model name.
	// Runtime: wired:auth/index.go:295 (ResolveSchema table merge).
	ModelName string

	// Fields maps logical field names to database columns (excluding "id").
	// Runtime: wired:auth/index.go:295 (ResolveSchema merge; route-level
	// decoding is incomplete).
	Fields map[string]string

	// AdditionalFields declares extra fields on the model (excluding "id"
	// and built-in keys). Mirrors better-auth's additionalFields.
	// Runtime: wired:auth/index.go:295 (schema declaration + route
	// input/output filtering).
	AdditionalFields map[string]FieldAttribute
}

// ValidateUserInfoAction mirrors better-auth's ValidateUserInfoAction:
// what Better Auth is about to do with an incoming identity when the user
// validation hook runs.
type ValidateUserInfoAction string

const (
	ValidateUserInfoActionCreateUser  ValidateUserInfoAction = "create-user"
	ValidateUserInfoActionLinkAccount ValidateUserInfoAction = "link-account"
	ValidateUserInfoActionSignIn      ValidateUserInfoAction = "sign-in"
)

// ValidateUserInfoMethod mirrors better-auth's ValidateUserInfoMethod: the
// authentication method that produced the incoming user info. The named
// methods cover the built-ins; Method remains an open string so plugins can
// report custom methods (e.g. "scim").
type ValidateUserInfoMethod string

const (
	ValidateUserInfoMethodOAuth         ValidateUserInfoMethod = "oauth"
	ValidateUserInfoMethodSSOOIDC       ValidateUserInfoMethod = "sso-oidc"
	ValidateUserInfoMethodSSOSAML       ValidateUserInfoMethod = "sso-saml"
	ValidateUserInfoMethodEmailPassword ValidateUserInfoMethod = "email-password"
	ValidateUserInfoMethodMagicLink     ValidateUserInfoMethod = "magic-link"
	ValidateUserInfoMethodEmailOTP      ValidateUserInfoMethod = "email-otp"
	ValidateUserInfoMethodAnonymous     ValidateUserInfoMethod = "anonymous"
	ValidateUserInfoMethodSIWE          ValidateUserInfoMethod = "siwe"
	ValidateUserInfoMethodPhoneNumber   ValidateUserInfoMethod = "phone-number"
	ValidateUserInfoMethodAdmin         ValidateUserInfoMethod = "admin"
)

// ValidateUserInfoSource describes why and how the incoming identity is
// being provisioned. ProviderID and Profile are present for the oauth,
// sso-oidc, and sso-saml methods only.
type ValidateUserInfoSource struct {
	Action     ValidateUserInfoAction
	Method     ValidateUserInfoMethod
	ProviderID string
	Profile    map[string]any
}

// ValidateUserInfoData is passed to ValidateUserInfoFunc. User carries the
// incoming (partial) user record plus any additional fields.
type ValidateUserInfoData struct {
	User   map[string]any
	Source ValidateUserInfoSource
}

// ValidateUserInfoResult rejects admission. A nil result allows the flow.
// Mirrors better-auth's ValidateUserInfoResult ({ error, errorDescription? }).
type ValidateUserInfoResult struct {
	Error            string
	ErrorDescription string
}

// ValidateUserInfoFunc mirrors better-auth's user.validateUserInfo hook
// return nil to allow, or a result to reject.
// Browser flows redirect to the configured error URL; programmatic flows
// surface a 403. The EndpointContext carries the request when one exists
// (nil-request calls mirror upstream context-init invocations). Enforced at
// every identity-admission seam: credential sign-up/sign-in, social
// create/link, and admin create-user.
// Runtime: wired:auth/api/routes/sign_up.go:143 (create),
// auth/api/routes/sign_in.go:108 (sign-in),
// auth/api/routes/social.go (create/link), plugins/admin (create-user).
type ValidateUserInfoFunc func(data ValidateUserInfoData, ctx EndpointContext) (*ValidateUserInfoResult, error)

// UserOptions mirrors better-auth's top-level user config block
type UserOptions struct {
	// Model customizes the user table name, column mapping, and additional
	// fields. Mirrors better-auth's BetterAuthDBOptions<"user", ...> spread
	// into options.user.
	// Runtime: wired:auth/index.go:295 (ResolveSchema merge).
	Model DBModelOptions

	// ValidateUserInfo gates which identities Better Auth admits across
	// every authentication method: credential sign-up/sign-in, social
	// create/link, and admin create-user all enforce it.
	// Runtime: wired (see ValidateUserInfoFunc).
	ValidateUserInfo ValidateUserInfoFunc

	// ChangeEmail configures the change-email flow.
	// Runtime: wired:auth/api/routes/account.go:198.
	ChangeEmail ChangeEmailOptions
	// DeleteUser configures the delete-user flow.
	// Runtime: wired:auth/api/routes/account.go:390.
	DeleteUser DeleteUserOptions
}

// AccountLinkingOptions mirrors better-auth's account.accountLinking block
type AccountLinkingOptions struct {
	// nil or true = account linking enabled (default); false = disabled.
	// Runtime: wired:auth/api/routes/social.go:374 (linking gate).
	Enabled *bool

	// Disable automatic linking during social sign-in.
	// Runtime: wired:auth/api/routes/social.go:374.
	DisableImplicitLinking bool

	// Providers that are trusted for implicit linking even when the provider
	// does not report a verified email address.
	// Runtime: wired:auth/api/routes/social.go:38.
	TrustedProviders []string

	// Optional dynamic trusted providers hook. The request may be nil:
	// upstream invokes the function during context init (request undefined)
	// and again per request, so it must tolerate nil (sync here; upstream
	// is Awaitable). When both are set, results merge.
	// Runtime: wired:auth/api/routes/social.go:43 (called with nil request
	// at link time; per-request forwarding is pending).
	TrustedProvidersFunc func(r *http.Request) []string

	// AllowDifferentEmails permits manual linking across email addresses.
	// Runtime: wired:auth/api/routes/social.go:284.
	AllowDifferentEmails bool
	// AllowUnlinkingAll permits unlinking every account.
	// Runtime: wired:auth/api/routes/account_extra.go:609.
	AllowUnlinkingAll bool
	// UpdateUserInfoOnLink copies the provider profile onto the local user
	// at link time (never email/emailVerified).
	// Runtime: wired:auth/api/routes/social.go (link block profile copy).
	UpdateUserInfoOnLink bool

	// RequireLocalEmailVerified mirrors better-auth's
	// accountLinking.requireLocalEmailVerified gate: the existing local user
	// row must have emailVerified=true before implicit linking uses the
	// IdP's email_verified claim as ownership proof.
	//
	// Upstream default (documented, behavior unchanged here): true.
	// Upstream marks it deprecated — the gate will become unconditional.
	// Runtime: wired:auth/api/routes/social.go:1056 (implicit-linking gate
	// with RequireLocalEmailVerifiedValue, AUTH-C7-03; verified Wave 10).
	RequireLocalEmailVerified *bool
}

func (o AccountLinkingOptions) IsEnabled() bool {
	return o.Enabled == nil || *o.Enabled
}

// RequireLocalEmailVerifiedValue reports whether implicit linking should
// require a locally verified email. Nil defaults to true (upstream default).
func (o AccountLinkingOptions) RequireLocalEmailVerifiedValue() bool {
	if o.RequireLocalEmailVerified == nil {
		return true
	}
	return *o.RequireLocalEmailVerified
}

// AccountOptions mirrors better-auth's top-level account config block
type AccountOptions struct {
	// Model customizes the account table name, column mapping, and
	// additional fields. Mirrors better-auth's
	// BetterAuthDBOptions<"account", ...> spread into options.account.
	// Runtime: wired:auth/index.go:295 (ResolveSchema merge).
	Model DBModelOptions

	// nil or true = refresh linked account tokens on sign-in (default).
	// Runtime: wired:auth/api/routes/social.go:299 (ShouldUpdateOnSignIn).
	UpdateAccountOnSignIn *bool

	// AccountLinking configures implicit/explicit linking rules.
	// Runtime: wired:auth/api/routes/social.go:38 (see per-field owners).
	AccountLinking AccountLinkingOptions

	// EncryptOAuthTokens encrypts tokens at rest (AES-256-GCM upstream).
	// No current runtime: social login is not registered.
	EncryptOAuthTokens bool
	// SkipStateCookieCheck skips the OAuth state cookie check (security
	// sensitive; default false).
	// No current runtime: social login is not registered.
	SkipStateCookieCheck bool
	// StoreStateStrategy selects "database" or "cookie" OAuth state storage.
	// Empty resolves via ResolvedStateStrategy ("database" when a DB or
	// secondary storage is configured, else "cookie").
	// No current runtime: social login is not registered.
	StoreStateStrategy string
	// StoreAccountCookie stores provider account data in an encrypted cookie
	// for database-less flows. Intentional exclusion (W10-04): the Go runtime
	// requires a database adapter, so database-less account-cookie flows are
	// out of scope; the option is preserved for surface compatibility.
	// Runtime: excluded(W10-04):no-database-less-flows.
	StoreAccountCookie bool
}

func (o AccountOptions) ShouldUpdateOnSignIn() bool {
	return o.UpdateAccountOnSignIn == nil || *o.UpdateAccountOnSignIn
}

func (o AccountOptions) ResolvedStateStrategy(hasDB bool) string {
	if o.StoreStateStrategy != "" {
		return o.StoreStateStrategy
	}
	if hasDB {
		return "database"
	}
	return "cookie"
}

// Secret declares a versioned auth secret.
// The first entry in Options.Secrets is used for newly issued auth state.
// Remaining entries are verification-only during a rotation window.
// Runtime: wired:auth/context/secret-utils.go:133 (resolveSecrets) via auth/index.go:292.
type Secret struct {
	// Version is the numeric key ID (envelope "version" upstream).
	// Runtime: wired:auth/context/secret-utils.go:85 (BuildSecretConfig).
	Version int
	// Value is the secret material.
	// Runtime: wired:auth/context/secret-utils.go:85 (BuildSecretConfig).
	Value string
}

// DefaultSecret is the fallback secret used when no secret is configured
// via Options or env. Mirrors DEFAULT_SECRET in
// vendor/.../src/utils/constants.ts. Use is an error in practice: BetterAuth
// rejects empty resolved secrets, and short secrets warn; this constant
// exists only to document the upstream fallback value, not for production.
const DefaultSecret = "better-auth-secret-12345678901234567890"

// SecretConfig mirrors better-auth's SecretConfig (secret-utils.ts):
// versioned keys for rotation, the current version issuing new state, and
// the legacy single secret (if any) kept for verification.
// Runtime: wired:auth/context/secret-utils.go:85 (BuildSecretConfig) via
// auth/index.go:292.
type SecretConfig struct {
	// Keys maps numeric version -> secret value.
	// Runtime: wired:auth/context/secret-utils.go:85.
	Keys map[int]string
	// CurrentVersion is the version issuing new auth state (first entry).
	// Runtime: wired:auth/context/secret-utils.go:85.
	CurrentVersion int
	// LegacySecret is the non-versioned secret (Options.Secret or env),
	// empty when none. It verifies old state during rotation.
	// Runtime: wired:auth/context/secret-utils.go:133.
	LegacySecret string
}

// CookieAttributes mirrors the subset of better-auth cookie attributes used by
// runtime auth cookie configuration (upstream CookieOptions).
// Runtime: wired:auth/api/routes/session.go (issueSessionCookies/issueSessionCookie assembly).
type CookieAttributes struct {
	// Domain pins the cookie domain. Runtime: wired:auth/api/routes/session.go.
	Domain string
	// Path pins the cookie path. Runtime: wired:auth/api/routes/session.go.
	Path string
	// Secure forces the Secure attribute (nil = environment default).
	// Runtime: wired:auth/api/routes/session.go.
	Secure *bool
	// HTTPOnly controls the HttpOnly flag (nil = default).
	// Runtime: wired:auth/api/routes/session.go.
	HTTPOnly *bool
	// SameSite controls the SameSite mode.
	// Runtime: wired:auth/api/routes/session.go.
	SameSite http.SameSite
	// MaxAge overrides the cookie lifetime in seconds (nil = default).
	// Runtime: wired:auth/api/routes/session.go.
	MaxAge *int
}

// CookieConfig overrides a named auth cookie's name and attributes
// (upstream advanced.cookies entries).
// Runtime: wired:auth/cookies/attributes.go:67 (prefix/name assembly).
type CookieConfig struct {
	// Name overrides the cookie name (prefix handling bypassed when set).
	// Runtime: wired:auth/cookies/attributes.go:67.
	Name string
	// Attributes overrides the cookie attributes.
	// Runtime: wired:auth/api/routes/session.go.
	Attributes CookieAttributes
}

// CrossSubDomainCookiesOptions configures cookie sharing across subdomains
// (upstream advanced.crossSubDomainCookies).
type CrossSubDomainCookiesOptions struct {
	// Enabled toggles cross-subdomain cookies.
	// Runtime: wired:auth/api/routes/session.go (issueSessionCookies and the
	// sign-out clearing path derive the shared domain when set).
	Enabled bool
	// AdditionalCookies lists extra cookies shared across subdomains.
	// Intentional exclusion (W10-05): no route issues those cookies; the
	// shared-domain helper is provided for deployments that do.
	// Runtime: excluded(W10-05):no-issuer-consumes.
	AdditionalCookies []string
	// Domain overrides the shared cookie domain (default: root of BaseURL).
	// Runtime: wired:auth/api/routes/session.go
	// (resolveCrossSubDomainCookieDomain).
	Domain string
}

// IPAddressOptions exposes better-auth's advanced IP address config surface
type IPAddressOptions struct {
	// IPAddressHeaders lists headers consulted for the client IP.
	// Runtime: wired:auth/api/rate_limiter.go:298 (custom header support).
	IPAddressHeaders []string
	// DisableIPTracking disables IP tracking (security sensitive).
	// Runtime: wired:auth/api/rate_limiter.go:298.
	DisableIPTracking bool
	// IPv6Subnet is the prefix length collapsing IPv6 addresses for
	// rate-limit keying (default /64 collapsing in RequestClientIP).
	// Runtime: wired:auth/api/index.go (RequestClientIP applies /64 collapsing).
	IPv6Subnet int

	// TrustedProxies lists trusted reverse-proxy IPs or CIDR ranges.
	// Mirrors better-auth's advanced.ipAddress.trustedProxies. When set, a
	// forwarded-IP chain is walked right to left, trusted hops are skipped,
	// and the first untrusted address is the client IP.
	//
	// Upstream default (documented): unset — only single-value IP headers
	// are trusted.
	// Runtime: wired:auth/api/index.go (RequestClientIP chain walk +
	// FindInvalidTrustedProxies; fail-closed per header).
	TrustedProxies []string
}

// GenerateIDMode selects a database-native ID strategy for
// AdvancedDatabaseOptions. Mirrors better-auth's generateId "serial" and
// "uuid" shorthands.
type GenerateIDMode string

const (
	// GenerateIDModeSerial uses the database's auto-generated ID.
	GenerateIDModeSerial GenerateIDMode = "serial"
	// GenerateIDModeUUID generates a random UUID for the ID.
	GenerateIDModeUUID GenerateIDMode = "uuid"
)

// GenerateIDFunc mirrors better-auth's GenerateIdFn
// it receives the model name and an optional size
// hint and returns a new ID, or false to fall back to the database's
// auto-generated ID. NOTE: upstream passes a single options object
// `{model, size}`; the Go form takes positional args. Consumed by the
// resolved AuthContext.GenerateID (see ResolveGenerateID in auth/index.go);
// direct crypto.GenerateID call sites in routes adopt it incrementally.
// Runtime: wired:auth/index.go (context resolver + default fallback).
type GenerateIDFunc func(model string, size *int) (string, bool)

// GenerateIDOption mirrors better-auth's advanced.database.generateId
// value: a custom function, false (database auto ID),
// or a "serial"/"uuid" shorthand. The zero value preserves current runtime
// ID generation. Consumed by the resolved AuthContext.GenerateID.
// Runtime: wired:auth/index.go (resolver + context).
type GenerateIDOption struct {
	// Func overrides ID generation. Runtime: wired:auth/index.go (resolver).
	Func GenerateIDFunc
	// Mode selects the "serial"/"uuid" shorthand. An explicit Mode, like a
	// non-nil Func, marks the option as set for validation purposes.
	// "serial" (like upstream generateId:false) resolves to ("", false) so
	// the database issues the ID; "uuid" resolves to a random UUID.
	// Runtime: wired:auth/index.go (resolver).
	Mode GenerateIDMode
}

// AdvancedDatabaseOptions mirrors better-auth's advanced.database config
// block. See per-field runtime owners below.
type AdvancedDatabaseOptions struct {
	// DefaultFindManyLimit is the default record count for findMany calls.
	// Upstream default (documented): 100. The shared constant already is
	// 100; adapter call sites that pass an explicit limit stay explicit.
	// Runtime: wired:auth/db/adapter-base.go:84 (DefaultFindManyLimit constant).
	DefaultFindManyLimit int

	// GenerateID overrides ID generation. Zero value preserves current
	// runtime behavior (crypto.GenerateIDWithSize default).
	// Runtime: wired:auth/index.go (AuthContext.GenerateID resolver).
	GenerateID GenerateIDOption

	// Joins enables database joins for adapters that support them.
	// Upstream default (documented): false. The Go adapter negotiates joins
	// via optional interfaces (see db/adapter-base.go); this flag is preserved
	// and surfaced on the resolved context for future enforcement.
	// Runtime: wired:auth/index.go (context surfacing; enforcement stays adapter-side).
	Joins bool

	// ValidateSchema toggles runtime schema validation.
	// Upstream default (documented): true. The pointer preserves current
	// behavior when nil. When not explicitly false, BetterAuth attaches a
	// CheckSchema validator (index-name validation over the resolved tables)
	// and the api middleware runs it per request, mirroring upstream's
	// checkSchema gate.
	// Runtime: wired:auth/index.go + auth/api/index.go (CheckSchema gate).
	ValidateSchema *bool
}

// BackgroundTaskHandler mirrors better-auth's
// advanced.backgroundTasks.handler: it receives a
// unit of deferred work to run after the response is sent (e.g. Vercel's
// waitUntil or the Cloudflare Workers ctx.waitUntil).
//
// DEVIATION (loud, intentional): upstream receives the pending
// `Promise<unknown>` directly; the Go form receives a `func()` thunk
// because Go has no promise value to hand over. Dispatched by
// RunInBackground in auth/index.go.
// Runtime: wired:auth/index.go (RunInBackground dispatches Handler).
type BackgroundTaskHandler func(task func())

// BackgroundTasksOptions mirrors better-auth's advanced.backgroundTasks
// config block. Dispatched by RunInBackground in
// auth/index.go.
// Runtime: wired:auth/index.go (RunInBackground dispatches Handler).
type BackgroundTasksOptions struct {
	// Handler runs deferred work after the response is sent.
	// Runtime: wired:auth/index.go (RunInBackground dispatches it).
	Handler BackgroundTaskHandler
}

// AdvancedOptions mirrors better-auth's advanced runtime and cookie config
type AdvancedOptions struct {
	// IPAddress configures client-IP resolution for rate limiting and
	// session tracking. See per-field owners in IPAddressOptions.
	// Runtime: wired:auth/api/rate_limiter.go:298 (headers/tracking).
	IPAddress IPAddressOptions

	// UseSecureCookies forces the Secure cookie attribute (nil = secure in
	// production only, mirroring upstream).
	// Runtime: wired:auth/cookies/attributes.go:37 (CookiePrefix) via
	// auth/api/routes/session.go.
	UseSecureCookies *bool
	// DisableCSRFCheck disables all CSRF protection (security sensitive).
	// Upstream default: false.
	// Runtime: wired:auth/api/index.go:39 (middleware gate).
	DisableCSRFCheck bool

	// DisableOriginCheck disables validation of callbackURL, redirectTo,
	// errorCallbackURL, and newUserCallbackURL against trusted origins.
	// Upstream default (documented, behavior unchanged here): false. The api
	// origin middleware honors it (skipping origin validation, with the
	// upstream backward-compatible CSRF skip); per-route redirect trust
	// checks in sibling route packages adopt it incrementally.
	// Runtime: wired:auth/api/index.go (origin middleware gate).
	DisableOriginCheck bool

	// CrossSubDomainCookies shares cookies across subdomains.
	// Runtime: wired:auth/api/routes/session.go (Enabled + Domain; see
	// per-field owners in CrossSubDomainCookiesOptions).
	CrossSubDomainCookies CrossSubDomainCookiesOptions
	// Cookies overrides named auth cookie names/attributes
	// ("session_token", "session_data", "dont_remember", "account_data",
	// plus plugin cookies).
	// Runtime: wired:auth/cookies/attributes.go:67 via
	// auth/api/routes/session.go.
	Cookies map[string]CookieConfig
	// DefaultCookieAttributes applies to every auth cookie.
	// Runtime: wired:auth/api/routes/session.go.
	DefaultCookieAttributes CookieAttributes
	// CookiePrefix overrides the cookie name prefix (default derives from
	// the app name, "better-auth" upstream).
	// Runtime: wired:auth/cookies/attributes.go:37.
	CookiePrefix string
	// TrustedProxyHeaders trusts x-forwarded-host/proto (security
	// sensitive; required for dynamic base-URL host/proto inference).
	// Runtime: wired:auth/api/rate_limiter.go:312 (proxy-chain opt-in).
	TrustedProxyHeaders *bool

	// Database mirrors better-auth's advanced.database block (find-many
	// limits, ID generation, joins, schema validation). See per-field owners
	// in AdvancedDatabaseOptions.
	// Runtime: wired:auth/index.go (GenerateID resolver, CheckSchema gate,
	// joins surfacing; find-many limit via the shared constant).
	Database AdvancedDatabaseOptions

	// BackgroundTasks mirrors better-auth's advanced.backgroundTasks block.
	// Runtime: wired:auth/index.go (RunInBackground dispatches Handler).
	BackgroundTasks BackgroundTasksOptions

	// SkipTrailingSlashes makes trailing-slash API routes behave like their
	// canonical spelling. Upstream default (documented): false. The api
	// router registers slash-variant duplicates when set (mirroring
	// upstream's skipTrailingSlashes router normalization) and rate-limit
	// keys normalize trailing slashes for middleware decisions.
	// Runtime: wired:auth/api/index.go (variant registration + key normalization).
	SkipTrailingSlashes bool
}

// SecondaryStorage mirrors better-auth's SecondaryStorage contract used for
// session and rate-limit data
// (core/src/db/type.ts). TTLs are in
// seconds; a nil TTL on Set means no expiry. Table inclusion drops
// secondary-stored tables (schema.go); session reads/writes consume it in
// auth/api/routes/session.go, verification reads/writes in
// auth/api/routes/email_verification.go, and rate limiting consumes
// Increment via auth/api/index.go. Startup rejects the session
// persistence flags only when no backend is configured (auth/index.go).
// Runtime: wired:auth/schema.go (table inclusion) + session/verification
// routes + auth/api/index.go (rate-limit backends) + auth/index.go
// (startup gate).
type SecondaryStorage interface {
	// Get returns the value stored at key.
	// Runtime: wired:auth/api/routes/session.go + email_verification.go.
	Get(key string) (any, error)
	// GetAndDelete atomically returns and removes the value at key.
	// Runtime: wired:auth/api/routes/email_verification.go (secondary
	// verification consume).
	GetAndDelete(key string) (any, error)
	// Increment atomically increments the counter at key by one, returning
	// the post-increment value. A missing key is created with value 1 and
	// the given TTL; later increments never extend it.
	// Runtime: wired:auth/api/index.go (secondary-storage rate limiting).
	Increment(key string, ttl int) (int64, error)
	// Set stores value at key with an optional TTL in seconds.
	// Runtime: wired:auth/api/routes/session.go + email_verification.go.
	Set(key string, value string, ttl *int) error
	// Delete removes the value at key.
	// Runtime: wired:auth/api/routes/session.go + email_verification.go.
	Delete(key string) error
}

// StoreIdentifierMode selects how verification identifiers (tokens, OTPs)
// are stored. Mirrors better-auth's verification.storeIdentifier value.
// Upstream default (documented): "plain".
type StoreIdentifierMode string

const (
	// StoreIdentifierPlain stores verification identifiers as-is.
	StoreIdentifierPlain StoreIdentifierMode = "plain"
	// StoreIdentifierHashed stores a hash of verification identifiers.
	StoreIdentifierHashed StoreIdentifierMode = "hashed"
)

// VerificationStoreIdentifier mirrors better-auth's
// verification.storeIdentifier option: a mode,
// an optional custom hash function, and optional per-identifier overrides.
// Upstream shape is `{ default: StoreIdentifierOption, overrides?: ... }`
// where each option is "plain" | "hashed" | { hash }; here Mode+Hash carry
// the upstream `default` and Overrides carries `overrides` (leaf entries
// must not nest further Overrides). Consumed by the verification
// read/write paths, which hash identifiers before storage and probe both
// forms on lookup.
// Runtime: wired:auth/api/routes/email_verification.go
// (resolveVerificationStoreOption/processVerificationIdentifier) and
// password.go (reset-token consume).
type VerificationStoreIdentifier struct {
	// Mode selects "plain" (default) or "hashed" storage.
	// Runtime: wired:auth/api/routes/email_verification.go.
	Mode StoreIdentifierMode
	// Hash maps an identifier to its stored form. Mirrors upstream's
	// { hash: (identifier) => Promise<string> } variant (sync here).
	// Runtime: wired:auth/api/routes/email_verification.go.
	Hash func(identifier string) (string, error)
	// Overrides customizes storage per verification identifier.
	// Runtime: wired:auth/api/routes/email_verification.go.
	Overrides map[string]VerificationStoreIdentifier
}

// VerificationOptions mirrors better-auth's top-level verification config
// block (BetterAuthDBOptions<"verification", ...> plus verification
// behavior flags).
type VerificationOptions struct {
	// Model customizes the verification table name, column mapping, and
	// additional fields.
	// Runtime: wired:auth/index.go:295 (ResolveSchema merge).
	Model DBModelOptions

	// DisableCleanup disables cleaning up expired values when a
	// verification value is fetched.
	// Runtime: wired:auth/api/routes/email_verification.go (expired-row
	// cleanup gate).
	DisableCleanup bool

	// StoreIdentifier selects how verification identifiers are stored.
	// Upstream default (documented): "plain".
	// Runtime: wired:auth/api/routes/email_verification.go (see
	// VerificationStoreIdentifier).
	StoreIdentifier VerificationStoreIdentifier

	// StoreInDatabase stores verification data in the database even when
	// secondary storage is configured. Upstream default (documented): false.
	// Runtime: wired:auth/schema.go:509 (table inclusion) +
	// auth/api/routes/email_verification.go (dual-write/consume paths).
	StoreInDatabase bool
}

// BaseURLProtocol selects the protocol used with dynamic base-URL
// resolution. Mirrors better-auth's DynamicBaseURLConfig protocol value.
// Upstream default (documented): "auto".
type BaseURLProtocol string

const (
	BaseURLProtocolHTTP  BaseURLProtocol = "http"
	BaseURLProtocolHTTPS BaseURLProtocol = "https"
	BaseURLProtocolAuto  BaseURLProtocol = "auto"
)

// DynamicBaseURLConfig mirrors better-auth's DynamicBaseURLConfig for
// multi-domain deployments (e.g. preview URLs)
// Upstream baseURL is `string |
// DynamicBaseURLConfig`; Go keeps the static BaseURL
// string and carries the object form in Options.DynamicBaseURL (exactly one
// may be set — see ValidateOptions). x-forwarded-host is only honored when
// Advanced.TrustedProxyHeaders is enabled upstream. BetterAuth validates and
// expands it for trusted origins; per-request handler rewriting stays future.
// Runtime: wired:auth/index.go (validateDynamicBaseURL + expansion merge)
// and auth/api/index.go (dynamic-aware origin middleware).
type DynamicBaseURLConfig struct {
	// AllowedHosts are permitted hostnames; supports wildcard patterns.
	// Runtime: wired:auth/index.go (validateDynamicBaseURL + expansion merge).
	AllowedHosts []string
	// Fallback is used when no allowed request host can be resolved.
	// Runtime: wired:auth/index.go (validateDynamicBaseURL + expansion merge).
	Fallback string
	// Protocol selects the URL scheme. Upstream default: "auto".
	// Runtime: wired:auth/index.go (validateDynamicBaseURL + expansion merge).
	Protocol BaseURLProtocol
}

// REMOVED (AUTH-F6-03): DatabaseHints / Options.DBHints /
// ValidateDatabaseHints.
//
// Upstream `database` object-form connection selectors (casing, debugLogs,
// transaction, schemaName) configure the Kysely
// adapter factory. Go adapters are constructed by the caller before
// BetterAuth runs, so no hint had an applicable adapter/runtime consumer:
// they were validated-and-preserved inert values. Per the parity rule
// against inert preserved options, the surface was removed rather than
// documented-as-ignored. Callers configure naming, logging, transactions,
// and schema qualification on their adapter directly (e.g.
// auth/adapters/bun). If a future Go adapter factory needs these selectors,
// revive them together with a runtime consumer and construction tests —
// never as validation-only fields.

// Options configures the auth instance (upstream BetterAuthOptions,
// init-options.ts). Every field carries a Runtime marker naming
// the owning runtime file; "wired" means BetterAuth/routes consume it,
// "excluded(W10-XX)" names the intentional-exclusion registry entry in
// registry. No field is silently ignored: the Wave-10 audit removed or
// wired every pending marker.
type Options struct {
	// AppName identifies the application in auth UX contexts.
	// Mirrors better-auth's appName option.
	// Runtime: wired:auth/index.go:285 (default "Better Auth" + context).
	AppName string

	// BaseURL is the full application URL, e.g. "https://myapp.com".
	// Its origin is always trusted. Mirrors the string half of upstream's
	// baseURL option; the object half lives in
	// DynamicBaseURL. Set exactly one of the two (see ValidateOptions).
	// Runtime: wired:auth/api/index.go:39 (origin middleware).
	BaseURL string

	// DynamicBaseURL carries the object half of upstream's baseURL option
	// (DynamicBaseURLConfig) for multi-domain
	// deployments. Nil means static-BaseURL mode. Exactly one of BaseURL
	// and DynamicBaseURL may be set.
	// Runtime: wired:auth/index.go (validation + trusted-origin expansion +
	// per-request ResolveRequestContext) and auth/api/index.go (dynamic-aware
	// origin middleware + per-request resolution).
	DynamicBaseURL *DynamicBaseURLConfig

	// BasePath is the route path prefix, default "/api/auth"
	// (upstream basePath).
	// Runtime: wired:auth/index.go:282 (default) via auth/api/index.go:24.
	BasePath string
	// Secret is the legacy single secret, preserved for backwards compatibility
	// (upstream secret; env fallback owned by
	// auth/context/secret-utils.go:133).
	// Runtime: wired:auth/context/secret-utils.go:133 (resolveSecrets).
	Secret string
	// Secrets holds versioned secrets for non-destructive rotation
	// (upstream secrets; BETTER_AUTH_SECRETS env form
	// owned by auth/context/secret-utils.go:133).
	// Runtime: wired:auth/context/secret-utils.go:133 (resolveSecrets).
	Secrets []Secret
	// Adapter is the HTTP router adapter created by the caller (humachi,
	// humagin, …). Go-only mount surface (upstream mounts via framework
	// integrations, intentionally excluded from this port).
	// Runtime: wired:auth/index.go:421 (Router).
	Adapter huma.Adapter
	// DB is the database adapter (bun, gorm, …).
	//
	// DEVIATION (loud, intentional, stable): upstream names this option
	// `database` (BetterAuthOptions.database). This port names it DB for
	// Go brevity and to avoid confusion with the `db` package name in
	// imports (`db.Adapter` vs `Database`). Renaming DB→Database would be
	// mechanical (100+ call sites in routes/plugins/tests) but churns the
	// entire call surface for no behavioral gain; it is deliberately NOT
	// renamed. New code must use DB; do not add a Database alias.
	// The upstream `database` object-form connection selectors
	// (casing/debugLogs/transaction/schemaName) have no Go equivalent: Go
	// adapters are caller-constructed, so the former DBHints surface was
	// removed in AUTH-F6-03 rather than preserved inertly (see the REMOVED
	// note above). Configure naming/logging/transactions/schema on the
	// adapter directly.
	// Runtime: wired:auth/index.go:409 (hook wrapping + route use).
	DB Adapter
	// Plugins extends auth with routes, schema, hooks, and error codes
	// (upstream plugins).
	// Runtime: wired:auth/index.go:319 (declaration-order init).
	Plugins []Plugin

	// Schema is computed by auth.BetterAuth from the active plugins; do not set manually.
	// Runtime: wired:auth/index.go:295 (ResolveSchema assignment).
	Schema PluginSchema

	// EmailAndPassword configures credential auth (upstream
	// emailAndPassword). See per-field owners in
	// email-password.go.
	// Runtime: wired:auth/api/routes/sign_up.go:42 (enable gate).
	EmailAndPassword EmailAndPasswordOptions
	// EmailVerification configures verification email flows (upstream
	// emailVerification). See per-field owners in
	// email-password.go.
	// Runtime: wired:auth/api/routes/email_verification.go:91.
	EmailVerification EmailVerificationOptions
	// Session configures session lifetime/refresh/storage (upstream
	// session). See per-field owners in
	// email-password.go.
	// Runtime: wired:auth/api/routes/session.go:366 (expiry/refresh).
	Session SessionOptions
	// User configures user model, admission gate, and lifecycle flows
	// (upstream user).
	// Runtime: wired:auth/api/routes/account.go:198 (change-email gate).
	User UserOptions
	// Account configures OAuth account storage and linking (upstream
	// account).
	// Runtime: wired:auth/api/routes/social.go:38 (linking).
	Account AccountOptions

	// Verification mirrors better-auth's top-level verification config
	// block. Table inclusion is wired; identifier
	// handling is types-only.
	// Runtime: wired:auth/schema.go:509 (table inclusion);
	// pending:auth/api/routes/email_verification.go:265 (identifier handling).
	Verification VerificationOptions

	// SecondaryStorage stores session and rate-limit data.
	// Mirrors better-auth's top-level secondaryStorage option
	// Table inclusion, session/verification runtime,
	// and rate-limit backends consume it (see the secondary-storage runtime
	// in auth/api/routes/session.go and email_verification.go).
	// Runtime: wired:auth/schema.go (table inclusion) + session/verification
	// routes + auth/api/index.go (rate-limit backends).
	SecondaryStorage SecondaryStorage

	// TrustedOrigins is a static list of additional trusted origin patterns
	// beyond the app's own BasePath origin. Supports wildcards:
	//   "*.example.com"           — any subdomain
	//   "https://*.example.com"   — any subdomain, HTTPS only
	// Mirrors the static half of upstream trustedOrigins.
	// Runtime: wired:auth/api/index.go:39 (origin middleware via
	// IsTrustedOrigin; collection finalized at auth/index.go:387).
	TrustedOrigins []string

	// TrustedOriginsFunc returns additional trusted origins per request.
	// Its results are merged with TrustedOrigins. Mirrors better-auth's
	// dynamic trustedOrigins function variant (init-options.ts; sync
	// here, upstream is Awaitable and may yield nullish entries — nil/empty
	// entries are filtered at auth/index.go:387). The request may be nil
	// (context-init calls).
	// Runtime: wired:auth/api/index.go:39 (reconstructed request
	// forwarding).
	TrustedOriginsFunc func(r *http.Request) []string

	// SocialProviders is the list of enabled OAuth / social auth providers.
	// Mirrors upstream socialProviders.
	// No current runtime: social login is not registered and no provider
	// factories ship with this module.
	SocialProviders []OAuthProvider

	// DisabledPaths disables specific auth routes using better-auth-style
	// relative paths like "/sign-in/email" (upstream disabledPaths,
	// Runtime: wired:auth/api/index.go:28 (middleware normalization).
	DisabledPaths []string

	// DatabaseHooks configures global DB lifecycle hooks that run in addition
	// to plugin hooks. Mirrors better-auth's top-level databaseHooks option
	// Runtime: wired:auth/index.go (user-sourced hook merge via NewHookedAdapterWithOptions).
	DatabaseHooks DBHooks

	// OnAfterCommitHookError reports post-commit (Transaction flush)
	// after-hook failures after the surrounding work has committed, mirroring
	// upstream runWithTransaction's onAfterCommitHookError option
	// (core/src/context/transaction.ts). Reporting cannot roll back
	// committed work or suppress later hooks; without a handler the first
	// flush failure fails the Transaction call instead. Nil (the default)
	// preserves the fail-first behavior.
	// Runtime: wired:auth/index.go (HookedAdapterOptions.OnAfterCommitHookError).
	OnAfterCommitHookError func(error)

	// SchemaCheck validates the resolved schema. Computed by BetterAuth;
	// do not set manually. Nil when Advanced.Database.ValidateSchema is
	// explicitly false. The api middleware runs it per request, mirroring
	// upstream's checkSchema gate (vendor/.../core/src/db/schema-check.ts);
	// construction never awaits the verdict so migration tooling can use a
	// context whose schema needs repair.
	// Runtime: wired:auth/index.go + auth/api/index.go (per-request gate).
	SchemaCheck func() error

	// RateLimit configures global and per-route request limits for auth
	// endpoints. Mirrors better-auth's top-level rateLimit option subset
	// See per-field owners in RateLimitOptions.
	// Runtime: wired:auth/api/rate_limiter.go:135 (resolveRateLimit).
	RateLimit RateLimitOptions

	// Hooks configures global request hooks that run around every auth route
	// (upstream hooks).
	// Runtime: wired:auth/api/index.go:68.
	Hooks HooksOptions

	// OnAPIError configures auth API error handling parity options
	// (upstream onAPIError).
	// Runtime: wired:auth/api/routes/hooks.go:41.
	OnAPIError APIErrorOptions

	// Logger configures auth logging parity options (upstream logger).
	// Level filtering (ShouldPublishLog, default "warn") gates Log for
	// hook errors, parity notes, telemetry diagnostics, and conflict
	// reports; Disabled suppresses all output.
	// Runtime: wired:auth/index.go + auth/api/index.go (level-gated).
	Logger LoggerOptions

	// Telemetry configures auth telemetry parity options (upstream
	// telemetry). Enabled publishes a local init
	// diagnostic (no network); Debug logs per-event payloads.
	// Runtime: wired:auth/telemetry.go (enabled/env gate + PublishTelemetry).
	Telemetry TelemetryOptions

	// Experimental mirrors better-auth's top-level experimental config
	// surface. Instrumentation Enabled (default true
	// when nil) keeps WithSpan tracing active as a passthrough.
	// Runtime: wired:auth/instrumentation.go (instrumentation passthrough).
	Experimental ExperimentalOptions

	// Advanced configures runtime request handling and cookie behavior that
	// better-auth groups under options.advanced. See
	// per-field owners in AdvancedOptions.
	// Runtime: wired:auth/api/index.go:39 (CSRF/origin middleware).
	Advanced AdvancedOptions
}

// AuthContext holds the resolved runtime configuration.
// Runtime: wired:auth/index.go (BetterAuth builds it from Options).
//
// The Go context carries the subset of upstream AuthContext services that
// the framework layer owns: identity (AppName, BaseURL, Version), secrets,
// resolved tables, trust (origins/providers + predicate), ID generation,
// rate-limit resolution, telemetry publishing, schema checking, and request
// flags. Cookie/session stores, password hashing, and the internal adapter
// remain with their owning packages; route handlers receive this context
// via PluginHookContext/AuthContext (see types/plugins.go) and the api
// middleware, which rebuilds the per-request slice (BaseURL, trust) for
// dynamic configurations.
type AuthContext struct {
	// Options is the resolved option set (defaults applied, plugin patches
	// merged, trusted origins collected).
	// Runtime: wired:auth/index.go.
	Options Options
	// AppName is the resolved application display name.
	// Runtime: wired:auth/index.go.
	AppName string
	// BaseURL is the resolved static origin ("" in dynamic mode until a
	// per-request ResolveRequestContext fills it). Mirrors ctx.baseURL.
	// Runtime: wired:auth/index.go.
	BaseURL string
	// Version is the Better Auth version this port tracks.
	// Runtime: wired:auth/index.go.
	Version string
	// Secret is the current secret issuing new auth state, resolved from
	// Options.Secrets/Options.Secret or BETTER_AUTH_SECRET/AUTH_SECRET/
	// BETTER_AUTH_SECRETS env (upstream precedence). Mirrors ctx.secret.
	// Runtime: wired:auth/context/secret-utils.go via auth/index.go.
	Secret string
	// SecretConfig is the versioned secret config honoring numeric Version,
	// mirroring ctx.secretConfig. Keys holds version->value; CurrentVersion
	// issues new state; LegacySecret verifies old single-secret state.
	// Runtime: wired:auth/context/secret-utils.go via auth/index.go.
	SecretConfig SecretConfig
	// Tables is the fully resolved schema (core + plugin + option
	// additionalFields, minus secondary-stored tables, plus the rate-limit
	// table when database storage is selected). Mirrors ctx.tables.
	// Runtime: wired:auth/index.go (FullSchema).
	Tables PluginSchema
	// TrustedOrigins is the resolved static trust list (BaseURL origin +
	// collected statics + BETTER_AUTH_TRUSTED_ORIGINS env). Per-request
	// dynamic resolvers re-derive it via IsTrustedOrigin.
	// Runtime: wired:auth/index.go.
	TrustedOrigins []string
	// TrustedProviders is the resolved account-linking trust list (static
	// entries; function resolvers evaluate per request with nil at
	// construction). Mirrors ctx.trustedProviders.
	// Runtime: wired:auth/index.go.
	TrustedProviders []string
	// IsTrustedOrigin reports whether url is trusted under the resolved
	// origins. Nil means trust was not resolved (no origins configured).
	// Mirrors ctx.isTrustedOrigin.
	// Runtime: wired:auth/index.go.
	IsTrustedOrigin func(url string) bool
	// GenerateID mints model IDs honoring
	// Advanced.Database.GenerateID (custom Func, "uuid", "serial"/false for
	// database-issued). Nil means default generation. Mirrors
	// ctx.generateId.
	// Runtime: wired:auth/index.go.
	GenerateID GenerateIDFunc
	// RateLimit is the resolved rate-limit triple (enabled default,
	// window/max defaults, storage default) mirroring ctx.rateLimit.
	// Runtime: wired:auth/index.go.
	RateLimit ResolvedRateLimit
	// SessionConfig carries the resolved session lifetime knobs (updateAge,
	// expiresIn, freshAge defaults) mirroring ctx.sessionConfig.
	// Runtime: wired:auth/index.go.
	SessionConfig ResolvedSessionConfig
	// OAuthStateStrategy is the resolved OAuth state strategy ("database"
	// when a DB or secondary storage is configured, else "cookie"),
	// mirroring ctx.oauthConfig.storeStateStrategy.
	// Runtime: wired:auth/index.go.
	OAuthStateStrategy string
	// SkipCSRFCheck mirrors ctx.skipCSRFCheck
	// (Advanced.DisableCSRFCheck).
	// Runtime: wired:auth/index.go.
	SkipCSRFCheck bool
	// SkipOriginCheck mirrors ctx.skipOriginCheck
	// (Advanced.DisableOriginCheck).
	// Runtime: wired:auth/index.go.
	SkipOriginCheck bool
	// CheckSchema validates the resolved schema against the adapter when
	// Advanced.Database.ValidateSchema is not explicitly false. Nil when
	// disabled or no database is configured. The api middleware runs it per
	// request, mirroring upstream's checkSchema gate.
	// Runtime: wired:auth/index.go + auth/api/index.go.
	CheckSchema func() error
	// PublishTelemetry reports telemetry events. It is a no-network local
	// diagnostic: a no-op unless telemetry is enabled (option or
	// BETTER_AUTH_TELEMETRY env), logging via Options.Logger when Debug is
	// set. Mirrors ctx.publishTelemetry.
	// Runtime: wired:auth/telemetry.go.
	PublishTelemetry func(TelemetryEvent)
}

// ResolvedRateLimit is the construction-resolved rate-limit triple,
// mirroring ctx.rateLimit (enabled default, window/max defaults, storage
// default). CustomStorage and rule details stay on Options.RateLimit.
type ResolvedRateLimit struct {
	Enabled bool
	Window  int
	Max     int
	Storage RateLimitStorage
}

// ResolvedSessionConfig carries the resolved session lifetime knobs,
// mirroring ctx.sessionConfig (updateAge, expiresIn, freshAge defaults).
type ResolvedSessionConfig struct {
	UpdateAge int
	ExpiresIn int
	FreshAge  int
}

// Auth is the result of auth.BetterAuth.
// The underlying HTTP handler is owned by the adapter the caller provided.
// Runtime: wired:auth/index.go:281 (BetterAuth return value).
type Auth struct {
	API     huma.API
	Context AuthContext
	// ErrorCodes merges plugin $ERROR_CODES with BASE_ERROR_CODES in
	// upstream order ({...pluginCodes, ...BASE...}), mirroring
	// `$ERROR_CODES` in vendor/.../src/auth/base.ts. Keys are UPPER_SNAKE
	// codes; values are RawError{code,message} objects. Upstream TypeScript
	// name: $ERROR_CODES.
	ErrorCodes map[string]RawError
}

// CurrentSecret returns the secret used for newly issued auth state.
func (o Options) CurrentSecret() string {
	if len(o.Secrets) > 0 && o.Secrets[0].Value != "" {
		return o.Secrets[0].Value
	}
	return o.Secret
}

// AllSecrets returns the ordered secrets accepted for verification.
func (o Options) AllSecrets() []string {
	if len(o.Secrets) == 0 {
		if o.Secret == "" {
			return nil
		}
		return []string{o.Secret}
	}

	all := make([]string, 0, len(o.Secrets)+1)
	seen := map[string]struct{}{}
	for _, secret := range o.Secrets {
		if secret.Value == "" {
			continue
		}
		if _, ok := seen[secret.Value]; ok {
			continue
		}
		all = append(all, secret.Value)
		seen[secret.Value] = struct{}{}
	}
	if o.Secret != "" {
		if _, ok := seen[o.Secret]; !ok {
			all = append(all, o.Secret)
		}
	}
	return all
}

// Validate reports types-level configuration problems without consulting
// the environment or changing BetterAuth behavior. It is a pure function
// with no callers outside package types: runtime construction
// (auth.BetterAuth at auth/index.go:281, secret resolution at
// auth/context/secret-utils.go:133) applies env fallback and its own errors
// independently. Validate exists so integrators and tests can pin the
// option contract (empty secrets, malformed URLs, conflicting storage
// flags, bad literals) without booting a router.
func (o Options) Validate() error { return ValidateOptions(o) }

// ValidateOptions checks an Options value for descriptive, types-level
// configuration errors. Pure: no I/O, no env reads (BETTER_AUTH_SECRET and
// friends are resolved at runtime by auth/context/secret-utils.go:133), no mutation, and
// no callers outside package types.
func ValidateOptions(o Options) error {
	if o.CurrentSecret() == "" {
		return fmt.Errorf("auth: options.Secret/Secrets is empty: set Secret or Secrets (runtime also accepts BETTER_AUTH_SECRET/AUTH_SECRET/BETTER_AUTH_SECRETS env, resolved at auth/context/secret-utils.go:133)")
	}
	for i, s := range o.Secrets {
		if s.Value == "" {
			return fmt.Errorf("auth: options.Secrets[%d] has an empty value", i)
		}
		if s.Version < 0 {
			return fmt.Errorf("auth: options.Secrets[%d] has a negative version %d", i, s.Version)
		}
	}
	seen := map[int]int{}
	for i, s := range o.Secrets {
		if prev, ok := seen[s.Version]; ok {
			return fmt.Errorf("auth: options.Secrets[%d] duplicates version %d (first at index %d)", i, s.Version, prev)
		}
		seen[s.Version] = i
	}
	if o.BaseURL != "" {
		if err := checkAbsoluteHTTPURL(o.BaseURL); err != nil {
			return fmt.Errorf("auth: options.BaseURL is invalid: %w", err)
		}
	}
	if o.DynamicBaseURL != nil {
		if o.BaseURL != "" {
			return fmt.Errorf("auth: options.BaseURL and options.DynamicBaseURL are mutually exclusive: upstream baseURL is string | DynamicBaseURLConfig (init-options.ts:189), set exactly one")
		}
		if len(o.DynamicBaseURL.AllowedHosts) == 0 {
			return fmt.Errorf("auth: options.DynamicBaseURL.AllowedHosts must not be empty")
		}
		if p := o.DynamicBaseURL.Protocol; p != "" && p != BaseURLProtocolHTTP && p != BaseURLProtocolHTTPS && p != BaseURLProtocolAuto {
			return fmt.Errorf("auth: options.DynamicBaseURL.Protocol must be %q, %q, or %q, got %q", BaseURLProtocolHTTP, BaseURLProtocolHTTPS, BaseURLProtocolAuto, p)
		}
		if o.DynamicBaseURL.Fallback != "" {
			if err := checkAbsoluteHTTPURL(o.DynamicBaseURL.Fallback); err != nil {
				return fmt.Errorf("auth: options.DynamicBaseURL.Fallback is invalid: %w", err)
			}
		}
	}
	for i, origin := range o.TrustedOrigins {
		if strings.TrimSpace(origin) == "" {
			return fmt.Errorf("auth: options.TrustedOrigins[%d] must not be empty", i)
		}
	}
	if err := o.EmailAndPassword.Validate(); err != nil {
		return err
	}
	if err := o.EmailVerification.Validate(); err != nil {
		return err
	}
	if err := o.Session.Validate(); err != nil {
		return err
	}
	if o.Session.StoreSessionInDatabase || o.Session.PreserveSessionInDatabase {
		if o.SecondaryStorage == nil {
			return fmt.Errorf("auth: session secondary-storage flags require options.SecondaryStorage: StoreSessionInDatabase=%v PreserveSessionInDatabase=%v without a backend (rejected at runtime by auth/index.go:296)", o.Session.StoreSessionInDatabase, o.Session.PreserveSessionInDatabase)
		}
	}
	if o.Verification.StoreInDatabase && o.SecondaryStorage == nil {
		return fmt.Errorf("auth: options.Verification.StoreInDatabase requires options.SecondaryStorage (meaningless without a secondary backend)")
	}
	if m := o.Verification.StoreIdentifier.Mode; m != "" && m != StoreIdentifierPlain && m != StoreIdentifierHashed {
		return fmt.Errorf("auth: options.Verification.StoreIdentifier.Mode must be %q or %q, got %q", StoreIdentifierPlain, StoreIdentifierHashed, m)
	}
	if s := o.RateLimit.Storage; s != "" && s != RateLimitStorageMemory && s != RateLimitStorageDatabase && s != RateLimitStorageSecondary {
		return fmt.Errorf("auth: options.RateLimit.Storage must be %q, %q, or %q, got %q", RateLimitStorageMemory, RateLimitStorageDatabase, RateLimitStorageSecondary, s)
	}
	if o.RateLimit.Storage == RateLimitStorageSecondary && o.SecondaryStorage == nil {
		return fmt.Errorf("auth: options.RateLimit.Storage=%q requires options.SecondaryStorage (no backend configured)", RateLimitStorageSecondary)
	}
	if o.RateLimit.Window < 0 {
		return fmt.Errorf("auth: options.RateLimit.Window must not be negative, got %d", o.RateLimit.Window)
	}
	if o.RateLimit.Max < 0 {
		return fmt.Errorf("auth: options.RateLimit.Max must not be negative, got %d", o.RateLimit.Max)
	}
	if strat := o.Session.CookieCache.Strategy; strat != "" && strat != SessionCookieCacheCompact && strat != SessionCookieCacheJWT && strat != SessionCookieCacheJWE {
		return fmt.Errorf("auth: options.Session.CookieCache.Strategy must be %q, %q, or %q, got %q", SessionCookieCacheCompact, SessionCookieCacheJWT, SessionCookieCacheJWE, strat)
	}
	if o.OnAPIError.ErrorURL != "" {
		if err := checkURLAllowsRelative(o.OnAPIError.ErrorURL); err != nil {
			return fmt.Errorf("auth: options.OnAPIError.ErrorURL is invalid: %w", err)
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

// checkURLAllowsRelative accepts absolute http(s) URLs and root-relative
// paths (upstream errorURL defaults to "/api/auth/error").
func checkURLAllowsRelative(raw string) error {
	if strings.HasPrefix(raw, "/") {
		if strings.ContainsAny(raw, " \t\n") {
			return fmt.Errorf("expected a URL path without whitespace, got %q", raw)
		}
		return nil
	}
	return checkAbsoluteHTTPURL(raw)
}
