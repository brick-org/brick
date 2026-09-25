package types

import (
	"fmt"
	"net/http"
	"time"
)

// --- callback data types (mirror better-auth's data object pattern) ---

// PasswordVerifyData is passed to password verify overrides.
type PasswordVerifyData struct {
	Hash     string
	Password string
}

// PasswordOptions mirrors better-auth's emailAndPassword.password overrides.
type PasswordOptions struct {
	Hash   func(password string) (string, error)
	Verify func(data PasswordVerifyData) (bool, error)
}

// ResetPasswordData is passed to SendResetPassword.
type ResetPasswordData struct {
	User  *User
	URL   string
	Token string
}

// PasswordResetData is passed to OnPasswordReset.
type PasswordResetData struct {
	User *User
}

// ExistingUserSignUpData is passed to OnExistingUserSignUp.
type ExistingUserSignUpData struct {
	User *User
}

// SyntheticUserCoreFields contains the built-in fields used to construct a
// synthetic user when enumeration protection is active.
type SyntheticUserCoreFields struct {
	Name          string
	Email         string
	EmailVerified bool
	Image         *string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// SyntheticUserData is passed to CustomSyntheticUser.
type SyntheticUserData struct {
	CoreFields       SyntheticUserCoreFields
	AdditionalFields map[string]any
	ID               string
}

// VerificationEmailData is passed to SendVerificationEmail.
type VerificationEmailData struct {
	User  *User
	URL   string
	Token string
}

// ChangeEmailData is passed to SendChangeEmailConfirmation.
type ChangeEmailData struct {
	User     *User
	NewEmail string
	URL      string
	Token    string
}

// DeleteAccountVerificationData is passed to SendDeleteAccountVerification.
type DeleteAccountVerificationData struct {
	User  *User
	URL   string
	Token string
}

// EmailAndPasswordOptions mirrors better-auth's emailAndPassword config block
type EmailAndPasswordOptions struct {
	// Enable email and password authentication (upstream enabled).
	// Runtime: wired:auth/api/routes/sign_up.go:42 (sign-up gate).
	Enabled bool

	// Prevent new sign-ups while still allowing existing users to sign in.
	// Runtime: wired:auth/api/routes/sign_up.go:42.
	DisableSignUp bool

	// Minimum password length. Default 8.
	// Runtime: wired:auth/api/routes/sign_up.go:236.
	MinPasswordLength int

	// Maximum password length. Default 128.
	// Runtime: wired:auth/api/routes/sign_up.go:243.
	MaxPasswordLength int

	// Password overrides the default password hash/verify behavior.
	// Runtime: wired:auth/api/routes/sign_up.go:236 (hash path via crypto).
	Password PasswordOptions

	// Block sign-in until the user verifies their email.
	// Runtime: wired:auth/api/routes/sign_in.go:79.
	RequireEmailVerification bool

	// Automatically create a session after sign-up.
	// nil or true = auto sign-in (default); false = skip session creation.
	// Runtime: wired:auth/api/routes/sign_up.go:250 (autoSignInEnabled).
	AutoSignIn *bool

	// Invalidate all sessions when the user resets their password.
	// Runtime: wired:auth/api/routes/password.go:222.
	RevokeSessionsOnPasswordReset bool

	// TTL of the password-reset token in seconds. Default 3600.
	// Runtime: wired:auth/api/routes/password.go:82.
	ResetPasswordTokenExpiresIn int

	// SendResetPassword is called to deliver the reset link to the user.
	// Runtime: wired:auth/api/routes/password.go:102.
	SendResetPassword func(data ResetPasswordData) error

	// SendResetPasswordRequest mirrors upstream's
	// sendResetPassword(data, request?) signature. When set, it takes
	// precedence over SendResetPassword; current routes invoke it with the
	// rebuilt request.
	// Runtime: wired:auth/api/routes/password.go (reset delivery).
	SendResetPasswordRequest func(data ResetPasswordData, r *http.Request) error

	// OnPasswordReset is called after a password reset succeeds.
	// Runtime: wired:auth/api/routes/password.go:215.
	OnPasswordReset func(data PasswordResetData) error

	// OnPasswordResetRequest mirrors upstream's onPasswordReset(data,
	// request?) signature. When set, it takes precedence over
	// OnPasswordReset; current routes invoke it with the rebuilt request.
	// Runtime: wired:auth/api/routes/password.go (post-reset hook).
	OnPasswordResetRequest func(data PasswordResetData, r *http.Request) error

	// OnExistingUserSignUp is called when a sign-up is attempted with an email
	// that already exists (only fires when RequireEmailVerification or AutoSignIn=false).
	// Runtime: wired:auth/api/routes/sign_up.go:69.
	OnExistingUserSignUp func(data ExistingUserSignUpData) error

	// OnExistingUserSignUpRequest mirrors upstream's
	// onExistingUserSignUp(data, request?) signature. When set, it takes
	// precedence over OnExistingUserSignUp; routes invoke it with the
	// rebuilt request.
	// Runtime: wired:auth/api/routes/sign_up.go (duplicate-sign-up path,
	// request-aware precedence; Wave 10 verified).
	OnExistingUserSignUpRequest func(data ExistingUserSignUpData, r *http.Request) error

	// CustomSyntheticUser customizes the synthetic user returned when duplicate
	// sign-up enumeration protection is active.
	// Runtime: wired:auth/api/routes/sign_up.go:85.
	CustomSyntheticUser func(data SyntheticUserData) map[string]any
}

// Validate reports types-level email/password misconfiguration (negative
// TTLs, inverted password-length bounds). Pure: no I/O and no callers
// outside package types (called by ValidateOptions).
func (o EmailAndPasswordOptions) Validate() error {
	if o.MinPasswordLength < 0 {
		return fmt.Errorf("auth: options.EmailAndPassword.MinPasswordLength must not be negative, got %d", o.MinPasswordLength)
	}
	if o.MaxPasswordLength < 0 {
		return fmt.Errorf("auth: options.EmailAndPassword.MaxPasswordLength must not be negative, got %d", o.MaxPasswordLength)
	}
	if o.MaxPasswordLength > 0 && o.MinPasswordLength > o.MaxPasswordLength {
		return fmt.Errorf("auth: options.EmailAndPassword.MinPasswordLength (%d) exceeds MaxPasswordLength (%d)", o.MinPasswordLength, o.MaxPasswordLength)
	}
	if o.ResetPasswordTokenExpiresIn < 0 {
		return fmt.Errorf("auth: options.EmailAndPassword.ResetPasswordTokenExpiresIn must not be negative, got %d", o.ResetPasswordTokenExpiresIn)
	}
	return nil
}

// EmailVerificationOptions mirrors better-auth's emailVerification config block
type EmailVerificationOptions struct {
	// SendVerificationEmail delivers the verification link to the user.
	// Runtime: wired:auth/api/routes/sign_up.go:154 (sign-up delivery) and
	// auth/api/routes/sign_in.go:93 (sign-in resend).
	SendVerificationEmail func(data VerificationEmailData) error

	// SendVerificationEmailRequest mirrors upstream's
	// sendVerificationEmail(data, request?) signature. When set, it takes
	// precedence over SendVerificationEmail; current routes invoke it with
	// the rebuilt request.
	// Runtime: wired:auth/api/routes/email_verification.go + account.go.
	SendVerificationEmailRequest func(data VerificationEmailData, r *http.Request) error

	// Automatically send a verification email after sign-up.
	// Tri-state mirroring upstream `sendOnSignUp?: boolean`: nil (unset) follows
	// EmailAndPassword.RequireEmailVerification; non-nil true sends
	// unconditionally and non-nil false never sends. Resolve with
	// ResolveSendOnSignUp.
	// Runtime: wired:auth/api/routes/sign_up.go:142.
	SendOnSignUp *bool

	// Send a verification email on sign-in when the user's email is not verified.
	// Runtime: wired:auth/api/routes/sign_in.go:82.
	SendOnSignIn bool

	// Automatically sign in the user after they verify their email.
	// Runtime: wired:auth/api/routes/email_verification.go:397.
	AutoSignInAfterVerification bool

	// TTL of the verification token in seconds. Default 3600.
	// Runtime: wired:auth/api/routes/email_verification.go:120.
	ExpiresIn int

	// BeforeEmailVerification is called before the email is marked verified.
	// Runtime: wired:auth/api/routes/verify_email_parity_test.go:96
	// (exercised via the verify-email flow; see
	// auth/api/routes/email_verification.go).
	BeforeEmailVerification func(user *User) error

	// BeforeEmailVerificationRequest mirrors upstream's
	// beforeEmailVerification(user, request?) signature. When set, it takes
	// precedence over BeforeEmailVerification; current routes invoke it with
	// the rebuilt request.
	// Runtime: wired:auth/api/routes/email_verification.go (verify gate).
	BeforeEmailVerificationRequest func(user *User, r *http.Request) error

	// AfterEmailVerification is called after the email is marked verified.
	// Runtime: wired:auth/api/routes/verify_email_parity_test.go:100
	// (exercised via the verify-email flow; see
	// auth/api/routes/email_verification.go).
	AfterEmailVerification func(user *User) error

	// AfterEmailVerificationRequest mirrors upstream's
	// afterEmailVerification(user, request?) signature. When set, it takes
	// precedence over AfterEmailVerification; current routes invoke it with
	// the rebuilt request.
	// Runtime: wired:auth/api/routes/email_verification.go (post-verify hook).
	AfterEmailVerificationRequest func(user *User, r *http.Request) error
}

// Validate reports types-level email-verification misconfiguration
// (negative token TTL). Pure: no I/O and no callers outside package types
// (called by ValidateOptions).
func (o EmailVerificationOptions) Validate() error {
	if o.ExpiresIn < 0 {
		return fmt.Errorf("auth: options.EmailVerification.ExpiresIn must not be negative, got %d", o.ExpiresIn)
	}
	return nil
}

// ResolveSendOnSignUp resolves the effective send-on-sign-up flag, mirroring
// upstream `sendOnSignUp ?? requireEmailVerification` (sign-up.ts:392-394):
// a non-nil explicit value wins (even false); nil (unset) falls back to
// requireVerification. Pure: no I/O.
func ResolveSendOnSignUp(sendOnSignUp *bool, requireVerification bool) bool {
	if sendOnSignUp != nil {
		return *sendOnSignUp
	}
	return requireVerification
}

// SessionCookieCacheStrategy selects the session cookie-cache encoding.
// Mirrors better-auth's session.cookieCache.strategy value
type SessionCookieCacheStrategy string

const (
	// SessionCookieCacheCompact uses base64url encoding with an HMAC-SHA256
	// signature. Upstream default (documented).
	// Runtime: wired:auth/cookies/session_cache.go:45 (compact build/verify).
	SessionCookieCacheCompact SessionCookieCacheStrategy = "compact"
	// SessionCookieCacheJWT uses JWT with an HMAC signature (no encryption).
	// Runtime: wired:auth/api/routes/session.go (strategy switch) +
	// auth/cookies/session_jwt.go (Create/VerifySessionCacheJWT codec).
	SessionCookieCacheJWT SessionCookieCacheStrategy = "jwt"
	// SessionCookieCacheJWE uses JWE (JSON Web Encryption) with
	// A256CBC-HS512 and HKDF key derivation.
	// Runtime: wired:auth/api/routes/session.go (strategy switch) +
	// auth/cookies/session_jwt.go (Encrypt/DecryptSessionCacheJWE codec).
	SessionCookieCacheJWE SessionCookieCacheStrategy = "jwe"
)

// SessionCookieCacheShouldRefresh mirrors the upstream cookie-cache
// refreshCache `shouldRefresh` function form: it decides per session/user
// whether the stateless cache should refresh before expiry. The pinned
// upstream type only carries `boolean |
// { updateAge }` while its own doc comment advertises an updateAge-or-
// shouldRefresh object; this hook is preserved for that advertised form and
// is consulted by the cookie-cache refresh path.
// Runtime: wired:auth/api/routes/session.go (refreshSessionIfNeeded + maybeRefreshCookieCache).
type SessionCookieCacheShouldRefresh func(session Session, user User) bool

// SessionCookieCacheRefresh controls stateless cookie-cache refresh before
// expiry (without querying the database). Mirrors better-auth's
// session.cookieCache.refreshCache value:
// false disables automatic refresh; Enabled refreshes when UpdateAge
// seconds of lifetime remain (upstream default: 20% of maxAge).
// Runtime: wired:auth/api/routes/session.go (refreshSessionIfNeeded + maybeRefreshCookieCache).
type SessionCookieCacheRefresh struct {
	// Enabled refreshes the cache before expiry. False (zero value)
	// disables automatic refresh.
	// Runtime: wired:auth/api/routes/session.go (refreshSessionIfNeeded + maybeRefreshCookieCache).
	Enabled bool
	// UpdateAge is the seconds-before-expiry refresh threshold (0 = 20% of
	// maxAge upstream default).
	// Runtime: wired:auth/api/routes/session.go (refreshSessionIfNeeded + maybeRefreshCookieCache).
	UpdateAge int
	// ShouldRefresh optionally decides per session/user whether to refresh.
	// See the type doc for the pinned-upstream caveat.
	// Runtime: wired:auth/api/routes/session.go (refreshSessionIfNeeded + maybeRefreshCookieCache).
	ShouldRefresh SessionCookieCacheShouldRefresh
}

// SessionCookieCacheVersionFunc mirrors better-auth's
// session.cookieCache.version function form:
// it derives the cache version from the session and user so rotating it
// invalidates existing caches. Upstream also allows an async function;
// Go is sync (return an error instead of a rejected promise). When set it
// takes precedence over the static Version string.
// Runtime: wired:auth/api/routes/session.go (cache-version resolution).
type SessionCookieCacheVersionFunc func(session Session, user User) (string, error)

// SessionCookieCacheOptions mirrors the supported subset of better-auth's
// session.cookieCache config.
type SessionCookieCacheOptions struct {
	// Enable caching session+user payloads in a signed cookie.
	// Runtime: wired:auth/api/routes/session.go:71 (read path) and :487
	// (write path).
	Enabled bool

	// MaxAge controls the cache cookie lifetime in seconds. Default 300.
	// Runtime: wired:auth/api/routes/session.go:437 (expiry assembly).
	MaxAge int

	// Strategy selects the cookie-cache encoding.
	// Upstream default (documented, behavior unchanged here): "compact".
	// All three strategies have Go codecs (compact in
	// auth/cookies/session_cache.go, jwt/jwe in auth/cookies/session_jwt.go);
	// the custom-JWKS signer path owned by the JWT plugin still fails closed
	// to the database.
	// Runtime: wired:auth/api/routes/session.go (strategy switch) +
	// auth/cookies/session_cache.go (compact codec).
	Strategy SessionCookieCacheStrategy

	// RefreshCache controls stateless refresh before expiry.
	// Runtime: wired:auth/api/routes/session.go (refreshSessionIfNeeded + maybeRefreshCookieCache).
	RefreshCache SessionCookieCacheRefresh

	// Version invalidates existing caches when changed.
	// Upstream default (documented): "1". VersionFunc takes precedence when
	// set.
	// Runtime: wired:auth/api/routes/session.go (cache-version resolution).
	Version string

	// VersionFunc derives the cache version per session/user, mirroring
	// upstream's function version form. When set it takes precedence over
	// Version.
	// Runtime: wired:auth/api/routes/session.go (cache-version resolution).
	VersionFunc SessionCookieCacheVersionFunc
}

// SessionQueryOptions mirrors the per-request get-session query knobs in
// upstream session.ts: disableCookieCache forces an authoritative
// server-side read (bypassing the signed cookie cache) and disableRefresh
// skips the session-refresh write for that request. Both only ever make
// validation stricter. The Go get-session path does not accept these query
// params yet; this type pins the contract for future wiring.
// Runtime: wired:auth/api/routes/session.go (query knobs + authoritative read) (get-session read path).
type SessionQueryOptions struct {
	// DisableCookieCache forces an authoritative server-side session read.
	// Runtime: wired:auth/api/routes/session.go (query knobs + authoritative read).
	DisableCookieCache bool
	// DisableRefresh skips the session-refresh write for the request.
	// Runtime: wired:auth/api/routes/session.go (query knobs + authoritative read).
	DisableRefresh bool
}

// SessionPersistenceOptions mirrors upstream's remember-me persistence
// knob: sign-up/sign-in accept `rememberMe?: boolean`
// (sign-up.ts:24, sign-in.ts:436); `rememberMe === false` sets the
// `dontRememberToken` cookie and creates a session that is never refreshed
// (session.ts:124-127,309-323; createSession(userId, dontRememberMe?) in
// context.ts:154-162). The behavior is wired end to end: sign-up/sign-in
// accept the RememberMe body field and mint non-persistent sessions via
// creationSessionExpiry + issueSessionCookies, and get-session skips refresh
// writes for dontRememberMe sessions. This struct pins the persistence half
// of that contract (it is not itself taken as a parameter).
// Runtime: wired:auth/api/routes/sign_up.go + sign_in.go (RememberMe mint)
// and auth/api/routes/session.go (refresh-skip).
type SessionPersistenceOptions struct {
	// DontRememberMe marks the session as non-persistent: no refresh writes
	// and no persistent cookie lifetime. Upstream sets this when
	// `rememberMe === false`.
	// Runtime: wired:auth/api/routes/session.go (refresh-skip + cookie
	// lifetime).
	DontRememberMe bool
}

// SessionOptions mirrors better-auth's session config block
type SessionOptions struct {
	// Model customizes the session table name, column mapping, and
	// additional fields. Mirrors better-auth's
	// BetterAuthDBOptions<"session", ...> spread into options.session.
	// Runtime: wired:auth/index.go:295 (ResolveSchema merge).
	Model DBModelOptions

	// How long a session lives in seconds. Default 604800 (7 days).
	// Runtime: wired:auth/api/routes/session.go:366 (expiry assembly).
	ExpiresIn int

	// How often the session expiry is refreshed on use, in seconds.
	// Tri-state mirroring upstream `session.updateAge?: number` (default 1 day): nil (unset) defaults to 86400;
	// explicit 0 refreshes on every use (always-refresh); >0 is seconds.
	// Resolve with ResolveUpdateAgeSeconds / UpdateAgeDuration.
	// Runtime: wired:auth/api/routes/session.go:392 (sessionUpdateAge).
	UpdateAge *int

	// DisableSessionRefresh disables session refresh regardless of
	// UpdateAge. Upstream default (documented, behavior unchanged here):
	// false. It suppresses the refresh write alongside the per-request
	// disableRefresh query knob (upstream session.ts:309).
	// Runtime: wired:auth/api/routes/session.go (refresh write path).
	DisableSessionRefresh bool

	// DeferSessionRefresh defers session refresh writes to POST requests;
	// GET becomes read-only. Useful for read-replica database setups.
	// Upstream default (documented, behavior unchanged here): false. POST
	// without deferral enabled surfaces
	// METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED upstream.
	// Runtime: wired:auth/api/routes/session.go (get-session read path:
	// deferred GET reads set NeedsRefresh instead of writing).
	// Runtime: wired:auth/api/routes/session.go (get-session read path).
	DeferSessionRefresh bool

	// FreshAge limits how old a session may be for sensitive flows when the
	// route requires a fresh session and no password re-check is supplied.
	// nil defaults to 86400 (1 day). An explicit 0 disables the freshness check.
	// Runtime: wired:auth/api/routes/account.go:412 (freshness gate).
	FreshAge *int

	// StoreSessionInDatabase mirrors upstream storeSessionInDatabase
	// with secondary storage configured, sessions
	// persist in both stores and reads fall back to the database.
	// Runtime: wired:auth/api/routes/session.go (dual-write/fallback) +
	// auth/index.go (startup gate requires a backend when set).
	StoreSessionInDatabase bool

	// PreserveSessionInDatabase mirrors upstream preserveSessionInDatabase
	// with StoreSessionInDatabase, session rows
	// survive secondary eviction (ended, not deleted).
	// Runtime: wired:auth/api/routes/session.go (sign-out/delete paths) +
	// auth/index.go (startup gate requires a backend when set).
	PreserveSessionInDatabase bool

	// CookieCache configures signed session caching in a secondary cookie
	// (upstream cookieCache). See per-field owners in
	// SessionCookieCacheOptions.
	// Runtime: wired:auth/api/routes/session.go:71 (read path).
	CookieCache SessionCookieCacheOptions
}

// Validate reports types-level session misconfiguration (negative
// lifetimes). Pure: no I/O and no callers outside package types (called by
// ValidateOptions). An explicit FreshAge of 0 is valid (disables the
// freshness check); only negative values are rejected.
func (o SessionOptions) Validate() error {
	if o.ExpiresIn < 0 {
		return fmt.Errorf("auth: options.Session.ExpiresIn must not be negative, got %d", o.ExpiresIn)
	}
	if o.UpdateAge != nil && *o.UpdateAge < 0 {
		return fmt.Errorf("auth: options.Session.UpdateAge must not be negative, got %d", *o.UpdateAge)
	}
	if o.FreshAge != nil && *o.FreshAge < 0 {
		return fmt.Errorf("auth: options.Session.FreshAge must not be negative, got %d", *o.FreshAge)
	}
	if o.CookieCache.MaxAge < 0 {
		return fmt.Errorf("auth: options.Session.CookieCache.MaxAge must not be negative, got %d", o.CookieCache.MaxAge)
	}
	if o.CookieCache.RefreshCache.UpdateAge < 0 {
		return fmt.Errorf("auth: options.Session.CookieCache.RefreshCache.UpdateAge must not be negative, got %d", o.CookieCache.RefreshCache.UpdateAge)
	}
	return nil
}

// DefaultSessionUpdateAgeSeconds is the default session refresh interval in
// seconds (1 day, 86400), mirroring upstream sessionConfig.updateAge
// (create-context.ts: `options.session?.updateAge !== undefined ? value :
// 24*60*60`).
const DefaultSessionUpdateAgeSeconds = 24 * 60 * 60

// ResolveUpdateAgeSeconds resolves SessionOptions.UpdateAge to seconds,
// mirroring upstream create-context.ts: nil (unset) yields the 24h default;
// an explicit value (including 0 for always-refresh) is returned as-is.
// Pure: no I/O.
func ResolveUpdateAgeSeconds(updateAge *int) int {
	if updateAge == nil {
		return DefaultSessionUpdateAgeSeconds
	}
	return *updateAge
}

// UpdateAgeDuration returns the resolved UpdateAge as a time.Duration: nil
// defaults to 24h; explicit 0 yields 0 (always-refresh: the refresh
// threshold equals the session creation time, so every use is due);
// >0 is seconds. Pure: no I/O.
func (s SessionOptions) UpdateAgeDuration() time.Duration {
	return time.Duration(ResolveUpdateAgeSeconds(s.UpdateAge)) * time.Second
}

// ExpiresInDuration returns ExpiresIn as a time.Duration (defaults to 7 days).
func (s SessionOptions) ExpiresInDuration() time.Duration {
	if s.ExpiresIn == 0 {
		return 7 * 24 * time.Hour
	}
	return time.Duration(s.ExpiresIn) * time.Second
}

// FreshAgeDuration returns the configured FreshAge and whether the freshness
// check is enabled. nil defaults to 1 day; explicit 0 disables the check.
func (s SessionOptions) FreshAgeDuration() (time.Duration, bool) {
	if s.FreshAge == nil {
		return 24 * time.Hour, true
	}
	if *s.FreshAge == 0 {
		return 0, false
	}
	return time.Duration(*s.FreshAge) * time.Second, true
}

// CookieCacheMaxAgeDuration returns CookieCache.MaxAge as a time.Duration
// (defaults to 5 minutes).
func (s SessionOptions) CookieCacheMaxAgeDuration() time.Duration {
	if s.CookieCache.MaxAge == 0 {
		return 5 * time.Minute
	}
	return time.Duration(s.CookieCache.MaxAge) * time.Second
}
