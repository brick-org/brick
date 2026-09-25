package types

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"
)

// OAuthProvider is implemented by built-in and custom social auth providers.
type OAuthProvider interface {
	ID() string
	Name() string
	CreateAuthorizationURL(params AuthorizationURLParams) (string, error)
	ExchangeCode(params CodeExchangeParams) (*OAuthTokens, error)
	GetUserInfo(tokens *OAuthTokens) (*OAuthUserInfo, error)
}

// AuthorizationURLParams holds parameters for building an OAuth authorization URL.
type AuthorizationURLParams struct {
	State        string
	CodeVerifier string
	RedirectURI  string
	Scopes       []string // extra scopes beyond provider defaults
}

// CodeExchangeParams holds parameters for the authorization code → token exchange.
type CodeExchangeParams struct {
	Code         string
	CodeVerifier string
	RedirectURI  string
}

// OAuthTokens holds the tokens returned after a successful code exchange.
type OAuthTokens struct {
	AccessToken           string
	RefreshToken          string
	IDToken               string
	Scope                 string
	AccessTokenExpiresAt  *time.Time
	RefreshTokenExpiresAt *time.Time
}

// OAuthUserInfo is the normalized user profile returned by a provider.
type OAuthUserInfo struct {
	ID            string
	Name          string
	Email         string
	Image         string
	EmailVerified bool
}

// The OAuthProvider interface above is intentionally small and stays fixed
// so existing providers keep compiling. The optional interfaces and config
// structs below mirror the wider upstream OAuthProvider/ProviderOptions
// surface without breaking it: routes probe for them with type assertions
// (the same pattern as the refreshableProvider in api/routes).
//
// The following upstream surface is expressible as types in this file
// (each marked `Runtime: wired:<owner>` where auth/oauth2 or
// auth/social-providers now enforces it, `pending:<owner>` where route
// call-sites are still missing; no network I/O lives here):
//   - JWKS-based ID-token signature verification (OAuthIDTokenConfig,
//     JWKSOptions; upstream idToken.jwks, verifyIdToken, verifyClaims).
//   - OIDC nonce enforcement (IDTokenNonceOptions, NonceStore; upstream
//     requiresIdTokenNonce / idTokenNonce round-trip through OAuth state).
//   - ID-token sign-in gating (IDTokenSignInDisabler; upstream
//     disableIdTokenSignIn) and custom verifiers (VerifyIDTokenFunc).
//   - Stable account subjects (AccountSubjectFunc/AccountSubjectProvider,
//     resolved from the raw verified profile, never the mapped user).
//   - Authorization-server mix-up defense (IssuerProvider, upstream issuer
//     check on the callback `iss` parameter, RFC 9207).
//   - IdP-initiated flows (AllowIDPInitiatedProvider, upstream
//     allowIdpInitiated) and custom callbackPath mounting
//     (CallbackPathProvider).
//   - Provider-specific options (GoogleProviderOptions, GithubProviderOptions,
//     AppleProviderOptions, DiscordProviderOptions, MicrosoftProviderOptions
//     with upstream PascalCase field names).

// OAuthRefreshContext carries request metadata to provider refresh hooks.
// The refresh flow may be triggered by endpoints such as /get-access-token
// or /refresh-token; hooks that do not need request-scoped data can ignore
// it. Mirrors better-auth's OAuthRefreshContext.
type OAuthRefreshContext struct {
	Request *http.Request
	Headers http.Header
}

// RefreshableProvider is optionally implemented by OAuth providers that can
// exchange a refresh token for a new access token. It mirrors the
// refreshableProvider probed by api/routes: providers without it serve
// stored tokens and report that refreshing is unsupported.
type RefreshableProvider interface {
	RefreshAccessToken(refreshToken string) (*OAuthTokens, error)
}

// RefreshableProviderWithContext is optionally implemented by providers
// whose refresh call needs request metadata (mirrors upstream's
// refreshAccessToken(refreshToken, ctx?) signature). Routes prefer this
// shape when available and fall back to RefreshableProvider otherwise.
type RefreshableProviderWithContext interface {
	RefreshAccessTokenWithContext(refreshToken string, ctx OAuthRefreshContext) (*OAuthTokens, error)
}

// TokenRevoker is optionally implemented by providers that can revoke a
// token at the provider. Mirrors upstream's revokeToken hook.
type TokenRevoker interface {
	RevokeToken(token string) error
}

// EndSessionParams carries the inputs for an OpenID Connect RP-Initiated
// Logout URL. Mirrors upstream's createEndSessionURL data argument.
type EndSessionParams struct {
	IDToken               *string
	PostLogoutRedirectURI string
	State                 string
}

// EndSessionProvider is optionally implemented by providers that can build
// an OpenID Connect RP-Initiated Logout URL. An empty URL with a nil error
// reports that provider logout is unavailable or disabled (mirrors upstream
// returning null).
type EndSessionProvider interface {
	CreateEndSessionURL(params EndSessionParams) (string, error)
}

// TokenEndpointAuthMethod selects the client authentication method used at
// the provider token endpoint.
type TokenEndpointAuthMethod string

const (
	// TokenEndpointAuthClientSecretBasic authenticates with HTTP Basic auth
	// (client_id:client_secret).
	TokenEndpointAuthClientSecretBasic TokenEndpointAuthMethod = "client_secret_basic"
	// TokenEndpointAuthClientSecretPost authenticates with credentials in
	// the POST body.
	TokenEndpointAuthClientSecretPost TokenEndpointAuthMethod = "client_secret_post"
	// TokenEndpointAuthNone sends no client secret (public clients, PKCE).
	TokenEndpointAuthNone TokenEndpointAuthMethod = "none"
)

// TokenEndpointAuth describes how the provider authenticates at its token
// endpoint. Mirrors the per-provider tokenEndpointAuth used upstream (e.g.
// TikTok, Reddit).
//
// Upstream: core/src/oauth2/token-endpoint-auth.ts
// (TokenEndpointAuth).
//
// Intentional exclusion (W10-01): legacy helper shape with zero runtime
// effect; method selection flows through the TokenAuth/ClientAssertion
// fields and TokenAuthConfig instead. Preserved as a compat alias.
// Runtime: excluded(W10-01):legacy-alias.
type TokenEndpointAuth struct {
	Method       TokenEndpointAuthMethod
	ClientID     string
	ClientSecret string
	ClientKey    string
	// Authentication selects basic vs post secret transport (upstream
	// TokenEndpointSecretAuthentication). Empty selects the runtime
	// default (post when a secret is set, none otherwise).
	Authentication TokenEndpointSecretAuthentication
	// GetClientAssertion signs RFC 7523 assertions for private_key_jwt.
	GetClientAssertion ClientAssertionFunc
}

// OIDCDiscoveryOptions configures OpenID Connect Discovery for a provider.
// Types only; the Go runtime does not perform discovery or fetch remote
// metadata yet — providers use statically configured endpoints.
type OIDCDiscoveryOptions struct {
	// Issuer is the expected issuer identifier (RFC 9207). When set,
	// callbacks should validate the `iss` query parameter against it.
	Issuer string
	// DiscoveryURL is the issuer's .well-known/openid-configuration URL.
	DiscoveryURL string
	// JWKSURL serves the provider's JSON Web Key Set for ID-token checks.
	JWKSURL string
	// RequireNonce binds ID-token verification to an authorization-request
	// nonce. Mirrors upstream's requiresIdTokenNonce.
	RequireNonce bool
}

// IDTokenVerifyConfig is the declarative ID-token verification config for a
// provider. Mirrors upstream's idToken config consumed by the shared
// verifyProviderIdToken verifier. Types only; the Go runtime does not
// verify ID-token signatures yet.
type IDTokenVerifyConfig struct {
	Issuer   []string
	Audience []string
	JWKSURL  string
	// MaxAge bounds the token age (e.g. Google's "1h"). Zero means unset.
	MaxAge string
}

// MapProfileToUserFunc maps a raw provider profile to mutable local-user
// attributes. The provider identity itself is owned by the account subject,
// not by this mapping (mirrors upstream's OAuthMappedUser contract, which
// forbids `id`). Types only; concrete providers map profiles internally.
type MapProfileToUserFunc func(raw map[string]any, tokens *OAuthTokens) map[string]any

// ProfileMappingProvider is optionally implemented by providers that expose
// their raw-profile-to-user mapping for reuse (e.g. synthetic users).
type ProfileMappingProvider interface {
	MapProfileToUser(raw map[string]any, tokens *OAuthTokens) map[string]any
}

// OAuthProviderConfig captures the common upstream ProviderOptions knobs in
// one portable struct so custom providers and generic-OAuth constructors can
// accept them without breaking the OAuthProvider interface. Fields mirror
// upstream names and defaults; the Go runtime consumes them only where the
// concrete provider implementation supports them.
type OAuthProviderConfig struct {
	ClientID     string
	ClientSecret string
	// ClientKey replaces ClientID for providers that use a key instead
	// (e.g. TikTok upstream).
	ClientKey string
	// Scopes are requested in addition to provider defaults. Empty combined
	// with DisableDefaultScope requests no scopes.
	Scopes []string
	// DisableDefaultScope drops the provider's default scopes.
	DisableDefaultScope bool
	// RedirectURI overrides the computed callback URI.
	RedirectURI string
	// AuthorizationEndpoint overrides the provider's authorization endpoint
	// (useful for testing or sandbox environments).
	AuthorizationEndpoint string
	// TokenEndpoint overrides the provider's token endpoint.
	TokenEndpoint string
	// UserInfoURL overrides the provider's userinfo endpoint.
	UserInfoURL string
	// TokenAuth selects the token-endpoint auth method.
	TokenAuth TokenEndpointAuthMethod
	// Discovery configures OIDC discovery. Types only; not performed yet.
	Discovery OIDCDiscoveryOptions
	// IDToken configures declarative ID-token verification. Types only; not
	// verified yet.
	IDToken IDTokenVerifyConfig
	// Prompt is the authorization prompt (e.g. "consent", "select_account").
	Prompt string
	// ResponseMode is the authorization response mode ("query" or
	// "form_post").
	ResponseMode string
	// DisableSignUp blocks new-user sign-up through this provider.
	DisableSignUp bool
	// DisableImplicitSignUp requires an explicit sign-up request for new
	// users through this provider.
	DisableImplicitSignUp bool
	// OverrideUserInfoOnSignIn replaces the stored user info with the
	// provider profile on sign-in. Upstream default: false.
	OverrideUserInfoOnSignIn bool
	// RequireEmailVerification gates session creation until the provider
	// reports a verified email (user/account rows are still created).
	// Upstream default: false. Only enable for providers with a trustworthy
	// email_verified signal.
	RequireEmailVerification bool
	// DisableIDTokenSignIn blocks ID-token sign-in for this provider.
	DisableIDTokenSignIn bool
	// MapProfileToUser customizes the raw-profile-to-user mapping.
	MapProfileToUser MapProfileToUserFunc
	// Issuer is the expected authorization-server issuer (RFC 9207
	// mix-up defense). Mirrors upstream's provider issuer field.
	Issuer string
	// VerifyIDToken overrides ID-token verification for this provider.
	// Mirrors upstream's ProviderOptions verifyIdToken.
	VerifyIDToken VerifyIDTokenFunc
	// GetUserInfo overrides user-info resolution for this provider.
	// Mirrors upstream's ProviderOptions getUserInfo.
	GetUserInfo GetUserInfoHookFunc
	// AccountSubject resolves the stable provider subject from the raw
	// verified profile. Mirrors upstream's provider accountSubject.
	AccountSubject AccountSubjectFunc
	// CallbackPath mounts this provider's OAuth callback handler under a
	// custom path (must start with "/"). Mirrors upstream's provider
	// callbackPath; providers using the shared `/callback/<id>` route omit
	// it.
	CallbackPath string
	// AllowIDPInitiated accepts callbacks arriving without a `state`
	// parameter for providers that initiate OAuth without RP-side flow
	// kickoff. Mirrors upstream's provider allowIdpInitiated.
	AllowIDPInitiated bool
	// ClientAssertion returns an RFC 7523 client assertion for token
	// endpoint authentication instead of a client secret. Mirrors
	// upstream's private_key_jwt getClientAssertion (e.g. Microsoft
	// clientAssertion).
	ClientAssertion ClientAssertionFunc
}

// ---------------------------------------------------------------------------
// Optional OAuth capability surface: nonce comparison, JWKS verification,
// ID-token config, token-auth selection, discovery/routing hooks, profile
// mapping hooks, provider-specific option bags, and pure helpers.
// ---------------------------------------------------------------------------

// IDTokenNonceComparison selects how an ID-token `nonce` claim is compared
// to the expected nonce recovered from OAuth state.
//
// (OAuthIdTokenConfig nonceComparison).
//
// Runtime: wired:auth/oauth2 (VerifyIDTokenNonceClaim enforces it).
type IDTokenNonceComparison string

const (
	// IDTokenNonceExact requires strict equality (upstream default).
	IDTokenNonceExact IDTokenNonceComparison = "exact"
	// IDTokenNonceExactOrSHA256 also accepts the hex SHA-256 of the
	// expected nonce (Apple behavior).
	IDTokenNonceExactOrSHA256 IDTokenNonceComparison = "exact-or-sha256"
)

// VerifyClaimsFunc is a provider-specific claim check applied after the
// signature, issuer, audience, max-age, and nonce checks pass. Return false
// to reject the token (e.g. Google's hosted-domain `hd` restriction).
//
// (OAuthIdTokenConfig verifyClaims).
//
// Runtime: wired:auth/oauth2 (VerifyIDTokenWithConfig enforces it;
// idtoken_config.go claim gate).
type VerifyClaimsFunc func(claims map[string]any) bool

// VerifyIDTokenFunc verifies a client-submitted ID token. It covers both
// the integrator `verifyIdToken` override on provider options and the
// custom `verify` branch of OAuthIdTokenConfig used by providers that
// verify against a remote endpoint instead of a local JWKS (e.g. LINE).
//
// (OAuthIdTokenConfig verify branch) and oauth-provider.ts:344-350
// (ProviderOptions verifyIdToken).
//
// Runtime: wired:auth/oauth2 (VerifyIDTokenWithConfig custom-verifier branch;
// idtoken_config.go; overlaid from provider options by social-providers).
type VerifyIDTokenFunc func(token, nonce string) (bool, error)

// DefaultJWKSCacheTTL bounds how long a fetched JWKS is trusted before it
// is refetched.
//
// (JWKS_CACHE_TTL_MS = 5 * 60 * 1000).
//
// Runtime: wired:auth/oauth2 (default behind JWKSOptions.EffectiveCacheTTL,
// consumed by the JWKS fetch cache in idtoken_config.go).
const DefaultJWKSCacheTTL = 5 * time.Minute

// DefaultJWKSNoKidRefetchCooldown bounds how often a kid-less verification
// failure retries against a freshly fetched JWKS.
//
// (JWKS_NO_KID_REFETCH_COOLDOWN_MS = 30 * 1000).
//
// Runtime: wired:auth/oauth2 (kid-miss refetch cooldown in idtoken_config.go).
const DefaultJWKSNoKidRefetchCooldown = 30 * time.Second

// DefaultIDTokenMaxAge is the maximum ID-token age accepted by the Google,
// Apple, and Microsoft providers.
//
// apple.ts:134, and microsoft-entra-id.ts:232 (each "1h").
//
// Runtime: wired:social-providers (default MaxTokenAge in the Google ID-token
// config built by bags.go).
const DefaultIDTokenMaxAge = "1h"

// JWKSOptions configures JSON Web Key Set resolution for ID-token
// signature verification: the remote set URL, cache TTL, permitted
// algorithms (alg pin), and optional inline static keys.
//
// (JwksFetchOptions) with TTL from verify.ts:77.
//
// Runtime: wired:auth/oauth2 (idtoken_config.go: cached fetch with TTL + kid-miss refetch).
type JWKSOptions struct {
	// URL serves the provider's JSON Web Key Set (upstream jwksFetch).
	URL string
	// CacheTTL bounds how long a fetched set is trusted. Zero selects
	// DefaultJWKSCacheTTL via EffectiveCacheTTL.
	CacheTTL time.Duration
	// Algorithms pins the permitted JWS algorithms. Empty accepts the
	// token's alg for the supported families.
	Algorithms []string
	// StaticKeys holds inline public JWKs (decoded JSON maps) used
	// instead of fetching URL when non-empty (tests, pinned keys).
	StaticKeys []map[string]any
}

// EffectiveCacheTTL reports the JWKS cache TTL, defaulting to
// DefaultJWKSCacheTTL when unset. Pure helper; no I/O.
//
// Runtime: wired:auth/oauth2 (JWKS fetch cache in idtoken_config.go).
func (o JWKSOptions) EffectiveCacheTTL() time.Duration {
	if o.CacheTTL > 0 {
		return o.CacheTTL
	}
	return DefaultJWKSCacheTTL
}

// JWKSCacheKey builds the stable cache key a JWKS set is stored under: the
// fetch URL scoped by provider ID, so a token is only ever matched against
// the key set published by its own source. Pure helper; no I/O.
//
// (cache scoped to the jwksFetch source string).
//
// Runtime: wired:auth/oauth2 (JWKS fetch cache key in idtoken_config.go).
func JWKSCacheKey(providerID, jwksURL string) string {
	if providerID == "" {
		return jwksURL
	}
	return providerID + "|" + jwksURL
}

// OAuthIDTokenConfig is the declarative ID-token verification config for a
// provider, mirroring upstream's OAuthIdTokenConfig JWKS branch. When
// Verify is set, the JWKS branch is skipped and Verify performs remote
// verification instead (the `verify` branch).
//
// (OAuthIdTokenConfig).
//
// Runtime: wired:auth/oauth2 (VerifyIDTokenWithConfig is the verification
// entry point; shared routes pass the provider's declared config via the
// IDTokenConfigProvider probe in api/routes/social.go).
type OAuthIDTokenConfig struct {
	// JWKS resolves the JWS verification keys.
	JWKS JWKSOptions
	// Issuer lists accepted `iss` values. Empty skips the issuer check
	// (providers whose issuer varies per tenant).
	Issuer []string
	// Audience lists accepted `aud` values (usually the client ID).
	Audience []string
	// MaxTokenAge bounds the token age (e.g. "1h"). Empty disables it.
	MaxTokenAge string
	// NonceComparison selects nonce matching strictness.
	NonceComparison IDTokenNonceComparison
	// AllowOpaqueToken accepts non-JWS (opaque) tokens without signature
	// verification; identity is then resolved via the provider userinfo
	// endpoint (e.g. Facebook Graph access tokens).
	AllowOpaqueToken bool
	// VerifyClaims enforces provider-specific constraints on the verified
	// payload (e.g. Google's hosted-domain `hd` restriction).
	VerifyClaims VerifyClaimsFunc
	// Verify is a custom remote verifier (e.g. LINE). When set, the JWKS
	// branch above is not used.
	Verify VerifyIDTokenFunc
}

// UsesCustomVerifier reports whether ID-token verification delegates to the
// custom Verify hook instead of the JWKS branch. Pure helper.
//
// (`"verify" in config` branch).
//
// Runtime: wired:auth/oauth2 (custom-verifier branch in
// VerifyIDTokenWithConfig).
func (c OAuthIDTokenConfig) UsesCustomVerifier() bool {
	return c.Verify != nil
}

// IDTokenConfigProvider is optionally implemented by providers that declare
// their ID-token verification config instead of verifying ad hoc, keeping
// verification centralized and fail-closed.
//
// Runtime: wired:auth/api/routes (probed by verifyIDTokenForProvider in
// social.go; verified via oauth2.VerifyIDTokenWithConfig).
type IDTokenConfigProvider interface {
	IDTokenConfig() OAuthIDTokenConfig
}

// NonceStore persists OIDC nonces between the authorization redirect and
// the callback so ID-token verification can bind the token to the request
// that minted it. TakeNonce must delete on read (single use).
//
// Upstream: the idTokenNonce round-trip through OAuth state, declared in
// core/src/oauth2/oauth-provider.ts
// (createAuthorizationURL idTokenNonce) and consumed as expectedIdTokenNonce
// in oauth-provider.ts:193-199.
//
// Runtime: wired:auth/oauth2 (PersistNonce/TakeExpectedNonce/ResolveExpectedNonce
// in nonce.go; routes resolve the expected nonce from state via
// ResolveExpectedNonce and enforce it via RequireNonceBinding).
type NonceStore interface {
	StoreNonce(key, nonce string, ttl time.Duration) error
	TakeNonce(key string) (string, error)
}

// IDTokenNonceOptions configures OIDC nonce enforcement for a provider.
//
// (requiresIdTokenNonce).
//
// Runtime: wired:auth/api/routes (nonceOptionsFor in social.go resolves the
// full options when exposed, else the boolean requirement).
type IDTokenNonceOptions struct {
	// Required binds ID-token verification to an authorization-request
	// nonce (upstream requiresIdTokenNonce).
	Required bool
	// MaxAge bounds the nonce lifetime. Zero means the runtime default.
	MaxAge time.Duration
	// Comparison selects nonce matching strictness.
	Comparison IDTokenNonceComparison
	// Store persists nonces across the redirect. Nil selects the runtime
	// default state persistence.
	Store NonceStore
}

// RequiresIDTokenNonceProvider is optionally implemented by providers that
// require shared OAuth redirect routes to bind ID-token verification to an
// authorization-request nonce.
//
// (requiresIdTokenNonce).
//
// Runtime: wired:auth/api/routes (probed by nonceOptionsFor in social.go).
type RequiresIDTokenNonceProvider interface {
	RequiresIDTokenNonce() bool
}

// IDTokenNonceOptionsProvider is optionally implemented by providers that
// expose their full nonce enforcement config.
//
// Runtime: wired:auth/api/routes (probed by nonceOptionsFor in social.go).
type IDTokenNonceOptionsProvider interface {
	IDTokenNonceOptions() IDTokenNonceOptions
}

// IsValidNonceString reports whether nonce has a plausible OIDC nonce
// shape: 8-512 chars from the OAuth random-string alphabet. It guards
// storage and lookup, never acceptance: verification compares exact values
// via MatchIDTokenNonce. Pure helper; no I/O.
//
// Runtime: wired:auth/oauth2 (AttachIDTokenNonce/PersistNonce guards in
// nonce.go).
func IsValidNonceString(nonce string) bool {
	if len(nonce) < 8 || len(nonce) > 512 {
		return false
	}
	for i := 0; i < len(nonce); i++ {
		c := nonce[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' {
			continue
		}
		return false
	}
	return true
}

// MatchIDTokenNonce reports whether the claim nonce satisfies the expected
// value: strict equality, or additionally the hex SHA-256 of the expected
// nonce for the exact-or-sha256 comparison (Apple). Pure helper; no I/O.
//
// (nonceMatches).
//
// Runtime: wired:auth/oauth2 (same contract as NonceMatches; this copy keeps types dependency-free).
func MatchIDTokenNonce(claimNonce, expected string, comparison IDTokenNonceComparison) bool {
	if claimNonce == "" || expected == "" {
		return claimNonce == expected
	}
	if claimNonce == expected {
		return true
	}
	if comparison == IDTokenNonceExactOrSHA256 {
		sum := sha256.Sum256([]byte(expected))
		return claimNonce == hex.EncodeToString(sum[:])
	}
	return false
}

// TokenEndpointAuthPrivateKeyJWT authenticates with an RFC 7523 client
// assertion JWT instead of a client secret.
//
// (TokenEndpointAuth private_key_jwt branch).
//
// Runtime: wired:auth/oauth2 (private_key_jwt branch in ApplyTokenEndpointAuthEx).
const TokenEndpointAuthPrivateKeyJWT TokenEndpointAuthMethod = "private_key_jwt"

// TokenEndpointAuthCustom delegates token-request authentication to a
// provider hook. There is no Go hook surface for it yet; the constant
// reserves the wire value.
//
// (TokenEndpointAuth custom branch).
//
// Runtime: wired:auth/oauth2 (mapped in baseProvider.TokenEndpointAuthMethod;
// provider.go; the custom hook itself runs via TokenEndpointRequestHook in
// ApplyTokenEndpointAuthEx).
const TokenEndpointAuthCustom TokenEndpointAuthMethod = "custom"

// TokenEndpointSecretAuthentication selects the legacy secret transport:
// HTTP Basic auth or POST body credentials.
//
// (TokenEndpointSecretAuthentication).
//
// Runtime: wired:auth/oauth2 (TokenAuthConfig.SecretAuthentication selects
// basic vs post when no explicit Method is set).
type TokenEndpointSecretAuthentication string

const (
	// TokenEndpointSecretBasic sends credentials via HTTP Basic auth.
	TokenEndpointSecretBasic TokenEndpointSecretAuthentication = "basic"
	// TokenEndpointSecretPost sends credentials in the POST body.
	TokenEndpointSecretPost TokenEndpointSecretAuthentication = "post"
)

// ClientAssertionType is the fixed assertion-type URN sent alongside every
// private_key_jwt client assertion.
//
// (CLIENT_ASSERTION_TYPE).
//
// Runtime: wired:auth/oauth2 (client_assertion_type body parameter in
// token_auth.go).
const ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// ClientAssertionContext carries the inputs a client-assertion signer needs.
//
// (ClientAssertionContext).
//
// Runtime: wired:auth/oauth2 (built by ApplyTokenEndpointAuthEx and passed
// to GetClientAssertion in token_auth.go).
type ClientAssertionContext struct {
	ClientID      string
	TokenEndpoint string
	GrantType     string
}

// ClientAssertionFunc signs an RFC 7523 client assertion JWT for the given
// context (iss=sub=clientID, aud=tokenEndpoint). The assertion type is
// always ClientAssertionType.
//
// (ClientAssertionGetter) with signing in client-assertion.ts:116-164.
//
// Runtime: wired:auth/oauth2 (fed into TokenAuthConfig.GetClientAssertion by
// baseProvider exchange paths in provider.go).
type ClientAssertionFunc func(ctx ClientAssertionContext) (string, error)

// ClientAssertionProvider is optionally implemented by providers that
// authenticate at the token endpoint with private_key_jwt assertions
// (e.g. Microsoft workload identity federation).
//
// Intentional exclusion (W10-01): no in-tree provider implements it;
// assertion flows use the OAuthProviderConfig.ClientAssertion func instead.
// Preserved as a compat interface.
// Runtime: excluded(W10-01):legacy-alias.
type ClientAssertionProvider interface {
	GetClientAssertion(ctx ClientAssertionContext) (string, error)
}

// TokenAuthMethodProvider is optionally implemented by providers that pin
// their token-endpoint authentication method.
//
// Intentional exclusion (W10-01): advertisement-only; method selection
// flows through config. Preserved as a compat interface.
// Runtime: excluded(W10-01):legacy-alias.
type TokenAuthMethodProvider interface {
	TokenEndpointAuthMethod() TokenEndpointAuthMethod
}

// DiscoveryProvider is optionally implemented by providers that expose
// their OIDC discovery config for routes that resolve endpoints dynamically.
//
// Intentional exclusion (W10-01): hints only; providers use statically
// configured endpoints (the Go deployment model). Preserved as a compat
// interface.
// Runtime: excluded(W10-01):legacy-alias.
type DiscoveryProvider interface {
	OIDCDiscoveryOptions() OIDCDiscoveryOptions
}

// IssuerProvider is optionally implemented by providers with a fixed
// authorization-server issuer so callbacks can validate the `iss` query
// parameter (RFC 9207 mix-up defense).
//
// (OAuthProvider issuer).
//
// Runtime: wired:auth/api/routes (ValidateCallbackIssuer enforces it at the
// shared callback in social.go; providers without it skip the check).
type IssuerProvider interface {
	Issuer() string
}

// CallbackPathProvider is optionally implemented by providers that mount
// their OAuth callback handler under a custom path (must start with "/").
// Providers using the shared `/callback/<id>` route omit this.
//
// (OAuthProvider callbackPath).
//
// Runtime: wired:auth/api/routes (OAuthCallbackPath in social.go probes it;
// shared `/callback/<id>` when unset).
type CallbackPathProvider interface {
	CallbackPath() string
}

// AllowIDPInitiatedProvider is optionally implemented by providers that
// accept callbacks arriving without a `state` parameter because they
// initiate OAuth without RP-side flow kickoff.
//
// (OAuthProvider allowIdpInitiated).
//
// Runtime: wired:auth/api/routes (allowsIdPInitiated/bounceIdPInitiated in
// social.go mint fresh state + PKCE for stateless arrivals).
type AllowIDPInitiatedProvider interface {
	AllowIDPInitiated() bool
}

// IDTokenSignInDisabler is optionally implemented by providers that block
// ID-token sign-in (upstream disableIdTokenSignIn, default false).
//
// (ProviderOptions disableIdTokenSignIn) gated by supportsIdTokenSignIn in
// core/src/oauth2/verify-id-token.ts.
//
// Runtime: wired:social-providers (SupportsIDTokenSignIn gates the
// client-submitted id_token path at POST /sign-in/social in social.go).
type IDTokenSignInDisabler interface {
	DisableIDTokenSignIn() bool
}

// DisableSignUpProvider is optionally implemented by providers that block
// new-user sign-up through this provider (upstream disableSignUp, default
// false). The shared sign-in completion refuses to create a user row when
// set, redirecting with signup_disabled (callback) or 401 OAUTH_LINK_ERROR
// (id_token branch).
//
// (OAuthProvider disableSignUp) and ProviderOptions disableSignUp
// (oauth-provider.ts:379-382), consumed as
// `(provider.disableImplicitSignUp && !requestSignUp) ||
// provider.options?.disableSignUp` in callback.ts:381-383 and
// sign-in.ts:342-344.
//
// Runtime: wired:auth/api/routes (probed by completeSocialLogin in
// social.go for new users).
type DisableSignUpProvider interface {
	DisableSignUp() bool
}

// DisableImplicitSignUpProvider is optionally implemented by providers that
// require an explicit sign-up request for new users (upstream
// disableImplicitSignUp, default false). New users are refused unless the
// flow carried requestSignUp=true (persisted in OAuth state from the
// sign-in body).
//
// (OAuthProvider disableImplicitSignUp) and ProviderOptions
// disableImplicitSignUp (oauth-provider.ts:374-378).
//
// Runtime: wired:auth/api/routes (probed by completeSocialLogin in
// social.go for new users together with the state requestSignUp flag).
type DisableImplicitSignUpProvider interface {
	DisableImplicitSignUp() bool
}

// OverrideUserInfoProvider is optionally implemented by providers whose
// profile overwrites the stored user on every sign-in (upstream
// overrideUserInfoOnSignIn, default false). When set, re-sign-in updates
// name/image/email/emailVerified from the provider profile; otherwise the
// stored row stands.
//
// (ProviderOptions overrideUserInfoOnSignIn), consumed as overrideUserInfo
// in link-account.ts:323-371.
//
// Runtime: wired:auth/api/routes (probed by completeSocialLogin in
// social.go for pre-existing users).
type OverrideUserInfoProvider interface {
	OverrideUserInfoOnSignIn() bool
}

// RequireEmailVerificationProvider is optionally implemented by providers
// that gate session creation until the provider reports a verified email
// (upstream requireEmailVerification, default false). The user and account
// rows are still created/linked, but no session is issued: the callback
// redirects with error=email_not_verified and id-token sign-in returns 403
// EMAIL_NOT_VERIFIED. The gate reads the local user's verification state,
// not the provider claim on each request.
//
// (ProviderOptions requireEmailVerification), enforced in
// link-account.ts:460-492.
//
// Runtime: wired:auth/api/routes (probed by completeSocialLogin in
// social.go before session issuance; verification-email resend stays open
// for the email-verification owner).
type RequireEmailVerificationProvider interface {
	RequireEmailVerification() bool
}

// RequestAwareIDTokenVerifier is optionally implemented by providers whose
// ID-token verification needs the originating request (headers, tenant,
// logging), mirroring upstream's verifyIdToken(token, nonce, ctx) override
// and the verify(token, nonce, ctx) branch of OAuthIdTokenConfig
// (oauth-provider.ts:58-62, verify-id-token.ts:73-82). The frozen
// VerifyIDTokenFunc (token, nonce) cannot carry the request, so this
// additive shape carries it explicitly. A nil request means no request was
// available (e.g. the huma callback path); verifiers must tolerate nil like
// upstream's optional ctx.
//
// Runtime: wired:auth/api/routes (probed first by verifyIDTokenForProvider
// in social.go; wins over the static config hook so routes can thread
// request-scoped data into remote verification).
type RequestAwareIDTokenVerifier interface {
	VerifyIDTokenWithRequest(token, nonce string, req *http.Request) (bool, error)
}

// AccountSubjectFunc resolves the stable provider subject used to build an
// OAuth account key. It must read the raw, provider-verified profile (for
// OpenID Connect providers, the `sub` claim) and never derive identity from
// the mapped local user.
//
// (OAuthProvider accountSubject) with context in oauth-provider.ts:97-100.
//
// Runtime: wired:auth/api/routes (accepted on OAuthProviderConfig, stored
// on bag caps, and resolved per sign-in/link seam via
// oauth2.ResolveAccountSubject with the userinfo-ID fallback in social.go).
type AccountSubjectFunc func(raw map[string]any, tokens *OAuthTokens) string

// AccountSubjectProvider is optionally implemented by providers that expose
// their stable-subject resolver for reuse (e.g. synthetic users, account
// linking).
//
// Runtime: wired:auth/api/routes (probed per sign-in/link seam via
// oauth2.ResolveAccountSubject in social.go; invalid subjects fail closed,
// unconfigured resolvers fall back to the resolved userinfo ID).
type AccountSubjectProvider interface {
	AccountSubject(raw map[string]any, tokens *OAuthTokens) string
}

// GetUserInfoHookFunc overrides user-info resolution for a provider.
//
// (ProviderOptions getUserInfo).
//
// Runtime: wired:social-providers (bag GetUserInfo hook overrides resolution
// in the *WithProviderOptions constructors in bags.go).
type GetUserInfoHookFunc func(tokens *OAuthTokens) (*OAuthUserInfo, error)

// PrimaryClientID returns the provider's primary client ID: the first
// non-empty entry. Upstream accepts a single string or an array whose index
// 0 is the primary (used for token-endpoint auth and ID-token audience
// verification); later entries are additional accepted audiences. Pure
// helper; no I/O.
//
// (getPrimaryClientId).
//
// Intentional exclusion (W10-01): single-string client IDs (upstream index
// 0); credential resolution is internal to each constructor. Preserved as a
// compat helper.
// Runtime: excluded(W10-01):legacy-alias.
func PrimaryClientID(clientIDs ...string) string {
	for _, id := range clientIDs {
		if id != "" {
			return id
		}
	}
	return ""
}

// GoogleIssuers lists the accepted Google ID-token issuers.
//
// and google.ts:224.
//
// Runtime: wired:social-providers (accepted issuers in the Google ID-token
// config built by bags.go).
var GoogleIssuers = []string{"https://accounts.google.com", "accounts.google.com"}

// GoogleJWKSURL serves Google's public signing keys.
//
//
// Runtime: wired:social-providers (JWKS URL in the Google ID-token config
// built by bags.go).
const GoogleJWKSURL = "https://www.googleapis.com/oauth2/v3/certs"

// GoogleDefaultScopes are requested unless disabled.
//
//
// Runtime: wired:social-providers (default scopes in GoogleWithProviderOptions
// via resolveScopes in bags.go).
var GoogleDefaultScopes = []string{"email", "profile", "openid"}

// GoogleProviderOptions mirrors upstream GoogleOptions with PascalCase
// field names. It embeds OAuthProviderConfig for the common ProviderOptions
// knobs (ClientID, ClientSecret, Scope, DisableDefaultScope, RedirectURI,
// AuthorizationEndpoint, Prompt, MapProfileToUser, ...).
//
// Runtime: wired:social-providers (GoogleWithProviderOptions in bags.go
// consumes the full bag: credentials, scopes, AccessType, Display, Hd,
// IncludeGrantedScopes, IDToken, Nonce, and every OAuthProviderConfig hook).
type GoogleProviderOptions struct {
	OAuthProviderConfig
	// AccessType is the authorization access type ("offline" or "online").
	AccessType string
	// Display is the authorization display mode ("page", "popup", "touch",
	// or "wap").
	Display string
	// Hd is the hosted-domain (Google Workspace) restriction. It is sent
	// as the `hd` authorization hint and enforced against the verified
	// `hd` claim; "*" requires any Workspace domain.
	Hd string
	// IncludeGrantedScopes sends include_granted_scopes=true for
	// incremental auth. Nil (default) means true.
	IncludeGrantedScopes *bool
	// IDToken declares Google's JWKS verification config (upstream
	// google.ts:221-235).
	IDToken OAuthIDTokenConfig
	// Nonce configures OIDC nonce enforcement for this provider.
	Nonce IDTokenNonceOptions
}

// EffectiveIncludeGrantedScopes reports whether incremental auth scopes are
// requested. Nil defaults to true (upstream default). Pure helper.
//
//
// Runtime: wired:social-providers (include_granted_scopes parameter in
// GoogleWithProviderOptions).
func (o GoogleProviderOptions) EffectiveIncludeGrantedScopes() bool {
	if o.IncludeGrantedScopes == nil {
		return true
	}
	return *o.IncludeGrantedScopes
}

// IsGoogleHostedDomainAllowed reports whether the verified `hd` claim
// satisfies the configured hosted-domain restriction. "*" accepts any
// Workspace hosted domain. Pure helper; no I/O.
//
// (isGoogleHostedDomainAllowed).
//
// Runtime: wired:social-providers (hd claim enforcement in
// GoogleWithProviderOptions).
func IsGoogleHostedDomainAllowed(configuredHostedDomain string, tokenHostedDomain any) bool {
	if configuredHostedDomain == "" {
		return true
	}
	hd, ok := tokenHostedDomain.(string)
	if !ok || hd == "" {
		return false
	}
	if configuredHostedDomain == "*" {
		return true
	}
	return hd == configuredHostedDomain
}

// GithubDefaultScopes are requested unless disabled.
//
//
// Runtime: wired:social-providers (default scopes in GitHubWithProviderOptions
// via resolveScopes in bags.go).
var GithubDefaultScopes = []string{"read:user", "user:email"}

// GithubProviderOptions mirrors upstream GithubOptions: ClientID is
// required; every other knob lives in the embedded OAuthProviderConfig.
// GitHub has no ID-token surface upstream.
//
// Runtime: wired:social-providers (GitHubWithProviderOptions in bags.go
// consumes credentials, scopes, and every OAuthProviderConfig hook).
type GithubProviderOptions struct {
	OAuthProviderConfig
}

// AppleIssuer is the fixed Apple ID-token issuer.
//
//
// Runtime: wired:social-providers (issuer in the Apple ID-token config built
// by bags.go).
const AppleIssuer = "https://appleid.apple.com"

// AppleJWKSURL serves Apple's public signing keys.
//
//
// Runtime: wired:social-providers (JWKS URL in the Apple ID-token config
// built by bags.go).
const AppleJWKSURL = "https://appleid.apple.com/auth/keys"

// AppleDefaultScopes are requested unless disabled.
//
//
// Runtime: wired:social-providers (default scopes in AppleWithProviderOptions
// via resolveScopes in bags.go).
var AppleDefaultScopes = []string{"email", "name"}

// AppleProviderOptions mirrors upstream AppleOptions with PascalCase field
// names. It embeds OAuthProviderConfig for the common ProviderOptions knobs.
//
// Runtime: wired:social-providers (AppleWithProviderOptions in bags.go
// consumes the full bag: credentials, scopes, AppBundleIdentifier, Audience,
// IDToken with exact-or-sha256 nonce comparison, Nonce, and every
// OAuthProviderConfig hook).
type AppleProviderOptions struct {
	OAuthProviderConfig
	// AppBundleIdentifier, when set, is the ID-token audience instead of
	// the client ID (native-app bundle).
	AppBundleIdentifier string
	// Audience lists additional accepted ID-token audiences.
	Audience []string
	// IDToken declares Apple's JWKS verification config with
	// exact-or-sha256 nonce comparison.
	IDToken OAuthIDTokenConfig
	// Nonce configures OIDC nonce enforcement for this provider.
	Nonce IDTokenNonceOptions
}

// EffectiveAudience resolves the accepted ID-token audiences: explicit
// Audience first, then the app bundle identifier, then the client ID.
// Pure helper; no I/O.
//
//
// Runtime: wired:social-providers (audience resolution in
// AppleWithProviderOptions via EffectiveAudience).
func (o AppleProviderOptions) EffectiveAudience(clientID string) []string {
	return ResolveAppleAudience(clientID, o.AppBundleIdentifier, o.Audience)
}

// ResolveAppleAudience resolves Apple ID-token audiences with the same
// precedence as the provider: explicit audience, app bundle identifier,
// client ID. Pure helper; no I/O.
//
//
// Runtime: wired:social-providers (via EffectiveAudience in
// AppleWithProviderOptions; no direct external callers).
func ResolveAppleAudience(clientID, appBundleIdentifier string, audience []string) []string {
	if len(audience) > 0 {
		return audience
	}
	if appBundleIdentifier != "" {
		return []string{appBundleIdentifier}
	}
	return []string{clientID}
}

// DiscordDefaultScopes are requested unless disabled.
//
//
// Runtime: wired:social-providers (default scopes in DiscordWithProviderOptions
// via resolveScopes in bags.go).
var DiscordDefaultScopes = []string{"identify", "email"}

// DiscordDefaultPrompt is sent when no prompt is configured.
//
// (options.prompt || "none").
//
// Runtime: wired:social-providers (via EffectivePrompt in
// DiscordWithProviderOptions; no direct external callers).
const DiscordDefaultPrompt = "none"

// DiscordProviderOptions mirrors upstream DiscordOptions with PascalCase
// field names. It embeds OAuthProviderConfig for the common ProviderOptions
// knobs. Discord has no ID-token surface upstream.
//
// Runtime: wired:social-providers (DiscordWithProviderOptions in bags.go
// consumes credentials, scopes, Prompt, Permissions, and every
// OAuthProviderConfig hook).
type DiscordProviderOptions struct {
	OAuthProviderConfig
	// Prompt is the authorization prompt ("none" or "consent").
	Prompt string
	// Permissions is sent as the `permissions` parameter when the bot
	// scope is requested. Nil means unset.
	Permissions *int
}

// EffectivePrompt reports the authorization prompt, defaulting to "none".
// Pure helper.
//
//
// Runtime: wired:social-providers (authorization prompt in
// DiscordWithProviderOptions).
func (o DiscordProviderOptions) EffectivePrompt() string {
	if o.Prompt == "" {
		return DiscordDefaultPrompt
	}
	return o.Prompt
}

// MicrosoftDefaultTenant is used when no tenant is configured.
//
// (tenantId default) and microsoft-entra-id.ts:164.
//
// Runtime: wired:social-providers (via EffectiveTenant in
// MicrosoftWithProviderOptions; no direct external callers).
const MicrosoftDefaultTenant = "common"

// MicrosoftDefaultAuthority is the default Entra ID authority.
//
// (authority default) and microsoft-entra-id.ts:169.
//
// Runtime: wired:social-providers (via EffectiveAuthority in
// MicrosoftWithProviderOptions; no direct external callers).
const MicrosoftDefaultAuthority = "https://login.microsoftonline.com"

// MicrosoftDefaultProfilePhotoSize is the default Graph profile photo size.
//
// (profilePhotoSize default) and microsoft-entra-id.ts:287.
//
// Runtime: wired:social-providers (via EffectiveProfilePhotoSize in
// MicrosoftWithProviderOptions; no direct external callers).
const MicrosoftDefaultProfilePhotoSize = 48

// MicrosoftConsumerTenantID is the fixed tenant ID carried as the `tid`
// claim by every personal (consumer) Microsoft account token.
//
//
// Runtime: wired:social-providers (consumer-tenant `tid` check in bags.go).
const MicrosoftConsumerTenantID = "9188040d-6c67-4c5b-b112-36a304b66dad"

// MicrosoftDefaultScopes are requested unless disabled.
//
//
// Runtime: wired:social-providers (default scopes in
// MicrosoftWithProviderOptions via resolveScopes in bags.go).
var MicrosoftDefaultScopes = []string{"openid", "profile", "email", "User.Read", "offline_access"}

// MicrosoftProviderOptions mirrors upstream MicrosoftOptions with PascalCase
// field names. It embeds OAuthProviderConfig for the common ProviderOptions
// knobs.
//
// Runtime: wired:social-providers (MicrosoftWithProviderOptions in bags.go
// consumes the full bag: TenantID, Authority, ProfilePhotoSize,
// DisableProfilePhoto, ClientAssertion, IDToken, Nonce, and every
// OAuthProviderConfig hook).
type MicrosoftProviderOptions struct {
	OAuthProviderConfig
	// TenantID selects the Entra tenant ("common", "organizations",
	// "consumers", or a tenant GUID). Default "common".
	TenantID string
	// Authority is the authentication authority URL (CIAM scenarios use
	// https://<tenant-id>.ciamlogin.com). Default MicrosoftDefaultAuthority.
	Authority string
	// ProfilePhotoSize selects the Graph profile-photo size. Zero selects
	// MicrosoftDefaultProfilePhotoSize.
	ProfilePhotoSize int
	// DisableProfilePhoto skips the Graph photo fetch.
	DisableProfilePhoto bool
	// ClientAssertion returns an RFC 7523 assertion for token endpoint
	// authentication (private_key_jwt / workload identity federation).
	// It cannot be combined with a client secret.
	ClientAssertion ClientAssertionFunc
	// IDToken declares Microsoft's JWKS verification config with
	// tenant-bound issuer/claim checks.
	IDToken OAuthIDTokenConfig
	// Nonce configures OIDC nonce enforcement for this provider.
	Nonce IDTokenNonceOptions
}

// EffectiveTenant reports the Entra tenant, defaulting to "common". Pure
// helper.
//
//
// Runtime: wired:social-providers (tenant routing in
// MicrosoftWithProviderOptions).
func (o MicrosoftProviderOptions) EffectiveTenant() string {
	if o.TenantID == "" {
		return MicrosoftDefaultTenant
	}
	return o.TenantID
}

// EffectiveAuthority reports the authority URL with trailing slashes
// trimmed so endpoint URLs and the issuer comparison never produce a double
// slash. Pure helper.
//
//
// Runtime: wired:social-providers (authority routing in
// MicrosoftWithProviderOptions).
func (o MicrosoftProviderOptions) EffectiveAuthority() string {
	authority := o.Authority
	if authority == "" {
		authority = MicrosoftDefaultAuthority
	}
	for len(authority) > 0 && strings.HasSuffix(authority, "/") {
		authority = authority[:len(authority)-1]
	}
	return authority
}

// EffectiveProfilePhotoSize reports the Graph photo size, defaulting to 48.
// Pure helper.
//
//
// Runtime: wired:social-providers (Graph photo fetch in
// MicrosoftWithProviderOptions).
func (o MicrosoftProviderOptions) EffectiveProfilePhotoSize() int {
	if o.ProfilePhotoSize == 0 {
		return MicrosoftDefaultProfilePhotoSize
	}
	return o.ProfilePhotoSize
}

// MicrosoftIssuer returns the expected ID-token issuer for an authority and
// tenant. Multi-tenant endpoints (common/organizations/consumers) skip the
// issuer check upstream because the issuer varies per tenant, so this
// returns "" for them and the tenant-bound issuer otherwise. Pure helper;
// no I/O.
//
//
// Runtime: wired:social-providers (tenant-bound issuer check in bags.go).
func MicrosoftIssuer(authority, tenant string) string {
	switch tenant {
	case "", MicrosoftDefaultTenant, "organizations", "consumers":
		return ""
	default:
		return authority + "/" + tenant + "/v2.0"
	}
}

// MicrosoftJWKSURL returns the JWKS URL for an authority and tenant. Pure
// helper; no I/O.
//
// (`${authority}/${tenant}/discovery/v2.0/keys`).
//
// Runtime: wired:social-providers (JWKS URL in the Microsoft ID-token config
// built by bags.go).
func MicrosoftJWKSURL(authority, tenant string) string {
	return authority + "/" + tenant + "/discovery/v2.0/keys"
}
