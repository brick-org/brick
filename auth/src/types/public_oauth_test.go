package types

import (
	"testing"
	"time"
)

// oauthBareStub implements only the minimal OAuthProvider surface: it must
// keep compiling and must NOT satisfy any optional capability interface.
type oauthBareStub struct{}

func (oauthBareStub) ID() string   { return "bare" }
func (oauthBareStub) Name() string { return "Bare" }
func (oauthBareStub) CreateAuthorizationURL(params AuthorizationURLParams) (string, error) {
	return "https://example.com/authorize?state=" + params.State, nil
}
func (oauthBareStub) ExchangeCode(params CodeExchangeParams) (*OAuthTokens, error) {
	return &OAuthTokens{AccessToken: "access:" + params.Code}, nil
}
func (oauthBareStub) GetUserInfo(tokens *OAuthTokens) (*OAuthUserInfo, error) {
	return &OAuthUserInfo{ID: "user-1"}, nil
}

// oauthCapStub implements the full new capability surface on top of the
// bare provider.
type oauthCapStub struct{ oauthBareStub }

func (oauthCapStub) RequiresIDTokenNonce() bool { return true }
func (oauthCapStub) IDTokenNonceOptions() IDTokenNonceOptions {
	return IDTokenNonceOptions{Required: true, Comparison: IDTokenNonceExact}
}
func (oauthCapStub) IDTokenConfig() OAuthIDTokenConfig {
	return OAuthIDTokenConfig{Audience: []string{"client-id"}}
}
func (oauthCapStub) TokenEndpointAuthMethod() TokenEndpointAuthMethod {
	return TokenEndpointAuthPrivateKeyJWT
}
func (oauthCapStub) GetClientAssertion(ctx ClientAssertionContext) (string, error) {
	return "assertion-for:" + ctx.ClientID, nil
}
func (oauthCapStub) OIDCDiscoveryOptions() OIDCDiscoveryOptions {
	return OIDCDiscoveryOptions{Issuer: "https://example.com"}
}
func (oauthCapStub) Issuer() string             { return "https://example.com" }
func (oauthCapStub) CallbackPath() string       { return "/callback/stub" }
func (oauthCapStub) AllowIDPInitiated() bool    { return false }
func (oauthCapStub) DisableIDTokenSignIn() bool { return false }
func (oauthCapStub) AccountSubject(raw map[string]any, tokens *OAuthTokens) string {
	if sub, ok := raw["sub"].(string); ok {
		return sub
	}
	return ""
}

// Compile-time shape assertions for the new capability interfaces.
var (
	_ RequiresIDTokenNonceProvider = oauthCapStub{}
	_ IDTokenNonceOptionsProvider  = oauthCapStub{}
	_ IDTokenConfigProvider        = oauthCapStub{}
	_ TokenAuthMethodProvider      = oauthCapStub{}
	_ ClientAssertionProvider      = oauthCapStub{}
	_ DiscoveryProvider            = oauthCapStub{}
	_ IssuerProvider               = oauthCapStub{}
	_ CallbackPathProvider         = oauthCapStub{}
	_ AllowIDPInitiatedProvider    = oauthCapStub{}
	_ IDTokenSignInDisabler        = oauthCapStub{}
	_ AccountSubjectProvider       = oauthCapStub{}
	_ NonceStore                   = (*memNonceStore)(nil)
)

// memNonceStore is a test-only NonceStore.
type memNonceStore struct{ kept map[string]string }

func (m *memNonceStore) StoreNonce(key, nonce string, ttl time.Duration) error {
	if m.kept == nil {
		m.kept = map[string]string{}
	}
	m.kept[key] = nonce
	return nil
}

func (m *memNonceStore) TakeNonce(key string) (string, error) {
	nonce := m.kept[key]
	delete(m.kept, key)
	return nonce, nil
}

func TestOAuthProviderShapeStaysBackwardCompatible(t *testing.T) {
	var core OAuthProvider = oauthBareStub{}
	if core.ID() != "bare" {
		t.Fatalf("bare provider ID = %q", core.ID())
	}
	// Every new capability must remain optional: a minimal provider keeps
	// compiling without implementing any of them.
	optional := []struct {
		name string
		ok   bool
	}{
		{"RequiresIDTokenNonceProvider", isRequiresIDTokenNonceProvider(core)},
		{"IDTokenNonceOptionsProvider", isIDTokenNonceOptionsProvider(core)},
		{"IDTokenConfigProvider", isIDTokenConfigProvider(core)},
		{"TokenAuthMethodProvider", isTokenAuthMethodProvider(core)},
		{"ClientAssertionProvider", isClientAssertionProvider(core)},
		{"DiscoveryProvider", isDiscoveryProvider(core)},
		{"IssuerProvider", isIssuerProvider(core)},
		{"CallbackPathProvider", isCallbackPathProvider(core)},
		{"AllowIDPInitiatedProvider", isAllowIDPInitiatedProvider(core)},
		{"IDTokenSignInDisabler", isIDTokenSignInDisabler(core)},
		{"AccountSubjectProvider", isAccountSubjectProvider(core)},
	}
	for _, c := range optional {
		if c.ok {
			t.Errorf("bare provider must not satisfy %s", c.name)
		}
	}

	var full OAuthProvider = oauthCapStub{}
	checks := []struct {
		name string
		ok   bool
	}{
		{"RequiresIDTokenNonceProvider", isRequiresIDTokenNonceProvider(full)},
		{"IDTokenNonceOptionsProvider", isIDTokenNonceOptionsProvider(full)},
		{"IDTokenConfigProvider", isIDTokenConfigProvider(full)},
		{"TokenAuthMethodProvider", isTokenAuthMethodProvider(full)},
		{"ClientAssertionProvider", isClientAssertionProvider(full)},
		{"DiscoveryProvider", isDiscoveryProvider(full)},
		{"IssuerProvider", isIssuerProvider(full)},
		{"CallbackPathProvider", isCallbackPathProvider(full)},
		{"AllowIDPInitiatedProvider", isAllowIDPInitiatedProvider(full)},
		{"IDTokenSignInDisabler", isIDTokenSignInDisabler(full)},
		{"AccountSubjectProvider", isAccountSubjectProvider(full)},
	}
	for _, c := range checks {
		if !c.ok {
			t.Errorf("capability stub should satisfy %s", c.name)
		}
	}
	if got := full.(AccountSubjectProvider).AccountSubject(map[string]any{"sub": "s-1"}, nil); got != "s-1" {
		t.Errorf("AccountSubject = %q, want %q", got, "s-1")
	}
}

func isRequiresIDTokenNonceProvider(p OAuthProvider) bool {
	_, ok := p.(RequiresIDTokenNonceProvider)
	return ok
}

func isIDTokenNonceOptionsProvider(p OAuthProvider) bool {
	_, ok := p.(IDTokenNonceOptionsProvider)
	return ok
}

func isIDTokenConfigProvider(p OAuthProvider) bool {
	_, ok := p.(IDTokenConfigProvider)
	return ok
}

func isTokenAuthMethodProvider(p OAuthProvider) bool {
	_, ok := p.(TokenAuthMethodProvider)
	return ok
}

func isClientAssertionProvider(p OAuthProvider) bool {
	_, ok := p.(ClientAssertionProvider)
	return ok
}

func isDiscoveryProvider(p OAuthProvider) bool {
	_, ok := p.(DiscoveryProvider)
	return ok
}

func isIssuerProvider(p OAuthProvider) bool {
	_, ok := p.(IssuerProvider)
	return ok
}

func isCallbackPathProvider(p OAuthProvider) bool {
	_, ok := p.(CallbackPathProvider)
	return ok
}

func isAllowIDPInitiatedProvider(p OAuthProvider) bool {
	_, ok := p.(AllowIDPInitiatedProvider)
	return ok
}

func isIDTokenSignInDisabler(p OAuthProvider) bool {
	_, ok := p.(IDTokenSignInDisabler)
	return ok
}

func isAccountSubjectProvider(p OAuthProvider) bool {
	_, ok := p.(AccountSubjectProvider)
	return ok
}

func TestOAuthOptionDefaultsPreserveBehavior(t *testing.T) {
	var cfg OAuthProviderConfig
	if cfg.VerifyIDToken != nil || cfg.GetUserInfo != nil || cfg.AccountSubject != nil {
		t.Error("zero OAuthProviderConfig should leave hooks nil")
	}
	if cfg.ClientAssertion != nil {
		t.Error("zero OAuthProviderConfig should leave ClientAssertion nil")
	}
	if cfg.CallbackPath != "" || cfg.AllowIDPInitiated || cfg.Issuer != "" {
		t.Error("zero OAuthProviderConfig should leave routing fields unset")
	}

	var idCfg OAuthIDTokenConfig
	if idCfg.UsesCustomVerifier() {
		t.Error("zero OAuthIDTokenConfig must use the JWKS branch")
	}
	withVerify := OAuthIDTokenConfig{Verify: func(token, nonce string) (bool, error) { return true, nil }}
	if !withVerify.UsesCustomVerifier() {
		t.Error("OAuthIDTokenConfig with Verify must use the custom branch")
	}

	var jwks JWKSOptions
	if jwks.EffectiveCacheTTL() != DefaultJWKSCacheTTL {
		t.Errorf("zero JWKSOptions TTL = %v, want default %v", jwks.EffectiveCacheTTL(), DefaultJWKSCacheTTL)
	}
	custom := JWKSOptions{CacheTTL: time.Minute}
	if custom.EffectiveCacheTTL() != time.Minute {
		t.Errorf("custom JWKSOptions TTL = %v, want 1m", custom.EffectiveCacheTTL())
	}

	var nonce IDTokenNonceOptions
	if nonce.Required || nonce.Store != nil || nonce.MaxAge != 0 {
		t.Error("zero IDTokenNonceOptions should leave enforcement off")
	}
}

func TestPublicOAuthDefaultConstants(t *testing.T) {
	if DefaultJWKSCacheTTL != 5*time.Minute {
		t.Errorf("DefaultJWKSCacheTTL = %v", DefaultJWKSCacheTTL)
	}
	if DefaultJWKSNoKidRefetchCooldown != 30*time.Second {
		t.Errorf("DefaultJWKSNoKidRefetchCooldown = %v", DefaultJWKSNoKidRefetchCooldown)
	}
	if DefaultIDTokenMaxAge != "1h" {
		t.Errorf("DefaultIDTokenMaxAge = %q", DefaultIDTokenMaxAge)
	}
	if ClientAssertionType != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Errorf("ClientAssertionType = %q", ClientAssertionType)
	}
	methods := map[TokenEndpointAuthMethod]bool{
		TokenEndpointAuthClientSecretBasic: true,
		TokenEndpointAuthClientSecretPost:  true,
		TokenEndpointAuthNone:              true,
		TokenEndpointAuthPrivateKeyJWT:     true,
		TokenEndpointAuthCustom:            true,
	}
	if len(methods) != 5 {
		t.Error("token-endpoint auth methods must cover basic/post/none/private_key_jwt/custom")
	}
	if TokenEndpointAuthPrivateKeyJWT != "private_key_jwt" || TokenEndpointAuthCustom != "custom" {
		t.Error("private_key_jwt/custom wire values changed")
	}
	if TokenEndpointSecretBasic != "basic" || TokenEndpointSecretPost != "post" {
		t.Error("secret transport values changed")
	}
	if IDTokenNonceExact != "exact" || IDTokenNonceExactOrSHA256 != "exact-or-sha256" {
		t.Error("nonce comparison values changed")
	}
}

func TestJWKSCacheKey(t *testing.T) {
	a := JWKSCacheKey("google", GoogleJWKSURL)
	b := JWKSCacheKey("google", GoogleJWKSURL)
	if a != b || a == "" {
		t.Errorf("JWKSCacheKey not deterministic: %q vs %q", a, b)
	}
	if JWKSCacheKey("google", GoogleJWKSURL) == JWKSCacheKey("apple", GoogleJWKSURL) {
		t.Error("JWKSCacheKey must scope keys by provider")
	}
	if JWKSCacheKey("google", GoogleJWKSURL) == JWKSCacheKey("google", AppleJWKSURL) {
		t.Error("JWKSCacheKey must scope keys by URL")
	}
	if got := JWKSCacheKey("", GoogleJWKSURL); got != GoogleJWKSURL {
		t.Errorf("empty provider JWKSCacheKey = %q, want URL", got)
	}
}

func TestNonceShapeAndMatching(t *testing.T) {
	if !IsValidNonceString("abcdefghijklmnopqrstuvwxyz012345") {
		t.Error("32-char alphabet nonce should be valid")
	}
	for _, bad := range []string{"", "short", "has space in it!!!!", "tab\there!!!!", "semi;colon!!"} {
		if IsValidNonceString(bad) {
			t.Errorf("IsValidNonceString(%q) = true, want false", bad)
		}
	}
	long := make([]byte, 513)
	for i := range long {
		long[i] = 'a'
	}
	if IsValidNonceString(string(long)) {
		t.Error("513-char nonce should be invalid")
	}

	if !MatchIDTokenNonce("n-0S6_WzA2Mj", "n-0S6_WzA2Mj", IDTokenNonceExact) {
		t.Error("exact match should hold")
	}
	if MatchIDTokenNonce("a", "b", IDTokenNonceExact) {
		t.Error("exact mismatch should fail")
	}
	if MatchIDTokenNonce("a", "b", IDTokenNonceExactOrSHA256) {
		t.Error("unrelated nonce must fail even with sha256 comparison")
	}
	// SHA-256("hello") = 2cf24dba...b9824: Apple-style stored-digest match.
	if !MatchIDTokenNonce("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", "hello", IDTokenNonceExactOrSHA256) {
		t.Error("sha256-digest nonce should match under exact-or-sha256")
	}
	if MatchIDTokenNonce("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", "hello", IDTokenNonceExact) {
		t.Error("sha256-digest nonce must fail under exact comparison")
	}
	if !MatchIDTokenNonce("", "", IDTokenNonceExact) {
		t.Error("empty nonces compare equal (skip semantics)")
	}
	if MatchIDTokenNonce("", "expected", IDTokenNonceExact) {
		t.Error("missing claim nonce must fail")
	}
}

func TestMemNonceStoreRoundTrip(t *testing.T) {
	var store NonceStore = &memNonceStore{}
	if err := store.StoreNonce("state-1", "nonce-1", time.Minute); err != nil {
		t.Fatal(err)
	}
	got, err := store.TakeNonce("state-1")
	if err != nil || got != "nonce-1" {
		t.Fatalf("TakeNonce = %q, %v", got, err)
	}
	again, err := store.TakeNonce("state-1")
	if err != nil || again != "" {
		t.Fatalf("nonce must be single-use, got %q, %v", again, err)
	}
}

func TestPrimaryClientID(t *testing.T) {
	if got := PrimaryClientID("primary", "extra"); got != "primary" {
		t.Errorf("PrimaryClientID = %q", got)
	}
	if got := PrimaryClientID("", "fallback"); got != "fallback" {
		t.Errorf("PrimaryClientID skips empties, got %q", got)
	}
	if got := PrimaryClientID("", ""); got != "" {
		t.Errorf("PrimaryClientID all-empty = %q", got)
	}
	if got := PrimaryClientID(); got != "" {
		t.Errorf("PrimaryClientID none = %q", got)
	}
}

func TestGoogleProviderOptions(t *testing.T) {
	var opts GoogleProviderOptions
	if !opts.EffectiveIncludeGrantedScopes() {
		t.Error("nil IncludeGrantedScopes must default to true")
	}
	off := false
	opts.IncludeGrantedScopes = &off
	if opts.EffectiveIncludeGrantedScopes() {
		t.Error("explicit false IncludeGrantedScopes must stay false")
	}
	if GoogleJWKSURL != "https://www.googleapis.com/oauth2/v3/certs" {
		t.Errorf("GoogleJWKSURL = %q", GoogleJWKSURL)
	}
	if len(GoogleIssuers) != 2 || GoogleIssuers[0] != "https://accounts.google.com" {
		t.Errorf("GoogleIssuers = %v", GoogleIssuers)
	}
	if len(GoogleDefaultScopes) != 3 {
		t.Errorf("GoogleDefaultScopes = %v", GoogleDefaultScopes)
	}

	cases := []struct {
		configured string
		claim      any
		want       bool
	}{
		{"", nil, true},
		{"", "anything", true},
		{"example.com", "example.com", true},
		{"example.com", "other.com", false},
		{"example.com", nil, false},
		{"example.com", "", false},
		{"example.com", 42, false},
		{"*", "any-workspace.com", true},
		{"*", nil, false},
	}
	for _, c := range cases {
		if got := IsGoogleHostedDomainAllowed(c.configured, c.claim); got != c.want {
			t.Errorf("IsGoogleHostedDomainAllowed(%q, %v) = %v, want %v", c.configured, c.claim, got, c.want)
		}
	}
}

func TestAppleProviderOptions(t *testing.T) {
	if AppleIssuer != "https://appleid.apple.com" {
		t.Errorf("AppleIssuer = %q", AppleIssuer)
	}
	if AppleJWKSURL != "https://appleid.apple.com/auth/keys" {
		t.Errorf("AppleJWKSURL = %q", AppleJWKSURL)
	}
	var opts AppleProviderOptions
	if got := opts.EffectiveAudience("client-id"); len(got) != 1 || got[0] != "client-id" {
		t.Errorf("default apple audience = %v", got)
	}
	opts.AppBundleIdentifier = "com.example.app"
	if got := opts.EffectiveAudience("client-id"); len(got) != 1 || got[0] != "com.example.app" {
		t.Errorf("bundle apple audience = %v", got)
	}
	opts.Audience = []string{"explicit"}
	if got := opts.EffectiveAudience("client-id"); len(got) != 1 || got[0] != "explicit" {
		t.Errorf("explicit apple audience = %v", got)
	}
}

func TestDiscordProviderOptions(t *testing.T) {
	var opts DiscordProviderOptions
	if opts.EffectivePrompt() != "none" {
		t.Errorf("default discord prompt = %q", opts.EffectivePrompt())
	}
	opts.Prompt = "consent"
	if opts.EffectivePrompt() != "consent" {
		t.Errorf("discord prompt = %q", opts.EffectivePrompt())
	}
	if len(DiscordDefaultScopes) != 2 {
		t.Errorf("DiscordDefaultScopes = %v", DiscordDefaultScopes)
	}
}

func TestMicrosoftProviderOptions(t *testing.T) {
	var opts MicrosoftProviderOptions
	if opts.EffectiveTenant() != "common" {
		t.Errorf("default tenant = %q", opts.EffectiveTenant())
	}
	if opts.EffectiveAuthority() != MicrosoftDefaultAuthority {
		t.Errorf("default authority = %q", opts.EffectiveAuthority())
	}
	opts.Authority = "https://login.microsoftonline.com/"
	if opts.EffectiveAuthority() != "https://login.microsoftonline.com" {
		t.Errorf("trailing-slash authority = %q", opts.EffectiveAuthority())
	}
	if opts.EffectiveProfilePhotoSize() != 48 {
		t.Errorf("default photo size = %d", opts.EffectiveProfilePhotoSize())
	}
	if MicrosoftIssuer(MicrosoftDefaultAuthority, "common") != "" {
		t.Error("common tenant must skip the issuer check")
	}
	for _, tenant := range []string{"organizations", "consumers"} {
		if MicrosoftIssuer(MicrosoftDefaultAuthority, tenant) != "" {
			t.Errorf("%s tenant must skip the issuer check", tenant)
		}
	}
	wantIssuer := MicrosoftDefaultAuthority + "/tenant-guid/v2.0"
	if got := MicrosoftIssuer(MicrosoftDefaultAuthority, "tenant-guid"); got != wantIssuer {
		t.Errorf("tenant issuer = %q, want %q", got, wantIssuer)
	}
	wantJWKS := MicrosoftDefaultAuthority + "/tenant-guid/discovery/v2.0/keys"
	if got := MicrosoftJWKSURL(MicrosoftDefaultAuthority, "tenant-guid"); got != wantJWKS {
		t.Errorf("tenant jwks url = %q, want %q", got, wantJWKS)
	}
	if MicrosoftConsumerTenantID != "9188040d-6c67-4c5b-b112-36a304b66dad" {
		t.Errorf("MicrosoftConsumerTenantID = %q", MicrosoftConsumerTenantID)
	}
}

func TestGithubProviderOptionsShape(t *testing.T) {
	var opts GithubProviderOptions
	opts.ClientID = "github-id"
	opts.Scopes = []string{"read:user"}
	if len(GithubDefaultScopes) != 2 {
		t.Errorf("GithubDefaultScopes = %v", GithubDefaultScopes)
	}
	var _ OAuthProvider = oauthBareStub{}
	_ = opts
}
