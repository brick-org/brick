package types

import (
	"net/http"
	"testing"
	"time"
)

// stubProvider implements OAuthProvider plus the optional refresh, revoke,
type stubProvider struct{}

func (stubProvider) ID() string   { return "stub" }
func (stubProvider) Name() string { return "Stub" }
func (stubProvider) CreateAuthorizationURL(params AuthorizationURLParams) (string, error) {
	return "https://example.com/authorize?state=" + params.State, nil
}
func (stubProvider) ExchangeCode(params CodeExchangeParams) (*OAuthTokens, error) {
	return &OAuthTokens{AccessToken: "access:" + params.Code}, nil
}
func (stubProvider) GetUserInfo(tokens *OAuthTokens) (*OAuthUserInfo, error) {
	return &OAuthUserInfo{ID: "user-1", EmailVerified: true}, nil
}
func (stubProvider) RefreshAccessToken(refreshToken string) (*OAuthTokens, error) {
	return &OAuthTokens{AccessToken: "refreshed", RefreshToken: refreshToken}, nil
}
func (stubProvider) RevokeToken(token string) error { return nil }
func (stubProvider) CreateEndSessionURL(params EndSessionParams) (string, error) {
	if params.PostLogoutRedirectURI == "" {
		return "", nil
	}
	return "https://example.com/logout", nil
}

// stubStorage implements SecondaryStorage and RateLimitCustomStorage.
type stubStorage struct{}

func (stubStorage) Get(key string) (any, error)                  { return nil, nil }
func (stubStorage) GetAndDelete(key string) (any, error)         { return nil, nil }
func (stubStorage) Increment(key string, ttl int) (int64, error) { return 1, nil }
func (stubStorage) Set(key, value string, ttl *int) error        { return nil }
func (stubStorage) Delete(key string) error                      { return nil }
func (stubStorage) Consume(key string, rule RateLimitRule) (RateLimitConsumeResult, error) {
	return RateLimitConsumeResult{Allowed: true}, nil
}

func TestOptionalProviderCapabilitiesDoNotBreakCoreInterface(t *testing.T) {
	var core OAuthProvider = stubProvider{}
	if core.ID() != "stub" {
		t.Fatalf("stub provider ID = %q", core.ID())
	}
	if _, ok := core.(RefreshableProvider); !ok {
		t.Fatal("stub provider should satisfy RefreshableProvider")
	}
	if _, ok := core.(TokenRevoker); !ok {
		t.Fatal("stub provider should satisfy TokenRevoker")
	}
	if _, ok := core.(EndSessionProvider); !ok {
		t.Fatal("stub provider should satisfy EndSessionProvider")
	}
	if _, ok := core.(RefreshableProviderWithContext); ok {
		t.Fatal("stub provider must not satisfy RefreshableProviderWithContext")
	}
}

func TestSecondaryStorageStubsSatisfyContracts(t *testing.T) {
	var _ SecondaryStorage = stubStorage{}
	var _ RateLimitCustomStorage = stubStorage{}
}

func TestParityDefaultsPreserveCurrentBehavior(t *testing.T) {
	var opts Options
	if opts.SecondaryStorage != nil {
		t.Error("zero Options.SecondaryStorage should be nil (no backend by default)")
	}
	if opts.Experimental.Instrumentation.Enabled != nil {
		t.Error("zero Experimental.Instrumentation.Enabled should be nil (inactive)")
	}
	if opts.Verification.StoreInDatabase {
		t.Error("zero Verification.StoreInDatabase should be false")
	}
	if opts.RateLimit.Storage != "" {
		t.Error("zero RateLimit.Storage should be empty (in-memory behavior)")
	}
	if opts.Advanced.DisableOriginCheck {
		t.Error("zero Advanced.DisableOriginCheck should be false")
	}
	if opts.Advanced.SkipTrailingSlashes {
		t.Error("zero Advanced.SkipTrailingSlashes should be false")
	}

	var rate RateLimitOptions
	if rate.EnabledValue() {
		t.Error("zero RateLimitOptions should stay disabled")
	}
	if rate.WindowOrDefault() != 10 || rate.MaxOrDefault() != 100 {
		t.Error("rate limit window/max defaults changed")
	}

	var linking AccountLinkingOptions
	if !linking.IsEnabled() {
		t.Error("zero AccountLinkingOptions should stay enabled")
	}
	if !linking.RequireLocalEmailVerifiedValue() {
		t.Error("nil RequireLocalEmailVerified should default to true (upstream default)")
	}

	var session SessionOptions
	if session.ExpiresInDuration() != 7*24*time.Hour {
		t.Error("session expiry default changed")
	}
	if session.DisableSessionRefresh || session.DeferSessionRefresh {
		t.Error("zero SessionOptions should leave refresh flags off")
	}
	if session.CookieCache.Strategy != "" || session.CookieCache.Version != "" {
		t.Error("zero SessionCookieCacheOptions should leave strategy/version unset")
	}

	var attr FieldAttribute
	if attr.Transform != nil || attr.Validator != nil || attr.OnUpdate != nil {
		t.Error("zero FieldAttribute should leave hooks nil")
	}
	if attr.BigInt || attr.Sortable || attr.Index || attr.FieldName != "" {
		t.Error("zero FieldAttribute should leave metadata flags unset")
	}
	var table TableSchema
	if table.ModelName != "" || table.Indexes != nil || table.Order != 0 {
		t.Error("zero TableSchema should leave new metadata unset")
	}
}

func TestRequestEndpointContext(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://app.example.com/api/auth/sign-in", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := RequestEndpointContext(req, AuthContext{}, "", "")
	if ctx.Method != http.MethodPost || ctx.Path != "/api/auth/sign-in" {
		t.Errorf("derived context = %s %s", ctx.Method, ctx.Path)
	}
	if ctx.Headers == nil {
		t.Error("headers should be copied from the request")
	}

	// Nil requests are valid (mirrors upstream hooks invoked without one).
	empty := RequestEndpointContext(nil, AuthContext{}, "", "")
	if empty.Method != "" || empty.Path != "" || empty.Headers != nil {
		t.Errorf("nil-request context = %+v", empty)
	}
}

func TestUpstreamDefaultConstants(t *testing.T) {
	if LogLevelSuccess != "success" {
		t.Errorf("LogLevelSuccess = %q", LogLevelSuccess)
	}
	if SessionCookieCacheCompact != "compact" ||
		SessionCookieCacheJWT != "jwt" ||
		SessionCookieCacheJWE != "jwe" {
		t.Error("cookie cache strategy values changed")
	}
	if RateLimitStorageMemory != "memory" ||
		RateLimitStorageDatabase != "database" ||
		RateLimitStorageSecondary != "secondary-storage" {
		t.Error("rate limit storage values changed")
	}
	if StoreIdentifierPlain != "plain" || StoreIdentifierHashed != "hashed" {
		t.Error("store identifier values changed")
	}
	if BaseURLProtocolAuto != "auto" {
		t.Errorf("BaseURLProtocolAuto = %q", BaseURLProtocolAuto)
	}
}
