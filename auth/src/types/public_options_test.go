package types

import (
	"strings"
	"testing"
)

// TestPublicOptions_NewFieldsPinPresence ensures the types-owned parity
func TestPublicOptions_NewFieldsPinPresence(t *testing.T) {
	var opts Options

	if opts.DynamicBaseURL != nil {
		t.Error("zero Options.DynamicBaseURL should be nil (static-BaseURL mode)")
	}
	dyn := &DynamicBaseURLConfig{
		AllowedHosts: []string{"myapp.com", "*.vercel.app"},
		Fallback:     "https://myapp.com",
		Protocol:     BaseURLProtocolAuto,
	}
	opts.DynamicBaseURL = dyn
	if len(opts.DynamicBaseURL.AllowedHosts) != 2 {
		t.Error("DynamicBaseURL.AllowedHosts not retained")
	}


	ev := TelemetryEvent{Type: "test", AnonymousID: "anon", Payload: map[string]any{"k": "v"}}
	if ev.Type != "test" || ev.Payload["k"] != "v" {
		t.Error("TelemetryEvent fields not retained")
	}

	// Session cookie-cache additions.
	var cc SessionCookieCacheOptions
	if cc.VersionFunc != nil {
		t.Error("zero SessionCookieCacheOptions.VersionFunc should be nil")
	}
	if cc.RefreshCache.ShouldRefresh != nil {
		t.Error("zero SessionCookieCacheRefresh.ShouldRefresh should be nil")
	}
	cc.VersionFunc = func(s Session, u User) (string, error) { return "2", nil }
	cc.RefreshCache.ShouldRefresh = func(s Session, u User) bool { return true }
	v, err := cc.VersionFunc(Session{}, User{})
	if err != nil || v != "2" {
		t.Error("VersionFunc round-trip failed")
	}
	if !cc.RefreshCache.ShouldRefresh(Session{}, User{}) {
		t.Error("ShouldRefresh round-trip failed")
	}

	// Per-request session knobs.
	var q SessionQueryOptions
	if q.DisableCookieCache || q.DisableRefresh {
		t.Error("zero SessionQueryOptions should leave knobs off")
	}
	var p SessionPersistenceOptions
	if p.DontRememberMe {
		t.Error("zero SessionPersistenceOptions should leave DontRememberMe off")
	}
}

func validTestOptions() Options {
	return Options{Secret: "test-secret-0123456789abcdef0123456789"}
}

func TestValidateOptions_EmptySecret(t *testing.T) {
	if err := ValidateOptions(Options{}); err == nil {
		t.Fatal("expected error for empty Secret/Secrets")
	} else if !strings.Contains(err.Error(), "Secret") {
		t.Fatalf("error should mention Secret, got %q", err)
	}
	t.Setenv("BETTER_AUTH_SECRET", "env-secret-0123456789abcdef0123")
	if err := ValidateOptions(Options{}); err == nil {
		t.Fatal("ValidateOptions must not consult the environment")
	}
}

func TestValidateOptions_ValidMinimal(t *testing.T) {
	if err := ValidateOptions(validTestOptions()); err != nil {
		t.Fatalf("valid minimal options rejected: %v", err)
	}
	if err := validTestOptions().Validate(); err != nil {
		t.Fatalf("Options.Validate delegation failed: %v", err)
	}
}

func TestValidateOptions_SecretRotation(t *testing.T) {
	opts := validTestOptions()
	opts.Secrets = []Secret{{Version: 2, Value: "new-0123456789abcdef0123456789"}, {Version: 1, Value: "old-0123456789abcdef0123456789"}}
	if err := ValidateOptions(opts); err != nil {
		t.Fatalf("versioned secrets rejected: %v", err)
	}

	bad := validTestOptions()
	bad.Secrets = []Secret{{Version: 1, Value: ""}}
	if err := ValidateOptions(bad); err == nil {
		t.Fatal("expected error for empty rotated secret value")
	}

	dup := validTestOptions()
	dup.Secrets = []Secret{{Version: 1, Value: "a-0123456789abcdef0123456789"}, {Version: 1, Value: "b-0123456789abcdef0123456789"}}
	if err := ValidateOptions(dup); err == nil {
		t.Fatal("expected error for duplicated secret versions")
	}
}

func TestValidateOptions_BaseURL(t *testing.T) {
	good := validTestOptions()
	good.BaseURL = "https://myapp.com"
	if err := ValidateOptions(good); err != nil {
		t.Fatalf("absolute https BaseURL rejected: %v", err)
	}

	for _, raw := range []string{"not-a-url", "ftp://myapp.com", "/relative/path", "https://"} {
		bad := validTestOptions()
		bad.BaseURL = raw
		if err := ValidateOptions(bad); err == nil {
			t.Fatalf("expected error for BaseURL %q", raw)
		}
	}
}

func TestValidateOptions_DynamicBaseURL(t *testing.T) {
	both := validTestOptions()
	both.BaseURL = "https://myapp.com"
	both.DynamicBaseURL = &DynamicBaseURLConfig{AllowedHosts: []string{"myapp.com"}}
	if err := ValidateOptions(both); err == nil {
		t.Fatal("expected mutual-exclusion error for BaseURL + DynamicBaseURL")
	}

	empty := validTestOptions()
	empty.DynamicBaseURL = &DynamicBaseURLConfig{}
	if err := ValidateOptions(empty); err == nil {
		t.Fatal("expected error for empty AllowedHosts")
	}

	proto := validTestOptions()
	proto.DynamicBaseURL = &DynamicBaseURLConfig{AllowedHosts: []string{"myapp.com"}, Protocol: "gopher"}
	if err := ValidateOptions(proto); err == nil {
		t.Fatal("expected error for bad Protocol")
	}

	fallback := validTestOptions()
	fallback.DynamicBaseURL = &DynamicBaseURLConfig{AllowedHosts: []string{"myapp.com"}, Fallback: "bogus"}
	if err := ValidateOptions(fallback); err == nil {
		t.Fatal("expected error for bad Fallback")
	}

	good := validTestOptions()
	good.DynamicBaseURL = &DynamicBaseURLConfig{
		AllowedHosts: []string{"myapp.com", "*.vercel.app"},
		Fallback:     "https://myapp.com",
		Protocol:     BaseURLProtocolAuto,
	}
	if err := ValidateOptions(good); err != nil {
		t.Fatalf("valid DynamicBaseURL rejected: %v", err)
	}
}

func TestValidateOptions_StorageConflicts(t *testing.T) {
	store := validTestOptions()
	store.Session.StoreSessionInDatabase = true
	if err := ValidateOptions(store); err == nil {
		t.Fatal("expected error for StoreSessionInDatabase without SecondaryStorage")
	}

	preserve := validTestOptions()
	preserve.Session.PreserveSessionInDatabase = true
	if err := ValidateOptions(preserve); err == nil {
		t.Fatal("expected error for PreserveSessionInDatabase without SecondaryStorage")
	}

	wired := validTestOptions()
	wired.SecondaryStorage = stubStorage{}
	wired.Session.StoreSessionInDatabase = true
	wired.Session.PreserveSessionInDatabase = true
	if err := ValidateOptions(wired); err != nil {
		t.Fatalf("secondary-storage session flags with a backend rejected: %v", err)
	}

	rate := validTestOptions()
	rate.RateLimit.Storage = RateLimitStorageSecondary
	if err := ValidateOptions(rate); err == nil {
		t.Fatal("expected error for secondary-storage rate limiting without a backend")
	}
	rate.SecondaryStorage = stubStorage{}
	if err := ValidateOptions(rate); err != nil {
		t.Fatalf("secondary-storage rate limiting with a backend rejected: %v", err)
	}

	literal := validTestOptions()
	literal.RateLimit.Storage = "disk"
	if err := ValidateOptions(literal); err == nil {
		t.Fatal("expected error for unknown RateLimit.Storage value")
	}

	strategy := validTestOptions()
	strategy.Session.CookieCache.Strategy = "rot13"
	if err := ValidateOptions(strategy); err == nil {
		t.Fatal("expected error for unknown CookieCache.Strategy value")
	}

	verify := validTestOptions()
	verify.Verification.StoreInDatabase = true
	if err := ValidateOptions(verify); err == nil {
		t.Fatal("expected error for Verification.StoreInDatabase without SecondaryStorage")
	}

	mode := validTestOptions()
	mode.Verification.StoreIdentifier.Mode = "scrambled"
	if err := ValidateOptions(mode); err == nil {
		t.Fatal("expected error for unknown StoreIdentifier.Mode value")
	}
}

func TestValidateOptions_RangesAndURLs(t *testing.T) {
	length := validTestOptions()
	length.EmailAndPassword.MinPasswordLength = 16
	length.EmailAndPassword.MaxPasswordLength = 8
	if err := ValidateOptions(length); err == nil {
		t.Fatal("expected error for MinPasswordLength > MaxPasswordLength")
	}

	neg := validTestOptions()
	neg.RateLimit.Window = -1
	if err := ValidateOptions(neg); err == nil {
		t.Fatal("expected error for negative RateLimit.Window")
	}

	negMax := validTestOptions()
	negMax.RateLimit.Max = -5
	if err := ValidateOptions(negMax); err == nil {
		t.Fatal("expected error for negative RateLimit.Max")
	}

	sess := validTestOptions()
	sess.Session.ExpiresIn = -1
	if err := ValidateOptions(sess); err == nil {
		t.Fatal("expected error for negative Session.ExpiresIn")
	}

	fresh := validTestOptions()
	zero := 0
	fresh.Session.FreshAge = &zero
	if err := ValidateOptions(fresh); err != nil {
		t.Fatalf("explicit FreshAge 0 (check disabled) must be valid: %v", err)
	}
	negFresh := -1
	fresh.Session.FreshAge = &negFresh
	if err := ValidateOptions(fresh); err == nil {
		t.Fatal("expected error for negative Session.FreshAge")
	}

	ttl := validTestOptions()
	ttl.EmailAndPassword.ResetPasswordTokenExpiresIn = -1
	if err := ValidateOptions(ttl); err == nil {
		t.Fatal("expected error for negative ResetPasswordTokenExpiresIn")
	}

	verifyTTL := validTestOptions()
	verifyTTL.EmailVerification.ExpiresIn = -1
	if err := ValidateOptions(verifyTTL); err == nil {
		t.Fatal("expected error for negative EmailVerification.ExpiresIn")
	}

	origins := validTestOptions()
	origins.TrustedOrigins = []string{"https://app.example.com", ""}
	if err := ValidateOptions(origins); err == nil {
		t.Fatal("expected error for empty TrustedOrigins entry")
	}

	errURL := validTestOptions()
	errURL.OnAPIError.ErrorURL = "https:// app.example.com/bad"
	if err := ValidateOptions(errURL); err == nil {
		t.Fatal("expected error for malformed OnAPIError.ErrorURL")
	}
	relURL := validTestOptions()
	relURL.OnAPIError.ErrorURL = "/api/auth/error"
	if err := ValidateOptions(relURL); err != nil {
		t.Fatalf("root-relative ErrorURL must be valid: %v", err)
	}
}

func TestValidateOptions_SubValidatorsArePure(t *testing.T) {
	var ep EmailAndPasswordOptions
	if err := ep.Validate(); err != nil {
		t.Fatalf("zero EmailAndPasswordOptions must be valid: %v", err)
	}
	var ev EmailVerificationOptions
	if err := ev.Validate(); err != nil {
		t.Fatalf("zero EmailVerificationOptions must be valid: %v", err)
	}
	var s SessionOptions
	if err := s.Validate(); err != nil {
		t.Fatalf("zero SessionOptions must be valid: %v", err)
	}
	if d := s.ExpiresInDuration(); d <= 0 {
		t.Fatal("session expiry default must stay positive")
	}
}
