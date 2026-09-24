package routes

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

// Pinned upstream: email-verification.test.ts — core (non-secondary,
// non-change-email-handshake) legs. The change-email JWT legs are covered by
// TestC702_VerifyEmailConfirmationLeg/TestC702_VerifyEmailVerificationLeg.

func credsVerifyAPI(t *testing.T, opts types.Options) humatest.TestAPI {
	t.Helper()
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	SignUpEmail(api, "/api/auth", opts)
	SignInEmail(api, "/api/auth", opts)
	SendVerificationEmail(api, "/api/auth", opts)
	VerifyEmail(api, "/api/auth", opts)
	return api
}

// email-verification.test.ts "should return APIError status when
// sendVerificationEmail throws (e.g. rate limit)" (#8757): sender APIErrors
// keep their status after the anti-enumeration floor instead of collapsing
// to 500.
func TestCredsV1_SendVerificationSenderAPIErrorPropagates(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.EmailVerification.SendVerificationEmail = func(types.VerificationEmailData) error {
		return types.HttpError{Code: "RATE_LIMIT_EXCEEDED", Message: "Too many requests. Please try again later.", Status: 429}
	}
	api := credsVerifyAPI(t, opts)
	credsSignInSeed(t, api, "ratelimit@test.com", "password123")

	start := time.Now()
	resp := api.Post("/api/auth/send-verification-email", map[string]any{
		"email": "ratelimit@test.com",
	})
	elapsed := time.Since(start)
	if resp.Code != 429 {
		t.Fatalf("status = %d, want 429: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "RATE_LIMIT_EXCEEDED") {
		t.Fatalf("sender code must survive, got %s", resp.Body.String())
	}
	if elapsed < 450*time.Millisecond {
		t.Fatalf("sender errors must still wait out the floor, elapsed %v", elapsed)
	}
}

// email-verification.test.ts "should enforce a constant-time floor for both
// existing and non-existing emails".
func TestCredsV1_SendVerificationMissingEmailFloor(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	var sent []string
	opts.EmailVerification.SendVerificationEmail = func(data types.VerificationEmailData) error {
		sent = append(sent, data.User.Email)
		return nil
	}
	api := credsVerifyAPI(t, opts)
	credsSignInSeed(t, api, "floor@test.com", "password123")

	start := time.Now()
	resp := api.Post("/api/auth/send-verification-email", map[string]any{
		"email": "nonexistent@example.com",
	})
	elapsed := time.Since(start)
	if resp.Code != 200 || !strings.Contains(resp.Body.String(), `"status":true`) {
		t.Fatalf("missing email must answer generic success, got %d: %s", resp.Code, resp.Body.String())
	}
	if elapsed < 450*time.Millisecond {
		t.Fatalf("floor must hold for missing emails, elapsed %v", elapsed)
	}
	for _, to := range sent {
		if to == "nonexistent@example.com" {
			t.Fatal("no send for unknown email")
		}
	}
}

// email-verification.test.ts "should send a verification email when
// enabled": the sender receives user/url/token.
func TestCredsV1_SendVerificationDelivers(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	var got types.VerificationEmailData
	opts.EmailVerification.SendVerificationEmail = func(data types.VerificationEmailData) error {
		got = data
		return nil
	}
	api := credsVerifyAPI(t, opts)
	credsSignInSeed(t, api, "deliver@test.com", "password123")

	resp := api.Post("/api/auth/send-verification-email", map[string]any{
		"email": "deliver@test.com",
	})
	if resp.Code != 200 {
		t.Fatalf("status = %d: %s", resp.Code, resp.Body.String())
	}
	if got.User == nil || got.User.Email != "deliver@test.com" {
		t.Fatalf("sender must receive the user, got %#v", got.User)
	}
	if got.Token == "" || got.URL == "" {
		t.Fatalf("sender must receive url+token, got %#v", got)
	}
}

// email-verification.test.ts "should not send verification email when a
// third party requests for an already verified user".
func TestCredsV1_SendVerificationSkipsVerifiedThirdParty(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	var calls int
	var token string
	opts.EmailVerification.SendVerificationEmail = func(data types.VerificationEmailData) error {
		calls++
		token = data.Token
		return nil
	}
	api := credsVerifyAPI(t, opts)
	credsSignInSeed(t, api, "thirdparty@test.com", "password123")

	if resp := api.Post("/api/auth/send-verification-email", map[string]any{
		"email": "thirdparty@test.com",
	}); resp.Code != 200 {
		t.Fatalf("first send = %d: %s", resp.Code, resp.Body.String())
	}
	verify := api.Post("/api/auth/verify-email", map[string]any{"token": token})
	if verify.Code != 200 {
		t.Fatalf("verify = %d: %s", verify.Code, verify.Body.String())
	}
	calls = 0
	resp := api.Post("/api/auth/send-verification-email", map[string]any{
		"email": "thirdparty@test.com",
	})
	if resp.Code != 200 || !strings.Contains(resp.Body.String(), `"status":true`) {
		t.Fatalf("verified retry must answer generic success, got %d: %s", resp.Code, resp.Body.String())
	}
	if calls != 0 {
		t.Fatal("no send for an already-verified address")
	}
}

// email-verification.test.ts "should redirect to callback": GET verify with
// callbackURL redirects to it.
func TestCredsV1_VerifyEmailGetRedirectsToCallback(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	var token string
	opts.EmailVerification.SendVerificationEmail = func(data types.VerificationEmailData) error {
		token = data.Token
		return nil
	}
	api := credsVerifyAPI(t, opts)
	credsSignInSeed(t, api, "redirect@test.com", "password123")
	if resp := api.Post("/api/auth/send-verification-email", map[string]any{
		"email": "redirect@test.com",
	}); resp.Code != 200 {
		t.Fatalf("send = %d: %s", resp.Code, resp.Body.String())
	}
	resp := api.Get("/api/auth/verify-email?token=" + url.QueryEscape(token) + "&callbackURL=" + url.QueryEscape("/callback"))
	if resp.Code != 302 {
		t.Fatalf("status = %d, want 302: %s", resp.Code, resp.Body.String())
	}
	if loc := resp.Header().Get("Location"); loc != "/callback" {
		t.Fatalf("Location = %q, want /callback", loc)
	}
}

// email-verification.test.ts "should preserve encoded characters in
// callback URL": the redirect echoes the callbackURL exactly.
func TestCredsV1_VerifyEmailGetPreservesEncodedCallback(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	var token string
	opts.EmailVerification.SendVerificationEmail = func(data types.VerificationEmailData) error {
		token = data.Token
		return nil
	}
	api := credsVerifyAPI(t, opts)
	credsSignInSeed(t, api, "encoded@test.com", "password123")
	if resp := api.Post("/api/auth/send-verification-email", map[string]any{
		"email": "encoded@test.com",
	}); resp.Code != 200 {
		t.Fatalf("send = %d: %s", resp.Code, resp.Body.String())
	}
	callback := "/sign-in?verifiedEmail=test%2Buser%40example.com"
	resp := api.Get("/api/auth/verify-email?token=" + url.QueryEscape(token) + "&callbackURL=" + url.QueryEscape(callback))
	if resp.Code != 302 {
		t.Fatalf("status = %d, want 302: %s", resp.Code, resp.Body.String())
	}
	if loc := resp.Header().Get("Location"); loc != callback {
		t.Fatalf("Location = %q, want %q", loc, callback)
	}
}
