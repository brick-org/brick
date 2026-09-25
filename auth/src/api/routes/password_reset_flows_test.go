package routes

import (
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

var errCredsSendFailure = errors.New("failed to send email")

// Pinned upstream: password.test.ts — forgot-password, revoke-on-reset and
// verify-password legs.

func credsPasswordAPI(t *testing.T, opts types.Options) humatest.TestAPI {
	t.Helper()
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	SignUpEmail(api, "/api/auth", opts)
	SignInEmail(api, "/api/auth", opts)
	RequestPasswordReset(api, "/api/auth", opts)
	ResetPassword(api, "/api/auth", opts)
	RequestPasswordResetCallback(api, "/api/auth", opts)
	VerifyPassword(api, "/api/auth", opts)
	return api
}

const credsResetGenericMessage = "If this email exists in our system, check your email for the reset link"

// password.test.ts "should not reveal user existence on failure" (+ the
func TestPasswordReset_RequestResetUnknownUserWarnsGeneric(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.EmailAndPassword.SendResetPassword = func(types.ResetPasswordData) error { return nil }
	opts.TrustedOrigins = []string{"http://localhost:3000"}
	var calls [][2]string
	opts.Logger.Log = func(level, message string, _ ...any) {
		calls = append(calls, [2]string{level, message})
	}
	api := credsPasswordAPI(t, opts)
	resp := api.Post("/api/auth/request-password-reset", map[string]any{
		"email": "non-existent-user@email.com", "redirectTo": "http://localhost:3000",
	})
	if resp.Code != 200 {
		t.Fatalf("status = %d, want 200: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), credsResetGenericMessage) {
		t.Fatalf("generic message required, got %s", resp.Body.String())
	}
	if !credsLogged(calls, "warn", "Reset Password: User not found") {
		t.Fatalf("expected warn 'Reset Password: User not found', got %#v", calls)
	}
	for _, c := range calls {
		if c[0] == "error" {
			t.Fatalf("no error-level logs expected, got %#v", calls)
		}
	}
}

// password.test.ts "should allow callbackURL to have multiple query params":
func TestPasswordReset_ResetURLCallbackEncoding(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.TrustedOrigins = []string{"http://localhost:3000"}
	var capturedURL string
	opts.EmailAndPassword.SendResetPassword = func(data types.ResetPasswordData) error {
		capturedURL = data.URL
		return nil
	}
	api := credsPasswordAPI(t, opts)
	credsSignInSeed(t, api, "reset-cb@test.com", "password123")
	redirectTo := "http://localhost:3000?foo=bar&baz=qux"
	resp := api.Post("/api/auth/request-password-reset", map[string]any{
		"email": "reset-cb@test.com", "redirectTo": redirectTo,
	})
	if resp.Code != 200 {
		t.Fatalf("status = %d: %s", resp.Code, resp.Body.String())
	}
	plain := strings.SplitN(capturedURL, "?", 2)
	if len(plain) != 2 {
		t.Fatalf("reset URL must carry a query string: %q", capturedURL)
	}
	segments := strings.Split(plain[0], "/")
	if token := segments[len(segments)-1]; len(token) < 10 {
		t.Fatalf("path token too short: %q", capturedURL)
	}
	parsed, err := url.Parse(capturedURL)
	if err != nil {
		t.Fatalf("parse reset URL: %v", err)
	}
	if got := parsed.Query().Get("callbackURL"); got != redirectTo {
		t.Fatalf("callbackURL round-trip = %q, want %q", got, redirectTo)
	}
}

// password.test.ts "should not reveal failure of email sending".
func TestPasswordReset_ResetSenderFailureStillGeneric(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.EmailAndPassword.SendResetPassword = func(types.ResetPasswordData) error {
		return errCredsSendFailure
	}
	api := credsPasswordAPI(t, opts)
	credsSignInSeed(t, api, "reset-fail@test.com", "password123")
	resp := api.Post("/api/auth/request-password-reset", map[string]any{
		"email": "reset-fail@test.com",
	})
	if resp.Code != 200 {
		t.Fatalf("status = %d, want 200: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), `"status":true`) ||
		!strings.Contains(resp.Body.String(), credsResetGenericMessage) {
		t.Fatalf("generic success required, got %s", resp.Body.String())
	}
}

// password.test.ts "should reject untrusted redirectTo".
func TestPasswordReset_RequestResetRejectsUntrustedRedirect(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.EmailAndPassword.SendResetPassword = func(types.ResetPasswordData) error { return nil }
	opts.TrustedOrigins = []string{"http://localhost:3000"}
	api := credsPasswordAPI(t, opts)
	credsSignInSeed(t, api, "reset-untrusted@test.com", "password123")
	resp := api.Post("/api/auth/request-password-reset", map[string]any{
		"email": "reset-untrusted@test.com", "redirectTo": "http://malicious.com",
	})
	if resp.Code != 403 {
		t.Fatalf("status = %d, want 403: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), types.ErrInvalidRedirectURL) {
		t.Fatalf("want INVALID_REDIRECT_URL, got %s", resp.Body.String())
	}
}

// password.test.ts verify-password legs: correct verifies, wrong is 400
func TestPasswordReset_VerifyPasswordStatuses(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	api := credsPasswordAPI(t, opts)
	credsSignInSeed(t, api, "verify-pw@test.com", "password123")
	signIn := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": "verify-pw@test.com", "password": "password123",
	})
	if signIn.Code != 200 {
		t.Fatalf("seed sign-in = %d: %s", signIn.Code, signIn.Body.String())
	}
	cookie := sessionCookieOf(t, signIn)

	resp := api.Post("/api/auth/verify-password", map[string]any{
		"password": "password123",
	}, "Cookie: "+cookie)
	if resp.Code != 200 || !strings.Contains(resp.Body.String(), `"status":true`) {
		t.Fatalf("correct password = %d, want 200 status:true: %s", resp.Code, resp.Body.String())
	}

	resp = api.Post("/api/auth/verify-password", map[string]any{
		"password": "wrong-password",
	}, "Cookie: "+cookie)
	if resp.Code != 400 {
		t.Fatalf("wrong password = %d, want 400: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), types.ErrInvalidPassword) {
		t.Fatalf("want INVALID_PASSWORD, got %s", resp.Body.String())
	}

	resp = api.Post("/api/auth/verify-password", map[string]any{
		"password": "password123",
	})
	if resp.Code != 401 {
		t.Fatalf("missing session = %d, want 401: %s", resp.Code, resp.Body.String())
	}
}

// password.test.ts "shouldn't allow the token to be used twice" at the HTTP
func TestPasswordReset_ResetTokenSingleUseHTTP(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	var token string
	opts.EmailAndPassword.SendResetPassword = func(data types.ResetPasswordData) error {
		token = data.Token
		return nil
	}
	api := credsPasswordAPI(t, opts)
	credsSignInSeed(t, api, "reset-once@test.com", "password123")
	if resp := api.Post("/api/auth/request-password-reset", map[string]any{
		"email": "reset-once@test.com",
	}); resp.Code != 200 {
		t.Fatalf("request reset = %d: %s", resp.Code, resp.Body.String())
	}
	if token == "" {
		t.Fatal("expected a reset token")
	}
	resp := api.Post("/api/auth/reset-password", map[string]any{
		"token": token, "newPassword": "brand-new-password-123",
	})
	if resp.Code != 200 || !strings.Contains(resp.Body.String(), `"status":true`) {
		t.Fatalf("first reset = %d, want 200 status:true: %s", resp.Code, resp.Body.String())
	}
	resp = api.Post("/api/auth/reset-password", map[string]any{
		"token": token, "newPassword": "another-new-password-123",
	})
	if resp.Code != 400 || !strings.Contains(resp.Body.String(), types.ErrInvalidToken) {
		t.Fatalf("replay = %d, want 400 INVALID_TOKEN: %s", resp.Code, resp.Body.String())
	}
	signIn := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": "reset-once@test.com", "password": "brand-new-password-123",
	})
	if signIn.Code != 200 {
		t.Fatalf("sign-in with new password = %d: %s", signIn.Code, signIn.Body.String())
	}
}

// password.test.ts "should expire" (callback leg): GET
func TestPasswordReset_ResetCallbackRedirect(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	var token string
	opts.EmailAndPassword.SendResetPassword = func(data types.ResetPasswordData) error {
		token = data.Token
		return nil
	}
	api := credsPasswordAPI(t, opts)
	credsSignInSeed(t, api, "reset-cb2@test.com", "password123")
	if resp := api.Post("/api/auth/request-password-reset", map[string]any{
		"email": "reset-cb2@test.com",
	}); resp.Code != 200 {
		t.Fatalf("request reset = %d: %s", resp.Code, resp.Body.String())
	}
	if token == "" {
		t.Fatal("expected a reset token")
	}
	resp := api.Get("/api/auth/reset-password/" + url.PathEscape(token) + "?callbackURL=" + url.QueryEscape("/cb"))
	if resp.Code != 302 {
		t.Fatalf("live token status = %d, want 302: %s", resp.Code, resp.Body.String())
	}
	loc := resp.Header().Get("Location")
	if !strings.Contains(loc, "token="+token) || strings.Contains(loc, "error") {
		t.Fatalf("live token must redirect with the token, got %q", loc)
	}
	bogus := api.Get("/api/auth/reset-password/does-not-exist?callbackURL=" + url.QueryEscape("/cb"))
	if bogus.Code != 302 {
		t.Fatalf("bogus token status = %d, want 302: %s", bogus.Code, bogus.Body.String())
	}
	if loc := bogus.Header().Get("Location"); !strings.Contains(loc, "error=INVALID_TOKEN") {
		t.Fatalf("bogus token must redirect with error, got %q", loc)
	}
}
