package routes

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/crypto"
	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

// Credential-residual triage ports. Pinned upstream: Better Auth v1.7.5 @
// 5468e6bf (sign-up/sign-in/account/update-user/password/email-verification
// route tests). Only passing tests stay; behavior failures are reported as
// FEATURE-GAPs with the probe deleted.

func triageCredsAPI(t *testing.T, opts types.Options) humatest.TestAPI {
	t.Helper()
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	SignUpEmail(api, "/api/auth", opts)
	SignInEmail(api, "/api/auth", opts)
	GetSession(api, "/api/auth", opts)
	UpdateUser(api, "/api/auth", opts)
	ChangeEmail(api, "/api/auth", opts)
	ChangePassword(api, "/api/auth", opts)
	DeleteUser(api, "/api/auth", opts)
	DeleteUserCallback(api, "/api/auth", opts)
	RequestPasswordReset(api, "/api/auth", opts)
	ResetPassword(api, "/api/auth", opts)
	RequestPasswordResetCallback(api, "/api/auth", opts)
	VerifyPassword(api, "/api/auth", opts)
	SendVerificationEmail(api, "/api/auth", opts)
	VerifyEmail(api, "/api/auth", opts)
	return api
}

func triagePostSignUp(t *testing.T, api humatest.TestAPI, name, email, password string) *httptest.ResponseRecorder {
	t.Helper()
	resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": name, "email": email, "password": password,
	})
	if resp.Code != 200 {
		t.Fatalf("sign-up %s = %d: %s", email, resp.Code, resp.Body.String())
	}
	return resp
}

func triageTokenOf(t *testing.T, resp *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Token *string `json:"token"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode token: %v", err)
	}
	if body.Token == nil || *body.Token == "" {
		t.Fatalf("expected a session token, got %s", resp.Body.String())
	}
	return *body.Token
}

// --- sign-up residual ---

// sign-up.test.ts "should allow email/password sign-up when validateUserInfo
// returns void": the gate observes action create-user / method email-password
// and the user persists.
func TestTriageV1_SignUpValidateUserInfoAllows(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	var action types.ValidateUserInfoAction
	var method types.ValidateUserInfoMethod
	var gatedEmail string
	opts.User.ValidateUserInfo = func(data types.ValidateUserInfoData, _ types.EndpointContext) (*types.ValidateUserInfoResult, error) {
		action, method = data.Source.Action, data.Source.Method
		gatedEmail, _ = data.User["email"].(string)
		return nil, nil
	}
	api := triageCredsAPI(t, opts)
	resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "Allowed User", "email": "allowed@test.com", "password": "password123",
	})
	if resp.Code != 200 {
		t.Fatalf("status = %d, want 200: %s", resp.Code, resp.Body.String())
	}
	if action != types.ValidateUserInfoActionCreateUser || method != types.ValidateUserInfoMethodEmailPassword {
		t.Fatalf("source = %q/%q, want create-user/email-password", action, method)
	}
	if gatedEmail != "allowed@test.com" {
		t.Fatalf("gated email = %q", gatedEmail)
	}
	row, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: "allowed@test.com"}}, nil)
	if row == nil {
		t.Fatal("allowed sign-up must persist a user")
	}
}

// sign-up.test.ts "should return token: null for new sign-up when autoSignIn
// is disabled".
func TestTriageV1_SignUpAutoSignInFalseTokenNull(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.EmailAndPassword.AutoSignIn = credsFalsePtr()
	api := triageCredsAPI(t, opts)
	resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "New User", "email": "new-auto-signin@test.com", "password": "password123",
	})
	if resp.Code != 200 {
		t.Fatalf("status = %d: %s", resp.Code, resp.Body.String())
	}
	var body struct {
		Token *string `json:"token"`
		User  struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Token != nil {
		t.Fatalf("token = %q, want null", *body.Token)
	}
	if body.User.Email != "new-auto-signin@test.com" {
		t.Fatalf("email = %q", body.User.Email)
	}
}

// sign-up.test.ts "should send verification email when sendOnSignUp is true".
func TestTriageV1_SignUpSendOnSignUpTrue(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.EmailAndPassword.RequireEmailVerification = true
	opts.EmailVerification.SendOnSignUp = boolPtr(true)
	var calls int
	opts.EmailVerification.SendVerificationEmail = func(types.VerificationEmailData) error {
		calls++
		return nil
	}
	api := triageCredsAPI(t, opts)
	triagePostSignUp(t, api, "With Verification", "with-verification@test.com", "password123")
	if calls != 1 {
		t.Fatalf("send calls = %d, want 1", calls)
	}
}

// sign-up.test.ts "should send verification email when sendOnSignUp is not
// set but requireEmailVerification is true (default)".
func TestTriageV1_SignUpSendOnSignUpDefault(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.EmailAndPassword.RequireEmailVerification = true
	var calls int
	opts.EmailVerification.SendVerificationEmail = func(types.VerificationEmailData) error {
		calls++
		return nil
	}
	api := triageCredsAPI(t, opts)
	triagePostSignUp(t, api, "Default Verification", "default-verification@test.com", "password123")
	if calls != 1 {
		t.Fatalf("send calls = %d, want 1", calls)
	}
}

// sign-up.test.ts "should not call onExistingUserSignUp when enumeration
// protection is inactive": the duplicate throws and the hook stays silent.
func TestTriageV1_SignUpExistingHookSkippedWhenInactive(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	var calls int
	opts.EmailAndPassword.OnExistingUserSignUp = func(types.ExistingUserSignUpData) error {
		calls++
		return nil
	}
	api := triageCredsAPI(t, opts)
	triagePostSignUp(t, api, "No Enum", "callback-noenum@test.com", "password123")
	resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "No Enum", "email": "callback-noenum@test.com", "password": "password123",
	})
	if resp.Code == 200 {
		t.Fatalf("inactive-protection duplicate must fail, got 200: %s", resp.Body.String())
	}
	if calls != 0 {
		t.Fatalf("hook calls = %d, want 0", calls)
	}
}

// sign-up.test.ts "should not call onExistingUserSignUp for new user
// sign-ups".
func TestTriageV1_SignUpExistingHookSkippedForNewUser(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.EmailAndPassword.RequireEmailVerification = true
	var calls int
	opts.EmailAndPassword.OnExistingUserSignUp = func(types.ExistingUserSignUpData) error {
		calls++
		return nil
	}
	api := triageCredsAPI(t, opts)
	triagePostSignUp(t, api, "Brand New", "brand-new-user@test.com", "password123")
	if calls != 0 {
		t.Fatalf("hook calls = %d, want 0 for a new user", calls)
	}
}

// --- sign-in residual ---

// sign-in.test.ts "should return a response with a set-cookie header".
func TestTriageV1_SignInSetsSessionCookie(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	api := triageCredsAPI(t, opts)
	triagePostSignUp(t, api, "Seed", "cookie-user@test.com", "password123")
	resp := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": "cookie-user@test.com", "password": "password123",
	})
	if resp.Code != 200 {
		t.Fatalf("sign-in = %d: %s", resp.Code, resp.Body.String())
	}
	found := false
	for _, raw := range resp.Header().Values("Set-Cookie") {
		if strings.Contains(raw, "session") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("sign-in must set a session cookie, got %q", resp.Header().Values("Set-Cookie"))
	}
	if token := triageTokenOf(t, resp); token == "" {
		t.Fatal("sign-in must return a token")
	}
}

// sign-in.test.ts "verification email will not be sent if sendOnSignIn is
// disabled": unverified sign-in still 403s but never resends.
func TestTriageV1_SignInNoResendWhenDisabled(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.EmailAndPassword.RequireEmailVerification = true
	opts.EmailVerification.SendOnSignIn = false
	var calls int
	opts.EmailVerification.SendVerificationEmail = func(types.VerificationEmailData) error {
		calls++
		return nil
	}
	api := triageCredsAPI(t, opts)
	triagePostSignUp(t, api, "Unverified", "no-resend@test.com", "password123")
	calls = 0 // isolate the sign-in resend (sign-up itself sends once)
	resp := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": "no-resend@test.com", "password": "password123",
	})
	if resp.Code != 403 {
		t.Fatalf("status = %d, want 403 EMAIL_NOT_VERIFIED: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), types.ErrEmailNotVerified) {
		t.Fatalf("want EMAIL_NOT_VERIFIED, got %s", resp.Body.String())
	}
	if calls != 0 {
		t.Fatalf("resend calls = %d, want 0", calls)
	}
}

// --- update-user residual ---

// update-user.test.ts "should update the user's password": the new password
// signs in, the old one stops working.
func TestTriageV1_ChangePasswordSuccessRotatesCredentials(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	api := triageCredsAPI(t, opts)
	triagePostSignUp(t, api, "PW", "chg-ok@test.com", "password123")
	cookie := credsAuthCookie(t, api, "chg-ok@test.com", "password123")
	resp := api.Post("/api/auth/change-password", map[string]any{
		"currentPassword": "password123", "newPassword": "newPassword123",
	}, "Cookie: "+cookie)
	if resp.Code != 200 || !strings.Contains(resp.Body.String(), `"status":true`) {
		t.Fatalf("change = %d, want 200 status:true: %s", resp.Code, resp.Body.String())
	}
	if signIn := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": "chg-ok@test.com", "password": "newPassword123",
	}); signIn.Code != 200 {
		t.Fatalf("new password sign-in = %d: %s", signIn.Code, signIn.Body.String())
	}
	if signIn := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": "chg-ok@test.com", "password": "password123",
	}); signIn.Code == 200 {
		t.Fatal("old password must stop working after change")
	}
}

// update-user.test.ts "should update account's updatedAt when changing
// password".
func TestTriageV1_ChangePasswordBumpsAccountUpdatedAt(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	api := triageCredsAPI(t, opts)
	triagePostSignUp(t, api, "Updated At", "test-updated-at@email.com", "originalPassword123")
	userRow, _ := db.FindOne(ctx, "user", []types.Where{{Field: "email", Value: "test-updated-at@email.com"}}, nil)
	if userRow == nil {
		t.Fatal("seed user missing")
	}
	beforeRow, _ := db.FindOne(ctx, "account", []types.Where{
		{Field: "userId", Value: userRow["id"]},
		{Field: "providerId", Value: "credential", Connector: "AND"},
	}, nil)
	before, ok := timeField(beforeRow, "updated_at", "updatedAt")
	if !ok {
		t.Fatal("account row missing updatedAt")
	}
	cookie := credsAuthCookie(t, api, "test-updated-at@email.com", "originalPassword123")
	if resp := api.Post("/api/auth/change-password", map[string]any{
		"currentPassword": "originalPassword123", "newPassword": "newPassword123",
	}, "Cookie: "+cookie); resp.Code != 200 {
		t.Fatalf("change = %d: %s", resp.Code, resp.Body.String())
	}
	afterRow, _ := db.FindOne(ctx, "account", []types.Where{
		{Field: "userId", Value: userRow["id"]},
		{Field: "providerId", Value: "credential", Connector: "AND"},
	}, nil)
	after, ok := timeField(afterRow, "updated_at", "updatedAt")
	if !ok {
		t.Fatal("account row missing updatedAt after change")
	}
	if !after.After(before) {
		t.Fatalf("updatedAt did not advance: %v -> %v", before, after)
	}
}

// update-user.test.ts "should not delete user if deleteUser is disabled".
func TestTriageV1_DeleteUserDisabledIs404(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	api := triageCredsAPI(t, opts)
	triagePostSignUp(t, api, "Locked", "locked@test.com", "password123")
	cookie := credsAuthCookie(t, api, "locked@test.com", "password123")
	resp := api.Post("/api/auth/delete-user", map[string]any{}, "Cookie: "+cookie)
	if resp.Code != 404 {
		t.Fatalf("disabled delete-user = %d, want 404: %s", resp.Code, resp.Body.String())
	}
	row, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: "locked@test.com"}}, nil)
	if row == nil {
		t.Fatal("disabled delete must not remove the user")
	}
}

// update-user.test.ts "should ignore cookie cache for sensitive operations
// like changePassword": with the cookie cache enabled, the password change
// validates against the database and the revoked session stays dead.
func TestTriageV1_ChangePasswordIgnoresCookieCache(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.Session.CookieCache.Enabled = true
	opts.Session.CookieCache.MaxAge = 60
	api := triageCredsAPI(t, opts)
	signUp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "Cache Test User", "email": "cache-chgpw@test.com", "password": "testPassword123",
	})
	if signUp.Code != 200 {
		t.Fatalf("sign-up = %d: %s", signUp.Code, signUp.Body.String())
	}
	token := triageTokenOf(t, signUp)
	header := cacheHeaderFor(t, ctx, opts, token)
	resp := api.Post("/api/auth/change-password", map[string]any{
		"currentPassword": "testPassword123", "newPassword": "newSecurePassword123",
		"revokeOtherSessions": true,
	}, "Cookie: "+header)
	if resp.Code != 200 || !strings.Contains(resp.Body.String(), `"status":true`) {
		t.Fatalf("change with cache header = %d, want 200 status:true: %s", resp.Code, resp.Body.String())
	}
	// The raw (cache-less) token is revoked: without the stale cache to
	// serve from, the session reads as upstream 200 null.
	sess := api.Get("/api/auth/get-session", "Cookie: "+signedSessionHeader(t, opts, token))
	if sess.Code != 200 || !strings.Contains(sess.Body.String(), `"session":null`) || !strings.Contains(sess.Body.String(), `"user":null`) {
		t.Fatalf("revoked session must read 200 null, got %d: %s", sess.Code, sess.Body.String())
	}
}

// --- password residual ---

// password.test.ts "should fail on invalid password": a short new password is
// a 400.
func TestTriageV1_ResetShortPasswordRejected(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	var token string
	opts.EmailAndPassword.SendResetPassword = func(data types.ResetPasswordData) error {
		token = data.Token
		return nil
	}
	api := triageCredsAPI(t, opts)
	triagePostSignUp(t, api, "Short", "reset-short@test.com", "password123")
	if resp := api.Post("/api/auth/request-password-reset", map[string]any{
		"email": "reset-short@test.com",
	}); resp.Code != 200 {
		t.Fatalf("request = %d: %s", resp.Code, resp.Body.String())
	}
	if token == "" {
		t.Fatal("expected a reset token")
	}
	resp := api.Post("/api/auth/reset-password", map[string]any{
		"token": token, "newPassword": "short",
	})
	if resp.Code != 400 {
		t.Fatalf("short password = %d, want 400: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), types.ErrPasswordTooShort) {
		t.Fatalf("want PASSWORD_TOO_SHORT, got %s", resp.Body.String())
	}
}

// password.test.ts "should send a reset password email when enabled" (token
// length leg): the reset URL carries a long single-use token.
func TestTriageV1_ResetEmailCarriesLongToken(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.TrustedOrigins = []string{"http://localhost:3000"}
	var token, resetURL string
	opts.EmailAndPassword.SendResetPassword = func(data types.ResetPasswordData) error {
		token, resetURL = data.Token, data.URL
		return nil
	}
	api := triageCredsAPI(t, opts)
	triagePostSignUp(t, api, "Token", "reset-tokenlen@test.com", "password123")
	if resp := api.Post("/api/auth/request-password-reset", map[string]any{
		"email": "reset-tokenlen@test.com", "redirectTo": "http://localhost:3000",
	}); resp.Code != 200 {
		t.Fatalf("request = %d: %s", resp.Code, resp.Body.String())
	}
	if len(token) <= 10 {
		t.Fatalf("token length = %d, want > 10", len(token))
	}
	if !strings.Contains(resetURL, token) {
		t.Fatalf("reset URL must carry the token, got %q", resetURL)
	}
}

// password.test.ts "should update account's updatedAt when resetting
// password".
func TestTriageV1_ResetBumpsAccountUpdatedAt(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.TrustedOrigins = []string{"http://localhost:3000"}
	var token string
	opts.EmailAndPassword.SendResetPassword = func(data types.ResetPasswordData) error {
		token = data.Token
		return nil
	}
	api := triageCredsAPI(t, opts)
	triagePostSignUp(t, api, "Reset Updated", "test-reset-updated@email.com", "originalPassword123")
	userRow, _ := db.FindOne(ctx, "user", []types.Where{{Field: "email", Value: "test-reset-updated@email.com"}}, nil)
	if userRow == nil {
		t.Fatal("seed user missing")
	}
	acctWhere := []types.Where{
		{Field: "userId", Value: userRow["id"]},
		{Field: "providerId", Value: "credential", Connector: "AND"},
	}
	beforeRow, _ := db.FindOne(ctx, "account", acctWhere, nil)
	before, ok := timeField(beforeRow, "updated_at", "updatedAt")
	if !ok {
		t.Fatal("account row missing updatedAt")
	}
	if resp := api.Post("/api/auth/request-password-reset", map[string]any{
		"email": "test-reset-updated@email.com", "redirectTo": "http://localhost:3000",
	}); resp.Code != 200 {
		t.Fatalf("request = %d: %s", resp.Code, resp.Body.String())
	}
	if token == "" {
		t.Fatal("expected a reset token")
	}
	if resp := api.Post("/api/auth/reset-password", map[string]any{
		"token": token, "newPassword": "newResetPassword123",
	}); resp.Code != 200 || !strings.Contains(resp.Body.String(), `"status":true`) {
		t.Fatalf("reset = %d, want 200 status:true: %s", resp.Code, resp.Body.String())
	}
	afterRow, _ := db.FindOne(ctx, "account", acctWhere, nil)
	after, ok := timeField(afterRow, "updated_at", "updatedAt")
	if !ok {
		t.Fatal("account row missing updatedAt after reset")
	}
	if !after.After(before) {
		t.Fatalf("updatedAt did not advance: %v -> %v", before, after)
	}
	if signIn := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": "test-reset-updated@email.com", "password": "newResetPassword123",
	}); signIn.Code != 200 {
		t.Fatalf("new password sign-in = %d: %s", signIn.Code, signIn.Body.String())
	}
}

// password.test.ts "should expire": an expired token is a 400 and the
// onPasswordReset hook does not fire again.
func TestTriageV1_ResetExpiredTokenRejected(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	var token string
	opts.EmailAndPassword.SendResetPassword = func(data types.ResetPasswordData) error {
		token = data.Token
		return nil
	}
	var resets int
	opts.EmailAndPassword.OnPasswordReset = func(types.PasswordResetData) error {
		resets++
		return nil
	}
	api := triageCredsAPI(t, opts)
	triagePostSignUp(t, api, "Expire", "reset-expire@test.com", "password123")
	if resp := api.Post("/api/auth/request-password-reset", map[string]any{
		"email": "reset-expire@test.com",
	}); resp.Code != 200 {
		t.Fatalf("request = %d: %s", resp.Code, resp.Body.String())
	}
	if resp := api.Post("/api/auth/reset-password", map[string]any{
		"token": token, "newPassword": "new-password-123",
	}); resp.Code != 200 {
		t.Fatalf("live reset = %d: %s", resp.Code, resp.Body.String())
	}
	if resets != 1 {
		t.Fatalf("hook calls = %d, want 1", resets)
	}
	if resp := api.Post("/api/auth/request-password-reset", map[string]any{
		"email": "reset-expire@test.com",
	}); resp.Code != 200 {
		t.Fatalf("second request = %d: %s", resp.Code, resp.Body.String())
	}
	rows, _ := db.FindMany(ctx, "verification", nil, 0, 0, nil, nil)
	var stored string
	for _, row := range rows {
		if id, _ := row["identifier"].(string); strings.Contains(id, token) {
			stored = id
			break
		}
	}
	if stored == "" {
		t.Fatal("reset verification row missing")
	}
	if _, err := db.Update(ctx, "verification", []types.Where{{Field: "identifier", Value: stored}},
		map[string]any{"expiresAt": time.Now().UTC().Add(-time.Hour)}); err != nil {
		t.Fatalf("expire row: %v", err)
	}
	resp := api.Post("/api/auth/reset-password", map[string]any{
		"token": token, "newPassword": "newer-password-123",
	})
	if resp.Code != 400 {
		t.Fatalf("expired reset = %d, want 400: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), types.ErrInvalidToken) {
		t.Fatalf("want INVALID_TOKEN, got %s", resp.Body.String())
	}
	if resets != 1 {
		t.Fatalf("hook calls = %d, want still 1", resets)
	}
}

// password.test.ts "should revoke other sessions when
// revokeSessionsOnPasswordReset is enabled".
func TestTriageV1_ResetRevokesSessionsWhenEnabled(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.EmailAndPassword.RevokeSessionsOnPasswordReset = true
	var token string
	opts.EmailAndPassword.SendResetPassword = func(data types.ResetPasswordData) error {
		token = data.Token
		return nil
	}
	api := triageCredsAPI(t, opts)
	signUp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "Revoke", "email": "reset-revoke@test.com", "password": "password123",
	})
	if signUp.Code != 200 {
		t.Fatalf("sign-up = %d: %s", signUp.Code, signUp.Body.String())
	}
	cookieA := sessionCookieOf(t, signUp)
	cookieB := credsAuthCookie(t, api, "reset-revoke@test.com", "password123")
	if resp := api.Post("/api/auth/request-password-reset", map[string]any{
		"email": "reset-revoke@test.com",
	}); resp.Code != 200 {
		t.Fatalf("request = %d: %s", resp.Code, resp.Body.String())
	}
	if resp := api.Post("/api/auth/reset-password", map[string]any{
		"token": token, "newPassword": "new-password-123",
	}); resp.Code != 200 {
		t.Fatalf("reset = %d: %s", resp.Code, resp.Body.String())
	}
	for i, cookie := range []string{cookieA, cookieB} {
		if sess := api.Get("/api/auth/get-session", "Cookie: "+cookie); sess.Code != 200 || !strings.Contains(sess.Body.String(), `"session":null`) {
			t.Fatalf("session %d must be revoked (200 null), got %d: %s", i, sess.Code, sess.Body.String())
		}
	}
}

// password.test.ts "should not revoke other sessions by default".
func TestTriageV1_ResetKeepsSessionsByDefault(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	var token string
	opts.EmailAndPassword.SendResetPassword = func(data types.ResetPasswordData) error {
		token = data.Token
		return nil
	}
	api := triageCredsAPI(t, opts)
	triagePostSignUp(t, api, "Keep", "reset-keep@test.com", "password123")
	cookie := credsAuthCookie(t, api, "reset-keep@test.com", "password123")
	if resp := api.Post("/api/auth/request-password-reset", map[string]any{
		"email": "reset-keep@test.com",
	}); resp.Code != 200 {
		t.Fatalf("request = %d: %s", resp.Code, resp.Body.String())
	}
	if resp := api.Post("/api/auth/reset-password", map[string]any{
		"token": token, "newPassword": "new-password-123",
	}); resp.Code != 200 {
		t.Fatalf("reset = %d: %s", resp.Code, resp.Body.String())
	}
	if sess := api.Get("/api/auth/get-session", "Cookie: "+cookie); sess.Code != 200 {
		t.Fatalf("session must survive by default, got %d: %s", sess.Code, sess.Body.String())
	}
}

// --- email-verification residual ---

// email-verification.test.ts "should sign after verification": with
// autoSignInAfterVerification the verify call mints a session and marks the
// address verified.
func TestTriageV1_VerifyEmailAutoSignInMintsSession(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.EmailVerification.AutoSignInAfterVerification = true
	var token string
	opts.EmailVerification.SendVerificationEmail = func(data types.VerificationEmailData) error {
		token = data.Token
		return nil
	}
	api := triageCredsAPI(t, opts)
	triagePostSignUp(t, api, "Verify Me", "autosignin-verify@test.com", "password123")
	if resp := api.Post("/api/auth/send-verification-email", map[string]any{
		"email": "autosignin-verify@test.com",
	}); resp.Code != 200 {
		t.Fatalf("send = %d: %s", resp.Code, resp.Body.String())
	}
	if token == "" {
		t.Fatal("expected a verification token")
	}
	verify := api.Post("/api/auth/verify-email", map[string]any{"token": token})
	if verify.Code != 200 || !strings.Contains(verify.Body.String(), `"status":true`) {
		t.Fatalf("verify = %d, want 200 status:true: %s", verify.Code, verify.Body.String())
	}
	if !strings.Contains(verify.Body.String(), `"emailVerified":true`) {
		t.Fatalf("user must be marked verified, got %s", verify.Body.String())
	}
	cookie := sessionCookieOf(t, verify)
	sess := api.Get("/api/auth/get-session", "Cookie: "+cookie)
	if sess.Code != 200 {
		t.Fatalf("minted session must serve, got %d: %s", sess.Code, sess.Body.String())
	}
	if !strings.Contains(sess.Body.String(), `"emailVerified":true`) {
		t.Fatalf("session user must be verified, got %s", sess.Body.String())
	}
}

// email-verification.test.ts "should use custom expiresIn": a token past its
// TTL reports TOKEN_EXPIRED without firing hooks; a live token verifies.
func TestTriageV1_VerifyEmailExpiredTokenRejected(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.EmailVerification.ExpiresIn = 10
	var after int
	opts.EmailVerification.AfterEmailVerification = func(*types.User) error {
		after++
		return nil
	}
	api := triageCredsAPI(t, opts)
	triagePostSignUp(t, api, "Expiry", "verify-expiry@test.com", "password123")
	expired, err := crypto.CreateEmailVerificationToken(opts.CurrentSecret(), "verify-expiry@test.com", "", -60, nil)
	if err != nil {
		t.Fatalf("craft expired token: %v", err)
	}
	resp := api.Post("/api/auth/verify-email", map[string]any{"token": expired})
	if !strings.Contains(resp.Body.String(), types.ErrTokenExpired) {
		t.Fatalf("want TOKEN_EXPIRED, got %d: %s", resp.Code, resp.Body.String())
	}
	if after != 0 {
		t.Fatalf("after hook calls = %d, want 0 for an expired token", after)
	}
	live, err := crypto.CreateEmailVerificationToken(opts.CurrentSecret(), "verify-expiry@test.com", "", 3600, nil)
	if err != nil {
		t.Fatalf("craft live token: %v", err)
	}
	if resp := api.Post("/api/auth/verify-email", map[string]any{"token": live}); resp.Code != 200 {
		t.Fatalf("live verify = %d: %s", resp.Code, resp.Body.String())
	}
	if after != 1 {
		t.Fatalf("after hook calls = %d, want 1", after)
	}
}

// email-verification.test.ts "should call afterEmailVerification callback
// when email is verified" (both duplicates): fired once with the verified
// user.
func TestTriageV1_VerifyEmailAfterHookFires(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	var got *types.User
	var calls int
	opts.EmailVerification.AfterEmailVerification = func(u *types.User) error {
		calls++
		got = u
		return nil
	}
	var token string
	opts.EmailVerification.SendVerificationEmail = func(data types.VerificationEmailData) error {
		token = data.Token
		return nil
	}
	api := triageCredsAPI(t, opts)
	triagePostSignUp(t, api, "Hooked", "after-hook@test.com", "password123")
	if resp := api.Post("/api/auth/send-verification-email", map[string]any{
		"email": "after-hook@test.com",
	}); resp.Code != 200 {
		t.Fatalf("send = %d: %s", resp.Code, resp.Body.String())
	}
	if resp := api.Post("/api/auth/verify-email", map[string]any{"token": token}); resp.Code != 200 {
		t.Fatalf("verify = %d: %s", resp.Code, resp.Body.String())
	}
	if calls != 1 {
		t.Fatalf("after hook calls = %d, want 1", calls)
	}
	if got == nil || got.Email != "after-hook@test.com" || !got.EmailVerified {
		t.Fatalf("after hook user = %#v, want verified after-hook@test.com", got)
	}
}

// email-verification.test.ts "should call beforeEmailVerification callback
// when email is verified".
func TestTriageV1_VerifyEmailBeforeHookFires(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	var got string
	var calls int
	opts.EmailVerification.BeforeEmailVerification = func(u *types.User) error {
		calls++
		got = u.Email
		return nil
	}
	var token string
	opts.EmailVerification.SendVerificationEmail = func(data types.VerificationEmailData) error {
		token = data.Token
		return nil
	}
	api := triageCredsAPI(t, opts)
	triagePostSignUp(t, api, "Before", "before-hook@test.com", "password123")
	if resp := api.Post("/api/auth/send-verification-email", map[string]any{
		"email": "before-hook@test.com",
	}); resp.Code != 200 {
		t.Fatalf("send = %d: %s", resp.Code, resp.Body.String())
	}
	if resp := api.Post("/api/auth/verify-email", map[string]any{"token": token}); resp.Code != 200 {
		t.Fatalf("verify = %d: %s", resp.Code, resp.Body.String())
	}
	if calls != 1 || got != "before-hook@test.com" {
		t.Fatalf("before hook calls = %d for %q, want 1 for before-hook@test.com", calls, got)
	}
}

// email-verification.test.ts "should properly encode callbackURL with query
// parameters when sending verification email".
func TestTriageV1_SendVerificationCallbackEncoding(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.TrustedOrigins = []string{"https://example.com"}
	var capturedURL string
	opts.EmailVerification.SendVerificationEmail = func(data types.VerificationEmailData) error {
		capturedURL = data.URL
		return nil
	}
	api := triageCredsAPI(t, opts)
	triagePostSignUp(t, api, "Encoder", "send-enc@test.com", "password123")
	callbackURL := "https://example.com/app?redirect=/dashboard&tab=settings"
	resp := api.Post("/api/auth/send-verification-email", map[string]any{
		"email": "send-enc@test.com", "callbackURL": callbackURL,
	})
	if resp.Code != 200 {
		t.Fatalf("send = %d: %s", resp.Code, resp.Body.String())
	}
	if capturedURL == "" {
		t.Fatal("expected a verification URL")
	}
	parsed, err := url.Parse(capturedURL)
	if err != nil {
		t.Fatalf("parse sent URL: %v", err)
	}
	if got := parsed.Query().Get("callbackURL"); got != callbackURL {
		t.Fatalf("callbackURL round-trip = %q, want %q", got, callbackURL)
	}
	if parsed.Query().Get("redirect") != "" || parsed.Query().Get("tab") != "" {
		t.Fatalf("query segments must not leak into the outer URL: %q", capturedURL)
	}
}

// email-verification.test.ts "should handle email case insensitivity when
// sending verification email while signed in".
func TestTriageV1_SendVerificationSignedInCaseInsensitive(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	var sentTo string
	var calls int
	opts.EmailVerification.SendVerificationEmail = func(data types.VerificationEmailData) error {
		calls++
		sentTo = data.User.Email
		return nil
	}
	api := triageCredsAPI(t, opts)
	mixed := "Test.Email.Case@Example.COM"
	signUp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "Test User", "email": mixed, "password": "password123",
	})
	if signUp.Code != 200 {
		t.Fatalf("sign-up = %d: %s", signUp.Code, signUp.Body.String())
	}
	var suBody struct {
		User struct {
			Email         string `json:"email"`
			EmailVerified bool   `json:"emailVerified"`
		} `json:"user"`
	}
	if err := json.Unmarshal(signUp.Body.Bytes(), &suBody); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if suBody.User.Email != strings.ToLower(mixed) || suBody.User.EmailVerified {
		t.Fatalf("signup user = %#v, want lowercase unverified", suBody.User)
	}
	cookie := sessionCookieOf(t, signUp)
	resp := api.Post("/api/auth/send-verification-email", map[string]any{
		"email": strings.ToUpper(mixed),
	}, "Cookie: "+cookie)
	if resp.Code != 200 || !strings.Contains(resp.Body.String(), `"status":true`) {
		t.Fatalf("send = %d, want 200 status:true: %s", resp.Code, resp.Body.String())
	}
	if calls != 1 || sentTo != strings.ToLower(mixed) {
		t.Fatalf("send calls = %d to %q, want 1 to %q", calls, sentTo, strings.ToLower(mixed))
	}
}
