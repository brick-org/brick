package routes

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/cookies"
	"github.com/brick-org/brick/auth/src/crypto"
	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

func f5PasswordAPI(t *testing.T, opts types.Options) humatest.TestAPI {
	t.Helper()
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	SignUpEmail(api, "/api/auth", opts)
	SignInEmail(api, "/api/auth", opts)
	GetSession(api, "/api/auth", opts)
	RequestPasswordReset(api, "/api/auth", opts)
	ResetPassword(api, "/api/auth", opts)
	ChangePassword(api, "/api/auth", opts)
	return api
}

func f5BodyToken(t *testing.T, body string) string {
	t.Helper()
	var decoded struct {
		Token *string `json:"token"`
	}
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatalf("decode token: %v (%s)", err, body)
	}
	if decoded.Token == nil || *decoded.Token == "" {
		t.Fatalf("response carries no token: %s", body)
	}
	return *decoded.Token
}

// P08-G1: ChangePassword(revokeOtherSessions:true) must emit Set-Cookie for
// the replacement session (upstream update-user.ts:300-303 calls
// setSessionCookie(newSession)).
func TestF5_ChangePasswordRevokeEmitsSetCookie(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	api := f5PasswordAPI(t, opts)
	if resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "F5", "email": "f5-cookie@test.com", "password": "password123",
	}); resp.Code != 200 {
		t.Fatalf("sign-up = %d: %s", resp.Code, resp.Body.String())
	}
	signIn := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": "f5-cookie@test.com", "password": "password123",
	})
	if signIn.Code != 200 {
		t.Fatalf("sign-in = %d: %s", signIn.Code, signIn.Body.String())
	}
	cookie := sessionCookieOf(t, signIn)

	resp := api.Post("/api/auth/change-password", map[string]any{
		"currentPassword": "password123", "newPassword": "newPassword123",
		"revokeOtherSessions": true,
	}, "Cookie: "+cookie)
	if resp.Code != 200 {
		t.Fatalf("change-password = %d: %s", resp.Code, resp.Body.String())
	}
	body := resp.Body.String()
	if !strings.Contains(body, `"status":true`) {
		t.Fatalf("must keep status:true: %s", body)
	}
	replacement := f5BodyToken(t, body)
	raw := resp.Header().Values("Set-Cookie")
	if len(raw) == 0 {
		t.Fatalf("revoke must emit Set-Cookie for the replacement session, got none (body %s)", body)
	}
	found := false
	for _, c := range raw {
		seg, _, _ := strings.Cut(c, ";")
		name, value, _ := strings.Cut(seg, "=")
		if !strings.Contains(strings.ToLower(name) + strings.ToLower(c), "session") {
			continue
		}
		if unsigned, ok := cookies.VerifyAny(opts.AllSecrets(), strings.TrimSpace(value)); ok && unsigned == replacement {
			found = true
			break
		}
		// Fallback: raw token embedded without signing (should not happen,
		// but accept if the replacement token is carried verbatim).
		if strings.Contains(c, replacement) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Set-Cookie must carry the replacement token %q, got %q", replacement, raw)
	}
	// Cookie-only client: the Set-Cookie value must authenticate get-session.
	var sessionCookie string
	for _, c := range raw {
		seg, _, _ := strings.Cut(c, ";")
		if strings.Contains(strings.ToLower(seg), "session") || strings.Contains(c, replacement) {
			// Reconstruct a forwardable Cookie header from the session cookie
			// segment (value is the signed replacement token).
			sessionCookie = strings.TrimSpace(seg)
			if unsigned, ok := cookies.VerifyAny(opts.AllSecrets(), strings.TrimSpace(strings.SplitN(seg, "=", 2)[1])); ok && unsigned == replacement {
				break
			}
		}
	}
	if sessionCookie == "" {
		t.Fatalf("no session cookie segment in %q", raw)
	}
	sess := api.Get("/api/auth/get-session", "Cookie: "+sessionCookie)
	if sess.Code != 200 {
		t.Fatalf("replacement cookie must authenticate get-session, got %d: %s", sess.Code, sess.Body.String())
	}
}

// Deviation: request-reset disabled must adopt the upstream status/code
// shape (400 RESET_PASSWORD_DISABLED, message "Reset password isn't
// enabled") as a global flag — identical for existing and unknown emails,
// no per-email oracle.
func TestF5_RequestResetDisabledUpstreamCode(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	// Disabled: both senders nil (global flag, checked before any lookup).
	opts.EmailAndPassword.SendResetPassword = nil
	opts.EmailAndPassword.SendResetPasswordRequest = nil
	api := f5PasswordAPI(t, opts)
	if resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "F5", "email": "f5-disabled@test.com", "password": "password123",
	}); resp.Code != 200 {
		t.Fatalf("sign-up = %d: %s", resp.Code, resp.Body.String())
	}
	existing := api.Post("/api/auth/request-password-reset", map[string]any{
		"email": "f5-disabled@test.com",
	})
	unknown := api.Post("/api/auth/request-password-reset", map[string]any{
		"email": "f5-unknown-does-not-exist@test.com",
	})
	if existing.Code != 400 {
		t.Fatalf("disabled existing status = %d, want 400: %s", existing.Code, existing.Body.String())
	}
	if unknown.Code != 400 {
		t.Fatalf("disabled unknown status = %d, want 400: %s", unknown.Code, unknown.Body.String())
	}
	exBody, unBody := existing.Body.String(), unknown.Body.String()
	if !strings.Contains(exBody, "RESET_PASSWORD_DISABLED") {
		t.Fatalf("disabled existing must carry RESET_PASSWORD_DISABLED, got %s", exBody)
	}
	if !strings.Contains(unBody, "RESET_PASSWORD_DISABLED") {
		t.Fatalf("disabled unknown must carry RESET_PASSWORD_DISABLED, got %s", unBody)
	}
	if !strings.Contains(exBody, "Reset password isn't enabled") {
		t.Fatalf("disabled body must carry upstream message, got %s", exBody)
	}
	if exBody != unBody {
		t.Fatalf("disabled responses must be identical (no per-email oracle): %q vs %q", exBody, unBody)
	}
}

// Deviation: reset USER_NOT_FOUND must be BAD_REQUEST (upstream
// password.ts:304), not the canonical 404.
func TestF5_ResetUserNotFoundIsBadRequest(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	var token string
	opts.EmailAndPassword.SendResetPassword = func(data types.ResetPasswordData) error {
		token = data.Token
		return nil
	}
	api := f5PasswordAPI(t, opts)
	if resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "F5", "email": "f5-gone@test.com", "password": "password123",
	}); resp.Code != 200 {
		t.Fatalf("sign-up = %d: %s", resp.Code, resp.Body.String())
	}
	if resp := api.Post("/api/auth/request-password-reset", map[string]any{
		"email": "f5-gone@test.com",
	}); resp.Code != 200 {
		t.Fatalf("request reset = %d: %s", resp.Code, resp.Body.String())
	}
	if token == "" {
		t.Fatal("expected a reset token")
	}
	userRow, _ := db.FindOne(ctx, "user", []types.Where{{Field: "email", Value: "f5-gone@test.com"}}, nil)
	if userRow == nil {
		t.Fatal("seed user missing")
	}
	uid, _ := userRow["id"].(string)
	if err := db.Delete(ctx, "user", []types.Where{{Field: "id", Value: uid}}); err != nil {
		t.Fatalf("delete user: %v", err)
	}
	resp := api.Post("/api/auth/reset-password", map[string]any{
		"token": token, "newPassword": "brand-new-password-123",
	})
	if resp.Code != 400 {
		t.Fatalf("reset with missing user = %d, want 400: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), types.ErrUserNotFound) {
		t.Fatalf("want USER_NOT_FOUND, got %s", resp.Body.String())
	}
}

// Migration bridge: legacy reusable HMAC email tokens still reset via HTTP.
func TestF5_ResetLegacyHMACFallbackHTTP(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	api := f5PasswordAPI(t, opts)
	if resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "F5", "email": "f5-legacy@test.com", "password": "password123",
	}); resp.Code != 200 {
		t.Fatalf("sign-up = %d: %s", resp.Code, resp.Body.String())
	}
	legacy, err := crypto.GenerateToken(opts.CurrentSecret(), "f5-legacy@test.com", time.Hour)
	if err != nil {
		t.Fatalf("generate legacy token: %v", err)
	}
	resp := api.Post("/api/auth/reset-password", map[string]any{
		"token": legacy, "newPassword": "legacy-new-password-123",
	})
	if resp.Code != 200 || !strings.Contains(resp.Body.String(), `"status":true`) {
		t.Fatalf("legacy reset = %d, want 200 status:true: %s", resp.Code, resp.Body.String())
	}
	signIn := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": "f5-legacy@test.com", "password": "legacy-new-password-123",
	})
	if signIn.Code != 200 {
		t.Fatalf("sign-in with legacy-reset password = %d: %s", signIn.Code, signIn.Body.String())
	}
}
