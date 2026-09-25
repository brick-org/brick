package routes

import (
	"net/url"
	"strings"
	"testing"

	"github.com/brick-org/brick/auth/src/types"
)

// F7b trust legs: untrusted callbackURL must 403 INVALID_CALLBACK_URL.

func TestF7b_ChangeEmailUntrustedCallbackURL(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.User.ChangeEmail.Enabled = true
	opts.EmailVerification.SendVerificationEmail = func(types.VerificationEmailData) error { return nil }
	api := credsAccountAPI(t, opts)
	credsSignInSeed(t, api, "f7b-change@test.com", "password123")
	cookie := credsAuthCookie(t, api, "f7b-change@test.com", "password123")
	resp := api.Post("/api/auth/change-email", map[string]any{
		"newEmail":    "new-f7b@test.com",
		"callbackURL": "https://evil.example.com/cb",
	}, "Cookie: "+cookie)
	if resp.Code != 403 || !strings.Contains(resp.Body.String(), types.ErrInvalidCallbackURL) {
		t.Fatalf("change-email untrusted = %d, want 403 INVALID_CALLBACK_URL: %s", resp.Code, resp.Body.String())
	}
}

func TestF7b_DeleteUserUntrustedCallbackURL(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.User.DeleteUser.Enabled = true
	sent := false
	opts.User.DeleteUser.SendDeleteAccountVerification = func(types.DeleteAccountVerificationData) error {
		sent = true
		return nil
	}
	api := credsAccountAPI(t, opts)
	credsSignInSeed(t, api, "f7b-del@test.com", "password123")
	cookie := credsAuthCookie(t, api, "f7b-del@test.com", "password123")
	resp := api.Post("/api/auth/delete-user", map[string]any{
		"callbackURL": "https://evil.example.com/bye",
	}, "Cookie: "+cookie)
	if resp.Code != 403 || !strings.Contains(resp.Body.String(), types.ErrInvalidCallbackURL) {
		t.Fatalf("delete-user untrusted = %d, want 403 INVALID_CALLBACK_URL: %s", resp.Code, resp.Body.String())
	}
	if sent {
		t.Fatal("verification mail must not send on untrusted callbackURL")
	}
}

func TestF7b_ResetCallbackUntrustedCallbackURL(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.EmailAndPassword.SendResetPassword = func(types.ResetPasswordData) error { return nil }
	api := credsPasswordAPI(t, opts)
	resp := api.Get("/api/auth/reset-password/some-token?callbackURL=" + url.QueryEscape("https://evil.example.com/cb"))
	if resp.Code != 403 || !strings.Contains(resp.Body.String(), types.ErrInvalidCallbackURL) {
		t.Fatalf("reset-callback untrusted = %d, want 403 INVALID_CALLBACK_URL: %s", resp.Code, resp.Body.String())
	}
}
