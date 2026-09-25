package routes

import (
	"net/url"
	"strings"
	"testing"

	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

// Follow-ups to the wiring lane: the ChangeEmail direct-update leg and the
// GET /delete-user/callback hook mapping were flagged open in the agent
// report and closed at integration.

// ChangeEmail direct-update leg (unverified user +
// UpdateEmailWithoutVerification) must fan out to secondary sessions like
// UpdateUser post-commit (upstream updateUser -> refreshUserSessions).
func TestWiringV1_ChangeEmailDirectPropagatesToSecondary(t *testing.T) {
	db := newParityMemAdapter()
	store := newMapSecondaryStorage(true)
	opts := emailAuthTestOptions(db)
	opts.SecondaryStorage = store
	opts.User.ChangeEmail.Enabled = true
	opts.User.ChangeEmail.UpdateEmailWithoutVerification = true
	api := wiringSecondaryAPI(t, opts)
	first, second := wiringSignUpIn(t, api, "wire-chdirect@test.com", "password123")

	resp := api.Post("/api/auth/change-email", map[string]any{
		"newEmail": "wire-chdirect-new@test.com",
	}, "Cookie: "+signedSessionHeader(t, opts, first))
	if resp.Code != 200 {
		t.Fatalf("change-email = %d, want 200: %s", resp.Code, resp.Body.String())
	}
	for _, token := range []string{first, second} {
		cached, err := findSecondarySession(opts, token)
		if err != nil || cached == nil {
			t.Fatalf("token %s lookup: %v %v", token, cached, err)
		}
		if cached.User.Email != "wire-chdirect-new@test.com" {
			t.Fatalf("token %s cached email %q, want updated address", token, cached.User.Email)
		}
	}
}

// GET /delete-user/callback must propagate hook-thrown APIErrors instead of
// collapsing to 500 INVALID_USER (same errors.As pattern as the other
// delete/verify hook sites).
func TestWiringV1_DeleteCallbackHookAPIErrorPropagates(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.User.DeleteUser.Enabled = true
	opts.User.DeleteUser.BeforeDelete = func(*types.User) error {
		return types.HttpError{Code: "WIRING_CALLBACK_BLOCKED", Message: "blocked", Status: 403}
	}
	var token string
	opts.User.DeleteUser.SendDeleteAccountVerification = func(data types.DeleteAccountVerificationData) error {
		token = data.Token
		return nil
	}
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	SignUpEmail(api, "/api/auth", opts)
	SignInEmail(api, "/api/auth", opts)
	DeleteUser(api, "/api/auth", opts)
	DeleteUserCallback(api, "/api/auth", opts)
	credsSignInSeed(t, api, "wire-cb-hook@test.com", "password123")
	cookie := credsAuthCookie(t, api, "wire-cb-hook@test.com", "password123")

	start := api.Post("/api/auth/delete-user", map[string]any{
		"password": "password123",
	}, "Cookie: "+cookie)
	if start.Code != 200 {
		t.Fatalf("delete-user start = %d: %s", start.Code, start.Body.String())
	}
	resp := api.Get("/api/auth/delete-user/callback?token="+url.QueryEscape(token), "Cookie: "+cookie)
	if resp.Code != 403 || !strings.Contains(resp.Body.String(), "WIRING_CALLBACK_BLOCKED") {
		t.Fatalf("callback with throwing before-hook = %d, want 403 WIRING_CALLBACK_BLOCKED: %s", resp.Code, resp.Body.String())
	}
}
