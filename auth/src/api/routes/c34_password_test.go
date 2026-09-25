package routes

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

func c34PasswordAPI(t *testing.T, opts types.Options) humatest.TestAPI {
	t.Helper()
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	SignUpEmail(api, "/api/auth", opts)
	SignInEmail(api, "/api/auth", opts)
	ChangePassword(api, "/api/auth", opts)
	return api
}

// C34-1: ChangePassword revoke path must fail the route when the replacement
// session cookie cannot be minted (upstream await setSessionCookie rejects,
// update-user.ts:288-305). The already-minted session row is kept (upstream
// create-then-cookie order); only the route fails with 500.
func TestC34_ChangePasswordCookieMintFailure500s(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	var failCookies bool
	opts.Session.CookieCache.Enabled = true
	opts.Session.CookieCache.VersionFunc = func(types.Session, types.User) (string, error) {
		if failCookies {
			return "", errors.New("c34 test: cookie cache version failed")
		}
		return "1", nil
	}
	api := c34PasswordAPI(t, opts)
	if resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "C34", "email": "c34-cookie@test.com", "password": "password123",
	}); resp.Code != 200 {
		t.Fatalf("sign-up = %d: %s", resp.Code, resp.Body.String())
	}
	signIn := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": "c34-cookie@test.com", "password": "password123",
	})
	if signIn.Code != 200 {
		t.Fatalf("sign-in = %d: %s", signIn.Code, signIn.Body.String())
	}
	cookie := sessionCookieOf(t, signIn)

	failCookies = true
	resp := api.Post("/api/auth/change-password", map[string]any{
		"currentPassword": "password123", "newPassword": "newPassword123",
		"revokeOtherSessions": true,
	}, "Cookie: "+cookie)
	if resp.Code != 500 {
		t.Fatalf("change-password cookie failure = %d, want 500: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), types.ErrFailedToCreateSession) {
		t.Fatalf("body must carry %q: %s", types.ErrFailedToCreateSession, resp.Body.String())
	}
	// The minted replacement session row is kept (no rollback).
	n, err := db.Count(context.Background(), "session", nil)
	if err != nil || n == 0 {
		t.Fatalf("session rows = %d (err=%v), want >=1 (minted row kept)", n, err)
	}
}

// C34-2: ChangePassword revoke shape pins the kept compat field status:true
// plus token+user. Upstream is {token nullable, user required}
// (update-user.ts:186-243); status is additive but existing suites require
// it (TestCredsV1_ChangePasswordRevokesOthers,
// TestTriageV1_ChangePasswordSuccessRotatesCredentials,
// TestTriageV1_ChangePasswordIgnoresCookieCache,
// TestF5_ChangePasswordRevokeEmitsSetCookie,
// TestC702_ChangePasswordOrderAndRevoke), so it stays.
func TestC34_ChangePasswordShapeKeepsStatus(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	api := c34PasswordAPI(t, opts)
	if resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "C34", "email": "c34-shape@test.com", "password": "password123",
	}); resp.Code != 200 {
		t.Fatalf("sign-up = %d: %s", resp.Code, resp.Body.String())
	}
	signIn := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": "c34-shape@test.com", "password": "password123",
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
		t.Fatalf("revoke response must keep status:true: %s", body)
	}
	var decoded struct {
		Token *string        `json:"token"`
		User  map[string]any `json:"user"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
	if decoded.Token == nil || *decoded.Token == "" {
		t.Fatalf("revoke response must carry token: %s", body)
	}
	if decoded.User == nil || len(decoded.User) == 0 {
		t.Fatalf("revoke response must carry user: %s", body)
	}
	_ = db
}
