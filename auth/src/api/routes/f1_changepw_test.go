package routes

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

func f1ChangePwAPI(t *testing.T, opts types.Options) humatest.TestAPI {
	t.Helper()
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	SignUpEmail(api, "/api/auth", opts)
	SignInEmail(api, "/api/auth", opts)
	ChangePassword(api, "/api/auth", opts)
	return api
}

// Gap 1 (V3-08 §8 / upstream update-user.ts:287,304,307-310): non-revoke
// success must return {token:null, user} while keeping status:true.
func TestF1_ChangePasswordNonRevokeReturnsNullTokenAndUser(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	api := f1ChangePwAPI(t, opts)
	if resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "F1", "email": "f1-nonrevoke@test.com", "password": "password123",
	}); resp.Code != 200 {
		t.Fatalf("sign-up = %d: %s", resp.Code, resp.Body.String())
	}
	signIn := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": "f1-nonrevoke@test.com", "password": "password123",
	})
	if signIn.Code != 200 {
		t.Fatalf("sign-in = %d: %s", signIn.Code, signIn.Body.String())
	}
	cookie := sessionCookieOf(t, signIn)

	resp := api.Post("/api/auth/change-password", map[string]any{
		"currentPassword": "password123", "newPassword": "newPassword123",
	}, "Cookie: "+cookie)
	if resp.Code != 200 {
		t.Fatalf("change-password = %d: %s", resp.Code, resp.Body.String())
	}
	body := resp.Body.String()
	if !strings.Contains(body, `"status":true`) {
		t.Fatalf("non-revoke must keep status:true: %s", body)
	}
	// token must serialize as explicit null, not be omitted (omitempty watch).
	if !strings.Contains(body, `"token":null`) {
		t.Fatalf("non-revoke token must be null (not omitted): %s", body)
	}
	var raw map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
	tok, ok := raw["token"]
	if !ok {
		t.Fatalf("non-revoke body must carry token key: %s", body)
	}
	if tok != nil {
		t.Fatalf("non-revoke token must be null, got %#v (%s)", tok, body)
	}
	var decoded struct {
		User map[string]any `json:"user"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
	if decoded.User == nil || len(decoded.User) == 0 {
		t.Fatalf("non-revoke must carry user: %s", body)
	}
	if decoded.User["email"] != "f1-nonrevoke@test.com" {
		t.Fatalf("user.email = %#v, want f1-nonrevoke@test.com (%s)", decoded.User["email"], body)
	}
}

// Revoke path unchanged: fresh token + user + status:true.
func TestF1_ChangePasswordRevokeUnchanged(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	api := f1ChangePwAPI(t, opts)
	if resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "F1", "email": "f1-revoke@test.com", "password": "password123",
	}); resp.Code != 200 {
		t.Fatalf("sign-up = %d: %s", resp.Code, resp.Body.String())
	}
	signIn := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": "f1-revoke@test.com", "password": "password123",
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
		t.Fatalf("revoke must keep status:true: %s", body)
	}
	var decoded struct {
		Token *string        `json:"token"`
		User  map[string]any `json:"user"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
	if decoded.Token == nil || *decoded.Token == "" {
		t.Fatalf("revoke must carry fresh token: %s", body)
	}
	if decoded.User == nil || len(decoded.User) == 0 {
		t.Fatalf("revoke must carry user: %s", body)
	}
	if decoded.User["email"] != "f1-revoke@test.com" {
		t.Fatalf("user.email = %#v (%s)", decoded.User["email"], body)
	}
}
