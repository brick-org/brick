package routes

import (
	"context"
	"strings"
	"testing"

	"github.com/brick-org/brick/auth/src/types"
)

// C5: POST /delete-user with an invalid single-use token must 404 (upstream
// deleteUserCallback throws NOT_FOUND on bad/owner-mismatch tokens,
// update-user.ts:641-642), matching the GET callback path. User survives.
func TestC5_DeleteUserInvalidTokenNotFound(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.User.DeleteUser.Enabled = true
	freshAge := 1000
	opts.Session.FreshAge = &freshAge
	api := credsAccountAPI(t, opts)
	email := "c5-invalid-token@test.com"
	credsSignInSeed(t, api, email, "password123")
	cookie := credsAuthCookie(t, api, email, "password123")

	resp := api.Post("/api/auth/delete-user", map[string]any{
		"token": "c5-invalid-token-xyz",
	}, "Cookie: "+cookie)
	if resp.Code != 404 || !strings.Contains(resp.Body.String(), types.ErrInvalidToken) {
		t.Fatalf("invalid token = %d, want 404 INVALID_TOKEN: %s", resp.Code, resp.Body.String())
	}
	if row, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: email}}, nil); row == nil {
		t.Fatal("user must survive an invalid token")
	}
}

// C5: a wrong-owner delete token is still burned by the single-use consume
// (upstream update-user.ts:634-643) while answering 404 and deleting nobody.
func TestC5_DeleteUserWrongOwnerBurnsToken(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.User.DeleteUser.Enabled = true
	freshAge := 1000
	opts.Session.FreshAge = &freshAge
	api := credsAccountAPI(t, opts)
	emailA := "c5-owner-a@test.com"
	emailB := "c5-owner-b@test.com"
	credsSignInSeed(t, api, emailA, "password123")
	credsSignInSeed(t, api, emailB, "password123")
	cookieB := credsAuthCookie(t, api, emailB, "password123")
	cookieA := credsAuthCookie(t, api, emailA, "password123")

	userAID := g7UserID(t, db, emailA)
	token, err := createDeleteAccountVerification(context.Background(), opts, userAID)
	if err != nil || token == "" {
		t.Fatalf("mint delete token: %v", err)
	}

	resp := api.Post("/api/auth/delete-user", map[string]any{
		"token": token,
	}, "Cookie: "+cookieB)
	if resp.Code != 404 || !strings.Contains(resp.Body.String(), types.ErrInvalidToken) {
		t.Fatalf("wrong-owner token = %d, want 404 INVALID_TOKEN: %s", resp.Code, resp.Body.String())
	}
	for _, email := range []string{emailA, emailB} {
		if row, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: email}}, nil); row == nil {
			t.Fatalf("user %s must survive a wrong-owner token", email)
		}
	}
	// Token was burned: the rightful owner can no longer use it either.
	retry := api.Post("/api/auth/delete-user", map[string]any{
		"token": token,
	}, "Cookie: "+cookieA)
	if retry.Code != 404 || !strings.Contains(retry.Body.String(), types.ErrInvalidToken) {
		t.Fatalf("replayed burned token = %d, want 404 INVALID_TOKEN: %s", retry.Code, retry.Body.String())
	}
	if row, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: emailA}}, nil); row == nil {
		t.Fatal("owner must survive a burned-token replay")
	}
}
