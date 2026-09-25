package routes

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/types"
)

// R3: upstream token path returns early (update-user.ts:492-504) before the
// freshAge gate (:539-545), so stale-session + valid-token without password
// deletes upstream. Go over-gates via sessionIsFresh upfront
// (account.go:721-723) before token consume.

func g7BackdateLatestSession(t *testing.T, db *parityMemAdapter) {
	t.Helper()
	rows, _ := db.FindMany(context.Background(), "session", nil, 0, 0, nil, nil)
	if len(rows) == 0 {
		t.Fatal("seed session missing")
	}
	latest, _ := rows[len(rows)-1]["token"].(string)
	if latest == "" {
		t.Fatal("seed session has no token")
	}
	if _, err := db.Update(context.Background(), "session",
		[]types.Where{{Field: "token", Value: latest}},
		map[string]any{"createdAt": time.Now().UTC().Add(-5 * time.Second)}); err != nil {
		t.Fatalf("backdate session: %v", err)
	}
}

func g7UserID(t *testing.T, db *parityMemAdapter, email string) string {
	t.Helper()
	row, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: email}}, nil)
	if row == nil {
		t.Fatal("seed user missing")
	}
	id, _ := row["id"].(string)
	if id == "" {
		t.Fatal("seed user has no id")
	}
	return id
}

// Stale session + valid delete token without password must delete (200),
// matching upstream early-return token path.
func TestDeleteUserStale_DeleteUserStaleSessionValidTokenDeletes(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.User.DeleteUser.Enabled = true
	staleAge := 1
	opts.Session.FreshAge = &staleAge
	api := credsAccountAPI(t, opts)
	email := "g7-stale-token@test.com"
	credsSignInSeed(t, api, email, "password123")
	cookie := credsAuthCookie(t, api, email, "password123")

	g7BackdateLatestSession(t, db)
	userID := g7UserID(t, db, email)
	token, err := createDeleteAccountVerification(context.Background(), opts, userID)
	if err != nil || token == "" {
		t.Fatalf("mint delete token: %v", err)
	}

	resp := api.Post("/api/auth/delete-user", map[string]any{
		"token": token,
	}, "Cookie: "+cookie)
	if resp.Code != 200 || !strings.Contains(resp.Body.String(), "User deleted") {
		t.Fatalf("stale+token delete = %d, want 200 User deleted: %s", resp.Code, resp.Body.String())
	}
	if row, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: email}}, nil); row != nil {
		t.Fatal("user row must be gone")
	}
}

// Stale session without token (and without password) must still fail with
// 400 SESSION_EXPIRED via the faithful second gate.
func TestDeleteUserStale_DeleteUserStaleSessionWithoutTokenExpired(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.User.DeleteUser.Enabled = true
	staleAge := 1
	opts.Session.FreshAge = &staleAge
	api := credsAccountAPI(t, opts)
	email := "g7-stale-notoken@test.com"
	credsSignInSeed(t, api, email, "password123")
	cookie := credsAuthCookie(t, api, email, "password123")

	g7BackdateLatestSession(t, db)

	resp := api.Post("/api/auth/delete-user", map[string]any{}, "Cookie: "+cookie)
	if resp.Code != 400 || !strings.Contains(resp.Body.String(), types.ErrSessionExpired) {
		t.Fatalf("stale delete = %d, want 400 SESSION_EXPIRED: %s", resp.Code, resp.Body.String())
	}
}

// Invalid delete token must fail with 404 INVALID_TOKEN (upstream
// deleteUserCallback throws NOT_FOUND on bad/owner-mismatch tokens,
// update-user.ts:641-642; realigned from 401 by C5 for POST/GET consistency).
func TestDeleteUserStale_DeleteUserInvalidTokenUnauthorized(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.User.DeleteUser.Enabled = true
	freshAge := 1000
	opts.Session.FreshAge = &freshAge
	api := credsAccountAPI(t, opts)
	email := "g7-invalid-token@test.com"
	credsSignInSeed(t, api, email, "password123")
	cookie := credsAuthCookie(t, api, email, "password123")

	resp := api.Post("/api/auth/delete-user", map[string]any{
		"token": "g7-invalid-token-xyz",
	}, "Cookie: "+cookie)
	if resp.Code != 404 || !strings.Contains(resp.Body.String(), types.ErrInvalidToken) {
		t.Fatalf("invalid token = %d, want 404 INVALID_TOKEN: %s", resp.Code, resp.Body.String())
	}
	if row, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: email}}, nil); row == nil {
		t.Fatal("user must survive an invalid token")
	}
}
