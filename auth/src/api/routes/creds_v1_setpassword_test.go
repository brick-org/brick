package routes

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/brick-org/brick/auth/src/crypto"
	"github.com/brick-org/brick/auth/src/types"
)

// Pinned upstream: update-user.test.ts describe("setPassword") — server-only
// `auth.api.setPassword` (update-user.ts:314-368). No HTTP route exists
// upstream, so these tests call the Go server-only counterpart SetPassword
// directly with an authenticated user ID.

func credsSetPasswordUser(t *testing.T, db *parityMemAdapter, opts types.Options, email string) string {
	t.Helper()
	api := credsSignUpAPI(t, opts)
	resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "Set Password Test", "email": email, "password": "password123",
	})
	if resp.Code != 200 {
		t.Fatalf("sign-up status = %d, want 200: %s", resp.Code, resp.Body.String())
	}
	var body struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.User.ID == "" {
		t.Fatalf("sign-up response missing user.id: %s", resp.Body.String())
	}
	return body.User.ID
}

func credsSetPasswordErrCode(err error) string {
	var herr types.HttpError
	if errors.As(err, &herr) {
		return herr.Code
	}
	return ""
}

// update-user.test.ts setPassword "sets the password on the existing
func TestCredsV1_SetPasswordOnPasswordlessAccount(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	userID := credsSetPasswordUser(t, db, opts, "setpw@test.com")
	if _, err := db.Update(ctx, "account", []types.Where{
		{Field: "userId", Value: userID},
		{Field: "providerId", Value: "credential", Connector: "AND"},
	}, map[string]any{"password": ""}); err != nil {
		t.Fatalf("null password: %v", err)
	}
	ok, err := SetPassword(ctx, opts, userID, "new-password")
	if err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if !ok {
		t.Fatal("status = false, want true")
	}
	row, _ := db.FindOne(ctx, "account", []types.Where{
		{Field: "userId", Value: userID},
		{Field: "providerId", Value: "credential", Connector: "AND"},
	}, nil)
	hash, _ := row["password"].(string)
	if hash == "" || !crypto.VerifyPassword(hash, "new-password") {
		t.Fatal("stored password must verify against the new password")
	}
}

// A credential account that already has a password rejects with
func TestCredsV1_SetPasswordAlreadySet(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	userID := credsSetPasswordUser(t, db, opts, "setpw-set@test.com")
	_, err := SetPassword(ctx, opts, userID, "another-password")
	if credsSetPasswordErrCode(err) != types.ErrPasswordAlreadySet {
		t.Fatalf("err = %v, want PASSWORD_ALREADY_SET", err)
	}
}

// Length gates mirror upstream with warn logs.
func TestCredsV1_SetPasswordTooShort(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	var calls [][2]string
	opts.Logger.Log = func(level, message string, _ ...any) {
		calls = append(calls, [2]string{level, message})
	}
	userID := credsSetPasswordUser(t, db, opts, "setpw-short@test.com")
	_, err := SetPassword(ctx, opts, userID, "short")
	if credsSetPasswordErrCode(err) != types.ErrPasswordTooShort {
		t.Fatalf("err = %v, want PASSWORD_TOO_SHORT", err)
	}
	if !credsLogged(calls, "warn", "Password is too short") {
		t.Fatalf("expected warn 'Password is too short', got %#v", calls)
	}
}

// mirroring upstream linkAccount.
func TestCredsV1_SetPasswordCreatesMissingAccount(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	userID := credsSetPasswordUser(t, db, opts, "setpw-nolink@test.com")
	if _, err := db.DeleteMany(ctx, "account", []types.Where{
		{Field: "userId", Value: userID},
	}); err != nil {
		t.Fatalf("delete accounts: %v", err)
	}
	ok, err := SetPassword(ctx, opts, userID, "new-password")
	if err != nil || !ok {
		t.Fatalf("ok = %v, err = %v; want true, nil", ok, err)
	}
	rows, _ := db.FindMany(ctx, "account", []types.Where{
		{Field: "userId", Value: userID},
		{Field: "providerId", Value: "credential", Connector: "AND"},
	}, 0, 0, nil, nil)
	if len(rows) != 1 {
		t.Fatalf("linked credential accounts = %d, want 1", len(rows))
	}
}
