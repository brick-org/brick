package routes

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/brick-org/brick/auth/src/types"
)

// P08-G2: delete-user paths must purge SecondaryStorage (active-sessions-*
// index + per-token entries), mirroring the deleteSecondaryAwareUserSessions
// pattern used by ChangePassword. These tests run the full HTTP stack with
// secondary storage enabled and assert both halves: the user row is gone AND
// no secondary residue survives.

// f7DeleteSecondarySetup builds secondary-enabled delete-user options over a
// fresh mem adapter + map store. When dual is true the database also persists
// session rows (StoreSessionInDatabase), covering both legs of the flag
// matrix; otherwise sessions live in secondary storage only.
func f7DeleteSecondarySetup(t *testing.T, dual bool) (*parityMemAdapter, *mapSecondaryStorage, types.Options) {
	t.Helper()
	db := newParityMemAdapter()
	store := newMapSecondaryStorage(true)
	opts := emailAuthTestOptions(db)
	opts.SecondaryStorage = store
	opts.User.DeleteUser.Enabled = true
	if dual {
		opts.Session.StoreSessionInDatabase = true
	}
	return db, store, opts
}

// f7DeleteSecondaryTokens returns the live secondary tokens for userID,
// failing when issuance did not populate secondary storage (a vacuous test
// would pass pre-fix without proving anything).
func f7DeleteSecondaryTokens(t *testing.T, opts types.Options, store *mapSecondaryStorage, userID string) []string {
	t.Helper()
	refs := getSecondarySessionRefs(opts, userID)
	if len(refs) == 0 {
		t.Fatalf("secondary issuance must populate active-sessions for %s", userID)
	}
	tokens := make([]string, 0, len(refs))
	for _, ref := range refs {
		tokens = append(tokens, ref.Token)
		if !store.has(ref.Token) {
			t.Fatalf("token entry %s must exist before delete", ref.Token)
		}
	}
	if !store.has(activeSessionsKey(userID)) {
		t.Fatal("active-sessions list key must exist before delete")
	}
	return tokens
}

// f7AssertSecondaryPurged fails when any secondary session residue survives
// for userID: per-token entries or the active-sessions index.
func f7AssertSecondaryPurged(t *testing.T, ctx context.Context, db *parityMemAdapter, opts types.Options, store *mapSecondaryStorage, userID string, tokens []string) {
	t.Helper()
	if row, _ := db.FindOne(ctx, "user", []types.Where{{Field: "id", Value: userID}}, nil); row != nil {
		t.Fatal("user row must be gone")
	}
	if rows, _ := db.FindMany(ctx, "session", []types.Where{{Field: "userId", Value: userID}}, 0, 0, nil, nil); len(rows) != 0 {
		t.Fatalf("database session rows must be gone, got %d", len(rows))
	}
	for _, token := range tokens {
		if store.has(token) {
			t.Fatalf("secondary token entry %s must be purged on delete", token)
		}
	}
	if store.has(activeSessionsKey(userID)) {
		t.Fatal("active-sessions list key must be purged on delete")
	}
	if refs := getSecondarySessionRefs(opts, userID); len(refs) != 0 {
		t.Fatalf("active-sessions refs must be empty, got %+v", refs)
	}
}

// TestF7_DeleteUserDirectPurgesSecondary runs POST /delete-user end to end
// with secondary storage enabled: the user is deleted AND every secondary
// session entry plus the active-sessions index is purged.
func TestF7_DeleteUserDirectPurgesSecondary(t *testing.T) {
	for _, dual := range []bool{false, true} {
		t.Run(fmt.Sprintf("dual=%v", dual), func(t *testing.T) {
			ctx := context.Background()
			db, store, opts := f7DeleteSecondarySetup(t, dual)
			api := credsAccountAPI(t, opts)
			email := "f7-direct@test.com"
			credsSignInSeed(t, api, email, "password123")
			cookie := credsAuthCookie(t, api, email, "password123")

			userRow, _ := db.FindOne(ctx, "user", []types.Where{{Field: "email", Value: email}}, nil)
			if userRow == nil {
				t.Fatal("seed user missing")
			}
			userID, _ := userRow["id"].(string)
			tokens := f7DeleteSecondaryTokens(t, opts, store, userID)

			resp := api.Post("/api/auth/delete-user", map[string]any{}, "Cookie: "+cookie)
			if resp.Code != 200 || !strings.Contains(resp.Body.String(), "User deleted") {
				t.Fatalf("delete = %d, want 200 User deleted: %s", resp.Code, resp.Body.String())
			}
			f7AssertSecondaryPurged(t, ctx, db, opts, store, userID, tokens)
		})
	}
}

// TestF7_DeleteUserCallbackPurgesSecondary runs the verification flow end to
// end with secondary storage enabled: POST /delete-user sends the token,
// GET /delete-user/callback consumes it and deletes the user AND purges
// every secondary session entry plus the active-sessions index.
func TestF7_DeleteUserCallbackPurgesSecondary(t *testing.T) {
	for _, dual := range []bool{false, true} {
		t.Run(fmt.Sprintf("dual=%v", dual), func(t *testing.T) {
			ctx := context.Background()
			db, store, opts := f7DeleteSecondarySetup(t, dual)
			var token string
			opts.User.DeleteUser.SendDeleteAccountVerification = func(data types.DeleteAccountVerificationData) error {
				token = data.Token
				return nil
			}
			api := credsAccountAPI(t, opts)
			email := "f7-callback@test.com"
			credsSignInSeed(t, api, email, "password123")
			cookie := credsAuthCookie(t, api, email, "password123")

			userRow, _ := db.FindOne(ctx, "user", []types.Where{{Field: "email", Value: email}}, nil)
			if userRow == nil {
				t.Fatal("seed user missing")
			}
			userID, _ := userRow["id"].(string)
			tokens := f7DeleteSecondaryTokens(t, opts, store, userID)

			req := api.Post("/api/auth/delete-user", map[string]any{
				"password": "password123",
			}, "Cookie: "+cookie)
			if req.Code != 200 || !strings.Contains(req.Body.String(), `"success":true`) {
				t.Fatalf("request = %d, want verification success: %s", req.Code, req.Body.String())
			}
			if token == "" {
				t.Fatal("expected a delete verification token")
			}
			if row, _ := db.FindOne(ctx, "user", []types.Where{{Field: "email", Value: email}}, nil); row == nil {
				t.Fatal("user must survive until the token is consumed")
			}

			done := api.Get("/api/auth/delete-user/callback?token="+url.QueryEscape(token), "Cookie: "+cookie)
			if done.Code != 200 || !strings.Contains(done.Body.String(), "User deleted") {
				t.Fatalf("callback = %d, want 200 User deleted: %s", done.Code, done.Body.String())
			}
			f7AssertSecondaryPurged(t, ctx, db, opts, store, userID, tokens)
		})
	}
}
