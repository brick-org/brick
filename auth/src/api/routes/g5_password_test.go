package routes

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

// P06-R2: ResetPassword with RevokeSessionsOnPasswordReset must purge
// SecondaryStorage live (upstream password.ts:328-330 deleteUserSessions),
// mirroring the deleteSecondaryAwareUserSessions pattern used by
// ChangePassword and the F7 delete-user matrix.

type g5PasswordMode struct {
	name      string
	secondary bool
	dual      bool
}

func g5PasswordModes() []g5PasswordMode {
	return []g5PasswordMode{
		{name: "secondary-only", secondary: true, dual: false},
		{name: "dual", secondary: true, dual: true},
		{name: "db-only", secondary: false, dual: false},
	}
}

func g5PasswordAPI(t *testing.T, opts types.Options) humatest.TestAPI {
	t.Helper()
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	SignUpEmail(api, "/api/auth", opts)
	SignInEmail(api, "/api/auth", opts)
	GetSession(api, "/api/auth", opts)
	RequestPasswordReset(api, "/api/auth", opts)
	ResetPassword(api, "/api/auth", opts)
	return api
}

func g5PasswordSetup(t *testing.T, mode g5PasswordMode, revoke bool) (*parityMemAdapter, *mapSecondaryStorage, types.Options, humatest.TestAPI, *string) {
	t.Helper()
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	var store *mapSecondaryStorage
	if mode.secondary {
		store = newMapSecondaryStorage(true)
		opts.SecondaryStorage = store
		if mode.dual {
			opts.Session.StoreSessionInDatabase = true
		}
	}
	opts.EmailAndPassword.RevokeSessionsOnPasswordReset = revoke
	token := new(string)
	opts.EmailAndPassword.SendResetPassword = func(data types.ResetPasswordData) error {
		*token = data.Token
		return nil
	}
	api := g5PasswordAPI(t, opts)
	return db, store, opts, api, token
}

func g5PasswordSeedTwoSessions(t *testing.T, api humatest.TestAPI, email string) (cookieA, cookieB string) {
	t.Helper()
	signUp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "G5", "email": email, "password": "password123",
	})
	if signUp.Code != 200 {
		t.Fatalf("sign-up = %d: %s", signUp.Code, signUp.Body.String())
	}
	cookieA = sessionCookieOf(t, signUp)
	signIn := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": email, "password": "password123",
	})
	if signIn.Code != 200 {
		t.Fatalf("sign-in = %d: %s", signIn.Code, signIn.Body.String())
	}
	cookieB = sessionCookieOf(t, signIn)
	return cookieA, cookieB
}

func g5PasswordUserID(t *testing.T, ctx context.Context, db *parityMemAdapter, email string) string {
	t.Helper()
	row, _ := db.FindOne(ctx, "user", []types.Where{{Field: "email", Value: email}}, nil)
	if row == nil {
		t.Fatalf("seed user %s missing", email)
	}
	uid, _ := row["id"].(string)
	if uid == "" {
		t.Fatal("seed user has no id")
	}
	return uid
}

func g5PasswordLiveTokens(t *testing.T, opts types.Options, store *mapSecondaryStorage, userID string) []string {
	t.Helper()
	refs := getSecondarySessionRefs(opts, userID)
	if len(refs) == 0 {
		t.Fatalf("secondary issuance must populate active-sessions for %s", userID)
	}
	tokens := make([]string, 0, len(refs))
	for _, ref := range refs {
		tokens = append(tokens, ref.Token)
		if !store.has(ref.Token) {
			t.Fatalf("token entry %s must exist before reset", ref.Token)
		}
	}
	if !store.has(activeSessionsKey(userID)) {
		t.Fatal("active-sessions list key must exist before reset")
	}
	return tokens
}

// TestG5_ResetWithRevokePurgesSecondary runs reset-password end to end with
// revoke enabled: DB rows are gone AND no secondary residue survives, so old
// cookies 401. Pre-fix this fails on secondary modes (raw DeleteMany leaves
// the cache live and get-session keeps serving 200).
func TestG5_ResetWithRevokePurgesSecondary(t *testing.T) {
	for _, mode := range g5PasswordModes() {
		t.Run(mode.name, func(t *testing.T) {
			ctx := context.Background()
			email := fmt.Sprintf("g5-revoke-%s@test.com", strings.ReplaceAll(mode.name, "-", ""))
			db, store, opts, api, token := g5PasswordSetup(t, mode, true)
			cookieA, cookieB := g5PasswordSeedTwoSessions(t, api, email)
			userID := g5PasswordUserID(t, ctx, db, email)
			var tokens []string
			if mode.secondary {
				tokens = g5PasswordLiveTokens(t, opts, store, userID)
			}

			if resp := api.Post("/api/auth/request-password-reset", map[string]any{"email": email}); resp.Code != 200 {
				t.Fatalf("request reset = %d: %s", resp.Code, resp.Body.String())
			}
			if *token == "" {
				t.Fatal("expected a reset token")
			}
			if resp := api.Post("/api/auth/reset-password", map[string]any{
				"token": *token, "newPassword": "new-password-123",
			}); resp.Code != 200 || !strings.Contains(resp.Body.String(), `"status":true`) {
				t.Fatalf("reset = %d, want 200 status:true: %s", resp.Code, resp.Body.String())
			}

			if rows, _ := db.FindMany(ctx, "session", []types.Where{{Field: "userId", Value: userID}}, 0, 0, nil, nil); len(rows) != 0 {
				t.Fatalf("database session rows must be gone, got %d", len(rows))
			}
			if mode.secondary {
				for _, tok := range tokens {
					if store.has(tok) {
						t.Fatalf("secondary token entry %s must be purged on reset revoke", tok)
					}
				}
				if store.has(activeSessionsKey(userID)) {
					t.Fatal("active-sessions list key must be purged on reset revoke")
				}
				if refs := getSecondarySessionRefs(opts, userID); len(refs) != 0 {
					t.Fatalf("active-sessions refs must be empty, got %+v", refs)
				}
			}
			for i, cookie := range []string{cookieA, cookieB} {
				if sess := api.Get("/api/auth/get-session", "Cookie: "+cookie); sess.Code != 401 {
					t.Fatalf("session %d must be revoked, got %d: %s", i, sess.Code, sess.Body.String())
				}
			}
		})
	}
}

// TestG5_ResetWithoutRevokeKeepsSessions runs reset-password end to end with
// revoke disabled: sessions survive in every storage mode (DB rows kept where
// persisted, secondary entries kept where enabled, cookies still 200).
func TestG5_ResetWithoutRevokeKeepsSessions(t *testing.T) {
	for _, mode := range g5PasswordModes() {
		t.Run(mode.name, func(t *testing.T) {
			ctx := context.Background()
			email := fmt.Sprintf("g5-keep-%s@test.com", strings.ReplaceAll(mode.name, "-", ""))
			db, store, opts, api, token := g5PasswordSetup(t, mode, false)
			cookieA, cookieB := g5PasswordSeedTwoSessions(t, api, email)
			userID := g5PasswordUserID(t, ctx, db, email)
			var tokens []string
			if mode.secondary {
				tokens = g5PasswordLiveTokens(t, opts, store, userID)
			}
			wantDB := 0
			if mode.dual || !mode.secondary {
				wantDB = 2
				if rows, _ := db.FindMany(ctx, "session", []types.Where{{Field: "userId", Value: userID}}, 0, 0, nil, nil); len(rows) != wantDB {
					t.Fatalf("pre-reset db sessions = %d, want %d", len(rows), wantDB)
				}
			}

			if resp := api.Post("/api/auth/request-password-reset", map[string]any{"email": email}); resp.Code != 200 {
				t.Fatalf("request reset = %d: %s", resp.Code, resp.Body.String())
			}
			if *token == "" {
				t.Fatal("expected a reset token")
			}
			if resp := api.Post("/api/auth/reset-password", map[string]any{
				"token": *token, "newPassword": "new-password-123",
			}); resp.Code != 200 || !strings.Contains(resp.Body.String(), `"status":true`) {
				t.Fatalf("reset = %d, want 200 status:true: %s", resp.Code, resp.Body.String())
			}

			if mode.dual || !mode.secondary {
				if rows, _ := db.FindMany(ctx, "session", []types.Where{{Field: "userId", Value: userID}}, 0, 0, nil, nil); len(rows) != wantDB {
					t.Fatalf("db sessions must survive without revoke, got %d want %d", len(rows), wantDB)
				}
			}
			if mode.secondary {
				for _, tok := range tokens {
					if !store.has(tok) {
						t.Fatalf("secondary token entry %s must survive without revoke", tok)
					}
				}
				if !store.has(activeSessionsKey(userID)) {
					t.Fatal("active-sessions list key must survive without revoke")
				}
				if refs := getSecondarySessionRefs(opts, userID); len(refs) == 0 {
					t.Fatal("active-sessions refs must survive without revoke")
				}
			}
			for i, cookie := range []string{cookieA, cookieB} {
				if sess := api.Get("/api/auth/get-session", "Cookie: "+cookie); sess.Code != 200 {
					t.Fatalf("session %d must survive without revoke, got %d: %s", i, sess.Code, sess.Body.String())
				}
			}
		})
	}
}
