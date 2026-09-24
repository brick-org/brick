package routes

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

// Pinned upstream: account.test.ts core legs (list-accounts; link/unlink,
// account-info, access-token and account-cookie legs are v1-excluded) plus
// update-user.test.ts core legs (update-user, change-password,
// change-email, delete-user, credential-identity; secondary-storage and
// cookie-cache legs belong to the session lane).

func credsAccountAPI(t *testing.T, opts types.Options) humatest.TestAPI {
	t.Helper()
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	SignUpEmail(api, "/api/auth", opts)
	SignInEmail(api, "/api/auth", opts)
	ListUserAccounts(api, "/api/auth", opts)
	UpdateUser(api, "/api/auth", opts)
	ChangeEmail(api, "/api/auth", opts)
	ChangePassword(api, "/api/auth", opts)
	DeleteUser(api, "/api/auth", opts)
	DeleteUserCallback(api, "/api/auth", opts)
	VerifyEmail(api, "/api/auth", opts)
	return api
}

func credsAuthCookie(t *testing.T, api humatest.TestAPI, email, password string) string {
	t.Helper()
	signIn := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": email, "password": password,
	})
	if signIn.Code != 200 {
		t.Fatalf("seed sign-in = %d: %s", signIn.Code, signIn.Body.String())
	}
	return sessionCookieOf(t, signIn)
}

// account.test.ts "should list all accounts".
func TestCredsV1_ListAccounts(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	api := credsAccountAPI(t, opts)
	credsSignInSeed(t, api, "listed@test.com", "password123")
	cookie := credsAuthCookie(t, api, "listed@test.com", "password123")
	resp := api.Get("/api/auth/list-accounts", "Cookie: "+cookie)
	if resp.Code != 200 {
		t.Fatalf("status = %d: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), `"providerId":"credential"`) {
		t.Fatalf("credential account must be listed: %s", resp.Body.String())
	}
}

// account.test.ts "should not expose empty scope tokens from stored empty
// account scope": a stored empty scope lists as [].
func TestCredsV1_ListAccountsEmptyScope(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	api := credsAccountAPI(t, opts)
	credsSignInSeed(t, api, "scoped@test.com", "password123")
	cookie := credsAuthCookie(t, api, "scoped@test.com", "password123")
	userRow, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: "scoped@test.com"}}, nil)
	if userRow == nil {
		t.Fatal("seed user missing")
	}
	rec := rowToAccount(map[string]any{
		"id": "a-empty", "providerId": "google", "accountId": "empty-scope-google-account",
		"userId": userRow["id"], "scope": "",
	})
	if rec.Scopes == nil || len(rec.Scopes) != 0 {
		t.Fatalf("empty stored scope must map to [], got %#v", rec.Scopes)
	}
	resp := api.Get("/api/auth/list-accounts", "Cookie: "+cookie)
	if resp.Code != 200 {
		t.Fatalf("status = %d: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), `"scopes":[]`) {
		t.Fatalf("credential entry must carry scopes:[], got %s", resp.Body.String())
	}
}

// update-user.test.ts "should update the user's name" + "shouldn't pass
// defaults": only supplied fields change; declared defaults never reset
// stored additional values.
func TestCredsV1_UpdateUserKeepsStoredAdditional(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.User.Model.AdditionalFields = map[string]types.FieldAttribute{
		"newField": {Type: "string", Required: credsFalsePtr(), DefaultValue: "default"},
	}
	api := credsAccountAPI(t, opts)
	credsSignInSeed(t, api, "keep@test.com", "password123")
	cookie := credsAuthCookie(t, api, "keep@test.com", "password123")
	if _, err := db.Update(context.Background(), "user",
		[]types.Where{{Field: "email", Value: "keep@test.com"}},
		map[string]any{"newField": "new"}); err != nil {
		t.Fatalf("seed additional: %v", err)
	}
	resp := api.Post("/api/auth/update-user", map[string]any{"name": "newName"}, "Cookie: "+cookie)
	if resp.Code != 200 || !strings.Contains(resp.Body.String(), `"status":true`) {
		t.Fatalf("update = %d, want 200 status:true: %s", resp.Code, resp.Body.String())
	}
	row, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: "keep@test.com"}}, nil)
	if row["name"] != "newName" {
		t.Fatalf("name = %#v", row["name"])
	}
	if row["newField"] != "new" {
		t.Fatalf("stored additional must survive a name-only update, got %#v", row["newField"])
	}
}

// update-user.test.ts "should unset image".
func TestCredsV1_UpdateUserUnsetsImage(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	api := credsAccountAPI(t, opts)
	credsSignInSeed(t, api, "img@test.com", "password123")
	cookie := credsAuthCookie(t, api, "img@test.com", "password123")
	if resp := api.Post("/api/auth/update-user", map[string]any{
		"image": "https://example.com/image.jpg",
	}, "Cookie: "+cookie); resp.Code != 200 {
		t.Fatalf("set image = %d: %s", resp.Code, resp.Body.String())
	}
	if resp := api.Post("/api/auth/update-user", map[string]any{
		"image": nil,
	}, "Cookie: "+cookie); resp.Code != 200 {
		t.Fatalf("unset image = %d: %s", resp.Code, resp.Body.String())
	}
	row, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: "img@test.com"}}, nil)
	if v, _ := row["image"].(string); v != "" {
		t.Fatalf("image must be unset, got %#v", row["image"])
	}
	if _, ok := row["image"]; ok {
		if v := row["image"]; v != nil {
			if s, _ := v.(string); s != "" {
				t.Fatalf("image must be unset, got %#v", v)
			}
		}
	}
}

// update-user.test.ts "should not allow updating user with additional
// fields that are input: false".
func TestCredsV1_UpdateUserInputFalseRejected(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.User.Model.AdditionalFields = map[string]types.FieldAttribute{
		"newField": {Type: "string", Required: credsFalsePtr(), DefaultValue: "default", Input: credsFalsePtr()},
	}
	api := credsAccountAPI(t, opts)
	credsSignInSeed(t, api, "nofield@test.com", "password123")
	cookie := credsAuthCookie(t, api, "nofield@test.com", "password123")
	resp := api.Post("/api/auth/update-user", map[string]any{
		"newField": "new",
	}, "Cookie: "+cookie)
	if resp.Code != 400 {
		t.Fatalf("status = %d, want 400: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "newField is not allowed to be set") {
		t.Fatalf("want the upstream message, got %s", resp.Body.String())
	}
}

// update-user.test.ts "should update the user's password" (wrong-password
// leg): a wrong current password fails and the old password keeps working.
func TestCredsV1_ChangePasswordWrongCurrent(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	api := credsAccountAPI(t, opts)
	credsSignInSeed(t, api, "chg-wrong@test.com", "password123")
	cookie := credsAuthCookie(t, api, "chg-wrong@test.com", "password123")
	resp := api.Post("/api/auth/change-password", map[string]any{
		"newPassword": "newPassword123", "currentPassword": "wrongPassword",
	}, "Cookie: "+cookie)
	if resp.Code == 200 {
		t.Fatalf("wrong current password must fail: %s", resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), types.ErrInvalidPassword) {
		t.Fatalf("want INVALID_PASSWORD, got %s", resp.Body.String())
	}
	signIn := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": "chg-wrong@test.com", "password": "password123",
	})
	if signIn.Code != 200 {
		t.Fatalf("old password must keep working: %d %s", signIn.Code, signIn.Body.String())
	}
}

// update-user.test.ts "should revoke other sessions": revokeOtherSessions
// mints a fresh token and kills the old session.
func TestCredsV1_ChangePasswordRevokesOthers(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	api := credsAccountAPI(t, opts)
	credsSignInSeed(t, api, "chg-revoke@test.com", "password123")
	cookie := credsAuthCookie(t, api, "chg-revoke@test.com", "password123")
	resp := api.Post("/api/auth/change-password", map[string]any{
		"newPassword": "newPassword123", "currentPassword": "password123",
		"revokeOtherSessions": true,
	}, "Cookie: "+cookie)
	if resp.Code != 200 {
		t.Fatalf("status = %d: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), `"status":true`) ||
		!strings.Contains(resp.Body.String(), `"token"`) ||
		!strings.Contains(resp.Body.String(), `"user"`) {
		t.Fatalf("revoke response must carry status+token+user: %s", resp.Body.String())
	}
	signIn := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": "chg-revoke@test.com", "password": "password123",
	})
	if signIn.Code == 200 {
		t.Fatal("old password must stop working after change")
	}
}

// update-user.test.ts "change-email enumeration protection": an existing
// target answers success without changing the email.
func TestCredsV1_ChangeEmailExistingTarget(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.EmailVerification.SendVerificationEmail = func(types.VerificationEmailData) error { return nil }
	opts.User.ChangeEmail.Enabled = true
	api := credsAccountAPI(t, opts)
	credsSignInSeed(t, api, "other-user@test.com", "password123")
	credsSignInSeed(t, api, "enum@test.com", "password123")
	cookie := credsAuthCookie(t, api, "enum@test.com", "password123")

	resp := api.Post("/api/auth/change-email", map[string]any{
		"newEmail": "other-user@test.com",
	}, "Cookie: "+cookie)
	if resp.Code != 200 || !strings.Contains(resp.Body.String(), `"status":true`) {
		t.Fatalf("existing target must answer success, got %d: %s", resp.Code, resp.Body.String())
	}
	row, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: "enum@test.com"}}, nil)
	if row == nil {
		t.Fatal("requesting user's email must not change")
	}
}

// update-user.test.ts "change-email without sendVerificationEmail": existing
// and non-existing targets fail with the same error.
func TestCredsV1_ChangeEmailSameErrorWithoutSender(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.User.ChangeEmail.Enabled = true
	api := credsAccountAPI(t, opts)
	credsSignInSeed(t, api, "existing-no-verif@test.com", "password123")
	credsSignInSeed(t, api, "nosender@test.com", "password123")
	cookie := credsAuthCookie(t, api, "nosender@test.com", "password123")

	existing := api.Post("/api/auth/change-email", map[string]any{
		"newEmail": "existing-no-verif@test.com",
	}, "Cookie: "+cookie)
	nonExisting := api.Post("/api/auth/change-email", map[string]any{
		"newEmail": "does-not-exist@test.com",
	}, "Cookie: "+cookie)
	if existing.Code != 400 || nonExisting.Code != 400 {
		t.Fatalf("both must be 400, got %d/%d: %s / %s",
			existing.Code, nonExisting.Code, existing.Body.String(), nonExisting.Body.String())
	}
	if existing.Body.String() != nonExisting.Body.String() {
		t.Fatalf("errors must be identical: %s vs %s", existing.Body.String(), nonExisting.Body.String())
	}
}

// update-user.test.ts "change-email callbackURL preservation": a
// callbackURL carrying its own query string round-trips verbatim through
// the confirmation URL.
func TestCredsV1_ChangeEmailCallbackEncoding(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.EmailVerification.SendVerificationEmail = func(types.VerificationEmailData) error { return nil }
	var confirmationURL string
	opts.User.ChangeEmail.Enabled = true
	opts.User.ChangeEmail.SendChangeEmailConfirmation = func(data types.ChangeEmailData) error {
		confirmationURL = data.URL
		return nil
	}
	api := credsAccountAPI(t, opts)
	credsSignInSeed(t, api, "cb-preserve@test.com", "password123")
	cookie := credsAuthCookie(t, api, "cb-preserve@test.com", "password123")
	if _, err := db.Update(context.Background(), "user",
		[]types.Where{{Field: "email", Value: "cb-preserve@test.com"}},
		map[string]any{"emailVerified": true}); err != nil {
		t.Fatalf("verify seed: %v", err)
	}
	callback := "/dashboard?tab=settings&from=email"
	if resp := api.Post("/api/auth/change-email", map[string]any{
		"newEmail": "new-email@email.com", "callbackURL": callback,
	}, "Cookie: "+cookie); resp.Code != 200 {
		t.Fatalf("change-email = %d: %s", resp.Code, resp.Body.String())
	}
	parsed, err := url.Parse(confirmationURL)
	if err != nil {
		t.Fatalf("parse confirmation URL: %v (%q)", err, confirmationURL)
	}
	if got := parsed.Query().Get("callbackURL"); got != callback {
		t.Fatalf("callbackURL round-trip = %q, want %q", got, callback)
	}
	if parsed.Query().Get("from") != "" {
		t.Fatalf("query segments must not leak: %q", confirmationURL)
	}
}

// update-user.test.ts "change-email rejects confirmation-only config for
// verified users": no verification sender means 400, not a misleading
// success.
func TestCredsV1_ChangeEmailConfirmationOnlyConfig(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.User.ChangeEmail.Enabled = true
	opts.User.ChangeEmail.SendChangeEmailConfirmation = func(types.ChangeEmailData) error { return nil }
	api := credsAccountAPI(t, opts)
	credsSignInSeed(t, api, "confonly@test.com", "password123")
	cookie := credsAuthCookie(t, api, "confonly@test.com", "password123")
	if _, err := db.Update(context.Background(), "user",
		[]types.Where{{Field: "email", Value: "confonly@test.com"}},
		map[string]any{"emailVerified": true}); err != nil {
		t.Fatalf("verify seed: %v", err)
	}
	resp := api.Post("/api/auth/change-email", map[string]any{
		"newEmail": "unreachable@email.com",
	}, "Cookie: "+cookie)
	if resp.Code != 400 {
		t.Fatalf("status = %d, want 400: %s", resp.Code, resp.Body.String())
	}
}

// update-user.test.ts "credential identity across email changes": the
// unverified direct-update leg keeps one credential account and moves
// sign-in to the new address.
func TestCredsV1_ChangeEmailKeepsCredentialAccount(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.User.ChangeEmail.Enabled = true
	opts.User.ChangeEmail.UpdateEmailWithoutVerification = true
	api := credsAccountAPI(t, opts)
	credsSignInSeed(t, api, "credential-email-change@example.com", "credential-password")
	cookie := credsAuthCookie(t, api, "credential-email-change@example.com", "credential-password")
	userRow, _ := db.FindOne(context.Background(), "user",
		[]types.Where{{Field: "email", Value: "credential-email-change@example.com"}}, nil)
	if userRow == nil {
		t.Fatal("seed user missing")
	}
	userID, _ := userRow["id"].(string)
	before, _ := db.FindMany(context.Background(), "account", []types.Where{{Field: "userId", Value: userID}}, 0, 0, nil, nil)
	if len(before) != 1 {
		t.Fatalf("want 1 credential account, got %d", len(before))
	}
	resp := api.Post("/api/auth/change-email", map[string]any{
		"newEmail": "changed-credential-email@example.com",
	}, "Cookie: "+cookie)
	if resp.Code != 200 || !strings.Contains(resp.Body.String(), `"status":true`) {
		t.Fatalf("change-email = %d: %s", resp.Code, resp.Body.String())
	}
	if old := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": "credential-email-change@example.com", "password": "credential-password",
	}); old.Code == 200 {
		t.Fatal("old address must stop working")
	}
	moved := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": "changed-credential-email@example.com", "password": "credential-password",
	})
	if moved.Code != 200 {
		t.Fatalf("new address sign-in = %d: %s", moved.Code, moved.Body.String())
	}
	after, _ := db.FindMany(context.Background(), "account", []types.Where{{Field: "userId", Value: userID}}, 0, 0, nil, nil)
	if len(after) != 1 || after[0]["id"] != before[0]["id"] {
		t.Fatalf("credential account must be untouched: %#v", after)
	}
}

// update-user.test.ts "should delete with verification flow and password":
// password + verification flow sends a 32-char token mail first, then the
// token completes deletion.
func TestCredsV1_DeleteUserVerificationFlowWithPassword(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.User.DeleteUser.Enabled = true
	var token string
	opts.User.DeleteUser.SendDeleteAccountVerification = func(data types.DeleteAccountVerificationData) error {
		token = data.Token
		return nil
	}
	api := credsAccountAPI(t, opts)
	credsSignInSeed(t, api, "del-flow@test.com", "password123")
	cookie := credsAuthCookie(t, api, "del-flow@test.com", "password123")

	resp := api.Post("/api/auth/delete-user", map[string]any{
		"password": "password123",
	}, "Cookie: "+cookie)
	if resp.Code != 200 || !strings.Contains(resp.Body.String(), `"success":true`) {
		t.Fatalf("request = %d, want success: %s", resp.Code, resp.Body.String())
	}
	if len(token) != 32 {
		t.Fatalf("delete token length = %d, want 32", len(token))
	}
	if row, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: "del-flow@test.com"}}, nil); row == nil {
		t.Fatal("user must survive until the token is consumed")
	}
	done := api.Post("/api/auth/delete-user", map[string]any{
		"token": token,
	}, "Cookie: "+cookie)
	if done.Code != 200 || !strings.Contains(done.Body.String(), "User deleted") {
		t.Fatalf("confirm = %d, want deletion: %s", done.Code, done.Body.String())
	}
	if row, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: "del-flow@test.com"}}, nil); row != nil {
		t.Fatal("user row must be gone")
	}
}

// update-user.test.ts "should require password when session is no longer
// fresh" (#8173): stale sessions need a password, else 400 SESSION_EXPIRED.
func TestCredsV1_DeleteUserRequiresPasswordWhenStale(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.User.DeleteUser.Enabled = true
	staleAge := 1
	opts.Session.FreshAge = &staleAge
	api := credsAccountAPI(t, opts)
	credsSignInSeed(t, api, "del-stale@test.com", "password123")
	cookie := credsAuthCookie(t, api, "del-stale@test.com", "password123")
	rows, _ := db.FindMany(context.Background(), "session", nil, 0, 0, nil, nil)
	if len(rows) == 0 {
		t.Fatal("seed session missing")
	}
	// Age the sign-in session past FreshAge, mirroring upstream's createdAt
	// backdate (#8173). The mem adapter's Update targets the first match,
	// so scope the write to the latest session row (the sign-in session).
	latest, _ := rows[len(rows)-1]["token"].(string)
	if latest == "" {
		t.Fatal("seed session has no token")
	}
	if _, err := db.Update(context.Background(), "session",
		[]types.Where{{Field: "token", Value: latest}},
		map[string]any{"createdAt": time.Now().UTC().Add(-5 * time.Second)}); err != nil {
		t.Fatalf("backdate session: %v", err)
	}
	resp := api.Post("/api/auth/delete-user", map[string]any{}, "Cookie: "+cookie)
	if resp.Code != 400 || !strings.Contains(resp.Body.String(), types.ErrSessionExpired) {
		t.Fatalf("stale delete = %d, want 400 SESSION_EXPIRED: %s", resp.Code, resp.Body.String())
	}
}

// update-user.test.ts "rejects /delete-user/callback when the backing
// session was revoked": the GET callback must fail closed on a revoked
// session even with a valid delete token.
func TestCredsV1_DeleteUserCallbackRevokedSession(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.User.DeleteUser.Enabled = true
	var token string
	opts.User.DeleteUser.SendDeleteAccountVerification = func(data types.DeleteAccountVerificationData) error {
		token = data.Token
		return nil
	}
	api := credsAccountAPI(t, opts)
	credsSignInSeed(t, api, "del-revoked@test.com", "password123")
	cookie := credsAuthCookie(t, api, "del-revoked@test.com", "password123")
	if resp := api.Post("/api/auth/delete-user", map[string]any{
		"password": "password123",
	}, "Cookie: "+cookie); resp.Code != 200 {
		t.Fatalf("request = %d: %s", resp.Code, resp.Body.String())
	}
	if token == "" {
		t.Fatal("expected a delete token")
	}
	// Revoke the backing session server-side while the cookie survives
	// (the latest row is the sign-in session the cookie carries).
	sessions, _ := db.FindMany(context.Background(), "session", nil, 0, 0, nil, nil)
	if len(sessions) == 0 {
		t.Fatal("seed session missing")
	}
	sessionToken, _ := sessions[len(sessions)-1]["token"].(string)
	if err := db.Delete(context.Background(), "session", []types.Where{{Field: "token", Value: sessionToken}}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	resp := api.Get("/api/auth/delete-user/callback?token="+url.QueryEscape(token), "Cookie: "+cookie)
	if resp.Code != 404 {
		t.Fatalf("revoked-session callback = %d, want 404: %s", resp.Code, resp.Body.String())
	}
	if row, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: "del-revoked@test.com"}}, nil); row == nil {
		t.Fatal("user must survive a revoked-session callback")
	}
}

// update-user.test.ts "should delete the user with a fresh session".
func TestCredsV1_DeleteUserFreshSession(t *testing.T) {	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.User.DeleteUser.Enabled = true
	freshAge := 1000
	opts.Session.FreshAge = &freshAge
	api := credsAccountAPI(t, opts)
	credsSignInSeed(t, api, "del-fresh@test.com", "password123")
	cookie := credsAuthCookie(t, api, "del-fresh@test.com", "password123")
	resp := api.Post("/api/auth/delete-user", map[string]any{}, "Cookie: "+cookie)
	if resp.Code != 200 || !strings.Contains(resp.Body.String(), `"success":true`) {
		t.Fatalf("delete = %d, want success: %s", resp.Code, resp.Body.String())
	}
	if row, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: "del-fresh@test.com"}}, nil); row != nil {
		t.Fatal("user row must be gone")
	}
}

// update-user.test.ts deleteUserCallback originCheck leg: an untrusted
// callbackURL fails with 403 INVALID_CALLBACK_URL before the token is
// consumed or the user deleted; retrying without it then succeeds.
func TestCredsV1_DeleteUserCallbackUntrustedCallbackURL(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.User.DeleteUser.Enabled = true
	var token string
	opts.User.DeleteUser.SendDeleteAccountVerification = func(data types.DeleteAccountVerificationData) error {
		token = data.Token
		return nil
	}
	api := credsAccountAPI(t, opts)
	credsSignInSeed(t, api, "del-untrusted@test.com", "password123")
	cookie := credsAuthCookie(t, api, "del-untrusted@test.com", "password123")
	if resp := api.Post("/api/auth/delete-user", map[string]any{
		"password": "password123",
	}, "Cookie: "+cookie); resp.Code != 200 {
		t.Fatalf("request = %d: %s", resp.Code, resp.Body.String())
	}
	resp := api.Get("/api/auth/delete-user/callback?token="+url.QueryEscape(token)+"&callbackURL="+url.QueryEscape("http://malicious.com"),
		"Cookie: "+cookie)
	if resp.Code != 403 || !strings.Contains(resp.Body.String(), types.ErrInvalidCallbackURL) {
		t.Fatalf("untrusted callback = %d, want 403 INVALID_CALLBACK_URL: %s", resp.Code, resp.Body.String())
	}
	if row, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: "del-untrusted@test.com"}}, nil); row == nil {
		t.Fatal("user must survive an untrusted-callback rejection")
	}
	// The token was not burned: the same token completes deletion without
	// the callbackURL.
	done := api.Get("/api/auth/delete-user/callback?token="+url.QueryEscape(token), "Cookie: "+cookie)
	if done.Code != 200 || !strings.Contains(done.Body.String(), "User deleted") {
		t.Fatalf("retry = %d, want deletion: %s", done.Code, done.Body.String())
	}
}

// update-user.test.ts "should change email only after confirming both
// addresses": verified users flow confirmation -> verification, and only
// the verification leg moves the email.
func TestCredsV1_ChangeEmailDoubleConfirm(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	var confirmationToken, verificationToken string
	opts.EmailVerification.SendVerificationEmail = func(data types.VerificationEmailData) error {
		verificationToken = data.Token
		return nil
	}
	opts.User.ChangeEmail.Enabled = true
	opts.User.ChangeEmail.SendChangeEmailConfirmation = func(data types.ChangeEmailData) error {
		confirmationToken = data.Token
		if data.NewEmail != "new-email@email.com" {
			t.Errorf("confirmation newEmail = %q", data.NewEmail)
		}
		return nil
	}
	api := credsAccountAPI(t, opts)
	credsSignInSeed(t, api, "double-confirm@test.com", "password123")
	cookie := credsAuthCookie(t, api, "double-confirm@test.com", "password123")
	if _, err := db.Update(context.Background(), "user",
		[]types.Where{{Field: "email", Value: "double-confirm@test.com"}},
		map[string]any{"emailVerified": true}); err != nil {
		t.Fatalf("verify seed: %v", err)
	}
	newEmail := "new-email@email.com"
	if resp := api.Post("/api/auth/change-email", map[string]any{
		"newEmail": newEmail,
	}, "Cookie: "+cookie); resp.Code != 200 {
		t.Fatalf("change-email = %d: %s", resp.Code, resp.Body.String())
	}
	if confirmationToken == "" {
		t.Fatal("confirmation email must be sent to the current address")
	}
	// 1. Confirm at the old address: no user update yet.
	if resp := api.Get("/api/auth/verify-email?token="+url.QueryEscape(confirmationToken), "Cookie: "+cookie); resp.Code != 200 {
		t.Fatalf("confirm = %d: %s", resp.Code, resp.Body.String())
	}
	if verificationToken == "" {
		t.Fatal("verification email must be sent to the new address")
	}
	if row, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: "double-confirm@test.com"}}, nil); row == nil {
		t.Fatal("email must still be the old address after confirmation")
	}
	// 2. Verify at the new address: email moves and verifies.
	if resp := api.Get("/api/auth/verify-email?token="+url.QueryEscape(verificationToken), "Cookie: "+cookie); resp.Code != 200 {
		t.Fatalf("verify = %d: %s", resp.Code, resp.Body.String())
	}
	row, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: newEmail}}, nil)
	if row == nil {
		t.Fatal("email must move to the new address after verification")
	}
	if verified, _ := row["emailVerified"].(bool); !verified {
		t.Fatal("new address must be verified")
	}
}
