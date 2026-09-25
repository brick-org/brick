package routes

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/brick-org/brick/auth/src/types"
)

// Upstream: sign-up.test.ts:125 "should rollback when session creation
// fails" — with createSession mocked to reject, signUpEmail rejects AND the
// user row is gone afterwards.

// orphanFailSessionAdapter forces the sign-up.go:413 path
// (createIssuedSession error): session-row creates reject while the
type orphanFailSessionAdapter struct {
	*parityMemAdapter
}

func (a *orphanFailSessionAdapter) Create(ctx context.Context, model string, data map[string]any, selectCols []string) (map[string]any, error) {
	if model == "session" {
		return nil, errors.New("orphan test: session creation failed")
	}
	return a.parityMemAdapter.Create(ctx, model, data, selectCols)
}

type orphanFailSecondaryStorage struct{}

func (orphanFailSecondaryStorage) Get(key string) (any, error) { return nil, nil }
func (orphanFailSecondaryStorage) GetAndDelete(key string) (any, error) {
	return nil, nil
}
func (orphanFailSecondaryStorage) Increment(key string, ttl int) (int64, error) {
	return 1, nil
}
func (orphanFailSecondaryStorage) Set(key, value string, ttl *int) error {
	return errors.New("orphan test: secondary mirror failed")
}
func (orphanFailSecondaryStorage) Delete(key string) error { return nil }

func orphanSignUpBody(email string) map[string]any {
	return map[string]any{
		"name": "Orphan Test", "email": email, "password": "password123",
	}
}

func orphanAssertUserGone(t *testing.T, db *parityMemAdapter, email string) {
	t.Helper()
	row, err := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: email}}, nil)
	if err != nil {
		t.Fatalf("user lookup: %v", err)
	}
	if row != nil {
		t.Fatalf("orphan user row remains for %q: %#v", email, row)
	}
	n, err := db.Count(context.Background(), "account", nil)
	if err != nil {
		t.Fatalf("account count: %v", err)
	}
	if n != 0 {
		t.Fatalf("orphan account rows remain: %d", n)
	}
}

// Session-create failure (:413) rejects and leaves no user+account rows.
func TestSignUpOrphan_SessionCreateFailureRemovesUser(t *testing.T) {
	mem := newParityMemAdapter()
	db := &orphanFailSessionAdapter{parityMemAdapter: mem}
	opts := emailAuthTestOptions(mem)
	opts.DB = db
	api := credsSignUpAPI(t, opts)
	resp := api.Post("/api/auth/sign-up/email", orphanSignUpBody("orphan-session@test.com"))
	if resp.Code != 400 {
		t.Fatalf("sign-up status = %d, want 400: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), types.ErrFailedToCreateSession) {
		t.Fatalf("body must carry %q: %s", types.ErrFailedToCreateSession, resp.Body.String())
	}
	orphanAssertUserGone(t, mem, "orphan-session@test.com")
}

// Secondary-mirror failure (:426) rejects and leaves no user+account rows.
func TestSignUpOrphan_SecondaryMirrorFailureRemovesUser(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.SecondaryStorage = orphanFailSecondaryStorage{}
	api := credsSignUpAPI(t, opts)
	resp := api.Post("/api/auth/sign-up/email", orphanSignUpBody("orphan-mirror@test.com"))
	if resp.Code < 400 || resp.Code >= 600 {
		t.Fatalf("sign-up status = %d, want error: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), types.ErrFailedToCreateSession) {
		t.Fatalf("body must carry %q: %s", types.ErrFailedToCreateSession, resp.Body.String())
	}
	orphanAssertUserGone(t, db, "orphan-mirror@test.com")
}

// Session-cookie failure (:429, via a rejecting cookie-cache VersionFunc)
func TestSignUpOrphan_SessionCookieFailureRemovesUser(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.Session.CookieCache.Enabled = true
	opts.Session.CookieCache.VersionFunc = func(types.Session, types.User) (string, error) {
		return "", errors.New("orphan test: cookie cache version failed")
	}
	api := credsSignUpAPI(t, opts)
	resp := api.Post("/api/auth/sign-up/email", orphanSignUpBody("orphan-cookie@test.com"))
	if resp.Code < 400 || resp.Code >= 600 {
		t.Fatalf("sign-up status = %d, want error: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), types.ErrFailedToCreateSession) {
		t.Fatalf("body must carry %q: %s", types.ErrFailedToCreateSession, resp.Body.String())
	}
	orphanAssertUserGone(t, db, "orphan-cookie@test.com")
	n, err := db.Count(context.Background(), "session", nil)
	if err != nil || n != 0 {
		t.Fatalf("session rows = %d (err=%v), want 0", n, err)
	}
}

// Guard against over-deletion: the success path still keeps user+account rows.
func TestSignUpOrphan_SuccessKeepsRows(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	api := credsSignUpAPI(t, opts)
	resp := api.Post("/api/auth/sign-up/email", orphanSignUpBody("orphan-ok@test.com"))
	if resp.Code != 200 {
		t.Fatalf("sign-up status = %d, want 200: %s", resp.Code, resp.Body.String())
	}
	row, err := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: "orphan-ok@test.com"}}, nil)
	if err != nil || row == nil {
		t.Fatalf("user row must persist (err=%v row=%#v)", err, row)
	}
	n, err := db.Count(context.Background(), "account", nil)
	if err != nil || n != 1 {
		t.Fatalf("account rows = %d (err=%v), want 1", n, err)
	}
}
