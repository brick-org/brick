package routes

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/cookies"
	"github.com/brick-org/brick/auth/src/crypto"
	"github.com/brick-org/brick/auth/src/types"
)

// F2 task1: fresh plain verify must return {status:true,user:null} like
// upstream (ts:540-543), not the updated user.
func TestVerifyUpdateTo_FreshPlainVerifyReturnsNull(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	parityCreateUser(t, db, "f2-fresh@example.com", false)
	token, err := crypto.CreateEmailVerificationToken(opts.CurrentSecret(), "f2-fresh@example.com", "", 3600, nil)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	user, _, errCode, status := processVerifyEmail(context.Background(), opts, token, CookieRequestHeaders{})
	if errCode != "" {
		t.Fatalf("expected success, got %s (%d)", errCode, status)
	}
	if user != nil {
		t.Fatalf("fresh plain verify must return null user, got %#v", user)
	}
	row, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: "f2-fresh@example.com"}}, nil)
	if verified, _ := row["emailVerified"].(bool); !verified {
		t.Fatal("user row must still be marked verified")
	}
}

// failSetSecondary delegates Gets to an underlying map store but fails Sets,
// simulating a secondary fan-out backend failure.
type failSetSecondary struct {
	*mapSecondaryStorage
	failErr error
}

func (f *failSetSecondary) Set(key, value string, ttl *int) error {
	return f.failErr
}

func f2SeedDBSession(t *testing.T, db *parityMemAdapter, email, token string) {
	t.Helper()
	userRow, err := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: email}}, nil)
	if err != nil || userRow == nil {
		t.Fatalf("seed user %q missing: %v", email, err)
	}
	now := time.Now().UTC()
	if _, err := db.Create(context.Background(), "session", map[string]any{
		"id": "sess-" + token, "userId": stringField(userRow, "id"),
		"token": token, "expiresAt": now.Add(time.Hour),
		"createdAt": now, "updatedAt": now,
	}, nil); err != nil {
		t.Fatalf("seed session: %v", err)
	}
}

func f2StoredCtx(t *testing.T, opts types.Options, token string) context.Context {
	t.Helper()
	signed, err := cookies.Sign(opts.CurrentSecret(), token)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	req, _ := http.NewRequest(http.MethodPost, "https://example.com/api/auth/verify-email", nil)
	req.Header.Set("Cookie", resolveSessionCookieName(opts, false)+"="+signed)
	return context.WithValue(context.Background(), storedRequestKey{}, req)
}

func f2CookieCarries(cookiesOut []http.Cookie, opts types.Options, token string) bool {
	for _, c := range cookiesOut {
		if v, ok := cookies.VerifyAny(opts.AllSecrets(), c.Value); ok && v == token {
			return true
		}
		if strings.Contains(c.Value, token) {
			return true
		}
	}
	return false
}

// F2 task2: updateTo verification leg must reuse pre-update activeSession
// token (compare against OLD email), swapping cookie email, not mint new.
func TestVerifyUpdateTo_UpdateToReusesPreUpdateToken(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	opts.BasePath = "/api/auth"
	parityCreateUser(t, db, "f2-old@example.com", true)
	f2SeedDBSession(t, db, "f2-old@example.com", "sess-f2-reuse-1")
	ctx := f2StoredCtx(t, opts, "sess-f2-reuse-1")
	token, err := crypto.CreateEmailVerificationToken(opts.CurrentSecret(), "f2-old@example.com", "f2-new@example.com", 3600, map[string]any{"requestType": "change-email-verification"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	user, cookiesOut, errCode, _ := processVerifyEmailWithSession(ctx, opts, token, CookieRequestHeaders{}, "/", "f2-old@example.com")
	if errCode != "" {
		t.Fatalf("expected success, got %s", errCode)
	}
	if user == nil || user.Email != "f2-new@example.com" {
		t.Fatalf("expected updated user f2-new@example.com, got %#v", user)
	}
	sessions, _ := db.FindMany(context.Background(), "session", nil, 0, 0, nil, nil)
	if len(sessions) != 1 {
		t.Fatalf("matching session must be reused (1 row), got %d", len(sessions))
	}
	if !f2CookieCarries(cookiesOut, opts, "sess-f2-reuse-1") {
		t.Fatalf("cookies must carry reused pre-update token, got %#v", cookiesOut)
	}
}

// F2 task3: secondary fan-out failure must be log-only, route still succeeds.
func TestVerifyUpdateTo_FanOutFailureStillSucceeds(t *testing.T) {
	db := newParityMemAdapter()
	baseStore := newMapSecondaryStorage(true)
	opts := secondarySessionTestOptions(db, baseStore)
	parityCreateUser(t, db, "f2-fanout@example.com", false)
	// Seed one live secondary session so fan-out has work to do.
	seedSecondarySession(t, context.Background(), opts, db, "f2-fanout@example.com", "tok-f2-fanout", time.Now().UTC().Add(time.Hour))
	// Swap in a failing backend sharing the same data for Gets.
	failing := &failSetSecondary{mapSecondaryStorage: baseStore, failErr: context.DeadlineExceeded}
	opts.SecondaryStorage = failing
	token, err := crypto.CreateEmailVerificationToken(opts.CurrentSecret(), "f2-fanout@example.com", "", 3600, nil)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	user, _, errCode, status := processVerifyEmail(context.Background(), opts, token, CookieRequestHeaders{})
	if errCode != "" {
		t.Fatalf("fan-out failure must still succeed, got %s (%d)", errCode, status)
	}
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	_ = user
	row, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: "f2-fanout@example.com"}}, nil)
	if verified, _ := row["emailVerified"].(bool); !verified {
		t.Fatal("user row must still be marked verified despite fan-out failure")
	}
}
