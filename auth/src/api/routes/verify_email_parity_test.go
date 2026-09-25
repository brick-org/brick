package routes

import (
	"context"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/crypto"
	"github.com/brick-org/brick/auth/src/types"
)

func TestProcessVerifyEmail_HMACMarksVerifiedAndReturnsUser(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	parityCreateUser(t, db, "verify-me@example.com", false)

	token, err := crypto.GenerateToken(opts.CurrentSecret(), "verify-me@example.com", time.Hour)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	user, _, errCode, status := processVerifyEmail(context.Background(), opts, token, CookieRequestHeaders{})
	if errCode != "" {
		t.Fatalf("expected success, got %s (%d)", errCode, status)
	}
	if user == nil || user.Email != "verify-me@example.com" || !user.EmailVerified {
		t.Fatalf("expected verified user object, got %#v", user)
	}
	row, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: "verify-me@example.com"}}, nil)
	if verified, _ := row["emailVerified"].(bool); !verified {
		t.Fatal("user row must be marked verified")
	}
}

func TestProcessVerifyEmail_AlreadyVerifiedReturnsUser(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	parityCreateUser(t, db, "verified@example.com", true)

	token, err := crypto.GenerateToken(opts.CurrentSecret(), "verified@example.com", time.Hour)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	user, _, errCode, status := processVerifyEmail(context.Background(), opts, token, CookieRequestHeaders{})
	if errCode != "" {
		t.Fatalf("expected success, got %s (%d)", errCode, status)
	}
	if user != nil {
		t.Fatalf("already-verified must return null user, got %#v", user)
	}
}

func TestProcessVerifyEmail_InvalidTokenReportsUnauthorized(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	parityCreateUser(t, db, "someone@example.com", false)

	_, _, errCode, status := processVerifyEmail(context.Background(), opts, "bogus", CookieRequestHeaders{})
	if errCode != types.ErrInvalidToken || status != 401 {
		t.Fatalf("expected INVALID_TOKEN/401, got %s/%d", errCode, status)
	}
}

func TestProcessVerifyEmail_ExpiredHMACTokenReportsTokenExpired(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	parityCreateUser(t, db, "expired@example.com", false)

	token, err := crypto.GenerateToken(opts.CurrentSecret(), "expired@example.com", -time.Hour)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	_, _, errCode, status := processVerifyEmail(context.Background(), opts, token, CookieRequestHeaders{})
	if errCode != types.ErrTokenExpired || status != 401 {
		t.Fatalf("expected TOKEN_EXPIRED/401, got %s/%d", errCode, status)
	}
}

func TestProcessVerifyEmail_UnknownUserReportsUserNotFound(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)

	token, err := crypto.GenerateToken(opts.CurrentSecret(), "ghost@example.com", time.Hour)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	_, _, errCode, status := processVerifyEmail(context.Background(), opts, token, CookieRequestHeaders{})
	if errCode != types.ErrUserNotFound || status != 404 {
		t.Fatalf("expected USER_NOT_FOUND/404, got %s/%d", errCode, status)
	}
}

func TestProcessVerifyEmail_RunsBeforeAndAfterHooks(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	var order []string
	opts.EmailVerification.BeforeEmailVerification = func(user *types.User) error {
		order = append(order, "before:"+user.Email)
		return nil
	}
	opts.EmailVerification.AfterEmailVerification = func(user *types.User) error {
		order = append(order, "after")
		return nil
	}
	parityCreateUser(t, db, "hooked@example.com", false)

	token, err := crypto.GenerateToken(opts.CurrentSecret(), "hooked@example.com", time.Hour)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	if _, _, errCode, _ := processVerifyEmail(context.Background(), opts, token, CookieRequestHeaders{}); errCode != "" {
		t.Fatalf("expected success, got %s", errCode)
	}
	if len(order) != 2 || order[0] != "before:hooked@example.com" || order[1] != "after" {
		t.Fatalf("expected before/after hooks in order, got %#v", order)
	}
}

func TestProcessVerifyEmail_AutoSignInMintsSession(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	opts.EmailVerification.AutoSignInAfterVerification = true
	parityCreateUser(t, db, "autosignin@example.com", false)

	token, err := crypto.GenerateToken(opts.CurrentSecret(), "autosignin@example.com", time.Hour)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	user, cookies, errCode, _ := processVerifyEmail(context.Background(), opts, token, CookieRequestHeaders{})
	if errCode != "" {
		t.Fatalf("expected success, got %s", errCode)
	}
	if user == nil {
		t.Fatal("expected user object")
	}
	if len(cookies) == 0 {
		t.Fatal("expected session cookies for auto sign-in")
	}
	sessions, _ := db.FindMany(context.Background(), "session", nil, 0, 0, nil, nil)
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session row, got %d", len(sessions))
	}
}

func TestAppendRedirectQuery(t *testing.T) {
	if got := appendRedirectQuery("https://app.example/cb", "error", "INVALID_TOKEN"); got != "https://app.example/cb?error=INVALID_TOKEN" {
		t.Fatalf("plain append: %q", got)
	}
	if got := appendRedirectQuery("https://app.example/cb?x=1", "token", "abc"); got != "https://app.example/cb?x=1&token=abc" {
		t.Fatalf("existing query append: %q", got)
	}
}
