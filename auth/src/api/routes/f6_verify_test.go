package routes

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/cookies"
	"github.com/brick-org/brick/auth/src/crypto"
	"github.com/brick-org/brick/auth/src/types"
)

// F6 GAP-1: change-email resend links must QueryEscape token/callbackURL.
func TestF6_ChangeEmailConfirmationResendEscapes(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	opts.BasePath = "/api/auth"
	var gotURL, gotToken string
	opts.EmailVerification.SendVerificationEmail = func(data types.VerificationEmailData) error {
		gotURL = data.URL
		gotToken = data.Token
		return nil
	}
	parityCreateUser(t, db, "old@example.com", true)
	token, err := crypto.CreateEmailVerificationToken(opts.CurrentSecret(), "old@example.com", "new@example.com", 3600, map[string]any{"requestType": "change-email-confirmation"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	callback := "/cb?next=/a&x=1"
	_, _, errCode, _ := processVerifyEmailWithSession(context.Background(), opts, token, CookieRequestHeaders{}, callback, "")
	if errCode != "" {
		t.Fatalf("expected success, got %s", errCode)
	}
	if gotURL == "" {
		t.Fatal("expected resend URL")
	}
	u, err := url.Parse(gotURL)
	if err != nil {
		t.Fatalf("parse URL %q: %v", gotURL, err)
	}
	q := u.Query()
	if q.Get("callbackURL") != callback {
		t.Fatalf("callbackURL round-trip = %q, want %q (raw URL %q)", q.Get("callbackURL"), callback, gotURL)
	}
	if q.Get("token") != gotToken {
		t.Fatalf("token round-trip mismatch: %q vs %q (URL %q)", q.Get("token"), gotToken, gotURL)
	}
	if !strings.Contains(gotURL, url.QueryEscape(callback)) {
		t.Fatalf("URL must contain escaped callbackURL, got %q", gotURL)
	}
}

func TestF6_ChangeEmailLegacyResendEscapes(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	opts.BasePath = "/api/auth"
	var gotURL, gotToken string
	opts.EmailVerification.SendVerificationEmail = func(data types.VerificationEmailData) error {
		gotURL = data.URL
		gotToken = data.Token
		return nil
	}
	parityCreateUser(t, db, "legacy-old@example.com", true)
	token, err := crypto.CreateEmailVerificationToken(opts.CurrentSecret(), "legacy-old@example.com", "legacy-new@example.com", 3600, nil)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	callback := "/cb?next=/a&x=1 y=2"
	_, _, errCode, _ := processVerifyEmailWithSession(context.Background(), opts, token, CookieRequestHeaders{}, callback, "")
	if errCode != "" {
		t.Fatalf("expected success, got %s", errCode)
	}
	if gotURL == "" {
		t.Fatal("expected resend URL")
	}
	u, err := url.Parse(gotURL)
	if err != nil {
		t.Fatalf("parse URL %q: %v", gotURL, err)
	}
	q := u.Query()
	if q.Get("callbackURL") != callback {
		t.Fatalf("callbackURL round-trip = %q, want %q (raw URL %q)", q.Get("callbackURL"), callback, gotURL)
	}
	if q.Get("token") != gotToken {
		t.Fatalf("token round-trip mismatch (URL %q)", gotURL)
	}
}

// F6 GAP-3: autoSignIn reuses matching live session instead of minting.
func TestF6_AutoSignInReusesMatchingSession(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	opts.BasePath = "/api/auth"
	opts.EmailVerification.AutoSignInAfterVerification = true
	parityCreateUser(t, db, "reuse@example.com", false)
	userRow, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: "reuse@example.com"}}, nil)
	if userRow == nil {
		t.Fatal("seed user missing")
	}
	now := time.Now().UTC()
	existingToken := "sess-reuse-1"
	if _, err := db.Create(context.Background(), "session", map[string]any{
		"id": "sess-reuse-1", "userId": stringField(userRow, "id"),
		"token": existingToken, "expiresAt": now.Add(time.Hour),
		"createdAt": now, "updatedAt": now,
	}, nil); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	signed, err := cookies.Sign(opts.CurrentSecret(), existingToken)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	req, _ := http.NewRequest("POST", "/", nil)
	req.Header.Set("Cookie", resolveSessionCookieName(opts, false)+"="+signed)
	ctx := context.WithValue(context.Background(), storedRequestKey{}, req)
	verifyToken, err := crypto.CreateEmailVerificationToken(opts.CurrentSecret(), "reuse@example.com", "", 3600, nil)
	if err != nil {
		t.Fatalf("issue verify token: %v", err)
	}
	_, cookiesOut, errCode, _ := processVerifyEmail(ctx, opts, verifyToken, CookieRequestHeaders{})
	if errCode != "" {
		t.Fatalf("expected success, got %s", errCode)
	}
	sessions, _ := db.FindMany(context.Background(), "session", nil, 0, 0, nil, nil)
	if len(sessions) != 1 {
		t.Fatalf("matching session must be reused (1 row), got %d", len(sessions))
	}
	if len(cookiesOut) == 0 {
		t.Fatal("expected session cookies")
	}
	foundReuse := false
	for _, c := range cookiesOut {
		if v, ok := cookies.VerifyAny(opts.AllSecrets(), c.Value); ok && v == existingToken {
			foundReuse = true
		}
		// Also accept raw token in cookie value (unsigned fallback names).
		if strings.Contains(c.Value, existingToken) {
			foundReuse = true
		}
	}
	if !foundReuse {
		t.Fatalf("cookies must carry the reused session token %q, got %#v", existingToken, cookiesOut)
	}
}

func TestF6_AutoSignInMintsOnMismatch(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	opts.BasePath = "/api/auth"
	opts.EmailVerification.AutoSignInAfterVerification = true
	parityCreateUser(t, db, "target@example.com", false)
	parityCreateUser(t, db, "other@example.com", true)
	otherRow, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: "other@example.com"}}, nil)
	now := time.Now().UTC()
	otherToken := "sess-other-1"
	if _, err := db.Create(context.Background(), "session", map[string]any{
		"id": "sess-other-1", "userId": stringField(otherRow, "id"),
		"token": otherToken, "expiresAt": now.Add(time.Hour),
		"createdAt": now, "updatedAt": now,
	}, nil); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	signed, _ := cookies.Sign(opts.CurrentSecret(), otherToken)
	req, _ := http.NewRequest("POST", "/", nil)
	req.Header.Set("Cookie", resolveSessionCookieName(opts, false)+"="+signed)
	ctx := context.WithValue(context.Background(), storedRequestKey{}, req)
	verifyToken, _ := crypto.CreateEmailVerificationToken(opts.CurrentSecret(), "target@example.com", "", 3600, nil)
	_, _, errCode, _ := processVerifyEmail(ctx, opts, verifyToken, CookieRequestHeaders{})
	if errCode != "" {
		t.Fatalf("expected success, got %s", errCode)
	}
	sessions, _ := db.FindMany(context.Background(), "session", nil, 0, 0, nil, nil)
	if len(sessions) != 2 {
		t.Fatalf("mismatched session must mint (2 rows), got %d", len(sessions))
	}
}
