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

// R5: POST verify must merge like GET — preserve the real request
// (URL/Host/RemoteAddr/headers), only filling Cookie/Authorization when the
// input carries them. The synthetic bare POST / shadows StoredRequestFromStd
// so hooks observe POST / instead of the real URL.
func TestVerifySessionReuse_PostVerifyPreservesRealRequest(t *testing.T) {
	realReq, _ := http.NewRequest(http.MethodPost, "https://example.com/api/auth/verify-email", nil)
	realReq.Host = "example.com"
	realReq.RemoteAddr = "1.2.3.4:5678"
	realReq.Header.Set("X-Custom", "custom-value")
	realReq.Header.Set("Cookie", "real-cookie-header")
	realReq.Header.Set("Authorization", "Bearer real-auth")
	ctx := context.WithValue(context.Background(), storedRequestKey{}, realReq)

	newCookie := "new-cookie-header"
	newAuth := "Bearer new-auth"
	mergedCtx := mergeVerifyPostStoredRequest(ctx, newCookie, newAuth)
	merged := StoredRequestFromStd(mergedCtx)
	if merged == nil {
		t.Fatal("expected stored request after merge")
	}
	if merged.URL == nil || merged.URL.Path != "/api/auth/verify-email" {
		t.Fatalf("hooks must observe real URL, got %#v (want /api/auth/verify-email)", merged.URL)
	}
	if merged.Host != "example.com" {
		t.Fatalf("must preserve Host, got %q", merged.Host)
	}
	if merged.RemoteAddr != "1.2.3.4:5678" {
		t.Fatalf("must preserve RemoteAddr, got %q", merged.RemoteAddr)
	}
	if got := merged.Header.Get("X-Custom"); got != "custom-value" {
		t.Fatalf("must preserve headers, X-Custom=%q", got)
	}
	if got := merged.Header.Get("Cookie"); got != newCookie {
		t.Fatalf("must fill Cookie from input, got %q", got)
	}
	if got := merged.Header.Get("Authorization"); got != newAuth {
		t.Fatalf("must fill Authorization from input, got %q", got)
	}
}

func TestVerifySessionReuse_PostVerifyPreservesHeadersWhenInputEmpty(t *testing.T) {
	realReq, _ := http.NewRequest(http.MethodPost, "https://example.com/api/auth/verify-email", nil)
	realReq.Host = "example.com"
	realReq.RemoteAddr = "9.9.9.9:1234"
	realReq.Header.Set("X-Custom", "keep-me")
	realReq.Header.Set("Cookie", "keep-cookie")
	realReq.Header.Set("Authorization", "Bearer keep-auth")
	ctx := context.WithValue(context.Background(), storedRequestKey{}, realReq)

	mergedCtx := mergeVerifyPostStoredRequest(ctx, "", "")
	merged := StoredRequestFromStd(mergedCtx)
	if merged == nil {
		t.Fatal("expected stored request after merge")
	}
	if merged.URL == nil || merged.URL.Path != "/api/auth/verify-email" {
		t.Fatalf("must preserve real URL, got %#v", merged.URL)
	}
	if got := merged.Header.Get("Cookie"); got != "keep-cookie" {
		t.Fatalf("empty input must not wipe Cookie, got %q", got)
	}
	if got := merged.Header.Get("Authorization"); got != "Bearer keep-auth" {
		t.Fatalf("empty input must not wipe Authorization, got %q", got)
	}
	if got := merged.Header.Get("X-Custom"); got != "keep-me" {
		t.Fatalf("must preserve headers, X-Custom=%q", got)
	}
}

func g6SeedSession(t *testing.T, db *parityMemAdapter, opts types.Options, email, token string) {
	t.Helper()
	userRow, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: email}}, nil)
	if userRow == nil {
		t.Fatalf("seed user %q missing", email)
	}
	now := time.Now().UTC()
	if _, err := db.Create(context.Background(), "session", map[string]any{
		"id": token, "userId": stringField(userRow, "id"),
		"token": token, "expiresAt": now.Add(time.Hour),
		"createdAt": now, "updatedAt": now,
	}, nil); err != nil {
		t.Fatalf("seed session: %v", err)
	}
}

func g6StoredCtx(t *testing.T, opts types.Options, token string) context.Context {
	t.Helper()
	signed, err := cookies.Sign(opts.CurrentSecret(), token)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	req, _ := http.NewRequest(http.MethodPost, "https://example.com/api/auth/verify-email", nil)
	req.Host = "example.com"
	req.RemoteAddr = "1.2.3.4:5678"
	req.Header.Set("Cookie", resolveSessionCookieName(opts, false)+"="+signed)
	return context.WithValue(context.Background(), storedRequestKey{}, req)
}

func g6CookieCarries(cookiesOut []http.Cookie, opts types.Options, token string) bool {
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

// G6: change-email-verification leg must reuse a live matching session
// (upstream TS:371-414 reuses activeSession when present).
func TestVerifySessionReuse_ChangeEmailVerificationReusesMatchingSession(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	opts.BasePath = "/api/auth"
	parityCreateUser(t, db, "g6-old@example.com", true)
	g6SeedSession(t, db, opts, "g6-old@example.com", "sess-g6-reuse-1")
	ctx := g6StoredCtx(t, opts, "sess-g6-reuse-1")

	token, err := crypto.CreateEmailVerificationToken(opts.CurrentSecret(), "g6-old@example.com", "g6-new@example.com", 3600, map[string]any{"requestType": "change-email-verification"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	user, cookiesOut, errCode, _ := processVerifyEmailWithSession(ctx, opts, token, CookieRequestHeaders{}, "/", "g6-old@example.com")
	if errCode != "" {
		t.Fatalf("expected success, got %s", errCode)
	}
	if user == nil || user.Email != "g6-new@example.com" {
		t.Fatalf("expected updated user g6-new@example.com, got %#v", user)
	}
	sessions, _ := db.FindMany(context.Background(), "session", nil, 0, 0, nil, nil)
	if len(sessions) != 1 {
		t.Fatalf("matching session must be reused (1 row), got %d", len(sessions))
	}
	if !g6CookieCarries(cookiesOut, opts, "sess-g6-reuse-1") {
		t.Fatalf("cookies must carry reused token, got %#v", cookiesOut)
	}
}

// G6: change-email-verification leg must mint on mismatch.
func TestVerifySessionReuse_ChangeEmailVerificationMintsOnMismatch(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	opts.BasePath = "/api/auth"
	parityCreateUser(t, db, "g6-old2@example.com", true)
	parityCreateUser(t, db, "g6-other@example.com", true)
	g6SeedSession(t, db, opts, "g6-other@example.com", "sess-g6-other-1")
	ctx := g6StoredCtx(t, opts, "sess-g6-other-1")

	token, err := crypto.CreateEmailVerificationToken(opts.CurrentSecret(), "g6-old2@example.com", "g6-new2@example.com", 3600, map[string]any{"requestType": "change-email-verification"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	// sessionEmail "" skips the INVALID_USER gate (POST shape) so the
	// mismatch surfaces as mint, mirroring the plain-leg mismatch test.
	user, cookiesOut, errCode, _ := processVerifyEmailWithSession(ctx, opts, token, CookieRequestHeaders{}, "/", "")
	if errCode != "" {
		t.Fatalf("expected success, got %s", errCode)
	}
	if user == nil || user.Email != "g6-new2@example.com" {
		t.Fatalf("expected updated user, got %#v", user)
	}
	sessions, _ := db.FindMany(context.Background(), "session", nil, 0, 0, nil, nil)
	if len(sessions) != 2 {
		t.Fatalf("mismatched session must mint (2 rows), got %d", len(sessions))
	}
	if g6CookieCarries(cookiesOut, opts, "sess-g6-other-1") {
		t.Fatalf("mismatched session must not be reused, got %#v", cookiesOut)
	}
}

// G6: legacy (default updateTo, no requestType) must reuse on match
// (upstream TS:421-478 reuses activeSession when present).
func TestVerifySessionReuse_LegacyUpdateToReusesMatchingSession(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	opts.BasePath = "/api/auth"
	parityCreateUser(t, db, "g6-leg-old@example.com", true)
	g6SeedSession(t, db, opts, "g6-leg-old@example.com", "sess-g6-leg-reuse-1")
	ctx := g6StoredCtx(t, opts, "sess-g6-leg-reuse-1")

	token, err := crypto.CreateEmailVerificationToken(opts.CurrentSecret(), "g6-leg-old@example.com", "g6-leg-new@example.com", 3600, nil)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	user, cookiesOut, errCode, _ := processVerifyEmailWithSession(ctx, opts, token, CookieRequestHeaders{}, "/", "g6-leg-old@example.com")
	if errCode != "" {
		t.Fatalf("expected success, got %s", errCode)
	}
	if user == nil || user.Email != "g6-leg-new@example.com" {
		t.Fatalf("expected updated user, got %#v", user)
	}
	sessions, _ := db.FindMany(context.Background(), "session", nil, 0, 0, nil, nil)
	if len(sessions) != 1 {
		t.Fatalf("matching session must be reused (1 row), got %d", len(sessions))
	}
	if !g6CookieCarries(cookiesOut, opts, "sess-g6-leg-reuse-1") {
		t.Fatalf("cookies must carry reused token, got %#v", cookiesOut)
	}
}

// G6: legacy leg must mint on mismatch.
func TestVerifySessionReuse_LegacyUpdateToMintsOnMismatch(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	opts.BasePath = "/api/auth"
	parityCreateUser(t, db, "g6-leg-old2@example.com", true)
	parityCreateUser(t, db, "g6-leg-other@example.com", true)
	g6SeedSession(t, db, opts, "g6-leg-other@example.com", "sess-g6-leg-other-1")
	ctx := g6StoredCtx(t, opts, "sess-g6-leg-other-1")

	token, err := crypto.CreateEmailVerificationToken(opts.CurrentSecret(), "g6-leg-old2@example.com", "g6-leg-new2@example.com", 3600, nil)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	user, cookiesOut, errCode, _ := processVerifyEmailWithSession(ctx, opts, token, CookieRequestHeaders{}, "/", "")
	if errCode != "" {
		t.Fatalf("expected success, got %s", errCode)
	}
	if user == nil || user.Email != "g6-leg-new2@example.com" {
		t.Fatalf("expected updated user, got %#v", user)
	}
	sessions, _ := db.FindMany(context.Background(), "session", nil, 0, 0, nil, nil)
	if len(sessions) != 2 {
		t.Fatalf("mismatched session must mint (2 rows), got %d", len(sessions))
	}
	if g6CookieCarries(cookiesOut, opts, "sess-g6-leg-other-1") {
		t.Fatalf("mismatched session must not be reused, got %#v", cookiesOut)
	}
}
