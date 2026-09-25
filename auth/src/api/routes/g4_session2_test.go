package routes

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/api/state"
	"github.com/brick-org/brick/auth/src/types"
)

// G4: expired/invalid session_token must emit the expired session_token
// cleanup cookie alongside session_data cleanup (upstream deleteSessionCookie
// clears both; session.ts:291,380). DB row deletion already happens.
func TestG4_ExpiredTokenCleanupCookieOnFailure(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)

	// Expired session row: must fail with SESSION_EXPIRED and still carry
	// the expired session_token cleanup (MaxAge<0).
	seedSessionUser(t, db, "g4-expired@example.com", "tok-g4-expired", time.Now().UTC().Add(-time.Hour))
	res, err := resolveGetSession(ctx, opts, getSessionRequest{
		token:        "tok-g4-expired",
		cookieHeader: "",
		headers:      CookieRequestHeaders{},
	})
	if err == nil {
		t.Fatal("expired token must fail")
	}
	if res == nil {
		t.Fatal("auth failure must still return result carrying cleanup cookies")
	}
	tokenNames := map[string]struct{}{}
	for _, n := range sessionCookieLookupNames(opts) {
		tokenNames[n] = struct{}{}
	}
	foundToken := false
	for _, c := range res.cookies {
		if _, ok := tokenNames[c.Name]; ok && c.MaxAge < 0 {
			foundToken = true
			break
		}
	}
	if !foundToken {
		t.Fatalf("expired session_token must emit expired token cleanup cookie, got %+v", res.cookies)
	}

	// Invalid (unknown) token: must fail with FAILED_TO_GET_SESSION and
	// still carry the expired session_token cleanup.
	res2, err := resolveGetSession(ctx, opts, getSessionRequest{
		token:        "tok-g4-bogus",
		cookieHeader: "",
		headers:      CookieRequestHeaders{},
	})
	if err == nil {
		t.Fatal("bogus token must fail")
	}
	if res2 == nil {
		t.Fatal("auth failure must still return result carrying cleanup cookies")
	}
	foundToken = false
	for _, c := range res2.cookies {
		if _, ok := tokenNames[c.Name]; ok && c.MaxAge < 0 {
			foundToken = true
			break
		}
	}
	if !foundToken {
		t.Fatalf("invalid session_token must emit expired token cleanup cookie, got %+v", res2.cookies)
	}
}

// G5-part (session.go side): oversize session_data must chunk on write via
// cookies.BuildChunkedCookies; >100-chunks maps to warn-and-skip (serve
// authoritative, no cache).
func TestG4_ChunkedIssuanceMultiCookieOnOversize(t *testing.T) {
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	opts.Session.CookieCache.Enabled = true
	now := time.Now().UTC()
	big := strings.Repeat("x", 8000)
	session := types.Session{
		ID:        "sess-g4-big",
		UserID:    "user-g4-big",
		Token:     "tok-g4-big",
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
		UpdatedAt: now,
		AdditionalFields: map[string]any{
			"blob": big,
		},
	}
	user := types.User{
		ID:            "user-g4-big",
		Email:         "g4-big@example.com",
		EmailVerified: true,
		Name:          "G4",
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	cookiesOut, err := issueSessionCookies(opts, CookieRequestHeaders{}, "tok-g4-big", session, user, opts.Session, now, false)
	if err != nil {
		t.Fatalf("issueSessionCookies: %v", err)
	}
	// Session token + chunked session_data (≥2 chunks) => ≥3 cookies.
	if len(cookiesOut) < 3 {
		t.Fatalf("oversize session_data must chunk into multi-cookie issuance, got %d cookies: %+v", len(cookiesOut), cookiesOut)
	}
	chunked := 0
	for _, c := range cookiesOut {
		if strings.HasPrefix(c.Name, sessionDataCookieName+".") {
			chunked++
		}
	}
	if chunked < 2 {
		names := make([]string, 0, len(cookiesOut))
		for _, c := range cookiesOut {
			names = append(names, c.Name)
		}
		t.Fatalf("expected >=2 session_data chunks, got names %v", names)
	}
}

// shouldSkipSessionRefresh gating (session.go side): the skip flag must
// suppress the DB refresh write (upstream session.ts:201-204,342-344).
func TestG4_SkipGateSuppressesRefresh(t *testing.T) {
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	// Due session: expires soon so the refresh write is due.
	seedSessionUser(t, db, "g4-skip@example.com", "tok-g4-skip", time.Now().UTC().Add(30*time.Second))

	// Sanity: without the flag the due session refreshes.
	_, _, refreshed, _, err := loadSessionWithRefresh(context.Background(), opts, "tok-g4-skip", sessionRefreshConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !refreshed {
		t.Fatal("sanity: due session must refresh without the skip flag")
	}

	// With the flag set the refresh write must be suppressed.
	// Re-seed a second due session since the first was extended above.
	seedSessionUser(t, db, "g4-skip2@example.com", "tok-g4-skip2", time.Now().UTC().Add(30*time.Second))
	skipCtx := state.SetShouldSkipSessionRefresh(context.Background(), true)
	_, _, refreshed, _, err = loadSessionWithRefresh(skipCtx, opts, "tok-g4-skip2", sessionRefreshConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if refreshed {
		t.Fatal("shouldSkipSessionRefresh must suppress the DB refresh write")
	}
}
