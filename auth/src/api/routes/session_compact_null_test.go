package routes

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/cookies"
	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

// F5 parity: get-session literal null, user-missing null, compact interop,
// dont_remember expiry on expiry.

func TestSessionCompactNull_GetSessionNullLiteral(t *testing.T) {
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	GetSession(api, "/api/auth", opts)

	resp := api.Get("/api/auth/get-session")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	got := strings.TrimSpace(resp.Body.String())
	if got != "null" {
		t.Fatalf("get-session missing token must be literal null, got %q", resp.Body.String())
	}
	if cc := resp.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", cc)
	}
}

func TestSessionCompactNull_UserMissingReturnsNull(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	now := time.Now().UTC()
	if _, err := db.Create(ctx, "session", map[string]any{
		"id": "sess-f5-orphan", "userId": "no-such-user", "token": "tok-f5-orphan",
		"expiresAt": now.Add(time.Hour), "createdAt": now, "updatedAt": now,
	}, nil); err != nil {
		t.Fatal(err)
	}
	// Resolver keeps an error for middleware (FAILED, not USER_NOT_FOUND).
	_, err := resolveGetSession(ctx, opts, getSessionRequest{token: "tok-f5-orphan", headers: CookieRequestHeaders{}})
	if err == nil {
		t.Fatal("orphan session must error at resolver layer")
	}
	status, detail := statusOf(t, err)
	if status == http.StatusNotFound || strings.Contains(detail, types.ErrUserNotFound) {
		t.Fatalf("orphan must not be 404 USER_NOT_FOUND, got %d %q", status, detail)
	}
	if status != http.StatusUnauthorized || !strings.Contains(detail, types.ErrFailedToGetSession) {
		t.Fatalf("orphan resolver: got %d %q, want 401 FAILED_TO_GET_SESSION", status, detail)
	}
	// HTTP layer maps to literal null.
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	GetSession(api, "/api/auth", opts)
	resp := api.Get("/api/auth/get-session", "Cookie: "+signedSessionHeader(t, opts, "tok-f5-orphan"))
	if resp.Code != http.StatusOK {
		t.Fatalf("orphan HTTP: got %d, want 200: %s", resp.Code, resp.Body.String())
	}
	if got := strings.TrimSpace(resp.Body.String()); got != "null" {
		t.Fatalf("orphan HTTP must be literal null, got %q", resp.Body.String())
	}
}

func TestSessionCompactNull_CompactInteropRead(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	opts.Session.CookieCache.Enabled = true
	seedSessionUser(t, db, "f5-compact@example.com", "tok-f5-compact", time.Now().UTC().Add(time.Hour))

	sessionRow, userRow, _, err := loadSessionAndUser(ctx, opts, "tok-f5-compact")
	if err != nil {
		t.Fatal(err)
	}
	session, user := rowToSession(sessionRow, opts), rowToUser(userRow, opts)
	sm, err := cacheStructMap(session)
	if err != nil {
		t.Fatal(err)
	}
	um, err := cacheStructMap(user)
	if err != nil {
		t.Fatal(err)
	}
	filterCookieCacheMaps(sm, um, opts, opts.Session)
	sessionData := map[string]any{
		"session":   sm,
		"user":      um,
		"updatedAt": time.Now().UnixMilli(),
		"version":   "1",
	}
	upstreamValue, err := cookies.CreateCompactCookieCache(opts.CurrentSecret(), sessionData, 5*time.Minute)
	if err != nil {
		t.Fatalf("mint upstream compact: %v", err)
	}
	// TS-issued compact value must hit the Go fast path (with legacy fallback intact).
	header := signedSessionHeader(t, opts, "tok-f5-compact") + "; " + sessionDataCookieName + "=" + upstreamValue
	if _, ok := cachedSessionFromRequest(header, opts.AllSecrets(), "tok-f5-compact", opts.Session); !ok {
		t.Fatal("TS-issued compact value must hit cachedSessionFromRequest")
	}
	if _, ok := cachedSessionFromRequestFull(ctx, header, opts.AllSecrets(), "tok-f5-compact", opts); !ok {
		t.Fatal("TS-issued compact value must hit cachedSessionFromRequestFull")
	}
	res, err := resolveGetSession(ctx, opts, getSessionRequest{
		token:        "tok-f5-compact",
		cookieHeader: header,
		headers:      CookieRequestHeaders{},
	})
	if err != nil {
		t.Fatalf("resolve with upstream compact: %v", err)
	}
	if res.session.Token != "tok-f5-compact" {
		t.Fatalf("wrong session: %+v", res.session)
	}
}

func TestSessionCompactNull_CompactInteropWrite(t *testing.T) {
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	opts.Session.CookieCache.Enabled = true
	seedSessionUser(t, db, "f5-compact-write@example.com", "tok-f5-compact-write", time.Now().UTC().Add(time.Hour))
	ctx := context.Background()
	sessionRow, userRow, _, err := loadSessionAndUser(ctx, opts, "tok-f5-compact-write")
	if err != nil {
		t.Fatal(err)
	}
	session, user := rowToSession(sessionRow, opts), rowToUser(userRow, opts)
	minted, err := newSessionDataCookie(opts.CurrentSecret(), session, user, opts, opts.Session, time.Now().UTC(), false)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	// Go-minted compact value must verify via upstream VerifyCompactCookieCache.
	got, _, verr := cookies.VerifyCompactCookieCache(opts.AllSecrets(), minted.Value)
	if verr != nil {
		t.Fatalf("Go compact value must verify upstream, got %v", verr)
	}
	inner, _ := got["session"].(map[string]any)
	if inner == nil {
		t.Fatalf("upstream payload missing inner session: %v", got)
	}
}

func TestSessionCompactNull_DontRememberExpiredOnExpiry(t *testing.T) {
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	seedSessionUser(t, db, "f5-expire@example.com", "tok-f5-expire", time.Now().UTC().Add(-time.Hour))
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	GetSession(api, "/api/auth", opts)
	resp := api.Get("/api/auth/get-session", "Cookie: "+signedSessionHeader(t, opts, "tok-f5-expire"))
	if resp.Code != http.StatusOK {
		t.Fatalf("expired: got %d, want 200: %s", resp.Code, resp.Body.String())
	}
	if got := strings.TrimSpace(resp.Body.String()); got != "null" {
		t.Fatalf("expired must be literal null, got %q", resp.Body.String())
	}
	// dont_remember marker must be expired alongside session_token + session_data.
	var foundSession, foundDontRemember bool
	for _, sc := range resp.Result().Cookies() {
		if strings.Contains(sc.Name, "session_token") && sc.MaxAge < 0 {
			foundSession = true
		}
		if strings.Contains(sc.Name, "dont_remember") && sc.MaxAge < 0 {
			foundDontRemember = true
		}
	}
	// Fallback to raw header scan (humatest may join cookies).
	raw := resp.Header().Get("Set-Cookie")
	if !foundSession && !strings.Contains(raw, "session_token") {
		t.Fatalf("expired 200-null must emit session_token cleanup, got %q", raw)
	}
	if !foundDontRemember {
		// Scan raw headers for dont_remember expiry.
		found := false
		for _, h := range resp.Result().Header.Values("Set-Cookie") {
			if strings.Contains(h, "dont_remember") && (strings.Contains(h, "Max-Age=0") || strings.Contains(h, "max-age=0") || strings.Contains(h, "Expires=Thu, 01 Jan 1970")) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expired 200-null must expire dont_remember marker, got %q / cookies %v", raw, resp.Result().Cookies())
		}
	}
}
