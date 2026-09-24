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

// Upstream update-session.ts: a cookie-cached session with no backing row in
// a durable store fails closed — except in DB-less deployments, where the
// signed cookie IS the session record and the update merges into it
// ("still refreshes the cookie in a DB-less deployment when no row exists").

// mintStatelessHeader builds a Cookie header for a session that exists only
// in the signed cookie cache (no database row anywhere).
func mintStatelessHeader(t *testing.T, opts types.Options, token string, session types.Session, user types.User) string {
	t.Helper()
	signed, err := cookies.Sign(opts.CurrentSecret(), token)
	if err != nil {
		t.Fatal(err)
	}
	cacheCookie, err := newSessionDataCookie(opts.CurrentSecret(), session, user, opts.Session, time.Now().UTC(), false)
	if err != nil {
		t.Fatal(err)
	}
	return resolveSessionCookieName(opts, false) + "=" + signed + "; " + cacheCookie.Name + "=" + cacheCookie.Value
}

func statelessSessionFixture(token string) (types.Session, types.User) {
	now := time.Now().UTC()
	return types.Session{
		ID:        "sess-" + token,
		UserID:    "user-" + token,
		Token:     token,
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
		UpdatedAt: now,
	}, types.User{
		ID:            "user-" + token,
		Email:         "stateless@example.com",
		Name:          "stateless",
		EmailVerified: false,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

func statelessTestOptions() types.Options {
	opts := parityTestOptions(nil)
	opts.DB = nil
	opts.Session.CookieCache.Enabled = true
	return opts
}

func TestV1_DBlessUpdateSessionFromCookieCache(t *testing.T) {
	opts := statelessTestOptions()
	session, user := statelessSessionFixture("tok-stateless")
	header := mintStatelessHeader(t, opts, "tok-stateless", session, user)

	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	UpdateSession(api, "/api/auth", opts)
	resp := api.Post("/api/auth/update-session", "Cookie: "+header, map[string]any{"theme": "dark"})
	if resp.Code != http.StatusOK {
		t.Fatalf("DB-less update expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), `"dark"`) {
		t.Fatalf("updated field missing from response: %s", resp.Body.String())
	}
	if resp.Header().Get("Set-Cookie") == "" {
		t.Fatal("DB-less update must refresh the cookie")
	}

	// Unknown token with no cache: 401, cookies expired.
	badResp := api.Post("/api/auth/update-session", "Cookie: "+signedSessionHeader(t, opts, "tok-missing"), map[string]any{"theme": "x"})
	if badResp.Code != http.StatusUnauthorized {
		t.Fatalf("DB-less unknown token expected 401, got %d: %s", badResp.Code, badResp.Body.String())
	}
}

func TestV1_DBlessGetSessionFromCookieCache(t *testing.T) {
	// Upstream "should work without database (session stored in cookie only)":
	// a valid cache serves with no database round-trip even when DB is nil.
	opts := statelessTestOptions()
	session, user := statelessSessionFixture("tok-cache-only")
	header := mintStatelessHeader(t, opts, "tok-cache-only", session, user)
	res, err := resolveGetSession(context.Background(), opts, getSessionRequest{
		token:        "tok-cache-only",
		cookieHeader: header,
		headers:      CookieRequestHeaders{},
	})
	if err != nil {
		t.Fatalf("DB-less cache hit must serve: %v", err)
	}
	if res.user.Email != "stateless@example.com" || res.session.Token != "tok-cache-only" {
		t.Fatalf("wrong session served: %+v / %+v", res.session, res.user)
	}
}
