package routes

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

// Upstream: session-api.test.ts "should set cookies correctly on sign in"
// (session_token max-age 604800) and "should not exceed the 400-day browser
// Max-Age ceiling on session refresh" (#9609). The session_token cookie must
// carry Max-Age=expiresIn (upstream getCookies/setSessionCookie,
// cookies/index.ts:122-125, session.ts:386-397); non-persistent sessions stay

// sessionTokenMaxAge extracts Max-Age for the named cookie from the response.
func sessionTokenMaxAge(t *testing.T, resp *httptest.ResponseRecorder, name string) (int, bool) {
	t.Helper()
	found := false
	maxAge := -1
	for _, line := range resp.Header().Values("Set-Cookie") {
		parts := strings.Split(line, ";")
		if len(parts) == 0 {
			continue
		}
		if strings.TrimSpace(strings.SplitN(parts[0], "=", 2)[0]) != name {
			continue
		}
		found = true
		for _, attr := range parts[1:] {
			if rest, ok := strings.CutPrefix(strings.TrimSpace(attr), "Max-Age="); ok {
				if n, err := strconv.Atoi(rest); err == nil {
					maxAge = n
				}
			}
		}
	}
	return maxAge, found
}

func TestSessionMaxAge_SessionTokenMaxAgeDefault(t *testing.T) {
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	cookie, err := issueSessionCookie(opts, CookieRequestHeaders{}, "tok", time.Now().UTC().Add(time.Hour), false)
	if err != nil {
		t.Fatal(err)
	}
	if cookie.MaxAge != 3600 {
		t.Fatalf("persistent session_token MaxAge = %d, want 3600", cookie.MaxAge)
	}

	transient, err := issueSessionCookie(opts, CookieRequestHeaders{}, "tok", time.Now().UTC().Add(time.Hour), true)
	if err != nil {
		t.Fatal(err)
	}
	if transient.MaxAge != 0 {
		t.Fatalf("dontRememberMe session_token MaxAge = %d, want 0 (absent)", transient.MaxAge)
	}
}

func TestSessionMaxAge_SessionTokenMaxAgeRefreshCeiling(t *testing.T) {
	const ceiling = 400 * 24 * 60 * 60
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	opts.Session.ExpiresIn = ceiling
	opts.Session.UpdateAge = intPtr(30)
	seedSessionUser(t, db, "ceiling@example.com", "tok-ceiling", time.Now().UTC().Add(30*time.Second))
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	GetSession(api, "/api/auth", opts)
	resp := api.Get("/api/auth/get-session", "Cookie: "+signedSessionHeader(t, opts, "tok-ceiling"))
	if resp.Code != http.StatusOK {
		t.Fatalf("GET expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	maxAge, found := sessionTokenMaxAge(t, resp, resolveSessionCookieName(opts, false))
	if !found {
		t.Fatal("no session_token Set-Cookie on refresh")
	}
	if maxAge <= 0 || maxAge > ceiling {
		t.Fatalf("refreshed session_token Max-Age = %d, want in (0, %d]", maxAge, ceiling)
	}
}

func TestSessionMaxAge_SessionTokenMaxAgeSignInDefault(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	cookie, err := issueSessionCookie(opts, CookieRequestHeaders{}, "tok", time.Now().UTC().Add(7*24*time.Hour), false)
	if err != nil {
		t.Fatal(err)
	}
	if cookie.MaxAge != 60*60*24*7 {
		t.Fatalf("default session_token MaxAge = %d, want 604800", cookie.MaxAge)
	}
}
