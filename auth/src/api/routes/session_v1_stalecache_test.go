package routes

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/types"
)

// Upstream session.ts get-session:
//   - session_data present while cookieCache is DISABLED → clean() expires the
//     retired cookie plus its chunks (session.ts:102-109;
//     cookie-cache-fallback.test.ts "ignores retired session_data when caching
//     is disabled in configuration").

func expiredNamedCookie(respCookies []http.Cookie, name string) (http.Cookie, bool) {
	for _, c := range respCookies {
		if c.Name == name && c.MaxAge < 0 {
			return c, true
		}
	}
	return http.Cookie{}, false
}

func TestV1_MalformedCacheExpiredAndServed(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	opts.Session.CookieCache.Enabled = true
	seedSessionUser(t, db, "malformed@example.com", "tok-malformed", time.Now().UTC().Add(time.Hour))

	header := signedSessionHeader(t, opts, "tok-malformed") + "; " +
		sessionDataCookieName + "=bm90LWpzb24"
	res, err := resolveGetSession(ctx, opts, getSessionRequest{
		token:        "tok-malformed",
		cookieHeader: header,
		headers:      CookieRequestHeaders{},
	})
	if err != nil {
		t.Fatalf("malformed cache must fall through to DB: %v", err)
	}
	if res.user.Email != "malformed@example.com" {
		t.Fatalf("served wrong user: %+v", res.user)
	}
	if _, ok := expiredNamedCookie(res.cookies, sessionDataCookieName); !ok {
		names := []string{}
		for _, c := range res.cookies {
			names = append(names, c.Name)
		}
		t.Fatalf("malformed session_data must be expired, got cookies %v", names)
	}
}

func TestV1_RetiredCacheCleanedWhenDisabled(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	opts.Session.CookieCache.Enabled = false
	opts.Advanced.Cookies = map[string]types.CookieConfig{
		"session_token": {Name: "custom.session_token"},
		"session_data":  {Name: "custom.session"},
	}
	seedSessionUser(t, db, "retired@example.com", "tok-retired", time.Now().UTC().Add(time.Hour))
	header := signedSessionHeader(t, opts, "tok-retired") +
		"; custom.session=retired-value" +
		"; custom.session.0=stale" +
		"; custom.session.1=chunks"
	res, err := resolveGetSession(ctx, opts, getSessionRequest{
		token:        "tok-retired",
		cookieHeader: header,
		headers:      CookieRequestHeaders{},
	})
	if err != nil {
		t.Fatalf("retired cache must not block the DB read: %v", err)
	}
	if res.user.Email != "retired@example.com" {
		t.Fatalf("served wrong user: %+v", res.user)
	}
	for _, name := range []string{"custom.session", "custom.session.0", "custom.session.1"} {
		if _, ok := expiredNamedCookie(res.cookies, name); !ok {
			t.Errorf("retired %q must be expired with Max-Age=0", name)
		}
	}
	for _, c := range res.cookies {
		if strings.HasPrefix(c.Name, "custom.session_token") && c.MaxAge >= 0 && c.Value != "" {
			t.Errorf("disabled cache must not re-issue session_token, got %+v", c)
		}
	}
}
