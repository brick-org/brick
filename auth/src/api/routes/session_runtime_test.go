package routes

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/cookies"
	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

// seedSessionUser creates a verified user plus a session row valid until
// expiresAt, returning the session token.
func seedSessionUser(t *testing.T, db *parityMemAdapter, email, token string, expiresAt time.Time) {
	t.Helper()
	parityCreateUser(t, db, email, true)
	userRow, err := db.FindOne(context.Background(), "user", []types.Where{
		{Field: "email", Value: email},
	}, nil)
	if err != nil || userRow == nil {
		t.Fatalf("seed user lookup: %v", err)
	}
	now := time.Now().UTC()
	if _, err := db.Create(context.Background(), "session", map[string]any{
		"id":        "sess-" + token,
		"userId":    stringField(userRow, "id"),
		"token":     token,
		"expiresAt": expiresAt,
		"createdAt": now,
		"updatedAt": now,
	}, nil); err != nil {
		t.Fatalf("seed session: %v", err)
	}
}

// sessionTestOptions returns options with a short session lifetime so refresh
// behavior is exercisable without waiting.
func sessionTestOptions(db *parityMemAdapter) types.Options {
	opts := parityTestOptions(db)
	opts.Session.ExpiresIn = 3600
	opts.Session.UpdateAge = intPtr(60)
	return opts
}

// signedSessionHeader builds a Cookie header carrying the signed session
// token, mirroring what newSessionCookie issuance produces.
func signedSessionHeader(t *testing.T, opts types.Options, token string) string {
	t.Helper()
	signed, err := cookies.Sign(opts.CurrentSecret(), token)
	if err != nil {
		t.Fatalf("sign session token: %v", err)
	}
	return resolveSessionCookieName(opts, false) + "=" + signed
}

// cacheHeaderFor builds a Cookie header carrying both the session cookie and
// a freshly minted cookie-cache cookie for token.
func cacheHeaderFor(t *testing.T, ctx context.Context, opts types.Options, token string) string {
	t.Helper()
	sessionRow, userRow, _, err := loadSessionAndUser(ctx, opts, token)
	if err != nil {
		t.Fatalf("load session for cache: %v", err)
	}
	session := rowToSession(sessionRow, opts)
	user := rowToUser(userRow, opts)
	cacheCookie, err := newSessionDataCookie(opts.CurrentSecret(), session, user, opts, opts.Session, time.Now().UTC(), false)
	if err != nil {
		t.Fatalf("mint cache cookie: %v", err)
	}
	return signedSessionHeader(t, opts, token) + "; " + cacheCookie.Name + "=" + cacheCookie.Value
}

func statusOf(t *testing.T, err error) (int, string) {
	t.Helper()
	var statusErr huma.StatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("expected huma StatusError, got %T (%v)", err, err)
	}
	return statusErr.GetStatus(), statusErr.Error()
}

func TestSessionRouteErrorStatuses(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"expired pins 400", sessionRouteError(types.ErrSessionExpired), http.StatusBadRequest, types.ErrSessionExpired},
		{"failed pins 401", sessionRouteError(types.ErrFailedToGetSession), http.StatusUnauthorized, types.ErrFailedToGetSession},
		{"missing user pins 404", sessionRouteError(types.ErrUserNotFound), http.StatusNotFound, types.ErrUserNotFound},
		{"defer-required pins 405", sessionRouteError(types.ErrMethodNotAllowedDeferSessionRequired), http.StatusMethodNotAllowed, types.ErrMethodNotAllowedDeferSessionRequired},
		{"internal keeps 500", sessionInternalError(types.ErrFailedToGetSession), http.StatusInternalServerError, types.ErrFailedToGetSession},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, detail := statusOf(t, tc.err)
			if status != tc.status {
				t.Errorf("status = %d, want %d", status, tc.status)
			}
			if !strings.Contains(detail, tc.code) {
				t.Errorf("detail %q does not contain code %q", detail, tc.code)
			}
			if got := types.StatusForCode(tc.code); tc.status != http.StatusInternalServerError && got != tc.status {
				t.Errorf("StatusForCode(%s) = %d, want adopted %d", tc.code, got, tc.status)
			}
		})
	}
}

func TestParseSessionQueryBool(t *testing.T) {
	for raw, want := range map[string]bool{
		"": false, "true": true, "1": true, "t": true,
		"false": false, "0": false, "bogus": false,
	} {
		if got := parseSessionQueryBool(raw); got != want {
			t.Errorf("parseSessionQueryBool(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestDontRememberCookieRoundTrip(t *testing.T) {
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	signed, err := cookies.Sign(opts.CurrentSecret(), "true")
	if err != nil {
		t.Fatal(err)
	}
	name := resolveDontRememberCookieName(opts, false)
	if !hasDontRememberCookie(name+"="+signed, opts) {
		t.Fatal("signed dont_remember cookie not detected")
	}
	// Secure spelling is accepted too.
	secureName := resolveDontRememberCookieName(opts, true)
	if !strings.HasPrefix(secureName, "__Secure-") {
		t.Fatalf("secure dont_remember name %q missing prefix", secureName)
	}
	if !hasDontRememberCookie(secureName+"="+signed, opts) {
		t.Fatal("secure dont_remember cookie not detected")
	}
	if hasDontRememberCookie(name+"=tampered.invalid", opts) {
		t.Fatal("tampered dont_remember cookie accepted")
	}
	if hasDontRememberCookie("", opts) {
		t.Fatal("empty cookie header accepted")
	}
	if hasDontRememberCookie("other=1", opts) {
		t.Fatal("unrelated cookie accepted")
	}
}

func TestCookieCacheVersioning(t *testing.T) {
	ctx := context.Background()

	t.Run("default version round-trips", func(t *testing.T) {
		db := newParityMemAdapter()
		opts := sessionTestOptions(db)
		opts.Session.CookieCache.Enabled = true
		seedSessionUser(t, db, "version@example.com", "tok-version", time.Now().UTC().Add(time.Hour))
		header := cacheHeaderFor(t, ctx, opts, "tok-version")
		cached, ok := cachedSessionFromRequest(header, opts.AllSecrets(), "tok-version", opts.Session)
		if !ok || cached == nil {
			t.Fatal("expected cache hit")
		}
		if normalizeCookieCacheVersion(cached.Version) != "1" {
			t.Fatalf("version = %q, want %q", cached.Version, "1")
		}
	})

	t.Run("static rotation invalidates", func(t *testing.T) {
		db := newParityMemAdapter()
		opts := sessionTestOptions(db)
		opts.Session.CookieCache.Enabled = true
		seedSessionUser(t, db, "rotate@example.com", "tok-rotate", time.Now().UTC().Add(time.Hour))
		header := cacheHeaderFor(t, ctx, opts, "tok-rotate")
		opts.Session.CookieCache.Version = "2"
		if _, ok := cachedSessionFromRequest(header, opts.AllSecrets(), "tok-rotate", opts.Session); ok {
			t.Fatal("rotated version must miss")
		}
	})

	t.Run("version func precedence and rejection", func(t *testing.T) {
		db := newParityMemAdapter()
		opts := sessionTestOptions(db)
		opts.Session.CookieCache.Enabled = true
		opts.Session.CookieCache.Version = "static"
		opts.Session.CookieCache.VersionFunc = func(session types.Session, user types.User) (string, error) {
			return "dynamic", nil
		}
		seedSessionUser(t, db, "func@example.com", "tok-func", time.Now().UTC().Add(time.Hour))
		header := cacheHeaderFor(t, ctx, opts, "tok-func")
		// Static "static" must not match the stamped "dynamic": re-check with
		// the func removed to prove the func took precedence at write time.
		withoutFunc := opts
		withoutFunc.Session.CookieCache.VersionFunc = nil
		if _, ok := cachedSessionFromRequest(header, opts.AllSecrets(), "tok-func", withoutFunc.Session); ok {
			t.Fatal("static version must not match func-stamped cache")
		}
		if _, ok := cachedSessionFromRequest(header, opts.AllSecrets(), "tok-func", opts.Session); !ok {
			t.Fatal("func-derived version must hit")
		}
		// A changed func output invalidates.
		rotated := opts
		rotated.Session.CookieCache.VersionFunc = func(types.Session, types.User) (string, error) {
			return "dynamic-2", nil
		}
		if _, ok := cachedSessionFromRequest(header, opts.AllSecrets(), "tok-func", rotated.Session); ok {
			t.Fatal("changed func version must miss")
		}
		// A failing func fails closed to a miss, never a hit.
		failing := opts
		failing.Session.CookieCache.VersionFunc = func(types.Session, types.User) (string, error) {
			return "", errors.New("boom")
		}
		if _, ok := cachedSessionFromRequest(header, opts.AllSecrets(), "tok-func", failing.Session); ok {
			t.Fatal("failing func must miss")
		}
	})
}

func TestCookieCacheStrategyGate(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	opts.Session.CookieCache.Enabled = true
	seedSessionUser(t, db, "strategy@example.com", "tok-strategy", time.Now().UTC().Add(time.Hour))

	sessionRow, userRow, _, err := loadSessionAndUser(ctx, opts, "tok-strategy")
	if err != nil {
		t.Fatal(err)
	}
	session, user := rowToSession(sessionRow, opts), rowToUser(userRow, opts)

	// Every strategy issues a cache cookie and serves it back: the jwt/jwe
	// strategies are wired (HS256 JWT / dir-A256CBC-HS512 JWE), not
	// fail-closed.
	for _, strategy := range []types.SessionCookieCacheStrategy{
		types.SessionCookieCacheCompact,
		types.SessionCookieCacheJWT,
		types.SessionCookieCacheJWE,
	} {
		strategyOpts := opts.Session
		strategyOpts.CookieCache.Strategy = strategy
		cacheCookie, err := newSessionDataCookie(opts.CurrentSecret(), session, user, opts, strategyOpts, time.Now().UTC(), false)
		if err != nil {
			t.Fatalf("%s: mint must succeed: %v", strategy, err)
		}
		header := signedSessionHeader(t, opts, "tok-strategy") + "; " + cacheCookie.Name + "=" + cacheCookie.Value
		if _, ok := cachedSessionFromRequest(header, opts.AllSecrets(), "tok-strategy", strategyOpts); !ok {
			t.Fatalf("%s: minted cache must hit", strategy)
		}
	}

	// Session creation still issues the session cookie in every strategy.
	jwtOpts := opts
	jwtOpts.Session.CookieCache.Strategy = types.SessionCookieCacheJWT
	issued, err := newSessionCookies(jwtOpts, CookieRequestHeaders{}, "tok-strategy", session, user, jwtOpts.Session, time.Now().UTC())
	if err != nil {
		t.Fatalf("session cookie issuance: %v", err)
	}
	if len(issued) != 2 {
		t.Fatalf("expected session+cache cookies, got %d", len(issued))
	}
}

func TestMaybeRefreshCookieCache(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	opts.Session.CookieCache.Enabled = true
	opts.Session.CookieCache.MaxAge = 300
	seedSessionUser(t, db, "refresh@example.com", "tok-refresh", time.Now().UTC().Add(time.Hour))
	sessionRow, userRow, _, err := loadSessionAndUser(ctx, opts, "tok-refresh")
	if err != nil {
		t.Fatal(err)
	}
	session, user := rowToSession(sessionRow, opts), rowToUser(userRow, opts)
	now := time.Now().UTC()

	payload := func(expiresAt time.Time) *sessionCookieCachePayload {
		return &sessionCookieCachePayload{Session: session, User: user, ExpiresAt: expiresAt, Version: "1"}
	}

	// Disabled refresh: always nil.
	if got := maybeRefreshCookieCache(opts, CookieRequestHeaders{}, "tok-refresh", payload(now.Add(10*time.Second)), now, false); got != nil {
		t.Fatal("disabled RefreshCache must not refresh")
	}

	enabled := opts
	enabled.Session.CookieCache.RefreshCache.Enabled = true
	// Fresh cache (default 20% of 300s = 60s threshold): nil.
	if got := maybeRefreshCookieCache(enabled, CookieRequestHeaders{}, "tok-refresh", payload(now.Add(5*time.Minute)), now, false); got != nil {
		t.Fatal("fresh cache must not refresh")
	}
	// Near-expiry cache: re-issued cookies.
	if got := maybeRefreshCookieCache(enabled, CookieRequestHeaders{}, "tok-refresh", payload(now.Add(30*time.Second)), now, false); len(got) != 2 {
		t.Fatalf("expected refreshed session+cache cookies, got %d", len(got))
	}
	// ShouldRefresh hook gates the refresh.
	gated := enabled
	gated.Session.CookieCache.RefreshCache.ShouldRefresh = func(types.Session, types.User) bool { return false }
	if got := maybeRefreshCookieCache(gated, CookieRequestHeaders{}, "tok-refresh", payload(now.Add(30*time.Second)), now, false); got != nil {
		t.Fatal("ShouldRefresh=false must suppress the refresh")
	}
	// Custom UpdateAge is honored.
	custom := enabled
	custom.Session.CookieCache.RefreshCache.UpdateAge = 10
	if got := maybeRefreshCookieCache(custom, CookieRequestHeaders{}, "tok-refresh", payload(now.Add(30*time.Second)), now, false); got != nil {
		t.Fatal("30s of lifetime left must not refresh with a 10s threshold")
	}
	if got := maybeRefreshCookieCache(custom, CookieRequestHeaders{}, "tok-refresh", payload(now.Add(5*time.Second)), now, false); len(got) != 2 {
		t.Fatalf("expected refresh under a 10s threshold, got %d", len(got))
	}
}

func TestLoadSessionRefreshPolicy(t *testing.T) {
	ctx := context.Background()
	expiresOf := func(t *testing.T, db *parityMemAdapter, token string) time.Time {
		t.Helper()
		row, err := db.FindOne(ctx, "session", []types.Where{{Field: "token", Value: token}}, nil)
		if err != nil || row == nil {
			t.Fatalf("session lookup: %v", err)
		}
		exp, ok := timeField(row, "expires_at", "expiresAt")
		if !ok {
			t.Fatal("session row missing expiry")
		}
		return exp
	}

	t.Run("default refreshes a due session", func(t *testing.T) {
		db := newParityMemAdapter()
		opts := sessionTestOptions(db)
		before := time.Now().UTC()
		seedSessionUser(t, db, "due@example.com", "tok-due", before.Add(30*time.Second))
		_, _, refreshed, _, err := loadSessionWithRefresh(ctx, opts, "tok-due", sessionRefreshConfig{})
		if err != nil {
			t.Fatal(err)
		}
		if !refreshed {
			t.Fatal("due session must refresh")
		}
		if got := expiresOf(t, db, "tok-due"); !got.After(before.Add(time.Hour)) {
			t.Fatalf("expiry not extended: %v", got)
		}
	})

	t.Run("dontRememberMe skips the write", func(t *testing.T) {
		db := newParityMemAdapter()
		opts := sessionTestOptions(db)
		seedSessionUser(t, db, "remember@example.com", "tok-remember", time.Now().UTC().Add(30*time.Second))
		before := expiresOf(t, db, "tok-remember")
		_, _, refreshed, _, err := loadSessionWithRefresh(ctx, opts, "tok-remember", sessionRefreshConfig{dontRememberMe: true})
		if err != nil {
			t.Fatal(err)
		}
		if refreshed {
			t.Fatal("dontRememberMe session must not refresh")
		}
		if got := expiresOf(t, db, "tok-remember"); !got.Equal(before) {
			t.Fatalf("expiry changed: %v -> %v", before, got)
		}
	})

	t.Run("per-request and global disable skip the write", func(t *testing.T) {
		for name, mutate := range map[string]func(*types.Options, *sessionRefreshConfig){
			"query disableRefresh": func(o *types.Options, c *sessionRefreshConfig) { c.disableRefresh = true },
			"global DisableSessionRefresh": func(o *types.Options, c *sessionRefreshConfig) {
				o.Session.DisableSessionRefresh = true
			},
		} {
			t.Run(name, func(t *testing.T) {
				db := newParityMemAdapter()
				opts := sessionTestOptions(db)
				var cfg sessionRefreshConfig
				mutate(&opts, &cfg)
				seedSessionUser(t, db, "disable@example.com", "tok-disable", time.Now().UTC().Add(30*time.Second))
				_, _, refreshed, _, err := loadSessionWithRefresh(ctx, opts, "tok-disable", cfg)
				if err != nil {
					t.Fatal(err)
				}
				if refreshed {
					t.Fatalf("%s must suppress the refresh write", name)
				}
			})
		}
	})

	t.Run("readOnly reports instead of writing", func(t *testing.T) {
		db := newParityMemAdapter()
		opts := sessionTestOptions(db)
		seedSessionUser(t, db, "defer-due@example.com", "tok-defer-due", time.Now().UTC().Add(30*time.Second))
		seedSessionUser(t, db, "defer-fresh@example.com", "tok-defer-fresh", time.Now().UTC().Add(time.Hour))
		before := expiresOf(t, db, "tok-defer-due")

		_, _, refreshed, needsRefresh, err := loadSessionWithRefresh(ctx, opts, "tok-defer-due", sessionRefreshConfig{readOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		if refreshed {
			t.Fatal("readOnly must not write")
		}
		if !needsRefresh {
			t.Fatal("due session must report needsRefresh")
		}
		if got := expiresOf(t, db, "tok-defer-due"); !got.Equal(before) {
			t.Fatalf("readOnly wrote the row: %v -> %v", before, got)
		}

		_, _, _, freshNeeds, err := loadSessionWithRefresh(ctx, opts, "tok-defer-fresh", sessionRefreshConfig{readOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		if freshNeeds {
			t.Fatal("fresh session must not report needsRefresh")
		}
	})
}

func TestResolveGetSessionQueryKnobs(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	opts.Session.CookieCache.Enabled = true
	opts.Session.CookieCache.MaxAge = 300
	seedSessionUser(t, db, "knobs@example.com", "tok-knobs", time.Now().UTC().Add(time.Hour))
	header := cacheHeaderFor(t, ctx, opts, "tok-knobs")
	base := getSessionRequest{
		token:        "tok-knobs",
		cookieHeader: header,
		headers:      CookieRequestHeaders{},
	}

	// Fresh cache hit: served without cookie writes.
	res, err := resolveGetSession(ctx, opts, base)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.cookies) != 0 {
		t.Fatalf("cache hit must not write cookies, got %d", len(res.cookies))
	}

	// ?disableCookieCache forces the authoritative read, which re-issues.
	disabled := base
	disabled.query.DisableCookieCache = true
	res, err = resolveGetSession(ctx, opts, disabled)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.cookies) == 0 {
		t.Fatal("disableCookieCache must fall through to the database read with fresh cookies")
	}

	// ?disableRefresh serves the session with no writes at all.
	noRefresh := base
	noRefresh.query.DisableRefresh = true
	res, err = resolveGetSession(ctx, opts, noRefresh)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.cookies) != 0 {
		t.Fatalf("disableRefresh must suppress cookie writes, got %d", len(res.cookies))
	}
	if res.session.Token != "tok-knobs" {
		t.Fatalf("wrong session: %+v", res.session)
	}
}

func TestResolveGetSessionMapsErrors(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)

	// Unknown token: 401 FAILED_TO_GET_SESSION.
	_, err := resolveGetSession(ctx, opts, getSessionRequest{token: "missing", headers: CookieRequestHeaders{}})
	status, detail := statusOf(t, err)
	if status != http.StatusUnauthorized || !strings.Contains(detail, types.ErrFailedToGetSession) {
		t.Fatalf("unknown token: %d %q", status, detail)
	}

	// Expired session: 400 SESSION_EXPIRED (upstream BAD_REQUEST site).
	seedSessionUser(t, db, "gone@example.com", "tok-gone", time.Now().UTC().Add(-time.Hour))
	_, err = resolveGetSession(ctx, opts, getSessionRequest{token: "tok-gone", headers: CookieRequestHeaders{}})
	status, detail = statusOf(t, err)
	if status != http.StatusBadRequest || !strings.Contains(detail, types.ErrSessionExpired) {
		t.Fatalf("expired session: %d %q", status, detail)
	}

	// Session without a user row: 404 USER_NOT_FOUND.
	now := time.Now().UTC()
	if _, err := db.Create(ctx, "session", map[string]any{
		"id": "sess-orphan", "userId": "no-such-user", "token": "tok-orphan",
		"expiresAt": now.Add(time.Hour), "createdAt": now, "updatedAt": now,
	}, nil); err != nil {
		t.Fatal(err)
	}
	_, err = resolveGetSession(ctx, opts, getSessionRequest{token: "tok-orphan", headers: CookieRequestHeaders{}})
	status, detail = statusOf(t, err)
	if status != http.StatusNotFound || !strings.Contains(detail, types.ErrUserNotFound) {
		t.Fatalf("orphan session: %d %q", status, detail)
	}
}

func TestResolveGetSessionDontRemember(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	opts.Session.CookieCache.Enabled = true
	seedSessionUser(t, db, "dontremember@example.com", "tok-dont", time.Now().UTC().Add(30*time.Second))
	beforeRow, err := db.FindOne(ctx, "session", []types.Where{{Field: "token", Value: "tok-dont"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	beforeExp, _ := timeField(beforeRow, "expires_at", "expiresAt")

	signed, err := cookies.Sign(opts.CurrentSecret(), "true")
	if err != nil {
		t.Fatal(err)
	}
	header := signedSessionHeader(t, opts, "tok-dont") + ";" +
		resolveDontRememberCookieName(opts, false) + "=" + signed
	res, err := resolveGetSession(ctx, opts, getSessionRequest{
		token:          "tok-dont",
		cookieHeader:   header,
		headers:        CookieRequestHeaders{},
		dontRememberMe: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.cookies) != 0 {
		t.Fatalf("dontRememberMe must suppress cookie writes, got %d", len(res.cookies))
	}
	afterRow, err := db.FindOne(ctx, "session", []types.Where{{Field: "token", Value: "tok-dont"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	afterExp, _ := timeField(afterRow, "expires_at", "expiresAt")
	if !afterExp.Equal(beforeExp) {
		t.Fatalf("dontRememberMe extended the session: %v -> %v", beforeExp, afterExp)
	}
}

func TestDeferredGetSessionReadOnly(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	opts.Session.CookieCache.Enabled = true
	seedSessionUser(t, db, "deferred@example.com", "tok-deferred", time.Now().UTC().Add(30*time.Second))
	beforeRow, _ := db.FindOne(ctx, "session", []types.Where{{Field: "token", Value: "tok-deferred"}}, nil)
	beforeExp, _ := timeField(beforeRow, "expires_at", "expiresAt")

	res, err := resolveGetSession(ctx, opts, getSessionRequest{
		token:        "tok-deferred",
		cookieHeader: signedSessionHeader(t, opts, "tok-deferred"),
		headers:      CookieRequestHeaders{},
		readOnly:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.needsRefresh == nil || !*res.needsRefresh {
		t.Fatal("deferred read of a due session must report needsRefresh")
	}
	// Cache-only re-issue: exactly the session_data cookie, no session_token
	// rewrite (upstream setCookieCache without setSessionCookie).
	if len(res.cookies) != 1 || res.cookies[0].Name != sessionDataCookieName {
		names := make([]string, 0, len(res.cookies))
		for _, c := range res.cookies {
			names = append(names, c.Name)
		}
		t.Fatalf("expected cache-only cookie, got %v", names)
	}
	afterRow, _ := db.FindOne(ctx, "session", []types.Where{{Field: "token", Value: "tok-deferred"}}, nil)
	afterExp, _ := timeField(afterRow, "expires_at", "expiresAt")
	if !afterExp.Equal(beforeExp) {
		t.Fatalf("deferred read wrote the row: %v -> %v", beforeExp, afterExp)
	}
}

// TestGetSessionPostRequiresDeferral pins the upstream POST contract
// (session.ts:79-84) end to end: POST without deferSessionRefresh is a 405
// METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED; with deferral it behaves like
// GET but with writes enabled.
func TestGetSessionPostRequiresDeferral(t *testing.T) {
	boot := func(t *testing.T, deferRefresh bool) (humatest.TestAPI, string) {
		t.Helper()
		db := newParityMemAdapter()
		opts := sessionTestOptions(db)
		opts.Session.DeferSessionRefresh = deferRefresh
		seedSessionUser(t, db, "post@example.com", "tok-post", time.Now().UTC().Add(time.Hour))
		_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
		GetSession(api, "/api/auth", opts)
		return api, signedSessionHeader(t, opts, "tok-post")
	}

	t.Run("post without deferral is 405", func(t *testing.T) {
		api, header := boot(t, false)
		resp := api.Post("/api/auth/get-session", "Cookie: "+header)
		if resp.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d: %s", resp.Code, resp.Body.String())
		}
		if !strings.Contains(resp.Body.String(), types.ErrMethodNotAllowedDeferSessionRequired) {
			t.Fatalf("body missing code: %s", resp.Body.String())
		}
		// GET still serves.
		getResp := api.Get("/api/auth/get-session", "Cookie: "+header)
		if getResp.Code != http.StatusOK {
			t.Fatalf("GET expected 200, got %d: %s", getResp.Code, getResp.Body.String())
		}
	})

	t.Run("post with deferral serves with writes", func(t *testing.T) {
		api, header := boot(t, true)
		resp := api.Post("/api/auth/get-session", "Cookie: "+header)
		if resp.Code != http.StatusOK {
			t.Fatalf("POST expected 200, got %d: %s", resp.Code, resp.Body.String())
		}
		if strings.Contains(resp.Body.String(), "needsRefresh") {
			t.Fatalf("POST must not report needsRefresh: %s", resp.Body.String())
		}
	})

	t.Run("deferred get reports needsRefresh", func(t *testing.T) {
		db := newParityMemAdapter()
		opts := sessionTestOptions(db)
		opts.Session.DeferSessionRefresh = true
		seedSessionUser(t, db, "needs@example.com", "tok-needs", time.Now().UTC().Add(30*time.Second))
		_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
		GetSession(api, "/api/auth", opts)
		resp := api.Get("/api/auth/get-session", "Cookie: "+signedSessionHeader(t, opts, "tok-needs"))
		if resp.Code != http.StatusOK {
			t.Fatalf("GET expected 200, got %d: %s", resp.Code, resp.Body.String())
		}
		if !strings.Contains(resp.Body.String(), `"needsRefresh":true`) {
			t.Fatalf("body missing needsRefresh:true: %s", resp.Body.String())
		}
	})
}

// TestGetSessionQueryBinding pins the ?disableRefresh knob end to end: a due
// session refreshes (Set-Cookie) by default and stays untouched with the
// knob set.
func TestGetSessionQueryBinding(t *testing.T) {
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	seedSessionUser(t, db, "binding@example.com", "tok-binding", time.Now().UTC().Add(30*time.Second))
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	GetSession(api, "/api/auth", opts)
	header := signedSessionHeader(t, opts, "tok-binding")

	plain := api.Get("/api/auth/get-session", "Cookie: "+header)
	if plain.Code != http.StatusOK {
		t.Fatalf("GET expected 200, got %d: %s", plain.Code, plain.Body.String())
	}
	if plain.Header().Get("Set-Cookie") == "" {
		t.Fatal("due session must refresh with Set-Cookie by default")
	}

	pinned := api.Get("/api/auth/get-session?disableRefresh=true", "Cookie: "+header)
	if pinned.Code != http.StatusOK {
		t.Fatalf("GET expected 200, got %d: %s", pinned.Code, pinned.Body.String())
	}
	if pinned.Header().Get("Set-Cookie") != "" {
		t.Fatalf("disableRefresh must suppress Set-Cookie, got %q", pinned.Header().Get("Set-Cookie"))
	}
}
