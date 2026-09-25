package routes

// Triage ports for vendor session-api.test.ts (Better Auth v1.7.5 @ 5468e6bf).
// Each test below names the upstream case it pins. Cases needing prod-code
// fixes were reported as FEATURE-GAPs instead of kept tests; every test in
// this file passes on the v1 tree.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/cookies"
	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

// triageSeedSecondSession adds a second live session row for the user that
// owns token, returning the new token.
func triageSeedSecondSession(t *testing.T, ctx context.Context, db *parityMemAdapter, token, newToken string) {
	t.Helper()
	row, err := db.FindOne(ctx, "session", []types.Where{{Field: "token", Value: token}}, nil)
	if err != nil || row == nil {
		t.Fatalf("seed session lookup: %v", err)
	}
	now := time.Now().UTC()
	if _, err := db.Create(ctx, "session", map[string]any{
		"id":        "sess-" + newToken,
		"userId":    stringField(row, "user_id", "userId"),
		"token":     newToken,
		"expiresAt": time.Now().UTC().Add(time.Hour),
		"createdAt": now,
		"updatedAt": now,
	}, nil); err != nil {
		t.Fatalf("seed second session: %v", err)
	}
}

func triageListTokens(t *testing.T, api humatest.TestAPI, cookie string) []string {
	t.Helper()
	resp := api.Get("/api/auth/list-sessions", "Cookie: "+cookie)
	if resp.Code != http.StatusOK {
		t.Fatalf("list-sessions: %d %s", resp.Code, resp.Body.String())
	}
	var sessions []struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &sessions); err != nil {
		t.Fatalf("decode list: %v (%s)", err, resp.Body.String())
	}
	tokens := make([]string, 0, len(sessions))
	for _, s := range sessions {
		tokens = append(tokens, s.Token)
	}
	return tokens
}

// Upstream "should list sessions" (describe session): two live sessions are
// both enumerated.
func TestTriageV1_ListSessionsPrimary(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	seedSessionUser(t, db, "trilist@example.com", "tok-tri-list", time.Now().UTC().Add(time.Hour))
	triageSeedSecondSession(t, ctx, db, "tok-tri-list", "tok-tri-list-2")
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	ListSessions(api, "/api/auth", opts)

	tokens := triageListTokens(t, api, signedSessionHeader(t, opts, "tok-tri-list"))
	if len(tokens) != 2 {
		t.Fatalf("expected 2 sessions, got %v", tokens)
	}
}

// Upstream "should revoke session" (describe session): revoking one of two
// sessions nulls it out while the survivor keeps working; revoke-sessions
// then clears everything with status:true.
func TestTriageV1_RevokeOwnSessionThenRevokeAll(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	seedSessionUser(t, db, "trirevoke@example.com", "tok-tri-rev", time.Now().UTC().Add(time.Hour))
	triageSeedSecondSession(t, ctx, db, "tok-tri-rev", "tok-tri-rev-2")
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	GetSession(api, "/api/auth", opts)
	ListSessions(api, "/api/auth", opts)
	RevokeSession(api, "/api/auth", opts)
	RevokeSessions(api, "/api/auth", opts)

	cookieA := signedSessionHeader(t, opts, "tok-tri-rev")
	cookieB := signedSessionHeader(t, opts, "tok-tri-rev-2")

	revoke := api.Post("/api/auth/revoke-session", "Cookie: "+cookieA, map[string]any{"token": "tok-tri-rev"})
	if revoke.Code != http.StatusOK || !strings.Contains(revoke.Body.String(), `"status":true`) {
		t.Fatalf("revoke-session: %d %s", revoke.Code, revoke.Body.String())
	}
	if resp := api.Get("/api/auth/get-session", "Cookie: "+cookieA); resp.Code != http.StatusUnauthorized {
		t.Fatalf("revoked get-session: got %d, want 401: %s", resp.Code, resp.Body.String())
	}
	if tokens := triageListTokens(t, api, cookieB); len(tokens) != 1 || tokens[0] != "tok-tri-rev-2" {
		t.Fatalf("expected only the survivor, got %v", tokens)
	}

	revokeAll := api.Post("/api/auth/revoke-sessions", "Cookie: "+cookieB)
	if revokeAll.Code != http.StatusOK || !strings.Contains(revokeAll.Body.String(), `"status":true`) {
		t.Fatalf("revoke-sessions: %d %s", revokeAll.Code, revokeAll.Body.String())
	}
	if resp := api.Get("/api/auth/get-session", "Cookie: "+cookieB); resp.Code != http.StatusUnauthorized {
		t.Fatalf("post-revoke-all get-session: got %d, want 401: %s", resp.Code, resp.Body.String())
	}
}

// Upstream "should update a custom additional field on a session" and
// "should update session cookie after mutation" (describe updateSession): a
// declared custom field updates, the mutation response re-issues cookies,
// and a later read serves the new value.
func TestTriageV1_UpdateSessionCustomFieldAndCookie(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	opts.Session.Model.AdditionalFields = map[string]types.FieldAttribute{
		"theme": {},
	}
	seedSessionUser(t, db, "triupd@example.com", "tok-tri-upd", time.Now().UTC().Add(time.Hour))
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	UpdateSession(api, "/api/auth", opts)
	GetSession(api, "/api/auth", opts)
	header := signedSessionHeader(t, opts, "tok-tri-upd")

	resp := api.Post("/api/auth/update-session", "Cookie: "+header, map[string]any{"theme": "dark"})
	if resp.Code != http.StatusOK {
		t.Fatalf("update-session: %d %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), `"dark"`) {
		t.Fatalf("updated field missing from response: %s", resp.Body.String())
	}
	if resp.Header().Get("Set-Cookie") == "" {
		t.Fatal("update-session must re-issue the session cookie after mutation")
	}

	row, err := db.FindOne(ctx, "session", []types.Where{{Field: "token", Value: "tok-tri-upd"}}, nil)
	if err != nil || row == nil {
		t.Fatalf("session lookup: %v", err)
	}
	if stringField(row, "theme") != "dark" {
		t.Fatalf("stored theme = %q, want dark", stringField(row, "theme"))
	}

	getResp := api.Get("/api/auth/get-session", "Cookie: "+header)
	if getResp.Code != http.StatusOK || !strings.Contains(getResp.Body.String(), `"dark"`) {
		t.Fatalf("get-session after mutation: %d %s", getResp.Code, getResp.Body.String())
	}
}

// Upstream "should ignore core session fields" and "should ignore core field
// userId" (describe updateSession): core-only bodies are 400 "No fields to
// update".
func TestTriageV1_UpdateSessionIgnoresCoreFields(t *testing.T) {
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	seedSessionUser(t, db, "tricore@example.com", "tok-tri-core", time.Now().UTC().Add(time.Hour))
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	UpdateSession(api, "/api/auth", opts)
	header := signedSessionHeader(t, opts, "tok-tri-core")

	for _, body := range []map[string]any{{"token": "malicious-token"}, {"userId": "another-user"}} {
		resp := api.Post("/api/auth/update-session", "Cookie: "+header, body)
		if resp.Code != http.StatusBadRequest {
			t.Fatalf("core-only body %v: got %d, want 400: %s", body, resp.Code, resp.Body.String())
		}
		if !strings.Contains(resp.Body.String(), "No fields to update") {
			t.Fatalf("core-only body %v missing message: %s", body, resp.Body.String())
		}
	}
}

// Upstream "should have max age expiry" (describe cookie cache with JWT
// strategy): the JWT cache exp lands on the ~300s default window.
func TestTriageV1_JWTCacheMaxAgeExpiry(t *testing.T) {
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	before := time.Now().Unix()
	token, err := cookies.CreateSessionCacheJWT(opts.CurrentSecret(),
		map[string]any{"token": "tok-tri-jwt", "id": "sess-tri-jwt"},
		map[string]any{"id": "user-tri-jwt"},
		"1", 5*time.Minute)
	if err != nil {
		t.Fatalf("mint jwt cache: %v", err)
	}
	_, expMillis, err := cookies.VerifySessionCacheJWT([]string{opts.CurrentSecret()}, token)
	if err != nil {
		t.Fatalf("verify jwt cache: %v", err)
	}
	remaining := expMillis/1000 - before
	if remaining < 299 || remaining > 300 {
		t.Fatalf("jwt cache expiry in %ds, want within [299,300]", remaining)
	}
}

// Upstream "refreshes expired cache and reuses the replacement cookie"
// (describe cookie cache, compact): an expired cache falls through to the
// database with a re-issued cache cookie, and the replacement serves the
// next read from the cache.
func TestTriageV1_CompactExpiredCacheRefreshes(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	opts.Session.CookieCache.Enabled = true
	seedSessionUser(t, db, "triexpire@example.com", "tok-tri-expire", time.Now().UTC().Add(time.Hour))

	sessionRow, userRow, _, err := loadSessionAndUser(ctx, opts, "tok-tri-expire")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(sessionCookieCachePayload{
		Session:   rowToSession(sessionRow, opts),
		User:      rowToUser(userRow, opts),
		ExpiresAt: time.Now().UTC().Add(-time.Minute),
		Version:   "1",
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := cookies.Sign(opts.CurrentSecret(), base64.RawURLEncoding.EncodeToString(payload))
	if err != nil {
		t.Fatal(err)
	}
	staleHeader := signedSessionHeader(t, opts, "tok-tri-expire") + "; " + sessionDataCookieName + "=" + signed

	res, err := resolveGetSession(ctx, opts, getSessionRequest{
		token: "tok-tri-expire", cookieHeader: staleHeader, headers: CookieRequestHeaders{},
	})
	if err != nil {
		t.Fatalf("expired cache must fall through to DB: %v", err)
	}
	if res.user.Email != "triexpire@example.com" {
		t.Fatalf("served wrong user: %+v", res.user)
	}
	var freshData string
	for _, c := range res.cookies {
		if c.Name == sessionDataCookieName {
			freshData = c.Value
		}
	}
	if freshData == "" {
		t.Fatal("expired cache must be replaced with a fresh session_data cookie")
	}

	replacementHeader := signedSessionHeader(t, opts, "tok-tri-expire") + "; " + sessionDataCookieName + "=" + freshData
	cached, err := resolveGetSession(ctx, opts, getSessionRequest{
		token: "tok-tri-expire", cookieHeader: replacementHeader, headers: CookieRequestHeaders{},
	})
	if err != nil {
		t.Fatalf("replacement cache must serve: %v", err)
	}
	if cached.session.Token != res.session.Token || cached.user.Email != res.user.Email {
		t.Fatalf("replacement mismatch: %+v / %+v", cached.session, cached.user)
	}
}

// Upstream "should preserve session expiry when refreshing stateless cookie
// cache", "should work without database when refreshCache threshold is
// reached", "should extend session_token cookie expiry when refreshCache
// threshold is reached" (describe cookie cache refreshCache), and "should
// have consistent date types between cookie cache and refresh paths"
// (describe date field type consistency): in a DB-less JWE deployment with
// the refresh threshold forced, the read serves from the cookie, preserves
// the session expiry/createdAt, and extends the session_token Max-Age to
// expiresIn.
func TestTriageV1_StatelessRefreshPreservesExpiry(t *testing.T) {
	opts := statelessTestOptions()
	opts.Session.CookieCache.Strategy = types.SessionCookieCacheJWE
	opts.Session.CookieCache.RefreshCache.Enabled = true
	opts.Session.CookieCache.RefreshCache.UpdateAge = 3600
	session, user := statelessSessionFixture("tok-tri-refresh")
	header := mintStatelessHeader(t, opts, "tok-tri-refresh", session, user)

	res, err := resolveGetSession(context.Background(), opts, getSessionRequest{
		token: "tok-tri-refresh", cookieHeader: header, headers: CookieRequestHeaders{},
	})
	if err != nil {
		t.Fatalf("stateless refresh must serve: %v", err)
	}
	if res.session.Token != "tok-tri-refresh" {
		t.Fatalf("wrong session: %+v", res.session)
	}
	if !res.session.ExpiresAt.Equal(session.ExpiresAt) {
		t.Fatalf("expiry changed by refresh: %v -> %v", session.ExpiresAt, res.session.ExpiresAt)
	}
	if !res.session.CreatedAt.Equal(session.CreatedAt) {
		t.Fatalf("createdAt changed by refresh: %v -> %v", session.CreatedAt, res.session.CreatedAt)
	}
	if len(res.cookies) != 2 {
		names := []string{}
		for _, c := range res.cookies {
			names = append(names, c.Name)
		}
		t.Fatalf("threshold refresh must re-issue session+cache cookies, got %v", names)
	}
	sessionName := resolveSessionCookieName(opts, false)
	for _, c := range res.cookies {
		if c.Name == sessionName && c.MaxAge != 7*24*60*60 {
			t.Fatalf("session_token MaxAge = %d, want 604800 (expiresIn)", c.MaxAge)
		}
	}
}

// Upstream "should update session on POST when deferSessionRefresh is
// enabled" (describe deferSessionRefresh): POST performs the refresh write.
// (The existing 405/GET-needsRefresh legs are pinned by
// TestGetSessionPostRequiresDeferral.)
func TestTriageV1_DeferPostWritesDueSession(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	opts.Session.DeferSessionRefresh = true
	seedSessionUser(t, db, "tridefer@example.com", "tok-tri-defer", time.Now().UTC().Add(30*time.Second))
	before := sessionExpiryOf(t, ctx, db, "tok-tri-defer")
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	GetSession(api, "/api/auth", opts)

	resp := api.Post("/api/auth/get-session", "Cookie: "+signedSessionHeader(t, opts, "tok-tri-defer"))
	if resp.Code != http.StatusOK {
		t.Fatalf("POST expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if got := sessionExpiryOf(t, ctx, db, "tok-tri-defer"); !got.After(before) {
		t.Fatalf("deferred POST must extend the session: %v -> %v", before, got)
	}
}

// Upstream "a request cannot re-enable the cookie cache on a route that
// forces it off" (describe forced strict session validation): change-password
// never consults the cache, so a stale cache plus an empty
// ?disableCookieCache= still 401s once the row is gone.
func TestTriageV1_ForcedStrictChangePassword(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	opts.Session.CookieCache.Enabled = true
	seedSessionUser(t, db, "tristrict@example.com", "tok-tri-strict", time.Now().UTC().Add(time.Hour))
	header := cacheHeaderFor(t, ctx, opts, "tok-tri-strict")
	if err := db.Delete(ctx, "session", []types.Where{{Field: "token", Value: "tok-tri-strict"}}); err != nil {
		t.Fatalf("revoke row: %v", err)
	}
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	ChangePassword(api, "/api/auth", opts)

	resp := api.Post("/api/auth/change-password?disableCookieCache=",
		"Cookie: "+header,
		map[string]any{"currentPassword": "password123", "newPassword": "new-password-1234"})
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("forced-strict change-password: got %d, want 401: %s", resp.Code, resp.Body.String())
	}
}

// Upstream "does not set Cache-Control: no-store on session-gated endpoints"
// (describe get-session cache headers): no-store is a get-session-only
// header; other session routes must not emit it.
func TestTriageV1_NoStoreAbsentElsewhere(t *testing.T) {
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	seedSessionUser(t, db, "trinostore@example.com", "tok-tri-nostore", time.Now().UTC().Add(time.Hour))
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	ListSessions(api, "/api/auth", opts)

	resp := api.Get("/api/auth/list-sessions", "Cookie: "+signedSessionHeader(t, opts, "tok-tri-nostore"))
	if resp.Code != http.StatusOK {
		t.Fatalf("list-sessions: %d %s", resp.Code, resp.Body.String())
	}
	if got := resp.Header().Get("Cache-Control"); got != "" {
		t.Fatalf("Cache-Control = %q on list-sessions, want absent", got)
	}
}

// Upstream "should include additionalFields when retrieving from cookie
// cache" (describe cookie cache versioning): extra session columns stored on
// the row survive the cache round-trip.
func TestTriageV1_CacheServesAdditionalFields(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	opts.Session.CookieCache.Enabled = true
	seedSessionUser(t, db, "triadd@example.com", "tok-tri-add", time.Now().UTC().Add(time.Hour))
	if _, err := db.Update(ctx, "session", []types.Where{{Field: "token", Value: "tok-tri-add"}},
		map[string]any{"role": "admin", "preferences": "{}"}); err != nil {
		t.Fatalf("seed additional fields: %v", err)
	}
	header := cacheHeaderFor(t, ctx, opts, "tok-tri-add")
	cached, ok := cachedSessionFromRequest(header, opts.AllSecrets(), "tok-tri-add", opts.Session)
	if !ok || cached == nil {
		t.Fatal("expected cache hit")
	}
	if cached.Session.AdditionalFields["role"] != "admin" {
		t.Fatalf("role missing from cache: %+v", cached.Session.AdditionalFields)
	}
	if cached.Session.AdditionalFields["preferences"] != "{}" {
		t.Fatalf("preferences missing from cache: %+v", cached.Session.AdditionalFields)
	}
}
