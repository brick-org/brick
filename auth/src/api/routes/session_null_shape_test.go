package routes

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

// B14 (upstream session.ts @ 5468e6bf): missing/expired sessions answer 200
// null (session.ts:94-112,287-303) with Cache-Control: no-store
// (test:2735-2745), and a rejecting cookie-cache VersionFunc 500s instead of
// failing closed to the database.

func b14NullBody(t *testing.T, resp *httptest.ResponseRecorder) {
	t.Helper()
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if got := strings.TrimSpace(resp.Body.String()); got != "null" {
		t.Fatalf("body must be literal null, got %q", resp.Body.String())
	}
	if cc := resp.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", cc)
	}
	if pragma := resp.Header().Get("Pragma"); pragma != "no-cache" {
		t.Fatalf("Pragma = %q, want no-cache", pragma)
	}
}

func TestSessionNull_GetSessionMissingTokenReturns200Null(t *testing.T) {
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	GetSession(api, "/api/auth", opts)

	b14NullBody(t, api.Get("/api/auth/get-session"))
}

func TestSessionNull_GetSessionUnknownTokenReturns200Null(t *testing.T) {
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	GetSession(api, "/api/auth", opts)

	b14NullBody(t, api.Get("/api/auth/get-session",
		"Cookie: "+signedSessionHeader(t, opts, "tok-b14-bogus")))
}

func TestSessionNull_GetSessionExpiredReturns200Null(t *testing.T) {
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	seedSessionUser(t, db, "b14-expired@example.com", "tok-b14-expired", time.Now().UTC().Add(-time.Hour))
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	GetSession(api, "/api/auth", opts)

	resp := api.Get("/api/auth/get-session",
		"Cookie: "+signedSessionHeader(t, opts, "tok-b14-expired"))
	b14NullBody(t, resp)
	if sc := resp.Header().Get("Set-Cookie"); sc == "" {
		t.Fatal("expired 200-null must still emit session cleanup cookies")
	}
}

func TestSessionNull_GetSessionValidStillServes(t *testing.T) {
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	seedSessionUser(t, db, "b14-valid@example.com", "tok-b14-valid", time.Now().UTC().Add(time.Hour))
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	GetSession(api, "/api/auth", opts)

	resp := api.Get("/api/auth/get-session",
		"Cookie: "+signedSessionHeader(t, opts, "tok-b14-valid"))
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "tok-b14-valid") {
		t.Fatalf("valid session must serve the token: %s", resp.Body.String())
	}
}

func TestSessionNull_GetSessionPostUnknownTokenReturns200Null(t *testing.T) {
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	opts.Session.DeferSessionRefresh = true
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	GetSession(api, "/api/auth", opts)

	b14NullBody(t, api.Post("/api/auth/get-session",
		"Cookie: "+signedSessionHeader(t, opts, "tok-b14-bogus")))
}

func TestSessionNull_CookieCacheVersionFuncFailure500s(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	opts.Session.CookieCache.Enabled = true
	opts.Session.CookieCache.VersionFunc = func(types.Session, types.User) (string, error) {
		return "v1", nil
	}
	seedSessionUser(t, db, "b14-ver@example.com", "tok-b14-ver", time.Now().UTC().Add(time.Hour))
	header := cacheHeaderFor(t, ctx, opts, "tok-b14-ver")

	failing := opts
	failing.Session.CookieCache.VersionFunc = func(types.Session, types.User) (string, error) {
		return "", errors.New("boom")
	}

	_, err := resolveGetSession(ctx, failing, getSessionRequest{
		token:        "tok-b14-ver",
		cookieHeader: header,
		headers:      CookieRequestHeaders{},
	})
	status, detail := statusOf(t, err)
	if status != http.StatusInternalServerError || !strings.Contains(detail, types.ErrFailedToGetSession) {
		t.Fatalf("version failure: got %d %q, want 500 FAILED_TO_GET_SESSION", status, detail)
	}

	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	GetSession(api, "/api/auth", failing)
	resp := api.Get("/api/auth/get-session", "Cookie: "+header)
	if resp.Code != http.StatusInternalServerError {
		t.Fatalf("version failure HTTP: got %d, want 500: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), types.ErrFailedToGetSession) {
		t.Fatalf("500 body must carry %q: %s", types.ErrFailedToGetSession, resp.Body.String())
	}
}
