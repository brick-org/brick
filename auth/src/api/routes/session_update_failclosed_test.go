package routes

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

// Upstream update-session cookie-cache revocation (session-api.test.ts):
// "fails closed when the backing session is revoked in a stateful
// deployment" — the server deletes the row while only the cookie cache still
// vouches for the session. The update must 401, never re-mint from stale
// data, and the strict (cache-bypassed) read must report the session gone.

func TestUpdateFailclosed_UpdateSessionRevokedFailsClosed(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	opts.Session.CookieCache.Enabled = true
	seedSessionUser(t, db, "revoked-update@example.com", "tok-revoked-update", time.Now().UTC().Add(time.Hour))
	header := cacheHeaderFor(t, ctx, opts, "tok-revoked-update")

	if err := deleteSecondaryAwareSession(ctx, opts, "tok-revoked-update"); err != nil {
		t.Fatal(err)
	}

	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	UpdateSession(api, "/api/auth", opts)
	resp := api.Post("/api/auth/update-session", "Cookie: "+header, map[string]any{"theme": "dark"})
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("revoked update expected 401, got %d: %s", resp.Code, resp.Body.String())
	}

	_, err := resolveGetSession(ctx, opts, getSessionRequest{
		token:        "tok-revoked-update",
		cookieHeader: header,
		headers:      CookieRequestHeaders{},
		query:        types.SessionQueryOptions{DisableCookieCache: true},
	})
	if err == nil {
		t.Fatal("strict read of a revoked session must fail")
	}
}

func TestUpdateFailclosed_DeferWithDisableSessionRefresh(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	opts.Session.DeferSessionRefresh = true
	opts.Session.DisableSessionRefresh = true
	seedSessionUser(t, db, "defer-disabled@example.com", "tok-defer-disabled", time.Now().UTC().Add(30*time.Second))
	beforeRow, err := db.FindOne(ctx, "session", []types.Where{{Field: "token", Value: "tok-defer-disabled"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	beforeExp, _ := timeField(beforeRow, "expires_at", "expiresAt")

	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	GetSession(api, "/api/auth", opts)
	resp := api.Get("/api/auth/get-session", "Cookie: "+signedSessionHeader(t, opts, "tok-defer-disabled"))
	if resp.Code != http.StatusOK {
		t.Fatalf("GET expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if body := resp.Body.String(); !containsNeedsRefreshFalse(body) {
		t.Fatalf("deferred GET with refresh disabled must report needsRefresh:false: %s", body)
	}
	afterRow, err := db.FindOne(ctx, "session", []types.Where{{Field: "token", Value: "tok-defer-disabled"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	afterExp, _ := timeField(afterRow, "expires_at", "expiresAt")
	if !afterExp.Equal(beforeExp) {
		t.Fatalf("disabled refresh must not write: %v -> %v", beforeExp, afterExp)
	}
}

func containsNeedsRefreshFalse(body string) bool {
	for _, needle := range []string{`"needsRefresh":false`, `"needsRefresh": false`} {
		found := false
		for i := 0; i+len(needle) <= len(body); i++ {
			if body[i:i+len(needle)] == needle {
				found = true
				break
			}
		}
		if found {
			return true
		}
	}
	return false
}
