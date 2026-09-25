package routes

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/types"
)

// F4 tri-state + stale-cleanup tests (PARITY_V2 P04-GAP-1, P05-GAP-1).
// Upstream refs: session.ts updateAge tri-state (updateAge:0 always-refresh,
// unset defaults 24h; session-api.test.ts:252-273) and retired session_data
// clean() on auth failure (session.ts:102-109,120-122;
// cookie-cache-fallback.test.ts:91-136).

func TestSessionUpdateAge_UpdateAgeTriState(t *testing.T) {
	if got := (types.SessionOptions{}).UpdateAgeDuration(); got != 24*time.Hour {
		t.Fatalf("nil UpdateAge = %v, want 24h default", got)
	}
	zero := 0
	if got := (types.SessionOptions{UpdateAge: &zero}).UpdateAgeDuration(); got != 0 {
		t.Fatalf("explicit 0 UpdateAge = %v, want 0 (always-refresh)", got)
	}
	v := 60
	if got := (types.SessionOptions{UpdateAge: &v}).UpdateAgeDuration(); got != 60*time.Second {
		t.Fatalf("UpdateAge 60 = %v, want 60s", got)
	}
}

func TestSessionUpdateAge_ExplicitZeroAlwaysRefresh(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	opts.Session.ExpiresIn = 3600
	opts.Session.UpdateAge = intPtr(0)
	seedSessionUser(t, db, "f4-always@example.com", "tok-f4-always", time.Now().UTC().Add(3600*time.Second))
	_, _, refreshed, _, err := loadSessionWithRefresh(ctx, opts, "tok-f4-always", sessionRefreshConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !refreshed {
		t.Fatal("explicit UpdateAge 0 must always refresh a fresh session")
	}
}

func TestSessionUpdateAge_StaleCleanupOnFailure(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	opts.Session.CookieCache.Enabled = false
	header := "bogus=1; " + sessionDataCookieName + "=retired-value"
	res, err := resolveGetSession(ctx, opts, getSessionRequest{
		token:        "tok-bogus",
		cookieHeader: header,
		headers:      CookieRequestHeaders{},
	})
	if err == nil {
		t.Fatal("bogus token must fail")
	}
	if res == nil {
		t.Fatal("auth failure must still return result carrying stale cleanup cookies")
	}
	found := false
	for _, c := range res.cookies {
		if c.MaxAge < 0 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected Max-Age=0 cleanup cookie on failure, got %+v", res.cookies)
	}
	var _ = http.StatusUnauthorized
}
