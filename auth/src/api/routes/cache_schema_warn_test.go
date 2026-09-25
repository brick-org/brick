package routes

import (
	"context"
	"testing"

	"github.com/brick-org/brick/auth/src/cookies"
)

// Warn-routing for schema-invalid caches (G1 integration follow-up).
// Upstream `parseCookieCachePayload` warns via the configured logger and
// returns null; the codecs surface `cookies.ErrCachePayloadSchema` and the
// session-layer readers must warn + miss (fall through to DB, never throw).
// This pins the route-layer contract: a correctly-signed compact cache with

// should use the configured logger for an invalid signed compact cookie.
func TestSchemaV1_InvalidCacheWarnsAndMisses(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	opts.Session.CookieCache.Enabled = true
	var warns []string
	opts.Logger.Log = func(level, message string, _ ...any) {
		if level == "warn" {
			warns = append(warns, message)
		}
	}
	session := schemaV1RouteSession()
	session["token"] = "tok-warn-1"
	user := schemaV1RouteUser()
	user["emailVerified"] = nil
	value := schemaV1RouteCompactValue(t, opts.CurrentSecret(), session, user)
	if _, ok := cookies.VerifyAny(opts.AllSecrets(), value); !ok {
		t.Fatal("test cookie must verify at the signature step")
	}
	header := sessionDataCookieName + "=" + value
	if payload, ok := cachedSessionFromRequestFull(ctx, header, opts.AllSecrets(), "tok-warn-1", opts); ok || payload != nil {
		t.Fatal("schema-invalid cache must miss, got a hit")
	}
	found := false
	for _, w := range warns {
		if len(w) >= 6 && w[:6] == "Cookie" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected schema-validation warn, got %q", warns)
	}
}
