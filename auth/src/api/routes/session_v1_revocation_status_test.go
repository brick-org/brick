package routes

import (
	"net/http"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

// Upstream listSessions/revokeSession sit behind freshSessionMiddleware and
// sensitiveSessionMiddleware: an expired (or missing) session never reaches
// the handler — the middleware throws UNAUTHORIZED (session.ts:544-572).
// The Go port must answer 401 there, not the get-session 400 SESSION_EXPIRED
// mapping (which pins only the get-session throw site).

func TestV1_ExpiredSessionListRevokeIs401(t *testing.T) {
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	seedSessionUser(t, db, "expired-gate@example.com", "tok-expired-gate", time.Now().UTC().Add(-time.Hour))
	header := signedSessionHeader(t, opts, "tok-expired-gate")

	_, listAPI := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	ListSessions(listAPI, "/api/auth", opts)
	if resp := listAPI.Get("/api/auth/list-sessions", "Cookie: "+header); resp.Code != http.StatusUnauthorized {
		t.Fatalf("list-sessions with expired session: got %d, want 401: %s", resp.Code, resp.Body.String())
	}

	_, revokeAPI := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	RevokeSession(revokeAPI, "/api/auth", opts)
	if resp := revokeAPI.Post("/api/auth/revoke-session", "Cookie: "+header, map[string]any{"token": "tok-expired-gate"}); resp.Code != http.StatusUnauthorized {
		t.Fatalf("revoke-session with expired session: got %d, want 401: %s", resp.Code, resp.Body.String())
	}

	// Unknown tokens stay 401 FAILED_TO_GET_SESSION on both routes.
	unknown := signedSessionHeader(t, opts, "tok-missing")
	if resp := listAPI.Get("/api/auth/list-sessions", "Cookie: "+unknown); resp.Code != http.StatusUnauthorized {
		t.Fatalf("list-sessions unknown token: got %d, want 401: %s", resp.Code, resp.Body.String())
	}
	if resp := revokeAPI.Post("/api/auth/revoke-session", "Cookie: "+unknown, map[string]any{"token": "tok-missing"}); resp.Code != http.StatusUnauthorized {
		t.Fatalf("revoke-session unknown token: got %d, want 401: %s", resp.Code, resp.Body.String())
	}

	// Sanity: a live session still lists.
	seedSessionUser(t, db, "live-gate@example.com", "tok-live-gate", time.Now().UTC().Add(time.Hour))
	if resp := listAPI.Get("/api/auth/list-sessions", "Cookie: "+signedSessionHeader(t, opts, "tok-live-gate")); resp.Code != http.StatusOK {
		t.Fatalf("list-sessions live session: got %d, want 200: %s", resp.Code, resp.Body.String())
	}
}
