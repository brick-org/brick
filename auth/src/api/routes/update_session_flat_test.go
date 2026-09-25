package routes

// F4 parity gaps 4+7 (PARITY_V3.md; upstream update-session.ts:76-82 +
// session.ts:853-870 @ 5468e6bf): update-session extras must serialize FLAT
// top-level (session.theme) like parseSessionOutput, and revoke-other must
// revoke only LIVE others with no cookie writes.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

// Update-session response must carry additional fields FLAT top-level
func TestUpdateSessionFlat_UpdateSessionFlatTheme(t *testing.T) {
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	opts.Session.Model.AdditionalFields = map[string]types.FieldAttribute{
		"theme": {},
	}
	seedSessionUser(t, db, "f4flat@example.com", "tok-f4-flat", time.Now().UTC().Add(time.Hour))
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	UpdateSession(api, "/api/auth", opts)

	resp := api.Post("/api/auth/update-session",
		"Cookie: "+signedSessionHeader(t, opts, "tok-f4-flat"),
		map[string]any{"theme": "dark"})
	if resp.Code != http.StatusOK {
		t.Fatalf("update-session: got %d, want 200: %s", resp.Code, resp.Body.String())
	}
	var body struct {
		Session map[string]any `json:"session"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode update-session: %v (%s)", err, resp.Body.String())
	}
	if body.Session["theme"] != "dark" {
		t.Fatalf("session.theme must be flat top-level = dark, got %v (%s)", body.Session["theme"], resp.Body.String())
	}
	if _, nested := body.Session["additionalFields"]; nested {
		t.Fatalf("session must not nest extras under additionalFields (%s)", resp.Body.String())
	}
}

// Revoke-other-sessions: revoke only LIVE others (expiresAt > now, exclude
func TestUpdateSessionFlat_RevokeOtherLiveOnlyNoCookies(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	seedSessionUser(t, db, "f4revoke@example.com", "tok-f4-cur", time.Now().UTC().Add(30*time.Second))
	userRow, err := db.FindOne(ctx, "user", []types.Where{{Field: "email", Value: "f4revoke@example.com"}}, nil)
	if err != nil || userRow == nil {
		t.Fatalf("seed user lookup: %v", err)
	}
	uid := stringField(userRow, "id")
	now := time.Now().UTC()
	mkSession := func(token string, exp time.Time) {
		t.Helper()
		if _, err := db.Create(ctx, "session", map[string]any{
			"id":        "sess-" + token,
			"userId":    uid,
			"token":     token,
			"expiresAt": exp,
			"createdAt": now,
			"updatedAt": now,
		}, nil); err != nil {
			t.Fatalf("seed %s: %v", token, err)
		}
	}
	mkSession("tok-f4-live", now.Add(time.Hour))
	mkSession("tok-f4-expired", now.Add(-time.Hour))

	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	RevokeOtherSessions(api, "/api/auth", opts)

	resp := api.Post("/api/auth/revoke-other-sessions",
		"Cookie: "+signedSessionHeader(t, opts, "tok-f4-cur"))
	if resp.Code != http.StatusOK {
		t.Fatalf("revoke-other-sessions: got %d, want 200: %s", resp.Code, resp.Body.String())
	}
	if got := resp.Header().Get("Set-Cookie"); got != "" {
		t.Fatalf("revoke-other must emit no Set-Cookie, got %q", got)
	}
	if row, _ := db.FindOne(ctx, "session", []types.Where{{Field: "token", Value: "tok-f4-expired"}}, nil); row == nil {
		t.Fatal("expired other session must survive revoke-other-sessions")
	}
	if row, _ := db.FindOne(ctx, "session", []types.Where{{Field: "token", Value: "tok-f4-live"}}, nil); row != nil {
		t.Fatal("live other session must be revoked")
	}
	if row, _ := db.FindOne(ctx, "session", []types.Where{{Field: "token", Value: "tok-f4-cur"}}, nil); row == nil {
		t.Fatal("current session must survive revoke-other-sessions")
	}
}
