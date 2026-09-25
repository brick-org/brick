package routes

// B2 unknown-passthrough: upstream update-session.ts:64-74 with test
// session-api.test.ts:2509-2518 (@ 5468e6bf) expects 400 "No fields to
// update" for unknown-only bodies (parseSessionInput drops unknown keys).
// Go kept the legacy union passthrough; this suite pins upstream.

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

func b2UpdateAPI(t *testing.T, opts types.Options) (humatest.TestAPI, string) {
	t.Helper()
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	UpdateSession(api, "/api/auth", opts)
	return api, signedSessionHeader(t, opts, "tok-b2-upd")
}

func TestB2_UpdateSessionUnknownOnly400(t *testing.T) {
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	seedSessionUser(t, db, "b2unknown@example.com", "tok-b2-upd", time.Now().UTC().Add(time.Hour))
	api, header := b2UpdateAPI(t, opts)

	resp := api.Post("/api/auth/update-session", "Cookie: "+header, map[string]any{"unknownField": "value"})
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("unknown-only body: got %d, want 400: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "No fields to update") {
		t.Fatalf("unknown-only body missing message: %s", resp.Body.String())
	}
}

func TestB2_UpdateSessionDeclaredAdditionalPasses(t *testing.T) {
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	opts.Session.Model.AdditionalFields = map[string]types.FieldAttribute{
		"theme": {},
	}
	seedSessionUser(t, db, "b2theme@example.com", "tok-b2-upd", time.Now().UTC().Add(time.Hour))
	api, header := b2UpdateAPI(t, opts)

	resp := api.Post("/api/auth/update-session", "Cookie: "+header, map[string]any{"theme": "dark"})
	if resp.Code != http.StatusOK {
		t.Fatalf("declared additional field: got %d, want 200: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), `"dark"`) {
		t.Fatalf("updated field missing from response: %s", resp.Body.String())
	}
}

func TestB2_UpdateSessionEmpty400(t *testing.T) {
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	seedSessionUser(t, db, "b2empty@example.com", "tok-b2-upd", time.Now().UTC().Add(time.Hour))
	api, header := b2UpdateAPI(t, opts)

	resp := api.Post("/api/auth/update-session", "Cookie: "+header, map[string]any{})
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("empty body: got %d, want 400: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "No fields to update") {
		t.Fatalf("empty body missing message: %s", resp.Body.String())
	}
}
