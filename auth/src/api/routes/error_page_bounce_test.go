package routes

// B67 regression pins (upstream error.ts:430, url.ts:84-87 @ 5468e6bf):
//   - B6: nil CustomizeDefaultErrorPage = unset = production bounce;
//     explicitly-set-but-empty (&DefaultErrorPageOptions{}) renders.
//   - B7: errorURL already carrying error params preserves them verbatim
//     (raw append like upstream appendQueryParams) instead of collapsing
//     duplicates via q.Set.

import (
	"net/http"
	"strings"
	"testing"

	"github.com/brick-org/brick/auth/src/types"
)

func TestErrorPageBounce_NilBouncesEmptyRenders(t *testing.T) {
	t.Setenv("NODE_ENV", "production")

	// Nil (unset) bounces to / with safe params.
	apiNil := newErrorTestAPI(t, types.Options{})
	respNil := apiNil.Get("/api/auth/error?error=access_denied")
	if respNil.Code != http.StatusFound {
		t.Fatalf("nil status = %d, want 302 (bounce)", respNil.Code)
	}
	if loc := respNil.Header().Get("Location"); !strings.HasPrefix(loc, "/?error=access_denied") {
		t.Fatalf("nil location = %q, want bounce to /", loc)
	}

	// Explicitly-set-but-empty renders (upstream !customizeDefaultErrorPage
	// is false for {} — only nil/undefined bounces).
	emptyOpts := types.Options{}
	emptyOpts.OnAPIError.CustomizeDefaultErrorPage = &types.DefaultErrorPageOptions{}
	apiEmpty := newErrorTestAPI(t, emptyOpts)
	respEmpty := apiEmpty.Get("/api/auth/error?error=access_denied")
	if respEmpty.Code != http.StatusOK {
		t.Fatalf("empty-options status = %d, want 200 (render)", respEmpty.Code)
	}
	if text := respEmpty.Body.String(); !strings.Contains(text, "<!DOCTYPE html>") {
		t.Fatalf("empty-options did not render page: %.200s", text)
	}
}

func TestErrorPageBounce_DupKeyErrorURLPreservedVerbatim(t *testing.T) {
	opts := types.Options{}
	opts.OnAPIError.ErrorURL = "https://app.example/auth-error?error=old1&error=old2&foo=bar"
	api := newErrorTestAPI(t, opts)
	resp := api.Get("/api/auth/error?error=new_error")
	if resp.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.Code)
	}
	loc := resp.Header().Get("Location")
	// Upstream appendQueryParams concatenates raw query text: existing
	// duplicates survive verbatim in order, new params appended.
	if !strings.Contains(loc, "error=old1&error=old2") {
		t.Fatalf("dup error params not preserved verbatim: %q", loc)
	}
	if !strings.Contains(loc, "error=new_error") {
		t.Fatalf("new error param missing: %q", loc)
	}
	if !strings.Contains(loc, "foo=bar") {
		t.Fatalf("existing foo param missing: %q", loc)
	}
	// Both old duplicates plus the new one must be present (3 error keys).
	if n := strings.Count(loc, "error="); n < 3 {
		t.Fatalf("want >=3 error= occurrences (2 old + 1 new), got %d in %q", n, loc)
	}
}
