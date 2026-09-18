package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestMissingDatabaseURLIs500(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	cached = sync.OnceValues(build)

	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rec := httptest.NewRecorder()
	Handler(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("Handler without DATABASE_URL = %d, want 500", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
	if !strings.Contains(rec.Body.String(), "DATABASE_URL is not set") {
		t.Errorf("body must name the missing env var, got %q", rec.Body.String())
	}
}

// TestServesDocsWithoutLiveDB proves the warm-instance path end to end:
// with a DSN set (even unreachable — pgdriver dials lazily), the cached
// handler builds once and serves the DB-free docs routes repeatedly.
func TestServesDocsWithoutLiveDB(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://localhost:1/unused?sslmode=disable")
	cached = sync.OnceValues(build)

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
		rec := httptest.NewRecorder()
		Handler(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: Handler = %d, want 200", i, rec.Code)
		}
	}
}
