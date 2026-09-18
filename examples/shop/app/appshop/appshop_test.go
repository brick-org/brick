package appshop

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// unusedDSN points at a port nothing listens on. The pgdriver connector is
// lazy, so New + route registration + spec marshal never dial — only tests
// that hit a CRUD route touch the network, and then only to fail fast with
// connection refused (mapped by brick to a 500 envelope).
const unusedDSN = "postgres://localhost:1/unused?sslmode=disable"

func newTestHandler(t *testing.T) http.Handler {
	t.Helper()
	b, bunDB, err := New(unusedDSN)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = bunDB.Close() })
	return b.Handler()
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestServesOpenAPIJSON(t *testing.T) {
	rec := get(t, newTestHandler(t), "/openapi.json")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /openapi.json = %d, want 200", rec.Code)
	}
	// Served by huma itself (not an appshop route) as application/openapi+json.
	if ct := rec.Header().Get("Content-Type"); ct != "application/openapi+json" {
		t.Errorf("Content-Type = %q, want application/openapi+json", ct)
	}
	body, _ := io.ReadAll(rec.Result().Body)
	if !strings.Contains(string(body), `"openapi"`) {
		t.Error("spec body must contain the openapi version marker")
	}
	for _, want := range []string{"/api/deal", "/api/note"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("spec body must document %q", want)
		}
	}
}

func TestServesReference(t *testing.T) {
	rec := get(t, newTestHandler(t), "/reference")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /reference = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	body, _ := io.ReadAll(rec.Result().Body)
	if len(body) == 0 {
		t.Fatal("reference page must not be empty")
	}
	// httptest requests arrive as http://example.com — the viewer must
	// embed that absolute spec URL (scalar-go rejects relative URLs).
	if !strings.Contains(string(body), "http://example.com/openapi.json") {
		t.Error("reference page must embed the request's absolute spec URL")
	}
}

// TestHandlerReusableAcrossRequests proves the serverless pattern: one
// built handler serves many requests, so per-instance caching (not
// per-request construction) is correct.
func TestHandlerReusableAcrossRequests(t *testing.T) {
	h := newTestHandler(t)
	for i := 0; i < 2; i++ {
		if rec := get(t, h, "/openapi.json"); rec.Code != http.StatusOK {
			t.Fatalf("request %d: GET /openapi.json = %d, want 200", i, rec.Code)
		}
	}
}

// TestCRUDRoutesRegistered drives a real CRUD route with a dead database:
// brick must fail at the DB (500 envelope), never at routing (404). The
// negative control proves unmatched paths still 404.
func TestCRUDRoutesRegistered(t *testing.T) {
	h := newTestHandler(t)
	if rec := get(t, h, "/api/deal"); rec.Code != http.StatusInternalServerError {
		t.Errorf("GET /api/deal with dead DB = %d, want 500 (route exists)", rec.Code)
	}
	if rec := get(t, h, "/no-such-route"); rec.Code != http.StatusNotFound {
		t.Errorf("GET /no-such-route = %d, want 404", rec.Code)
	}
}
