package routes

// Exact-port tests for GET /error against the pinned upstream page
// (vendor/better-auth/packages/better-auth/src/api/routes/error.ts and
// error.test.ts): safe code/description parameters, custom errorURL and
// production redirects, configurable rendering, and structural snapshots.
// All hermetic (humatest, no network).

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

func newErrorTestAPI(t *testing.T, opts types.Options) humatest.TestAPI {
	t.Helper()
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	Error(api, "/api/auth", opts)
	return api
}

// Port of upstream error.test.ts "should sanitize error description".
func TestErrorPageSanitizesDescription(t *testing.T) {
	api := newErrorTestAPI(t, types.Options{})
	attack := url.QueryEscape("<script>alert(1)</script>")
	resp := api.Get("/api/auth/error?error=TEST&error_description=" + attack)
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d", resp.Code)
	}
	text := resp.Body.String()
	if strings.Contains(text, "<script>") {
		t.Fatal("raw script tag leaked into the page")
	}
	if !strings.Contains(text, "&lt;script&gt;") {
		t.Fatal("escaped description missing")
	}
}

// Port of upstream error.test.ts "should sanitize code parameter".
func TestErrorPageSanitizesCode(t *testing.T) {
	api := newErrorTestAPI(t, types.Options{})
	attack := url.QueryEscape("<script>")
	resp := api.Get("/api/auth/error?error=" + attack)
	text := resp.Body.String()
	if strings.Contains(text, "<script>") {
		t.Fatal("raw code leaked into the page")
	}
	// Invalid codes default to UNKNOWN.
	if !strings.Contains(text, "UNKNOWN") {
		t.Fatal("invalid code did not default to UNKNOWN")
	}
}

// Valid codes pass through verbatim (charset: letters, digits, ', -, _).
func TestErrorPageValidCodePassesThrough(t *testing.T) {
	api := newErrorTestAPI(t, types.Options{})
	resp := api.Get("/api/auth/error?error=invalid_grant")
	if text := resp.Body.String(); !strings.Contains(text, "invalid_grant") {
		t.Fatalf("valid code missing: %.200s", text)
	}
}

// A configured errorURL redirects with the safe error parameters.
func TestErrorPageCustomURLRedirect(t *testing.T) {
	opts := types.Options{}
	opts.OnAPIError.ErrorURL = "https://app.example/auth-error"
	api := newErrorTestAPI(t, opts)
	resp := api.Get("/api/auth/error?error=access_denied&error_description=" + url.QueryEscape("no <b>access</b>"))
	if resp.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.Code)
	}
	loc := resp.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(loc, "https://app.example/auth-error") {
		t.Fatalf("location = %q", loc)
	}
	q := u.Query()
	if q.Get("error") != "access_denied" {
		t.Fatalf("error param = %q", q.Get("error"))
	}
	// The redirect carries the raw description URL-encoded (upstream
	// appendQueryParams); the redirect target owns escaping.
	if q.Get("error_description") != "no <b>access</b>" {
		t.Fatalf("description param = %q", q.Get("error_description"))
	}
	if !strings.Contains(loc, "error_description=no+%3Cb%3Eaccess%3C%2Fb%3E") {
		t.Fatalf("description not URL-encoded in transit: %q", loc)
	}
}

// Production without customization bounces to / (upstream isProduction).
func TestErrorPageProductionRedirect(t *testing.T) {
	t.Setenv("NODE_ENV", "production")
	api := newErrorTestAPI(t, types.Options{})
	resp := api.Get("/api/auth/error?error=access_denied")
	if resp.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 in production", resp.Code)
	}
	if loc := resp.Header().Get("Location"); !strings.HasPrefix(loc, "/?error=access_denied") {
		t.Fatalf("location = %q", loc)
	}
	// Customization disables the production bounce: the page renders.
	custom := types.Options{}
	custom.OnAPIError.CustomizeDefaultErrorPage.Colors.Primary = "#123456"
	api2 := newErrorTestAPI(t, custom)
	resp2 := api2.Get("/api/auth/error?error=access_denied")
	if resp2.Code != http.StatusOK {
		t.Fatalf("customized status = %d, want 200", resp2.Code)
	}
}

// Configurable rendering: colors, fonts, sizes, and decoration toggles.
func TestErrorPageCustomRendering(t *testing.T) {
	opts := types.Options{}
	p := &opts.OnAPIError.CustomizeDefaultErrorPage
	p.Colors.Background = "#111111"
	p.Colors.Primary = "#123456"
	p.Colors.TitleBorder = "#654321"
	p.Font.DefaultFamily = "Custom Font, sans-serif"
	p.Font.MonoFamily = "Custom Mono, monospace"
	p.Size.Text6xl = "4rem"
	p.Size.RadiusSm = "2px"
	api := newErrorTestAPI(t, opts)
	text := api.Get("/api/auth/error?error=TEST").Body.String()
	for _, want := range []string{
		"#111111", "#123456", "#654321",
		"Custom Font, sans-serif", "Custom Mono, monospace",
		"4rem", "2px",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("custom value %q missing", want)
		}
	}
	// Decoration toggles remove their markup.
	off := types.Options{}
	off.OnAPIError.CustomizeDefaultErrorPage.DisableCornerDecorations = true
	off.OnAPIError.CustomizeDefaultErrorPage.DisableBackgroundGrid = true
	off.OnAPIError.CustomizeDefaultErrorPage.DisableTitleBorder = true
	apiOff := newErrorTestAPI(t, off)
	plain := apiOff.Get("/api/auth/error?error=TEST").Body.String()
	if strings.Contains(plain, "Corner decorations") {
		t.Fatal("corner decorations rendered when disabled")
	}
	if strings.Contains(plain, "background-image: linear-gradient") {
		t.Fatal("background grid rendered when disabled")
	}
	if !strings.Contains(plain, "border: 2px solid transparent") {
		t.Fatal("title border must render transparent when disabled")
	}
}

// Structural snapshot of the default page (upstream layout contract).
func TestErrorPageStructure(t *testing.T) {
	api := newErrorTestAPI(t, types.Options{})
	resp := api.Get("/api/auth/error?error=TEST")
	text := resp.Body.String()
	for _, marker := range []string{
		"<!DOCTYPE html>", "<title>Error</title>",
		"Something went wrong", "CODE:", "TEST", "Go Home", "Ask AI",
		"better-auth.com/docs/reference/errors/TEST",
		"prefers-color-scheme: dark",
		"--text-6xl", "--radius",
		"We encountered an unexpected error",
	} {
		if !strings.Contains(text, marker) {
			t.Fatalf("marker %q missing", marker)
		}
	}
	if ct := resp.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("content-type = %q", ct)
	}
}
