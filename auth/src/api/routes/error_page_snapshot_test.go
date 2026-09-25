package routes

// F3 snapshot pins for GET /error (P03-GAP-1).
// Pins the rendered HTML for default + customized pages against the pinned
// upstream template
// (vendor/better-auth/.../src/api/routes/error.ts:18-372 at 5468e6bf):
// body/grid background fallbacks, every customizeDefaultErrorPage knob,

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

func newF3ErrorTestAPI(t *testing.T, opts types.Options) humatest.TestAPI {
	t.Helper()
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	Error(api, "/api/auth", opts)
	return api
}

// Default page snapshot: upstream fallbacks and static contract.
func TestErrorPageDefaultSnapshot(t *testing.T) {
	api := newF3ErrorTestAPI(t, types.Options{})
	resp := api.Get("/api/auth/error?error=TEST")
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.Code)
	}
	if ct := resp.Header().Get("Content-Type"); ct != "text/html" {
		t.Fatalf("content-type = %q, want exactly %q (upstream error.ts:441)", ct, "text/html")
	}
	text := resp.Body.String()
	for _, marker := range []string{
		"<!DOCTYPE html>",
		"<title>Error</title>",
		"ERROR",
		"Something went wrong",
		"CODE:",
		"TEST",
		"font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif",
		"background: var(--background);",
		"background-image: linear-gradient(to right, var(--border) 1px, transparent 1px),",
		"mask-image: radial-gradient(ellipse at center, transparent 20%, black);",
		"background: var(--background);",
		"background: var(--background);",
		"background: var(--background);",
		"border: 2px solid var(--destructive);",
		"color: var(--foreground);",
		"<!-- Corner decorations -->",
		"We encountered an unexpected error. Please try again or return to the home page.",
		"more information about the error",
		"<a href='https://better-auth.com/docs/reference/errors/TEST'",
		"Go Home",
		"Ask AI",
		"https://better-auth.com/docs/reference/errors/TEST?askai=What%20does%20the%20error%20code%20TEST%20mean%3F",
		"prefers-color-scheme: dark",
		"--primary: black;",
		"--primary: white;",
	} {
		if !strings.Contains(text, marker) {
			t.Fatalf("marker %q missing", marker)
		}
	}
}

// Customized page snapshot: every knob from init-options.ts:1747-1778 must
func TestErrorPageCustomizedSnapshot(t *testing.T) {
	opts := types.Options{}
	opts.OnAPIError.CustomizeDefaultErrorPage = &types.DefaultErrorPageOptions{}
	p := opts.OnAPIError.CustomizeDefaultErrorPage
	p.Colors.Background = "#0b0b0b"
	p.Colors.Foreground = "#f0f0f0"
	p.Colors.Primary = "#123456"
	p.Colors.PrimaryForeground = "#abcdef"
	p.Colors.MutedForeground = "#777777"
	p.Colors.Border = "#222222"
	p.Colors.Destructive = "#ff0000"
	p.Colors.TitleBorder = "#654321"
	p.Colors.TitleColor = "#112233"
	p.Colors.GridColor = "#333333"
	p.Colors.CardBackground = "#101010"
	p.Colors.CornerBorder = "#999999"
	p.Size.RadiusSm = "2px"
	p.Size.TextSm = "0.9rem"
	p.Size.Text2xl = "1.6rem"
	p.Size.Text4xl = "2.4rem"
	p.Size.Text6xl = "4rem"
	p.Font.DefaultFamily = "Custom Font, sans-serif"
	p.Font.MonoFamily = "Custom Mono, monospace"
	api := newF3ErrorTestAPI(t, opts)
	text := api.Get("/api/auth/error?error=TEST").Body.String()
	for _, want := range []string{
		"#0b0b0b", "#f0f0f0", "#123456", "#abcdef",
		"#777777", "#222222", "#ff0000", "#654321",
		"#112233", "#333333", "#101010", "#999999",
		"2px", "0.9rem", "1.6rem", "2.4rem", "4rem",
		"Custom Font, sans-serif", "Custom Mono, monospace",
		"background: #0b0b0b;",
		"linear-gradient(to right, #333333 1px, transparent 1px),",
		"border: 2px solid #654321;",
		"color: #112233;",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("custom value %q missing", want)
		}
	}
	if n := strings.Count(text, "--primary: #123456;"); n != 2 {
		t.Fatalf("--primary custom appears %d times, want 2 (light + dark)", n)
	}
}

// Decoration toggles remove their markup (upstream error.ts:124-155,168-218,225).
func TestErrorPageDecorationToggles(t *testing.T) {
	opts := types.Options{}
	opts.OnAPIError.CustomizeDefaultErrorPage = &types.DefaultErrorPageOptions{}
	opts.OnAPIError.CustomizeDefaultErrorPage.DisableCornerDecorations = true
	opts.OnAPIError.CustomizeDefaultErrorPage.DisableBackgroundGrid = true
	opts.OnAPIError.CustomizeDefaultErrorPage.DisableTitleBorder = true
	text := newF3ErrorTestAPI(t, opts).Get("/api/auth/error?error=TEST").Body.String()
	if strings.Contains(text, "Corner decorations") {
		t.Fatal("corner decorations rendered when disabled")
	}
	if strings.Contains(text, "background-image: linear-gradient") {
		t.Fatal("background grid rendered when disabled")
	}
	if !strings.Contains(text, "border: 2px solid transparent") {
		t.Fatal("title border must render transparent when disabled")
	}
}

// Custom description is rendered sanitized (upstream sanitize branch,
func TestErrorPageCustomDescriptionSnapshot(t *testing.T) {
	api := newF3ErrorTestAPI(t, types.Options{})
	resp := api.Get("/api/auth/error?error=TEST&error_description=" + url.QueryEscape("hello <b>world</b>"))
	text := resp.Body.String()
	if !strings.Contains(text, "hello &lt;b&gt;world&lt;/b&gt;") {
		t.Fatalf("sanitized custom description missing: %.300s", text)
	}
	if strings.Contains(text, "We encountered an unexpected error") {
		t.Fatal("default copy rendered despite custom description")
	}
}

// Regression anchor: script in the description is escaped, never raw.
func TestErrorPageXSSDescriptionRegression(t *testing.T) {
	api := newF3ErrorTestAPI(t, types.Options{})
	attack := url.QueryEscape("<script>alert(1)</script>")
	text := api.Get("/api/auth/error?error=TEST&error_description=" + attack).Body.String()
	if strings.Contains(text, "<script>") {
		t.Fatal("raw script tag leaked into the page")
	}
	if !strings.Contains(text, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatal("escaped description payload missing")
	}
}

// Regression anchor: hostile code collapses to UNKNOWN, never raw.
func TestErrorPageXSSCodeRegression(t *testing.T) {
	api := newF3ErrorTestAPI(t, types.Options{})
	attack := url.QueryEscape("<script>")
	text := api.Get("/api/auth/error?error=" + attack).Body.String()
	if strings.Contains(text, "<script>") {
		t.Fatal("raw code leaked into the page")
	}
	if !strings.Contains(text, "UNKNOWN") {
		t.Fatal("invalid code did not default to UNKNOWN")
	}
	if !strings.Contains(text, "https://better-auth.com/docs/reference/errors/UNKNOWN") {
		t.Fatal("docs link missing safe UNKNOWN code")
	}
}
