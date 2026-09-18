package routes

import (
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
)

// GET /error renders the configurable default error page.
//
// Exact port of vendor/better-auth/packages/better-auth/src/api/routes/error.ts:
//   - Query parameters are `error` (code) and `error_description`.
//   - The code must match /^['A-Za-z0-9_-]+$/; anything else renders UNKNOWN.
//   - Descriptions are HTML-sanitized (see sanitizeErrorHTML).
//   - A configured onAPIError.errorURL receives a 302 with the safe error
//     parameters instead of the page.
//   - Production (NODE_ENV=production, mirroring the rate-limit default in
//     auth/index.go) without customizeDefaultErrorPage bounces to / with the
//     safe parameters instead of rendering.
//   - Rendering honors every customizeDefaultErrorPage knob (colors, font,
//     size, decoration toggles) with the upstream defaults. The Go-only
//     ErrorPageSize RadiusMd/RadiusLg tokens have no upstream counterpart
//     and are intentionally unused.
func Error(api huma.API, basePath string, opts types.Options) {
	op := &huma.Operation{
		Tags:        []string{"Auth"},
		Method:      http.MethodGet,
		Path:        basePath + "/error",
		OperationID: "auth-error-page",
		Summary:     "Auth error page",
		Metadata: map[string]any{
			"openapi": map[string]any{
				"description": "Displays an error page",
			},
		},
	}

	api.Adapter().Handle(op, func(ctx huma.Context) {
		unsanitizedCode := ctx.Query("error")
		if unsanitizedCode == "" {
			unsanitizedCode = "UNKNOWN"
		}
		unsanitizedDescription := ctx.Query("error_description")

		safeCode := unsanitizedCode
		if !isValidErrorCode(safeCode) {
			safeCode = "UNKNOWN"
		}
		safeDescription := ""
		if unsanitizedDescription != "" {
			safeDescription = sanitizeErrorHTML(unsanitizedDescription)
		}

		params := url.Values{}
		params.Set("error", safeCode)
		if unsanitizedDescription != "" {
			params.Set("error_description", unsanitizedDescription)
		}

		if opts.OnAPIError.ErrorURL != "" {
			redirect(ctx, mergeErrorParams(opts.OnAPIError.ErrorURL, params))
			return
		}

		if os.Getenv("NODE_ENV") == "production" && opts.OnAPIError.CustomizeDefaultErrorPage == (types.DefaultErrorPageOptions{}) {
			redirect(ctx, "/?"+params.Encode())
			return
		}

		body := renderDefaultErrorPage(opts.OnAPIError.CustomizeDefaultErrorPage, safeCode, safeDescription)
		ctx.SetHeader("Content-Type", "text/html; charset=utf-8")
		ctx.SetStatus(http.StatusOK)
		_, _ = ctx.BodyWriter().Write([]byte(body))
	})
}

func redirect(ctx huma.Context, location string) {
	ctx.SetHeader("Location", location)
	ctx.SetStatus(http.StatusFound)
}

// mergeErrorParams appends the safe error parameters to a base URL,
// preserving existing query parameters and fragments (upstream
// appendQueryParams).
func mergeErrorParams(base string, params url.Values) string {
	u, err := url.Parse(base)
	if err != nil {
		sep := "?"
		if strings.Contains(base, "?") {
			sep = "&"
		}
		return base + sep + params.Encode()
	}
	q := u.Query()
	for k, vs := range params {
		for _, v := range vs {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// isValidErrorCode mirrors upstream /^['A-Za-z0-9_-]+$/ (invalid codes
// render UNKNOWN).
func isValidErrorCode(code string) bool {
	if code == "" {
		return false
	}
	for i := 0; i < len(code); i++ {
		c := code[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
			c == '\'' || c == '-' || c == '_' {
			continue
		}
		return false
	}
	return true
}

// sanitizeErrorHTML mirrors the upstream sanitize helper: <, >, ", ' are
// escaped, and & is escaped unless it already opens an HTML entity (amp,
// lt, gt, quot, #39, #xHEX, #DEC).
func sanitizeErrorHTML(input string) string {
	s := strings.ReplaceAll(input, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	var out strings.Builder
	out.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		if s[i] != '&' || isHTMLEntityAt(s, i) {
			out.WriteByte(s[i])
			continue
		}
		out.WriteString("&amp;")
	}
	return out.String()
}

// isHTMLEntityAt reports whether s[i:] opens an HTML entity reference
// (upstream /&(?!amp;|lt;|gt;|quot;|#39;|#x[0-9a-fA-F]+;|#[0-9]+;)/).
func isHTMLEntityAt(s string, i int) bool {
	rest := s[i+1:]
	if strings.HasPrefix(rest, "amp;") || strings.HasPrefix(rest, "lt;") ||
		strings.HasPrefix(rest, "gt;") || strings.HasPrefix(rest, "quot;") ||
		strings.HasPrefix(rest, "#39;") {
		return true
	}
	if strings.HasPrefix(rest, "#") {
		j := 1
		if j < len(rest) && (rest[j] == 'x' || rest[j] == 'X') {
			j++
			start := j
			for j < len(rest) && isHexDigit(rest[j]) {
				j++
			}
			return j > start && j < len(rest) && rest[j] == ';'
		}
		start := j
		for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
			j++
		}
		return j > start && j < len(rest) && rest[j] == ';'
	}
	return false
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// jsEncodeURIComponent mirrors encodeURIComponent for the error-code links
// (unreserved marks stay raw, everything else %XX with uppercase hex).
func jsEncodeURIComponent(s string) string {
	var out strings.Builder
	out.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
			c == '-' || c == '_' || c == '.' || c == '!' || c == '~' ||
			c == '*' || c == '\'' || c == '(' || c == ')' {
			out.WriteByte(c)
			continue
		}
		const hex = "0123456789ABCDEF"
		out.WriteByte('%')
		out.WriteByte(hex[c>>4])
		out.WriteByte(hex[c&0x0f])
	}
	return out.String()
}

func orErrorDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// renderDefaultErrorPage renders the upstream default error page with the
// configured theme applied (upstream `html` in error.ts).
func renderDefaultErrorPage(custom types.DefaultErrorPageOptions, code, description string) string {
	c := custom.Colors
	s := custom.Size
	f := custom.Font

	fontDefault := orErrorDefault(f.DefaultFamily, "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif")
	textSm := orErrorDefault(s.TextSm, "0.875rem")
	text2xl := orErrorDefault(s.Text2xl, "1.5rem")
	text4xl := orErrorDefault(s.Text4xl, "2.25rem")
	text6xl := orErrorDefault(s.Text6xl, "3rem")
	radius := orErrorDefault(s.RadiusSm, "0.625rem")
	mono := orErrorDefault(f.MonoFamily, "var(--font-geist-mono)")
	primary := orErrorDefault(c.Primary, "black")
	primaryFg := orErrorDefault(c.PrimaryForeground, "white")
	background := orErrorDefault(c.Background, "white")
	foreground := orErrorDefault(c.Foreground, "oklch(0.271 0 0)")
	border := orErrorDefault(c.Border, "oklch(0.89 0 0)")
	destructive := orErrorDefault(c.Destructive, "oklch(0.55 0.15 25.723)")
	mutedFg := orErrorDefault(c.MutedForeground, "oklch(0.545 0 0)")
	cornerBorder := orErrorDefault(c.CornerBorder, "#404040")

	darkPrimary := orErrorDefault(c.Primary, "white")
	darkPrimaryFg := orErrorDefault(c.PrimaryForeground, "black")
	darkBackground := orErrorDefault(c.Background, "oklch(0.15 0 0)")
	darkForeground := orErrorDefault(c.Foreground, "oklch(0.98 0 0)")
	darkBorder := orErrorDefault(c.Border, "oklch(0.27 0 0)")
	darkDestructive := orErrorDefault(c.Destructive, "oklch(0.65 0.15 25.723)")
	darkMutedFg := orErrorDefault(c.MutedForeground, "oklch(0.65 0 0)")
	darkCornerBorder := orErrorDefault(c.CornerBorder, "#a0a0a0")

	gridColor := orErrorDefault(c.GridColor, "var(--border)")
	cardBackground := orErrorDefault(c.CardBackground, "var(--background)")
	titleBorder := orErrorDefault(c.TitleBorder, "var(--destructive)")
	if custom.DisableTitleBorder {
		titleBorder = "transparent"
	}
	titleColor := orErrorDefault(c.TitleColor, "var(--foreground)")

	var grid string
	if !custom.DisableBackgroundGrid {
		grid = `
      <div
        style="
          position: absolute;
          inset: 0;
          background-image: linear-gradient(to right, ` + gridColor + ` 1px, transparent 1px),
            linear-gradient(to bottom, ` + gridColor + ` 1px, transparent 1px);
          background-size: 40px 40px;
          opacity: 0.6;
          pointer-events: none;
          width: 100vw;
          height: 100vh;
        "
      ></div>
      <div
        style="
          position: absolute;
          inset: 0;
          display: flex;
          align-items: center;
          justify-content: center;
          background: ` + background + `;
          mask-image: radial-gradient(ellipse at center, transparent 20%, black);
          -webkit-mask-image: radial-gradient(ellipse at center, transparent 20%, black);
          pointer-events: none;
        "
      ></div>
`
	}

	var corners string
	if !custom.DisableCornerDecorations {
		corners = `
        <!-- Corner decorations -->
        <div
          style="
            position: absolute;
            top: -2px;
            left: -2px;
            width: 2rem;
            height: 2rem;
            border-top: 4px solid var(--corner-border);
            border-left: 4px solid var(--corner-border);
          "
        ></div>
        <div
          style="
            position: absolute;
            top: -2px;
            right: -2px;
            width: 2rem;
            height: 2rem;
            border-top: 4px solid var(--corner-border);
            border-right: 4px solid var(--corner-border);
          "
        ></div>

        <div
          style="
            position: absolute;
            bottom: -2px;
            left: -2px;
            width: 2rem;
            height: 2rem;
            border-bottom: 4px solid var(--corner-border);
            border-left: 4px solid var(--corner-border);
          "
        ></div>
        <div
          style="
            position: absolute;
            bottom: -2px;
            right: -2px;
            width: 2rem;
            height: 2rem;
            border-bottom: 4px solid var(--corner-border);
            border-right: 4px solid var(--corner-border);
          "
        ></div>`
	}

	desc := description
	if desc == "" {
		desc = "We encountered an unexpected error. Please try again or return to the home page. If you're a developer, you can find " +
			`<a href='https://better-auth.com/docs/reference/errors/` + jsEncodeURIComponent(code) + `' target='_blank' rel="noopener noreferrer" style='color: var(--foreground); text-decoration: underline;'>more information about the error</a>.`
	}
	askAI := "https://better-auth.com/docs/reference/errors/" + jsEncodeURIComponent(code) +
		"?askai=" + jsEncodeURIComponent("What does the error code "+code+" mean?")

	var page strings.Builder
	page.WriteString(`<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Error</title>
    <style>
      * {
        box-sizing: border-box;
      }
      body {
        font-family: ` + fontDefault + `;
        background: ` + background + `;
        color: var(--foreground);
        margin: 0;
      }
      :root,
      :host {
        --spacing: 0.25rem;
        --container-md: 28rem;
        --text-sm: ` + textSm + `;
        --text-sm--line-height: calc(1.25 / 0.875);
        --text-2xl: ` + text2xl + `;
        --text-2xl--line-height: calc(2 / 1.5);
        --text-4xl: ` + text4xl + `;
        --text-4xl--line-height: calc(2.5 / 2.25);
        --text-6xl: ` + text6xl + `;
        --text-6xl--line-height: 1;
        --font-weight-medium: 500;
        --font-weight-semibold: 600;
        --font-weight-bold: 700;
        --default-transition-duration: 150ms;
        --default-transition-timing-function: cubic-bezier(0.4, 0, 0.2, 1);
        --radius: ` + radius + `;
        --default-mono-font-family: ` + mono + `;
        --primary: ` + primary + `;
        --primary-foreground: ` + primaryFg + `;
        --background: ` + background + `;
        --foreground: ` + foreground + `;
        --border: ` + border + `;
        --destructive: ` + destructive + `;
        --muted-foreground: ` + mutedFg + `;
        --corner-border: ` + cornerBorder + `;
      }

      button, .btn {
        cursor: pointer;
        background: none;
        border: none;
        color: inherit;
        font: inherit;
        transition: all var(--default-transition-duration)
          var(--default-transition-timing-function);
      }
      button:hover, .btn:hover {
        opacity: 0.8;
      }

      @media (prefers-color-scheme: dark) {
        :root,
        :host {
          --primary: ` + darkPrimary + `;
          --primary-foreground: ` + darkPrimaryFg + `;
          --background: ` + darkBackground + `;
          --foreground: ` + darkForeground + `;
          --border: ` + darkBorder + `;
          --destructive: ` + darkDestructive + `;
          --muted-foreground: ` + darkMutedFg + `;
          --corner-border: ` + darkCornerBorder + `;
        }
      }
      @media (max-width: 640px) {
        :root, :host {
          --text-6xl: 2.5rem;
          --text-2xl: 1.25rem;
          --text-sm: 0.8125rem;
        }
      }
      @media (max-width: 480px) {
        :root, :host {
          --text-6xl: 2rem;
          --text-2xl: 1.125rem;
        }
      }
    </style>
  </head>
  <body style="width: 100vw; min-height: 100vh; overflow-x: hidden; overflow-y: auto;">
    <div
        style="
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            gap: 1.5rem;
            position: relative;
            width: 100%;
            min-height: 100vh;
            padding: 1rem;
        "
        >
`)
	page.WriteString(grid)
	page.WriteString(`
<div
  style="
    position: relative;
    z-index: 10;
    border: 2px solid var(--border);
    background: ` + cardBackground + `;
    padding: 1.5rem;
    max-width: 42rem;
    width: 100%;
  "
>
`)
	page.WriteString(corners)
	page.WriteString(`
        <div style="text-align: center; margin-bottom: 1.5rem;">
          <div style="margin-bottom: 1.5rem;">
            <div
              style="
                display: inline-block;
                border: 2px solid ` + titleBorder + `;
                padding: 0.375rem 1rem;
              "
            >
              <h1
                style="
                  font-size: var(--text-6xl);
                  font-weight: var(--font-weight-semibold);
                  color: ` + titleColor + `;
                  letter-spacing: -0.02em;
                  margin: 0;
                "
              >
                ERROR
              </h1>
            </div>
            <div
              style="
                height: 2px;
                background-color: var(--border);
                width: calc(100% + 3rem);
                margin-left: -1.5rem;
                margin-top: 1.5rem;
              "
            ></div>
          </div>

          <h2
            style="
              font-size: var(--text-2xl);
              font-weight: var(--font-weight-semibold);
              color: var(--foreground);
              margin: 0 0 1rem;
            "
          >
            Something went wrong
          </h2>

          <div
            style="
                display: inline-flex;
                align-items: center;
                gap: 0.5rem;
                border: 2px solid var(--border);
                background-color: var(--muted);
                padding: 0.375rem 0.75rem;
                margin: 0 0 1rem;
                flex-wrap: wrap;
                justify-content: center;
            "
            >
            <span
                style="
                font-size: 0.75rem;
                color: var(--muted-foreground);
                font-weight: var(--font-weight-semibold);
                "
            >
                CODE:
            </span>
            <span
                style="
                font-size: var(--text-sm);
                font-family: var(--default-mono-font-family, monospace);
                color: var(--foreground);
                word-break: break-all;
                "
            >
                ` + sanitizeErrorHTML(code) + `
            </span>
            </div>

          <p
            style="
              color: var(--muted-foreground);
              max-width: 28rem;
              margin: 0 auto;
              font-size: var(--text-sm);
              line-height: 1.5;
              text-wrap: pretty;
            "
          >
            ` + desc + `
          </p>
        </div>

        <div
          style="
            display: flex;
            gap: 0.75rem;
            margin-top: 1.5rem;
            justify-content: center;
            flex-wrap: wrap;
          "
        >
          <a
            href="/"
            style="
              text-decoration: none;
            "
          >
            <div
              style="
                border: 2px solid var(--border);
                background: var(--primary);
                color: var(--primary-foreground);
                padding: 0.5rem 1rem;
                border-radius: 0;
                white-space: nowrap;
              "
              class="btn"
            >
              Go Home
            </div>
          </a>
          <a
            href="` + askAI + `"
            target="_blank"
            rel="noopener noreferrer"
            style="
              text-decoration: none;
            "
          >
            <div
              style="
                border: 2px solid var(--border);
                background: transparent;
                color: var(--foreground);
                padding: 0.5rem 1rem;
                border-radius: 0;
                white-space: nowrap;
              "
              class="btn"
            >
              Ask AI
            </div>
          </a>
        </div>
      </div>
    </div>
  </body>
</html>`)
	return page.String()
}
