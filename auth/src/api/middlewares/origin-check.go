package middlewares

import (
	"net/http"
	"strings"
)

// --- Origin / CSRF checks (upstream
// `src/api/middlewares/origin-check.ts`) ---
//
// Upstream wires `originCheckMiddleware` on `/**` plus per-endpoint
// `originCheck(getValue)` guards and the `formCsrfMiddleware` Fetch-Metadata
// gate. The shared core is `validateOrigin`: only state-changing requests
// carrying browser evidence are challenged, skip flags
// (`skipOriginCheck` boolean or path list, `skipCSRFCheck`, and the
// `disableOriginCheck`-implies-no-CSRF backward-compat path) short-circuit
// first, and trust is decided by `matchesOriginPattern` over the configured
// trusted origins (plus per-request dynamic origins).
//
// The Go enforcement lives in `api.Router` (`auth/src/api/index.go`):
// the origin-check middleware challenges mutating requests carrying both an
// `Origin` and a `Cookie` header via `originTrustedForRequest` (static trust
// through `types.IsTrustedOrigin` plus the `ExpandDynamicBaseURLOrigins`
// dynamic leg), honoring `Advanced.DisableCSRFCheck` /
// `Advanced.DisableOriginCheck` with the same backward-compat warning; route
// handlers validate `callbackURL`/`redirectTo`/`errorCallbackURL`/
// `newUserCallbackURL` via `types.IsTrustedRedirect` (the per-endpoint
// `originCheck` equivalent). The pure gates below mirror the upstream
// predicates so middleware decisions and tests share one spelling. This file
// stays dependency-free (no `api`/`routes` imports) so `api` can consume it
// without a cycle.

// IsMutatingMethod reports whether method carries a state-changing semantic
// subject to origin validation, mirroring the upstream gate that skips
// `GET`, `OPTIONS`, and `HEAD` (vendor/.../src/api/middlewares/origin-check.ts:69-76).
func IsMutatingMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// NeedsOriginValidation reports whether a request carries the browser-style
// evidence upstream challenges: an origin (or referer) AND cookies. Requests
// without cookies (server-to-server) always pass through, mirroring
// upstream's `shouldValidate = forceValidate || useCookies` with
// `forceValidate=false` on the router path
// (vendor/.../src/api/middlewares/origin-check.ts:247-251).
func NeedsOriginValidation(originOrReferer, cookieHeader string) bool {
	return strings.TrimSpace(originOrReferer) != "" && strings.TrimSpace(cookieHeader) != ""
}

// OriginOrReferer prefers the `Origin` header, falling back to `Referer`,
// mirroring `headers.get("origin") || headers.get("referer") || ""`
// (vendor/.../src/api/middlewares/origin-check.ts:230).
func OriginOrReferer(origin, referer string) string {
	if strings.TrimSpace(origin) != "" {
		return origin
	}
	return referer
}

// ShouldSkipOriginCheck reports whether a request path is exempted by a
// skip-origin-check path list, mirroring upstream's array branch
// (vendor/.../src/api/middlewares/origin-check.ts:33-49): only an exact path
// or a slash-boundary child matches, so skipping "/public/data" never also
// skips "/public/database" or "/public/data-delete". skipAll mirrors the
// boolean `skipOriginCheck === true` branch (upstream `Advanced.
// DisableOriginCheck`).
func ShouldSkipOriginCheck(skipAll bool, skipPaths []string, currentPath string) bool {
	if skipAll {
		return true
	}
	if len(skipPaths) == 0 {
		return false
	}
	normalized := "/" + strings.Trim(strings.TrimSpace(currentPath), "/")
	if normalized == "/" {
		normalized = strings.TrimSpace(currentPath)
		if normalized == "" {
			normalized = "/"
		}
	}
	for _, skip := range skipPaths {
		candidate := strings.TrimRight(strings.TrimSpace(skip), "/")
		if candidate == "" {
			continue
		}
		if !strings.HasPrefix(candidate, "/") {
			candidate = "/" + candidate
		}
		if normalized == candidate || strings.HasPrefix(normalized, candidate+"/") {
			return true
		}
	}
	return false
}
