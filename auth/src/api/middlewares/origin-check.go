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
// the origin-check middleware challenges mutating requests carrying browser
// evidence — an `Origin` (or `Referer` fallback, with `Origin: null` +
// `Sec-Fetch-Site: same-origin` inferring the request-target origin) AND a
// `Cookie` header — via `originTrustedForRequest` (static trust through
// `types.IsTrustedOrigin` plus the `ExpandDynamicBaseURLOrigins` dynamic
// leg), force-validates cookie-less requests that carry Fetch Metadata or an
// Origin/Referer header on the two login legs only (/sign-in/email +
// /sign-up/email per-endpoint formCsrfMiddleware; blocking cross-site
// navigations), honors
// `Advanced.DisableCSRFCheck` / `Advanced.DisableOriginCheck` with the same
// backward-compat warning plus plugin-contributed skip-path arrays; route
// handlers validate `callbackURL`/`redirectTo`/`errorCallbackURL`/
// `newUserCallbackURL` via `types.IsTrustedRedirect` (the per-endpoint
// `originCheck` equivalent). The pure gates below mirror the upstream
// predicates so middleware decisions and tests share one spelling. This file
// stays dependency-free (no `api`/`routes` imports) so `api` can consume it
// without a cycle.

// IsMutatingMethod reports whether method carries a state-changing semantic
// subject to origin validation, mirroring the upstream gate that skips
// `GET`, `OPTIONS`, and `HEAD` and validates everything else
// (vendor/.../src/api/middlewares/origin-check.ts:69-76). The set is
// intentionally open: TRACE, PROPFIND, PURGE, and custom verbs are all
// validated (TRACE safely fails closed like any other non-idempotent
// method). Names compare case-insensitively after trimming; an empty method
// (no request line to classify) counts as mutating so degenerate requests
// fail closed rather than bypass validation.
func IsMutatingMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodOptions, http.MethodHead:
		return false
	default:
		return true
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

// ResolveOriginCandidate computes the origin value to validate, mirroring
// upstream validateOrigin's origin selection
// (vendor/.../src/api/middlewares/origin-check.ts:229-269):
//
//   - the candidate starts as OriginOrReferer(origin, referer) (upstream
//     `headers.get("origin") || headers.get("referer") || ""`);
//   - a same-origin form using `no-referrer` can send `Origin: null`.
//     Upstream infers the origin from the request target via Fetch Metadata
//     (`sec-fetch-site === "same-origin"`); here the caller passes the
//     already-derived request-target origin parts (scheme without "://" and
//     the Host header, port included). When inference applies the candidate
//     becomes `scheme://host`; otherwise the raw candidate (including a bare
//     "null") is returned so the caller rejects it as missing/null.
//
// An empty scheme defaults to "http" (non-TLS request target). An empty host
// disables inference (returns the raw candidate).
func ResolveOriginCandidate(origin, referer, secFetchSite, scheme, host string) string {
	candidate := OriginOrReferer(origin, referer)
	if strings.TrimSpace(origin) != "null" {
		return candidate
	}
	if strings.TrimSpace(secFetchSite) != "same-origin" {
		return candidate
	}
	trimmedHost := strings.TrimSpace(host)
	if trimmedHost == "" {
		return candidate
	}
	trimmedScheme := strings.ToLower(strings.TrimSpace(scheme))
	if trimmedScheme != "http" && trimmedScheme != "https" {
		trimmedScheme = "http"
	}
	return trimmedScheme + "://" + trimmedHost
}

// HasFetchMetadata reports whether the request carries any Fetch Metadata
// header, mirroring upstream validateFormCsrf's hasMetadata gate
// (vendor/.../src/api/middlewares/origin-check.ts:341-343): a non-blank
// Sec-Fetch-Site, Sec-Fetch-Mode, or Sec-Fetch-Dest value.
func HasFetchMetadata(secFetchSite, secFetchMode, secFetchDest string) bool {
	return strings.TrimSpace(secFetchSite) != "" ||
		strings.TrimSpace(secFetchMode) != "" ||
		strings.TrimSpace(secFetchDest) != ""
}

// IsCrossSiteNavigation reports the classic CSRF attack pattern upstream
// blocks outright (vendor/.../src/api/middlewares/origin-check.ts:347):
// a cross-site navigation request.
func IsCrossSiteNavigation(secFetchSite, secFetchMode string) bool {
	return strings.TrimSpace(secFetchSite) == "cross-site" &&
		strings.TrimSpace(secFetchMode) == "navigate"
}

// RequiresForceOriginValidation reports whether a cookie-less mutating
// request must still have its origin validated (upstream validateFormCsrf's
// forceValidate legs, vendor/.../src/api/middlewares/origin-check.ts:345-373):
// Fetch Metadata present, or an Origin/Referer header present. Requests with
// neither (non-browser clients like curl or server-to-server) keep the
// permissive fallback.
func RequiresForceOriginValidation(origin, referer, secFetchSite, secFetchMode, secFetchDest string) bool {
	if HasFetchMetadata(secFetchSite, secFetchMode, secFetchDest) {
		return true
	}
	return strings.TrimSpace(OriginOrReferer(origin, referer)) != ""
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
