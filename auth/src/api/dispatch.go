package api

import (
	"net/http"
	"strings"
)

// --- Dispatch (upstream `src/api/dispatch.ts`) ---
//
// Go port distributes the pipeline across the Huma stack (route catalog,
// header merge, hook runners, Router capture); see routes/ and index.go.
//
// The helpers below are pure parity mirrors. They are not wired into
// `Router` (which keeps its existing behavior byte-for-byte); they exist so
// the upstream file boundary has a Go counterpart in this package.

// GetOperationID resolves the operation id used for spans and hook
// attribution, mirroring upstream `getOperationId`
// (upstream dispatch.ts): an explicit id wins, then the
// OpenAPI one, then the caller's fallback (the `auth.api.*` map key), then
// the route path, defaulting to "/:virtual".
func GetOperationID(explicit, openAPIOperationID, fallback, path string) string {
	if explicit != "" {
		return explicit
	}
	if openAPOOperationID := openAPIOperationID; openAPOOperationID != "" {
		return openAPOOperationID
	}
	if fallback != "" {
		return fallback
	}
	if path != "" {
		return path
	}
	return "/:virtual"
}

// MergeResponseHeaders merges src response headers onto dst with upstream
// `mergeResponseHeaders` semantics
// (upstream dispatch.ts): `set-cookie` appends (multiple
// cookies are legal) while every other header replaces. A nil dst is
// allocated; a nil/empty src is a no-op. It returns dst for chaining.
//
// This is the map form of the context merge done by
// `applyTSResponseHeaders` (Huma context) and `capturedContext.Flush`
// (captured wire headers); all three treat only Set-Cookie as accumulative.
func MergeResponseHeaders(dst, src http.Header) http.Header {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(http.Header, len(src))
	}
	for name, values := range src {
		if isSetCookieHeader(name) {
			for _, value := range values {
				dst.Add(name, value)
			}
			continue
		}
		dst.Del(name)
		for _, value := range values {
			dst.Add(name, value)
		}
	}
	return dst
}

// GetHookSourceLabel normalizes a hook attribution label for span/logging
// use, mirroring the `user` / `plugin:<id>` / `unknown` source tags upstream
// tracks in `hooksSourceWeakMap` (upstream dispatch.ts).
// Empty plugin ids fall back to "unknown"; a bare "plugin:" prefix without
// an id is kept as-is so misconfigurations stay visible.
func GetHookSourceLabel(source string) string {
	trimmed := strings.TrimSpace(source)
	if trimmed == "" {
		return "unknown"
	}
	return trimmed
}
