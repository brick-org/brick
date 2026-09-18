package api

import (
	"net/http"
	"strings"
)

// --- Dispatch (upstream `src/api/dispatch.ts`) ---
//
// Upstream `dispatch.ts` is the canonical single-endpoint hook runner:
// `getOperationId`, `mergeResponseHeaders`/`mergeAPIErrorHeaders`,
// `runBeforeHooks`/`runAfterHooks`, `getHooks`, and `dispatchAuthEndpoint`.
// The Go port distributes that pipeline across the Huma stack:
//
//   - `getOperationId` (explicit `operationId` ?? OpenAPI `operationId` ??
//     map key ?? path): every Go route registration carries a static
//     `OperationID` (see the route catalog in `routes/index.go`), and the
//     middleware pipeline propagates the matched identity via
//     `routes.EndpointMetadata` (`WithEndpointMetadata` /
//     `EndpointMetadataFromStd`). Use GetOperationID below for the same
//     precedence when deriving an ID from parts.
//   - `mergeResponseHeaders` (set-cookie appends, everything else replaces):
//     `applyTSResponseHeaders` (below) and `capturedContext.Flush` enforce
//     the same semantics when hook mutations reach the wire. Use
//     MergeResponseHeaders below for the same merge onto a plain header map.
//   - `runBeforeHooks`/`runAfterHooks` + `getHooks` (user hooks first, then
//     plugin hooks in declaration order; before-hook errors abort, after-hook
//     errors report): `routes.RunTSRouteBeforeHooks` /
//     `routes.RunTSRouteAfterHooks` (`auth/src/api/routes/hooks.go`) plus the
//     lifecycle middleware in `Router` (user global hooks, legacy route
//     hooks, then TypeScript-faithful hooks).
//   - `dispatchAuthEndpoint` (normalize response/headers/APIError the same
//     way for router and `auth.api.*` callers): the `Router` capture pipeline
//     (`capturedContext`, `callAPIErrorHandler`, `writeHookError`) plus
//     `routes.registerAuthOperation`'s per-route error tap. There is no
//     `auth.api.*` direct-dispatch entry point in Go; Huma owns dispatch.
//
// The helpers below are pure parity mirrors. They are not wired into
// `Router` (which keeps its existing behavior byte-for-byte); they exist so
// the upstream file boundary has a Go counterpart in this package.

// GetOperationID resolves the operation id used for spans and hook
// attribution, mirroring upstream `getOperationId`
// (vendor/.../src/api/dispatch.ts:66-80): an explicit id wins, then the
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
// (vendor/.../src/api/dispatch.ts:86-100): `set-cookie` appends (multiple
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
// tracks in `hooksSourceWeakMap` (vendor/.../src/api/dispatch.ts:56-59).
// Empty plugin ids fall back to "unknown"; a bare "plugin:" prefix without
// an id is kept as-is so misconfigurations stay visible.
func GetHookSourceLabel(source string) string {
	trimmed := strings.TrimSpace(source)
	if trimmed == "" {
		return "unknown"
	}
	return trimmed
}
