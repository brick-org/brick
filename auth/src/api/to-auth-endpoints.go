package api

// --- Endpoint conversion (upstream `src/api/to-auth-endpoints.ts`) ---
//
// Upstream `to-auth-endpoints.ts` wraps each raw endpoint so a router or
// `auth.api.*` call runs it through the configured hook pipeline. Its
// per-call work is:
//
//   - `resolveDynamicContext`: with a dynamic `baseURL`, resolve the
//     per-call `AuthContext` from the request source (or the configured
//     fallback), throwing when neither exists; static configurations reuse
//     the shared context as-is.
//   - `toAuthEndpoints`: copy `path`/`options` onto each wrapped endpoint,
//     initialize request state (`runWithRequestState`) unless one already
//     exists, await any pending schema check, resolve the dynamic context,
//     then enter `dispatchAuthEndpoint` with the resolved `operationId` and
//     the `asResponse` decision.
//
// The Go port distributes the same work across `Router` and the `routes`
// package (a physical extraction of `routes/hooks.go` into this package
// would cycle: `api` already imports `routes` for registration, so moved
// hook/context helpers would need `routes` -> `api` imports back):
//
//   - `resolveDynamicContext` -> `ResolveDynamicBaseURLForRequest` (below in
//     this package, used by the always-on request-context middleware and by
//     route URL builders via `routes.EffectiveFullBaseURL`). The dynamic
//     trusted-origin expansion it depends on is `ExpandDynamicBaseURLOrigins`
//     (mirroring `getTrustedOrigins`' dynamic branch); `types.IsTrustedOrigin`
//     covers the static leg.
//   - Request-state initialization (`runWithRequestState` /
//     `hasRequestState`) -> the always-on middleware in `Router` installing a
//     fresh store via `NewRequestState`/`WithRequestState` (shared by pointer
//     with `routes.WithRequestStateStore` so hooks and handlers see one
//     store), mirroring upstream's per-call `WeakMap`.
//   - The pending schema check (`ctx.checkSchema?.()`) ->
//     `opts.SchemaCheck` middleware in `Router`, failing closed with a 500
//     before rate limiting and request hooks.
//   - `path`/`options` copying and the hook pipeline entry ->
//     `dispatch.go` in this package (operation-id and header-merge mirrors)
//     plus `routes.RunTSRouteBeforeHooks`/`routes.RunTSRouteAfterHooks`
//     (`auth/src/api/routes/hooks.go`) driven by the `Router` lifecycle
//     middleware.
//   - Route registration and operation IDs are preserved exactly; see the
//     catalog in `auth/src/api/routes/index.go`. There is no `auth.api.*`
//     direct-dispatch entry point in Go; Huma owns dispatch.
//
// This file intentionally adds no new symbols: it is the upstream-shaped
// boundary documenting where each `to-auth-endpoints.ts` responsibility
// lives in Go. Go-only Huma plumbing (the `capturedContext` capture/flush
// layer, `requestOverrideContext`, trailing-slash variant registration)
// stays where it is in `index.go` and is documented there.
