// Package middlewares is the Go source-layout counterpart of the upstream
// TypeScript module `src/api/middlewares/index.ts` (pinned v1.7.5,
// commit 5468e6bfcdff799848537cf5ad06ebab15aad9dd).
//
// Upstream `middlewares/index.ts` re-exports the authorization helpers and
// the origin/CSRF checks:
//
//	export { requireOrgRole, requireResourceOwnership } from "./authorization";
//	export { formCsrfMiddleware, originCheck, originCheckMiddleware } from "./origin-check";
//
// The Go counterparts live in this package with the same split:
//
//   - `authorization.go`: RequireResourceOwnership / RequireOrgRole,
//     mirroring `requireResourceOwnership` / `requireOrgRole`.
//   - `origin-check.go`: IsMutatingMethod / OriginOrReferer /
//     ResolveOriginCandidate / NeedsOriginValidation / HasFetchMetadata /
//     IsCrossSiteNavigation / RequiresForceOriginValidation plus the
//     skip-gate documentation, mirroring the `validateOrigin` /
//     `validateFormCsrf` / `shouldSkipOriginCheck` /
//     `shouldSkipCSRFForBackwardCompat` gates.
//
// Enforcement wiring stays in the `api` package's `Router`
// (`auth/src/api/index.go`), which installs the origin-check middleware
// inline (global origin check plus the formCsrf force gate narrowed to the
// two login legs per upstream per-endpoint use) and resolves trust via
// `originTrustedForRequest` over
// `types.IsTrustedOrigin` plus the dynamic-baseURL expansion; route handlers
// validate redirect/callback URLs via `types.IsTrustedRedirect`. This package
// intentionally imports only `context`, the standard library, and `types`
// (never `api` or `api/routes`) so the enforcement layer can consume it
// without an import cycle.
package middlewares
