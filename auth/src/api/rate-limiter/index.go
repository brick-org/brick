// Package ratelimiter is the Go source-layout counterpart of the upstream
// TypeScript module `src/api/rate-limiter/index.ts` (pinned v1.7.5,
// commit 5468e6bfcdff799848537cf5ad06ebab15aad9dd).
//
// The rate-limit enforcement implementation lives in the parent `api`
// package (`auth/src/api/rate-limiter.go`, package `api`) together with the
// storage-backend selection in `auth/src/api/index.go`
// (`selectRateLimitBackend`, `rateLimitNeedsCustomMiddleware`,
// `useRateLimitMiddlewareWithStorage`). A physical `git mv` of the parent
// file into this directory would require a new package plus re-export shims
// in the old location, and the limiter is tightly coupled to parent-package
// helpers in both directions:
//
//   - parent `index.go` consumes `resolveRateLimit`,
//     `resolvePluginRateLimit`, `ConsumeResolvedRateLimit`,
//     `useRateLimitMiddleware`, `applyRateLimitRules` from `rate-limiter.go`;
//   - `rate-limiter.go` consumes `RequestClientIP`, `requestIP`,
//     `middlewareRateLimitPath`, `normalizeRateLimitPath`, `apiLogf`,
//     `selectRateLimitBackend` from `index.go`.
//
// Splitting those into a child package would cycle
// (`api` -> `ratelimiter` -> `api`). Per the layout task's minimal-churn
// rule, the implementation therefore stays in the parent package and this
// package provides the upstream-shaped boundary with dependency-free parity
// symbols. It must stay dependency-free (no import of the parent `api`
// package) so a future parent -> child import can never cycle.
//
// Upstream parity map
// (`vendor/better-auth/packages/better-auth/src/api/rate-limiter/index.ts`):
//
//   - `NO_TRUSTED_IP_KEY` -> NoTrustedIPKey (shared per-path bucket sentinel
//     used when no trusted client IP can be derived; parent spells it
//     `noTrustedIPKey`).
//   - `MEMORY_STORE_MAX_ENTRIES` -> MemoryStoreMaxEntries (hard ceiling on
//     the process-wide in-memory fallback store; parent spells it
//     `memoryStoreMaxEntries`).
//   - `getDefaultSpecialRules`, `resolveRateLimitConfig`, `onRequestRateLimit`,
//     `getRateLimitStorage`, `createDatabaseStorageWrapper` ->
//     `defaultSpecialRateLimitRules`, `resolveRateLimit` (+ proxy-aware
//     `resolveRateLimitWithProxies`), `useRateLimitMiddleware` /
//     `useRateLimitMiddlewareWithStorage`, `selectRateLimitBackend`,
//     `DatabaseRateLimitStorage` in the parent package.
//   - `rateLimitResponse` (`{"message": ...}` + `X-Retry-After`) ->
//     `writeRateLimitResponse` in the parent package (kept intentionally
//     distinct from the huma `{status,title,detail}` error shape).
package ratelimiter

// NoTrustedIPKey is the sentinel IP segment for the shared rate-limit bucket
// used when no trusted client IP can be derived. It is not a valid IP, so it
// never collides with a real client IP key.
//
// Upstream TypeScript name: NO_TRUSTED_IP_KEY
// (vendor/.../src/api/rate-limiter/index.ts:335). The parent `api` package
// carries the same value as the unexported `noTrustedIPKey`; this export
// exists for layout parity and for external backend implementations that key
// buckets the same way.
const NoTrustedIPKey = "no-trusted-ip"

// MemoryStoreMaxEntries caps the process-wide in-memory rate-limit store so
// a flood of distinct keys (e.g. spoofed IPs) cannot grow it without bound.
//
// Upstream TypeScript name: MEMORY_STORE_MAX_ENTRIES
// (vendor/.../src/api/rate-limiter/index.ts:21). The parent `api` package
// enforces the same bound as the unexported `memoryStoreMaxEntries`; this
// export exists for layout parity.
const MemoryStoreMaxEntries = 100_000
