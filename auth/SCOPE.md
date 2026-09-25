# Auth v1 scope (core-only)

Pinned upstream: Better Auth **v1.7.5** at
`vendor/better-auth` commit `5468e6bfcdff799848537cf5ad06ebab15aad9dd`.

v1 covers **email/password + session** only. No plugins, no providers.

## In scope

Go (`auth/src/`):

- `index.go`, `init_patches.go`, `secrets.go`, `telemetry.go`, `instrumentation.go`
- `schema.go`, `hooked_adapter.go`, `db/`, `adapters/bun/`, `cmd/generate-schema/`
- `api/`, `api/routes/` (23 routes below), `api/middlewares/`, `api/rate-limiter/`, `api/state/`
- `cookies/`, `crypto/`, `context/`, `types/`, `utils/`, `testutil/`

Routes (23, basePath-relative):

`/sign-up/email`, `/sign-in/email`, `/sign-out`, `/ok`, `/error`,
`/get-session`, `/list-sessions`, `/revoke-session`,
`/request-password-reset`, `/reset-password`, `/reset-password/{token}`,
`/change-password`, `/send-verification-email`, `/verify-email`,
`/list-accounts`, `/update-user`, `/change-email`, `/delete-user`,
`/delete-user/callback`, `/verify-password`, `/revoke-sessions`,
`/revoke-other-sessions`, `/update-session`

Upstream tests tracked (13 files, 495 cases — see `parity_ledger.json`):

- `packages/better-auth/src/api/routes/` (10 files: account,
  cookie-cache-fallback, email-verification, error, password, session-api,
  sign-in, sign-out, sign-up, update-user)
- `packages/better-auth/src/cookies/cookies.test.ts`
- `packages/better-auth/src/crypto/password.test.ts`
- `packages/better-auth/src/crypto/secret-rotation.test.ts`

## Out of scope for v1 (not "missing", explicitly excluded)
- All `src/plugins/*` (admin, organization, jwt, anonymous, email-otp,
  phone-number, two-factor, magic-link, bearer, multi-session, etc. — 27 total)
- `packages/oauth-provider/src/*` (protocol, DCR, device-code, extensions)
- `social-providers/*` + `oauth2/*` social flows: `/sign-in/social`,
  `/callback/{provider}`, `/link-social`, `/unlink-account`, `/account-info`,
  `/get-access-token`, `/refresh-token`, and all 36 social providers
- 17 OAuth helper paths (`/oauth2/*`, `/admin/oauth2/*`)
- Framework/client integrations (`src/client/`, adapters beyond Bun/SQLite/PG)

These remain absent by decision. A v1 consumer needing them should use
upstream Better Auth (TS) directly.

## Maintenance rules

1. `parity_ledger.json` + `src/parity_ledger_test.go` (`TestParityLedger_*`)
   are the drift gate. Pin, 23-route catalog, and 13-file manifest must not
   drift silently.
2. Upstream upgrade = update submodule pin, run
   `GOWORK=off go build ./... && go vet ./... && go test -count=1 ./...`,
   review diffs on the ~10 core TS route files only.
3. Parity v2 removed the archived reference docs (`TRANSPILER_PLAN.md`,
   `TRANSPILER_CANDIDATES.md`, `plan.md` Waves 5–10) and the `transpiler/`
   generator itself. `src/utils/*.gen.go` are checked-in frozen artifacts.
4. `PARITY_V2.md` is the authoritative parity audit (old `PARITY.md`
   removed in v2). Its plugin/oauth-provider/social legs are excluded by
   this file; they describe code that does not exist in this tree.

## File map (TS → Go, 1:1 at package level)

Upstream module → Go counterpart. Splits are documented, never phantom:

- `api/routes/account.ts` → `src/api/routes/account.go` (list-accounts)
- `api/routes/update-user.ts` → `src/api/routes/account.go` (UpdateUser,
  ChangeEmail, DeleteUser) + `delete-user-callback.go` (DeleteUserCallback)
- `api/routes/callback.ts` → `src/api/routes/callback.go` (v1-excluded stub;
  social `CallbackOAuth` never registered)
- `api/routes/email-verification.ts` → `email-verification.go`
- `api/routes/error.ts` → `error.go`
- `api/routes/ok.ts` → `ok.go`
- `api/routes/password.ts` → `password.go` + `password-extra.go`
  (VerifyPassword, reset-password callback)
- `api/routes/session.ts` → `session.go` + `session-extra.go`
  (revoke variants, UpdateSession) + `session-c701.go` (cookie-cache issuance)
- `api/routes/update-session.ts` → `session-extra.go` (UpdateSession)
- `api/routes/sign-in.ts` (email leg) → `sign-in.go` (social leg excluded)
- `api/routes/sign-out.ts` → `sign-out.go`
- `api/routes/sign-up.ts` → `sign-up.go`
- `api/routes/index.ts` → `index.go` (catalog doc only)
- `cookies/*` → `src/cookies/*`, `crypto/*` → `src/crypto/*`,
  `db/*` → `src/db/*` + `adapters/bun/*`, `context/*` → `src/context/*`

Go-only (no TS counterpart, kept): `generate-id.go`, `schema-fields.go`,
`hooks.go`, `api/dispatch.go`, `api/to-auth-endpoints.go`.
Merges of the `*-extra.go` / `session-c701.go` splits into single-file TS
owners are deferred as high-churn, behavior-neutral (see `index.go`).

## Explicit v1 exclusions within core files

- `setPassword` has no HTTP route upstream (`createAuthEndpoint.serverOnly`);
  Go exposes server-only `routes.SetPassword` instead (tested).
- `sendOnSignUp: false` + `requireEmailVerification` still sends: needs
  `SendOnSignUp *bool` tri-state; `types` is frozen for v1, recorded here
  instead of implemented.
- Huma schema-validation failures are 422 vs upstream 400 (framework-wide
  convention, not per-route drift).
- Chunked multi-cookie writes: read path only (safe degradation).

- Session `ipAddress`/`userAgent` are directly resolved (XFF leftmost →
  X-Real-IP → RemoteAddr host → `""`; UA verbatim → `""`). Full upstream
  `getIP` proxy-chain semantics are intentionally not replicated; session
  issuance stores the directly resolved address.

- Get-session null-shape: upstream answers 200 `null` for missing/expired
  sessions; Go answers 401/400 fail-closed (pinned). G1/G3/G5 recorded as
  intentional deviations, not gaps.
- Explicit `updateAge: 0` (always-refresh) is not distinguished from unset
  (needs `*int` tri-state; `types` frozen) — open post-v1 gap.
- Unknown-only update-session bodies pass through (union semantics, pinned)
  instead of upstream 400 — accepted divergence.
