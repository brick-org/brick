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
3. `TRANSPILER_PLAN.md` / `TRANSPILER_CANDIDATES.md` / `plan.md` Waves 5–10
   are archived reference, not active work. The supported generator covers
   `src/utils/*.gen.go` only (`transpiler/README.md`).
4. `PARITY.md` plugin/oauth-provider/social `Done` tables are superseded by
   this file; they describe code that does not exist in this tree.
