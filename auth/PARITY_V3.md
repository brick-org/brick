# Auth parity v3 (core-only, v1-release gate)

Pinned upstream: Better Auth **v1.7.5** at `vendor/better-auth` commit `5468e6bfcdff799848537cf5ad06ebab15aad9dd`.
Scope: `SCOPE.md` (email/password + session; no plugins/providers/social/oauth).
Method: 20 read-only review parts (V3-01..V3-20), TS vs Go at pin with file:line refs.
Fix round F1-F11 (this section): 11 fixers merged, one commit each; ledger 218 -> 226.
Follow-ups: F10 call-site swap, B8 file-structure alignment, crypto/utils naming —
all merged, full hermetic gate 13/13 green.
V2 (`PARITY_V2.md`) untouched; this file is the v1-release audit.

## Stats (post-fix)

| Part  | Area                  | Verdict                                              |
| ----- | --------------------- | ---------------------------------------------------- |
| V3-01 | sign-up               | PORTED, minors CLOSED (F7a)                          |
| V3-02 | sign-in email         | MATCH + intentional Location hardening               |
| V3-03 | sign-out              | MATCH core CLOSED (F6); provider flow excluded       |
| V3-04 | ok + error            | PASS (OpenAPI + merge-branch notes only)             |
| V3-05 | session-core          | PASS, deltas CLOSED (F5)                             |
| V3-06 | update-session        | MATCH, shape CLOSED (F4 flat extras)                 |
| V3-07 | password              | PASS (2 minors noted)                                |
| V3-08 | update-user           | PASS, shape CLOSED (F1)                              |
| V3-09 | account + callback    | PASS                                                 |
| V3-10 | email-verification    | MATCH, deltas CLOSED (F2)                            |
| V3-11 | routes-infra          | PASS 23/23                                           |
| V3-12 | middleware/rate/state | MATCH core, G9 CLOSED (F7a/b)                        |
| V3-13 | cookies               | PASS, interop CLOSED (F5)                            |
| V3-14 | crypto                | MATCH, header CLOSED (F3)                            |
| V3-15 | db                    | helpers + swap CLOSED (F10)                          |
| V3-16 | types                 | PASS (0 missing fields, 49/49 codes)                 |
| V3-17 | utils                 | helpers CLOSED (F11)                                 |
| V3-18 | init + context        | PASS, defaults CLOSED (F8)                           |
| V3-19 | schema + adapters     | PASS (live-DB scope only)                            |
| V3-20 | structure + catalog   | PASS pin, 23 gates, 0 plugin routes; B8 CLOSED       |

Done: 23/23 endpoints registered, 0 plugin/social/oauth routes, 49/49 error codes,
all option fields present, all tri-states preserved, literal-null session shape,
flat update-session extras, 403 trust gates, stateless defu defaults, compact
interop both directions, exact JWE headers, atomic consume via adapter race gate.
File structure mirrors upstream core 1:1 at file level (see §Structure);
single remaining deviation is the rate-limiter package split (measured below).

## Gaps (all 18 closed)

1. **Change-password non-revoke** — CLOSED (F1): `{status, token:null, user}`.
2. **Fresh plain verify user** — CLOSED (F2): `{status:true,user:null}` + 7 pin realigns.
3. **Compact cookie interop** — CLOSED (F5): verify-first read, compact write, legacy fallback.
4. **Update-session extras nesting** — CLOSED (F4): flat top-level via `flatSession`.
5. **Get-session null literal** — CLOSED (F5): body `null`, + 7 pin realigns.
6. **User-row-missing** — CLOSED (F5): 200 null, not 404.
7. **Revoke-other** — CLOSED (F4): live-only, no cookie writes.
8. **Sign-out body** — CLOSED core (F6): body parsed, requireHeaders 401;
   OIDC provider flow stays excluded as social.
9. **G9 skip-vs-reject** — CLOSED (F7a/b): 403 trust gates + F2-leg realign.
10. **Stateless defaults** — CLOSED (F8): defu cache + account-cookie + baseURL warn.
11. **Cookies-JWE typ/cty** — CLOSED (F3): exactly `{alg,enc,kid}`.
12. **updateTo rotation** — CLOSED (F2): pre-update token reuse + email swap.
13. **Fan-out sync-500** — CLOSED (F2): post-commit log-only.
14. **DB gaps** — CLOSED (F10): reserveVerification, typed duplicate-key,
    `ConsumeOneWithFallback` helper + route call-site swap (password,
    delete-token). Verification cleanup deletes stay plain (no race gate
    needed, by design).
15. **Utils gaps** — CLOSED (F11): `GetDate`, `TimeString` ms/sec, `IsAPIError`;
    keccak/safeClone documented excluded.
16. **Sign-up minors** — CLOSED (F7a): disabled code, synthetic scope,
    mint-before-send. 422-vs-400 stays per framework convention.
17. **Session minors** — CLOSED (F5): `dont_remember` expired on expiry.
18. **Docs/naming** — CLOSED (B8): merges, update-user.go split,
    symmetric→index, kebab names (incl. plain `boolean.go` etc.), catalog +
    crypto map comments fixed.

## Structure (TS → Go, post-B8)

- 1:1 exact: `ok`, `error`, `sign-in` (email), `sign-out`, `sign-up`,
  `email-verification`, `callback` (exclusion stub), `routes/index`,
  all 5 `cookies/*`, `middlewares/*`, `state/should-session-refresh`,
  `crypto/index` (impl), `crypto/buffer|jwt|password|random`.
- Merged 1:1 (B8, same package): `update-user.ts` → `update-user.go` +
  `delete-user-callback.go` (+ `account.go` ListUserAccounts);
  `password.ts` → `password.go`; `session.ts` + `update-session.ts` →
  `session.go`; `db/*` remainder → root `schema.go`/`hooked_adapter.go`/
  `adapters/bun`; `context/*` → root `index.go`/`secrets.go`/
  telemetry/instrumentation.
- Renamed to TS kebab-case: `types/email-password.go`,
  `types/trusted-origins.go`, `utils/boolean.go`, `utils/constants.go`,
  `utils/hide-metadata.go` (frozen content untouched, do not hand-edit).
- Go-only (keep): `generate-id.go`, `schema-fields.go`, `hooks.go`,
  crypto `email-verification/jwe/pkce/token`, types `oauth/dpop`,
  `api/dispatch.go`, `api/to-auth-endpoints.go`.
- Excluded by decision (no counterpart): `api/state/oauth.ts`, plugins,
  social-providers, oauth2, client, adapters beyond Bun, integrations,
  `state.ts` (social-only).
- Single deviation: `api/rate-limiter/index.ts` → parent `rate-limiter.go` +
  stub. Go forbids two packages per directory; the limiter shares 4 helpers
  bidirectionally with the parent and ~15 unexported symbols are used across
  8 test files — mirroring needs a ~20-symbol export + test-move batch.
  Revisit only with a dedicated API-review batch.

## Endpoint catalog (23 gates, 25 registrations — V3-11)

POST `/sign-up/email`, POST `/sign-in/email`, POST `/sign-out`, GET `/ok`,
GET `/error`, GET+POST `/get-session`, GET `/list-sessions`,
POST `/revoke-session`, POST `/send-verification-email`, GET+POST(alias)
`/verify-email`, POST `/request-password-reset`, POST `/reset-password`,
GET `/reset-password/{token}`, POST `/change-password`, GET `/list-accounts`,
POST `/update-user`, POST `/change-email`, POST `/delete-user`,
GET `/delete-user/callback`, POST `/verify-password`, POST `/revoke-sessions`,
POST `/revoke-other-sessions`, POST `/update-session`.
Zero plugin/social/oauth registrations. `setPassword` server-only (no route).
Extra method: POST `/verify-email` (Go alias, no upstream counterpart).

## Exclusions reaffirmed (not gaps)

All `src/plugins/*` (27), `oauth-provider`, `social-providers` + `oauth2`
flows, 17 OAuth helper paths, client/framework integrations, adapters beyond
Bun/SQLite/PG, custom JWKS signer, `integrations/*`, `test-utils/*` harness.

## Fix round results (all merged, gate green)

- F1 gap 1 CLOSED (non-revoke user). F2 gaps 2/12/13 CLOSED (fresh-null +
  7 pin realigns, updateTo reuse, fan-out log-only). F3 gap 11 CLOSED
  (JWE header exact). F4 gaps 4/7 CLOSED (flat extras, live-only revoke).
  F5 gaps 3/5/6 CLOSED (literal null, compact interop, user-missing) +
  7 pin realigns + dont_remember expiry. F6 gap 8 core CLOSED (body +
  requireHeaders; provider flow stays excluded) + 2 root-test realigns.
  F7a/b gap 9 CLOSED (403 trust, F2-leg realign) + sign-up minors
  (disabled code, synthetic scope, mint-before-send). F8 gap 10 CLOSED
  (stateless defu + baseURL warn). F10 gap 14 CLOSED (reserve, typed
  duplicate, consume fallback helper + route call-site swap). F11 gap
  15 CLOSED (GetDate, TimeString, IsAPIError; keccak/clone excluded).
- B8 file-structure CLOSED: merges, update-user.go split (incl.
  ChangePassword), kebab-case files (incl. plain `boolean.go` etc.),
  crypto impl into index.go, catalog + SCOPE maps updated.
- Ledger 218 -> 226. Full hermetic gate 13/13 green.
- Blast-radius catches fixed along the way: F6 sign-out cookie tests,
  F2 root verify pins, B14-era 200-null object pins → literal null.

## Proposed fix batches (v1 release — all complete)

- B1 (shapes): gaps 1, 2, 4, 5 — CLOSED.
- B2 (cookies/crypto bytes): gaps 3, 11 — CLOSED.
- B3 (session semantics): gaps 6, 7 + revoke minors — CLOSED.
- B4 (trust): gap 9 (G9 adoption) + sign-out body (gap 8 core part) — CLOSED.
- B5 (init defaults): gap 10 — CLOSED.
- B6 (verify ordering): gaps 12, 13 — CLOSED.
- B7 (db/utils tail): gaps 14, 15 + sign-up minors — CLOSED.
- B8 (docs/renames/structure): gap 18 — CLOSED except the single
  rate-limiter deviation above.
