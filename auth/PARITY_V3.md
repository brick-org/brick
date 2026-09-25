# Auth parity v3 (core-only, v1-release gate)

Pinned upstream: Better Auth **v1.7.5** at `vendor/better-auth` commit `5468e6bfcdff799848537cf5ad06ebab15aad9dd`.
Scope: `SCOPE.md` (email/password + session; no plugins/providers/social/oauth).
Method: 20 read-only review parts (V3-01..V3-20), TS vs Go at pin with file:line refs.
V2 (`PARITY_V2.md`) untouched; this file is the v1-release audit.

## Stats

| Part  | Area                  | Verdict                                                    |
| ----- | --------------------- | ---------------------------------------------------------- |
| V3-01 | sign-up               | PORTED + 7 minor gaps                                      |
| V3-02 | sign-in email         | MATCH + 1 hardening deviation                              |
| V3-03 | sign-out              | MATCH core / 2 major gaps (provider flow, body)            |
| V3-04 | ok + error            | PASS + 2 partials (OpenAPI, merge default-branch)          |
| V3-05 | session-core          | PASS + 3 deltas (null shape, user-missing, revoke-other)   |
| V3-06 | update-session        | MATCH + 1 shape GAP (nested vs flat extras)                |
| V3-07 | password              | PASS + 2 minors                                            |
| V3-08 | update-user           | PASS except 1 FAIL (change-pw non-revoke user)             |
| V3-09 | account + callback    | PASS + 1 nit                                               |
| V3-10 | email-verification    | MATCH + 1 FAIL (fresh-verify user vs null) + ordering gaps |
| V3-11 | routes-infra          | PASS 23/23                                                 |
| V3-12 | middleware/rate/state | MATCH core + G9 gap + oauth-state missing                  |
| V3-13 | cookies               | PASS except 1 FAIL (compact interop)                       |
| V3-14 | crypto                | MATCH except cookies-JWE typ/cty                           |
| V3-15 | db                    | PARTIAL (no InternalAdapter type; several gaps)            |
| V3-16 | types                 | PASS (0 missing fields, 49/49 codes)                       |
| V3-17 | utils                 | 6 ported / 3 partial / 4 missing                           |
| V3-18 | init + context        | PASS + 2 gaps (stateless defu, strategy default)           |
| V3-19 | schema + adapters     | PASS (live-DB gaps only)                                   |
| V3-20 | structure + catalog   | PASS pin, 23 gates, 0 plugin routes                        |

Done: 23/23 endpoints registered, 0 plugin/social/oauth routes, 49/49 error codes,
all option fields present, all tri-states preserved, cookie/crypto codecs match
except noted bytes, session refresh math matches, secondary fan-out matches.
File structure: cookies 1:1 exact; routes/types/context consolidated with
documented splits (see §Structure).

## Gaps for v1 release (ranked, load-bearing first)

1. **Change-password non-revoke omits user** (V3-08 §8): Go `{status:true}` vs
   upstream `{token:null,user}`. Breaks clients reading `data.user`.
2. **Fresh plain verify returns user** (V3-10 §3): Go returns updated user vs
   upstream `{status:true,user:null}` on fresh plain leg.
3. **Compact cookie interop** (V3-13 §12): live path uses legacy codec;
   upstream compact values always miss and vice versa (JWT/JWE interop OK).
4. **Update-session extras nesting** (V3-06 §13): Go nests under
   `additionalFields` vs upstream flat top-level (`session.theme` absent).
5. **Get-session null literal** (V3-05): Go `{"session":null,"user":null}` vs
   upstream literal `null`. Status 200 matches.
6. **User-row-missing 404 vs null** (V3-05): Go 404 `USER_NOT_FOUND` vs 200 null.
7. **Revoke-other over-revocation + cookies** (V3-05): Go revokes expired rows
   too and emits refresh cookies; upstream live-only, no cookies.
8. **Sign-out body + provider logout** (V3-03): Go drops
   `{callbackURL,disableRedirect,state}`, no OIDC RP-initiated flow, no
   `Location`/redirect contract. Core delete+clear matches.
9. **G9 skip-vs-reject** (V3-12 §3): sign-in/up embed unchecked `callbackURL`;
   reset-callback redirects vs 403; `errorCallbackURL`/`newUserCallbackURL`
   unvalidated. Fail-closed but not 403-parity.
10. **Stateless defaults missing** (V3-18 §2+§6): no auto
    `cookieCache{enabled,strategy:jwe,maxAge,refreshCache}` /
    `storeAccountCookie`; Go default strategy `compact` vs upstream `jwe`.
11. **Cookies-JWE typ/cty** (V3-14 §4): `cookies.CreateSessionCacheJWE` adds
    `typ/cty:JWT`; upstream bare `{alg,enc,kid}`. Decrypt-tolerant, bytes differ.
12. **updateTo session rotation vs reuse** (V3-10 §5c): Go mints new row (email
    compare vs new) vs upstream reuse pre-update token + email swap.
13. **Fan-out sync-500 vs post-commit-log** (V3-10 §4): Go fails route on
    secondary refresh; upstream post-commit log-only.
14. **DB gaps** (V3-15): no `reserveVerificationValue`/consume-lock/batch
    finders/`createOAuthUser`/`validateUserInfo` gate; no live introspection;
    no constraint-violation mapping; join fallback only.
15. **Utils missing** (V3-17): `getDate`, keccak `toChecksumAddress`,
    `TimeString` ms/sec, `safeCloneRequest` (by design), `IsAPIError`
    predicate, base-URL env cascade.
16. Sign-up minors (V3-01 G1-G7): 422-vs-400 validation, disabled-code string,
    gate ordering, synthetic-field scope, mint-skip, BasePath vs baseURL,
    rollback window.
17. Session minors: `dont_remember` not expired on get-session expiry;
    stateless DB-nil revoke 401s (V3-05).
18. Docs/naming (V3-20 §4, V3-11 §8, V3-14 §7): kebab-case renames,
    rate-limiter fold, `*-extra.go`/`session-c701.go` merges,
    `update-user.go` split, symmetric/index swap, stale catalog comment,
    crypto index file-map comment.

## Structure (TS → Go, from V3-20)

- 1:1 exact: `ok`, `error`, `sign-in` (email), `sign-out`, `sign-up`,
  `email-verification`, `callback` (exclusion stub), `routes/index`,
  all 5 `cookies/*`, `types/*` (7), `middlewares/*`, `state/should-session-refresh`.
- Documented splits (keep, behavior-neutral): `update-user.ts` →
  `account.go`+`delete-user-callback.go`+`password.go`(ChangePassword);
  `password.ts` → `password.go`+`password-extra.go`; `session.ts` →
  `session.go`+`session-extra.go`+`session-c701.go`; `update-session.ts` →
  `session-extra.go`; `rate-limiter/index.ts` → parent `rate-limiter.go`+stub;
  `db/*` remainder → root `schema.go`/`hooked_adapter.go`/`adapters/bun`;
  `context/*` → root `index.go`/`secrets.go`/telemetry/instrumentation.
- Go-only (keep): `generate-id.go`, `schema-fields.go`, `hooks.go`,
  crypto `email-verification/jwe/pkce/token`, types
  `email_password/oauth/trusted_origins/dpop`.
- Excluded by decision (no counterpart): `api/state/oauth.ts`, plugins,
  social-providers, oauth2, client, adapters beyond Bun, integrations,
  `state.ts` (social-only).

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

## Proposed fix batches (v1 release)

- B1 (shapes): gaps 1, 2, 4, 5 — response-shape alignment, one batch.
- B2 (cookies/crypto bytes): gaps 3, 11 — compact wiring + drop typ/cty.
- B3 (session semantics): gaps 6, 7 + revoke minors.
- B4 (trust): gap 9 (G9 adoption) + sign-out body (gap 8 core part).
- B5 (init defaults): gap 10 — stateless defu + strategy default.
- B6 (verify ordering): gaps 12, 13.
- B7 (db/utils tail): gaps 14, 15 + sign-up minors.
- B8 (docs/renames): gap 18 — behavior-neutral moves last.
