# Auth parity v2 (core-only)

Pinned upstream: Better Auth **1.7.5** at
`vendor/better-auth` commit `5468e6bfcdff799848537cf5ad06ebab15aad9dd`.
Scope: `SCOPE.md` (core email/password + session; no plugins/providers/social).
Date: 2026-09-25. Supersedes the deleted `PARITY.md` (v1 audit).

Method: 12 read-only review parts (P01–P12 below), one upstream file at a
time, Go vs TS at the pinned commit with exact file:line refs on both sides.
Agents were read-only (no writes, no worktrees); sections were merged
centrally into this file. Verdicts per case: PORTED / DEVIATION (pinned,
intentional) / EXCLUDED (out of scope per `SCOPE.md`) / FEATURE-GAP
(in-scope but missing — the actionable list, consolidated in
`## Later-work backlog`).

Authoritative counts live in `parity_ledger.json` (ledger `AUTH-R5-01`):
13 upstream test files, 495 cases, 188 covered entries, pending 0.
Runtime: pending expectation: the v1 closure converted every pending marker
to an explicit exclusion; `pending.count` in the ledger is 0 and the drift
gate (`src/parity_ledger_test.go`, `TestParityLedger_*`) enforces it.

Core route catalog (23, basePath-relative — all registered, see P09):

`/sign-up/email`, `/sign-in/email`, `/sign-out`, `/ok`, `/error`,
`/get-session`, `/list-sessions`, `/revoke-session`,
`/request-password-reset`, `/reset-password`, `/reset-password/{token}`,
`/change-password`, `/send-verification-email`, `/verify-email`,
`/list-accounts`, `/update-user`, `/change-email`, `/delete-user`,
`/delete-user/callback`, `/verify-password`, `/revoke-sessions`,
`/revoke-other-sessions`, `/update-session`

## Parity ledger (AUTH-R5-01)

`parity_ledger.json` is authoritative for counts. Summary at v2 creation:

| Upstream test file                         | Cases | Covered |
| ------------------------------------------ | ----- | ------- |
| `api/routes/account.test.ts`               | 53    | 2       |
| `api/routes/cookie-cache-fallback.test.ts` | 11    | 2       |
| `api/routes/email-verification.test.ts`    | 29    | 16      |
| `api/routes/error.test.ts`                 | 3     | 2       |
| `api/routes/password.test.ts`              | 21    | 19      |
| `api/routes/session-api.test.ts`           | 85    | 30      |
| `api/routes/sign-in.test.ts`               | 30    | 6       |
| `api/routes/sign-out.test.ts`              | 10    | 2       |
| `api/routes/sign-up.test.ts`               | 40    | 18      |
| `api/routes/update-user.test.ts`           | 35    | 22      |
| `cookies/cookies.test.ts`                  | 118   | 42      |
| `crypto/password.test.ts`                  | 14    | 13      |
| `crypto/secret-rotation.test.ts`           | 46    | 14      |
| Total (13 files)                           | 495   | 188     |

Disposition everywhere is `partial`: list-accounts/social-link/token/
stateless legs, CSRF/origin/form-data legs, JWKS/JWE/plugin-authority legs
and concurrent-race legs are recorded exclusions/deviations in `SCOPE.md`,
not work. Intentional exclusions: all `src/plugins/*` (27 total),
`packages/oauth-provider/src/*`, `social-providers/*` + `oauth2/*` social
flows (`/sign-in/social`, `/callback/{provider}`, `/link-social`,
`/unlink-account`, `/account-info`, `/get-access-token`, `/refresh-token`),
17 OAuth helper paths (`/oauth2/*`, `/admin/oauth2/*`), framework/client
integrations. A v1 consumer needing them should use upstream Better Auth
(TS) directly.

## P01 sign-up

**File map**

| upstream                                                            | Go                                                                                                                                            | ledger                                                                                   |
| ------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `vendor/better-auth/packages/better-auth/src/api/routes/sign-up.ts` | `auth/src/api/routes/sign-up.go`                                                                                                              | `auth/parity_ledger.json` (`sign-up.test.ts`, 40 cases, `partial`, 18 `covered` claimed) |
| `vendor/.../src/api/routes/sign-up.test.ts`                         | `auth/src/api/routes/creds_v1_signup_test.go`, `creds_triage_v1_test.go`, `signup_generic_v1_test.go`, `ipua_v1_test.go`, `orphan_v1_test.go` | `goOwner: ["api/routes/sign_up.go"]` — stale underscore; real file is `sign-up.go`       |

All 18 ledger `goTest` names verified present (`TestCredsV1_SignUp*`, `TestTriageV1_SignUp*`, `TestGenericV1_AutoSignIn*`, `TestIPUA_SignUp*`, `TestOrphanV1_*`).

**Per-case verdicts (`TS symbol/case | verdict | Go ref | TS ref | note`)**

| TS case                                                                                                            | verdict              | Go ref                                                                  | TS ref                   | note                                                                                                                                                          |
| ------------------------------------------------------------------------------------------------------------------ | -------------------- | ----------------------------------------------------------------------- | ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `signUpEmail` route `POST /sign-up/email`, schema `name/email/password/image/callbackURL/rememberMe + record<any>` | PORTED               | `sign-up.go:139-146`, `18-35`, `41-123`                                 | `sign-up.ts:17-35,57-94` | `TransformSchema AdditionalProperties` mirrors `.and(record)`                                                                                                 |
| `formCsrfMiddleware` + `cloneRequest:true` + `allowedMediaTypes json+form`                                         | PORTED / FEATURE-GAP | `api/index.go:75`, `middlewares/origin-check.go:12`; `sign-up.go:41-89` | `sign-up.ts:34,36,38-41` | CSRF delegated to global origin-check; form-urlencoded has no Go parser (JSON-only `UnmarshalJSON`) — see GAP-1                                               |
| `runWithTransaction(adapter)` atomic user+account                                                                  | PORTED               | `sign-up.go:340-362`                                                    | `sign-up.ts:183`         | `DB.Transaction` with rollback; orphan cleanup after commit at `455-464`                                                                                      |
| disabled gate `!enabled \|\| disableSignUp` → `400 EMAIL_PASSWORD_SIGN_UP_DISABLED`                                | DEVIATION            | `sign-up.go:147-149`                                                    | `sign-up.ts:184-191`     | status 400 kept; specific `code` string not preserved (plain `Error400`)                                                                                      |
| `INVALID_EMAIL` format check → 400                                                                                 | DEVIATION            | `sign-up.go:20` (`format:email`)                                        | `sign-up.ts:209-213`     | Huma schema fail is 422 per `SCOPE.md` framework convention                                                                                                   |
| `INVALID_PASSWORD` missing/non-string → 400                                                                        | DEVIATION            | `sign-up.go:18-21,151`                                                  | `sign-up.ts:215-217`     | missing → Huma 422; empty → `PASSWORD_TOO_SHORT` 400; accepted divergence                                                                                     |
| `PASSWORD_TOO_SHORT/LONG` + `warn` log                                                                             | PORTED               | `sign-up.go:151-158,563-575`                                            | `sign-up.ts:219-235`     | verified `TestCredsV1_SignUpShortPasswordWarns`                                                                                                               |
| `shouldReturnGenericDuplicate=requireEmailVerification\|\|autoSignIn===false`; `shouldSkipAutoSignIn`              | PORTED               | `sign-up.go:163-164,577-579`                                            | `sign-up.ts:236-241`     | generic-duplicate covers `autoSignIn=false`; verified `TestGenericV1_AutoSignInFalse*`                                                                        |
| `parseUserInput(rest,"create")` + `additionalFields`/`input:false` gate before lookup                              | PORTED               | `sign-up.go:173-179,484-494`                                            | `sign-up.ts:242-246`     | verified `TestCredsV1_SignUpAdditionalFields`, `TestCredsV1_SignUpInputFalseRejected`                                                                         |
| `normalizedEmail=email.toLowerCase()` + case-insensitive dedupe                                                    | PORTED               | `sign-up.go:160,182-184`                                                | `sign-up.ts:247,307-308` | verified `TestCredsV1_SignUpDuplicateCaseInsensitive`                                                                                                         |
| `buildGenericDuplicateResponse` (`generateId`, `token:null`)                                                       | PORTED               | `sign-up.go:214-254,279-305,496-552`                                    | `sign-up.ts:253-305`     | image parity verified `TestCredsV1_SyntheticResponseParity`                                                                                                   |
| `customSyntheticUser` (core filter)                                                                                | PORTED / EXCLUDED    | `sign-up.go:233-245,284-296`                                            | `sign-up.ts:266-289`     | core hook ported; **admin-plugin** variant excluded per `SCOPE.md` (27 plugins)                                                                               |
| duplicate: timing hash + `onExistingUserSignUp` + generic return vs `422 USER_ALREADY_EXISTS`                      | PORTED               | `sign-up.go:189-256`                                                    | `sign-up.ts:309-332`     | request-aware precedence, hook-skip legs verified                                                                                                             |
| `validateUserInfo` 403 gate → generic-duplicate under protection                                                   | PORTED               | `sign-up.go:264-308`, `606-637`                                         | `sign-up.ts:362-368`     | code ported; ledger pins only the `Allows` leg; `rejects 403` / `hides gate` legs have code but no ledger `covered` entry                                     |
| `createUser` failure mapping                                                                                       | DEVIATION            | `sign-up.go:363-377`                                                    | `sign-up.ts:355-385`     | Go collapses to 422; `HttpError` passthrough preserves hook codes                                                                                             |
| `linkAccount{credential,accountId=userId,password:hash}`                                                           | PORTED               | `sign-up.go:346-358`                                                    | `sign-up.ts:386-391`     | inside same tx (stronger, same observable)                                                                                                                    |
| `sendOnSignUp ?? requireEmailVerification`, token create, `callbackURL` encode, background send                    | PORTED / EXCLUDED    | `sign-up.go:379-394,466-474`                                            | `sign-up.ts:392-419`     | true/default verified; `sendOnSignUp:false+requireVerification still sends` is **excluded** — `types/email_password.go` needs `*bool` tri-state, types frozen |
| `shouldSkipAutoSignIn → {token:null}`                                                                              | PORTED               | `sign-up.go:396-401`                                                    | `sign-up.ts:421-429`     | verified `TestTriageV1_SignUpAutoSignInFalseTokenNull`                                                                                                        |
| `createSession` → `400 FAILED_TO_CREATE_SESSION`; `setSessionCookie`; `rememberMe=false` non-persistent            | PORTED               | `sign-up.go:408-441`                                                    | `sign-up.ts:431-455`     | IP/UA via issuance seam; rollback via orphan cleanup (`TestOrphanV1_*`)                                                                                       |

**FEATURE-GAP list (in-scope, missing)**

- **P01-GAP-1 — `application/x-www-form-urlencoded` body:** upstream `allowedMediaTypes` (`sign-up.ts:38-41`) + test `should accept form-urlencoded` has no Go decoder (`signUpBody.UnmarshalJSON` is JSON-only, `sign-up.go:41-89`). No `goTest` covers it.

## P02 sign-in

File map:

| Upstream                                                                            | Go                                                      | Ledger                                                           |
| ----------------------------------------------------------------------------------- | ------------------------------------------------------- | ---------------------------------------------------------------- |
| `vendor/better-auth/packages/better-auth/src/api/routes/sign-in.ts` (`signInEmail`) | `auth/src/api/routes/sign-in.go:47-186` (`SignInEmail`) | `auth/parity_ledger.json` (`sign-in.test.ts`, 30 cases, partial) |
| `sign-in.ts` (`signInSocial`)                                                       | excluded — no counterpart (stub never registered)       | same ledger entry                                                |

Per-case verdicts (`TS line` → `Go line`):

| Branch/case                                                                  | Verdict              | Refs / reason                                                                                                                                          |
| ---------------------------------------------------------------------------- | -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `POST /sign-in/social` full handler                                          | EXCLUDED             | TS `196-398`; `SCOPE.md` social flows excluded                                                                                                         |
| `signInEmail` disabled gate `400 EMAIL_PASSWORD_DISABLED`                    | PORTED               | TS `512-520` → Go `55-57`                                                                                                                              |
| `INVALID_EMAIL` format check `z.email()`                                     | FEATURE-GAP          | TS `522-525` has no Go counterpart; Go `59-70` falls through to `401 INVALID_EMAIL_OR_PASSWORD`                                                        |
| Lowercase lookup + credential-account match                                  | PORTED               | TS `526-534` → Go `59-77`; verified by `TestCredsV1_SignInCaseInsensitive`                                                                             |
| Unknown user / missing credential → timing-hash + 401                        | PORTED               | TS `536-545` → Go `64-70,78-82`; dummy-hash mechanism differs but timing-guard intent kept                                                             |
| Missing `password` on credential account → 401                               | PORTED               | TS `548-556` → Go `84-91`                                                                                                                              |
| Wrong password → 401; warn-below-error logging                               | PORTED               | TS `557-566` → Go `92-100`; verified by `TestCredsV1_SignInWarnLogs`                                                                                   |
| `requireEmailVerification` → `403 EMAIL_NOT_VERIFIED`; `sendOnSignIn` resend | PORTED               | TS `569-601` → Go `101-119`; disabled-resend verified by `TestTriageV1_SignInNoResendWhenDisabled`; enabled-resend implemented but unclaimed in ledger |
| `rememberMe===false` → non-persistent session                                | PORTED               | TS `603-606,616-623` → Go `141-142,148,168` + `session.go` expiry                                                                                      |
| Session create failure → `401 FAILED_TO_CREATE_SESSION`                      | PORTED               | TS `608-613` → Go `148-158` (explicit 401 kept)                                                                                                        |
| `set-cookie` session-cookie issuance                                         | PORTED               | TS `616-623` → Go `168-172` via `issueSessionCookies`; verified by `TestTriageV1_SignInSetsSessionCookie`                                              |
| IP/UA capture onto session                                                   | PORTED + DEVIATION   | TS via `internal-adapter` + `getIP` → Go `generate-id.go:89-184`; pinned deviation `SCOPE.md` (XFF-leftmost→X-Real-IP→RemoteAddr, no proxy-chain)      |
| `callbackURL` → `{redirect,url}` + `Location` header                         | PORTED + FEATURE-GAP | TS `625-637` → Go `177-182` returns pair but never sets `Location` header (TS `626`)                                                                   |
| `additionalFields` flattened into `user`                                     | PORTED               | TS `633-636` → Go `161,183`; verified by `TestCredsV1_SignInAdditionalFields`                                                                          |
| `formCsrfMiddleware`, form-urlencoded, CSRF/origin/null-Origin/proxy matrix  | EXCLUDED             | TS `406,446-449`; per `SCOPE.md` + ledger notes CSRF/origin/form-data excluded                                                                         |
| Extra `ValidateUserInfo` sign-in gate (Go-only)                              | DEVIATION            | Go `125-135`; no call in TS email leg — Go-only fail-closed extension                                                                                  |
| Secondary-mirror / cookie-issue failures → `500`                             | DEVIATION            | Go `165-171` vs TS email leg (no equivalent); canonical `500`                                                                                          |

FEATURE-GAP list (in-scope, missing):

- **P02-GAP-1:** Invalid-email format `400 INVALID_EMAIL` (TS `522-525`): Go answers `401 INVALID_EMAIL_OR_PASSWORD`.
- **P02-GAP-2:** `Location: <callbackURL>` response header with `callbackURL` (TS `625-627`): Go sets body `redirect/url` only.
- **P02-GAP-3 (coverage):** `sendOnSignIn:true` resend is implemented (Go `104-117`) but has no claimed Go test.

## P03 sign-out/ok/error

**File map (upstream → Go):**
- `vendor/.../api/routes/sign-out.ts:36-167` → `auth/src/api/routes/sign-out.go:25-50`
- `vendor/.../api/routes/sign-out.test.ts:1-276` → `auth/src/api/routes/creds_v1_signout_test.go:28,65`
- `vendor/.../api/routes/ok.ts:4-39` → `auth/src/api/routes/ok.go:17-28`
- `vendor/.../api/routes/error.ts:7-445` → `auth/src/api/routes/error.go:28-602`
- `vendor/.../api/routes/error.test.ts:1-33` → `auth/src/api/routes/error_test.go:28,45`
- Ledger claims: sign-out (10 cases/2 covered), error (3 cases/2 covered); scope `SCOPE.md`

**Verdict table:**

| Handler / case                                                                     | Upstream ref                                  | Go ref                                     | Verdict                                                     |
| ---------------------------------------------------------------------------------- | --------------------------------------------- | ------------------------------------------ | ----------------------------------------------------------- |
| sign-out: session delete (best-effort, never throws)                               | `sign-out.ts:85-99`                           | `sign-out.go:33-42`                        | PORTED (secondary-aware wrapper of same best-effort delete) |
| sign-out: cookie clearing always                                                   | `sign-out.ts:100`                             | `sign-out.go:44-46`                        | PORTED                                                      |
| sign-out: unreadable-session still clears + `success:true`                         | `sign-out.ts:87-91,93-99,165` + test `:31-55` | `sign-out.go:41,46-48`, test `:65`         | PORTED                                                      |
| sign-out: basic `success:true`                                                     | test `:19-29`                                 | `creds_v1_signout_test.go:28`              | PORTED                                                      |
| sign-out: provider-logout URL (`id_token_hint`, redirect, `url`/`redirect` fields) | `sign-out.ts:28-34,101-164` + tests           | none                                       | EXCLUDED per `SCOPE.md` (no social providers)               |
| sign-out: `callbackURL`/`state`/`disableRedirect` body + untrusted-callbackURL 403 | `sign-out.ts:5-26,124-126,153-157` + tests    | none (no body in `sign-out.go:11-15`)      | EXCLUDED (legs exist only for RP-initiated logout)          |
| ok: `GET /ok → {ok:true}`                                                          | `ok.ts:34-38`                                 | `ok.go:24-28`                              | PORTED                                                      |
| error: XSS sanitize description                                                    | `error.ts:7-16,406-408` + test `:7-19`        | `error.go:128-143,54-56`, test `:28`       | PORTED                                                      |
| error: invalid `code` → `UNKNOWN`                                                  | `error.ts:404-405` + test `:21-32`            | `error.go:49-52,108-123`, test `:45`       | PORTED                                                      |
| error: `errorURL` 302 with safe params                                             | `error.ts:416-428`                            | `error.go:58-67,89-106`                    | PORTED                                                      |
| error: production bounce without customization                                     | `error.ts:430-437`                            | `error.go:69-72`                           | PORTED                                                      |
| error: full HTML + all `customizeDefaultErrorPage` knobs                           | `error.ts:18-372,439-443`                     | `error.go:207-602`                         | PORTED with FEATURE-GAP below                               |
| error: `Content-Type: text/html`                                                   | `error.ts:439-443`                            | `error.go:75` (`text/html; charset=utf-8`) | DEVIATION (charset suffix only, harmless)                   |

**FEATURE-GAP list:**
- **P03-GAP-1:** Full-snapshot error-page parity open — XSS legs ported, byte-for-byte HTML/template drift not gated; post-v1 item.

## P04 session-core

**File map (upstream → Go):**
- `vendor/better-auth/packages/better-auth/src/api/routes/session.ts` → `auth/src/api/routes/session.go` + `session-c701.go` (cookie issuance/cache only)
- `vendor/.../src/api/routes/update-session.ts` → `auth/src/api/routes/session-extra.go:206-365`
- `session-api.test.ts` core-routes describes → ledger `session-api` partial 85 cases (38 cited, 16 ported, 10 excluded, 3 deviations, 1 divergence, 1 open)

**Verdict table (per handler/case):**

| Handler/Case                                                                                                        | Verdict                    | Upstream                                                          | Go                                                                             | Note                                                                        |
| ------------------------------------------------------------------------------------------------------------------- | -------------------------- | ----------------------------------------------------------------- | ------------------------------------------------------------------------------ | --------------------------------------------------------------------------- |
| `GET /get-session` core read + `POST` defer gate                                                                    | PORTED                     | `session.ts:29-38,75-84`                                          | `session.go:63-106`                                                            | POST without defer → 405                                                    |
| Null-shape missing/expired → 200 `null`                                                                             | DEVIATION fail-closed      | `session.ts:94-112,287-303`                                       | `session.go:140-143,175-186`                                                   | Go 401/400; pinned `SCOPE.md`                                               |
| Expired row delete + `SESSION_EXPIRED` code                                                                         | PORTED w/ DEVIATION status | `session.ts:290-303`                                              | `session.go:586-596`                                                           | Row deleted (DB + secondary-aware); status 400/401 not 200 null             |
| `dontRememberMe`/`?disableRefresh` skip write+cookies                                                               | PORTED                     | `session.ts:124-127,309-323`                                      | `session.go:190-197,640-648`                                                   | Served unextended                                                           |
| `updateAge` refresh formula                                                                                         | PORTED                     | `session.ts:324-344`                                              | `session.go:634-660`                                                           | `refreshSessionIfNeeded`, `sessionRefreshDue`                               |
| `updateAge:0` always-refresh tri-state                                                                              | FEATURE-GAP                | test `:252-273`                                                   | `session.go:681-686` + `types/email_password.go`                               | `UpdateAge int` collapses `0`=unset→24h default; needs `*int`; types frozen |
| `MaxAge` 400-day ceiling                                                                                            | PORTED (vacuous)           | test `:508-544`; `cookies/index.ts:122-124`; `session.ts:386-397` | `session.go:717-724` + `session-c701.go:610-616`; `session_v1_maxage_test.go`  | browser-enforced, never exceeded                                            |
| `disableSessionRefresh`+`defer` interplay                                                                           | PORTED                     | `session.ts:339-344,350-365`                                      | `session.go:198-212,622-648`                                                   | Both flags suppress write/flag                                              |
| Defer `needsRefresh` matrix, GET no-write, POST writes, POST-reject, GET no-delete, POST delete, default GET writes | PORTED exc. one DEVIATION  | test `:2110-2385`; `session.ts:297-301,350-365`                   | `session.go:64-75,170-212,587-607`                                             | POST-expired delete: row deleted per upstream, Go 400 not 200 null          |
| Secondary-storage fan-out                                                                                           | PORTED                     | test `:547-646`                                                   | `session.go:332-342,559-563,1718-2216`; `session-extra.go:55,115-148,249-284`  | Dual-write, live-only list, store/preserve matrix                           |
| Fresh-session gate `list-sessions`                                                                                  | PORTED                     | `session.ts:598-616`; test `:141-186`                             | `session.go:319-328` + `types/email_password.go:477-487`                       | stale → 403 `SESSION_NOT_FRESH`                                             |
| `list-sessions` / `revoke-session` / `revoke-sessions` / `revoke-other`                                             | PORTED                     | `session.ts:620-671,676-871`                                      | `session.go:293-368,387-434`; `session-extra.go:27-70,86-161`                  | Ownership check, secondary-aware deletes, refresh-cookie reissue            |
| Forced-strict routes                                                                                                | PORTED                     | `session.ts:479-539,561-572`; test `:2635-2666`                   | `password.go:393-402` direct DB read; test `triage_v1_session_test.go:340-358` | strict routes bypass cookie cache                                           |
| `no-store` on `GET /get-session`, absent elsewhere                                                                  | PORTED w/ DEVIATION        | `session.ts:72-73`; test `:2707-2777`                             | `session.go:79-82`                                                             | Success-only; unauth 401 has no `no-store` (follows null-shape deviation)   |
| `update-session` custom field + cookie re-mint                                                                      | PORTED                     | `update-session.ts:64-82,102-109`; test `:2459-2475,2520-2531`    | `session-extra.go:180-203,286-322` + `session-c701.go:737-771`                 | `FilterSessionUpdateFieldsFull`, `fullSessionFields`                        |
| Ignore core `token`/`userId` → 400 `No fields`                                                                      | PORTED                     | `update-session.ts:64-74`; test `:2477-2497`                      | `session-extra.go:199-201`; `schema-fields.go:329-336`                         | `isCoreSessionColumn:session.go:486-493`                                    |
| Reject `input:false`, validator/transform hooks                                                                     | PORTED                     | `update-session.ts:64-68`                                         | `schema-fields.go:223-266`                                                     | `FIELD_NOT_ALLOWED`, `VALIDATION_ERROR`, 500 transform fail                 |
| Unknown-only body passthrough                                                                                       | DEVIATION accepted         | `update-session.ts:64-74`; test `:2509-2518` expects 400          | `schema-fields.go:230-233`; `session-extra.go:199-201`                         | Union semantics, pinned `SCOPE.md`                                          |
| Revoked-backing fail-closed / DB-less merge                                                                         | PORTED                     | `update-session.ts:88-100`; test `:2558-2633`                     | `session-extra.go:224-226,301-307,331-365`                                     | Stateless uses cached session as record                                     |
| Cookie-cache issuance (compact/JWT/JWE codecs, version/expiry binding, chunk recovery, stale cleanup)               | PORTED (core only)         | `session.ts:102-122,132-284`                                      | `session.go:157-168,965-1012`; `session-c701.go:54-180,621-771,836-909`        | `resolveCookieCacheVersion`, `maybeRefresh`                                 |
| JWKS-backed JWT (custom signer, rotation, claims)                                                                   | EXCLUDED                   | test `:906-1230`; `cookies/jwt.ts`; `plugins/jwt/cookie-cache.ts` | `session-c701.go:182-206,306-356` stub only                                    | No `jwt` plugin in v1 (`SCOPE.md`)                                          |
| JWE strategy + concurrent-request legs                                                                              | EXCLUDED                   | test `:1231-1340,872-905,1320`                                    | codec present, legs unpinned                                                   | Codec ported; concurrency/JWE-cache test legs not claimed                   |
| `updateSession` plugin authority fields                                                                             | EXCLUDED                   | test `:2534-2556`                                                 | `schema-fields.go:329-336`                                                     | Requires org/admin plugins; v1-excluded                                     |
| `returnHeaders`/`asResponse` forwarding + `getSessionFromCtx` fan-out                                               | EXCLUDED                   | `session.ts:472-518`; test `:462-502`                             | `session.go:231-245` (no header fan-out)                                       | Huma model has no TS `returnHeaders` leg                                    |

**FEATURE-GAP list:**
- **P04-GAP-1:** Explicit `updateAge:0` tri-state needs `*int` (`types` frozen) — `session.go:681-686` defaults `0→24h`, breaking always-refresh.

## P05 cookie-cache

**File map (upstream → Go)**
- `.../src/api/routes/session.ts` → `auth/src/api/routes/session.go` + `session-extra.go` + `session-c701.go` (per `SCOPE.md`)
- `.../src/api/routes/cookie-cache-fallback.test.ts` → ledger (partial, 11 cases, 2 covered)
- `.../src/cookies/index.ts` → `auth/src/cookies/cache.go`, `jwt.go`, `session-store.go`, `index.go`
- `.../src/cookies/cache.ts` → `auth/src/cookies/cache.go:115-166`
- `.../src/cookies/session-store.ts` → `auth/src/cookies/session-store.go:39-149`
- `.../src/cookies/jwt.ts` (JWKS signer) → `session-c701.go:182-206,306-356` (shim; plugin v1-excluded per `SCOPE.md`)
- Ledger `goOwner: cookies/session_cache.go, cookies/session_jwt.go` = actual `cache.go`, `jwt.go`
- `.../src/context/create-context.ts` + `store-capabilities.ts` → `session-c701.go:580-587`, `session.go:569-577`, `session-extra.go:219-226,331-365`

| Case                                                       | Verdict             | Refs                                                                                                                                                                               |
| ---------------------------------------------------------- | ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| HMAC-fail falls through to `session_token` DB read         | PORTED              | up `session.ts:114-122`; `fallback.test.ts:157-228`; Go `session.go:140-170,965-992`, `session-c701.go:140-180`                                                                    |
| Malformed compact expired + DB served (`Max-Age=0`)        | PORTED              | up `session.ts:120-122`; `fallback.test.ts:230-274`; Go `session.go:165-167`, `session-c701.go:836-887`, `cache.go:173-222`                                                        |
| Both cookies invalid → null/fail-closed                    | DEVIATION           | up `session.ts:287-303` returns `null`; Go `session.go:170-186,581-583` returns 401/400 fail-closed (pinned `SCOPE.md`)                                                            |
| Disabled cache ignores + cleans retired `session_data`     | PORTED              | up `session.ts:102-109`; `fallback.test.ts:26-83`; Go `session.go:152-156`, `session-c701.go:777-834`                                                                              |
| Clears retired when `session_token` missing/invalid        | FEATURE-GAP         | up `fallback.test.ts:91-136`; Go `session.go:141-142,175-186` discards cleanup on error return, no `Set-Cookie` on auth failure                                                    |
| JWT default-secret tamper → DB fallback                    | PORTED              | up `index.ts:301-326`; `fallback.test.ts:325-365`; Go `session.go:985-987,1049-1059`, `jwt.go:131-203`                                                                             |
| JWE decrypt-fail → DB fallback                             | PORTED              | up `index.ts:285-299`; `fallback.test.ts:367-407`; Go `session.go:988-989,1061-1069`, `jwt.go:263-354`                                                                             |
| Custom JWKS signer                                         | EXCLUDED            | `cookies/jwt.ts`, `index.ts:216-218,303-312`; plugins excluded `SCOPE.md`; Go shim only                                                                                            |
| Cross-subdomain migration, no silent logout                | EXCLUDED            | `fallback.test.ts:425-518,524-582`; Go recovers names/chunks but Domain-scope migration has no v1 Domain infra                                                                     |
| `refreshCache` threshold / `ShouldRefresh` / `false` as-is | PORTED w/ DEVIATION | up `session.ts:170-259`, `create-context.ts:318-351`; Go `cache.go:74-85`, `session.go:1185-1202`, `session-c701.go:892-909` honors literally                                      |
| Version string/func binding + expiry binding               | PORTED w/ DEVIATION | up `session.ts:135-165`, `index.ts:176-185,602-611`; Go `session.go:996-1011,1150-1167`, `session-c701.go:176-179,627-630`; `VersionFunc` error fails closed to DB vs upstream 500 |
| `additionalFields` in cache (filter + parse)               | PORTED              | up `index.ts:169-174`; Go `session.go:744-759,771-801`, `session-c701.go:360-455,627-690`                                                                                          |
| DB-less mode (cache-as-authority, stateless update)        | PORTED              | up `session.ts:450-539`, `create-context.ts:100-112`; Go `session-c701.go:580-587`, `session.go:569-577`, `session-extra.go:224-226,331-365`                                       |
| Chunked re-issue on write                                  | EXCLUDED            | up `session-store.ts:84-131`; read-only per `SCOPE.md`; Go writes single cookie, reads/cleanup chunk-aware                                                                         |

**FEATURE-GAP list**
- **P05-GAP-1:** Retired-cache expiry lost on auth failure: `session.go:175-186` returns error without `staleCleanup`; `fallback.test.ts:91-136` has no Go test.
- **P05-GAP-2 (excluded, recorded):** Chunked `Set-Cookie` issuance unported (explicit read-only exclusion, `SCOPE.md`).
- **P05-GAP-3:** Stateful `refreshCache` warn-disable not replicated; Go documents literal honoring.
- **P05-GAP-4:** `VersionFunc` rejection semantics: upstream 500s via endpoint catch-all; Go fails closed to DB.

## P06 password

**File map:**
- UP: `vendor/.../src/api/routes/password.ts`
- UP-TEST: `vendor/.../src/api/routes/password.test.ts`
- GO-A: `auth/src/api/routes/password.go`
- GO-B: `auth/src/api/routes/password-extra.go`
- LEDGER: `auth/parity_ledger.json` (21 cases, partial)
- SCOPE: `password.go`+`password-extra.go`

| Handler / Case                               | Upstream ref                                     | Go ref                                                                               | Verdict   | Note                                                                                                          |
| -------------------------------------------- | ------------------------------------------------ | ------------------------------------------------------------------------------------ | --------- | ------------------------------------------------------------------------------------------------------------- |
| request-reset disabled                       | `password.ts:90-98`                              | `password.go:56-58` 400 generic                                                      | DEVIATION | no code string; guarded on both senders                                                                       |
| request-reset issuance/expiry                | `password.ts:120-131` 3600s def, 24-char id      | `password.go:92-101,145-177`                                                         | PORTED    | secondary+DB dual-write additive, identifier honored                                                          |
| enumeration-safe generic (unknown/success)   | `password.ts:105-118,144-148`                    | `password.go:52-54,74-90`                                                            | PORTED    | `TestCredsV1_RequestResetUnknownUserWarnsGeneric`                                                             |
| sender-failure generic                       | `password.ts:134-143`                            | `password.go:108,117-130` + `account.go` swallow+log                                 | PORTED    | `TestCredsV1_ResetSenderFailureStillGeneric`                                                                  |
| redirectTo/callbackURL encoding              | `password.ts:132-133`, `11-33`                   | `password.go:104`, `password-extra.go:157-163`                                       | PORTED    | multi-query preserved; `TestCredsV1_ResetURLCallbackEncoding`                                                 |
| originCheck redirectTo/callbackURL           | `password.ts:87,162`                             | `password.go:64-72`, `password-extra.go:104-123`                                     | PORTED    | centralized trust superset; `TestParity_PasswordResetRedirectToFlow`                                          |
| reset-password token sources                 | `password.ts:275-278` body\|\|query, missing 400 | `password.go:227-236,259-267`                                                        | PORTED    | `TestParity_PasswordResetAcceptsQueryToken`; body wins                                                        |
| reset length gates                           | `password.ts:282-289`                            | `password.go:269-274`                                                                | PORTED    | `TestTriageV1_ResetShortPasswordRejected`                                                                     |
| reset single-use + concurrent-reuse          | `password.ts:293-300` first-wins                 | `password.go:276-279,503-600` txn + secondary `GetAndDelete`, burned-even-if-expired | PORTED    | unit `TestConsumeResetPasswordToken_SingleUse`; HTTP race see GAP-1                                           |
| reset expiry (callback + consume)            | `password.ts:219-223`                            | `password.go:545-559`, `password-extra.go:125-128,140-146`                           | PORTED    | `TestTriageV1_ResetExpiredTokenRejected`                                                                      |
| reset user/account + `updatedAt` bump        | `password.ts:301-318`                            | `password.go:281-335`                                                                | PORTED    | `TestTriageV1_ResetBumpsAccountUpdatedAt`                                                                     |
| reset USER_NOT_FOUND status                  | `password.ts:304` BAD_REQUEST                    | `password.go:292-297` canonical status                                               | DEVIATION | intentional canonical-status win per comment                                                                  |
| reset `onPasswordReset` hook                 | `password.ts:320-327` direct await, fail route   | `password.go:337-342`, 500 on err                                                    | PORTED    | `Request` variant additive                                                                                    |
| `revokeSessionsOnPasswordReset` on/off       | `password.ts:328-330`                            | `password.go:344-348`                                                                | PORTED    | `TestTriageV1_ResetRevokesSessionsWhenEnabled` / `KeepsSessionsByDefault`                                     |
| `GET /reset-password/{token}` callback       | `password.ts:207-226`                            | `password-extra.go:82-132`                                                           | PORTED    | `TestCredsV1_ResetCallbackRedirect`                                                                           |
| `verify-password` statuses                   | `password.ts:373-390`                            | `password-extra.go:31-76`                                                            | PORTED    | `TestVerifyPassword_AcceptsCurrentPassword` + `TestCredsV1_VerifyPasswordStatuses`; empty-hash guard additive |
| legacy HMAC email-token fallback             | none in `password.ts`                            | `password.go:590-600`, `password-extra.go:140-146`                                   | DEVIATION | migration bridge, rotation-aware; extra accept, never weakens single-use rows                                 |
| `ChangePassword` in `password.go:380-490`    | owned by `update-user.ts`, not `password.ts`     | —                                                                                    | EXCLUDED  | P06 out-of-scope, judged in P08                                                                               |
| `SetPassword` in `password-extra.go:179-233` | `update-user.ts` `serverOnly`, no HTTP route     | —                                                                                    | EXCLUDED  | server-only by decision (`SCOPE.md`)                                                                          |

**FEATURE-GAP list:**
- **P06-GAP-1:** concurrent same-token HTTP race: atomic consume PORTED, but only helper-level test pins it; HTTP-level 1×200+1×400 race left unpinned as non-deterministic on mem adapter (same note as delete-race).
- No other functional gap.

## P07 email-verification

**File map**
- Upstream: `vendor/.../src/api/routes/email-verification.ts` (545 lines); test `email-verification.test.ts` (29 cases)
- Go: `auth/src/api/routes/email-verification.go` (1096 lines); `auth/src/crypto/email-verification.go` (204 lines)
- Claims: ledger (`partial`, 29 cases, body-consumption excluded); `SCOPE.md` maps TS→`email-verification.go`

**Verdict table**
| Handler / case                                                                             | Verdict     | Refs                                                                    | Note                                                                                          |
| ------------------------------------------------------------------------------------------ | ----------- | ----------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `createEmailVerificationToken` issuance (HS256, lowercased email/`updateTo`, default 3600) | PORTED      | TS:17-43 vs Go crypto:50-74,34-36                                       | stdlib HS256; rotation via `VerifyAny`                                                        |
| `POST /send-verification-email` unauth floor + dummy-sign                                  | PORTED      | TS:175-207 vs Go:24,84-104,180-185                                      | 500ms floor + dummy JWT; sender error deferred past floor                                     |
| `POST /send-verification-email` auth legs + case-insensitive                               | PORTED      | TS:209-218 vs Go:64-79                                                  | `EqualFold`; invalid session falls through to unauth                                          |
| Send URL/callback encoding (plain leg)                                                     | PORTED*     | TS:65-68 vs Go:199-213                                                  | `QueryEscape` vs `encodeURIComponent` (`+` vs `%20` for spaces)                               |
| `GET /verify-email` query contract, originCheck→redirect, `redirectOnError ?error=CODE`    | PORTED      | TS:225-241,293-301,537-539 vs Go:274-365,320                            | `IsTrustedRedirect`→403 mirrors `FORBIDDEN`                                                   |
| JWT verify (HS256, expired vs invalid)                                                     | PORTED      | TS:302-317 vs Go:388-397,733-735 + crypto:140-175                       | string-contains `expired` approximates `JWTExpired`                                           |
| Plain verify + `before/afterEmailVerification`, mark verified                              | PORTED      | TS:489-506 vs Go:651-711,152-176                                        | hook APIError status preserved; non-API→500                                                   |
| `autoSignInAfterVerification` mints session+cookie                                         | DEVIATION   | TS:507-535 vs Go:703-710,719-731                                        | Go always mints new session; upstream reuses `currentSession` when email matches (TS:527-534) |
| Already-verified shape                                                                     | DEVIATION   | TS:480-488,540-543 vs Go:663-664,359-363                                | Upstream JSON `user:null`; Go returns verified user (redirect with `callbackURL` same)        |
| `USER_NOT_FOUND` status (no callback)                                                      | DEVIATION   | TS:300,327-328 (401 via redirect) vs Go:425-427,655-660 (canonical 404) | intentional per Go comment                                                                    |
| Stateless `updateTo` 3 legs (confirmation / verification / legacy)                         | PORTED      | TS:330-478 vs Go:418-527                                                | `INVALID_USER` check skipped when session unknown is documented equivalent                    |
| Change-email resend URL encoding                                                           | FEATURE-GAP | TS:347-350,447-455 vs Go:449,518-519                                    | Go interpolates raw `callbackURL`/`token`; plain-send leg escapes but these two do not        |
| Legacy `updateTo` (no `requestType`) re-issue TTL                                          | DEVIATION   | TS:443-446 (default expiry) vs Go:511 (custom `ExpiresIn`)              | Go honors custom expiry where upstream falls back to 3600                                     |
| Confirmation leg missing-sender                                                            | DEVIATION   | TS:351 (skip) vs Go:442-444 (throw)                                     | legacy leg correctly skips like upstream                                                      |
| Secondary-session fan-out                                                                  | PORTED      | TS implicit via `updateUserByEmail` vs Go:468,505,626,686-691           | failing mirror fails update loudly, as commented                                              |
| Custom `expiresIn` expiry enforced                                                         | PORTED      | TS:27,63 + test:404-432 vs Go:108-116,173-175                           | negative→expired; `TestTriageV1_VerifyEmailExpiredTokenRejected`                              |
| Body-consumption JS semantics (4 cases)                                                    | EXCLUDED    | test cases vs Go:43-49,118-135 + ledger notes                           | `Request.clone()/text()`; Go single-arg + `Request`-aware variant, no body-clone concept      |
| Stateful change-email verification rows (secondary/DB dual-store)                          | DEVIATION   | TS: none (stateless JWT) vs Go:534-646,737-751                          | self-declared legacy bridge: single-use, consumed on success                                  |

**FEATURE-GAP list**
1. **P07-GAP-1:** Change-email resend links omit `QueryEscape` on `token`/`callbackURL` (`email-verification.go:449,518-519`); query-bearing `callbackURL` corrupts.
2. **P07-GAP-2:** Already-verified `GET/POST` without `callbackURL` returns `{status:true,user:<user>}` instead of upstream `{status:true,user:null}`.
3. **P07-GAP-3:** `autoSignInAfterVerification` never reuses the matching current session, always creating a new session row.
4. **P07-GAP-4 (inherited):** `sendOnSignUp:false` + `requireEmailVerification` still sends cannot be represented (`SendOnSignUp *bool` frozen).

## P08 account/update-user

**File map (upstream → Go):**
- `vendor/.../src/api/routes/account.ts:45-124` (list-accounts) → `auth/src/api/routes/account.go:221-268` (`ListUserAccounts`)
- `.../routes/update-user.ts:25-145` (updateUser) → `account.go:391-484` (`UpdateUser`); `update-user.ts:147-312` (changePassword) → `auth/src/api/routes/password.go:380-490` (`ChangePassword`)
- `update-user.ts:314-368` (setPassword, `serverOnly`) → `auth/src/api/routes/password-extra.go:179-233` (`SetPassword`, no HTTP route)
- `update-user.ts:370-563` (deleteUser) → `account.go:671-806` (`DeleteUser`); `update-user.ts:565-666` (deleteUserCallback) → `auth/src/api/routes/delete-user-callback.go:17-153`
- `update-user.ts:668-900` (changeEmail) → `account.go:487-649` (`ChangeEmail`); confirm→verify move lands in `email-verification.go`
- Ledger `goOwner: api/routes/account_extra.go, delete_user_callback.go` is **stale**: no `account_extra.go` exists; callback file is kebab-case `delete-user-callback.go`. `SCOPE.md` names are correct.

**Verdict table (social legs excluded per SCOPE):**

| Upstream case                                                                                                     | Verdict                  | Evidence                                                                                                                                                                                |
| ----------------------------------------------------------------------------------------------------------------- | ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| account `should list all accounts`                                                                                | PORTED                   | `account.go:247-266`; `creds_v1_account_test.go:48-61`                                                                                                                                  |
| account `empty scope → []`                                                                                        | PORTED                   | `account.go:1075-1079`; test `:65-89`                                                                                                                                                   |
| account link/unlink/account-info/get-access-token/refresh-token/cookie/token-cache/stateless-mismatch (~49 cases) | EXCLUDED                 | No social providers in v1 (`SCOPE.md`); no link/unlink/info/token handlers registered                                                                                                   |
| update-user `should update the user's name` + `shouldn't pass defaults`                                           | PORTED                   | `account.go:422-452` only-supplied-fields; `newSessionCookies:477`                                                                                                                      |
| `should unset image` (null clears)                                                                                | PORTED                   | `nullableString:32-58`; `account.go:428-434`; test `:122-149`                                                                                                                           |
| `email` rejected in update-user                                                                                   | PORTED                   | `update-user.ts:98-103` → `account.go:418-420`                                                                                                                                          |
| `input:false` additional field rejected                                                                           | PORTED                   | `account.go:438-452`; test `:153-171`                                                                                                                                                   |
| password update / wrong current / `updatedAt` bump                                                                | PORTED                   | `update-user.ts:254-286` → `password.go:408-450`; tests `TestCredsV1_ChangePasswordWrongCurrent`, `TestTriageV1_ChangePassword{SuccessRotatesCredentials,BumpsAccountUpdatedAt}`        |
| `should revoke other sessions` + preserve replacement in secondary                                                | PORTED w/ GAP            | `password.go:460-487`; tests `TestCredsV1_ChangePasswordRevokesOthers`, `TestSecondaryV1_DeleteAllThenRecreateKeepsOnlyReplacement`. GAP: no `Set-Cookie` for replacement — see G1      |
| propagate updates across sessions + write once per token (secondary)                                              | PORTED                   | `account.go:470,589`; impl `session.go:1970-2004`; helper tests                                                                                                                         |
| ignore cookie cache for sensitive ops                                                                             | PORTED (by construction) | Go `ChangePassword` reads DB directly (`password.go:393-395`); `UpdateUser/ChangeEmail/DeleteUser/Callback` via DB/secondary only; test `TestTriageV1_ChangePasswordIgnoresCookieCache` |
| change email only after confirming both addresses                                                                 | PORTED                   | `update-user.ts:831-898` → `account.go:610-644` (`QueryEscape(callbackURL)`); test `TestCredsV1_ChangeEmailDoubleConfirm`                                                               |
| change-email enumeration (`200 existing target`; same error without sender)                                       | PORTED                   | gate before lookup `account.go:522-530` + timing token + `status:true`; tests `:228-274`                                                                                                |
| change-email `callbackURL` encoding                                                                               | PORTED                   | `url.QueryEscape` `account.go:602,624,642`; test `:279-313`                                                                                                                             |
| change-email confirmation-only config → 400                                                                       | PORTED                   | `account.go:527-530`; test `:318-337`                                                                                                                                                   |
| change-email same email → 400, disabled gate, lowercasing                                                         | PORTED                   | `account.go:495-520`                                                                                                                                                                    |
| keeps one credential account across email change                                                                  | PORTED                   | `account.go:571-576` never touches `account` rows; test `:342-381`                                                                                                                      |
| delete disabled → 404                                                                                             | PORTED                   | `update-user.ts:465-470` → `account.go:679-681` + `delete-user-callback.go:51-54`; test `TestTriageV1_DeleteUserDisabledIs404`                                                          |
| delete with fresh session                                                                                         | PORTED                   | `account.go:721-723,780-786` freshness via `sessionIsFresh:808-818`; test `:498-513`                                                                                                    |
| require password when stale → 400 `SESSION_EXPIRED`                                                               | PORTED                   | `account.go:702-723`; test `:424-453`                                                                                                                                                   |
| delete every session (plain)                                                                                      | PORTED                   | `deleteUserRecords:1018-1028` txn deletes sessions+accounts+user; expired cookies `801-803`                                                                                             |
| delete with verification flow + password                                                                          | PORTED                   | `account.go:758-778` 32-char token, `delete-account-` id, callback `?token=&callbackURL=`; consume-then-delete `729-756`; test `:386-420`                                               |
| POST `/delete-user` with `token` delegates to callback                                                            | PORTED                   | `update-user.ts:492-504` → `account.go:725-756`; wrong-owner still burned                                                                                                               |
| `delete only once concurrently`                                                                                   | EXCLUDED (race note)     | Atomic consume mirrors upstream; mem-adapter race not deterministically pinnable                                                                                                        |
| rejects callback when backing session revoked                                                                     | PORTED                   | `update-user.ts:625-627` → `delete-user-callback.go:77-87` → 404; token not consumed; test `:458-495`                                                                                   |
| callback `originCheck` untrusted `callbackURL` → 403                                                              | PORTED                   | `update-user.ts:580` → `delete-user-callback.go:62-75,140-147`; test `:518-549`                                                                                                         |
| `beforeDelete/afterDelete` bracket + hook-status passthrough                                                      | PORTED                   | `runBefore/AfterDeleteHook:181-208`, `finishDeleteUser:1005-1016`; `HttpError` passthrough                                                                                              |
| `setPassword` server-only                                                                                         | PORTED                   | `update-user.ts:314-368` → `password-extra.go:179-233` no route; tests `TestCredsV1_SetPassword{OnPasswordlessAccount,CreatesMissingAccount}`                                           |

**FEATURE-GAP list:**
- **P08-G1:** `ChangePassword(revokeOtherSessions:true)` returns the new token in-body (`password.go:484`) and recreates+mirrors the secondary session but never emits `Set-Cookie` for it, while upstream calls `setSessionCookie(newSession)`. Cookie-only clients keep the dead token.
- **P08-G2:** `finishDeleteUser/deleteUserRecords` (`account.go:1005-1028`) purges only DB rows; with `SecondaryStorage` the `active-sessions-*` index + per-token entries are never deleted. Needs secondary fan-out delete on both delete paths + callback path.

## P09 routes-infra

23-route catalog (`SCOPE.md`) vs `auth/src/api/index.go:411-479` (23 call-sites, each once). Upstream catalog `vendor/.../src/api/routes/index.ts:1-12`; social stub `vendor/.../src/api/routes/callback.ts:42-45` correctly excluded.

| route                      | Go ref                                                                              | Y/N |
| -------------------------- | ----------------------------------------------------------------------------------- | --- |
| `/ok`                      | `auth/src/api/index.go:411-412`                                                     | Y   |
| `/error`                   | `auth/src/api/index.go:414-415`                                                     | Y   |
| `/sign-up/email`           | `auth/src/api/index.go:417-418`                                                     | Y   |
| `/sign-in/email`           | `auth/src/api/index.go:420-421`                                                     | Y   |
| `/sign-out`                | `auth/src/api/index.go:423-424`                                                     | Y   |
| `/get-session`             | `auth/src/api/index.go:426-427` + `session.go:88-105` GET+POST                      | Y   |
| `/list-sessions`           | `auth/src/api/index.go:429-430`                                                     | Y   |
| `/revoke-session`          | `auth/src/api/index.go:432-433`                                                     | Y   |
| `/send-verification-email` | `auth/src/api/index.go:435-436`                                                     | Y   |
| `/verify-email`            | `auth/src/api/index.go:438-439` + `email-verification.go:249-272` POST + `:279` GET | Y   |
| `/request-password-reset`  | `auth/src/api/index.go:441-442`                                                     | Y   |
| `/reset-password`          | `auth/src/api/index.go:444-445`                                                     | Y   |
| `/change-password`         | `auth/src/api/index.go:447-448`                                                     | Y   |
| `/list-accounts`           | `auth/src/api/index.go:450-451`                                                     | Y   |
| `/update-user`             | `auth/src/api/index.go:453-454`                                                     | Y   |
| `/change-email`            | `auth/src/api/index.go:456-457`                                                     | Y   |
| `/delete-user`             | `auth/src/api/index.go:459-460`                                                     | Y   |
| `/delete-user/callback`    | `auth/src/api/index.go:462-463` + `delete-user-callback.go:17-24`                   | Y   |
| `/revoke-sessions`         | `auth/src/api/index.go:465-466`                                                     | Y   |
| `/revoke-other-sessions`   | `auth/src/api/index.go:468-469`                                                     | Y   |
| `/update-session`          | `auth/src/api/index.go:471-472`                                                     | Y   |
| `/verify-password`         | `auth/src/api/index.go:474-475`                                                     | Y   |
| `/reset-password/{token}`  | `auth/src/api/index.go:477-478` + `password-extra.go:82-89`                         | Y   |

No duplicates/missing. Excluded paths never registered: `/sign-in/social`, `/callback/{provider}` — stub-only `auth/src/api/routes/callback.go:1-19`.

| check                             | verdict                | ref                                                                                                                                                                                            |
| --------------------------------- | ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 23 routes registered exactly once | PASS                   | `auth/src/api/index.go:411-479` vs `SCOPE.md`                                                                                                                                                  |
| social-callback legs excluded     | PASS (by scope)        | upstream `callback.ts:42-45`; Go stub `routes/callback.go:10-11`                                                                                                                               |
| origin-check core                 | PASS w/ gaps           | Go `api/index.go:75-105` vs upstream `origin-check.ts:67-76,221-251`                                                                                                                           |
| rate-limit resolvers              | PASS w/ gaps           | Go `rate-limiter.go:616-637,701-740,751-773,784-812` + `index.go:1508-1636` vs upstream `rate-limiter/index.ts:337-468,418-437`                                                                |
| middlewares/state/dispatch shape  | PASS (boundary parity) | `middlewares/index.go`, `middlewares/origin-check.go:33-99`, `middlewares/authorization.go:77-157`, `state/should-session-refresh.go:27-49`, `dispatch.go:42-105`, `to-auth-endpoints.go:1-51` |
| upstream router wiring            | PASS                   | `getEndpoints`+`originCheckMiddleware`+`onRequestRateLimit`+`disabledPaths` mirrored by `Router`+`disabledPathMatched`+`useRateLimitMiddleware[WithStorage]`                                   |

FEATURE-GAP:
- **P09-GAP-1:** `Referer` fallback + `Origin: null`/`sec-fetch-site` inference missing: Router reads only `Origin` (`api/index.go:85-88`) vs upstream `origin||referer` + inferred origin; helper `OriginOrReferer` (`middlewares/origin-check.go:58-63`) not wired.
- **P09-GAP-2:** `formCsrfMiddleware` Fetch-Metadata first-login gate missing: `CROSS_SITE_NAVIGATION_LOGIN_BLOCKED` + no-cookie `Origin` enforcement has no Go counterpart; Router passes cookie-less requests through.
- **P09-GAP-3:** `skipOriginCheck` path-array + `skipCSRFCheck` granularity not wired: `Router` honors only `DisableOriginCheck`/`DisableCSRFCheck` bools.
- **P09-GAP-4:** Mutating-method set narrower: Go `POST/PUT/PATCH/DELETE` vs upstream "not GET/OPTIONS/HEAD" (e.g. `TRACE` validated upstream, skipped in Go).
- **P09-GAP-5:** Legacy rate-limit path is two-phase check+record vs upstream single atomic `consume`; concurrent burst can overshoot on default backend.
- **P09-GAP-6:** Custom-rule wildcard uses `path.Match` sorted keys vs upstream `wildcardMatch`; `**`/edge patterns may diverge.
- **P09-GAP-7:** Plugin-bucket consumption only inside lifecycle middleware; when `needsMiddleware=false` plugin rules never consume (no v1 impact — no plugins — but divergent).

## P10 cookies

File map (upstream → Go; ledger `goOwner` names are stale — no such files):
- `vendor/.../src/cookies/index.ts` → `auth/src/cookies/index.go:12-49` (signed-cookie primitive) + `cookie-utils.go` + `cache.go` + `jwt.go` + `session-store.go`; issuance orchestration at `session.go:861-893` / `session-c701.go`
- `cookie-utils.ts` → `cookie-utils.go:28-36,59-116,125-212,264-386,427-739`
- `cache.ts:20-44` → `cache.go:91-113,141-222,247-304`
- `session-store.ts` → `session-store.go:39-149` (+ account JWE in `jwt.go`)
- `jwt.ts:52-87` (JWKS custom signer) → no Go owner (plugin-excluded)
- `cookies.test.ts` (118 cases) → `setcookie_v1_test.go`, `cookies_parity_test.go`, `triage_v1_cookies_test.go`, `edge_parity_test.go`, `cache_*_test.go`, `session_jwt_test.go`

| Util / case                                                                              | Verdict                               | Refs                                                                                                                                                                                          |
| ---------------------------------------------------------------------------------------- | ------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| secure resolution (override > dynamic protocol > `https://` > prod)                      | PORTED                                | `index.ts:66-76` → `cookie-utils.go:59-80`                                                                                                                                                    |
| `__Secure-` prefix, custom-name override                                                 | PORTED                                | `index.ts:76,96-99` → `cookie-utils.go:40-95`                                                                                                                                                 |
| crossSubdomain domain                                                                    | PORTED                                | `index.ts:79-91` → `cookie-utils.go:103-116`                                                                                                                                                  |
| defaults (`Secure`, `SameSite=Lax`, `Path=/`, `HttpOnly`; token=`expiresIn`, data=`300`) | PORTED                                | `index.ts:105-110,122-128` → `cookie-utils.go:140-148`; `session.go:872-893`                                                                                                                  |
| `getCookies` catalog as single function                                                  | DEVIATION (split, behavior same)      | no `GetCookies` in Go; built at `session.go:861-893`, `session-c701.go`                                                                                                                       |
| `splitSetCookieHeader` (Expires commas never split)                                      | PORTED                                | `cookie-utils.ts:53-90` → `cookie-utils.go:427-461`                                                                                                                                           |
| Expires-comma / mixed / GMT-substring legs                                               | PORTED                                | test `:245-320` → `setcookie_v1_test.go:20-104`                                                                                                                                               |
| RFC850 + asctime Expires                                                                 | PORTED                                | `cookie-utils.go:565-579`                                                                                                                                                                     |
| `Expires=0` split values                                                                 | DEVIATION (minor)                     | TS `new Date("0")` Invalid vs Go leaves `ExpiresSet=false`                                                                                                                                    |
| `partitioned` + `toCookieOptions`                                                        | PORTED                                | `ts:144-146,160-173` → `cookie-utils.go:523,548-561`                                                                                                                                          |
| unknown attrs kept in parse map                                                          | DEVIATION (minor)                     | TS keeps; Go drops; `ToAttributes` output identical                                                                                                                                           |
| `stripSecureCookiePrefix` (8 legs)                                                       | PORTED                                | `ts:40-48` → `cookie-utils.go:28-36`; `setcookie_v1_test.go:131-151`                                                                                                                          |
| `parseCookies`                                                                           | PORTED                                | `ts:180-247` → `cookie-utils.go:264-386`                                                                                                                                                      |
| `setRequestCookie` join/replace/encode                                                   | PORTED                                | `ts:257-272` → `cookie-utils.go:654-688`                                                                                                                                                      |
| `applySetCookies` strip-attrs / last-wins / re-encode                                    | PORTED                                | `ts:282-300` → `cookie-utils.go:695-711`                                                                                                                                                      |
| `getSessionCookie`                                                                       | PORTED                                | `index.ts:559-593` → `cookie-utils.go:297-323`                                                                                                                                                |
| set-cookie attribute emission                                                            | DEVIATION                             | `net/http` vs `serializeCookie`; `MaxAge=0` omitted in helper (`cookie-utils.go:718-723`) vs wire `Max-Age=0`; route expiry uses `MaxAge:-1`+epoch so wire expiry still correct on route path |
| `expireCookie` preserve-attrs + chunk scrub                                              | PORTED                                | `index.ts:495-504,425-457` → `cookie-utils.go:718-739`                                                                                                                                        |
| signed-cookie `value.sig` (HMAC-SHA256 base64urlnopad)                                   | PORTED                                | `index.go:12-36`                                                                                                                                                                              |
| compact cache create/verify/rotation/outer+embedded expiry                               | PORTED                                | `index.ts:225-243,328-354` → `cache.go:91-113,173-222`                                                                                                                                        |
| post-signature payload-schema validation                                                 | PORTED (ledger stale, see P10-GAP-1)  | `cache.ts:20-39` → `cache.go:127-166,209-213` + jwt codec sentinels                                                                                                                           |
| JWT/JWE default-secret cache                                                             | PORTED                                | `index.ts:207-223,285-326` → `jwt.go:95-203,210-354`                                                                                                                                          |
| JWKS custom signer                                                                       | EXCLUDED (plugin, v1 scope)           | `jwt.ts:52-87`; ledger "JWKS x4"                                                                                                                                                              |
| chunk READ                                                                               | PORTED                                | `session-store.ts:46-60,210-238` → `session-store.go:80-149`                                                                                                                                  |
| chunk WRITE issuance                                                                     | EXCLUDED (read-path-only, `SCOPE.md`) | `session-store.ts:84-131`; `ChunkCookieValue:39-63` exists unwired                                                                                                                            |
| `setSessionCookie`/`setCookieCache` orchestration, dual-scope scrub, account user-switch | EXCLUDED/PARTIAL (social legs)        | `index.ts:356-398,425-490,252-275`; Go `session.go:872-893`                                                                                                                                   |
| sensitive-middleware `disableCookieCache` guard                                          | EXCLUDED (route scope)                | judged in P08                                                                                                                                                                                 |

FEATURE-GAP list:
- **P10-GAP-1 (ledger note stale, no code gap):** post-signature payload-schema validation IS wired (`ValidateCachePayloadSchema` + `ErrCachePayloadSchema`, `cache.go:127-166`, all three codecs, warn+miss at route layer); the ledger `notes` text saying it is open needs updating (ledger untouched in v2 recreation).
- No other open gap in `cookies` scope.

## P11 crypto

**File map (one upstream file at a time):**
- `vendor/.../src/crypto/password.ts:8-23` (thin re-export, `node:crypto scrypt`) → `auth/src/crypto/password.go:1-61`
- `vendor/.../src/crypto/index.ts:18-124` → `auth/src/crypto/symmetric.go:50-229` + `token.go:104-124` (HMAC)
- `vendor/.../src/crypto/jwt.ts:52-185` (HKDF, `symmetricEncode/DecodeJWT`, kid/clock tolerance) → `auth/src/crypto/jwe.go:62-103` + `jwt.go:29-43` + `cookies/jwt.go:208-301` (full JWE)
- `vendor/.../src/crypto/buffer.ts:4-24` → `auth/src/crypto/buffer.go:17-33`
- `vendor/.../src/crypto/random.ts:1-7` → `auth/src/crypto/random.go:8-51`
- `vendor/.../src/context/secret-utils.ts:16-108` (tested inside `secret-rotation.test.ts`) → `auth/src/context/secret-utils.go:34-108` + `auth/src/secrets.go:29-45` shim
- `vendor/.../src/crypto/email-verification.ts` (no file; issuance in route) → Go-only `auth/src/crypto/email-verification.go:50-121`

**Verdict table (per primitive/case):**

| Primitive / case                                                                    | Verdict                          | Evidence                                                                                                                                        |
| ----------------------------------------------------------------------------------- | -------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| scrypt params `N=16384/r=16/p=1/dkLen=64`, `salt:key` hex, 16B salt, NFKC           | PORTED                           | `password.test.ts:68-80` ↔ `password.go:15-21,33,59`; vector verifies                                                                           |
| `password.test.ts` 14 cases                                                         | PORTED                           | ledger claims 14/14; `password_test.go` + `password_v1_test.go`                                                                                 |
| Verify timing-safety (scrypt `ConstantTimeCompare`, HMAC `hmac.Equal`)              | PORTED                           | `password.go:60`; `email-verification.go:158`; `token.go:76,119`                                                                                |
| `constantTimeEqual` max-length loop                                                 | DEVIATION                        | `buffer.ts:16-22` loops `max(len)`; `buffer.go:18` uses `subtle.ConstantTimeCompare` (length-mismatch early-0; unobservable for fixed 64B path) |
| Hash upgrade path (rehash-on-verify)                                                | EXCLUDED                         | Neither upstream (verify-only) nor Go rehashes; no caller                                                                                       |
| bcrypt `$2a$/$2b$/$2y$` accept                                                      | DEVIATION (Go-only bounded read) | `password.go:43-46`; upstream never accepts bcrypt; writes scrypt-only, no auto-upgrade → gap below                                             |
| symmetric: `SHA256(secret)→XChaCha20-Poly1305` managed-nonce                        | PORTED                           | `index.ts:40-52` ↔ `symmetric.go:191-229`                                                                                                       |
| JWE: HKDF-SHA256, `dir/A256CBC-HS512`, thumbprint-kid, 15s tolerance                | PORTED                           | `jwt.ts:41-60,99-116` ↔ `jwe.go:32-103`, `jwt.go:29-43`                                                                                         |
| Envelope parse/format                                                               | PORTED                           | `index.ts:18-33` ↔ `symmetric.go:52-72`                                                                                                         |
| Symmetric rotation (bare-hex, 1-key envelope, v2, old-after-rotation, legacy, gaps) | PORTED                           | `secret-rotation.test.ts:44-183` ↔ `rotation_v1_test.go`, `symmetric_parity_test.go`                                                            |
| `ParseEnvelope` strictness                                                          | DEVIATION (fail-closed stricter) | Upstream `parseInt` accepts prefix; Go `strconv.Atoi` rejects (pinned `TestF6ParseSecretsEnvStrictVersion`)                                     |
| Verify-across-rotation + grace                                                      | PORTED                           | `index.ts:81-98`, `jwt.ts:118-184` ↔ `symmetric.go:116-189`, `cookies/jwt.go:258-301`                                                           |
| `getCryptoKey`/`makeSignature` HMAC-SHA256 base64                                   | PORTED                           | `index.ts:100-124` ↔ `token.go:106-124`                                                                                                         |
| `secret-rotation.test.ts` context helpers                                           | EXCLUDED (sibling scope)         | Ledger delegates to `src/context`; implemented `context/secret-utils.go:34-108`                                                                 |
| JWE `encode/decode` legs unclaimed in ledger                                        | FEATURE-GAP                      | `secret-rotation.test.ts:187-293` only kid-less/mismatched claimed; full JWE vectors live in `cookies/` tests                                   |
| Email-token rotation                                                                | PORTED (Go-only extension)       | `email-verification.go:102-138`; mirrors route `jwtVerify`                                                                                      |

**FEATURE-GAP list:**
1. **P11-GAP-1:** No automatic `bcrypt→scrypt` rehash on successful login — legacy hashes verify forever until password change (read-only bridge; removal policy pinned).
2. **P11-GAP-2 (coverage):** JWE multi-secret legs have no `crypto/` ledger `goTest`; coverage relies on `cookies/` JWE tests, not byte-identical `jwt.ts` vectors.

## P12 core-infra

| Go file                                                                                                                                        | Upstream counterpart                                                                   | Verdict                                                                                                                                     |
| ---------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `auth/src/index.go:343` `BetterAuth`                                                                                                           | `vendor/.../src/context/create-context.ts` + `init.ts` (no `src/init.ts`)              | **Kept, split** — ctx build `finalizeAuthContext` (`index.go:849`), secrets-first (`index.go:355`), plugin loop w/ patches (`index.go:384`) |
| `auth/src/init_patches.go:13`                                                                                                                  | `vendor/.../src/context/helpers.ts:44` + `defu`                                        | **Kept w/ loud deviation** — scalar zero-value falsy loss pinned (`init_patches.go:35`)                                                     |
| `auth/src/secrets.go:8` shim                                                                                                                   | `vendor/.../src/context/secret-utils.ts`                                               | **Kept, moved** — delegates to `context/secret-utils.go:34,179`; strict `Atoi` deviation                                                    |
| `auth/src/telemetry.go:21`                                                                                                                     | `packages/telemetry/src/index.ts`                                                      | **Kept, no-network exclusion** — local `PublishTelemetry` only (`telemetry.go:70`); gate `Enabled‖BETTER_AUTH_TELEMETRY`                    |
| `auth/src/instrumentation.go:25` `WithSpan`                                                                                                    | `packages/core/src/instrumentation/`                                                   | **Kept, passthrough** — no OTel SDK, both paths inline                                                                                      |
| `auth/src/version.go:5` `1.7.5`                                                                                                                | `SCOPE.md` pin `5468e6bf`                                                              | **Parity**                                                                                                                                  |
| `auth/src/schema.go:276` `CoreSchema`, `:564` `GetAuthTables`, `:706` `FullSchema`                                                             | `packages/core/src/db/get-tables.ts` + `better-auth/src/db/schema.ts,get-migration.ts` | **Kept w/ deltas** — `ResolveSchema` plugin-only allow-list frozen (`schema.go:686`); plural-always + `ModelName` ignore on core            |
| `auth/src/hooked_adapter.go:215`                                                                                                               | `vendor/.../src/db/with-hooks.ts`                                                      | **Preserved** — `plugin:<id>`/`user` sources, merge-over, `EndPreservedSessions`                                                            |
| `auth/src/db/adapter-base.go:31`                                                                                                               | `vendor/.../src/db/adapter-base.ts` + `core/src/db/adapter/`                           | **Kept, partial** — no join param, error-only `Transaction`, no auto limit-100                                                              |
| `auth/src/db/get-schema.go:9`                                                                                                                  | `get-schema.ts` vs `core/src/db/schema-check.ts`                                       | **Split by design** — this file = `schema-check.ts` port only; table-shape stays in root `schema.go`                                        |
| `auth/src/db/with-hooks.go:28`                                                                                                                 | `core/src/db/adapter/index.ts`, `factory.ts` generic `transaction<R>`                  | **Kept** — hooked writes stay in root per file note                                                                                         |
| `auth/src/adapters/bun/bun.go:65,186` + `models.go:9,101`                                                                                      | `vendor/.../src/db/adapter-kysely.ts`                                                  | **Kept (Go-only adapter)** — `DefaultModelDefs` core-only; `pgLocked*` row-lock paths                                                       |
| `auth/src/cmd/generate-schema/main.go:38,1342` + `diff.go:41` + `config.go:23`                                                                 | `get-migration.ts,schema-diff.ts`                                                      | **Kept** — fresh `BuildMigrationPlan` + incremental `DiffMigrationPlan`; `-from/-check/-throw-on-unsafe`                                    |
| `auth/src/context/secret-utils.go:1`                                                                                                           | `secret-utils.ts,create-context.ts,helpers.ts,init.ts`                                 | **Parity** (only context file in v1 scope)                                                                                                  |
| `auth/src/types/helper.go:39` `MintModelID`                                                                                                    | `context/create-context.ts:248`                                                        | **Kept, Go-only location** (moved ex-`generate-id.go`)                                                                                      |
| `auth/src/types/index.go` + `models.go` + `auth.go` + `email_password.go`                                                                      | `src/types/*`                                                                          | **Frozen for v1** — `SendOnSignUp bool`, `UpdateAge int`, `FreshAge *int` tri-state gaps recorded not fixed                                 |
| `auth/src/utils/constants.gen.go` `boolean.gen.go` `hide_metadata.gen.go`                                                                      | `utils/constants.ts,boolean.ts,hide-metadata.ts`                                       | **Parity frozen** — generator removed in v2, outputs checked in as-is (`SCOPE.md`)                                                                              |
| `auth/src/testutil/fixtures.go,doc.go,live_test.go`                                                                                            | — (harness)                                                                            | **Kept** — hermetic vectors + opt-in live smoke only                                                                                        |
| Go-only kept: `api/routes/generate-id.go`, `api/routes/schema-fields.go`, `api/routes/hooks.go`, `api/dispatch.go`, `api/to-auth-endpoints.go` | none (per `SCOPE.md`)                                                                  | **Kept** — all exist on disk                                                                                                                |

Verdicts: schema parity claimed by `schema_parity_test.go` + `ValidateSchemaIndexes` gate in generator and `buildSchemaCheck`; secondary-storage wiring = startup gate, table inclusion, `SecondaryStorage` iface + session/verification dual paths; hooked preservation via synthetic `patchHooksPlugin`; ip/UA direct-resolution deviation per SCOPE (`api/routes/generate-id.go:151`, test `api/routes/ipua_v1_test.go:177`); Huma 422-vs-400 framework convention (e.g. `sign-up.go:119`, `account.go:55`); chunked-cookie read-only degradation (`cookies/session-store.go:26,100`); live PG scope = core+rate-limit only (no plugin columns).

FEATURE-GAP list:
- **P12-GAP-1:** `SendOnSignUp: false` + `requireEmailVerification` still sends — needs `*bool` tri-state; `types` frozen (`SCOPE.md`, `email_password.go:196`).
- **P12-GAP-2:** Explicit `updateAge: 0` (always-refresh) conflated with unset — needs `*int`; frozen (`SCOPE.md`, `email_password.go:400`).
- `init.ts` has no 1:1 Go file; covered by `index.go` + `context/` split — accepted, not a gap.
- `db/get-schema.ts` table-shape intentionally not in `db/get-schema.go` — lives in root `schema.go`; accepted split.

## Later-work backlog

Consolidated actionable FEATURE-GAPs (in-scope, missing). Pinned deviations
(null-shape fail-closed, 422-vs-400, IP/UA direct resolution, chunked-read-only,
JWKS/plugin/social exclusions) are NOT backlog — see `SCOPE.md`.

Auth correctness (do first):
- P08-G1: `ChangePassword(revokeOtherSessions:true)` never emits `Set-Cookie` for the replacement session — cookie-only clients keep the dead token.
- P08-G2: delete-user paths never purge `SecondaryStorage` (`active-sessions-*` index + per-token entries).
- P07-GAP-1: change-email resend links omit `QueryEscape` on `token`/`callbackURL`.
- P07-GAP-2: already-verified without `callbackURL` returns the user instead of upstream `user:null`.
- P07-GAP-3: `autoSignInAfterVerification` never reuses the matching current session.
- P05-GAP-1: retired `session_data` cleanup lost on auth-failure paths (no `Set-Cookie` on 401/400).
- P02-GAP-1: sign-in has no `400 INVALID_EMAIL` format leg (falls through to 401).
- P02-GAP-2: sign-in with `callbackURL` never sets the `Location` header.
- P01-GAP-1: no `application/x-www-form-urlencoded` decoder on sign-up (and by extension the shared auth body path).

Types-unfrozen work (post-v1, `types/` frozen):
- P12-GAP-1 / P07-GAP-4: `SendOnSignUp *bool` tri-state.
- P12-GAP-2 / P04-GAP-1: `UpdateAge *int` tri-state (explicit `updateAge: 0` always-refresh).

Infra hardening:
- P09-GAP-1: wire `OriginOrReferer` (`Referer` fallback + `Origin: null` inference).
- P09-GAP-2: Fetch-Metadata first-login gate (`CROSS_SITE_NAVIGATION_LOGIN_BLOCKED`).
- P09-GAP-3: `skipOriginCheck` path-array / `skipCSRFCheck` granularity.
- P09-GAP-4: widen mutating-method set to "not GET/OPTIONS/HEAD".
- P09-GAP-5: atomic rate-limit consume on the default backend (burst overshoot).
- P09-GAP-6: `wildcardMatch` semantics for custom rate-limit rules (`**` patterns).
- P05-GAP-4: `VersionFunc` rejection should 500 like upstream (currently fails closed to DB).
- P05-GAP-3: stateful `refreshCache` warn-disable.
- P11-GAP-1: `bcrypt→scrypt` rehash on successful login (legacy hashes verify forever).

Parity snapshots / coverage pins (no behavior change):
- P03-GAP-1: full-snapshot error-page parity (XSS legs ported).
- P06-GAP-1: HTTP-level concurrent same-token reset race pin (non-deterministic on mem adapter).
- P02-GAP-3: `sendOnSignIn:true` resend leg has code but no claimed test.
- P11-GAP-2: JWE multi-secret legs rely on `cookies/` tests, no `crypto/` ledger claim.
- P10-GAP-1: ledger `notes` text claims post-signature payload-schema validation is open — it is wired; update the ledger note (ledger untouched in this v2 recreation).

Recorded exclusions (not backlog): P05-GAP-2 chunked `Set-Cookie` issuance
(read-only per `SCOPE.md`); all social/plugin/JWKS legs; CSRF/origin/form-data
matrix legs; concurrent-delete/reset mem-adapter race pins.

## Wave-10 exclusion registry

Narrow, explicit, and tested (carried over from v1 `PARITY.md`, which is
deleted). Each entry records what is excluded, why, and the removal policy.
Anything not listed here is implemented. Entries referencing
plugins/social/oauth-provider describe code outside v1 scope (`SCOPE.md`).

- Dead compat interfaces (W10-01): `TokenEndpointAuth` struct,
  `ClientAssertionProvider`, `TokenAuthMethodProvider`, `DiscoveryProvider`,
  `PrimaryClientID` helper. Zero runtime effect; removal would break in-tree
  consumers and tests asserting them. Preserved as legacy aliases. Removal:
  major-version cleanup with migration notes only.
- Array-form `clientId` (W10-02): Go takes the single primary ID (upstream
  index 0); `Audience`/`IDToken` overrides cover multi-audience verification.
  Removal: widen provider constructors on a major version.
- WeChat dedicated token field (W10-03): the per-instance openid store
  carries openid correctly (fail-closed, refresh supported); a dedicated
  `OAuthTokens` field is cosmetic. Removal: add the field when a second
  consumer needs it.
- `StoreAccountCookie` (W10-04): the Go runtime requires a database adapter,
  so database-less account-cookie flows are out of scope; the option is
  preserved for surface compatibility.
- `AdditionalCookies` (W10-05): no route issues those cookies; the shared-
  domain helper is provided for deployments that do.
- Chunked session-data writes (W10-06): single-cookie writes only; oversize
  caches degrade safely to authoritative lookup (browsers drop oversize
  cookies, producing a cache miss against the store); reads recover
  upstream/custom/chunked names.
- Private-host fetch guards for `jwks_uri`/backchannel URLs (W10-07): not
  implemented; outbound uses a 5s no-redirect client and loopback is allowed
  for hermetic tests.
- `WWW-Authenticate` error headers on OAuth endpoints (W10-08): Huma errors
  carry no headers; statuses are asserted. Removal: Huma header-carrying
  errors or a custom envelope.
- Strict `clientCredentialsScopes` ceiling (W10-09): the legacy fallback is
  kept for compatibility with existing clients; explicit ceilings are
  enforced when set.
- Custom auth-code hashing (W10-10): consume tries the custom hash then the
  default (rotation-safe); issue-side hashing stays default.
- Empty-string `prompt`/`max_age` over GET (W10-11): Huma drops empty query
  values framework-wide; covered via POST.
- `setPassword` HTTP endpoint (W10-12): upstream server-only with no Go HTTP
  owner; password setting flows through create/change/reset routes.
- Extension token-issuance capability surface (W10-13): simplified Go
  envelope signatures, documented in code; full provider capability
  plumbing on token paths stays future work.
- `at_hash` signing-alg heuristic (W10-14): HS256 vs RS256 selection
  documented in code; full `resolveSigningKey` parity open.
- Live MySQL/MSSQL contract runs (W10-15): no MySQL/MSSQL drivers in go.mod
  (intentional, no new dependencies); SQL-generation conformance plus
  SQLite fallback cascades are green.
- Cross-package PostgreSQL parallelism (W10-16): plugin/root harnesses share
  physical tables, so live runs require `-p 1` (documented process); the Bun
  adapter itself is parallel-safe per the isolation matrix.
- Unknown-key additional-field bodies on sign-up (W10-17): Huma structs drop
  unknown keys framework-wide; update paths parse full input.
- Banned social/id-token redirect harnesses (W10-18): no social harness in
  the admin package; the ban hook applies to all session creation (tested).
- Server-call-only shapes (W10-19): Go is HTTP-only; unauthenticated HTTP
  yields 401 in those paths (tested).
- Organization-hook DB org creation via core sign-up (W10-20): covered —
  post-commit hook writes see committed rows and hook failures surface
  their code with the user kept (`hook_signup_test.go`).
- Client-only test areas (W10-21): `useSession` revalidation,
  `checkRolePermission`, client declaration files — no Go client exists.

## Ledger ID registry

Self-contained definition of every `AUTH-*-ID` referenced in this file (the
drift gate requires each referenced ID to be defined here):
- `AUTH-R5-01`: the v1 parity ledger (`parity_ledger.json`) — 13 upstream test files, 495 cases, 188 covered, pending 0.
- `AUTH-C7-01`: session/cookie-cache parity wave (cookie-cache issuance, fallback, secondary fan-out).
- `AUTH-C7-02`: credential-routes parity wave (sign-up, sign-in, password, email-verification, account/update-user triage).
- `AUTH-C7-04`: error-page parity wave (XSS sanitization ported, full snapshot open).
