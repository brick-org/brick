# Next 40 core transpiler candidates

Ordered roughly from smaller shared behavior to larger core flows. Paths in the
source and test columns are relative to their respective upstream `src/`
directories:

- **BA:** `vendor/better-auth/packages/better-auth/src/`
- **Core:** `vendor/better-auth/packages/core/src/`

Add a shared TS↔Go test case only when the pinned TypeScript test actually
asserts that behavior. A test file's existence does not establish coverage of
every export or branch. Route tests may exercise their source through an
integration API rather than importing it directly. Each source remains a
whole-file, fail-closed transpiler candidate; test availability does not relax
the requirement to account for every runtime construct in the file.

| # | Source file | Existing TS test |
|---:|---|---|
| 1 | Core `utils/fetch-metadata.ts` | `utils/fetch-metadata.test.ts` |
| 2 | BA `utils/date.ts` | `api/routes/session-api.test.ts` |
| 3 | Core `utils/deprecate.ts` | `utils/deprecate.test.ts` |
| 4 | Core `utils/string.ts` | `utils/string.test.ts` |
| 5 | BA `utils/request.ts` | `utils/request.test.ts` |
| 6 | Core `utils/url.ts` | `utils/url.test.ts` |
| 7 | Core `utils/ip.ts` | `utils/ip.test.ts` |
| 8 | Core `utils/host.ts` | `utils/host.test.ts` |
| 9 | Core `utils/async.ts` | `utils/async.test.ts` |
| 10 | BA `crypto/password.ts` | `crypto/password.test.ts` |
| 11 | BA `context/secret-utils.ts` | `crypto/secret-rotation.test.ts` |
| 12 | BA `utils/url.ts` | `utils/url.test.ts` |
| 13 | BA `cookies/cookie-utils.ts` | `cookies/cookies.test.ts` |
| 14 | BA `crypto/index.ts` | `crypto/secret-rotation.test.ts` |
| 15 | BA `crypto/jwt.ts` | `crypto/secret-rotation.test.ts` |
| 16 | BA `cookies/index.ts` | `cookies/cookies.test.ts` |
| 17 | BA `db/to-zod.ts` | `db/to-zod.test.ts` |
| 18 | BA `context/init-minimal.ts` | `context/init-minimal.test.ts` |
| 19 | BA `context/init.ts` | `context/init.test.ts` |
| 20 | Core `env/env-impl.ts` | `env/env-impl.test.ts` |
| 21 | Core `context/request-state.ts` | `context/request-state.test.ts` |
| 22 | Core `context/endpoint-context.ts` | `context/endpoint-context.test.ts` |
| 23 | BA `context/helpers.ts` | `context/create-context.test.ts` |
| 24 | BA `context/create-context.ts` | `context/create-context.test.ts` |
| 25 | BA `api/to-auth-endpoints.ts` | `api/to-auth-endpoints.test.ts` |
| 26 | BA `api/middlewares/authorization.ts` | `api/middlewares/authorization.test.ts` |
| 27 | BA `api/middlewares/origin-check.ts` | `api/middlewares/origin-check.test.ts` |
| 28 | BA `api/rate-limiter/index.ts` | `api/rate-limiter/rate-limiter.test.ts` |
| 29 | BA `api/routes/error.ts` | `api/routes/error.test.ts` |
| 30 | BA `api/routes/sign-out.ts` | `api/routes/sign-out.test.ts` |
| 31 | BA `api/routes/password.ts` | `api/routes/password.test.ts` |
| 32 | BA `api/routes/sign-in.ts` | `api/routes/sign-in.test.ts` |
| 33 | BA `api/routes/sign-up.ts` | `api/routes/sign-up.test.ts` |
| 34 | BA `api/routes/email-verification.ts` | `api/routes/email-verification.test.ts` |
| 35 | BA `api/routes/session.ts` | `api/routes/session-api.test.ts` |
| 36 | BA `api/routes/update-user.ts` | `api/routes/update-user.test.ts` |
| 37 | BA `api/routes/account.ts` | `api/routes/account.test.ts` |
| 38 | BA `db/get-migration.ts` | `db/get-migration.test.ts` |
| 39 | Core `db/schema-check.ts` | `db/schema-check.test.ts` |
| 40 | BA `api/index.ts` | `api/index.test.ts` |

`BA utils/date.ts` is the next suggested whole-file slice: the existing
`api/routes/session-api.test.ts` exercises `getDate`. The already-generated
`BA utils/boolean.ts`, `utils/hide-metadata.ts`, and `utils/constants.ts` are
excluded. `BA types/helper.ts` is type-only and has no executable server
behavior to emit as Go.
