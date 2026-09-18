# Better Auth parity completion plan

This plan turns the per-file backlog in [`PARITY.md`](./PARITY.md) into
dependency-ordered implementation waves. The target is Better Auth v1.7.5 at
`vendor/better-auth` commit `5468e6bfcdff799848537cf5ad06ebab15aad9dd`.

> **Status:** Waves 1–4 are complete. The original backlog and immediate
> action below are retained as execution history. The active plan is
> [Parity closure review and Waves 5–10](#parity-closure-review-and-waves-510).

## Operating rules

Before parallel work starts:

1. Run the current validation gate.
2. Review `git diff --check`.
3. Snapshot the baseline in a commit or dedicated worktree after authorization.
4. Assign stable IDs to every backlog item (`AUTH-P0-01`, `AUTH-P1-01`, etc.).
5. Record owned Go files, upstream TS files, tests, intended behavior, and
   accepted deviations for every task.

Use at most **four implementation agents concurrently**. Agents own packages
or cohesive file groups, not arbitrary individual files.

Every task follows this workflow:

1. Inspect the pinned upstream implementation and tests.
2. Port the relevant tests first.
3. Confirm the tests fail for the expected reason.
4. Implement the behavior without weakening tests.
5. Run package-local build, vet, tests, and race tests where relevant.
6. Report hunks mapped to task IDs and disclose anything left open.
7. Cross-check the diff for scope, API breaks, silent fallbacks, and unrelated
   edits.
8. Run the full-module validation gate.
9. Update `PARITY.md` only after verification.

## Wave 1: storage and adapter foundations

These tasks unblock sessions, rate limiting, schema handling, and plugins.

### Agent A: secondary storage and rate limiting

**Owns**

- `index.go`
- `api/index.go`
- `api/rate_limiter.go`
- `api/routes/session.go`
- `api/routes/session_extra.go`
- `api/routes/email_verification.go`
- Tests in the corresponding packages

**Tasks**

- Secondary-storage session runtime
- Secondary verification storage
- `StoreSessionInDatabase`
- `PreserveSessionInDatabase`
- Atomic database rate-limit backend
- Remove the database rate-limit startup rejection
- Production-default rate-limit behavior
- Custom rule resolvers
- Plugin-rule IP resolution

**Upstream references**

- `context/create-context.ts`
- `db/secondary-storage.test.ts`
- `api/rate-limiter/index.ts`
- `api/routes/session.ts`
- `db/verification-token-storage.ts`

**Must not touch:** Bun adapter, OAuth packages, or plugins.

### Agent B: Bun adapter correctness

**Owns**

- `db/adapter.go`
- `adapters/bun/bun.go`
- `adapters/bun/models.go`
- Adapter tests

**Tasks**

- Return the persisted row from `Create`
- Preserve generated IDs, defaults, and trigger values
- Implement non-RETURNING fallback lookup
- Port date, boolean, JSON, array, and numeric-ID transforms
- Execute custom field transforms
- Validate configured identifiers
- Add the join contract and capability flags
- Add savepoint/nested-transaction behavior
- Enforce strict model, field, and value validation

**Required tests**

- SQLite in-memory integration
- PostgreSQL integration when `DATABASE_URL` exists
- SQL-generation tests for MySQL/MSSQL fallback paths
- Shared adapter contract suite

### Agent C: schema and migrations

**Owns**

- `schema.go`
- `api/routes/schema_fields.go`
- `cmd/generate-schema/main.go`
- Schema and generator tests

**Tasks**

- Split the full schema from the legacy route allow-list
- Move route field processing to the full schema
- Carry timestamp defaults and `onUpdate`
- Implement complete index validation
- Enforce required/input/returned attributes
- Execute field transforms and validators
- Honor model aliases
- Generate executable FK/cascade/index migrations
- Add dialect-specific DDL
- Load arbitrary plugin schemas in the CLI
- Produce safe migration plans

**Must not touch:** Bun runtime behavior or unrelated route business logic.

### Agent D: hooks and plugin runtime

**Owns**

- `hooked_adapter.go`
- `types/plugins.go`
- `api/routes/hooks.go`
- Hook and plugin tests

**Tasks**

- Merge before-hook results instead of replacing payloads
- Pass the bulk result count to bulk after-hooks
- Propagate post-commit errors
- Add `onAfterCommitHookError`
- Add the TS-faithful endpoint context
- Consume named endpoints and TS route hooks
- Consume adapter overrides and plugin migrations
- Execute field validator/transform adapters

### Wave 1 merge gate

```bash
cd auth
git diff --check
GOWORK=off go build ./...
GOWORK=off go vet ./...
env -u DATABASE_URL GOWORK=off go test -count=1 ./...
env -u DATABASE_URL GOWORK=off go test -race ./...
```

Database validation:

```bash
DATABASE_URL=... GOWORK=off go test -count=1 ./adapters/bun/... .
```

Cross-check specifically for whole-table mutations, weakened assertions,
non-atomic fallbacks, undocumented interface breaks, and schema/adapter name
drift.

## Wave 2: core runtime behavior

Start after Wave 1 is integrated.

### Agent A: session and cookie strategies

**Owns**

- `api/routes/session.go`
- `api/routes/session_extra.go`
- `api/routes/sign_in.go`
- `api/routes/sign_up.go`
- `api/routes/sign_out.go`
- `cookies/session_cache.go`
- Relevant crypto helpers only when required

**Tasks**

- JWT session cache
- JWE session cache
- Claim, version, and key binding
- Remember-me marker mint/clear
- Expired-row deletion
- Stateful/stateless refresh defaults
- Secondary-storage session behavior
- Custom-session behavior
- No-store/freshness semantics
- Response parity

### Agent B: account, password, and email flows

**Owns**

- `api/routes/account.go`
- `api/routes/account_extra.go`
- `api/routes/delete_user_callback.go`
- `api/routes/password.go`
- `api/routes/password_extra.go`
- `api/routes/email_verification.go`
- Corresponding tests

**Tasks**

- Request-aware callbacks
- Account-token response parity
- Delete callback behavior
- Secondary verification storage
- Store-identifier and cleanup modes
- HS256 email-JWT issuance
- Legacy-HMAC read-only migration
- Exact rollback, hook, and error matrices
- Background-task timing

### Agent C: framework context and options

**Owns**

- `index.go`
- `api/index.go`
- `init_patches.go`
- `secrets.go`
- `types/auth.go`
- Root and API tests

**Tasks**

- Per-request dynamic BaseURL propagation
- Full context services
- Telemetry publishing and instrumentation
- Logger-level behavior
- Request state
- Schema checks and migrations
- `DBHints`
- ID-generation overrides
- Runtime option-marker reconciliation
- Endpoint conflict detection
- Trailing-slash registration
- Exact middleware header ordering

### Agent D: OAuth client conformance

**Owns**

- `oauth2/*.go`
- OAuth tests

**Tasks**

- `auth_time` enforcement
- Real request context for custom verifiers
- Exact refresh/revoke/userinfo/discovery errors
- DPoP client primitives
- Discovery/JWKS cache concurrency
- Malformed-key and malformed-token limits
- Cross-language state fixtures
- DB-state concurrency
- `serverContext` support API

### Wave 2 merge gate

```bash
env -u DATABASE_URL GOWORK=off go test -count=10 ./api/routes/... ./cookies/... ./oauth2/...
env -u DATABASE_URL GOWORK=off go test -race ./api/... ./cookies/... ./oauth2/...
```

Review JWT/JWE algorithm pinning, wrong/stale key rejection, nonce single-use,
session refresh races, redirect trust, and secondary-storage consistency.

## Wave 3: first-party plugins

### Wave 3 status — DONE

All four agents accepted and merge gate passed (diff-check, build, vet,
full tests, plugins suite, Invitation/Refresh/Replay/Rotation race).
797 named tests, 69.9% statement coverage.

- Agent A (admin): self checks, exact error messages + 22 codes, set-role
  gating, custom hash, filter fixes, impersonation ownership. Justified
  breaks: has-permission 200, role-create gating, ban message.
- Agent B (JWT): cookie-cache signer, keyPairConfigs gating, remote JWKS,
  custom sign/header, adapter/schema overrides, rotation matrix,
  persisted-key fix.
- Agent C (OAuth Provider): private-key JWT + replay tombstones, PAR
  surface + advanced authorize semantics, CAS rotation + replay window +
  DPoP binding, registration hardening, logout fan-out, strict
  resources. Adapted its own test to JWT's faithful gating (merge item
  closed by owner).
- Agent D (organization): membership keys/counts, role gating, atomic
  claims with race-verified double-accept protection, team hooks,
  aligned matrices, 36-route e2e. Recorded deviations: AC-absent
  leniency, add-member superset, shapes, static-only options.

Launched four parallel agents (admin; JWT; OAuth Provider; organization).
Awaiting reports; merge gate, `PARITY.md` updates, progress entry, and
commit to follow.

- Agent A (admin) ACCEPTED: self permission checks (gate removed),
  username/additional-field passthrough, exact upstream error messages on
  all 15 endpoints, 22-entry error codes, set-role gating on create-user,
  custom hash fn, `_id`/bool filter fixes, impersonation ownership check.
  Package vet + tests green (7 new suites). Justified breaks: non-admin
  has-permission 200 (was 403), explicit-role create requires set-role,
  longer default ban message. Open: username-plugin validation, session
  route impersonation filtering, custom schema option, strict adminRoles
  throw (intentionally permissive).
- Tree-wide build currently blocked by Agent C's mid-edit untracked
  `plugins/oauthprovider/private_key_jwt.go` (syntax error, still in
  flight) — not a regression; merge gate waits for convergence.
- Agent B (JWT) ACCEPTED: session-cookie-cache signer mode, `keyPairConfigs`
  with faithful gating, remote JWKS, custom sign/header, adapter + schema
  overrides, rotation/grace matrix, persisted-key compat (null-alg inherit
  fix). Package vet + tests green (38 new tests; 1-line parity-test update
  required by the faithful gating). Known merge item: oauthprovider's
  `TestOAuthParity_ResourceSigningPin` needs `KeyPairConfigs:[ES256]`
  declared (will fix at gate after Agent C lands).
- Agent D (organization) ACCEPTED: `membershipKey` generation/idempotency,
  `memberCount` maintenance with guarded seat reservation, dynamic-role
  endpoint gating (breaking, per plan), atomic invitation claim with
  concurrent double-accept protection (race-verified), 8 team hooks,
  option gates, error-matrix alignment, 36-route e2e. Package vet + tests
  + Invitation race green. Recorded deviations: AC-absent leniency,
  add-member HTTP superset, role/metadata shapes, static-only
  function-form options.

All four plugin agents can run in parallel after Waves 1 and 2.

### Agent A: Admin plugin

**Owns:** `plugins/admin/**`

**Tasks**

- Self permission checks
- Username/additional fields
- Exact response/error schemas
- Session behavior matrix
- Option combinations
- PostgreSQL route coverage

### Agent B: JWT plugin

**Owns:** `plugins/jwt/**`

**Tasks**

- Session-cookie-cache mode
- Multiple `keyPairConfigs`
- Remote JWKS
- Custom sign function and header behavior
- Adapter and schema overrides
- Rotation/grace migration matrix
- Persisted-key compatibility

Avoid changing shared crypto unless Wave 2 established the required API.

### Agent C: OAuth Provider plugin

**Owns:** `plugins/oauthprovider/**`

**Tasks, in order**

1. Private-key JWT and assertion replay prevention
2. PAR/JAR/JARM and advanced authorization semantics
3. Refresh-token family rotation/replay and DPoP
4. Registration, software statements, and initial access tokens
5. Logout fan-out and capability-dependent metadata
6. Strict resource/audience behavior

### Agent D: Organization plugin

**Owns:** `plugins/organization/**`

**Tasks**

- Generate and maintain `membershipKey`
- Maintain `memberCount`
- Gate dynamic-role endpoints
- Atomically accept invitations
- Prevent concurrent double acceptance
- Port remaining callbacks/options
- Complete team/member/invitation error matrices
- Exercise all 36 routes end to end

### Wave 3 merge gate

```bash
env -u DATABASE_URL GOWORK=off go test -count=1 ./plugins/...
env -u DATABASE_URL GOWORK=off go test -race ./plugins/...
DATABASE_URL=... GOWORK=off go test -count=1 ./plugins/...
GOWORK=off go test -race -run 'Invitation|Refresh|Replay|Rotation' ./plugins/...
```

## Wave 4: tooling, provider depth, and cleanup

### Wave 4 status — DONE

All four agents accepted and merge gate passed (diff-check, build, vet,
full tests, race, coverage). 930 named tests, 72.9% statement coverage.

- Agent A (generator + migrations): schema-diff port, 4-dialect goldens,
  FK-safe ordering, JSON plugin config, migration planning flags, live
  SQLite execution. Default CLI output unchanged.
- Agent B (provider matrix): 36-provider audit, 15+ divergence fixes,
  comment reconciliation, 10 extended option surfaces, full fixtures.
- Agent C (types reconciliation): ~130 markers audited, StatusForCode
  sweep complete, pure DPoP types, IDNA no-dependency decision pinned.
- Agent D (conformance + fuzzing, tests-only): 55 ported tests, 12/13
  fuzz targets clean, 2 bugs reported.
- Merge facilitation: fixed both fuzzer/agent-reported bugs —
  `WildcardMatch` literal-star false negative (star branch prioritized,
  regression test) and nil-DB query panic (descriptive `requireDB`
  errors ordered after pure validation, regression test).

### Live PostgreSQL verification (postgres:17, serial `-p 1`)

Full module green on live PG (`DATABASE_URL` set, `-p 1 -count=1`:
all 15 packages ok). Cross-package parallel runs (`go test ./...`)
interfere via the shared database — PG suites must run serially until
per-test schema isolation lands. Fixes made during verification (all
covered by the PG tests themselves):

- Test-schema gaps: JWT + oauthprovider `jwkss` tables gained
  `alg`/`crv`; admin `users`/`sessions` tables gained role/ban/
  impersonation columns; oauth consent/refresh/access tables use the
  Go physical `requested_user_info_claims` spelling.
- Admin `migrate` now creates core `users`/`sessions` tables.
- `oauthprovider` register rate-limit test enables global rate limiting
  (plugin rules honor the production-default gate).
- Real product bugs fixed: Bun default table mapping now lowercases
  (`oauthRefreshToken` → `oauthrefreshtokens`; quoted raw-SQL paths
  broke while unquoted paths folded silently); rate-limit and origin
  403 responses set headers before status (huma drops post-status
  headers); update-user `image` input gained a `TransformSchema`
  accepting string|null (plain payloads were 422).
- Test setups now enable `DeleteUser` where delete-user 200 is asserted
  (previously 404 by config, masked because the tests skip without
  `DATABASE_URL`).

- Agent C (types reconciliation) ACCEPTED: ~130 markers audited with
  ~45 pending→wired flips + 1 wired→pending correction, stale
  surface-only claims removed, new pure `types/dpop.go`, StatusForCode
  sweep (zero hunks needed — adoption complete), IDNA no-new-dependency
  decision pinned by test. Comments/markers + additive types only, no
  runtime change. Types package vet + tests (+race) green.
- Merge gate blocked on Agent B's untracked `social-providers/fetchers.go`
  (redeclares 3 mappers from `index.go`; B still running — its own
  collision to resolve, not touched).
- Agent A (generator + migrations) ACCEPTED: append-only schema diffing
  port (`DiffSchemas`, unsafe-change errors, timestamp support matrix),
  dialect golden fixtures ×4, FK-safe ordering extraction, `-config`
  JSON + `-plugins id:json` plugin configuration, `-from`/`-check`/
  `-throw-on-unsafe` migration planning, e2e compile checks with live
  SQLite execution. Cmd + root schema suites green; default CLI output
  unchanged. Open: live Postgres/MySQL/MSSQL wire runs.
- Agent B (social-provider matrix) ACCEPTED: audited all 36 providers,
  fixed 15+ endpoint/scope/mapping/transport divergences (Figma, Spotify,
  GitLab, Kick, TikTok, Twitter, Twitch, Facebook, Reddit, Roblox,
  Dropbox, Notion, LinkedIn/Slack, PayPal/Cloudflare/Railway, Atlassian,
  Discord, WeChat), NEEDS→WIRED comment reconciliation, 10 new option
  surfaces, upstream-shaped profile/JWKS/URL/transport fixtures.
  Package + collateral (routes, oauth2, root) suites green, race-clean.
  Tree builds again (B resolved its own fetchers.go collision in-tree).
  Open: WeChat openid carriage (needs types owner), per-operation Reddit
  headers (cosmetic), VK/PayPal upstream no-ops.

These four agents can run in parallel.

### Agent A: generator and migration conformance

- Dialect-specific DDL
- Safe migration diffing
- FK/index execution
- Arbitrary plugin configuration
- PostgreSQL/SQLite/MySQL/MSSQL golden fixtures

### Agent B: social-provider matrix

- Audit all 36 provider option surfaces
- Remove stale `NEEDS` comments
- Reconcile stale `Runtime: pending` markers
- Add provider-specific profile fixtures
- Add JWKS/discovery fixtures
- Cover transport quirks

### Agent C: public type/runtime reconciliation

- Reconcile every pending/wired marker
- Remove stale surface-only claims
- Finish runtime consumers
- Add DPoP types
- Complete status mapping adoption
- Decide IDNA/punycode support

### Agent D: conformance and fuzzing

- Port remaining upstream tests
- Fuzz trusted origins, cookie parsing/chunking, JWT/JWE parsing, OAuth
  state, and adapter where clauses
- Add race tests and malformed-input limits
- Add cross-language golden vectors

## Completion criteria

A `PARITY.md` row becomes **Done** only when:

1. The current pinned upstream source was inspected.
2. Relevant upstream tests were ported or declared non-applicable with reason.
3. Go tests cover success and failure behavior.
4. No accepted option is silently ignored.
5. Intentional deviations are documented.
6. Package-local build, vet, tests, and race tests pass.
7. Full-module build, vet, tests, and race tests pass.
8. PostgreSQL tests pass where applicable.
9. The corresponding backlog item is removed or moved to intentional
   exclusions.

Final validation:

```bash
cd auth

git diff --check
test -z "$(gofmt -l .)"

GOWORK=off go build ./...
GOWORK=off go vet ./...

env -u DATABASE_URL GOWORK=off go test -count=1 ./...
env -u DATABASE_URL GOWORK=off go test -race -count=1 ./...
env -u DATABASE_URL GOWORK=off go test -coverpkg=./... ./...

DATABASE_URL=... GOWORK=off go test -count=1 ./...
DATABASE_URL=... GOWORK=off go test -race -count=1 ./...
```

## Immediate next action

Historical action (completed): start Wave 1 with four parallel agents:

1. Secondary storage and rate limiting
2. Bun adapter correctness
3. Schema and migrations
4. Hooks and plugin runtime

This order provides the highest leverage and avoids rebuilding route/plugin
work on incomplete storage, schema, or adapter contracts.

## Progress log

Wave entries are appended here after the merge gate passes and the wave is
committed. Format per wave: scope completed, validation results, commit hash,
known follow-ups carried to the next wave.

### Wave 1: storage and adapter foundations — DONE

All four agents accepted and merge gate passed (diff-check, build, vet,
full tests, race). 602 named tests, 61.8% statement coverage.

- Agent A (secondary storage + rate limiting): secondary session runtime
  with flag matrix, secondary verification storage, atomic DB rate-limit
  backend wired into middleware, startup rejection narrowed to
  flags-without-backend, production-default enablement, custom rule
  resolvers, proxy-aware plugin-rule IPs. Transitional deviations:
  creation paths still DB-only with backfill, preserve-mode deletes fire
  update hooks, plugin buckets stay memory two-phase.
- Agent B (Bun adapter): persisted-row `Create`, factory-ordered
  transforms with custom hooks, joins via optional interfaces (`Adapter`
  signature frozen), savepoint nesting + sequential nil-DB fallback,
  identifier/model/field validation, shared contract suite + SQLite
  integration. Accepted deviations: MSSQL `OUTPUT inserted` unused,
  `UpdateMany`/`DeleteMany` empty-where match-all executes per upstream.
- Agent C (schema + migrations): full/legacy split with additive `*Full`
  helpers (no behavior flip), timestamp func-defaults, full index
  validation, plugin-schema registry + CLI support, dialect DDL with
  executable FK-safe migration plans. Route rewiring to `*Full` helpers
  carried to Wave 2.
- Agent D (hooks + plugin runtime): before-hook merge, bulk after-hook
  counts, post-commit error propagation with handler, adapter overrides,
  field validator/transform execution, named-endpoint/TS-hook/migration
  collectors, TS endpoint-context pipeline. Non-transactional after-hook
  errors stay log-and-continue (pinned; follow-up decision). Router/schema
  consumption of the new runners carried to Wave 2.

Follow-ups carried forward: `index.go` adopts
`NewHookedAdapterWithOptions`; `api/index.go` registers named endpoints
and runs TS route hooks; schema owner populates `FieldSchemas`; live
MySQL/MSSQL wire conformance; rate-limit table migration.

Committed as `0ceea64` ("feat(auth): complete Wave 1 parity foundations",
78 files, +16811/−912). Full gate green: diff-check, build, vet,
tests, race. 602 named tests, 61.8% statement coverage.

### Wave 2: core runtime behavior — DONE

All four agents accepted and merge gate passed (diff-check, build, vet,
full tests, 10× stress on routes/cookies/oauth2, race). 702 named tests,
64.4% statement coverage.

- Agent A (session + cookies): JWT/JWE session-cache strategies with
  binding/rotation, remember-me mint/clear, expired-row deletion,
  secondary creation mirroring, secondary-aware sign-out, `*Full`
  update-field migration, no-store/freshness gates, sign-in/up response
  parity. Open: custom-session plugin (nonexistent), stateful
  refresh-default deviation, cross-language fixtures.
- Agent B (account/password/email): request-aware callbacks,
  background-task timing, HS256 issuance with HMAC fallback, secondary
  verification modes, transactional delete consume, account-info parity,
  update-user matrices. Justified breaks: delete-account prefix, HS256
  wire tokens, non-500 delivery failures. Open: stateless TS-JWT legs,
  link-social idToken flow, `*Full` update-user parsing.
- Agent C (framework): full `AuthContext` services, local telemetry
  publish, request state, per-request BaseURL resolution, conflict
  detection, slash variants, header-ordering fix, logger levels, DBHints
  validation, GenerateID resolver, `OnAfterCommitHookError` option,
  named-endpoint + TS-hook consumption, `FieldSchemas` population.
  Open: handler adoption of per-request BaseURL/GenerateID, live-DB
  conformance.
- Agent D (oauth2): opt-in `auth_time`, request-aware verifiers, exact
  error normalization, DPoP client primitives + proofs, JWKS
  singleflight, size limits, cross-language state reads, atomic DB
  consume, serverContext support API. Open: discovery caching by design,
  TS-spelling writes (migration decision).
- Merge facilitation: deduped `stripPort` (kept lenient shared version),
  restored it after Agent C's refactor dropped the definition.

Committed as Wave 2 (`94cea44`). Follow-ups carried to Wave 3+:
`serverContext` producer, handler-side BaseURL/GenerateID adoption,
stateless TS-JWT legs, creation-path DB-skip for secondary-only.

- Agent B (account/password/email) ACCEPTED: request-aware callbacks via
  rebuilt huma requests, background-task timing, HS256 email-JWT issuance
  with HMAC read-only fallback, secondary verification + store-identifier
  + cleanup modes, transactional delete-token consume with shared
  finish path, account-info token parity, update-user matrices.
  Verified: routes suite green (20 new tests, race-clean), no weakening.
  Justified breaks: `delete-account:` prefix, HS256 wire tokens,
  non-500 delivery failures. Open: stateless TS-JWT change-email legs,
  link-social idToken flow, `*Full` update-user parsing.
- Merge facilitation: deduped `stripPort` (rate_limiter.go vs api/index.go
  concurrent declarations, kept the lenient shared version) to unblock
  the tree build.
- The only failing tests in-tree are Agent C's own new
  `framework_wave2_test.go` cases against its in-progress framework code
  (C still running) — not regressions from A/B/D.

- Agent D (hooks + plugin runtime) ACCEPTED: hook-merge semantics, bulk
  after-hook counts, post-commit error propagation with handler, adapter
  overrides, field validator/transform execution, named endpoints + TS route
  hooks collection, TS endpoint-context pipeline. Verified in-tree (build,
  vet, 17 hook tests + types/routes suites green; one test rename reflects
  the intended merge-behavior change). Left for owners: `index.go` should
  adopt `NewHookedAdapterWithOptions`, `api/index.go` should register named
  endpoints and run TS route hooks, schema owner should populate
  `FieldSchemas`.
- Agent C (schema + migrations) ACCEPTED: full-vs-legacy schema split
  (`FullSchema`, additive `*Full` route helpers, no behavior flip),
  timestamp func-defaults carried, full index validation, plugin-schema
  registry + CLI support, dialect DDL + executable migration plans.
  Verified in-tree (build, vet, generator suite + schema/field tests green).
  Route rewiring to the `*Full` helpers belongs to route owners (Wave 2).
  The 3 remaining failures in root/routes suites are Agent A's area
  (rate-limit/secondary-storage, still in flight) — to confirm at merge gate.
- Agent A (secondary storage + rate limiting) ACCEPTED: secondary session
  runtime with flag matrix, secondary verification storage, atomic DB
  rate-limit backend wired into middleware, startup rejection narrowed to
  flags-without-backend, production-default enablement, custom rule
  resolvers, proxy-aware plugin-rule IPs. Verified in-tree (build, vet,
  full api + root suites green including the 3 previously failing tests;
  one test setup addition, no assertion changes). Transitional deviations
  recorded: creation paths still DB-only with backfill, preserve-mode
  deletes fire update hooks, plugin buckets stay memory two-phase.

### Wave 5: truth reset and framework contracts — DONE

All four agents accepted and merge gate passed (diff-check, gofmt, build,
vet, full hermetic tests, race on root/types/testutil). 967 Test funcs
across 16 packages (was 930 across 15; +testutil).

- AUTH-R5-01 (ledger) ACCEPTED: `parity_ledger.json` manifest (pin, 30 core
  routes, 17 OAuth helper paths, 36 providers, 14 pending markers, 73
  upstream test files with 2046 case names + dispositions), 8 drift-guard
  tests, `PARITY.md` ledger section + 51 backlog rows tagged with
  completion/owner references. Default disposition open (54 partial, 16
  open, 3 not-applicable); 26 cases claimed covered with Go test names.
- AUTH-R5-02 (options) ACCEPTED: all 14 `Runtime: pending` markers proven
  truly pending against consumers; 2 stale comment wordings fixed
  (zero behavior change); `types/marker_audit_test.go` ledger pins count +
  membership; 23-item implementation queue (Q1–Q23) delivered for Waves
  6–9, including dead-duplicate removal candidates (Q2/Q5/Q11/Q12).
- AUTH-R5-03 (decisions) ACCEPTED: 17 decisions D01–D17 pinned by
  `decisions_test.go` (17/17 pass); JAR/JARM confirmed NOT a parity task
  (pinned `request_not_supported`); D05/D06/D16 writer cutovers queued to
  Waves 6–7; D07/D12 queued to D6-01/P8-03. Main agent applied the decision
  registry + stale-summary corrections to `PARITY.md` (HS256 issuance, JWE
  wired, secondary-storage matrix).
- AUTH-R5-04 (fixtures) ACCEPTED: `testdata/` (12 vectors + provenance),
  `scripts/gen-fixtures.sh` + Go generator, `testutil/` hermetic suite
  (11 pass + subtests, live smoke opt-in only); Kick hermetic pins
  (default scope, endpoints, array userinfo, accountSubject, emailVerified
  false).

Follow-ups carried forward: Waves 6–9 implementation queue (Q1–Q23);
AUTH-S6-01 owns D05 throw-vs-keep; Wave 7 owns D06/D16 writer cutovers;
AUTH-D6-01 owes live MySQL/MSSQL runs; AUTH-P8-03 owns D12 function options.

### Wave 6: framework, schema, storage, and adapter closure — DONE

F6-01 landed first (shared `index.go`), then F6-02/F6-03/S6-01/D6-01 ran
concurrently on disjoint ownership. Merge gate passed (diff-check, gofmt,
build, vet, full hermetic tests, race on root/api/db/types, live PG serial
green on all 16 packages). 1050 Test funcs (was 967).

- AUTH-F6-01 (context) ACCEPTED: per-request BaseURL authoritative for
  route builders (9 direct-read sites replaced, static fallback kept),
  always-on request-context middleware (state, stored request, endpoint
  metadata), trusted `serverContext` producer (client input can never
  inject), dynamic secure-cookie inference, `WithSpan`/`RunInBackground`
  plumbing, concurrent two-host isolation tests. Open for route owners:
  remaining `StoredRequestFromStd` adoption, plugin `EffectiveBaseURL`
  opt-in, full context-threaded cookie issuance (C7-01), OTEL wiring (done
  as passthrough; F6-03 exclusion).
- AUTH-F6-02 (IDs) ACCEPTED: `types.MintModelID` single source of truth
  (custom/model+size, uuid, serial), mechanical migration of model-row
  creates (sign-up/in, social, account, password, email, admin, jwt,
  organization, oauth2 state rows); tokens stay random per upstream.
  Secondary-only creation skips the primary DB with failure matrices.
  Open: 15 `crypto.GenerateID()` sites in `plugins/oauthprovider/**`
  deferred to Wave 9; secondary-only hook execution decision for Wave 7.
- AUTH-F6-03 (init) ACCEPTED: pinned defu semantics + overwrite order +
  trusted-origin composition, exact secret diagnostics/rotation, telemetry/
  instrumentation contracts with explicit no-network exclusion, 28 focused
  tests. BREAKING: `Options.DBHints`/`DatabaseHints` removed (the four
  selectors configure the Kysely factory with no Go consumer); tests updated
  without weakening.
- AUTH-S6-01 (schema) ACCEPTED: `GetSchema`/`InputFields`/`OutputFields`
  single-schema pipeline with additive `Full*` route targets (no behavior
  flip), `ValidateUserInfo` seams with exact redirect-vs-403, additional-
  field pipeline vs `to-zod.test.ts`. DECISION D05 aligned to throw:
  non-transactional after-hook failures now propagate (write stays
  committed). Route rewiring belongs to Wave 7.
- AUTH-D6-01 (storage) ACCEPTED: generic `TransactionResult`,
  `CreateSchemaCheck` port, atomic `ConsumeResolvedRateLimit` for global
  and plugin buckets, rate-limit table migrations/goldens, PG per-test
  isolation (parallel-safe), transaction/savepoint tests, MSSQL `OUTPUT`
  registered as intentional exclusion with persisted-row fallback. Live PG
  serial green; MySQL/MSSQL remain wire-conformance only (no drivers/
  servers here).

Follow-ups carried to Wave 7+: `Full*`/`AssertValidUserInfo` route adoption,
outgoing `ValidateUserInfo` seams, context-threaded cookie issuance, plugin-
bucket middleware call-site wiring, secondary-only hook execution, live
MySQL/MSSQL runs, oauthprovider ID adoption (Wave 9).

### Wave 7: core routes, cookies, crypto, OAuth client, and providers — DONE

All four lanes accepted and merge gate passed (diff-check, gofmt, build,
vet, full hermetic tests, race on api/oauth2/social-providers/cookies/
crypto, live PG serial green except one pre-existing 1/16 test flake fixed
in-gate). 1110 Test funcs (was 1050). Pending markers 14→12 (two
AccountSubject markers flipped to wired with execution evidence).

- AUTH-C7-01 (sessions) ACCEPTED: upstream `session_data` name + chunk/
  custom-name recovery reads, custom JWKS signer path with claim binding +
  authoritative fallback, context-aware secure/domain issuance incl.
  `AdditionalCookies` domain, DB-nil stateless guard, no-store headers,
  deferred expired-row cleanup, TS-fixture JWT/JWE route interop
  (rotation, binding, malformed limits, wrong/stale rejection). Open:
  chunked multi-cookie writes, preserve-mode delete-hook primitive.
- AUTH-C7-02 (credentials) ACCEPTED: every core route test file ported by
  case; `OnExistingUserSignUpRequest` precedence, `ValidateUserInfo` seams,
  `ParseUserInputFull` update parsing, transactional create, stateless
  email-JWT legs, background delivery, upstream-ordered change-password +
  additive session revocation, stored-request trust. Open: link-time seams
  (social owner), Huma-struct body limits, `setPassword` server-only.
- AUTH-C7-03 (oauth2) ACCEPTED: signup gating (Q7), local-email gate (Q20),
  email promotion/overwrite (Q8), per-provider email gate (Q9), account-
  subject resolution with fallback (Q15), request-aware verifiers, 10 new
  tests. Dead-type removals deferred to the R5-02 follow-up (existing
  consumers assert them); array `clientId` explicitly excluded.
- AUTH-C7-04 (providers) ACCEPTED: 20 standard `*WithOptions` surfaces,
  shared override forwarding (Q1/Q3/Q4/Q10), gate advertisement on caps,
  WeChat openid carriage, exact error-page port (XSS removed), 33 provider
  fixtures + 36-provider matrix test. Open: Q2/Q6 removals for types owner.
- Merge facilitation: fixed pre-existing 1/16 flake in
  `TestEncryptedTokenRoundTripRotationAndTampering` (fixed "0" tamper prefix
  collides when the token starts with "0"); formatted
  `session_c701_test.go`; rewrote 10 stale `PARITY.md` rows from Wave 7
  evidence.

Follow-ups carried to Wave 8+: dead-duplicate removals (Q2/Q5/Q11/Q12),
chunked writes, preserve-hook primitive, link-time seams, live MySQL/MSSQL,
oauthprovider ID adoption + protocol closure (Wave 9).

### Wave 8: Admin, JWT, Organization, and OAuth Provider surface — DONE

All four lanes accepted and merge gate passed (diff-check, gofmt, build,
vet, full hermetic tests, plugins race, live PG serial green on all 16
packages). 1214 Test funcs (was 1110; 291 in plugins).

- AUTH-P8-01 (admin) ACCEPTED: strict-roles opt-in flag (D09 default
  preserved), custom schema merge, username validation with all 5 codes,
  session-route impersonation filtering, `validateUserInfo` admin gate,
  `banExpiresIn:0` falsy exactness; both upstream test files ported by case
  (34 new tests). Open: banned social/id-token harnesses, server-call-only
  shapes (401 verified), client-only its (N/A).
- AUTH-P8-02 (jwt) ACCEPTED: all-keys verify (no grace filter/mint),
  `image` + additional-field claim spread, all four upstream test files
  ported (~40 tests) with TS↔Go fixtures and live-PG rotation tests.
  Open: `jwtClient` types (N/A), serverOnly HTTP (methods exposed; 404
  tested).
- AUTH-P8-03 (organization) ACCEPTED: function-valued options (D12 closed),
  strict role errors, shapes alignment, transactional remove-member with
  rollback; all nine upstream test files ported or classified (client-only
  N/A). D10/D11 stay explicit exclusions pinned by tests. Open: org-creation
  DB-hook test (core owner).
- AUTH-P8-04 (surface) ACCEPTED: complete `OAuthOptions` diff with all
  expressible surface added (resources/seed/PKCE/signup/format/storage/
  extensions/prefixes/metadata/contexts), executable manifest (8 tests)
  freezing defaults, endpoint catalog (36 entries), schema coverage, D17
  request-object rejection, and the 4 `wave9EndpointGaps` for Wave 9.
  Main agent rewrote the 4 plugin rows + D12 decision from Wave 8 evidence.

Follow-ups carried to Wave 9: wire every declared-but-inert surface
(seeding, PKCE opt-out, continuation hooks, refresh format, custom stores,
prefixes/generators, extension dispatch, Resources/RequestedClaims); close
the 4 frozen endpoint gaps with manifest updates; port grant/token/
introspection/revoke/private-key-JWT/DPoP/registration/CRUD/metadata/
userinfo/logout/extension tests by case.

### Wave 9: OAuth Provider protocol closure — DONE

All four lanes accepted and merge gate passed (diff-check, gofmt, build,
vet, full hermetic tests, oauthprovider race, live PG serial green after
one stale-test update). 1303 Test funcs (was 1214; 180 in oauthprovider).

- AUTH-O9-01 (authorize) ACCEPTED: upstream-exact PKCE policy, continuation
  hooks, consent `claims` narrowing, strict continue branches, trust-
  resolving error redirects, loopback matching, `POST /oauth2/authorize`
  (frozen gap closed with manifest update). Fixed the consent
  `requestedUserInfoClaims` column misspelling. Request objects stay
  rejected (D17).
- AUTH-O9-02 (token) ACCEPTED: custom secret/token stores, refresh
  formatting, prefixes/generators, extension grants + client-auth, sender
  constraints, claim context, HS256 ID tokens without JWT, exact revocation
  semantics, concurrent redemption tests (15 new tests). No endpoint gaps
  closed.
- AUTH-O9-03 (registration) ACCEPTED: #8588-exact DCR defaults, scope
  union, PKCE policy, seed/cache/update modes, privileges, CRUD matrices
  (23 new tests). `OAuthClient.metadata` spread blocked on client owner.
- AUTH-O9-04 (metadata) ACCEPTED: capability-derived discovery, `POST
  /oauth2/userinfo` (frozen gap closed), full logout, generic extension
  contract + device-code composition (fail-closed without a device plugin).
  `POST /oauth2/end-session[/confirm]` behavior done, catalog entries
  frozen with reason (needs `register.go` change).
- Merge facilitation: fixed `requested_user_info_claims` spelling in
  crud.go/token.go (consistency with authorize/resource); gofmt-aligned
  O9-02 struct drift; updated the stale `TestRegister_Unauthenticated
  PublicClient` to upstream #8588 behavior (omitted method → confidential;
  added explicit-`none` public test); rewrote 8 oauthprovider `PARITY.md`
  rows from Wave 9 evidence.

Follow-ups carried to Wave 10: `OAuthClient.metadata` spread, `jwks_uri`
SSRF guards, `WWW-Authenticate` headers, full custom auth-code hashing,
strict client-credentials scopes, device-code exchange plugin, extension
capability surface on token paths.

### Wave 10: closure audit and release gate — DONE

The re-audit returned NOT-READY with 4 blockers; all are closed below.
Merge gate passed (diff-check, gofmt, build, vet, full hermetic tests,
full race, merged 75.8% coverage profile, live PG serial green on all
packages). 1355 Test funcs + 30 fuzz targets.

- AUTH-V10-01 (re-audit) ACCEPTED as the work list: F2 (OAuth IDs bypassed
  generator), F3 (static BaseURL in OAuth builders), F5 (claim-column
  spelling), F6 (manifest/catalog gaps), F9 (status table), plus polish
  F1/F4/F7/F8/F10–F12/F15–F17. False alarms confirmed (D02/D03, D17,
  catalogs, pin).
- Blockers closed: F2 — all 10 OAuth model-row IDs flow through
  `types.MintModelID` (tokens stay random with upstream cites);
  F3 — request-resolved baseURL threaded through issuer/error/metadata/
  audience builders with static fallbacks + two-host test; F5 — triple
  claim-column spelling unified; F6 — POST end-session/confirm promoted to
  standalone catalog entries, gaps emptied, catalog↔mount test added.
- AUTH-V10-02 (adversarial) ACCEPTED: 28 tests + 16 fuzz targets, full race
  green, both-direction goldens, 30/30 fuzz targets building.
- AUTH-V10-03 (live DB) ACCEPTED: live PG serial green + isolation/migration
  matrices; production contention bug fixed (ctid-guard stale recovery +
  row-lock slow path); MySQL/MSSQL wire-only (no drivers, intentional).
- Wave-10 merge facilitation: metadata envelope (spread/strip/merge,
  upstream client-metadata.ts), preserve-mode delete hooks
  (`EndPreservedSessions`), atomic plugin-bucket consume, social
  ValidateUserInfo/link/profile/resend seams, post-commit hook-code
  surfacing, 7→0 pending markers (4 wired, 3 excluded), tamper-test flake
  fix, consent-column consistency, #8588 test alignment, F11/F12
  annotations.
- V10-04 (evidence): PARITY.md has zero Partial/Close rows, zero P-rows,
  zero pending markers (7 explicit exclusions), decision + Wave-10
  exclusion registries, rewritten audit sections, 75.8% merged coverage.

Final gate (from `auth/`, all passing): `git diff --check`, empty
`gofmt -l`, `go build ./...`, `go vet ./...`, hermetic + race
`go test ./...`, live PG `go test -p 1 ./...`, zero `**Partial`/`**Close`
rows, zero `^| P[012]` rows, zero non-test `Runtime: pending` markers
(test files reference the phrase only inside the guards asserting zero).

Recovery note: AUTH-F6-01's files were found stashed (`f6-wip`, a sibling
agent stashed them seeking a clean tree) and absent from the Wave 6 commit.
They were re-applied by merge (only `index.go`/`social.go` overlapped, both
auto-merged cleanly), re-gated (build, vet, hermetic, api race, 10 F6-01
tests green), and committed as the Wave 6 fixup below. Lesson for later
waves: agents must never `stash`/`reset`/`clean` the shared tree; use
`git worktree` or `/tmp` copies for isolation.

## Parity closure review and Waves 5–10

This section supersedes the old `Later-work backlog` as the active plan. It
was prepared after Waves 1–4 and live PostgreSQL verification at commit
`6757fec7`. The target remains exactly Better Auth v1.7.5 at the pinned
submodule commit; later upstream behavior is out of scope.

### Review result

The current implementation is substantially ahead of the prose in
`PARITY.md`, but it cannot yet support a defensible all-**Done** claim.

Verified baseline:

- Hermetic full-module tests pass in all 15 packages.
- Live PostgreSQL passes serially (`-p 1`) in all 15 packages.
- 930 named tests and 72.9% statement coverage are the current recorded
  baseline. Counts and coverage are diagnostics, not completion criteria.

The review found four classes of work:

1. **Stale audit claims.** The backlog still lists completed Waves 1–4 work
   (secondary storage, persisted-row `Create`, hook merging, JWT/JWE cache,
   private-key JWT, atomic invitations, and more). Some summaries also say
   email verification still writes HMAC and JWE is fail-closed, while the
   runtime now writes HS256 and issues/verifies JWE cookies.
2. **Accepted-but-ignored public options.** There are 14 explicit
   `Runtime: pending` markers. Important examples are `ValidateUserInfo`,
   account-link profile updates/local-email verification, account cookies,
   extra cross-subdomain cookies, and the request-aware duplicate-sign-up
   callback.
3. **Context adoption gaps.** The framework resolves request BaseURL and ID
   services, but production code still has 13 direct `opts.BaseURL` reads in
   route builders and 54 direct `crypto.GenerateID()` calls. OAuth
   `serverContext` storage APIs exist, but core routes do not produce the
   plugin/request context upstream stores.
4. **Conformance depth.** The largest unaudited area is OAuth Provider (41
   pinned upstream test files), followed by core route matrices, complete
   option/default matrices, cross-language JOSE/cookie vectors, and live
   MySQL/MSSQL behavior.

The old OAuth backlog also overstates work: pinned upstream explicitly
rejects OIDC request objects with `request_not_supported`; “implement JAR” is
therefore not a parity task. Every planned feature must be proven from the
pinned source/tests before implementation.

### Closure ledger rules

Every active item below has a stable ID. Before changing implementation, add
an entry for the ID to the parity ledger in `PARITY.md` containing:

- owned Go files and exact pinned TS source/test files;
- upstream test cases classified as **ported**, **covered-equivalently**,
  **not applicable** (with reason), or **open**;
- public options/defaults, persistence/wire formats, statuses, headers, hook
  order, transaction behavior, and security invariants in scope;
- intentional deviations and their migration/compatibility rationale;
- failing Go test names added before implementation;
- validation commands and commit hash after acceptance.

An item is complete only when no upstream test remains **open**, no accepted
option in scope is silently ignored, and its `PARITY.md` rows are rewritten
from current code evidence. A high coverage number or matching route name is
not evidence by itself.

### Wave 5: truth reset and framework contracts

Wave 5 prevents more implementation against stale claims. Run tasks in
parallel only where ownership is disjoint.

#### AUTH-R5-01 — machine-checkable source/test ledger

**Owns:** `PARITY.md`, a new manifest/test under `auth/` if useful; no runtime
files.

- Enumerate every mapped Go file/package and pinned TS implementation/test
  file for core, the 36 social providers, Admin, JWT, Organization, and OAuth
  Provider.
- Record every upstream test case disposition. Preserve the intentional
  exclusion of unrelated first-party plugins; do not silently expand scope.
- Add checks that the pinned commit/version, endpoint catalog, provider
  catalog, explicit `Runtime: pending` markers, and ledger IDs cannot drift.
- Remove historical completed tasks from the active `PARITY.md` backlog.

#### AUTH-R5-02 — public option and marker audit

**Owns:** `types/**`, option declarations in plugin packages, marker tests.

- Reconcile all 14 `Runtime: pending` markers and all “accepted/preserved,”
  “types only,” and “faithful subset” claims against real consumers.
- Compare every exposed option with the pinned default, nil semantics,
  callback context, validation, and runtime call site.
- Remove dead duplicate surfaces (or deprecate them with a migration) rather
  than marking unused compatibility structs Done.
- Produce the exact implementation queue for Waves 6–9; no marker changes to
  `wired` without an execution test.

#### AUTH-R5-03 — decision and deviation registry

**Owns:** `PARITY.md`, public migration notes, decision tests only.

Resolve each existing decision as either align-now or intentional exclusion:

- `Options.DB` naming, random-ID alphabet, PKCE plain mode, IDNA/punycode;
- non-transactional after-hook error behavior and TS-spelling state writes;
- MSSQL `OUTPUT inserted`, unregistered OAuth audiences, admin role strictness;
- organization AC-absent leniency/add-member HTTP superset/function options;
- verify-email POST alias and bounded legacy token/password reads.

Recommended default: preserve source/API-compatible Go deviations only when
they do not weaken security or make an accepted option inert. Wire/storage
differences require migration reads, an explicit writer cutover, and fixtures.

#### AUTH-R5-04 — upstream test harness and golden generation

**Owns:** test helpers/fixtures and scripts only.

- Add a repeatable fixture path that generates pinned TS vectors with `pnpm`
  and targeted `vitest` commands (never the full upstream suite).
- Generate state, email JWT, XChaCha, session JWT/JWE, JWK/JWKS, OAuth error,
  cookie, and provider-profile fixtures where wire compatibility matters.
- Check fixture provenance (upstream file, test, commit, generation command)
  into the repository.

**Wave 5 exit:** all current `PARITY.md` claims are current or explicitly
tagged with an active ID; every later task has a complete upstream test list;
the standard hermetic gate remains green.

### Wave 6: framework, schema, storage, and adapter closure

#### AUTH-F6-01 — request context and dynamic BaseURL

**Owns:** `index.go`, `api/index.go`, `api/routes/hooks.go`, context helpers.

- Make the resolved per-request BaseURL authoritative for downstream route
  handlers, cookies, callbacks, errors, redirects, issuer/audience values,
  and plugin endpoint context.
- Carry the real request, endpoint metadata, response mutation, request state,
  logger/instrumentation services, and background tasks through the complete
  middleware pipeline.
- Produce OAuth `serverContext` from trusted plugin/request context and expose
  it to route owners; client input must never be able to inject it.
- Port `api/index.test.ts`, dispatch/call tests, context-init tests, conflict
  tests, origin tests, and instrumentation endpoint tests.

#### AUTH-F6-02 — ID generation and creation seams

**Owns:** `index.go` ID service plus a mechanical, reviewed migration of
production create call sites; excludes OAuth Provider internals until Wave 9.

This task starts after AUTH-F6-01 lands because both touch `index.go`.

- Replace all 54 direct production `crypto.GenerateID()` bypasses where the
  upstream context generator applies; preserve token/non-model randomness
  where upstream does not call `generateId`.
- Honor serial/UUID/custom generation, model and size arguments, adapter-
  generated IDs, and persisted-row return values.
- Make secondary-only session/verification creation skip the primary DB where
  upstream does, including rollback/failure matrices.

#### AUTH-F6-03 — initialization, secrets, telemetry, and instrumentation

**Owns:** `init_patches.go`, `secrets.go`, telemetry/instrumentation helpers,
and focused root tests.

- Port pinned `defu` merge semantics, plugin context overwrite order, nested
  option patches, and dynamic trusted-origin composition.
- Match default/production secret lookup, versioned env JSON, entropy
  diagnostics, warnings, and rotation failure behavior exactly.
- Replace local-placeholder telemetry/instrumentation behavior with the pinned
  contracts, or register network publication as an explicit privacy/platform
  exclusion while preserving event shape, disable controls, and hooks.
- Make `DBHints` affect applicable adapter/runtime behavior rather than merely
  validating and preserving inert values; remove unsupported fields otherwise.
  (Closed in Wave 6: removed — the four selectors configure the Kysely
  factory with no Go consumer; `Options.DBHints` deleted with revival policy
  in AUTH-F6-03.)

#### AUTH-S6-01 — full schema and identity admission pipeline

**Owns:** `schema.go`, `api/routes/schema_fields.go`, `hooked_adapter.go`, and
schema-specific tests. Route adoption is coordinated through explicit helper
APIs consumed in Wave 7.

- Remove the legacy/full ambiguity: one resolved schema must drive adapter
  mapping, route input, output filtering, validators, transforms, aliases,
  required/input/returned flags, hooks, migrations, and plugin fields.
- Implement `ValidateUserInfo` at every create/link/sign-in seam with exact
  browser redirect vs API 403 behavior.
- Verify additional-field defaults, transforms, validators, nullability,
  aliases, update behavior, and output stripping against `to-zod.test.ts` and
  core schema tests.
- Decide and test upstream throw behavior for non-transactional after-hooks.

#### AUTH-D6-01 — database, migration, and rate-limit foundations

**Owns:** `db/**`, `adapters/bun/**`, `cmd/generate-schema/**`, migration
runner/schema-check code, and database rate-limit storage.

- Add the rate-limit table to schema/migrations and make plugin buckets use
  the selected atomic backend rather than the memory-only two-phase path.
- Match pinned fixed/sliding-window rollover, retry-after, failed-request,
  custom resolver, and storage-error semantics under concurrency.
- Finish generic transaction result/sequential fallback behavior without
  breaking `HookedAdapter`; test nested transactions and post-commit errors.
- Implement runtime migration/schema-check services promised by context, with
  safe startup/request behavior and no implicit destructive migration.
- Isolate PostgreSQL tests per schema/database so default parallel package
  execution is reliable.
- Add live MySQL and MSSQL contract/migration/atomic/fallback runs; either
  implement MSSQL persisted-row behavior or register the exact intentional
  exclusion.

**Wave 6 exit:** zero framework-level pending options; zero applicable direct
ID-generator bypasses; dynamic BaseURL tests exercise two hosts concurrently;
initialization/secret/telemetry behavior is aligned or explicitly excluded;
all schema/storage contracts pass hermetic, race, PostgreSQL, MySQL, and MSSQL
gates where applicable.

### Wave 7: core routes, cookies, crypto, OAuth client, and providers

Four package-owned lanes may run concurrently after Wave 6.

#### AUTH-C7-01 — sessions, cookies, and JOSE cache

**Owns:** `api/routes/session*.go`, `api/routes/sign_out.go`, `cookies/**`,
session-cache crypto helpers.

- Close stateful/stateless refresh defaults, freshness/no-store semantics,
  preserve-mode hooks, expiration cleanup, secondary-only behavior, and exact
  list/revoke/update response matrices.
- Wire JWT plugin `sessionCookieCache` as the route-side custom signer/verifier
  path, including key rotation, claim binding, and authoritative fallback.
- Finish extra cross-subdomain cookie propagation, cookie-name/chunk recovery,
  dynamic secure/domain behavior, and all pinned cookie vectors.
- Prove JWT/JWE interop with TS-produced vectors, malformed limits, wrong/stale
  key rejection, and rotation. Remove stale comments claiming JWE is absent.

#### AUTH-C7-02 — credential, user, account, email, and password flows

**Owns:** `api/routes/sign_in.go`, `sign_up.go`, `account*.go`,
`delete_user_callback.go`, `email_verification.go`, `password*.go`.

- Adopt Wave 6 full-schema parsing and request context throughout.
- Wire `OnExistingUserSignUpRequest`, all request-aware callbacks,
  `ValidateUserInfo`, account-link profile update/local verification, account
  cookie storage, and account cookie options.
- Close stateless email-JWT change-email/delete/reset legs, cleanup flags,
  rollback transactions, callback/background timing, anti-enumeration timing,
  response variants, hook order, statuses, and headers.
- Migrate remaining writers to pinned upstream formats while retaining only
  bounded, documented legacy reads.
- Port every test case from the ten pinned core route test files, not only the
  happy paths.

#### AUTH-C7-03 — social routes and OAuth/OIDC client

**Owns:** `api/routes/social.go`, `oauth2/**`, route-facing provider interfaces.

- Consume the real request and serverContext producer in sign-in, callback,
  linking, ID-token, and custom-verifier paths.
- Consume discovery/token-auth/account-subject capabilities instead of leaving
  parallel config-only paths; remove or deprecate duplicate unused types.
- Finish discovery/JWKS live-style interop, claim tolerance, cache eviction,
  DB-state concurrency, auth_time branches, refresh/revoke/userinfo errors,
  private-key-JWT and DPoP vectors, and Go-write/TS-read state fixtures.
- Pin all limits and algorithms; malformed keys/tokens must fail closed.

#### AUTH-C7-04 — 36-provider matrix and API presentation

**Owns:** `social-providers/**` plus `api/routes/error.go`; no OAuth core
changes.

- Verify every provider option/default, auth URL, token transport, discovery,
  ID-token policy, profile mapping, stable account subject, and error mapping.
- Resolve WeChat openid carriage and remaining provider transport deviations.
- Add hermetic discovery/profile/JWKS fixtures for all providers that use
  those paths; optional opt-in live smoke tests must never gate normal CI.
- Port the configurable error page exactly (safe parameters, rendering,
  colors/font/size, snapshots) or document the Go-native response as an
  intentional presentation exclusion.

**Wave 7 exit:** every core route/cookie/crypto/OAuth/social row is Done or an
approved intentional exclusion; all 14 initial pending markers are gone or
removed with their dead surface.

### Wave 8: Admin, JWT, Organization, and OAuth Provider surface

#### AUTH-P8-01 — Admin plugin closure

**Owns:** `plugins/admin/**`.

- Port every `admin.test.ts` and `admin-username.test.ts` case.
- Finish username-plugin validation, session impersonation filtering, custom
  schema, all option combinations, exact response/error/session behavior, and
  strict admin-role semantics (or register the compatibility deviation).

#### AUTH-P8-02 — JWT plugin closure

**Owns:** `plugins/jwt/**`.

- Complete the claim/default/header matrix, session-cookie-cache route
  integration contract, custom sign path, adapter/schema overrides, remote
  JWKS, persisted-key migrations, and multi-alg rotation/grace behavior.
- Port all four pinned JWT test files plus TS↔Go key/token fixtures and live
  PostgreSQL rotation tests.

#### AUTH-P8-03 — Organization plugin closure

**Owns:** `plugins/organization/**`.

- Port all nine pinned organization test files by case.
- Implement function-valued options and remaining callback/response matrices.
- Resolve AC-absent leniency, add-member superset, shapes, strict role errors,
  and all team/member/invitation races through alignment or explicit exclusion.

#### AUTH-P8-04 — OAuth Provider public surface freeze

**Owns:** `plugins/oauthprovider/oauthprovider.go`, schema/type declarations,
and a generated option/endpoint/extension manifest. Do not edit protocol
handlers in this task.

- Diff the complete pinned `OAuthOptions`, schemas, endpoint catalog,
  extension API, and defaults against Go.
- Add the missing expressible surface before handler work: resource seeding
  and cache modes, PKCE registration policy, signup/select-account/post-login,
  refresh/token formatting, custom secret/token storage, extension hooks,
  advertised metadata, and callback contexts.
- Classify request objects correctly as unsupported upstream; do not invent
  JAR/JARM behavior absent from v1.7.5.

### Wave 9: OAuth Provider protocol closure

Freeze shared option/helper contracts in AUTH-P8-04 first, then use four
disjoint handler lanes.

#### AUTH-O9-01 — authorization, consent, and continuation

**Owns:** `authorize.go`, claims/consent/continuation/signed-query helpers and
tests.

- Complete prompt/max_age/nonce/ACR/claims, pairwise subjects, loopback URI,
  PKCE optional/required policy, request_uri resolution, signup,
  select-account, post-login continuation, consent references, no-store, and
  the full redirect/error matrix.

#### AUTH-O9-02 — token, client authentication, and sender constraints

**Owns:** `token.go`, `client.go`, `private_key_jwt.go`, DPoP/rotation,
introspection/revocation handlers and tests.

- Port grant/token/introspection/revoke/private-key-JWT/DPoP tests by case.
- Complete custom secret/token storage, refresh formatting, auth methods,
  extension grants, concurrent code redemption, refresh-family replay,
  resource carryover, sender constraints, token revocation, and HS256 ID-token
  behavior when JWT is disabled.

#### AUTH-O9-03 — registration, CRUD, clients, and resources

**Owns:** `register.go`, `crud.go`, `resources.go` (plural), client/resource
admin endpoint helpers and tests. `resource.go` (singular) belongs to
AUTH-O9-04.

- Complete client metadata/JWKS/software-statement validation, initial access
  tokens, secret rotation, privileges, default/allowed scopes/resources,
  resource seed/cache/update modes, strict audience migration, resource
  challenges/binding, and all CRUD consistency/race tests.

#### AUTH-O9-04 — metadata, userinfo, logout, and extensions

**Owns:** `metadata.go`, `resource.go` userinfo portions, `logout.go`, and new
extension/device-flow files.

- Make discovery/protected-resource metadata derive exactly from enabled
  capabilities.
- Complete standard/custom claims and userinfo authorization.
- Complete confirmation, front-channel and back-channel logout, cookie
  clearing, fan-out, and redirect validation.
- Implement the pinned generic extension contract and device-code extension,
  or explicitly exclude extension packages from the declared OAuth Provider
  scope. An all-Done claim may not advertise extension support while ignoring
  it.

**Wave 9 exit:** every one of the 41 pinned OAuth Provider test files has no
open case in the ledger; all enabled protocol metadata describes actual
runtime behavior.

### Wave 10: closure audit and release gate

#### AUTH-V10-01 — independent file-by-file re-audit

- Reinspect every mapped pinned source file without relying on old notes.
- Search for pending/incomplete/faithful-subset claims, inert options, direct
  context bypasses, silent fallback, ignored errors, and test-only behavior.
- Verify each `Done` row from implementation and tests; downgrade any row with
  an unresolved finding.

#### AUTH-V10-02 — adversarial and cross-language conformance

- Run race/stress suites for session refresh, rate limits, state consume,
  authorization code consume, refresh rotation, invitation acceptance, key
  rotation, migrations, and hooks.
- Run all golden vectors in both directions where a wire/storage format is
  shared with TypeScript.
- Fuzz every parser/decoder and pin size/work limits for passwords, cookies,
  JOSE, state, redirects, where clauses, and registration metadata.

#### AUTH-V10-03 — live database matrix

- Run the shared adapter, auth, migration, and plugin suites against SQLite,
  PostgreSQL, MySQL, and MSSQL with isolated schemas and parallel execution.
- Record exact skipped capabilities as intentional exclusions; a forced-label
  SQLite run is not live MySQL/MSSQL evidence.

#### AUTH-V10-04 — documentation and release evidence

- Rewrite `PARITY.md` so no **Partial**, **Close**, active backlog item, stale
  marker, or unclassified upstream test remains.
- Keep intentional exclusions narrow and explicit; list compatibility bridges
  with removal policy.
- Update auth docs for all behavior/default/migration changes.
- Store final command outputs, coverage, race/stress results, database matrix,
  pinned commit, and commit hashes in the progress log.

### Final all-Done gate

Run from `auth/`:

```bash
git diff --check
test -z "$(gofmt -l .)"

GOWORK=off go build ./...
GOWORK=off go vet ./...
env -u DATABASE_URL GOWORK=off go test -count=1 ./...
env -u DATABASE_URL GOWORK=off go test -race -count=1 ./...
env -u DATABASE_URL GOWORK=off go test -coverpkg=./... ./...

DATABASE_URL=... GOWORK=off go test -count=1 ./...
DATABASE_URL=... GOWORK=off go test -race -count=1 ./...
MYSQL_DATABASE_URL=... GOWORK=off go test -count=1 ./...
MSSQL_DATABASE_URL=... GOWORK=off go test -count=1 ./...
```

Additionally, all of these must be empty/true:

```bash
! grep -R "Runtime: pending" --include='*.go' .
! grep -R "faithful subset\|not wired\|accepted and preserved" --include='*.go' .
! grep -q '\*\*Partial\|\*\*Close' PARITY.md
! grep -q '^| P[012].*|' PARITY.md
```

The grep gates may be satisfied by removing obsolete/dead surface or by an
explicit intentional-exclusion annotation with a dedicated check; they must
never be satisfied by wording changes that hide unfinished behavior.

### Active immediate action

All waves complete. The tree is the parity release candidate — see the Wave
10 entry below for evidence. Next: cut lockstep module tags from the release
workflow when ready (`brick/`, `auth/`, `dsl/`).
