# Better Auth v1.7.5 → Go transpiler plan

## Goal and acceptance contract

Build a **repository-specific source-to-source transpiler** for the declared
server-side Better Auth scope, pinned to
`vendor/better-auth@5468e6bfcdff799848537cf5ad06ebab15aad9dd` (v1.7.5).
Generated Go must be executable production code, not just a route manifest or
empty files. A later upstream upgrade should be: update pin, regenerate, inspect
semantic changes, fix explicit unsupported constructs, run differential tests.

There are two different meanings of parity:

1. **Observable server parity (merge gate):** the same accepted inputs produce
   equivalent status, headers, JSON, cookies, redirects, persistence changes,
   side effects and concurrency behavior for every in-scope endpoint.
2. **Source/type parity (separate inventory):** each in-scope source construct
   has a generated counterpart, explicit handwritten lowering, or an approved
   Go-specific adaptation/exclusion. TS generic inference, browser clients,
   framework integrations, and adapter implementations are not Go runtime
   behavior and must not be counted as unimplemented endpoints.

Do not call the port 100% until both inventories are closed and the differential
gate passes. Compilation or a passing Go-only test suite does not establish
behavioral parity. Keep the current Go public API and standalone `auth` module;
breaking API changes require an explicit migration decision.

## Scope and authoritative inputs

- Scoped upstream files: `auth/BETTER_AUTH_SOURCE_TREE.md` if present, pinned
  `vendor/better-auth/packages/better-auth/src/`,
  `vendor/better-auth/packages/core/src/`, and
  `vendor/better-auth/packages/oauth-provider/src/`.
- Existing Go: `auth/src/` (including API, cookies, crypto, OAuth2, public
  types, Admin, JWT, Organization, OAuth Provider, and 36 social providers).
- Exclude Bun/other database adapter implementations, browsers, framework
  integrations, unrelated plugins, and build-only packages.
- Findings/fixtures: `auth/PARITY.md`, `auth/parity_ledger.json`,
  `auth/audit/*.md`, `auth/SOURCE_LAYOUT_MOVE_LIST.md`, and pinned upstream
  test files. Inventory paths should be discovered from the tree, not inferred
  solely from old documentation; the working tree may contain user changes.
- Follow `vendor/better-auth/AGENTS.md` when touching upstream tooling:
  `pnpm`, targeted Vitest runs, no modification of the pinned vendor source.

## Architecture

### 1. TypeScript front end

Use the pinned upstream's TypeScript compiler API (or a separately pinned
`typescript` dependency in an **auth-owned tooling workspace**). Do not parse
functions with regular expressions. The front end must resolve imports,
re-exports, aliases, generic instantiations needed at runtime, Zod schema
combinators, route declarations, plugin factories, and source locations.

The parser emits a versioned, deterministic intermediate representation (IR)
with source file, span, symbol, type information, defaults, endpoint metadata,
schema constraints, control-flow tree, operations and side-effect dependencies.
Keep a hash of each source node and of the entire pinned source inventory.
Represent `undefined`, `null`, absent property, empty string/array, and false
as **different IR values**. Retain ordered object-spread semantics and the
order of middleware/hook execution.

Suggested layout (tooling, not part of the runtime import graph):

```text
auth/transpiler/
  package.json                 # pinned TypeScript parser; pnpm lockfile
  src/scan.ts                  # scoped source inventory, exports/imports
  src/ir.ts                    # versioned AST/IR schema
  src/lower/                   # TS/Zod/endpoint/plugin lowering rules
  src/emit/                    # Go AST or deterministic Go source emitter
  src/diagnostics.ts           # fail-closed unsupported-node reports
  fixtures/                    # TS↔Go cross-language behavior vectors
  coverage.json               # generated/handwritten/excluded per symbol
auth/src/internal/tsruntime/   # only the semantics generated code requires
auth/src/.../*.gen.go          # generated production Go, Go API preserved
```

The TS parser is a build-time tool; generated Go must compile and run with
`GOWORK=off` and no Node dependency. Pin tooling versions and make generation
reproducible in a clean checkout.

### 2. Lowering rules (real code generation)

Translate a deliberately constrained subset of TS syntax into Go AST/source:

| TS construct | Go lowering requirement |
| --- | --- |
| `createAuthEndpoint`, middleware, route metadata | Huma/net/http registration and request lifecycle in the correct order |
| `z.object`, `z.union`, arrays, coercion, optional/default/nullish/refine | Generated input validation and distinct presence states; preserve Zod errors/status mapping |
| literals, objects, spreads, destructuring, arrays | Ordered field merging, explicit absent/null states |
| `if`, loops, ternary, `?.`, `??`, truthiness | Explicit Go control flow/semantic helpers; never conflate `||` with `??` |
| async/await and thrown `APIError` | `context.Context`, `(value, error)`, error body/status/header mapping |
| adapter calls, hooks, transactions | Calls through explicit Go service interfaces, preserving transaction and hook order |
| cookies, cryptography, URL operations | Calls into reviewed Go runtime helpers with fixture-backed wire parity |
| TS type-only exports/generics | Inventory as type-only; generate Go types only where the Go public contract needs them |

Use Go's `go/ast` and `go/format` or a deterministic template emitter whose
output is parsed and formatted by `go/parser`/`go/format`. Include source
location comments beside generated functions. No silent `any` fallback,
TODO-generated success path, unimplemented stub or default response.

### 3. Small semantic runtime

Introduce only helpers required by emitted code: JS truthiness, missing vs
null, `String(...)` coercion, property lookup, array join, URL/query encoding,
Date/time conversion, object spread, and explicit error propagation. Prefer
directly generated typed Go for common cases. Test helpers against a pinned TS
oracle; a generic JS interpreter embedded in Go would obscure parity and
slow reviews.

### 4. Handwritten intrinsics and boundaries

Some behavior cannot be emitted safely by syntactic translation (Huma,
database adapters, cryptographic primitives, request/response streaming,
background tasks). Treat these as **named intrinsics** with:

- upstream symbol and TS source span;
- Go implementation path and signature;
- TS↔Go fixtures asserting the intrinsic's behavior;
- explicit version and owner;
- a declaration in the transpiler coverage map.

Existing Go public types may remain facades. Do not force TS-only inference
helpers into runtime Go or move code across Go package boundaries if that
creates cycles. An adaptation is never recorded as mechanically translated.

### 5. Fail-closed diagnostics and coverage

For every in-scope runtime declaration, record one state:

`GENERATED`, `INTRINSIC`, `HANDWRITTEN_WITH_TEST`, `TYPE_ONLY_NA`, or
`EXCLUDED_WITH_DECISION`. Unknown AST forms, unresolved imports, unsupported
Zod combinators, unaccounted source changes, and duplicate symbol ownership
must terminate generation with source file/line, AST kind and a suggested
lowering rule. Maintain separate **source coverage** and **behavior coverage**;
percentage of TS AST nodes translated is not a parity percentage.

`transpiler check` regenerates into a temporary directory, compares tracked
generated Go byte-for-byte, verifies the source pin and coverage inventory,
and fails on drift. Do not write over handwritten or untracked user files.

## Differential parity harness

Run the pinned TS server and generated+handwritten Go server with identical
fixtures, fake clock/ID/secret generation, deterministic mail/network stubs,
and logically equivalent in-memory/SQLite state. Compare normalized:

- status, structured errors, content type and all meaningful headers;
- JSON including absent vs null fields, arrays, ordering where contractual;
- cookies (value and attributes), redirects, URL encoding;
- DB mutations, hook calls, token/session state and background effects;
- concurrency outcomes and replay behavior for atomic endpoints.

Normalization may remove only known nondeterminism (timestamps, random IDs,
cryptographic nonces) via injected deterministic dependencies; it must **not**
erase status, error body, `Set-Cookie`, `WWW-Authenticate`, or persistence
differences. First port upstream test cases to shared vectors, then add
adversarial and fuzz vectors. A closed `AUTH-AUDIT-*` gap requires an oracle
fixture reproducing the old mismatch, generated/handwritten fix, green
differential check, and updated `parity_ledger.json` disposition.

## Delivery waves and validation gates

### Wave 0 — freeze the baseline

- [ ] Capture current working-tree changes; do not overwrite the ongoing
      source-layout/audit work.
- [ ] Verify pinned commit and enumerate scoped source symbols/routes/tests.
- [ ] Reconcile `PARITY.md` and `parity_ledger.json`: classify each
      `AUTH-AUDIT-*` ID as proven behavioral gap, Go adaptation, excluded or
      needs reproduction. Resolve contradictory historical “Done” claims.
- [ ] Define a deterministic TS/Go test environment and baseline vectors.

### Wave 1 — executable vertical slice: Admin `setRole`

- [ ] Parse pinned `plugins/admin/routes.ts` and its `setRoleBodySchema`,
      `parseRoles`, `adminMiddleware`, permission and output dependencies.
- [ ] Emit executable Go registrar/handler + validation into a `.gen.go`
      file. Preserve public `admin.SetRole` via a narrow handwritten facade
      during migration, then remove duplicated handler logic.
- [ ] Cover a scalar/array/empty/whitespace role, coerced `userId`, custom
      roles, denied permission, missing user, hook-modified update, failed
      update, metadata and filtered output. Port pinned TS tests first.
- [ ] Show that changing a TS AST node causes either a changed generated Go
      file or a hard diagnostic. Verify repeated generation is byte-stable.

### Wave 2 — reusable endpoint/schema/plugin compiler

- [ ] Support all in-scope `createAuthEndpoint` declaration shapes, Zod
      combinators, plugin registration and error-code metadata.
- [ ] Port core routes, then Admin, JWT and Organization routes; keep
      package boundaries and public Go constructors stable.
- [ ] Wire before/after hooks, session middleware, request lifecycle and
      error/response filtering as tested intrinsics.
- [ ] Fail the build when an endpoint or upstream case is unaccounted for.

### Wave 3 — protocol/provider compiler and intrinsics

- [ ] Compile the OAuth2 and OAuth Provider route/control flow. Review
      crypto/cookie/DB/DPoP implementations as intrinsics with oracle vectors.
- [ ] Compile all 36 provider option/default/profile mappings from their
      canonical `packages/core/src/social-providers/` owners.
- [ ] Resolve the public Go model/option surface and `SendOnSignUp` tri-state;
      keep TS type-only/client-only declarations classified separately.

### Wave 4 — close the audit before merge

- [ ] Address every proven in-scope `AUTH-AUDIT-*` gap with a reproducing
      pinned TS fixture and Go fix, or record an approved exclusion. Prioritize
      shared hooks, CSRF, sessions, signup, token/cookie wire formats, rate
      limits and atomic operations before file-order cleanups.
- [ ] Reconcile every upstream test file/case in the ledger; no `open` or
      `partial` in-scope disposition without an explicit exclusion.
- [ ] Run generation drift check, Go build/vet/hermetic/race/coverage tests,
      pinned TS tests, cross-language differential suite and serial live
      PostgreSQL tests where available. MySQL/MSSQL live tests remain scoped
      by the existing documented driver/server availability decision.
- [ ] Produce a source/behavior coverage report with zero unknown runtime
      symbols and zero unresolved in-scope differential failures.

## Parallel ownership

- **Parser/IR owner:** scoped source scan, TS compiler integration, stable
  spans/hashes, fail-closed diagnostics.
- **Emitter/runtime owner:** Go AST, semantic primitives, formatting, public
  API preservation.
- **Endpoint owners:** core API, Admin/JWT, Organization, OAuth Provider; each
  owns only its generated templates/lowering rules and fixtures.
- **Oracle/ledger owner:** pinned TS execution, fixtures, mutation checks,
  case disposition, CI comparison and coverage report.
- **Integration owner:** resolve package cycles, enforce deterministic builds,
  validate production behavior, and merge only after all gates pass.

Subtasks can run in parallel in isolated worktrees; a single owner updates the
coverage map and `PARITY.md` to prevent conflicting writes. Do not treat an
agent's audit prose as proof of parity until the differential fixture passes.

## Important constraints

- A general-purpose TS→Go compiler is not required; **all runtime constructs
  in the pinned declared scope** must be generated, handled by tested
  intrinsics, or explicitly classified. A route manifest alone is insufficient.
- Preserving existing Go APIs may require compatibility facades; never silently
  replace public import paths or change legacy behavior without a decision.
- The transpiler makes upgrades cheaper, not automatically correct: new AST
  shapes and changed semantics must fail closed and receive a reviewed lowering
  rule and oracle tests.
- “100% parity” is only defensible within the declared server-side scope and
  the explicit exclusion register; it does not mean byte-identical TS types,
  browser behavior, or untested external database drivers.
