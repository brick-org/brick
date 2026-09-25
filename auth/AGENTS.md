# AGENTS.md — auth/ contributor rules

Module: `github.com/brick-org/brick/auth` (Go 1.26, `GOWORK=off`).
Hermetic gate: `env -u DATABASE_URL GOWORK=off go test ./... -count=1` from `auth/`.
Live DB runs need `-p 1`. Upstream pin: Better Auth v1.7.5 @ `5468e6bf`
(`vendor/better-auth` submodule — init before ledger tests).

## 1. Standard library first (no reimplementation)

- `min` / `max` builtins — never write helpers or ternaries.
- `slices` / `maps` packages (`Contains`, `Sort`, `Clone`, `Equal`, `DeleteFunc`)
  — never hand-roll search/sort/clone loops.
- `sync.Once`, `sync.Pool`, `context`, `errors.As/Is/Unwrap`, `io`,
  `strconv`, `net/url`, `encoding/json` — never custom variants.
- `crypto/subtle.ConstantTimeCompare` for every secret/token comparison
  (short-circuits on length mismatch — acceptance-identical, note it).
- UUIDs: `google/uuid` (`uuid.NewString()`, direct dep) — never hand-roll
  RFC 4122 bit-twiddling (removed in `types/helper.go`).
- Random strings: `crypto/rand.Text()` (Go 1.24+) when the alphanumeric
  alphabet fits; else `crypto.GenerateRandomString` (Better Auth
  `a-z0-9A-Z-_` alphabet). Never per-byte `big.Int` loops outside it.
- Durations: `time.ParseDuration` for Go syntax; internal `utils.Ms/Sec`
  only for Better Auth `TimeString` grammar (`7d`, `ago`, `from now`).
- `net/http` semantics (`MaxAge:-1`+epoch renders `Max-Age=0`) over
  reimplementing cookie serialization; `url.Values.Encode` only where
  upstream uses `searchParams.set`, else raw-append.

## 2. Comments: one-line TS refs, no essays

- Every ported symbol gets at most one `// Upstream <path>:<lines>` ref.
- Keep verbatim: FAIL-CLOSED / WARNING / DO NOT / NEVER / MUST lines,
  error-code mappings, tri-state semantics, algorithm params.
- Cut: repeated vendor provenances, audit-pointer-only lines,
  batch-story narratives, commented-out code.
- Test names are descriptive (`session_null_shape_test.go`), never batch
  codes (`b14_`, `g2_`, `c2_`).

## 3. Deduplication

- Redirect-trust: `trustRequest` / `trustRequestFromHuma` + `types.IsTrustedRedirect`
  (never re-inline the resolve-fallback).
- Verification keys: `verificationCandidates` (never re-inline stored+plain).
- Consume paths: `db.ConsumeOneWithFallback` (never FindOne+Delete for
  single-use values).
- New shared logic (≥3 call sites) goes in the owning package's helper file
  with a `redirect_trust_test.go`-style pin — never a third copy.

## 4. Hard rules

- Never edit `parity_ledger.json` or `SCOPE.md` in fixer batches;
  never weaken an existing test (conflict → revert + BLOCKED + test name).
- Frozen: `src/utils/boolean.go`, `constants.go`, `hide-metadata.go`
  (renamed from `*.gen.go`; content untouched, do not hand-edit).
- File layout mirrors upstream TS owners 1:1, except the rate-limiter impl
  (stays in parent `api`: Go forbids two packages per directory).
- Truth files + drift gate (`src/parity_ledger_test.go`) must stay green.
