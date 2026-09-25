# Auth v1 handoff

Date: 2026-09-25. Branch: `auth` (tracking `origin/auth`).
Pinned upstream: Better Auth v1.7.5 @ `5468e6bf`. Scope: `SCOPE.md`
(core email/password + session; no plugins/providers/social).

## Where things stand

- Ledger `parity_ledger.json`: **188 covered entries** across all 13 v1 test
  files. Every lane merged AND checker-verified (5/5 PASS each, NITs closed).
- Gates green: hermetic `go test ./...`, `go test -race` (all packages),
  live PostgreSQL serial `-p 1` (all packages, PG 18).
- Remaining ledger "opens" are recorded exclusions/deviations in `SCOPE.md`,
  not work. Known post-v1 items: `updateAge: 0` tri-state (needs `*int`,
  `types` frozen), full-snapshot error-page parity, live MySQL/MSSQL
  (wire-conformance only, no drivers).
- Docs: `SCOPE.md` (scope + exclusions), `DEPLOY.md` (operator runbook),
  `PARITY.md` (audit, ledger section is authoritative), `plan.md` /
  `TRANSPILER_*.md` are archived reference, not active plans.

## The loop (how work got done — keep using it)

1. **Self-check**: read-only audit of one gap (upstream case + Go code),
   confirm with exact file:line refs. Never guess.
2. **Fixer** (background subagent, isolated `git worktree` off HEAD):
   disjoint owned files ONLY, new `*_v1_test.go` files, never
   `parity_ledger.json`/`PARITY.md`/`SCOPE.md`, never `stash/reset/clean`,
   tests-first with FAIL pre-fix, package-local gate.
   Triage variant: owns ZERO prod files, emits EXCLUDED/CITED/PORTED/
   FEATURE-GAP per case.
3. **Merge** (integration owner = you): apply patch, negative-control new
   tests, full gate, update ledger (`covered` + notes) + `PARITY.md` counts,
   commit. Extract worktree patches BEFORE `worktree remove`.
4. **Checker** (read-only subagent): scope/gates/ledger-verbatim/
   no-weakening(/consistency) checks against the merge commit. Close NITs,
   then next fixer.
5. Max 2 fixers + checkers concurrently; 20 parallel agents was tried and
   failed (tree stomping, conflicting truth-file rewrites).

## Constraints learned the hard way

- `parity_ledger_test.go` (`TestParityLedger_*`) is the drift gate: 23
  routes, 13 test files, pin, marker counts. Keep it green.
- `types/` is frozen for v1 (trivia like `SendOnSignUp *bool`,
  `UpdateAge *int` wait for post-v1).
- Fail-loud per D05 (secondary/propagation errors return 500, never
  swallowed); fail-closed null-shape (401/400, never 200 null).
- Live runs need `-p 1` (shared DB); hermetic runs `env -u DATABASE_URL`.
- `go test -race` full module takes ~3 min (routes ~2 min).
- Commit style: conventional (`feat/fix/docs(auth): …`) — releases are
  automated from it.
