# Auth v1 operator runbook

Pinned upstream: Better Auth v1.7.5 @ `5468e6bf`. Scope: `SCOPE.md`
(core email/password + session; no plugins/providers).

## 1. Provision PostgreSQL

```sql
CREATE DATABASE auth;
```

Bun `pgdriver` connects via `DATABASE_URL`:

```sh
export DATABASE_URL='postgres://user:pass@localhost:5432/auth?sslmode=disable'
```

MySQL/MSSQL are wire-conformance only (no drivers in `go.mod`).

## 2. Generate the migration

```sh
cd auth
GOWORK=off go run ./src/cmd/generate-schema \
  -dialect postgres -id-type string -sql > /tmp/auth_schema.sql
psql "$DATABASE_URL" -f /tmp/auth_schema.sql
```

Core tables (default physical names `users`, `sessions`, `accounts`,
`verifications`). Every table carries exactly one primary key;
`sessions`/`accounts` reference `users(id)`. The `rate_limit` table is
emitted only when selected (include the rate-limit schema via `-config`)
for the database backend.

## 3. Safe upgrades (no destructive statements)

```sh
# snapshot current schema once (checked in with your app)
GOWORK=off go run ./src/cmd/generate-schema \
  -dialect postgres -sql > schema/baseline.sql
# later: diff live-vs-desired; exits 2 on drift, emits ALTER ADD COLUMN only
GOWORK=off go run ./src/cmd/generate-schema \
  -dialect postgres -from schema/baseline.json -check
```

The planner never emits `DROP TABLE` / `DROP COLUMN` / `TRUNCATE` /
`DELETE FROM` (pinned by `TestLivePG_DiffPlanAddsExtensionTables`).

## 4. Secrets

- `Options.Secrets` (or `BETTER_AUTH_SECRET` env): current secret first,
  older secrets appended for rotation reads. Unknown-key tokens fail closed.
- Email-verification/password-reset use HS256 JWTs by default with
  legacy-HMAC read bridges — safe to rotate the primary secret; old links
  keep verifying until expiry.

## 5. Rate limiting

Default is in-memory. Production default enables it when
`NODE_ENV=production` (mirrors upstream). For multi-instance deployments
select the database backend (`RateLimit.Storage: "database"`, migrates the
`rate_limit` table above) or secondary storage; plugin buckets consume
atomically through the selected backend.

## 6. Health verification

```sh
cd auth
env -u DATABASE_URL GOWORK=off go test -count=1 ./...            # hermetic
DATABASE_URL=... GOWORK=off go test -p 1 -count=1 ./...          # live, serial
```

Serial (`-p 1`) is required for live runs: suites share one database.
`GET /ok` is the liveness endpoint; `GET /error` renders the safe error page.

## 7. Known v1 boundaries

`SCOPE.md` lists every intentional exclusion (social auth, plugins,
chunked cookie writes, `SendOnSignUp` tri-state, 422-vs-400 convention,
fail-closed null-shape). Anything outside `parity_ledger.json`'s 13 test
files is out of scope by decision, not missing.
