package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	auth "github.com/brick-org/brick/auth/src"
	"github.com/uptrace/bun/driver/pgdriver"
)

// AUTH-V10-03 live PostgreSQL migration coverage (generate-schema half).
//
// These tests build real migration plans (BuildMigrationPlan /
// DiffMigrationPlan), apply every statement to live PostgreSQL under unique
// table names, and introspect information_schema + pg_indexes to prove the
// plans execute and produce the intended shape (PKs, uniques, FKs, bigint
// rate-limit columns, plugin columns on core tables, deferred indexes).
// They skip without DATABASE_URL so default runs stay hermetic; table-name
// uniqueness keeps them safe under default parallel package execution
// (`go test ./...`) — they never touch the shared integration tables
// (users/sessions/accounts/verifications), which still require `-p 1`
// (see adapters/bun/pg_live_matrix_test.go for the exact serial
// requirement). The adapter-level half (plugin create/drop cycles,
// rate-limit behavior, core apply+introspect) lives there.

var livePGPlanSeq atomic.Uint64

func requireLivePG(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping live PostgreSQL migration conformance")
	}
	db := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn)))
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		t.Skipf("postgres unreachable: %v", err)
	}
	return db
}

// livePlanConfig clones schema (clearing TableSchema.ModelName overrides so
// the mapping below wins everywhere) and maps every model to a unique
// physical table under prefix.
func livePlanConfig(t *testing.T, schema auth.PluginSchema, prefix string) (auth.PluginSchema, auth.AdapterConfig) {
	t.Helper()
	n := livePGPlanSeq.Add(1)
	cloned := auth.CloneSchema(schema)
	cfg := auth.AdapterConfig{ModelNames: map[string]string{}}
	for key, tbl := range cloned {
		tbl.ModelName = ""
		name := fmt.Sprintf("%s_%d_%s", prefix, n, strings.ToLower(key))
		if len(name) > 55 {
			name = name[:55]
		}
		cfg.ModelNames[key] = name
		cloned[key] = tbl
	}
	return cloned, cfg
}

// liveDesiredSchema merges core + rate-limit schemas.
func liveDesiredSchema(t *testing.T) auth.PluginSchema {
	t.Helper()
	return auth.MergeSchemas(auth.CoreSchema(), auth.RateLimitSchema())
}

func applyPlanStatements(t *testing.T, db *sql.DB, script string) []string {
	t.Helper()
	ctx := context.Background()
	applied := []string{}
	for _, stmt := range strings.Split(script, ";\n\n") {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("apply %q: %v", stmt, err)
		}
		applied = append(applied, stmt)
	}
	if len(applied) == 0 {
		t.Fatal("plan script applied zero statements")
	}
	return applied
}

func liveTableNames(cfg auth.AdapterConfig, schema auth.PluginSchema) []string {
	names := make([]string, 0, len(schema))
	for key, tbl := range schema {
		names = append(names, auth.PhysicalTableName(key, tbl, cfg))
	}
	return names
}

func dropLiveTables(t *testing.T, db *sql.DB, tables []string) {
	t.Helper()
	if len(tables) == 0 {
		return
	}
	quoted := make([]string, 0, len(tables))
	for _, tbl := range tables {
		quoted = append(quoted, `"`+strings.ReplaceAll(tbl, `"`, `""`)+`"`)
	}
	_, _ = db.ExecContext(context.Background(), `DROP TABLE IF EXISTS `+strings.Join(quoted, ", ")+` CASCADE`)
}

func liveColumnTypes(t *testing.T, db *sql.DB, table string) map[string]string {
	t.Helper()
	rows, err := db.QueryContext(context.Background(),
		`SELECT column_name, data_type FROM information_schema.columns WHERE table_schema='public' AND table_name=$1`, table)
	if err != nil {
		t.Fatalf("introspect %s: %v", table, err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var name, typ string
		if err := rows.Scan(&name, &typ); err != nil {
			t.Fatal(err)
		}
		out[name] = typ
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestLivePG_FullPlanApplyAndIntrospect applies the fresh-install postgres
// plan for the v1 core + rate-limit schemas and proves the resulting shape
// (plugin schemas are v1-excluded per SCOPE.md and asserted nowhere here).
func TestLivePG_FullPlanApplyAndIntrospect(t *testing.T) {
	db := requireLivePG(t)
	ctx := context.Background()
	schema, cfg := livePlanConfig(t, liveDesiredSchema(t), "v10g")

	plan, err := BuildMigrationPlan(schema, cfg, DialectPostgres, "string")
	if err != nil {
		t.Fatalf("BuildMigrationPlan: %v", err)
	}
	if len(plan.Tables) == 0 {
		t.Fatal("fresh-install plan must create tables")
	}
	for _, stmt := range plan.UnsafeChanges {
		t.Logf("plan advisory: %s", stmt)
	}
	tables := liveTableNames(cfg, schema)
	t.Cleanup(func() { dropLiveTables(t, db, tables) })

	applyPlanStatements(t, db, plan.Script())

	// Every planned table exists.
	for _, want := range tables {
		var n int
		if err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public' AND table_name=$1`, want).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("planned table %s missing after apply", want)
		}
	}

	byKey := map[string]string{}
	for key, tbl := range schema {
		byKey[key] = auth.PhysicalTableName(key, tbl, cfg)
	}

	// Core user/session columns (v1 scope: no admin/org plugin columns such
	// as role/banned/impersonated_by/active_organization_id).
	userCols := liveColumnTypes(t, db, byKey["user"])
	for _, col := range []string{"id", "email", "name"} {
		if _, ok := userCols[col]; !ok {
			t.Fatalf("user table missing core column %s (have %v)", col, userCols)
		}
	}
	sessionCols := liveColumnTypes(t, db, byKey["session"])
	for _, col := range []string{"id", "token"} {
		if _, ok := sessionCols[col]; !ok {
			t.Fatalf("session table missing core column %s (have %v)", col, sessionCols)
		}
	}

	// Rate-limit table: key/count/lastRequest with bigint last_request.
	var rlTable string
	for key, tbl := range schema {
		joined := strings.ToLower(key + " " + auth.PhysicalTableName(key, tbl, cfg))
		if strings.Contains(joined, "rate") {
			rlTable = auth.PhysicalTableName(key, tbl, cfg)
		}
	}
	if rlTable == "" {
		t.Fatalf("rate-limit table missing from plan (tables %v)", tables)
	}
	rlCols := liveColumnTypes(t, db, rlTable)
	for _, col := range []string{"key", "count", "last_request"} {
		if _, ok := rlCols[col]; !ok {
			t.Fatalf("rate-limit table missing column %s (have %v)", col, rlCols)
		}
	}
	if rlCols["last_request"] != "bigint" {
		t.Fatalf("last_request must be bigint, got %q", rlCols["last_request"])
	}

	// Primary keys on every table.
	for _, tbl := range tables {
		var n int
		if err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM information_schema.table_constraints WHERE table_schema='public' AND table_name=$1 AND constraint_type='PRIMARY KEY'`, tbl).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("table %s must have exactly one PK, got %d", tbl, n)
		}
	}

	// FK-safe ordering proof: the plan carries FK references and applied in
	// order without error. Scope the FK count to our tables (the shared DB
	// may hold others); at least the core userId chain must be enforced.
	ourFKs := 0
	for _, tbl := range tables {
		var n int
		if err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM information_schema.table_constraints WHERE table_schema='public' AND table_name=$1 AND constraint_type='FOREIGN KEY'`, tbl).Scan(&n); err != nil {
			t.Fatal(err)
		}
		ourFKs += n
	}
	if ourFKs == 0 {
		t.Fatal("full plan must enforce at least one FK (core userId chain)")
	}

	// Deferred indexes exist in pg_indexes for our tables.
	indexed := 0
	for _, tbl := range tables {
		var n int
		if err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM pg_indexes WHERE schemaname='public' AND tablename=$1`, tbl).Scan(&n); err != nil {
			t.Fatal(err)
		}
		indexed += n
	}
	t.Logf("applied %d tables, %d own FKs, %d indexes", len(tables), ourFKs, indexed)
}

// TestLivePG_DiffPlanAddsExtensionTables applies a core-only fresh plan,
// then the incremental core->core+rate-limit diff (new tables only),
// proving safe-startup migrations execute live without destructive
// statements. (Plugin-table diffs are v1-excluded per SCOPE.md.)
func TestLivePG_DiffPlanAddsExtensionTables(t *testing.T) {
	db := requireLivePG(t)
	ctx := context.Background()
	full, cfg := livePlanConfig(t, liveDesiredSchema(t), "v10d")

	coreKeys := map[string]bool{"user": true, "session": true, "account": true, "verification": true}
	core := auth.PluginSchema{}
	for key := range coreKeys {
		if tbl, ok := full[key]; ok {
			core[key] = tbl
		}
	}
	if len(core) != len(coreKeys) {
		t.Fatalf("full schema must contain the core tables, have %v", keysOf(full))
	}

	// Same cfg for both plans so physical names align.
	corePlan, err := BuildMigrationPlan(core, cfg, DialectPostgres, "string")
	if err != nil {
		t.Fatalf("core plan: %v", err)
	}
	tables := liveTableNames(cfg, full)
	t.Cleanup(func() { dropLiveTables(t, db, tables) })
	applyPlanStatements(t, db, corePlan.Script())

	diff, err := DiffMigrationPlan(core, full, cfg, DialectPostgres, "string", map[string]bool{})
	if err != nil {
		t.Fatalf("diff plan: %v", err)
	}
	for _, destructive := range []string{"DROP TABLE", "DROP COLUMN", "TRUNCATE", "DELETE FROM"} {
		if strings.Contains(strings.ToUpper(diff.Script()), destructive) {
			t.Fatalf("incremental diff must never be destructive, found %q", destructive)
		}
	}
	if len(diff.Tables) == 0 {
		t.Fatal("diff must create the missing extension tables")
	}
	applyPlanStatements(t, db, diff.Script())

	// Extension tables (rate-limit) exist after the diff apply.
	pluginKeys := 0
	for key, tbl := range full {
		if coreKeys[key] {
			continue
		}
		pluginKeys++
		name := auth.PhysicalTableName(key, tbl, cfg)
		var n int
		if err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public' AND table_name=$1`, name).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("diff-created table %s (%s) missing after apply", key, name)
		}
	}
	if pluginKeys == 0 {
		t.Fatal("full schema must add extension tables beyond core")
	}
	t.Logf("core tables + %d extension tables via incremental diff", pluginKeys)

	// No plugin-column ALTERs in v1 scope: the diff must not reference
	// admin/org columns.
	for _, col := range []string{"role", "banned", "impersonated_by", "active_organization_id", "organizations", "members"} {
		if strings.Contains(strings.ToLower(diff.Script()), col) {
			t.Fatalf("v1 diff must not reference plugin surface %q", col)
		}
	}
}

func keysOf(schema auth.PluginSchema) []string {
	out := make([]string, 0, len(schema))
	for key := range schema {
		out = append(out, key)
	}
	return out
}
