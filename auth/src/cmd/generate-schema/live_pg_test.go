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

// TestLivePG_FullPlanApplyAndIntrospect applies the fresh-install postgres plan and proves its shape.
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

// TestLivePG_DiffPlanAddsExtensionTables applies the incremental core-to-core+rate-limit diff live.
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
