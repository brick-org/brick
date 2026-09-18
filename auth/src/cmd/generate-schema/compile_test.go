package main

// End-to-end compile checks of generated output: Go models must parse as
// valid Go, and SQLite plans must execute against a real database
// (foreign keys, unique indexes, defaults, incremental ALTERs).

import (
	"database/sql"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	auth "github.com/brick-org/brick/auth/src"
	_ "modernc.org/sqlite"
)

func TestGeneratedModelsParse(t *testing.T) {
	for _, tc := range []struct {
		name        string
		pkg         string
		prefix      string
		migrateFunc string
	}{
		{"defaults", "authmodels", "Auth", "AuthModels"},
		{"custom", "custom", "Custom", "CustomTables"},
	} {
		models, err := buildModels(tc.prefix, canonicalGoldenSchema(), testConfig())
		if err != nil {
			t.Fatalf("%s: models must build: %v", tc.name, err)
		}
		source := renderModels(tc.pkg, tc.migrateFunc, models)
		formatted, err := format.Source([]byte(source))
		if err != nil {
			t.Fatalf("%s: generated source must format: %v\n%s", tc.name, err, source)
		}
		file, err := parser.ParseFile(token.NewFileSet(), "models.go", formatted, parser.AllErrors)
		if err != nil {
			t.Fatalf("%s: generated source must parse: %v", tc.name, err)
		}
		if file.Name.Name != tc.pkg {
			t.Fatalf("%s: package name = %q, want %q", tc.name, file.Name.Name, tc.pkg)
		}
		structs, funcs := 0, 0
		for _, d := range file.Decls {
			switch n := d.(type) {
			case *ast.FuncDecl:
				if n.Name.Name == tc.migrateFunc || n.Name.Name == tc.migrateFunc+"Indexes" {
					funcs++
				}
			case *ast.GenDecl:
				for _, spec := range n.Specs {
					if _, ok := spec.(*ast.TypeSpec); ok {
						structs++
					}
				}
			}
		}
		// 4 model structs + index struct = 5 types; migrate + indexes = 2 funcs.
		if structs != 5 {
			t.Fatalf("%s: type decls = %d, want 5", tc.name, structs)
		}
		if funcs != 2 {
			t.Fatalf("%s: migrate funcs = %d, want 2", tc.name, funcs)
		}
		decls := len(file.Decls)
		// 4 structs + 2 funcs + 1 index-struct + imports = 8 top-level decls.
		if decls != 8 {
			t.Fatalf("%s: top-level decls = %d, want 8", tc.name, decls)
		}
		if !strings.Contains(string(formatted), "func "+tc.migrateFunc+"() []any") {
			t.Fatalf("%s: migrate func missing", tc.name)
		}
		if !strings.Contains(string(formatted), "func "+tc.migrateFunc+"Indexes() []"+tc.migrateFunc+"Index") {
			t.Fatalf("%s: indexes func missing", tc.name)
		}
		// Every non-relation field carries a bun tag with its column.
		for _, col := range []string{`bun:"email`, `bun:"user_id`, `bun:"organization_id`} {
			if !strings.Contains(string(formatted), col) {
				t.Fatalf("%s: column %s missing from models", tc.name, col)
			}
		}
	}
}

func TestGoldenSQLiteExecutes(t *testing.T) {
	db := openTestSQLite(t)
	execScript(t, db, mustReadGolden(t, "golden_sqlite.sql"))
	assertTestTables(t, db, []string{"app_users", "sessions", "organizations", "members"})

	// Static defaults backfill on omitted inserts.
	execTest(t, db, `INSERT INTO "app_users" ("id", "name", "email", "created_at", "updated_at") VALUES ('u1', 'Ada', 'ada@example.com', '2020-01-01', '2020-01-01')`)
	execTest(t, db, `INSERT INTO "organizations" ("id", "name", "slug", "created_at") VALUES ('o1', 'Acme', 'acme', '2020-01-01')`)
	execTest(t, db, `INSERT INTO "members" ("id", "organization_id", "user_id") VALUES ('m1', 'o1', 'u1')`)
	if got := queryTestString(t, db, `SELECT "email_verified" FROM "app_users" WHERE "id" = 'u1'`); got != "0" {
		t.Fatalf("boolean default must backfill 0, got %q", got)
	}
	if got := queryTestString(t, db, `SELECT "role" FROM "members" WHERE "id" = 'm1'`); got != "member" {
		t.Fatalf("role default must backfill 'member', got %q", got)
	}
	if got := queryTestString(t, db, `SELECT "seats" FROM "organizations" WHERE "id" = 'o1'`); got != "5" {
		t.Fatalf("seats default must backfill 5, got %q", got)
	}

	// Unique enforcement.
	if _, err := db.Exec(`INSERT INTO "app_users" ("id", "name", "email", "created_at", "updated_at") VALUES ('u2', 'Bo', 'ada@example.com', '2020-01-01', '2020-01-01')`); err == nil {
		t.Fatal("duplicate email must fail")
	}
	// Compound unique enforcement.
	execTest(t, db, `INSERT INTO "app_users" ("id", "name", "email", "created_at", "updated_at") VALUES ('u2', 'Bo', 'bo@example.com', '2020-01-01', '2020-01-01')`)
	execTest(t, db, `INSERT INTO "members" ("id", "organization_id", "user_id", "role") VALUES ('m2', 'o1', 'u2', 'admin')`)
	if _, err := db.Exec(`INSERT INTO "members" ("id", "organization_id", "user_id") VALUES ('m3', 'o1', 'u1')`); err == nil {
		t.Fatal("duplicate member pair must fail")
	}
	// Foreign keys.
	if _, err := db.Exec(`INSERT INTO "members" ("id", "organization_id", "user_id") VALUES ('mx', 'nope', 'u1')`); err == nil {
		t.Fatal("dangling organization FK must fail")
	}
	if _, err := db.Exec(`INSERT INTO "sessions" ("id", "token", "expires_at", "user_id") VALUES ('s9', 'tok', '2030-01-01', 'ghost')`); err == nil {
		t.Fatal("dangling session FK must fail")
	}
	// Plain index presence.
	if got := queryTestString(t, db, `SELECT COUNT(*) FROM sqlite_master WHERE "type" = 'index' AND "name" = 'sessions_user_id_idx'`); got != "1" {
		t.Fatalf("deferred plain index must exist, count = %q", got)
	}
}

func TestDiffAlterExecutesOnSQLite(t *testing.T) {
	db := openTestSQLite(t)
	current := auth.PluginSchema{
		"user": {Fields: map[string]auth.FieldAttribute{
			"name": {Type: auth.FieldTypeString},
		}},
	}
	fresh, err := BuildMigrationPlan(current, testConfig(), DialectSQLite, "string")
	if err != nil {
		t.Fatalf("fresh plan must build: %v", err)
	}
	execScript(t, db, fresh.Script())
	execTest(t, db, `INSERT INTO "users" ("id", "name") VALUES ('u1', 'Ada')`)

	desired := auth.PluginSchema{
		"user": {Fields: map[string]auth.FieldAttribute{
			"name": {Type: auth.FieldTypeString},
			"tier": {Type: auth.FieldTypeString, Required: boolPtrMain(false)},
			"role": {Type: auth.FieldTypeString, DefaultValue: "member"},
		}},
		"session": {Fields: map[string]auth.FieldAttribute{
			"token":  {Type: auth.FieldTypeString, Unique: true},
			"userId": {Type: auth.FieldTypeString, Index: true, References: &auth.FieldReference{Model: "user", Field: "id", OnDelete: "cascade"}},
		}},
	}
	plan, err := DiffMigrationPlan(current, desired, testConfig(), DialectSQLite, "string", map[string]bool{"users": true})
	if err != nil {
		t.Fatalf("diff must build: %v", err)
	}
	if len(plan.UnsafeChanges) != 0 {
		t.Fatalf("nullable/defaulted adds must be safe: %v", plan.UnsafeChanges)
	}
	execScript(t, db, plan.Script())
	// New table exists with its FK; added columns backfill.
	assertTestTables(t, db, []string{"users", "sessions"})
	if got := queryTestString(t, db, `SELECT "role" FROM "users" WHERE "id" = 'u1'`); got != "member" {
		t.Fatalf("added static default must backfill, got %q", got)
	}
	execTest(t, db, `INSERT INTO "sessions" ("id", "token", "user_id") VALUES ('s1', 'tok', 'u1')`)
	if _, err := db.Exec(`INSERT INTO "sessions" ("id", "token", "user_id") VALUES ('s2', 'tok', 'u1')`); err == nil {
		t.Fatal("added unique column must enforce uniqueness")
	}
	if _, err := db.Exec(`INSERT INTO "sessions" ("id", "token", "user_id") VALUES ('s3', 'tok3', 'ghost')`); err == nil {
		t.Fatal("added FK must enforce references")
	}
}

func TestSerialIDTypes(t *testing.T) {
	schema := auth.PluginSchema{
		"user": {Fields: map[string]auth.FieldAttribute{"name": {Type: auth.FieldTypeString}}},
	}
	postgres, err := BuildMigrationPlan(schema, testConfig(), DialectPostgres, "serial")
	if err != nil {
		t.Fatalf("postgres serial must build: %v", err)
	}
	if !strings.Contains(postgres.Script(), "GENERATED BY DEFAULT AS IDENTITY") {
		t.Fatalf("postgres serial identity missing:\n%s", postgres.Script())
	}
	mssql, err := BuildMigrationPlan(schema, testConfig(), DialectMSSQL, "serial")
	if err != nil {
		t.Fatalf("mssql serial must build: %v", err)
	}
	if !strings.Contains(mssql.Script(), "IDENTITY(1,1)") {
		t.Fatalf("mssql serial identity missing:\n%s", mssql.Script())
	}
	uuid, err := BuildMigrationPlan(schema, testConfig(), DialectPostgres, "uuid")
	if err != nil {
		t.Fatalf("postgres uuid must build: %v", err)
	}
	if !strings.Contains(uuid.Script(), `"id" uuid PRIMARY KEY NOT NULL`) {
		t.Fatalf("postgres uuid id missing:\n%s", uuid.Script())
	}
}

func openTestSQLite(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		t.Fatal(err)
	}
	return db
}

func execScript(t *testing.T, db *sql.DB, script string) {
	t.Helper()
	for _, stmt := range strings.Split(script, ";") {
		trimmed := strings.TrimSpace(stmt)
		if trimmed == "" {
			continue
		}
		// Skip banner comments.
		lines := strings.Split(trimmed, "\n")
		kept := lines[:0]
		for _, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), "--") {
				continue
			}
			kept = append(kept, line)
		}
		trimmed = strings.TrimSpace(strings.Join(kept, "\n"))
		if trimmed == "" {
			continue
		}
		if _, err := db.Exec(trimmed); err != nil {
			t.Fatalf("exec %q: %v", trimmed, err)
		}
	}
}

func execTest(t *testing.T, db *sql.DB, stmt string) {
	t.Helper()
	if _, err := db.Exec(stmt); err != nil {
		t.Fatalf("exec %q: %v", stmt, err)
	}
}

func queryTestString(t *testing.T, db *sql.DB, query string) string {
	t.Helper()
	var got any
	if err := db.QueryRow(query).Scan(&got); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	switch v := got.(type) {
	case nil:
		return ""
	case string:
		return v
	case []byte:
		return string(v)
	default:
		return fmt.Sprint(v)
	}
}

func assertTestTables(t *testing.T, db *sql.DB, tables []string) {
	t.Helper()
	for _, table := range tables {
		var name string
		if err := db.QueryRow(`SELECT "name" FROM sqlite_master WHERE "type" = 'table' AND "name" = ?`, table).Scan(&name); err != nil {
			t.Fatalf("table %q must exist: %v", table, err)
		}
	}
}

func mustReadGolden(t *testing.T, file string) string {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + file)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
