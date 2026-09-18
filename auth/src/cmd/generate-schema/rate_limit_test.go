package main

import (
	"strings"
	"testing"

	auth "github.com/brick-org/brick/auth/src"
)

// AUTH-D6-01: rate-limit table in schema/migrations across all dialects.
//
// The rate-limit storage table (get-tables.ts rateLimitTable block) must be
// planned with key/count/lastRequest columns, a unique key constraint, and
// dialect-correct types/quoting. Plans never contain destructive statements
// (no DROP): safe startup creates missing tables/columns only, and request
// behavior never migrates implicitly.

func rateLimitDesired() auth.PluginSchema {
	return auth.MergeSchemas(auth.CoreSchema(), auth.RateLimitSchema())
}

func TestRateLimitTable_PlannedOnAllDialects(t *testing.T) {
	for _, dialect := range []Dialect{DialectSQLite, DialectPostgres, DialectMySQL, DialectMSSQL} {
		plan, err := BuildMigrationPlan(rateLimitDesired(), auth.AdapterConfig{}, dialect, "string")
		if err != nil {
			t.Fatalf("%s: %v", dialect, err)
		}
		var table *plannedTable
		for i := range plan.Tables {
			if plan.Tables[i].Name == "rateLimits" || plan.Tables[i].Name == "rate_limit" || strings.Contains(plan.Tables[i].Name, "rate") {
				table = &plan.Tables[i]
			}
		}
		if table == nil {
			// Resolve the physical name through the schema helper.
			names := []string{}
			for _, pt := range plan.Tables {
				names = append(names, pt.Name)
			}
			t.Fatalf("%s: rate-limit table missing, have %v", dialect, names)
		}
		cols := map[string]string{}
		for _, c := range table.Columns {
			cols[c.Name] = c.Definition
		}
		if _, ok := cols["key"]; !ok {
			t.Fatalf("%s: rate-limit table missing key column: %v", dialect, cols)
		}
		if _, ok := cols["count"]; !ok {
			t.Fatalf("%s: rate-limit table missing count column", dialect)
		}
		if _, ok := cols["last_request"]; !ok {
			t.Fatalf("%s: rate-limit table missing last_request column: %v", dialect, cols)
		}
		if !strings.Contains(cols["key"], "UNIQUE") {
			t.Fatalf("%s: key column must be UNIQUE, got %q", dialect, cols["key"])
		}
		// lastRequest is bigint on every dialect (FieldTypeNumber BigInt).
		if !strings.Contains(strings.ToLower(cols["last_request"]), "bigint") {
			t.Fatalf("%s: last_request must be bigint, got %q", dialect, cols["last_request"])
		}
	}
}

func TestRateLimitTable_WireConformanceQuoting(t *testing.T) {
	schema := rateLimitDesired()
	pg, err := BuildMigrationPlan(schema, auth.AdapterConfig{}, DialectPostgres, "string")
	if err != nil {
		t.Fatal(err)
	}
	mysql, err := BuildMigrationPlan(schema, auth.AdapterConfig{}, DialectMySQL, "string")
	if err != nil {
		t.Fatal(err)
	}
	mssql, err := BuildMigrationPlan(schema, auth.AdapterConfig{}, DialectMSSQL, "string")
	if err != nil {
		t.Fatal(err)
	}
	pgScript, mysqlScript, mssqlScript := pg.Script(), mysql.Script(), mssql.Script()
	if !strings.Contains(pgScript, `"`) {
		t.Fatalf("postgres must double-quote identifiers:\n%s", pgScript)
	}
	if !strings.Contains(mysqlScript, "`") {
		t.Fatalf("mysql must backtick identifiers:\n%s", mysqlScript)
	}
	if !strings.Contains(mssqlScript, "[") || !strings.Contains(mssqlScript, "]") {
		t.Fatalf("mssql must bracket identifiers:\n%s", mssqlScript)
	}
	// MySQL indexed strings stay bounded (varchar, not unbounded text for the
	// unique key column).
	if !strings.Contains(strings.ToLower(mysqlScript), "varchar") {
		t.Fatalf("mysql rate-limit key must be bounded varchar:\n%s", mysqlScript)
	}
}

func TestMigrationPlans_NeverDestructive(t *testing.T) {
	schema := rateLimitDesired()
	for _, dialect := range []Dialect{DialectSQLite, DialectPostgres, DialectMySQL, DialectMSSQL} {
		plan, err := BuildMigrationPlan(schema, auth.AdapterConfig{}, dialect, "string")
		if err != nil {
			t.Fatal(err)
		}
		script := strings.ToUpper(plan.Script())
		for _, destructive := range []string{"DROP TABLE", "DROP COLUMN", "TRUNCATE", "DELETE FROM"} {
			if strings.Contains(script, destructive) {
				t.Fatalf("%s: fresh-install plan must never be destructive, found %q", dialect, destructive)
			}
		}
		// Incremental diff against empty current is also create-only.
		diff, err := DiffMigrationPlan(auth.PluginSchema{}, schema, auth.AdapterConfig{}, dialect, "string", map[string]bool{})
		if err != nil {
			t.Fatal(err)
		}
		dscript := strings.ToUpper(diff.Script())
		for _, destructive := range []string{"DROP TABLE", "DROP COLUMN", "TRUNCATE", "DELETE FROM"} {
			if strings.Contains(dscript, destructive) {
				t.Fatalf("%s: diff plan must never be destructive, found %q", dialect, destructive)
			}
		}
	}
}

func TestRateLimitTable_AddedByDiffWhenMissing(t *testing.T) {
	// Safe startup: a missing rate-limit table is created, never destructive.
	current := auth.CoreSchema()
	desired := rateLimitDesired()
	plan, err := DiffMigrationPlan(current, desired, auth.AdapterConfig{}, DialectSQLite, "string", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tbl := range plan.Tables {
		if strings.Contains(tbl.Name, "rate") {
			found = true
		}
	}
	if !found {
		names := []string{}
		for _, tbl := range plan.Tables {
			names = append(names, tbl.Name)
		}
		t.Fatalf("diff must create the missing rate-limit table, created %v", names)
	}
}
