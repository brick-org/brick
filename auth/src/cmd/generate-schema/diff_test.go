package main

// Tests for current-vs-desired migration diffing (diff.go), porting the
// unsafe-change and ALTER-path behavior of upstream get-migration.ts
// (get-migration.test.ts, get-migration-unsafe-change.test.ts) to the
// offline planner.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	auth "github.com/brick-org/brick/auth/src"
)

func TestDiffMigrationPlanMatchesFreshOnEmptyCurrent(t *testing.T) {
	desired := testSchema()
	cfg := testConfig()
	fresh, err := BuildMigrationPlan(desired, cfg, DialectSQLite, "string")
	if err != nil {
		t.Fatalf("fresh plan must build: %v", err)
	}
	diff, err := DiffMigrationPlan(auth.PluginSchema{}, desired, cfg, DialectSQLite, "string", nil)
	if err != nil {
		t.Fatalf("diff plan must build: %v", err)
	}
	if fresh.Script() != diff.Script() {
		t.Fatalf("empty current must equal fresh install:\n%s", lineDiff(fresh.Script(), diff.Script()))
	}
	if len(diff.UnsafeChanges) != 0 {
		t.Fatalf("fresh diff must be safe: %v", diff.UnsafeChanges)
	}
}

func TestDiffMigrationPlanAddsNullableColumnToEmptyTable(t *testing.T) {
	current := auth.PluginSchema{
		"user": {Fields: map[string]auth.FieldAttribute{
			"name": {Type: auth.FieldTypeString},
		}},
	}
	desired := auth.PluginSchema{
		"user": {Fields: map[string]auth.FieldAttribute{
			"name": {Type: auth.FieldTypeString},
			"tier": {Type: auth.FieldTypeString, Required: boolPtrMain(false)},
		}},
	}
	plan, err := DiffMigrationPlan(current, desired, testConfig(), DialectSQLite, "string", map[string]bool{"users": false})
	if err != nil {
		t.Fatalf("diff must build: %v", err)
	}
	if len(plan.Tables) != 0 {
		t.Fatalf("no tables to create: %+v", plan.Tables)
	}
	if len(plan.Alters) != 1 {
		t.Fatalf("one column to add: %+v", plan.Alters)
	}
	script := plan.Script()
	if !strings.Contains(script, `alter table "users" add column "tier" text;`) {
		t.Fatalf("sqlite ALTER must add a nullable text column:\n%s", script)
	}
	if len(plan.UnsafeChanges) != 0 {
		t.Fatalf("empty table must be safe: %v", plan.UnsafeChanges)
	}
}

func TestDiffMigrationPlanRefusesRequiredColumnOnPopulatedTable(t *testing.T) {
	current := auth.PluginSchema{
		"directoryUser": {Fields: map[string]auth.FieldAttribute{
			"externalId": {Type: auth.FieldTypeString},
		}},
	}
	desired := auth.PluginSchema{
		"directoryUser": {Fields: map[string]auth.FieldAttribute{
			"externalId":       {Type: auth.FieldTypeString},
			"connectionIssuer": {Type: auth.FieldTypeString, Required: boolPtrMain(true)},
		}},
	}
	// Nil populated map assumes populated (conservative offline default).
	plan, err := DiffMigrationPlan(current, desired, testConfig(), DialectSQLite, "string", nil)
	if err != nil {
		t.Fatalf("diff must build: %v", err)
	}
	if len(plan.UnsafeChanges) != 1 {
		t.Fatalf("populated table must flag unsafe: %+v", plan.UnsafeChanges)
	}
	if !strings.Contains(plan.UnsafeChanges[0], `Cannot add required column "connection_issuer" to populated table "directory_users"`) {
		t.Fatalf("unsafe message uses physical names: %q", plan.UnsafeChanges[0])
	}
	if err := plan.ThrowOnUnsafe(); err == nil {
		t.Fatal("ThrowOnUnsafe must refuse")
	} else if _, ok := err.(*auth.UnsafeMigrationError); !ok {
		t.Fatalf("refusal must be UnsafeMigrationError: %T", err)
	}
	// The statements still compile for inspection (generate spirit).
	if script := plan.Script(); !strings.Contains(strings.ToLower(script), `add column "connection_issuer" text not null`) {
		t.Fatalf("unsafe plan still compiles statements:\n%s", script)
	}
	// Static defaults stay safe on populated tables.
	withDefault := auth.PluginSchema{
		"directoryUser": {Fields: map[string]auth.FieldAttribute{
			"externalId":       {Type: auth.FieldTypeString},
			"connectionIssuer": {Type: auth.FieldTypeString, Required: boolPtrMain(true), DefaultValue: "local"},
		}},
	}
	safe, err := DiffMigrationPlan(current, withDefault, testConfig(), DialectSQLite, "string", nil)
	if err != nil {
		t.Fatalf("defaulted diff must build: %v", err)
	}
	if len(safe.UnsafeChanges) != 0 {
		t.Fatalf("static default must be safe: %v", safe.UnsafeChanges)
	}
	if script := safe.Script(); !strings.Contains(script, `"connection_issuer" text NOT NULL DEFAULT 'local'`) {
		t.Fatalf("defaulted ALTER carries its default:\n%s", script)
	}
}

func TestDiffMigrationPlanSQLiteUniqueWithoutInline(t *testing.T) {
	current := auth.PluginSchema{
		"m": {Fields: map[string]auth.FieldAttribute{
			"a": {Type: auth.FieldTypeString},
		}},
	}
	desired := auth.PluginSchema{
		"m": {Fields: map[string]auth.FieldAttribute{
			"a":    {Type: auth.FieldTypeString},
			"code": {Type: auth.FieldTypeString, Unique: true, Required: boolPtrMain(false)},
		}},
	}
	plan, err := DiffMigrationPlan(current, desired, testConfig(), DialectSQLite, "string", map[string]bool{"ms": false})
	if err != nil {
		t.Fatalf("diff must build: %v", err)
	}
	script := plan.Script()
	for _, line := range strings.Split(script, "\n") {
		if strings.Contains(line, "add column") && strings.Contains(line, "UNIQUE") {
			t.Fatalf("sqlite ALTER must never inline UNIQUE:\n%s", script)
		}
	}
	if !strings.Contains(script, `create unique index "ms_code_uidx" on "ms" ("code")`) {
		t.Fatalf("unique column needs a separate index:\n%s", script)
	}
}

func TestDiffMigrationPlanMSSQLNullableUniqueFiltered(t *testing.T) {
	current := auth.PluginSchema{
		"m": {Fields: map[string]auth.FieldAttribute{
			"a": {Type: auth.FieldTypeString},
		}},
	}
	desired := auth.PluginSchema{
		"m": {Fields: map[string]auth.FieldAttribute{
			"a":    {Type: auth.FieldTypeString},
			"code": {Type: auth.FieldTypeString, Unique: true, Required: boolPtrMain(false)},
		}},
	}
	plan, err := DiffMigrationPlan(current, desired, testConfig(), DialectMSSQL, "string", map[string]bool{"ms": true})
	if err != nil {
		t.Fatalf("diff must build: %v", err)
	}
	script := plan.Script()
	// NULL-filtered unique indexes are MSSQL-only (upstream ALTER path).
	if !strings.Contains(script, `create unique index [ms_code_uidx] on [ms] ([code]) where [code] is not null`) {
		t.Fatalf("mssql nullable unique must filter NULLs:\n%s", script)
	}
	sqlite, err := DiffMigrationPlan(current, desired, testConfig(), DialectSQLite, "string", map[string]bool{"ms": true})
	if err != nil {
		t.Fatalf("sqlite diff must build: %v", err)
	}
	if strings.Contains(sqlite.Script(), "where") {
		t.Fatalf("non-mssql indexes must not filter:\n%s", sqlite.Script())
	}
}

func TestDiffMigrationPlanNewTablesOrdered(t *testing.T) {
	current := auth.PluginSchema{
		"user": {Fields: map[string]auth.FieldAttribute{
			"name": {Type: auth.FieldTypeString},
		}},
	}
	desired := auth.PluginSchema{
		"user": {Fields: map[string]auth.FieldAttribute{
			"name": {Type: auth.FieldTypeString},
		}},
		"organization": {Fields: map[string]auth.FieldAttribute{
			"name": {Type: auth.FieldTypeString},
		}},
		"member": {Fields: map[string]auth.FieldAttribute{
			"organizationId": {Type: auth.FieldTypeString, References: &auth.FieldReference{Model: "organization", Field: "id", OnDelete: "cascade"}},
			"userId":         {Type: auth.FieldTypeString, References: &auth.FieldReference{Model: "user", Field: "id", OnDelete: "cascade"}},
		}},
	}
	plan, err := DiffMigrationPlan(current, desired, testConfig(), DialectPostgres, "string", nil)
	if err != nil {
		t.Fatalf("diff must build: %v", err)
	}
	if len(plan.Tables) != 2 {
		t.Fatalf("two tables to create: %+v", plan.Tables)
	}
	if plan.Tables[0].Name != "organizations" || plan.Tables[1].Name != "members" {
		t.Fatalf("referenced tables first: %+v", plan.Tables)
	}
	script := plan.Script()
	if strings.Index(script, `"organizations"`) > strings.Index(script, `"members"`) {
		t.Fatalf("organization must precede member:\n%s", script)
	}
}

func TestDiffMigrationPlanIndexConflict(t *testing.T) {
	current := auth.PluginSchema{
		"m": {Fields: map[string]auth.FieldAttribute{
			"a": {Type: auth.FieldTypeString},
			"b": {Type: auth.FieldTypeString},
		}, Indexes: []auth.TableIndex{{Fields: []string{"a"}, Name: "m_ab_uidx", Unique: true}}},
	}
	desired := auth.PluginSchema{
		"m": {Fields: map[string]auth.FieldAttribute{
			"a": {Type: auth.FieldTypeString},
			"b": {Type: auth.FieldTypeString},
		}, Indexes: []auth.TableIndex{{Fields: []string{"a", "b"}, Name: "m_ab_uidx", Unique: true}}},
	}
	// Same name, different definition: a plain BetterAuthError-style
	// refusal, never an UnsafeMigrationError.
	_, err := DiffMigrationPlan(current, desired, testConfig(), DialectSQLite, "string", nil)
	if err == nil || !strings.Contains(err.Error(), `database index "m_ab_uidx" on table "ms" does not match`) {
		t.Fatalf("conflicting index must error: %v", err)
	}
	if _, ok := err.(*auth.UnsafeMigrationError); ok {
		t.Fatal("index conflicts must not classify as unsafe")
	}
}

func TestDiffMigrationPlanCycleDeterministic(t *testing.T) {
	cycle := auth.PluginSchema{
		"b": {Fields: map[string]auth.FieldAttribute{
			"aId": {Type: auth.FieldTypeString, References: &auth.FieldReference{Model: "a", Field: "id"}},
		}},
		"a": {Fields: map[string]auth.FieldAttribute{
			"bId": {Type: auth.FieldTypeString, References: &auth.FieldReference{Model: "b", Field: "id"}},
		}},
	}
	first, err := DiffMigrationPlan(auth.PluginSchema{}, cycle, testConfig(), DialectSQLite, "string", nil)
	if err != nil {
		t.Fatalf("cyclic diff must build: %v", err)
	}
	second, err := DiffMigrationPlan(auth.PluginSchema{}, cycle, testConfig(), DialectSQLite, "string", nil)
	if err != nil {
		t.Fatalf("cyclic diff must build: %v", err)
	}
	if first.Script() != second.Script() {
		t.Fatal("cyclic ordering must be deterministic")
	}
	if len(first.Tables) != 2 {
		t.Fatalf("both cyclic tables planned: %+v", first.Tables)
	}
}

func TestLoadSnapshotFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snapshot.json")
	content := `{"tables": {
		"user": {"modelName": "app_users", "fields": {
			"name": {"type": "string"},
			"tier": {"type": "string", "required": false}
		}},
		"session": {"fields": {"token": {"type": "string", "unique": true}}}
	}, "rowCounts": {"app_users": 3, "sessions": 0}}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	current, populated, err := loadSnapshotFile(path, testConfig())
	if err != nil {
		t.Fatalf("snapshot must load: %v", err)
	}
	if current["user"].ModelName != "app_users" || len(current["user"].Fields) != 2 {
		t.Fatalf("snapshot tables must load: %+v", current)
	}
	if !populated["app_users"] || populated["sessions"] {
		t.Fatalf("rowCounts map to populated: %v", populated)
	}
	// Explicit empty populated list means no populated tables (differs
	// from an absent key, which assumes populated).
	emptyPath := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(emptyPath, []byte(`{"tables": {}, "populated": []}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, populated, err = loadSnapshotFile(emptyPath, testConfig())
	if err != nil {
		t.Fatalf("empty snapshot must load: %v", err)
	}
	if populated == nil {
		t.Fatal("explicit empty list must be exact, not nil")
	}
	if _, _, err := loadSnapshotFile(filepath.Join(dir, "missing.json"), testConfig()); err == nil {
		t.Fatal("missing file must fail")
	}
	badPath := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badPath, []byte(`{"tables": {"m": {"fields": {"a": {"type": "bogus"}}}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadSnapshotFile(badPath, testConfig()); err == nil {
		t.Fatal("unknown field type must fail")
	}
}

func boolPtrMain(v bool) *bool { return &v }
