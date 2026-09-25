package main

import (
	"strings"
	"testing"

	auth "github.com/brick-org/brick/auth/src"
)

func testSchema() auth.PluginSchema {
	return auth.PluginSchema{
		"user": {
			ModelName: "app_users",
			Fields: map[string]auth.FieldAttribute{
				"name":      {Type: auth.FieldTypeString},
				"email":     {Type: auth.FieldTypeString, Unique: true},
				"createdAt": {Type: auth.FieldTypeDate, DefaultValue: auth.DateNowDefault},
				"updatedAt": {Type: auth.FieldTypeDate, DefaultValue: auth.DateNowDefault, OnUpdate: auth.DateNowDefault},
			},
		},
		"session": {
			Fields: map[string]auth.FieldAttribute{
				"token": {Type: auth.FieldTypeString, Unique: true},
				"userId": {
					Type:       auth.FieldTypeString,
					Index:      true,
					References: &auth.FieldReference{Model: "user", Field: "id", OnDelete: "cascade"},
				},
			},
		},
	}
}

func testConfig() auth.AdapterConfig { return auth.AdapterConfig{} }

func TestJWTPluginSchemaIsRegisteredForMigrationGeneration(t *testing.T) {
	schema, err := auth.PluginSchemasForIDs([]string{"jwt"})
	if err != nil {
		t.Fatalf("PluginSchemasForIDs(jwt) error = %v", err)
	}
	if _, ok := schema["jwks"]; !ok {
		t.Fatalf("registered JWT schema is missing jwks table: %#v", schema)
	}
}

func TestParseDialect(t *testing.T) {
	for in, want := range map[string]Dialect{
		"sqlite": DialectSQLite, "postgres": DialectPostgres,
		"postgresql": DialectPostgres, "mysql": DialectMySQL,
		"mssql": DialectMSSQL, "sqlserver": DialectMSSQL,
	} {
		got, err := parseDialect(in)
		if err != nil || got != want {
			t.Fatalf("parseDialect(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := parseDialect("oracle"); err == nil {
		t.Fatal("unknown dialect must fail")
	}
	if err := validateIDType("serial"); err != nil {
		t.Fatalf("serial must validate: %v", err)
	}
	if err := validateIDType("bson"); err == nil {
		t.Fatal("unknown id type must fail")
	}
}

func TestBuildMigrationPlanSQLite(t *testing.T) {
	plan, err := BuildMigrationPlan(testSchema(), testConfig(), DialectSQLite, "string")
	if err != nil {
		t.Fatalf("plan must build: %v", err)
	}
	if len(plan.UnsafeChanges) != 0 {
		t.Fatalf("fresh plan must be safe: %v", plan.UnsafeChanges)
	}
	script := plan.Script()
	for _, want := range []string{
		`create table "app_users"`,
		`"id" text PRIMARY KEY NOT NULL`,
		`"email" text NOT NULL UNIQUE`,
		`"created_at" date NOT NULL`,
		`create table "sessions"`,
		`REFERENCES "app_users" ("id") ON DELETE CASCADE`,
		`create index "sessions_user_id_idx" on "sessions" ("user_id")`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("sqlite script must contain %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, "CURRENT_TIMESTAMP") {
		t.Fatal("sqlite must not emit timestamp defaults")
	}
	if strings.Index(script, `"app_users"`) > strings.Index(script, `"sessions"`) {
		t.Fatal("referenced tables must be created first")
	}
}

func TestBuildMigrationPlanPostgres(t *testing.T) {
	plan, err := BuildMigrationPlan(testSchema(), testConfig(), DialectPostgres, "string")
	if err != nil {
		t.Fatalf("plan must build: %v", err)
	}
	script := plan.Script()
	for _, want := range []string{
		`"created_at" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP`,
		`"email" text NOT NULL UNIQUE`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("postgres script must contain %q:\n%s", want, script)
		}
	}
}

func TestBuildMigrationPlanMySQLBounded(t *testing.T) {
	plan, err := BuildMigrationPlan(testSchema(), testConfig(), DialectMySQL, "string")
	if err != nil {
		t.Fatalf("plan must build: %v", err)
	}
	script := plan.Script()
	if !strings.Contains(script, "`email` varchar(191) NOT NULL UNIQUE") {
		t.Fatalf("mysql indexed strings must be bounded:\n%s", script)
	}
	if !strings.Contains(script, "`created_at` timestamp(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)") {
		t.Fatalf("mysql timestamp default must carry precision:\n%s", script)
	}
}

func TestBuildMigrationPlanMSSQL(t *testing.T) {
	plan, err := BuildMigrationPlan(testSchema(), testConfig(), DialectMSSQL, "serial")
	if err != nil {
		t.Fatalf("plan must build: %v", err)
	}
	script := plan.Script()
	for _, want := range []string{
		"[id] integer IDENTITY(1,1) PRIMARY KEY NOT NULL",
		"[created_at] datetime2(3) NOT NULL DEFAULT CURRENT_TIMESTAMP",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("mssql script must contain %q:\n%s", want, script)
		}
	}
}

func TestBuildMigrationPlanUnsafeUniqueDefault(t *testing.T) {
	schema := auth.PluginSchema{
		"m": {Fields: map[string]auth.FieldAttribute{
			"code": {Type: auth.FieldTypeString, Unique: true, DefaultValue: "x"},
		}},
	}
	plan, err := BuildMigrationPlan(schema, testConfig(), DialectSQLite, "string")
	if err != nil {
		t.Fatalf("plan must build: %v", err)
	}
	if len(plan.UnsafeChanges) == 0 {
		t.Fatal("required unique static default must be flagged unsafe")
	}
	if banner := unsafeBanner(plan.UnsafeChanges); !strings.Contains(banner, "DO NOT RUN THIS SCRIPT AS IT IS.") {
		t.Fatal("unsafe banner must carry the upstream warning")
	}
}

func TestBuildMigrationPlanRejectsBadIndexes(t *testing.T) {
	schema := auth.PluginSchema{
		"m": {Fields: map[string]auth.FieldAttribute{
			"a": {Type: auth.FieldTypeString},
		}, Indexes: []auth.TableIndex{{Fields: []string{"nope"}}}},
	}
	if _, err := BuildMigrationPlan(schema, testConfig(), DialectSQLite, "string"); err == nil {
		t.Fatal("bad indexes must fail the plan")
	}
}

func TestBuildPluginsArbitraryRegistry(t *testing.T) {
	auth.RegisterPluginSchema("test-gen-fake", func() auth.PluginSchemaProvider {
		return &fakeSchemaProvider{schema: auth.PluginSchema{
			"custom": {Fields: map[string]auth.FieldAttribute{"a": {Type: auth.FieldTypeString}}},
		}}
	})
	defer auth.UnregisterPluginSchema("test-gen-fake")
	plugins, err := buildPlugins("test-gen-fake", false)
	if err != nil {
		t.Fatalf("registered plugin must build: %v", err)
	}
	if len(plugins) != 1 || len(plugins[0].Schema()["custom"].Fields) != 1 {
		t.Fatal("registered plugin schema must be visible")
	}
	if _, err := buildPlugins("no-such-plugin", false); err == nil {
		t.Fatal("unknown plugin must fail")
	}
	if _, err = buildPlugins("test-gen-fake,admin", false); err == nil {
		t.Fatal("removed built-in admin must fail")
	}
}

type fakeSchemaProvider struct {
	schema auth.PluginSchema
}

func (f *fakeSchemaProvider) Schema() auth.PluginSchema { return f.schema }

func TestFieldFromSchemaSkipsFuncDefaults(t *testing.T) {
	table := auth.TableSchema{Fields: map[string]auth.FieldAttribute{
		"createdAt": {Type: auth.FieldTypeDate, DefaultValue: auth.DateNowDefault},
		"name":      {Type: auth.FieldTypeString, DefaultValue: "x"},
	}}
	field, err := fieldFromSchema("user", table, "createdAt", testConfig())
	if err != nil {
		t.Fatalf("field must build: %v", err)
	}
	for _, part := range field.TagParts {
		if strings.HasPrefix(part, "default:") {
			t.Fatalf("func defaults must not render tags: %v", field.TagParts)
		}
	}
	field, err = fieldFromSchema("user", table, "name", testConfig())
	if err != nil {
		t.Fatalf("field must build: %v", err)
	}
	found := false
	for _, part := range field.TagParts {
		if part == "default:'x'" {
			found = true
		}
	}
	if !found {
		t.Fatalf("static defaults must still render: %v", field.TagParts)
	}
}
