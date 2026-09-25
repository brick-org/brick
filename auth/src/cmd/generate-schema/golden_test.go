package main

// Dialect-specific DDL golden fixtures mirroring upstream compileMigrations output.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	auth "github.com/brick-org/brick/auth/src"
)

func canonicalGoldenSchema() auth.PluginSchema {
	optional := false
	return auth.PluginSchema{
		"user": {
			ModelName: "app_users",
			Fields: map[string]auth.FieldAttribute{
				"name":          {Type: auth.FieldTypeString},
				"email":         {Type: auth.FieldTypeString, Unique: true},
				"emailVerified": {Type: auth.FieldTypeBoolean, DefaultValue: false},
				"image":         {Type: auth.FieldTypeString, Required: &optional},
				"age":           {Type: auth.FieldTypeNumber, Required: &optional},
				"createdAt":     {Type: auth.FieldTypeDate, DefaultValue: auth.DateNowDefault},
				"updatedAt":     {Type: auth.FieldTypeDate, DefaultValue: auth.DateNowDefault, OnUpdate: auth.DateNowDefault},
			},
		},
		"session": {
			Fields: map[string]auth.FieldAttribute{
				"token":     {Type: auth.FieldTypeString, Unique: true},
				"expiresAt": {Type: auth.FieldTypeDate},
				"ipAddress": {Type: auth.FieldTypeString, Required: &optional},
				"userAgent": {Type: auth.FieldTypeString, Required: &optional},
				"createdAt": {Type: auth.FieldTypeDate, DefaultValue: auth.DateNowDefault},
				"updatedAt": {Type: auth.FieldTypeDate, DefaultValue: auth.DateNowDefault, OnUpdate: auth.DateNowDefault},
				"userId": {
					Type:       auth.FieldTypeString,
					Index:      true,
					References: &auth.FieldReference{Model: "user", Field: "id", OnDelete: "cascade"},
				},
			},
		},
		"organization": {
			Fields: map[string]auth.FieldAttribute{
				"name":      {Type: auth.FieldTypeString},
				"slug":      {Type: auth.FieldTypeString, Unique: true},
				"seats":     {Type: auth.FieldTypeNumber, DefaultValue: int64(5)},
				"metadata":  {Type: auth.FieldTypeJSON, Required: &optional},
				"createdAt": {Type: auth.FieldTypeDate, DefaultValue: auth.DateNowDefault},
			},
		},
		"member": {
			Fields: map[string]auth.FieldAttribute{
				"organizationId": {
					Type:       auth.FieldTypeString,
					Index:      true,
					References: &auth.FieldReference{Model: "organization", Field: "id", OnDelete: "cascade"},
				},
				"userId": {
					Type:       auth.FieldTypeString,
					Index:      true,
					References: &auth.FieldReference{Model: "user", Field: "id", OnDelete: "cascade"},
				},
				"role": {Type: auth.FieldTypeString, DefaultValue: "member"},
			},
			Indexes: []auth.TableIndex{{Fields: []string{"organizationId", "userId"}, Unique: true}},
		},
	}
}

func TestGoldenFixtures(t *testing.T) {
	schema := canonicalGoldenSchema()
	cfg := auth.AdapterConfig{}
	for dialect, file := range map[Dialect]string{
		DialectSQLite:   "golden_sqlite.sql",
		DialectPostgres: "golden_postgres.sql",
		DialectMySQL:    "golden_mysql.sql",
		DialectMSSQL:    "golden_mssql.sql",
	} {
		plan, err := BuildMigrationPlan(schema, cfg, dialect, "string")
		if err != nil {
			t.Fatalf("%s: plan must build: %v", dialect, err)
		}
		if len(plan.UnsafeChanges) != 0 {
			t.Fatalf("%s: golden schema must be safe: %v", dialect, plan.UnsafeChanges)
		}
		got := plan.Script()
		path := filepath.Join("testdata", file)
		if os.Getenv("GOLDEN_UPDATE") != "" {
			if err := os.MkdirAll("testdata", 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: read fixture (regenerate with GOLDEN_UPDATE=1): %v", dialect, err)
		}
		if got != string(want) {
			t.Fatalf("%s: script differs from fixture; diff:\n%s", dialect, lineDiff(string(want), got))
		}
	}
}

// TestGoldenFixturesFKOrdering: FK targets before dependents, tables before indexes (upstream deferredIndexes).
func TestGoldenFixturesFKOrdering(t *testing.T) {
	plan, err := BuildMigrationPlan(canonicalGoldenSchema(), auth.AdapterConfig{}, DialectSQLite, "string")
	if err != nil {
		t.Fatalf("plan must build: %v", err)
	}
	script := plan.Script()
	order := []string{`"app_users"`, `"sessions"`, `"organizations"`, `"members"`}
	for i := 1; i < len(order); i++ {
		if strings.Index(script, order[i-1]) > strings.Index(script, order[i]) {
			t.Fatalf("table order violated: %s must precede %s:\n%s", order[i-1], order[i], script)
		}
	}
	lastCreate := strings.LastIndex(script, "create table")
	firstIndex := strings.Index(script, "create index")
	if firstIndex >= 0 && firstIndex < lastCreate {
		t.Fatalf("indexes must defer until after every table:\n%s", script)
	}
	if !strings.Contains(script, `create unique index "members_organization_id_user_id_uidx" on "members" ("organization_id", "user_id")`) {
		t.Fatalf("compound unique member index must defer:\n%s", script)
	}
}

func lineDiff(want, got string) string {
	wantLines := strings.Split(want, "\n")
	gotLines := strings.Split(got, "\n")
	var b strings.Builder
	for i := 0; i < len(wantLines) || i < len(gotLines); i++ {
		var w, g string
		if i < len(wantLines) {
			w = wantLines[i]
		}
		if i < len(gotLines) {
			g = gotLines[i]
		}
		if w != g {
			b.WriteString("line " + itoa(i+1) + ":\n  want " + w + "\n  got  " + g + "\n")
		}
	}
	return b.String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
