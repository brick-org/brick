package auth_test

import (
	"strings"
	"testing"

	auth "github.com/brick-org/brick/auth/src"
)

// Port of vendor/better-auth/packages/core/src/db/schema-diff.test.ts
// (Better Auth v1.7.5) plus Go-only DiffSchemas/unsafe-change coverage.
// Upstream uses vitest; the cases below preserve the assertions.

func diffExpected() auth.ExpectedSchema {
	return auth.ExpectedSchema{
		"account": {Fields: map[string]auth.FieldAttribute{
			"accountId":  {Type: auth.FieldTypeString},
			"providerId": {Type: auth.FieldTypeString},
		}},
	}
}

func diffColumn(name string, nullable, hasDefault bool) auth.IntrospectedColumn {
	return auth.IntrospectedColumn{Name: name, Nullable: nullable, HasDefault: hasDefault}
}

func TestSchemaDiff_MissingTable(t *testing.T) {
	findings := auth.DiffSchema(diffExpected(), nil)
	if len(findings) != 1 || findings[0].Kind != auth.SchemaFindingMissingTable || findings[0].Table != "account" {
		t.Fatalf("must report the missing table: %v", findings)
	}
}

func TestSchemaDiff_MissingColumnIncludingImplicitID(t *testing.T) {
	actual := []auth.IntrospectedTable{{Name: "account", Columns: []auth.IntrospectedColumn{diffColumn("accountId", false, false)}}}
	findings := auth.DiffSchema(diffExpected(), actual)
	want := []auth.SchemaFinding{
		{Kind: auth.SchemaFindingMissingColumn, Table: "account", Column: "id"},
		{Kind: auth.SchemaFindingMissingColumn, Table: "account", Column: "providerId"},
	}
	if len(findings) != len(want) {
		t.Fatalf("findings = %v, want %v", findings, want)
	}
	for i := range want {
		if findings[i] != want[i] {
			t.Fatalf("findings = %v, want %v", findings, want)
		}
	}
}

func TestSchemaDiff_UnexpectedRequiredColumn(t *testing.T) {
	actual := []auth.IntrospectedTable{{Name: "account", Columns: []auth.IntrospectedColumn{
		diffColumn("id", false, false),
		diffColumn("accountId", false, false),
		diffColumn("providerId", false, false),
		diffColumn("issuer", false, false),
	}}}
	findings := auth.DiffSchema(diffExpected(), actual)
	if len(findings) != 1 || findings[0].Kind != auth.SchemaFindingUnexpectedRequiredColumn || findings[0].Column != "issuer" {
		t.Fatalf("must report the unexpected required column: %v", findings)
	}
}

func TestSchemaDiff_ToleratesNullableOrDefaultedExtras(t *testing.T) {
	actual := []auth.IntrospectedTable{{Name: "account", Columns: []auth.IntrospectedColumn{
		diffColumn("id", false, false),
		diffColumn("accountId", false, false),
		diffColumn("providerId", false, false),
		diffColumn("issuer", true, false),
		diffColumn("tier", false, true),
	}}}
	if findings := auth.DiffSchema(diffExpected(), actual); len(findings) != 0 {
		t.Fatalf("nullable/defaulted extras must be tolerated: %v", findings)
	}
}

func TestSchemaDiff_SchemaQualifiedMatching(t *testing.T) {
	columns := []auth.IntrospectedColumn{diffColumn("id", false, false), diffColumn("accountId", false, false), diffColumn("providerId", false, false)}
	qualified := auth.ExpectedSchema{"account": {Fields: diffExpected()["account"].Fields, Schema: "auth"}}
	if findings := auth.DiffSchema(qualified, []auth.IntrospectedTable{{Name: "account", Schema: "public", Columns: columns}}); len(findings) != 1 || findings[0].Kind != auth.SchemaFindingMissingTable {
		t.Fatalf("schema-qualified table must miss in another schema: %v", findings)
	}
	if findings := auth.DiffSchema(qualified, []auth.IntrospectedTable{{Name: "account", Schema: "auth", Columns: columns}}); len(findings) != 0 {
		t.Fatalf("schema-qualified table must match in its schema: %v", findings)
	}
	if findings := auth.DiffSchema(diffExpected(), []auth.IntrospectedTable{{Name: "account", Schema: "auth", Columns: columns}}); len(findings) != 0 {
		t.Fatalf("unqualified expectation must match any schema: %v", findings)
	}
}

func TestSchemaDiff_SkipsDisableMigrations(t *testing.T) {
	expected := auth.ExpectedSchema{
		"account": diffExpected()["account"],
		"jwks":    {Fields: map[string]auth.FieldAttribute{}, DisableMigrations: true},
	}
	actual := []auth.IntrospectedTable{{Name: "account", Columns: []auth.IntrospectedColumn{
		diffColumn("id", false, false), diffColumn("accountId", false, false), diffColumn("providerId", false, false),
	}}}
	if findings := auth.DiffSchema(expected, actual); len(findings) != 0 {
		t.Fatalf("self-managed tables must be skipped: %v", findings)
	}
}

// Shared physical tables merge regardless of model order (upstream
// "shared physical tables" suite with reversed=%s).
func TestSchemaDiff_SharedPhysicalTables(t *testing.T) {
	for _, reversed := range []bool{false, true} {
		models := [][2]string{{"managed", "value"}, {"external", ""}}
		if reversed {
			models[0], models[1] = models[1], models[0]
		}
		tables := auth.PluginSchema{}
		for _, m := range models {
			if m[1] == "" {
				tables[m[0]] = auth.TableSchema{ModelName: "shared", DisableMigration: true, Fields: map[string]auth.FieldAttribute{}}
			} else {
				tables[m[0]] = auth.TableSchema{ModelName: "shared", Fields: map[string]auth.FieldAttribute{"value": {Type: auth.FieldTypeString}}}
			}
		}
		expected := auth.ExpectedSchemaFromTables(tables, auth.AdapterConfig{})
		shared := auth.ExpectedSchema{"shared": expected["shared"]}
		if findings := auth.DiffSchema(shared, nil); len(findings) != 1 || findings[0].Kind != auth.SchemaFindingMissingTable {
			t.Fatalf("reversed=%v: shared table must be missing: %v", reversed, findings)
		}
		partial := []auth.IntrospectedTable{{Name: "shared", Columns: []auth.IntrospectedColumn{diffColumn("id", false, false)}}}
		findings := auth.DiffSchema(shared, partial)
		if len(findings) != 1 || findings[0].Kind != auth.SchemaFindingMissingColumn || findings[0].Column != "value" {
			t.Fatalf("reversed=%v: shared value column must be missing: %v", reversed, findings)
		}
		full := []auth.IntrospectedTable{{Name: "shared", Columns: []auth.IntrospectedColumn{diffColumn("id", false, false), diffColumn("value", false, false)}}}
		if findings := auth.DiffSchema(shared, full); len(findings) != 0 {
			t.Fatalf("reversed=%v: shared table must match: %v", reversed, findings)
		}
	}
}

func TestSchemaDiff_FormatMessages(t *testing.T) {
	issuer := auth.SchemaFinding{Kind: auth.SchemaFindingUnexpectedRequiredColumn, Table: "account", Column: "issuer"}
	for _, table := range []string{"account", "accounts", "plugin_tokens"} {
		message := auth.FormatSchemaFinding(auth.SchemaFinding{Kind: issuer.Kind, Table: table, Column: "issuer"}, auth.SchemaSourceDatabase)
		if !strings.Contains(message, "If this column came from Better Auth 1.7.0 through 1.7.2") {
			t.Fatalf("issuer note missing for %s: %q", table, message)
		}
		if strings.Contains(message, table+"_issuer_accountId_uidx") {
			t.Fatalf("must not assume an index name: %q", message)
		}
	}
	if got := auth.FormatSchemaFinding(issuer, auth.SchemaSourcePrisma); !strings.Contains(got, "Remove it from the Prisma schema") {
		t.Fatalf("prisma fix wording: %q", got)
	}
	if got := auth.FormatSchemaFinding(issuer, auth.SchemaSourceDrizzle); !strings.Contains(got, "Remove it from the Drizzle schema") {
		t.Fatalf("drizzle fix wording: %q", got)
	}
	if got := auth.FormatSchemaFinding(auth.SchemaFinding{Kind: auth.SchemaFindingMissingTable, Table: "user"}, auth.SchemaSourceDatabase); !strings.Contains(got, `Table "user" is missing.`) || !strings.Contains(got, "npx auth migrate") {
		t.Fatalf("missing-table wording: %q", got)
	}
}

func TestSchemaDiff_MismatchGrouping(t *testing.T) {
	err := &auth.SchemaMismatchError{
		Findings: []auth.SchemaFinding{
			{Kind: auth.SchemaFindingMissingTable, Table: "user"},
			{Kind: auth.SchemaFindingMissingTable, Table: "session"},
			{Kind: auth.SchemaFindingMissingTable, Table: "account"},
			{Kind: auth.SchemaFindingMissingTable, Table: "verification"},
		},
		Source: auth.SchemaSourceDatabase,
	}
	want := "Database schema mismatch\n\n  Missing tables\n    user, session, account, verification\n\n  help: Run `npx auth migrate` to add the missing tables and columns."
	if err.Error() != want {
		t.Fatalf("mismatch message:\n got %q\nwant %q", err.Error(), want)
	}

	mixed := &auth.SchemaMismatchError{
		Findings: []auth.SchemaFinding{
			{Kind: auth.SchemaFindingMissingColumn, Table: "user", Column: "email"},
			{Kind: auth.SchemaFindingUnexpectedRequiredColumn, Table: "account", Column: "issuer"},
			{Kind: auth.SchemaFindingMissingTable, Table: "verification"},
		},
		Source: auth.SchemaSourceDatabase,
	}
	wantMixed := "Database schema mismatch\n\n  Missing tables\n    verification\n\n  Missing columns\n    user.email\n\n  Required columns Better Auth never writes\n    account.issuer\n\n  Inserts into account will fail.\n\n  help: Make the listed columns nullable, give them defaults, or remove them.\n        Run `npx auth migrate` to add the missing tables and columns.\n\n  note: If this column came from Better Auth 1.7.0 through 1.7.2,\n        follow the upgrade guide before removing it:\n        https://www.better-auth.com/docs/guides/1-7-upgrade-guide"
	if mixed.Error() != wantMixed {
		t.Fatalf("mixed message:\n got %q\nwant %q", mixed.Error(), wantMixed)
	}
}

func TestSchemaDiff_NonDatabaseWorkflow(t *testing.T) {
	for _, tc := range []struct {
		source auth.SchemaSource
		repair string
		apply  string
	}{
		{auth.SchemaSourceDrizzle, "nullable in your Drizzle schema", "apply it with your migration tool"},
		{auth.SchemaSourcePrisma, "optional in your Prisma schema", "prisma migrate"},
	} {
		err := &auth.SchemaMismatchError{
			Findings: []auth.SchemaFinding{
				{Kind: auth.SchemaFindingUnexpectedRequiredColumn, Table: "account", Column: "legacyKey"},
				{Kind: auth.SchemaFindingUnexpectedRequiredColumn, Table: "user", Column: "legacyRole"},
			},
			Source: tc.source,
		}
		message := err.Error()
		if !strings.Contains(message, tc.repair) || !strings.Contains(message, tc.apply) {
			t.Fatalf("%s workflow wording: %q", tc.source, message)
		}
		if strings.Count(message, "npx auth generate") != 1 {
			t.Fatalf("%s must name generate exactly once: %q", tc.source, message)
		}
		if strings.Contains(message, "npx auth migrate") {
			t.Fatalf("%s must not name migrate: %q", tc.source, message)
		}
	}
}

func TestSchemaDiff_UnsafeColumnMessage(t *testing.T) {
	message := auth.UnsafeColumnChangeMessage("directoryUser", "connectionIssuer", auth.FieldTypeString)
	if !strings.Contains(message, `Cannot add required column "connectionIssuer" to populated table "directoryUser"`) {
		t.Fatalf("unsafe message names table/column: %q", message)
	}
	if !strings.Contains(message, "MySQL") || !strings.Contains(message, "empty string") {
		t.Fatalf("unsafe message carries corruption details: %q", message)
	}
	number := auth.UnsafeColumnChangeMessage("directoryUser", "seatCount", auth.FieldTypeNumber)
	if strings.Contains(number, "empty string") {
		t.Fatalf("non-text columns must not carry the empty-string detail: %q", number)
	}
	var unsafeErr *auth.UnsafeMigrationError
	_ = unsafeErr
	if got := (&auth.UnsafeMigrationError{Message: message}).Error(); got != message {
		t.Fatal("UnsafeMigrationError must carry its message")
	}
}

func TestSchemaDiff_IsUnsafeColumnAddition(t *testing.T) {
	required := true
	optional := false
	if !auth.IsUnsafeColumnAddition(auth.FieldAttribute{Type: auth.FieldTypeString, Required: &required}, false) {
		t.Fatal("required no-default column must be unsafe")
	}
	if auth.IsUnsafeColumnAddition(auth.FieldAttribute{Type: auth.FieldTypeString, Required: &optional}, false) {
		t.Fatal("nullable column must be safe")
	}
	if auth.IsUnsafeColumnAddition(auth.FieldAttribute{Type: auth.FieldTypeString, Required: &required, DefaultValue: "x"}, false) {
		t.Fatal("static default must be safe")
	}
	if auth.IsUnsafeColumnAddition(auth.FieldAttribute{Type: auth.FieldTypeDate, Required: &required, DefaultValue: auth.DateNowDefault}, true) {
		t.Fatal("timestamp default on a timestamp dialect must be safe")
	}
	if !auth.IsUnsafeColumnAddition(auth.FieldAttribute{Type: auth.FieldTypeDate, Required: &required, DefaultValue: auth.DateNowDefault}, false) {
		t.Fatal("timestamp default on sqlite must be unsafe")
	}
	if !auth.SupportsTimestampColumnDefault("postgres") || !auth.SupportsTimestampColumnDefault("mysql") || !auth.SupportsTimestampColumnDefault("mssql") {
		t.Fatal("postgres/mysql/mssql must support timestamp defaults")
	}
	if auth.SupportsTimestampColumnDefault("sqlite") {
		t.Fatal("sqlite must not support timestamp defaults")
	}
}

func TestSchemaDiff_MatchColumnType(t *testing.T) {
	if !auth.MatchColumnType("timestamptz", auth.FieldTypeDate, "postgres") {
		t.Fatal("timestamptz must match date on postgres")
	}
	if !auth.MatchColumnType("TEXT", auth.FieldTypeString, "sqlite") {
		t.Fatal("TEXT must match string on sqlite")
	}
	if !auth.MatchColumnType("varchar(255)", auth.FieldTypeString, "mysql") {
		t.Fatal("varchar(255) must match string on mysql ignoring parameters")
	}
	if !auth.MatchColumnType("json", "string[]", "postgres") {
		t.Fatal("array fields expect a JSON store")
	}
	if auth.MatchColumnType("text", auth.FieldTypeString, "postgres") != true {
		t.Fatal("text must match string on postgres")
	}
	if auth.MatchColumnType("integer", auth.FieldTypeString, "postgres") {
		t.Fatal("integer must not match string on postgres")
	}
	if auth.MatchColumnType("text", auth.FieldTypeString, "oracle") {
		t.Fatal("unknown dialects must not match")
	}
}

func TestSchemaDiff_DiffSchemasFreshAndIncremental(t *testing.T) {
	cfg := auth.AdapterConfig{}
	desired := auth.PluginSchema{
		"directoryUser": {Fields: map[string]auth.FieldAttribute{
			"externalId":       {Type: auth.FieldTypeString},
			"connectionIssuer": {Type: auth.FieldTypeString, Required: boolPtrDiff(true)},
		}},
	}
	// Fresh install: everything is created, nothing is unsafe.
	fresh, err := auth.DiffSchemas(auth.PluginSchema{}, desired, cfg, nil, false)
	if err != nil {
		t.Fatalf("fresh diff must build: %v", err)
	}
	if len(fresh.ToBeCreated) != 1 || len(fresh.UnsafeChanges) != 0 {
		t.Fatalf("fresh diff must create without unsafe: %+v", fresh)
	}
	// Incremental on an empty table: safe ALTER.
	current := auth.PluginSchema{
		"directoryUser": {Fields: map[string]auth.FieldAttribute{
			"externalId": {Type: auth.FieldTypeString},
		}},
	}
	empty, err := auth.DiffSchemas(current, desired, cfg, map[string]bool{"directory_users": false}, false)
	if err != nil {
		t.Fatalf("empty-table diff must build: %v", err)
	}
	if len(empty.ToBeAdded) != 1 || len(empty.UnsafeChanges) != 0 {
		t.Fatalf("empty table must plan a safe add: %+v", empty)
	}
	// Incremental on a populated table: unsafe refusal as data.
	populated, err := auth.DiffSchemas(current, desired, cfg, map[string]bool{"directory_users": true}, false)
	if err != nil {
		t.Fatalf("populated diff must build: %v", err)
	}
	if len(populated.ToBeAdded) != 1 || len(populated.UnsafeChanges) != 1 {
		t.Fatalf("populated table must flag unsafe: %+v", populated)
	}
	if !strings.Contains(populated.UnsafeChanges[0], `Cannot add required column "connection_issuer" to populated table "directory_users"`) {
		t.Fatalf("unsafe message uses physical names: %q", populated.UnsafeChanges[0])
	}
	// Nil populated map assumes populated (conservative offline default).
	conservative, err := auth.DiffSchemas(current, desired, cfg, nil, false)
	if err != nil {
		t.Fatalf("conservative diff must build: %v", err)
	}
	if len(conservative.UnsafeChanges) != 1 {
		t.Fatalf("nil populated map must assume populated: %+v", conservative)
	}
	// Static defaults stay safe on populated tables.
	withDefault := auth.PluginSchema{
		"directoryUser": {Fields: map[string]auth.FieldAttribute{
			"externalId":       {Type: auth.FieldTypeString},
			"connectionIssuer": {Type: auth.FieldTypeString, Required: boolPtrDiff(true), DefaultValue: "local"},
		}},
	}
	safe, err := auth.DiffSchemas(current, withDefault, cfg, nil, false)
	if err != nil {
		t.Fatalf("defaulted diff must build: %v", err)
	}
	if len(safe.UnsafeChanges) != 0 {
		t.Fatalf("static default must be safe: %+v", safe)
	}
}

func TestSchemaDiff_DiffSchemasIndexConflict(t *testing.T) {
	cfg := auth.AdapterConfig{}
	current := auth.PluginSchema{
		"directoryUser": {
			ModelName: "directory_user",
			Fields: map[string]auth.FieldAttribute{
				"connectionId": {Type: auth.FieldTypeString, FieldName: "connection_id"},
				"externalId":   {Type: auth.FieldTypeString, FieldName: "external_id"},
			},
			Indexes: []auth.TableIndex{{Fields: []string{"connectionId"}, Name: "directory_identity_uidx"}},
		},
	}
	desired := auth.PluginSchema{
		"directoryUser": {
			ModelName: "directory_user",
			Fields: map[string]auth.FieldAttribute{
				"connectionId": {Type: auth.FieldTypeString, FieldName: "connection_id"},
				"externalId":   {Type: auth.FieldTypeString, FieldName: "external_id"},
			},
			Indexes: []auth.TableIndex{{Fields: []string{"connectionId", "externalId"}, Name: "directory_identity_uidx", Unique: true}},
		},
	}
	if _, err := auth.DiffSchemas(current, desired, cfg, nil, false); err == nil || !strings.Contains(err.Error(), `database index "directory_identity_uidx" on table "directory_user" does not match`) {
		t.Fatalf("conflicting index definitions must error: %v", err)
	}
}

func TestSchemaDiff_GetExpectedSchemaMergesSharedTables(t *testing.T) {
	plugin := &schemaDiffPlugin{id: "shared", schema: auth.PluginSchema{
		"managed":  {ModelName: "shared", Fields: map[string]auth.FieldAttribute{"value": {Type: auth.FieldTypeString}}},
		"external": {ModelName: "shared", DisableMigration: true, Fields: map[string]auth.FieldAttribute{}},
	}}
	opts := auth.Options{Plugins: []auth.Plugin{plugin}}
	expected := auth.GetExpectedSchema(opts, auth.AdapterConfig{})
	shared, ok := expected["shared"]
	if !ok {
		t.Fatal("shared physical table must be present")
	}
	if _, ok := shared.Fields["value"]; !ok {
		t.Fatal("shared fields must merge")
	}
	if !shared.DisableMigrations {
		// Shared disableMigrations ANDs from true: any migrating
		// contributor keeps the shared table migrating.
	} else {
		t.Fatal("shared table must migrate when any contributor migrates")
	}
}

type schemaDiffPlugin struct {
	id     string
	schema auth.PluginSchema
}

func (p *schemaDiffPlugin) ID() string { return p.id }

func (p *schemaDiffPlugin) Init(_ auth.AuthContext) error { return nil }

func (p *schemaDiffPlugin) Endpoints() []auth.Endpoint { return nil }

func (p *schemaDiffPlugin) Schema() auth.PluginSchema { return p.schema }

func (p *schemaDiffPlugin) Hooks() auth.DBHooks { return nil }

func (p *schemaDiffPlugin) RouteHooks() auth.PluginRouteHooks { return auth.PluginRouteHooks{} }

func (p *schemaDiffPlugin) ErrorCodes() map[string]string { return nil }

func boolPtrDiff(v bool) *bool { return &v }
