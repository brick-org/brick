package auth_test

import (
	"strings"
	"testing"
	"time"

	auth "github.com/brick-org/brick/auth/src"
)

// FullSchema must name the complete resolved schema (core + plugins +
// options) so route code can migrate off the legacy plugin-only
// ResolveSchema allow-list without behavior flips.
func TestSchemaSplit_FullSchemaEqualsGetAuthTables(t *testing.T) {
	plugin := &schemaFixPlugin{
		id: "test",
		schema: auth.PluginSchema{
			"user": {Fields: map[string]auth.FieldAttribute{
				"role": {Type: auth.FieldTypeString},
			}},
		},
	}
	opts := auth.Options{Plugins: []auth.Plugin{plugin}}
	full := auth.FullSchema(opts)
	tables := auth.GetAuthTables(opts)
	if len(full) != len(tables) {
		t.Fatalf("FullSchema must equal GetAuthTables: %d vs %d tables", len(full), len(tables))
	}
	if _, ok := full["user"].Fields["role"]; !ok {
		t.Fatal("FullSchema must include plugin fields")
	}
	if _, ok := full["user"].Fields["email"]; !ok {
		t.Fatal("FullSchema must include core fields")
	}
	legacy := auth.ResolveSchema(opts)
	if _, ok := legacy["user"].Fields["email"]; ok {
		t.Fatal("legacy ResolveSchema must stay plugin-only (no core fields)")
	}
}

// Core timestamp columns must carry defaultValue/onUpdate metadata mirroring
// upstream get-tables.ts (() => new Date() factories and onUpdate hooks).
func TestSchemaSplit_TimestampDefaultsCarried(t *testing.T) {
	tables := auth.GetAuthTables(auth.Options{})
	for _, pair := range [][2]string{
		{"user", "createdAt"}, {"user", "updatedAt"},
		{"session", "createdAt"}, {"session", "updatedAt"},
		{"account", "createdAt"}, {"account", "updatedAt"},
		{"verification", "createdAt"}, {"verification", "updatedAt"},
	} {
		model, field := pair[0], pair[1]
		attr := tables[model].Fields[field]
		if !auth.HasTimestampColumnDefault(attr) {
			t.Fatalf("%s.%s must carry a timestamp default", model, field)
		}
		if v := auth.DateNowDefault(); v == nil {
			t.Fatal("DateNowDefault must produce a value")
		}
	}
	for _, pair := range [][2]string{
		{"user", "updatedAt"},
		{"session", "updatedAt"},
		{"account", "updatedAt"},
		{"verification", "updatedAt"},
	} {
		model, field := pair[0], pair[1]
		if tables[model].Fields[field].OnUpdate == nil {
			t.Fatalf("%s.%s must carry onUpdate", model, field)
		}
		if got := tables[model].Fields[field].OnUpdate(); got == nil {
			t.Fatalf("%s.%s onUpdate must produce a value", model, field)
		}
	}
	if _, ok := tables["user"].Fields["createdAt"].DefaultValue.(func() any); !ok {
		t.Fatal("createdAt DefaultValue must be a func (upstream () => new Date())")
	}
}

func TestSchemaSplit_RateLimitTimestampDefault(t *testing.T) {
	rl := auth.RateLimitSchema()["rateLimit"]
	lastRequest := rl.Fields["lastRequest"]
	if !auth.HasFuncDefault(lastRequest) {
		t.Fatal("rateLimit.lastRequest must carry the Date.now() factory default")
	}
	if auth.HasStaticColumnDefault(lastRequest) {
		t.Fatal("func defaults are not static column defaults")
	}
	if auth.DateNowMillisDefault() == nil {
		t.Fatal("DateNowMillisDefault must produce a value")
	}
	_ = time.Now
}

// Explicit index names must be validated like upstream getDatabaseIndexName.
func TestSchemaSplit_ValidateIndexName(t *testing.T) {
	if err := auth.ValidateIndexName("custom_idx"); err != nil {
		t.Fatalf("valid name must pass: %v", err)
	}
	for _, bad := range []string{"", "   ", "has-dash", "9starts", strings.Repeat("a", 64)} {
		if err := auth.ValidateIndexName(bad); err == nil {
			t.Fatalf("invalid index name %q must fail", bad)
		}
	}
}

func TestSchemaSplit_ValidateSchemaIndexes(t *testing.T) {
	cfg := auth.AdapterConfig{}
	cases := map[string]auth.PluginSchema{
		"unknown field": {
			"m": {Fields: map[string]auth.FieldAttribute{
				"a": {Type: auth.FieldTypeString},
			}, Indexes: []auth.TableIndex{{Fields: []string{"nope"}}}},
		},
		"empty fields": {
			"m": {Fields: map[string]auth.FieldAttribute{
				"a": {Type: auth.FieldTypeString},
			}, Indexes: []auth.TableIndex{{Fields: []string{}}}},
		},
		"duplicate fields": {
			"m": {Fields: map[string]auth.FieldAttribute{
				"a": {Type: auth.FieldTypeString},
			}, Indexes: []auth.TableIndex{{Fields: []string{"a", "a"}}}},
		},
		"nullable unique": {
			"m": {Fields: map[string]auth.FieldAttribute{
				"a": {Type: auth.FieldTypeString, Required: boolPtrForTest(false)},
			}, Indexes: []auth.TableIndex{{Fields: []string{"a"}, Unique: true}}},
		},
		"json indexed": {
			"m": {Fields: map[string]auth.FieldAttribute{
				"a": {Type: auth.FieldTypeJSON},
			}, Indexes: []auth.TableIndex{{Fields: []string{"a"}}}},
		},
		"same column twice": {
			"m": {Fields: map[string]auth.FieldAttribute{
				"a": {Type: auth.FieldTypeString},
				"b": {Type: auth.FieldTypeString, FieldName: "a"},
			}, Indexes: []auth.TableIndex{{Fields: []string{"a", "b"}}}},
		},
		"same name different definition": {
			"m": {Fields: map[string]auth.FieldAttribute{
				"a": {Type: auth.FieldTypeString},
				"b": {Type: auth.FieldTypeString},
			}, Indexes: []auth.TableIndex{
				{Fields: []string{"a"}, Name: "dup"},
				{Fields: []string{"b"}, Name: "dup"},
			}},
		},
		"index name collides with table": {
			"users": {Fields: map[string]auth.FieldAttribute{
				"a": {Type: auth.FieldTypeString},
			}, Indexes: []auth.TableIndex{{Fields: []string{"a"}, Name: "ms"}}},
			"m": {Fields: map[string]auth.FieldAttribute{
				"a": {Type: auth.FieldTypeString},
			}},
		},
		"cross-table name collision": {
			"m1": {Fields: map[string]auth.FieldAttribute{
				"a": {Type: auth.FieldTypeString},
			}, Indexes: []auth.TableIndex{{Fields: []string{"a"}, Name: "shared_idx"}}},
			"m2": {Fields: map[string]auth.FieldAttribute{
				"b": {Type: auth.FieldTypeString},
			}, Indexes: []auth.TableIndex{{Fields: []string{"b"}, Name: "shared_idx"}}},
		},
		"aliased tables with indexes": {
			"m1": {ModelName: "shared", Fields: map[string]auth.FieldAttribute{
				"a": {Type: auth.FieldTypeString},
			}, Indexes: []auth.TableIndex{{Fields: []string{"a"}}}},
			"m2": {ModelName: "shared", Fields: map[string]auth.FieldAttribute{
				"b": {Type: auth.FieldTypeString},
			}, Indexes: []auth.TableIndex{{Fields: []string{"b"}}}},
		},
	}
	for name, schema := range cases {
		if err := auth.ValidateSchemaIndexes(schema, cfg); err == nil {
			t.Fatalf("case %q must fail validation", name)
		}
	}
}

func TestSchemaSplit_ValidateSchemaIndexesAcceptsGood(t *testing.T) {
	if err := auth.ValidateSchemaIndexes(auth.GetAuthTables(auth.Options{}), auth.AdapterConfig{}); err != nil {
		t.Fatalf("core schema must validate: %v", err)
	}
	schema := auth.PluginSchema{
		"m": {
			Fields: map[string]auth.FieldAttribute{
				"a": {Type: auth.FieldTypeString},
				"b": {Type: auth.FieldTypeString},
			},
			Indexes: []auth.TableIndex{
				{Fields: []string{"a", "b"}},
				{Fields: []string{"a"}, Name: "m_a_uidx", Unique: true},
			},
		},
	}
	if err := auth.ValidateSchemaIndexes(schema, auth.AdapterConfig{}); err != nil {
		t.Fatalf("valid schema must pass: %v", err)
	}
	// Disabled tables are skipped like upstream.
	disabled := auth.PluginSchema{
		"m": {
			DisableMigration: true,
			Fields:           map[string]auth.FieldAttribute{"a": {Type: auth.FieldTypeString}},
			Indexes:          []auth.TableIndex{{Fields: []string{"nope"}}},
		},
	}
	if err := auth.ValidateSchemaIndexes(disabled, auth.AdapterConfig{}); err != nil {
		t.Fatalf("disabled tables must be skipped: %v", err)
	}
}

func TestSchemaSplit_PluginSchemaRegistry(t *testing.T) {
	auth.RegisterPluginSchema("test-split-fake", func() auth.PluginSchemaProvider {
		return &schemaFixPlugin{id: "fake", schema: auth.PluginSchema{
			"custom": {Fields: map[string]auth.FieldAttribute{"a": {Type: auth.FieldTypeString}}},
		}}
	})
	defer auth.UnregisterPluginSchema("test-split-fake")
	merged, err := auth.PluginSchemasForIDs([]string{"test-split-fake"})
	if err != nil {
		t.Fatalf("registered provider must resolve: %v", err)
	}
	if _, ok := merged["custom"]; !ok {
		t.Fatal("registered provider schema must merge")
	}
	if _, err := auth.PluginSchemasForIDs([]string{"no-such-plugin"}); err == nil {
		t.Fatal("unknown plugin ID must error")
	}
}
