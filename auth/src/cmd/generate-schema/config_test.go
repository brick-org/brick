package main

// Tests for the arbitrary plugin configuration surface (config.go): specs, JSON tables, builders, files.

import (
	"os"
	"path/filepath"
	"testing"

	auth "github.com/brick-org/brick/auth/src"
)

func TestParsePluginSpec(t *testing.T) {
	id, opts, err := ParsePluginSpec("admin")
	if err != nil || id != "admin" || len(opts) != 0 {
		t.Fatalf("bare spec: %q %q %v", id, opts, err)
	}
	id, opts, err = ParsePluginSpec(`org:{"teams":true}`)
	if err != nil || id != "org" || string(opts) != `{"teams":true}` {
		t.Fatalf("json spec: %q %q %v", id, opts, err)
	}
	id, opts, err = ParsePluginSpec("  ")
	if err != nil || id != "" {
		t.Fatalf("blank spec must be empty: %q %v", id, err)
	}
	for _, bad := range []string{":{}", "org:", `org:{nope}`, `org:[unclosed`} {
		if _, _, err := ParsePluginSpec(bad); err == nil {
			t.Fatalf("spec %q must fail", bad)
		}
	}
}

func TestTableSchemaJSONConversion(t *testing.T) {
	required := true
	optional := false
	declared := TableSchemaJSON{
		ModelName: "app_things",
		Fields: map[string]FieldJSON{
			"name":      {Type: "string"},
			"nick":      {Type: "string", Required: &optional},
			"unique":    {Type: "string", Unique: true},
			"createdAt": {Type: "date", Default: []byte(`"now"`)},
			"ownerId":   {Type: "string", References: &ReferenceJSON{Model: "user", Field: "id", OnDelete: "set null"}},
		},
		Indexes:           []IndexJSON{{Fields: []string{"name", "nick"}, Unique: true}},
		DisableMigrations: &optional,
		Order:             9,
	}
	table, err := declared.ToPluginSchema()
	if err != nil {
		t.Fatalf("conversion must succeed: %v", err)
	}
	if table.ModelName != "app_things" || table.Order != 9 || len(table.Fields) != 5 {
		t.Fatalf("table shape lost: %+v", table)
	}
	if !auth.HasTimestampColumnDefault(table.Fields["createdAt"]) {
		t.Fatal(`"now" sentinel must map to DateNowDefault`)
	}
	if table.Fields["ownerId"].References.OnDelete != "set null" {
		t.Fatalf("references lost: %+v", table.Fields["ownerId"].References)
	}
	if table.DisableMigrations == nil || *table.DisableMigrations {
		t.Fatal("explicit false DisableMigrations must survive")
	}
	_ = required
	for name, field := range map[string]FieldJSON{
		"missing-type": {},
		"bogus":        {Type: "bogus"},
		"array":        {Type: "string[]"},
		"now-on-text":  {Type: "string", Default: []byte(`"now"`)},
		"bad-default":  {Type: "string", Default: []byte(`{oops`)},
		"bad-ref":      {Type: "string", References: &ReferenceJSON{Model: "user"}},
	} {
		if _, err := (TableSchemaJSON{Fields: map[string]FieldJSON{"a": field}}).ToPluginSchema(); err == nil {
			t.Fatalf("field %s must fail", name)
		}
	}
	if _, err := (TableSchemaJSON{Indexes: []IndexJSON{{Name: "x"}}}).ToPluginSchema(); err == nil {
		t.Fatal("empty index fields must fail")
	}
}

func TestBuildPluginsExtended(t *testing.T) {
	auth.RegisterPluginSchema("test-cfg-fake", func() auth.PluginSchemaProvider {
		return &fakeSchemaProvider{schema: auth.PluginSchema{
			"custom": {Fields: map[string]auth.FieldAttribute{"a": {Type: auth.FieldTypeString}}},
		}}
	})
	defer auth.UnregisterPluginSchema("test-cfg-fake")

	if _, err := buildPluginsExtended([]string{"test-cfg-fake"}, nil, false); err != nil {
		t.Fatalf("registered provider must build: %v", err)
	}
	if _, err := buildPluginsExtended([]string{`test-cfg-fake:{"x":1}`}, nil, false); err == nil {
		t.Fatal("registry provider with options must fail")
	}
	if _, err := buildPluginsExtended([]string{"no-such-plugin"}, nil, false); err == nil {
		t.Fatal("unknown plugin must fail")
	}
	if _, err := buildPluginsExtended([]string{"admin"}, nil, false); err == nil {
		t.Fatal("removed built-in admin must fail")
	}
	if _, err := buildPluginsExtended([]string{"org"}, nil, false); err == nil {
		t.Fatal("removed built-in org must fail")
	}
	fileCfg := &GeneratorConfig{ExtraSchemas: map[string]TableSchemaJSON{
		"ticket": {Fields: map[string]FieldJSON{"subject": {Type: "string"}}},
	}}
	plugins, err := buildPluginsExtended(nil, fileCfg, false)
	if err != nil {
		t.Fatalf("extra schemas must build: %v", err)
	}
	if len(plugins) != 1 || len(plugins[0].Schema()["ticket"].Fields) != 1 {
		t.Fatalf("inline schema must be visible: %+v", plugins)
	}
	badCfg := &GeneratorConfig{ExtraSchemas: map[string]TableSchemaJSON{
		"ticket": {Fields: map[string]FieldJSON{"subject": {Type: "bogus"}}},
	}}
	if _, err := buildPluginsExtended(nil, badCfg, false); err == nil {
		t.Fatal("bad inline schema must fail")
	}
}

func TestLoadGeneratorConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gen.json")
	content := `{
		"plugins": ["test-cfg-fake"],
		"pluginOptions": {},
		"extraSchemas": {"ticket": {"fields": {"subject": {"type": "string"}}}},
		"modelNames": {"user": "app_users"},
		"fieldNames": {"user.email": "email_address"},
		"withRateLimit": true,
		"orgTeams": true,
		"dialect": "postgres",
		"idType": "uuid",
		"package": "authmodels",
		"prefix": "Auth",
		"migrateFunc": "AuthModels"
	}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadGeneratorConfig(path)
	if err != nil {
		t.Fatalf("config must load: %v", err)
	}
	if len(cfg.Plugins) != 1 || !cfg.WithRateLimit || !cfg.OrgTeams || cfg.Dialect != "postgres" {
		t.Fatalf("config values lost: %+v", cfg)
	}
	if cfg.ModelNames["user"] != "app_users" || cfg.FieldNames["user.email"] != "email_address" {
		t.Fatalf("renames lost: %+v", cfg)
	}
	auth.RegisterPluginSchema("test-cfg-fake", func() auth.PluginSchemaProvider {
		return &fakeSchemaProvider{schema: auth.PluginSchema{
			"custom": {Fields: map[string]auth.FieldAttribute{"a": {Type: auth.FieldTypeString}}},
		}}
	})
	defer auth.UnregisterPluginSchema("test-cfg-fake")
	plugins, err := buildPluginsExtended(nil, cfg, false)
	if err != nil {
		t.Fatalf("config plugins must build: %v", err)
	}
	if len(plugins) != 2 {
		t.Fatalf("want 2 plugins, got %d", len(plugins))
	}
	merged := auth.SchemasForProviders(pluginProviders(plugins))
	if _, ok := merged["ticket"]; !ok {
		t.Fatal("inline ticket table must merge")
	}
	if _, err := LoadGeneratorConfig(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("missing file must fail")
	}
	if err := os.WriteFile(path, []byte(`{oops`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadGeneratorConfig(path); err == nil {
		t.Fatal("bad JSON must fail")
	}
}

func pluginProviders(plugins []auth.Plugin) []auth.PluginSchemaProvider {
	out := make([]auth.PluginSchemaProvider, 0, len(plugins))
	for _, p := range plugins {
		provider, ok := p.(auth.PluginSchemaProvider)
		if !ok {
			continue
		}
		out = append(out, provider)
	}
	return out
}

func TestMergeAdapterConfigFlagWins(t *testing.T) {
	cfg := parseAdapterConfig("user=flag_users", "user.email=flag_email")
	mergeAdapterConfig(cfg, &GeneratorConfig{
		ModelNames: map[string]string{"user": "file_users", "session": "file_sessions"},
		FieldNames: map[string]string{"user.email": "file_email", "user.name": "file_name"},
	})
	if cfg.ModelNames["user"] != "flag_users" || cfg.ModelNames["session"] != "file_sessions" {
		t.Fatalf("model renames must merge flag-first: %v", cfg.ModelNames)
	}
	if cfg.FieldNames["user.email"] != "flag_email" || cfg.FieldNames["user.name"] != "file_name" {
		t.Fatalf("field renames must merge flag-first: %v", cfg.FieldNames)
	}
	mergeAdapterConfig(cfg, nil)
}
