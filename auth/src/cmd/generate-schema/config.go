package main

// Schema configuration surface for the generate-schema CLI.
//
// -plugins accepts registered schema IDs and inline extraSchemas only.
//
// The JSON table/field shape is also the -from snapshot shape for
// current-vs-desired diffing (see diff.go).

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	auth "github.com/brick-org/brick/auth/src"
)

// GeneratorConfig is the JSON-serializable generator configuration loaded
// with -config. Explicit CLI flags override file values: non-empty
// strings win, bools OR-accumulate, plugin/model/field maps merge with
// flag entries winning.
type GeneratorConfig struct {
	// Plugins lists plugin specs, same syntax as -plugins
	// (bare IDs or id:json-options).
	Plugins []string `json:"plugins"`
	// PluginOptions carries per-plugin JSON options by plugin ID,
	// merged under -plugins :json suffixes (suffix wins on conflict).
	PluginOptions map[string]json.RawMessage `json:"pluginOptions"`
	// ExtraSchemas declares inline arbitrary tables (no Go required),
	// merged over every other schema source.
	ExtraSchemas map[string]TableSchemaJSON `json:"extraSchemas"`
	// ModelNames maps logical model names to physical tables.
	ModelNames map[string]string `json:"modelNames"`
	// FieldNames maps "model.field" to physical columns.
	FieldNames map[string]string `json:"fieldNames"`
	// WithRateLimit includes the rateLimit storage table.
	WithRateLimit bool `json:"withRateLimit"`
	// SecondaryStorage omits secondary-stored tables per the
	// get-tables.ts inclusion rules.
	SecondaryStorage bool `json:"secondaryStorage"`
	// StoreSessionInDatabase keeps session with -secondary-storage.
	StoreSessionInDatabase bool `json:"storeSessionInDatabase"`
	// StoreVerificationInDatabase keeps verification with
	// -secondary-storage.
	StoreVerificationInDatabase bool `json:"storeVerificationInDatabase"`
	// OrgTeams enables org team tables (convenience alias for the org
	// {"teams":true} plugin option).
	OrgTeams bool `json:"orgTeams"`
	// Dialect selects the SQL flavor (sqlite, postgres, mysql, mssql).
	Dialect string `json:"dialect"`
	// IDType selects the id flavor (string, uuid, serial).
	IDType string `json:"idType"`
	// Package names the generated Go package.
	Package string `json:"package"`
	// Prefix prefixes generated struct names.
	Prefix string `json:"prefix"`
	// MigrateFunc names the generated migration helper.
	MigrateFunc string `json:"migrateFunc"`
}

// TableSchemaJSON is the serializable subset of auth.TableSchema used by
// extraSchemas and -from snapshots. Func-valued metadata (transforms,
// validators, OnUpdate, func defaults) cannot cross JSON: date fields
// accept the "now" default sentinel for DateNowDefault, other types take
// static scalar defaults.
type TableSchemaJSON struct {
	ModelName         string               `json:"modelName"`
	Fields            map[string]FieldJSON `json:"fields"`
	Indexes           []IndexJSON          `json:"indexes"`
	DisableMigration  bool                 `json:"disableMigration"`
	DisableMigrations *bool                `json:"disableMigrations"`
	Order             int                  `json:"order"`
}

// FieldJSON is the serializable subset of auth.FieldAttribute.
type FieldJSON struct {
	Type       string          `json:"type"`
	Required   *bool           `json:"required"`
	Returned   *bool           `json:"returned"`
	Input      *bool           `json:"input"`
	Unique     bool            `json:"unique"`
	Index      bool            `json:"index"`
	Sortable   bool            `json:"sortable"`
	BigInt     bool            `json:"bigint"`
	FieldName  string          `json:"fieldName"`
	Default    json.RawMessage `json:"default"`
	References *ReferenceJSON  `json:"references"`
}

// ReferenceJSON is the serializable subset of auth.FieldReference.
type ReferenceJSON struct {
	Model    string `json:"model"`
	Field    string `json:"field"`
	OnDelete string `json:"onDelete"`
}

// IndexJSON is the serializable subset of auth.TableIndex.
type IndexJSON struct {
	Fields []string `json:"fields"`
	Name   string   `json:"name"`
	Unique bool     `json:"unique"`
}

// LoadGeneratorConfig reads a -config JSON file.
func LoadGeneratorConfig(path string) (*GeneratorConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read -config file: %w", err)
	}
	var cfg GeneratorConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse -config file: %w", err)
	}
	return &cfg, nil
}

// ToPluginSchema converts inline table declarations to a PluginSchema.
// Unknown field types are rejected; the "now" default sentinel maps to
// DateNowDefault on date fields.
func (t TableSchemaJSON) ToPluginSchema() (auth.TableSchema, error) {
	out := auth.TableSchema{
		ModelName:        t.ModelName,
		DisableMigration: t.DisableMigration,
		Order:            t.Order,
	}
	if t.DisableMigrations != nil {
		v := *t.DisableMigrations
		out.DisableMigrations = &v
	}
	if len(t.Fields) > 0 {
		out.Fields = make(map[string]auth.FieldAttribute, len(t.Fields))
		for name, f := range t.Fields {
			attr, err := f.toFieldAttribute()
			if err != nil {
				return auth.TableSchema{}, fmt.Errorf("field %q: %w", name, err)
			}
			out.Fields[name] = attr
		}
	}
	for _, index := range t.Indexes {
		if len(index.Fields) == 0 {
			return auth.TableSchema{}, fmt.Errorf("index must include at least one field")
		}
		out.Indexes = append(out.Indexes, auth.TableIndex{Fields: append([]string(nil), index.Fields...), Name: index.Name, Unique: index.Unique})
	}
	return out, nil
}

func (f FieldJSON) toFieldAttribute() (auth.FieldAttribute, error) {
	var attr auth.FieldAttribute
	switch auth.FieldType(strings.ToLower(strings.TrimSpace(f.Type))) {
	case auth.FieldTypeString, auth.FieldTypeNumber, auth.FieldTypeBoolean, auth.FieldTypeDate, auth.FieldTypeJSON:
		attr.Type = auth.FieldType(strings.ToLower(strings.TrimSpace(f.Type)))
	case "":
		return auth.FieldAttribute{}, fmt.Errorf("missing type (want one of string, number, boolean, date, json)")
	default:
		if strings.HasSuffix(f.Type, "[]") {
			return auth.FieldAttribute{}, fmt.Errorf("array type %q has no bun-struct representation", f.Type)
		}
		return auth.FieldAttribute{}, fmt.Errorf("unsupported type %q (want one of string, number, boolean, date, json)", f.Type)
	}
	attr.Required = f.Required
	attr.Returned = f.Returned
	attr.Input = f.Input
	attr.Unique = f.Unique
	attr.Index = f.Index
	attr.Sortable = f.Sortable
	attr.BigInt = f.BigInt
	attr.FieldName = f.FieldName
	if len(f.Default) > 0 {
		if string(f.Default) == `"now"` {
			if attr.Type != auth.FieldTypeDate {
				return auth.FieldAttribute{}, fmt.Errorf(`"now" default requires a date field`)
			}
			attr.DefaultValue = auth.DateNowDefault
		} else {
			var v any
			if err := json.Unmarshal(f.Default, &v); err != nil {
				return auth.FieldAttribute{}, fmt.Errorf("invalid default: %w", err)
			}
			attr.DefaultValue = v
		}
	}
	if f.References != nil {
		if f.References.Model == "" || f.References.Field == "" {
			return auth.FieldAttribute{}, fmt.Errorf("references must name a model and field")
		}
		attr.References = &auth.FieldReference{Model: f.References.Model, Field: f.References.Field, OnDelete: f.References.OnDelete}
	}
	return attr, nil
}

// ParsePluginSpec splits a -plugins entry into its ID and optional JSON
// options (id:{"teams":true}). Bare IDs carry no options.
func ParsePluginSpec(raw string) (id string, opts json.RawMessage, err error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil, nil
	}
	if i := strings.Index(trimmed, ":"); i >= 0 {
		id = strings.TrimSpace(trimmed[:i])
		optsText := strings.TrimSpace(trimmed[i+1:])
		if id == "" {
			return "", nil, fmt.Errorf("invalid plugin spec %q: missing plugin ID", raw)
		}
		if optsText == "" {
			return "", nil, fmt.Errorf("invalid plugin spec %q: missing JSON options after ':'", raw)
		}
		var probe any
		if err := json.Unmarshal([]byte(optsText), &probe); err != nil {
			return "", nil, fmt.Errorf("invalid plugin spec %q: bad JSON options: %w", raw, err)
		}
		return id, json.RawMessage(optsText), nil
	}
	return trimmed, nil, nil
}

// buildPluginsExtended resolves plugin specs (bare IDs or id:json) plus a
// loaded GeneratorConfig into full plugins. Core-only: only registered
// schema-only providers, inline extraSchemas, and empty IDs are supported.
// Built-in admin/org wiring was removed with the plugins and will return
// with them.
func buildPluginsExtended(specs []string, fileCfg *GeneratorConfig, orgTeamsFlag bool) ([]auth.Plugin, error) {
	type combined struct {
		id   string
		opts json.RawMessage
	}
	var ordered []combined
	seenOpts := map[string]json.RawMessage{}
	add := func(id string, opts json.RawMessage) {
		if _, ok := seenOpts[id]; !ok {
			ordered = append(ordered, combined{id: id})
		}
		if len(opts) > 0 {
			seenOpts[id] = opts
		} else if _, ok := seenOpts[id]; !ok {
			seenOpts[id] = nil
		}
	}
	if fileCfg != nil {
		for _, spec := range fileCfg.Plugins {
			id, opts, err := ParsePluginSpec(spec)
			if err != nil {
				return nil, err
			}
			if id == "" {
				continue
			}
			add(id, opts)
		}
		for id, opts := range fileCfg.PluginOptions {
			if len(opts) == 0 {
				continue
			}
			if _, ok := seenOpts[id]; !ok {
				ordered = append(ordered, combined{id: id})
			}
			seenOpts[id] = opts
		}
	}
	for _, spec := range specs {
		id, opts, err := ParsePluginSpec(spec)
		if err != nil {
			return nil, err
		}
		if id == "" {
			continue
		}
		add(id, opts)
		// Flag suffixes win over file options on conflict.
		if len(opts) > 0 {
			seenOpts[id] = opts
		}
	}

	orgTeams := orgTeamsFlag
	if fileCfg != nil && fileCfg.OrgTeams {
		orgTeams = true
	}
	_ = orgTeams
	plugins := make([]auth.Plugin, 0, len(ordered)+1)
	for _, c := range ordered {
		opts := seenOpts[c.id]
		switch c.id {
		case "admin", "org":
			return nil, fmt.Errorf("unsupported plugin %q: built-in plugins are removed in this core-only tree (registered: %s)", c.id, strings.Join(auth.RegisteredPluginSchemaIDs(), ", "))
		case "":
			continue
		default:
			if len(opts) > 0 {
				return nil, fmt.Errorf("unsupported plugin %q: registered schema providers take no JSON options (registered: %s)", c.id, strings.Join(auth.RegisteredPluginSchemaIDs(), ", "))
			}
			schema, err := auth.PluginSchemasForIDs([]string{c.id})
			if err != nil {
				return nil, fmt.Errorf("unsupported plugin %q (registered: %s)", c.id, strings.Join(auth.RegisteredPluginSchemaIDs(), ", "))
			}
			plugins = append(plugins, schemaOnlyPlugin{id: c.id, schema: schema})
		}
	}
	if fileCfg != nil && len(fileCfg.ExtraSchemas) > 0 {
		extra := auth.PluginSchema{}
		names := make([]string, 0, len(fileCfg.ExtraSchemas))
		for name := range fileCfg.ExtraSchemas {
			names = append(names, name)
		}
		for _, name := range names {
			table, err := fileCfg.ExtraSchemas[name].ToPluginSchema()
			if err != nil {
				return nil, fmt.Errorf("invalid extraSchemas table %q: %w", name, err)
			}
			extra[name] = table
		}
		plugins = append(plugins, schemaOnlyPlugin{id: "config", schema: extra})
	}
	return plugins, nil
}
