package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/brick-org/brick/auth/src/types"
)

// This file mirrors get-tables.ts (Better Auth v1.7.5).
// Row-key contract: rows use logical camelCase keys; custom names reverse
// to logical on reads.
type TableIndex = types.TableIndex

// ResolvedDBTableIndex mirrors better-auth's ResolvedDBTableIndex
// (physical column names plus a concrete index name).
type ResolvedDBTableIndex struct {
	// Columns holds physical database column names, in index order.
	Columns []string
	// Name is the concrete database index name.
	Name string
	// Unique reports whether the indexed tuple must be unique.
	Unique bool
}

// CloneSchema deep-copies a plugin schema map so callers never mutate inputs.
// Hooks and func-valued DefaultValue stay shared.
func CloneSchema(schema PluginSchema) PluginSchema {
	if len(schema) == 0 {
		return nil
	}
	cloned := PluginSchema{}
	for model, table := range schema {
		clonedTable := TableSchema{
			ModelName:        table.ModelName,
			DisableMigration: table.DisableMigration,
			Order:            table.Order,
		}
		if table.DisableMigrations != nil {
			v := *table.DisableMigrations
			clonedTable.DisableMigrations = &v
		}
		if len(table.Fields) > 0 {
			clonedTable.Fields = make(map[string]FieldAttribute, len(table.Fields))
			for name, field := range table.Fields {
				// Deep-copy the nested References pointer so mutating the
				// source schema's foreign key can never leak into the clone.
				if field.References != nil {
					refs := *field.References
					field.References = &refs
				}
				clonedTable.Fields[name] = field
			}
		}
		if len(table.Indexes) > 0 {
			clonedTable.Indexes = make([]TableIndex, len(table.Indexes))
			for i, index := range table.Indexes {
				// Deep-copy each index's Fields slice for the same reason.
				if len(index.Fields) > 0 {
					index.Fields = append([]string(nil), index.Fields...)
				}
				clonedTable.Indexes[i] = index
			}
		}
		cloned[model] = clonedTable
	}
	return cloned
}

// MergeSchemas merges plugin table declarations field-by-field.
// Presence-safe: DisableMigrations last-wins; legacy DisableMigration OR-accumulates.
// New code must use DisableMigrations.
func MergeSchemas(base PluginSchema, additions ...PluginSchema) PluginSchema {
	merged := CloneSchema(base)
	if merged == nil {
		merged = PluginSchema{}
	}
	for _, schema := range additions {
		for model, table := range schema {
			current := merged[model]
			if current.Fields == nil {
				current.Fields = map[string]FieldAttribute{}
			}
			for name, field := range table.Fields {
				current.Fields[name] = field
			}
			current.Indexes = MergeTableIndexes(current.Indexes, table.Indexes)
			if table.ModelName != "" {
				current.ModelName = table.ModelName
			}
			if table.Order != 0 {
				current.Order = table.Order
			}
			if table.DisableMigrations != nil {
				v := *table.DisableMigrations
				current.DisableMigrations = &v
				current.DisableMigration = v
			} else if table.DisableMigration {
				// Legacy true implies presence (false is ambiguous with absent).
				current.DisableMigration = true
				// Do not set DisableMigrations (preserve absent for explicit-false wins later).
			}
			merged[model] = current
		}
	}
	return merged
}

// SchemasForProviders merges schemas from plugin-schema providers.
// Go-only helper.
func SchemasForProviders(providers []PluginSchemaProvider) PluginSchema {
	schemas := make([]PluginSchema, 0, len(providers))
	for _, p := range providers {
		if p == nil {
			continue
		}
		schemas = append(schemas, p.Schema())
	}
	return MergeSchemas(nil, schemas...)
}

// MergeTableIndexes merges table-level index collections, deduplicating by
// (name, fields, unique).
func MergeTableIndexes(collections ...[]TableIndex) []TableIndex {
	var out []TableIndex
	seen := map[string]struct{}{}
	for _, collection := range collections {
		for _, index := range collection {
			var name any
			if index.Name != "" {
				name = index.Name
			}
			keyBytes, err := json.Marshal([]any{name, index.Fields, index.Unique})
			var key string
			if err != nil {
				// Field names are strings, so marshaling cannot fail; fall
				// back to a length-prefixed encoding rather than dropping
				// the index.
				key = fmt.Sprintf("%d:%q|%q|%v", len(index.Fields), index.Fields, index.Name, index.Unique)
			} else {
				key = string(keyBytes)
			}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, index)
		}
	}
	return out
}

// DateNowDefault is the `() => new Date()` factory for core timestamp columns.
func DateNowDefault() any { return time.Now().UTC() }

// DateNowMillisDefault is the `() => Date.now()` factory for rate-limit rows.
func DateNowMillisDefault() any { return time.Now().UnixMilli() }

// HasFuncDefault reports whether attr carries a func-valued DefaultValue.
func HasFuncDefault(attr FieldAttribute) bool {
	if attr.DefaultValue == nil {
		return false
	}
	return reflect.TypeOf(attr.DefaultValue).Kind() == reflect.Func
}

// HasTimestampColumnDefault reports a date field with a func default.
func HasTimestampColumnDefault(attr FieldAttribute) bool {
	return attr.Type == FieldTypeDate && HasFuncDefault(attr)
}

// HasStaticColumnDefault reports a static string/number/boolean default.
func HasStaticColumnDefault(attr FieldAttribute) bool {
	if attr.Unique && attr.Required != nil && !*attr.Required {
		return false
	}
	if attr.DefaultValue == nil || HasFuncDefault(attr) {
		return false
	}
	switch attr.Type {
	case FieldTypeString, FieldTypeNumber, FieldTypeBoolean:
		return true
	}
	return false
}

// boolPtrGo is a Go-only helper boxing a bool for *bool option fields.
func boolPtrGo(v bool) *bool { return &v }

// CoreSchema returns the canonical core tables with logical field names.
func CoreSchema() PluginSchema {
	return PluginSchema{
		"user": {
			Order: 1,
			Fields: map[string]FieldAttribute{
				"name":          {Type: FieldTypeString, Sortable: true},
				"email":         {Type: FieldTypeString, Unique: true, Sortable: true},
				"emailVerified": {Type: FieldTypeBoolean, DefaultValue: false, Input: boolPtrGo(false)},
				"image":         {Type: FieldTypeString, Required: boolPtrGo(false)},
				"createdAt":     {Type: FieldTypeDate, DefaultValue: DateNowDefault},
				"updatedAt":     {Type: FieldTypeDate, DefaultValue: DateNowDefault, OnUpdate: DateNowDefault},
			},
		},
		"session": {
			Order: 2,
			Fields: map[string]FieldAttribute{
				"expiresAt": {Type: FieldTypeDate},
				"token":     {Type: FieldTypeString, Unique: true},
				"createdAt": {Type: FieldTypeDate, DefaultValue: DateNowDefault},
				"updatedAt": {Type: FieldTypeDate, DefaultValue: DateNowDefault, OnUpdate: DateNowDefault},
				"ipAddress": {Type: FieldTypeString, Required: boolPtrGo(false)},
				"userAgent": {Type: FieldTypeString, Required: boolPtrGo(false)},
				"userId": {
					Type:       FieldTypeString,
					Index:      true,
					References: &FieldReference{Model: "user", Field: "id", OnDelete: "cascade"},
				},
			},
		},
		"account": {
			Order: 3,
			Fields: map[string]FieldAttribute{
				"accountId":  {Type: FieldTypeString},
				"providerId": {Type: FieldTypeString},
				"userId": {
					Type:       FieldTypeString,
					Index:      true,
					References: &FieldReference{Model: "user", Field: "id", OnDelete: "cascade"},
				},
				"accessToken":           {Type: FieldTypeString, Required: boolPtrGo(false), Returned: boolPtrGo(false)},
				"refreshToken":          {Type: FieldTypeString, Required: boolPtrGo(false), Returned: boolPtrGo(false)},
				"idToken":               {Type: FieldTypeString, Required: boolPtrGo(false), Returned: boolPtrGo(false)},
				"accessTokenExpiresAt":  {Type: FieldTypeDate, Required: boolPtrGo(false), Returned: boolPtrGo(false)},
				"refreshTokenExpiresAt": {Type: FieldTypeDate, Required: boolPtrGo(false), Returned: boolPtrGo(false)},
				"scope":                 {Type: FieldTypeString, Required: boolPtrGo(false)},
				"password":              {Type: FieldTypeString, Required: boolPtrGo(false), Returned: boolPtrGo(false)},
				"createdAt":             {Type: FieldTypeDate, DefaultValue: DateNowDefault},
				"updatedAt":             {Type: FieldTypeDate, DefaultValue: DateNowDefault, OnUpdate: DateNowDefault},
			},
		},
		"verification": {
			Order: 4,
			Fields: map[string]FieldAttribute{
				"identifier": {Type: FieldTypeString, Index: true},
				"value":      {Type: FieldTypeString},
				"expiresAt":  {Type: FieldTypeDate},
				"createdAt":  {Type: FieldTypeDate, DefaultValue: DateNowDefault},
				"updatedAt":  {Type: FieldTypeDate, DefaultValue: DateNowDefault, OnUpdate: DateNowDefault},
			},
		},
	}
}

// RateLimitSchema returns the rate-limit storage table.
func RateLimitSchema() PluginSchema {
	return PluginSchema{
		"rateLimit": {
			Fields: map[string]FieldAttribute{
				"key":         {Type: FieldTypeString, Unique: true},
				"count":       {Type: FieldTypeNumber},
				"lastRequest": {Type: FieldTypeNumber, BigInt: true, DefaultValue: DateNowMillisDefault},
			},
		},
	}
}

// RateLimitSchemaForOptions returns the rate-limit table with configured names.
func RateLimitSchemaForOptions(opts Options) PluginSchema {
	table := TableSchema{Fields: map[string]FieldAttribute{}}
	if opts.RateLimit.ModelName != "" {
		table.ModelName = opts.RateLimit.ModelName
	}
	for name, attr := range RateLimitSchema()["rateLimit"].Fields {
		if col, ok := opts.RateLimit.Fields[name]; ok && col != "" {
			attr.FieldName = col
		}
		table.Fields[name] = attr
	}
	return PluginSchema{"rateLimit": table}
}

// CoreTableIndexes returns table-level index metadata for core tables.
func CoreTableIndexes() map[string][]TableIndex {
	return map[string][]TableIndex{
		"session": {
			{Fields: []string{"userId"}},
		},
		"account": {
			{Fields: []string{"userId"}},
		},
		"verification": {
			{Fields: []string{"identifier"}},
		},
	}
}

// ShouldIncludeSessionTable reports the session inclusion rule.
func ShouldIncludeSessionTable(hasSecondaryStorage, storeSessionInDatabase bool) bool {
	return !hasSecondaryStorage || storeSessionInDatabase
}

// ShouldIncludeVerificationTable reports the verification inclusion rule.
func ShouldIncludeVerificationTable(hasSecondaryStorage, storeVerificationInDatabase bool) bool {
	return !hasSecondaryStorage || storeVerificationInDatabase
}

// ShouldAddRateLimitTable reports the rate-limit table rule.
func ShouldAddRateLimitTable(rateLimitStorage string) bool {
	return rateLimitStorage == "database" || rateLimitStorage == string(types.RateLimitStorageDatabase)
}

// HasSecondaryStorage reports whether secondary storage is configured.
func HasSecondaryStorage(opts Options) bool {
	return opts.SecondaryStorage != nil
}

// applyModelFieldNames overlays modelName and per-field renames onto one table.
func applyModelFieldNames(table TableSchema, model types.DBModelOptions) TableSchema {
	out := TableSchema{
		ModelName:        table.ModelName,
		Fields:           map[string]FieldAttribute{},
		Indexes:          append([]TableIndex(nil), table.Indexes...),
		DisableMigration: table.DisableMigration,
		Order:            table.Order,
	}
	if table.DisableMigrations != nil {
		v := *table.DisableMigrations
		out.DisableMigrations = &v
	}
	for name, field := range table.Fields {
		if col, ok := model.Fields[name]; ok && col != "" {
			field.FieldName = col
		}
		out.Fields[name] = field
	}
	if model.ModelName != "" {
		out.ModelName = model.ModelName
	}
	return out
}

// applyOptionAdditionalFields merges option additionalFields over tables.
func applyOptionAdditionalFields(tables PluginSchema, opts Options) PluginSchema {
	additional := map[string]map[string]FieldAttribute{
		"user":         opts.User.Model.AdditionalFields,
		"session":      opts.Session.Model.AdditionalFields,
		"account":      opts.Account.Model.AdditionalFields,
		"verification": opts.Verification.Model.AdditionalFields,
	}
	for model, fields := range additional {
		if len(fields) == 0 {
			continue
		}
		table, ok := tables[model]
		if !ok {
			continue
		}
		if table.Fields == nil {
			table.Fields = map[string]FieldAttribute{}
		}
		for name, field := range fields {
			table.Fields[name] = field
		}
		tables[model] = table
	}
	return tables
}

// baseCoreTables builds the core tables with renames applied.
func baseCoreTables(opts Options) PluginSchema {
	core := CoreSchema()
	return PluginSchema{
		"user":         applyModelFieldNames(core["user"], opts.User.Model),
		"session":      applyModelFieldNames(core["session"], opts.Session.Model),
		"account":      applyModelFieldNames(core["account"], opts.Account.Model),
		"verification": applyModelFieldNames(core["verification"], opts.Verification.Model),
	}
}

// isCoreTableKey reports whether key is a core table.
func isCoreTableKey(key string) bool {
	switch key {
	case "user", "session", "account", "verification":
		return true
	}
	return false
}

// mergePluginTable merges one plugin table over tables.
func mergePluginTable(tables PluginSchema, model string, table TableSchema) PluginSchema {
	if !isCoreTableKey(model) {
		return MergeSchemas(tables, PluginSchema{model: table})
	}
	current, ok := tables[model]
	if !ok {
		current = TableSchema{}
	}
	if current.Fields == nil {
		current.Fields = map[string]FieldAttribute{}
	}
	for name, field := range table.Fields {
		current.Fields[name] = field
	}
	current.Indexes = MergeTableIndexes(current.Indexes, table.Indexes)
	tables[model] = current
	return tables
}

// buildAuthTables assembles core, plugin, and option fields in order.
func buildAuthTables(opts Options) PluginSchema {
	tables := baseCoreTables(opts)
	for _, plugin := range opts.Plugins {
		for model, table := range plugin.Schema() {
			tables = mergePluginTable(tables, model, table)
		}
	}
	return applyOptionAdditionalFields(tables, opts)
}

// GetAuthTables follows upstream getAuthTables/buildAuthTables.
func GetAuthTables(opts Options) PluginSchema {
	tables := buildAuthTables(opts)
	if HasSecondaryStorage(opts) {
		if !ShouldIncludeSessionTable(true, opts.Session.StoreSessionInDatabase) {
			delete(tables, "session")
		}
		if !ShouldIncludeVerificationTable(true, opts.Verification.StoreInDatabase) {
			delete(tables, "verification")
		}
	}
	if ShouldAddRateLimitTable(string(opts.RateLimit.Storage)) {
		tables = MergeSchemas(tables, RateLimitSchemaForOptions(opts))
	}
	return tables
}

// GetAuthTablesWithSecondaryStorage applies secondary-storage inclusion rules.
func GetAuthTablesWithSecondaryStorage(opts Options, hasSecondaryStorage, storeSessionInDatabase, storeVerificationInDatabase bool) PluginSchema {
	tables := buildAuthTables(opts)
	if hasSecondaryStorage {
		if !ShouldIncludeSessionTable(true, storeSessionInDatabase) {
			delete(tables, "session")
		}
		if !ShouldIncludeVerificationTable(true, storeVerificationInDatabase) {
			delete(tables, "verification")
		}
	}
	return tables
}

// GetAuthTablesWithRateLimit returns GetAuthTables plus the rate-limit table.
func GetAuthTablesWithRateLimit(opts Options, rateLimitStorage string) PluginSchema {
	tables := GetAuthTables(opts)
	if ShouldAddRateLimitTable(rateLimitStorage) {
		if _, ok := tables["rateLimit"]; !ok {
			tables = MergeSchemas(tables, RateLimitSchemaForOptions(opts))
		}
	}
	return tables
}

// GetAuthTablesWithResolvedIndexes returns tables plus physical index metadata.
func GetAuthTablesWithResolvedIndexes(opts Options, cfg AdapterConfig) (PluginSchema, map[string][]ResolvedDBTableIndex) {
	tables := GetAuthTables(opts)
	indexes := ResolveSchemaIndexes(tables, cfg)
	return tables, indexes
}

// ResolveSchemaIndexes resolves logical index metadata to physical columns.
func ResolveSchemaIndexes(schema PluginSchema, cfg AdapterConfig) map[string][]ResolvedDBTableIndex {
	out := map[string][]ResolvedDBTableIndex{}
	for model, table := range schema {
		if table.DisableMigrationsEffective() {
			continue
		}
		tableName := PhysicalTableName(model, table, cfg)
		indexes := MergeTableIndexes(table.Indexes)
		if core, ok := CoreTableIndexes()[model]; ok {
			indexes = MergeTableIndexes(indexes, core)
		}
		for name, field := range table.Fields {
			if field.Unique || field.Index {
				indexes = MergeTableIndexes(indexes, []TableIndex{{Fields: []string{name}, Unique: field.Unique}})
			}
		}
		if len(indexes) == 0 {
			continue
		}
		resolved := make([]ResolvedDBTableIndex, 0, len(indexes))
		for _, index := range indexes {
			columns := make([]string, 0, len(index.Fields))
			for _, f := range index.Fields {
				columns = append(columns, PhysicalColumnName(model, table, f, cfg))
			}
			resolved = append(resolved, ResolvedDBTableIndex{
				Columns: columns,
				Name:    GetDatabaseIndexName(tableName, TableIndex{Fields: columns, Name: index.Name, Unique: index.Unique}),
				Unique:  index.Unique,
			})
		}
		out[tableName] = resolved
	}
	return out
}

// ResolveSchema returns the legacy route-filter view of the schema: plugin
// field extensions merged over each other, WITHOUT the core tables.
//
// Do not "fix" this to return GetAuthTables: route input/output filters
// treat a non-empty table entry as an allow-list ("only declared additional
// fields"), so including the core tables here would reject previously
// accepted undeclared fields. The load-bearing consumer is
// filterSessionUpdateFields in api/routes/session_extra.go (with
// extractAdditionalFields in api/routes/session.go and sign_up.go), which
// reads opts.Schema["session"]/["user"].Fields as the declared-field
// allow-list; opts.Schema is populated by BetterAuth in index.go, and
// rewiring it to the full table set is an open decision (see report), not
// taken here.
func ResolveSchema(opts Options) PluginSchema {
	schemas := make([]PluginSchema, 0, len(opts.Plugins))
	for _, plugin := range opts.Plugins {
		schemas = append(schemas, plugin.Schema())
	}
	return MergeSchemas(nil, schemas...)
}

// FullSchema returns the complete resolved schema for options.
// New route processing must read the full schema here; the legacy
// plugin-only ResolveSchema stays frozen. The migration must union, not intersect.
func FullSchema(opts Options) PluginSchema {
	return GetAuthTables(opts)
}

// FullSchemaFields returns the merged field map for one logical model.
func FullSchemaFields(opts Options, model string) map[string]FieldAttribute {
	if table, ok := FullSchema(opts)[model]; ok {
		return table.Fields
	}
	return nil
}

// pluginSchemaRegistry maps CLI/plugin IDs to factories.
var pluginSchemaRegistry = map[string]func() PluginSchemaProvider{}

// RegisterPluginSchema registers a named provider factory for CLI generation.
func RegisterPluginSchema(id string, factory func() PluginSchemaProvider) {
	if id == "" || factory == nil {
		return
	}
	pluginSchemaRegistry[id] = factory
}

// UnregisterPluginSchema removes a registered provider factory.
func UnregisterPluginSchema(id string) {
	delete(pluginSchemaRegistry, id)
}

// RegisteredPluginSchemaIDs returns the sorted registry IDs.
func RegisteredPluginSchemaIDs() []string {
	ids := make([]string, 0, len(pluginSchemaRegistry))
	for id := range pluginSchemaRegistry {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// PluginSchemasForIDs merges the schemas of the named providers.
func PluginSchemasForIDs(ids []string) (PluginSchema, error) {
	providers := make([]PluginSchemaProvider, 0, len(ids))
	for _, id := range ids {
		factory, ok := pluginSchemaRegistry[id]
		if !ok {
			return nil, fmt.Errorf("auth: unknown plugin schema %q (registered: %s)", id, strings.Join(RegisteredPluginSchemaIDs(), ", "))
		}
		providers = append(providers, factory())
	}
	return SchemasForProviders(providers), nil
}

// ValidateIndexName checks an explicit index name.
func ValidateIndexName(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("auth: database index names must contain at least one visible character")
	}
	for i, r := range name {
		ok := r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (i > 0 && r >= '0' && r <= '9')
		if !ok {
			return fmt.Errorf("auth: database index name %q must start with a letter or underscore and contain only letters, numbers, and underscores", name)
		}
	}
	if len(name) > 63 {
		return fmt.Errorf("auth: database index name %q must be at most 63 UTF-8 bytes", name)
	}
	return nil
}

// maxDatabaseIndexFields caps a table-level index at 16 fields.
const maxDatabaseIndexFields = 16

// portableIndexKey lowercases an identifier for uniqueness checks.
func portableIndexKey(name string) string {
	return strings.ToLower(name)
}

// ValidateSchemaIndexes validates logical index metadata for every table in
// schema, mirroring upstream resolveDatabaseSchemaIndexes +
// resolveDatabaseTableIndexes (database-index.ts):
//
//   - declared table indexes must name at least one and at most 16 fields,
//     with no repeats, referencing known fields of indexable type (json and
//     array types are rejected), resolving to distinct physical columns;
//   - unique indexes may only cover required fields (their behavior differs
//     across databases for NULL);
//   - explicit names are validated by ValidateIndexName; the same name with
//     a different definition on one table is rejected;
//   - index names must be unique schema-wide (case-insensitive) and must not
//     collide with table names; field-level (Index/Unique flag) names reserve
//     their generated names first, like upstream;
//   - two logical tables aliasing one physical table may not both declare
//     indexes (upstream multi-table aliasing error).
//
// Tables with DisableMigrationsEffective are skipped, matching
// getAuthTablesWithResolvedIndexes (upstream filters disableMigrations
// tables before resolving). It returns the first violation. ResolveSchemaIndexes
// stays non-validating for backwards compatibility; the generator calls this
// before emitting DDL.
//
// Upstream TypeScript names: resolveDatabaseSchemaIndexes,
// resolveDatabaseTableIndexes, getDatabaseIndexName.
func ValidateSchemaIndexes(schema PluginSchema, cfg AdapterConfig) error {
	keys := make([]string, 0, len(schema))
	for key := range schema {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	tableNames := map[string]string{}
	for _, key := range keys {
		table := schema[key]
		if table.DisableMigrationsEffective() {
			continue
		}
		name := PhysicalTableName(key, table, cfg)
		tableNames[portableIndexKey(name)] = name
	}

	// Field-level index names reserve their generated names first (upstream
	// pre-pass over source.fields), so a table-level index reusing one is
	// reported as a reservation conflict rather than silently shadowing it.
	fieldIndexOwner := map[string]string{}
	for _, key := range keys {
		table := schema[key]
		if table.DisableMigrationsEffective() {
			continue
		}
		tableName := PhysicalTableName(key, table, cfg)
		fieldNames := make([]string, 0, len(table.Fields))
		for name := range table.Fields {
			fieldNames = append(fieldNames, name)
		}
		sort.Strings(fieldNames)
		for _, name := range fieldNames {
			field := table.Fields[name]
			if !field.Index && !field.Unique {
				continue
			}
			column := PhysicalColumnName(key, table, name, cfg)
			indexName := GetDatabaseIndexName(tableName, TableIndex{Fields: []string{column}, Unique: field.Unique})
			if _, ok := tableNames[portableIndexKey(indexName)]; ok {
				return fmt.Errorf("auth: database index name %q conflicts with a table name", indexName)
			}
			idKey := portableIndexKey(indexName)
			if owner, ok := fieldIndexOwner[idKey]; ok && !strings.EqualFold(owner, tableName) {
				return fmt.Errorf("auth: database field-level index name %q is used by both table %q and table %q", indexName, owner, tableName)
			}
			fieldIndexOwner[idKey] = tableName
		}
	}

	// Multi-table aliasing: more than one indexed logical table resolving to
	// one physical table is rejected (upstream merges field maps only when
	// neither side declares indexes).
	byPhysical := map[string][]string{}
	for _, key := range keys {
		table := schema[key]
		if table.DisableMigrationsEffective() {
			continue
		}
		byPhysical[PhysicalTableName(key, table, cfg)] = append(byPhysical[PhysicalTableName(key, table, cfg)], key)
	}
	physicalNames := make([]string, 0, len(byPhysical))
	for name := range byPhysical {
		physicalNames = append(physicalNames, name)
	}
	sort.Strings(physicalNames)
	for _, name := range physicalNames {
		logical := byPhysical[name]
		if len(logical) < 2 {
			continue
		}
		for _, key := range logical {
			if len(schema[key].Indexes) > 0 {
				return fmt.Errorf("auth: database schema resolves more than one indexed logical table to %q; define table-level indexes through one logical schema key instead of aliasing multiple keys to the same database table", name)
			}
		}
	}

	indexOwnerByName := map[string]string{}
	for _, key := range keys {
		table := schema[key]
		if table.DisableMigrationsEffective() {
			continue
		}
		tableName := PhysicalTableName(key, table, cfg)
		definitionsByName := map[string]string{}
		for _, index := range table.Indexes {
			if len(index.Fields) == 0 {
				return fmt.Errorf("auth: index on table %q must include at least one field", tableName)
			}
			if len(index.Fields) > maxDatabaseIndexFields {
				return fmt.Errorf("auth: index on table %q can include at most %d fields so it works across supported databases", tableName, maxDatabaseIndexFields)
			}
			seen := map[string]struct{}{}
			for _, f := range index.Fields {
				if _, ok := seen[f]; ok {
					return fmt.Errorf("auth: index on table %q contains the same field more than once", tableName)
				}
				seen[f] = struct{}{}
			}
			if index.Unique {
				for _, f := range index.Fields {
					if field, ok := table.Fields[f]; ok && field.Required != nil && !*field.Required {
						return fmt.Errorf("auth: unique index on table %q can only include required fields so its behavior is consistent across databases", tableName)
					}
				}
			}
			for _, f := range index.Fields {
				field, ok := table.Fields[f]
				if !ok {
					return fmt.Errorf("auth: index on table %q references unknown field %q", tableName, f)
				}
				if field.Type == FieldTypeJSON || strings.HasSuffix(string(field.Type), "[]") {
					return fmt.Errorf("auth: index on table %q references field %q, whose type is not portably indexable", tableName, f)
				}
			}
			columns := make([]string, 0, len(index.Fields))
			for _, f := range index.Fields {
				columns = append(columns, PhysicalColumnName(key, table, f, cfg))
			}
			lowered := map[string]struct{}{}
			for _, c := range columns {
				k := portableIndexKey(c)
				if _, ok := lowered[k]; ok {
					return fmt.Errorf("auth: index on table %q resolves more than one field to the same database column", tableName)
				}
				lowered[k] = struct{}{}
			}
			var resolvedName string
			if index.Name != "" {
				if err := ValidateIndexName(index.Name); err != nil {
					return err
				}
				resolvedName = index.Name
			} else {
				resolvedName = GetDatabaseIndexName(tableName, TableIndex{Fields: columns, Unique: index.Unique})
			}
			definition, err := json.Marshal([]any{columns, index.Unique})
			if err != nil {
				return fmt.Errorf("auth: index on table %q cannot be compared: %v", tableName, err)
			}
			idKey := portableIndexKey(resolvedName)
			if existing, ok := definitionsByName[idKey]; ok {
				if existing != string(definition) {
					return fmt.Errorf("auth: database index name %q identifies more than one index on table %q", resolvedName, tableName)
				}
				continue
			}
			definitionsByName[idKey] = string(definition)
			if _, ok := tableNames[idKey]; ok {
				return fmt.Errorf("auth: database index name %q conflicts with a table name", resolvedName)
			}
			if owner, ok := fieldIndexOwner[idKey]; ok {
				return fmt.Errorf("auth: database index name %q is already reserved by field-level index metadata on table %q", resolvedName, owner)
			}
			if owner, ok := indexOwnerByName[idKey]; ok && !strings.EqualFold(owner, tableName) {
				return fmt.Errorf("auth: database index name %q is used by both table %q and table %q", resolvedName, owner, tableName)
			}
			indexOwnerByName[idKey] = tableName
		}
	}
	return nil
}

// ResolveTableName is a Go-only helper mapping a logical schema key to its
// physical table name via cfg (AdapterConfig). Explicit ModelNames win;
// otherwise the plural convention (<model>s, snake_cased) applies.
//
// DELTA vs upstream getModelName: upstream appends the plural "s" only when
// the adapter sets usePlural; this port always pluralizes.
// Table-declared ModelName overrides use PhysicalTableName.
func ResolveTableName(model string, cfg AdapterConfig) string {
	if name := cfg.ModelName(model); name != model {
		return name
	}
	return camelToSnakeGo(model) + "s"
}

// PhysicalTableName is a Go-only helper mapping a logical schema key to its
// physical table name, honoring a TableSchema.ModelName override first, then
// cfg, then the plural convention. A ModelName equal to the logical key (the
// upstream default) is treated as "no override" so default output keeps
// plural tables.
func PhysicalTableName(model string, table TableSchema, cfg AdapterConfig) string {
	if table.ModelName != "" && table.ModelName != model {
		return table.ModelName
	}
	return ResolveTableName(model, cfg)
}

// ResolveColumnName is a Go-only helper mapping a logical field to its
// physical column via cfg. Explicit FieldNames win; otherwise camelCase
// folds to snake_case. Field-declared field names use PhysicalColumnName.
//
// DELTA vs upstream getFieldName: upstream canonicalizes model and field
// through getDefaultModelName/getDefaultFieldName (throwing on unknown
// names) and then reads schema[model].fields[field].fieldName; this helper
// performs only the cfg/snake mapping.
func ResolveColumnName(model, field string, cfg AdapterConfig) string {
	if name := cfg.FieldName(model, field); name != field {
		return name
	}
	return camelToSnakeGo(field)
}

// PhysicalColumnName is a Go-only helper mapping a logical field to its
// physical column, honoring a FieldAttribute.FieldName override first, then
// cfg, then snake_case.
func PhysicalColumnName(model string, table TableSchema, field string, cfg AdapterConfig) string {
	if attr, ok := table.Fields[field]; ok && attr.FieldName != "" && attr.FieldName != field {
		return attr.FieldName
	}
	return ResolveColumnName(model, field, cfg)
}

// GetDefaultModelName resolves a physical-or-logical model reference back to
// its canonical schema key: an exact schema-key match wins over a ModelName
// alias so internal references (references.model, which always use canonical
// keys) are never rerouted (upstream issue #8111). It returns an error when
// the model is unknown.
//
// DELTAS vs upstream initGetDefaultModelName: the trailing-"s" plural strip
// applies unconditionally here (upstream only when the adapter sets
// usePlural); alias lookup additionally honors PhysicalTableName and
// cfg.ModelName mappings, not just the schema-declared modelName; and schema
// keys are scanned in sorted order so ambiguous aliases resolve
// deterministically (Go map iteration is randomized).
func GetDefaultModelName(schema PluginSchema, cfg AdapterConfig, model string) (string, error) {
	if _, ok := schema[model]; ok {
		return model, nil
	}
	keys := make([]string, 0, len(schema))
	for key := range schema {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		table := schema[key]
		if PhysicalTableName(key, table, cfg) == model {
			return key, nil
		}
		if table.ModelName != "" && table.ModelName == model {
			return key, nil
		}
		if cfg.ModelName(key) == model {
			return key, nil
		}
	}
	// Tolerate a trailing "s" plural. DELTA vs upstream: this strip applies
	// unconditionally here; upstream only strips when the adapter sets
	// usePlural.
	if strings.HasSuffix(model, "s") {
		if name, err := GetDefaultModelName(schema, cfg, strings.TrimSuffix(model, "s")); err == nil {
			return name, nil
		}
	}
	return "", fmt.Errorf("auth: model %q not found in schema", model)
}

// GetModelName maps a model reference to its physical table name. The input
// is first resolved through GetDefaultModelName so physical aliases
// round-trip: with user modelName "app_users", GetModelName("app_users")
// returns "app_users" instead of double-pluralizing to "app_userss".
//
// DELTA vs upstream getModelName: upstream appends the plural "s" only when
// the adapter sets usePlural; this port always uses the plural convention
// via ResolveTableName.
func GetModelName(schema PluginSchema, cfg AdapterConfig, model string) string {
	if key, err := GetDefaultModelName(schema, cfg, model); err == nil {
		model = key
	}
	if table, ok := schema[model]; ok {
		return PhysicalTableName(model, table, cfg)
	}
	return ResolveTableName(model, cfg)
}

// GetDefaultFieldName resolves a physical-or-logical field back to its
// canonical logical name within model.
//
// DELTAS vs upstream initGetDefaultFieldName: unknown fields are returned
// unchanged (upstream throws), and the model itself is NOT canonicalized
// first (upstream runs getDefaultModelName on it). Like upstream,
// "id"/"_id" short-circuit to "id" (plugin schemas never declare their own
// id; it is auto-provided). All alias scans run in sorted key order so
// ambiguous mappings resolve deterministically (Go map iteration is
// randomized).
func GetDefaultFieldName(model string, cfg AdapterConfig, tables PluginSchema, field string) string {
	// Plugin schemas can't define their own `id`: it is auto-provided, so
	// it is never present in the fields map to match against.
	if field == "id" || field == "_id" {
		return "id"
	}
	if tbl, ok := tables[model]; ok {
		if _, ok := tbl.Fields[field]; ok {
			return field
		}
		names := make([]string, 0, len(tbl.Fields))
		for name := range tbl.Fields {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if tbl.Fields[name].FieldName == field {
				return name
			}
		}
	}
	prefix := model + "."
	keys := make([]string, 0, len(cfg.FieldNames))
	for key := range cfg.FieldNames {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if cfg.FieldNames[key] == field {
			return strings.TrimPrefix(key, prefix)
		}
	}
	// Tolerate default snake_case physical names.
	names := make([]string, 0, len(tables[model].Fields))
	for name := range tables[model].Fields {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if camelToSnakeGo(name) == field {
			return name
		}
	}
	return field
}

// GetFieldName is a Go-only helper mapping a logical field to its physical
// column via cfg (AdapterConfig) with a snake_case fallback.
//
// DELTA vs upstream getFieldName: upstream canonicalizes model and field
// through getDefaultModelName/getDefaultFieldName (throwing on unknown
// names) and then reads schema[model].fields[field].fieldName; this helper
// performs only the cfg/snake mapping — callers needing canonicalization
// must call GetDefaultModelName/GetDefaultFieldName explicitly.
func GetFieldName(model, field string, cfg AdapterConfig) string {
	return ResolveColumnName(model, field, cfg)
}

// GetDatabaseIndexName returns the stable database name for a table-level
// index: an explicit name is preserved, otherwise
// <table>_<columns>_<idx|uidx> is used with FNV-based truncation when it
// exceeds 63 UTF-8 bytes. Truncation strips the trailing "_<kind>" before
// cutting to the byte budget and re-appends "_<hash>_<kind>", mirroring
// upstream getDatabaseIndexName.
//
// DELTAS vs upstream: explicit names are not validated (upstream rejects
// empty/malformed/overlong names); the FNV-1a/32 hash runs over UTF-8 bytes
// (upstream iterates UTF-16 code units — identical output for ASCII names,
// potentially different for non-ASCII).
func GetDatabaseIndexName(tableName string, index TableIndex) string {
	if index.Name != "" {
		return index.Name
	}
	kind := "idx"
	if index.Unique {
		kind = "uidx"
	}
	generated := tableName + "_" + strings.Join(index.Fields, "_") + "_" + kind
	if len(generated) <= 63 {
		return generated
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(generated))
	suffix := fmt.Sprintf("_%08x_%s", h.Sum32(), kind)
	// Strip "_<kind>" before truncating so the hash suffix replaces the kind
	// tail rather than mid-name bytes (upstream slices
	// generatedName.slice(0, -indexKind.length - 1)).
	base := generated[:len(generated)-len(kind)-1]
	trim := 63 - len(suffix)
	if trim <= 0 {
		return suffix[1:]
	}
	return truncateUTF8Bytes(base, trim) + suffix
}

// truncateUTF8Bytes cuts s to at most n bytes on a UTF-8 character boundary.
// Go-only helper mirroring upstream truncateUtf8 (which iterates by
// character); len() counts bytes, matching upstream getUtf8ByteLength.
func truncateUTF8Bytes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if n >= len(s) {
		return s
	}
	for n > 0 && !validUTF8Prefix(s, n) {
		n--
	}
	return s[:n]
}

// validUTF8Prefix is a Go-only helper reporting whether byte offset n falls
// on a UTF-8 character boundary in s (used by truncateUTF8Bytes).
func validUTF8Prefix(s string, n int) bool {
	if n >= len(s) {
		return true
	}
	c := s[n]
	// Continuation bytes have the form 10xxxxxx.
	return c < 0x80 || c >= 0xC0
}

// camelToSnakeGo is a Go-only helper folding camelCase to snake_case for
// default physical names.
func camelToSnakeGo(s string) string {
	var b strings.Builder
	for i, r := range s {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(r + 32)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Migration diff (schema-diff.ts / get-migration.ts unsafe-change port)
//
// This section mirrors
// vendor/better-auth/packages/core/src/db/schema-diff.ts (Better Auth
// v1.7.5, commit 5468e6bf) plus the populated-table unsafe-change guard
// from vendor/better-auth/packages/better-auth/src/db/get-migration.ts.
// It is purely additive: nothing above is modified. The CLI
// (auth/cmd/generate-schema) consumes these helpers for current-vs-desired
// diffing; the runtime does not run migrations.
//
// Upstream TypeScript names are noted per symbol; Go-only helpers are
// marked as such.
// ---------------------------------------------------------------------------

// IntrospectedColumn describes one column as the database (or an ORM schema
// definition) reports it.
//
// Upstream TypeScript name: IntrospectedColumn (schema-diff.ts).
type IntrospectedColumn struct {
	// Name is the physical column name.
	Name string
	// Nullable reports whether the column accepts NULL.
	Nullable bool
	// HasDefault reports whether the store fills the column when an
	// insert omits it.
	HasDefault bool
}

// IntrospectedTable describes one table as the database (or an ORM schema
// definition) reports it.
//
// Upstream TypeScript name: IntrospectedTable (schema-diff.ts).
type IntrospectedTable struct {
	// Name is the physical table name.
	Name string
	// Schema is the schema the table lives in, when the store has
	// schemas. Empty means unqualified.
	Schema string
	// Columns holds the reported columns.
	Columns []IntrospectedColumn
}

// ExpectedTable is one entry of an ExpectedSchema: the columns Better Auth
// writes, keyed the way the store addresses them (physical table name,
// then physical column name).
//
// Upstream TypeScript name: the anonymous ExpectedSchema entry
// (schema-diff.ts).
type ExpectedTable struct {
	// Fields maps physical column names to their attributes.
	Fields map[string]FieldAttribute
	// IDColumn is the physical id column. Empty means "id" (upstream
	// `table.idColumn ?? "id"`).
	IDColumn string
	// DisableMigrations marks tables that manage their own storage and
	// are excluded from migrations and comparison.
	DisableMigrations bool
	// Schema is the schema the table is addressed in. Empty means the
	// table is found by name alone.
	Schema string
}

// ExpectedSchema holds the tables Better Auth writes, keyed the way the
// store addresses them (physical table name).
//
// Upstream TypeScript name: ExpectedSchema (schema-diff.ts).
type ExpectedSchema map[string]ExpectedTable

// ExpectedSchemaFromTables groups logical tables by physical table name,
// merging tables that share one physical name into a single entry (fields
// union; DisableMigrations ANDs so a shared table migrates when any
// contributor migrates), mirroring getExpectedSchema. Go-only helper;
// upstream inlines this grouping in getExpectedSchema.
//
// DELTA vs upstream: physical names derive from TableSchema.ModelName,
// per-field FieldName entries, and cfg (AdapterConfig); upstream uses only
// the schema-declared modelName/fieldName (plus a usePlural flag). Logical
// keys are scanned in sorted order so ambiguous shared-table merges resolve
// deterministically (Go map iteration is randomized).
func ExpectedSchemaFromTables(tables PluginSchema, cfg AdapterConfig) ExpectedSchema {
	expected := ExpectedSchema{}
	keys := make([]string, 0, len(tables))
	for key := range tables {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		table := tables[key]
		name := PhysicalTableName(key, table, cfg)
		entry := expected[name]
		if entry.Fields == nil {
			entry.Fields = map[string]FieldAttribute{}
			entry.DisableMigrations = true
		}
		for logical, field := range table.Fields {
			entry.Fields[PhysicalColumnName(key, table, logical, cfg)] = field
		}
		entry.DisableMigrations = entry.DisableMigrations && table.DisableMigrationsEffective()
		if entry.IDColumn == "" {
			entry.IDColumn = PhysicalColumnName(key, table, "id", cfg)
		}
		expected[name] = entry
	}
	return expected
}

// GetExpectedSchema returns the tables the resolved options write, keyed
// the way the adapter addresses them, mirroring getExpectedSchema (tables
// that manage their own storage stay present with DisableMigrations set;
// DiffSchema skips them).
//
// Upstream TypeScript name: getExpectedSchema (schema-diff.ts).
func GetExpectedSchema(opts Options, cfg AdapterConfig) ExpectedSchema {
	return ExpectedSchemaFromTables(GetAuthTables(opts), cfg)
}

// IntrospectedTablesFromSchema converts a desired/current PluginSchema into
// introspected tables (physical names; nullable from Required;
// hasDefault from static/timestamp defaults), for offline
// current-vs-desired comparison without a live database. Go-only helper;
// upstream introspects the live store instead.
func IntrospectedTablesFromSchema(schema PluginSchema, cfg AdapterConfig) []IntrospectedTable {
	names := make([]string, 0, len(schema))
	for name := range schema {
		names = append(names, name)
	}
	sort.Strings(names)
	seen := map[string]bool{}
	out := make([]IntrospectedTable, 0, len(names))
	for _, key := range names {
		table := schema[key]
		name := PhysicalTableName(key, table, cfg)
		if seen[name] {
			continue
		}
		seen[name] = true
		cols := []IntrospectedColumn{{Name: PhysicalColumnName(key, table, "id", cfg)}}
		fields := make([]string, 0, len(table.Fields))
		for field := range table.Fields {
			fields = append(fields, field)
		}
		sort.Strings(fields)
		for _, field := range fields {
			attr := table.Fields[field]
			cols = append(cols, IntrospectedColumn{
				Name:       PhysicalColumnName(key, table, field, cfg),
				Nullable:   attr.Required != nil && !*attr.Required,
				HasDefault: HasStaticColumnDefault(attr) || HasTimestampColumnDefault(attr),
			})
		}
		sort.Slice(cols, func(i, j int) bool { return cols[i].Name < cols[j].Name })
		out = append(out, IntrospectedTable{Name: name, Columns: cols})
	}
	return out
}

// SchemaFindingKind identifies the kind of a schema finding.
//
// Upstream TypeScript name: the SchemaFinding kind union (schema-diff.ts).
type SchemaFindingKind string

const (
	// SchemaFindingMissingTable reports a table Better Auth writes that
	// the store does not hold.
	SchemaFindingMissingTable SchemaFindingKind = "missing-table"
	// SchemaFindingMissingColumn reports a column Better Auth writes that
	// the table does not hold (including the implicit id column).
	SchemaFindingMissingColumn SchemaFindingKind = "missing-column"
	// SchemaFindingUnexpectedRequiredColumn reports a required column
	// Better Auth never writes (and that carries no default), which fails
	// every insert into its table.
	SchemaFindingUnexpectedRequiredColumn SchemaFindingKind = "unexpected-required-column"
)

// SchemaFinding is one schema comparison problem as data.
//
// Upstream TypeScript name: SchemaFinding (schema-diff.ts).
type SchemaFinding struct {
	Kind   SchemaFindingKind
	Table  string
	Column string
}

// DiffSchema compares the tables Better Auth writes with what the store
// holds, mirroring diffSchema: a table or column Better Auth writes must
// exist; a column Better Auth does not write must accept an insert that
// omits it (nullable or defaulted).
//
// Upstream TypeScript name: diffSchema (schema-diff.ts).
func DiffSchema(expected ExpectedSchema, actual []IntrospectedTable) []SchemaFinding {
	names := make([]string, 0, len(expected))
	for name := range expected {
		names = append(names, name)
	}
	sort.Strings(names)
	var findings []SchemaFinding
	for _, tableName := range names {
		table := expected[tableName]
		if table.DisableMigrations {
			continue
		}
		var actualTable *IntrospectedTable
		for i := range actual {
			candidate := &actual[i]
			if candidate.Name != tableName {
				continue
			}
			if table.Schema != "" && candidate.Schema != table.Schema {
				continue
			}
			actualTable = candidate
			break
		}
		if actualTable == nil {
			findings = append(findings, SchemaFinding{Kind: SchemaFindingMissingTable, Table: tableName})
			continue
		}
		idColumn := table.IDColumn
		if idColumn == "" {
			idColumn = "id"
		}
		written := map[string]struct{}{idColumn: {}}
		columns := make([]string, 0, len(table.Fields))
		for column := range table.Fields {
			columns = append(columns, column)
		}
		sort.Strings(columns)
		for _, column := range columns {
			written[column] = struct{}{}
		}
		ordered := append([]string{idColumn}, columns...)
		for _, column := range ordered {
			found := false
			for _, candidate := range actualTable.Columns {
				if candidate.Name == column {
					found = true
					break
				}
			}
			if !found {
				findings = append(findings, SchemaFinding{Kind: SchemaFindingMissingColumn, Table: tableName, Column: column})
			}
		}
		for _, column := range actualTable.Columns {
			if _, ok := written[column.Name]; ok {
				continue
			}
			if column.Nullable || column.HasDefault {
				continue
			}
			findings = append(findings, SchemaFinding{Kind: SchemaFindingUnexpectedRequiredColumn, Table: tableName, Column: column.Name})
		}
	}
	return findings
}

// SchemaSource names how the schema reaches the store, which decides the
// fix each finding names.
//
// Upstream TypeScript name: SchemaSource (schema-diff.ts).
type SchemaSource string

const (
	// SchemaSourceDatabase diffs against the live database.
	SchemaSourceDatabase SchemaSource = "database"
	// SchemaSourceDrizzle diffs against a Drizzle schema.
	SchemaSourceDrizzle SchemaSource = "drizzle"
	// SchemaSourcePrisma diffs against a Prisma schema.
	SchemaSourcePrisma SchemaSource = "prisma"
)

// FormatSchemaFinding renders one finding as a sentence naming the change
// that resolves it.
//
// Upstream TypeScript name: formatSchemaFinding (schema-diff.ts).
func FormatSchemaFinding(finding SchemaFinding, source SchemaSource) string {
	applyHint := map[SchemaSource]string{
		SchemaSourceDatabase: "Run `npx auth migrate` to add it.",
		SchemaSourceDrizzle:  "Run `npx auth generate` to refresh the Drizzle schema, then apply it with your migration tool.",
		SchemaSourcePrisma:   "Run `npx auth generate` to refresh the Prisma schema, then run `prisma migrate`.",
	}[source]
	relaxHint := map[SchemaSource]string{
		SchemaSourceDatabase: "Drop the column, make it nullable, or give it a database default.",
		SchemaSourceDrizzle:  "Remove it from the Drizzle schema, make it nullable, or give it a default, then apply the change with your migration tool.",
		SchemaSourcePrisma:   "Remove it from the Prisma schema, make it optional, or give it a default, then run `prisma migrate`.",
	}[source]
	switch finding.Kind {
	case SchemaFindingMissingTable:
		return fmt.Sprintf("Table %q is missing. %s", finding.Table, applyHint)
	case SchemaFindingMissingColumn:
		return fmt.Sprintf("Column %q is missing from table %q. %s", finding.Column, finding.Table, applyHint)
	case SchemaFindingUnexpectedRequiredColumn:
		issuer := ""
		if finding.Column == "issuer" {
			issuer = " If this column came from Better Auth 1.7.0 through 1.7.2, follow the upgrade guide before removing it: https://www.better-auth.com/docs/guides/1-7-upgrade-guide"
		}
		return fmt.Sprintf("Column %q on table %q is required but Better Auth never writes it, so every insert into %q fails. %s%s", finding.Column, finding.Table, finding.Table, relaxHint, issuer)
	default:
		return fmt.Sprintf("Unknown schema finding %q on table %q.", finding.Kind, finding.Table)
	}
}

// formatSchemaMismatch groups findings into the multi-line mismatch report
// carried by SchemaMismatchError. Go-only name; upstream inlines this in
// the SchemaMismatchError constructor (schema-diff.ts).
func formatSchemaMismatch(findings []SchemaFinding, source SchemaSource) string {
	sourceLabel := map[SchemaSource]string{
		SchemaSourceDatabase: "Database",
		SchemaSourceDrizzle:  "Drizzle",
		SchemaSourcePrisma:   "Prisma",
	}[source]
	var tables, columns, required []string
	affected := map[string]struct{}{}
	affectedOrder := []string{}
	hasIssuer := false
	for _, finding := range findings {
		switch finding.Kind {
		case SchemaFindingMissingTable:
			tables = append(tables, finding.Table)
		case SchemaFindingMissingColumn:
			columns = append(columns, finding.Table+"."+finding.Column)
		case SchemaFindingUnexpectedRequiredColumn:
			required = append(required, finding.Table+"."+finding.Column)
			if _, ok := affected[finding.Table]; !ok {
				affected[finding.Table] = struct{}{}
				affectedOrder = append(affectedOrder, finding.Table)
			}
			hasIssuer = hasIssuer || finding.Column == "issuer"
		}
	}
	sections := []string{sourceLabel + " schema mismatch"}
	if len(tables) > 0 {
		sections = append(sections, "  Missing tables\n    "+strings.Join(tables, ", "))
	}
	if len(columns) > 0 {
		sections = append(sections, "  Missing columns\n    "+strings.Join(columns, "\n    "))
	}
	if len(required) > 0 {
		sections = append(sections, "  Required columns Better Auth never writes\n    "+strings.Join(required, "\n    "))
		sections = append(sections, "  Inserts into "+strings.Join(affectedOrder, ", ")+" will fail.")
	}
	var help []string
	if len(required) > 0 {
		help = append(help, map[SchemaSource]string{
			SchemaSourceDatabase: "Make the listed columns nullable, give them defaults, or remove them.",
			SchemaSourceDrizzle:  "Make the listed columns nullable in your Drizzle schema, give them defaults, or remove them.",
			SchemaSourcePrisma:   "Make the listed fields optional in your Prisma schema, give them defaults, or remove them.",
		}[source])
	}
	if len(tables) > 0 || len(columns) > 0 || (len(required) > 0 && source != SchemaSourceDatabase) {
		migrationHint := map[SchemaSource]string{
			SchemaSourceDatabase: "Run `npx auth migrate` to add the missing tables and columns.",
			SchemaSourceDrizzle:  "Run `npx auth generate` to refresh the Drizzle schema, then apply it with your migration tool.",
			SchemaSourcePrisma:   "Run `npx auth generate` to refresh the Prisma schema, then run `prisma migrate`.",
		}[source]
		help = append(help, migrationHint)
	}
	if len(help) > 0 {
		sections = append(sections, "  help: "+strings.Join(help, "\n        "))
	}
	if hasIssuer {
		sections = append(sections, "  note: If this column came from Better Auth 1.7.0 through 1.7.2,\n        follow the upgrade guide before removing it:\n        https://www.better-auth.com/docs/guides/1-7-upgrade-guide")
	}
	return strings.Join(sections, "\n\n")
}

// SchemaMismatchError reports that the store cannot hold what the
// configuration writes. Findings carries every problem as data; the
// message lists each one with the change that resolves it.
//
// Upstream TypeScript name: SchemaMismatchError (schema-diff.ts).
type SchemaMismatchError struct {
	Findings []SchemaFinding
	Source   SchemaSource
}

// Error implements the error interface.
func (e *SchemaMismatchError) Error() string {
	return formatSchemaMismatch(e.Findings, e.Source)
}

// UnsafeMigrationError is returned when a migration refuses to add a
// required column with no default value to a populated table. It is
// distinct from plain index-definition errors so callers can distinguish
// the two without matching on message text.
//
// Upstream TypeScript name: UnsafeMigrationError (get-migration.ts).
type UnsafeMigrationError struct {
	Message string
}

// Error implements the error interface.
func (e *UnsafeMigrationError) Error() string { return e.Message }

// UnsafeColumnChangeMessage builds the populated-table refusal message for
// adding a required column with no default, mirroring the getMigrations
// reportUnsafeChange text (including the MySQL silent-corruption detail
// and the text-column empty-string detail).
//
// Upstream TypeScript name: the reportUnsafeChange call in getMigrations
// (get-migration.ts).
func UnsafeColumnChangeMessage(table, column string, fieldType FieldType) string {
	textDetail := ""
	if fieldType == FieldTypeString {
		textDetail = " For a text column, every existing row ends up with the same empty string."
	}
	return fmt.Sprintf("Cannot add required column %q to populated table %q: the schema declares no default value, so existing rows have no value to backfill. MySQL accepts this statement instead of rejecting it and fills every existing row with an implicit default for the column type, reporting a successful migration over corrupted data.%s Add the column as nullable, backfill a correct value for every row, then make it NOT NULL.", column, table, textDetail)
}

// IsUnsafeColumnAddition reports whether adding attr to a populated table
// is unsafe: the column is required and carries neither a static default
// nor (when hasTimestampDefault) a timestamp column default, mirroring the
// getMigrations populated-table guard. hasTimestampDefault stands in for
// hasTimestampColumnDefault(field, dbType): pass
// SupportsTimestampColumnDefault(dialect) && HasTimestampColumnDefault(attr).
// Nullable unique columns are safe via HasStaticColumnDefault (NULL is
// their unique-safe backfill).
//
// Upstream TypeScript names: the hasTimestampColumnDefault /
// hasStaticColumnDefault guard in getMigrations (get-migration.ts).
func IsUnsafeColumnAddition(attr FieldAttribute, hasTimestampDefault bool) bool {
	if attr.Required != nil && !*attr.Required {
		return false
	}
	if hasTimestampDefault {
		return false
	}
	if HasStaticColumnDefault(attr) {
		return false
	}
	return true
}

// SupportsTimestampColumnDefault reports whether dialect renders func date
// defaults as a native CURRENT_TIMESTAMP column default (postgres, mysql,
// mssql families), mirroring the hasTimestampColumnDefault dialect gate in
// get-migration.ts. SQLite (and unknown dialects, conservatively) do not.
// Go-only helper; upstream gates inline on KyselyDatabaseType.
func SupportsTimestampColumnDefault(dialect string) bool {
	switch strings.ToLower(strings.TrimSpace(dialect)) {
	case "postgres", "postgresql", "mysql", "mssql", "sqlserver":
		return true
	default:
		return false
	}
}

// matchColumnTypeMaps mirrors the postgresMap/mysqlMap/sqliteMap/mssqlMap
// physical-type tables in get-migration.ts. Go-only value.
var matchColumnTypeMaps = map[string]map[FieldType][]string{
	"postgres": {
		FieldTypeString:  {"character varying", "varchar", "text", "uuid"},
		FieldTypeNumber:  {"int4", "integer", "bigint", "smallint", "numeric", "real", "double precision"},
		FieldTypeBoolean: {"bool", "boolean"},
		FieldTypeDate:    {"timestamptz", "timestamp", "date"},
		FieldTypeJSON:    {"json", "jsonb"},
	},
	"mysql": {
		FieldTypeString:  {"varchar", "text", "uuid"},
		FieldTypeNumber:  {"integer", "int", "bigint", "smallint", "decimal", "float", "double"},
		FieldTypeBoolean: {"boolean", "tinyint"},
		FieldTypeDate:    {"timestamp", "datetime", "date"},
		FieldTypeJSON:    {"json"},
	},
	"sqlite": {
		FieldTypeString:  {"TEXT"},
		FieldTypeNumber:  {"INTEGER", "REAL", "BIGINT"},
		FieldTypeBoolean: {"INTEGER", "BOOLEAN"},
		FieldTypeDate:    {"DATE", "INTEGER"},
		FieldTypeJSON:    {"TEXT"},
	},
	"mssql": {
		FieldTypeString:  {"varchar", "nvarchar", "uniqueidentifier"},
		FieldTypeNumber:  {"int", "bigint", "smallint", "decimal", "float", "double"},
		FieldTypeBoolean: {"bit", "smallint"},
		FieldTypeDate:    {"datetime2", "date", "datetime"},
		FieldTypeJSON:    {"varchar", "nvarchar"},
	},
}

// MatchColumnType reports whether a live column type matches a declared
// field type on dialect, mirroring matchType in get-migration.ts
// (case-insensitive, ignoring parenthesized parameters; array field types
// expect a JSON store).
//
// Upstream TypeScript name: matchType (get-migration.ts).
func MatchColumnType(columnDataType string, fieldType FieldType, dialect string) bool {
	normalize := func(t string) string {
		t = strings.ToLower(t)
		if i := strings.Index(t, "("); i >= 0 {
			t = t[:i]
		}
		return strings.TrimSpace(t)
	}
	if fieldType == "string[]" || fieldType == "number[]" || strings.HasSuffix(string(fieldType), "[]") {
		return strings.Contains(strings.ToLower(columnDataType), "json")
	}
	types, ok := matchColumnTypeMaps[strings.ToLower(strings.TrimSpace(dialect))]
	if !ok {
		// DELTA vs upstream (which indexes map[dbType] unconditionally):
		// unknown dialects report no match instead of throwing.
		return false
	}
	expected, ok := types[fieldType]
	if !ok {
		return false
	}
	normalized := normalize(columnDataType)
	for _, want := range expected {
		if normalized == strings.ToLower(want) {
			return true
		}
	}
	return false
}

// AddedColumn is one column present in the desired schema but absent from
// the current schema. Go-only type for offline current-vs-desired diffing.
type AddedColumn struct {
	// LogicalTable is the desired logical model key.
	LogicalTable string
	// Table is the physical table name.
	Table string
	// LogicalField is the desired logical field name.
	LogicalField string
	// Column is the physical column name.
	Column string
	// Attr is the desired field declaration.
	Attr FieldAttribute
}

// AddedIndex is one resolved index present in the desired schema but
// absent from the current schema. Go-only type for offline diffing.
type AddedIndex struct {
	// Table is the physical table name.
	Table string
	// Index is the desired resolved index.
	Index ResolvedDBTableIndex
}

// SchemaDiff is the offline current-vs-desired diff: tables/columns/indexes
// to add plus unsafe-change advisories in the upstream generate spirit
// (kysely unsafeChanges). Go-only type; upstream computes this against a
// live database inside getMigrations.
type SchemaDiff struct {
	// ToBeCreated holds desired logical model keys whose physical table
	// is absent from current, in sorted order.
	ToBeCreated []string
	// ToBeAdded holds desired columns absent from current, ordered by
	// physical table then column.
	ToBeAdded []AddedColumn
	// ToBeAddedIndexes holds desired resolved indexes absent from
	// current, ordered by physical table then index name.
	ToBeAddedIndexes []AddedIndex
	// UnsafeChanges carries populated-table refusals as data (same text
	// the throwing path returns in UnsafeMigrationError).
	UnsafeChanges []string
	// Findings carries the same gap as SchemaFinding values
	// (missing-table/missing-column only; both schemas are desired
	// shapes, so unexpected-required columns never arise here).
	Findings []SchemaFinding
}

// DiffSchemas diffs current against desired (both logical PluginSchema
// maps) without a live database: tables/columns/indexes present in desired
// but absent from current are planned; adding a required column with no
// default to a populated table is reported in UnsafeChanges instead of
// throwing (pass throwOnUnsafe-style handling to the caller).
//
// populated maps physical table names to whether they hold rows. A nil map
// assumes every existing table is populated (conservative offline
// default); a non-nil (possibly empty) map is exact. timestampDefaults
// stands in for the dialect gate (see SupportsTimestampColumnDefault):
// pass true when the target dialect renders func date defaults as
// CURRENT_TIMESTAMP.
//
// Tables with DisableMigrationsEffective in desired are skipped, matching
// getAuthTablesWithResolvedIndexes. An index-name conflict with a different
// definition is an error mirroring the upstream
// BetterAuthError index-definition refusals.
//
// Go-only helper; upstream diffs a live store inside getMigrations
// (get-migration.ts).
func DiffSchemas(current, desired PluginSchema, cfg AdapterConfig, populated map[string]bool, timestampDefaults bool) (SchemaDiff, error) {
	var diff SchemaDiff
	currentPhysical := map[string]bool{}
	currentColumns := map[string]map[string]bool{}
	for _, table := range IntrospectedTablesFromSchema(current, cfg) {
		currentPhysical[table.Name] = true
		cols := map[string]bool{}
		for _, col := range table.Columns {
			cols[col.Name] = true
		}
		if existing, ok := currentColumns[table.Name]; ok {
			for col := range cols {
				existing[col] = true
			}
		} else {
			currentColumns[table.Name] = cols
		}
	}
	desiredKeys := make([]string, 0, len(desired))
	for key := range desired {
		desiredKeys = append(desiredKeys, key)
	}
	sort.Strings(desiredKeys)
	for _, key := range desiredKeys {
		table := desired[key]
		if table.DisableMigrationsEffective() {
			continue
		}
		tableName := PhysicalTableName(key, table, cfg)
		if !currentPhysical[tableName] {
			diff.ToBeCreated = append(diff.ToBeCreated, key)
			continue
		}
		fields := make([]string, 0, len(table.Fields))
		for field := range table.Fields {
			fields = append(fields, field)
		}
		sort.Strings(fields)
		for _, field := range fields {
			attr := table.Fields[field]
			column := PhysicalColumnName(key, table, field, cfg)
			if currentColumns[tableName][column] {
				continue
			}
			diff.ToBeAdded = append(diff.ToBeAdded, AddedColumn{
				LogicalTable: key,
				Table:        tableName,
				LogicalField: field,
				Column:       column,
				Attr:         attr,
			})
			isPopulated := populated == nil || populated[tableName]
			if isPopulated && IsUnsafeColumnAddition(attr, timestampDefaults && HasTimestampColumnDefault(attr)) {
				diff.UnsafeChanges = append(diff.UnsafeChanges, UnsafeColumnChangeMessage(tableName, column, attr.Type))
			}
		}
	}
	sort.Slice(diff.ToBeAdded, func(i, j int) bool {
		if diff.ToBeAdded[i].Table != diff.ToBeAdded[j].Table {
			return diff.ToBeAdded[i].Table < diff.ToBeAdded[j].Table
		}
		return diff.ToBeAdded[i].Column < diff.ToBeAdded[j].Column
	})
	currentIndexes := ResolveSchemaIndexes(current, cfg)
	desiredIndexes := ResolveSchemaIndexes(desired, cfg)
	type indexKey struct{ table, name string }
	seen := map[indexKey]ResolvedDBTableIndex{}
	for table, indexes := range currentIndexes {
		for _, index := range indexes {
			seen[indexKey{table, portableIndexKey(index.Name)}] = index
		}
	}
	for table, indexes := range desiredIndexes {
		if _, ok := currentPhysical[table]; !ok {
			continue
		}
		for _, index := range indexes {
			key := indexKey{table, portableIndexKey(index.Name)}
			if existing, ok := seen[key]; ok {
				if existing.Unique != index.Unique || len(existing.Columns) != len(index.Columns) {
					return SchemaDiff{}, fmt.Errorf("auth: database index %q on table %q does not match the configured fields and uniqueness. Rename or replace the existing index, then run the migration again.", index.Name, table)
				}
				mismatch := false
				for i := range existing.Columns {
					if existing.Columns[i] != index.Columns[i] {
						mismatch = true
						break
					}
				}
				if mismatch {
					return SchemaDiff{}, fmt.Errorf("auth: database index %q on table %q does not match the configured fields and uniqueness. Rename or replace the existing index, then run the migration again.", index.Name, table)
				}
				continue
			}
			seen[key] = index
			diff.ToBeAddedIndexes = append(diff.ToBeAddedIndexes, AddedIndex{Table: table, Index: index})
		}
	}
	sort.Slice(diff.ToBeAddedIndexes, func(i, j int) bool {
		if diff.ToBeAddedIndexes[i].Table != diff.ToBeAddedIndexes[j].Table {
			return diff.ToBeAddedIndexes[i].Table < diff.ToBeAddedIndexes[j].Table
		}
		return diff.ToBeAddedIndexes[i].Index.Name < diff.ToBeAddedIndexes[j].Index.Name
	})
	diff.Findings = DiffSchema(ExpectedSchemaFromTables(desired, cfg), IntrospectedTablesFromSchema(current, cfg))
	return diff, nil
}

// AUTH-S6-01: unified schema + identity admission pipeline.
// New code must use FullSchema/GetSchema and the Input/Output helpers below.
// ---------------------------------------------------------------------------

// GetSchema mirrors upstream getSchema: physical modelName/column view.
// Upstream TypeScript name: getSchema.
func GetSchema(opts Options) PluginSchema {
	tables, _ := GetAuthTablesWithResolvedIndexes(opts, AdapterConfig{})
	// Physical index metadata keyed by physical table name for attachment.
	indexes := ResolveSchemaIndexes(tables, AdapterConfig{})
	keys := make([]string, 0, len(tables))
	for key := range tables {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	schema := PluginSchema{}
	for _, key := range keys {
		table := tables[key]
		modelName := table.ModelName
		if modelName == "" {
			modelName = key
		}
		actualFields := make(map[string]FieldAttribute, len(table.Fields))
		for logical, field := range table.Fields {
			physical := field.FieldName
			if physical == "" {
				physical = logical
			}
			if field.References != nil {
				refs := *field.References
				if target, ok := tables[field.References.Model]; ok {
					if target.ModelName != "" {
						refs.Model = target.ModelName
					} else {
						refs.Model = field.References.Model
					}
				}
				field.References = &refs
			}
			actualFields[physical] = field
		}
		if existing, ok := schema[modelName]; ok {
			for name, field := range actualFields {
				existing.Fields[name] = field
			}
			if table.DisableMigrationsEffective() {
				existing.DisableMigrations = boolPtrGo(true)
				existing.DisableMigration = true
			}
			schema[modelName] = existing
			continue
		}
		entry := TableSchema{
			ModelName:        modelName,
			Fields:           actualFields,
			Order:            table.Order,
			DisableMigration: table.DisableMigration,
		}
		if table.DisableMigrations != nil {
			v := *table.DisableMigrations
			entry.DisableMigrations = &v
		}
		if table.DisableMigrationsEffective() {
			entry.DisableMigration = true
		}
		// Attach resolved index metadata by physical table name.
		if resolved, ok := indexes[PhysicalTableName(key, table, AdapterConfig{})]; ok {
			entry.Indexes = resolvedIndexesToTableIndexes(resolved)
		}
		schema[modelName] = entry
	}
	return schema
}

// resolvedIndexesToTableIndexes converts resolved index metadata back to TableIndex.
func resolvedIndexesToTableIndexes(resolved []ResolvedDBTableIndex) []TableIndex {
	out := make([]TableIndex, 0, len(resolved))
	for _, r := range resolved {
		out = append(out, TableIndex{Fields: append([]string(nil), r.Columns...), Name: r.Name, Unique: r.Unique})
	}
	return out
}

// InputFields returns the resolved input field map for one logical model.
func InputFields(opts Options, model string) map[string]FieldAttribute {
	out := map[string]FieldAttribute{}
	for _, plugin := range opts.Plugins {
		if plugin == nil {
			continue
		}
		if table, ok := plugin.Schema()[model]; ok {
			for name, field := range table.Fields {
				out[name] = field
			}
		}
	}
	var additional map[string]FieldAttribute
	switch model {
	case "user":
		additional = opts.User.Model.AdditionalFields
	case "session":
		additional = opts.Session.Model.AdditionalFields
	case "account":
		additional = opts.Account.Model.AdditionalFields
	case "verification":
		additional = opts.Verification.Model.AdditionalFields
	}
	for name, field := range additional {
		out[name] = field
	}
	return out
}

// OutputFields returns the resolved output field map for one logical model.
func OutputFields(opts Options, model string) map[string]FieldAttribute {
	if table, ok := FullSchema(opts)[model]; ok {
		return table.Fields
	}
	return nil
}

// UserInputFields returns InputFields for the user model.
func UserInputFields(opts Options) map[string]FieldAttribute { return InputFields(opts, "user") }

// UserOutputFields returns OutputFields for the user model.
func UserOutputFields(opts Options) map[string]FieldAttribute { return OutputFields(opts, "user") }

// SessionInputFields returns InputFields for the session model.
func SessionInputFields(opts Options) map[string]FieldAttribute {
	return InputFields(opts, "session")
}

// SessionOutputFields returns OutputFields for the session model.
func SessionOutputFields(opts Options) map[string]FieldAttribute {
	return OutputFields(opts, "session")
}

// AccountInputFields returns InputFields for the account model.
func AccountInputFields(opts Options) map[string]FieldAttribute {
	return InputFields(opts, "account")
}

// AccountOutputFields returns OutputFields for the account model.
func AccountOutputFields(opts Options) map[string]FieldAttribute {
	return OutputFields(opts, "account")
}

// BuildSyntheticUserOutput builds an enumeration-safe synthetic user.
func BuildSyntheticUserOutput(opts Options, data map[string]any) map[string]any {
	schema := OutputFields(opts, "user")
	result := map[string]any{}
	for key, attr := range schema {
		if attr.Returned != nil && !*attr.Returned {
			continue
		}
		if v, ok := data[key]; ok && v != nil {
			result[key] = v
			continue
		}
		if attr.DefaultValue != nil {
			result[key] = callDefaultValue(attr.DefaultValue)
			continue
		}
		if attr.Required != nil && !*attr.Required {
			result[key] = nil
		}
	}
	if id, ok := data["id"]; ok {
		result["id"] = id
	}
	return result
}

// callDefaultValue evaluates a field DefaultValue: any zero-arg func (of any
// signature, e.g. func() any, func() string, func() time.Time) is invoked
// via reflection like upstream () => new Date() / () => Date.now()
// factories; any other value is returned as-is. Go-only helper.
func callDefaultValue(v any) any {
	if v == nil {
		return nil
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Func && rv.Type().NumIn() == 0 && rv.Type().NumOut() == 1 {
		out := rv.Call(nil)
		return out[0].Interface()
	}
	return v
}

// ValidateUserInfo admission seam.
// Upstream gate runs before create-user, link-account, and OAuth/SSO sign-in.
// A throwing hook fails closed as validation_failed; a missing/invalid source fails closed
// as validation_source_missing.
// Route handlers must call AssertValidUserInfo at each seam.
// ---------------------------------------------------------------------------

// ValidateUserInfoSourceBuilder builds a flat ValidateUserInfoSource.
type ValidateUserInfoSourceBuilder struct {
	src types.ValidateUserInfoSource
}

// OAuthProvisioningSource starts a provisioning source for method "oauth".
func OAuthProvisioningSource(providerID string, profile map[string]any) ValidateUserInfoSourceBuilder {
	return ValidateUserInfoSourceBuilder{src: types.ValidateUserInfoSource{
		Method:     types.ValidateUserInfoMethodOAuth,
		ProviderID: providerID,
		Profile:    profile,
	}}
}

// SSOProvisioningSource starts a provisioning source for an SSO method.
func SSOProvisioningSource(method types.ValidateUserInfoMethod, providerID string, profile map[string]any) ValidateUserInfoSourceBuilder {
	return ValidateUserInfoSourceBuilder{src: types.ValidateUserInfoSource{
		Method:     method,
		ProviderID: providerID,
		Profile:    profile,
	}}
}

// MethodProvisioningSource starts a provisioning source for a non-provider method.
func MethodProvisioningSource(method types.ValidateUserInfoMethod) ValidateUserInfoSourceBuilder {
	return ValidateUserInfoSourceBuilder{src: types.ValidateUserInfoSource{Method: method}}
}

// WithAction sets the lifecycle action and returns the flat source.
func (b ValidateUserInfoSourceBuilder) WithAction(action types.ValidateUserInfoAction) types.ValidateUserInfoSource {
	b.src.Action = action
	return b.src
}

// AssertValidUserInfoSource checks the method and provider id.
func AssertValidUserInfoSource(src types.ValidateUserInfoSource) error {
	if src.Method == "" {
		return types.HttpError{Code: "validation_source_missing", Message: "User validation source is required", Status: 403}
	}
	if src.Method == types.ValidateUserInfoMethodOAuth && src.ProviderID == "" {
		return types.HttpError{Code: "validation_source_missing", Message: "OAuth user validation source requires oauth.providerId", Status: 403}
	}
	if (src.Method == types.ValidateUserInfoMethodSSOOIDC || src.Method == types.ValidateUserInfoMethodSSOSAML) && src.ProviderID == "" {
		return types.HttpError{Code: "validation_source_missing", Message: "SSO user validation source requires sso.providerId", Status: 403}
	}
	return nil
}

// AssertValidUserInfo invokes the user.validateUserInfo gate.
// A nil hook allows everything. A throwing hook fails closed as
// validation_failed.
func AssertValidUserInfo(_ context.Context, hook types.ValidateUserInfoFunc, epCtx types.EndpointContext, user map[string]any, src types.ValidateUserInfoSource) error {
	if hook == nil {
		return nil
	}
	if err := AssertValidUserInfoSource(src); err != nil {
		return err
	}
	result, err := hook(types.ValidateUserInfoData{User: user, Source: src}, epCtx)
	if err != nil {
		return types.HttpError{Code: "validation_failed", Message: "User validation failed", Status: 403}
	}
	if result != nil && result.Error != "" {
		msg := result.ErrorDescription
		if msg == "" {
			msg = result.Error
		}
		return types.HttpError{Code: result.Error, Message: msg, Status: 403}
	}
	return nil
}

// ValidateUserInfoRedirectURL builds the browser-flow redirect for a gate rejection.
func ValidateUserInfoRedirectURL(baseURL, code, description string) string {
	params := url.Values{}
	params.Set("error", code)
	if description != "" {
		params.Set("error_description", description)
	}
	encoded := params.Encode()
	// Preserve any fragment: insert before #.
	var fragment string
	base := baseURL
	if i := strings.Index(base, "#"); i >= 0 {
		fragment = base[i:]
		base = base[:i]
	}
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + encoded + fragment
}
