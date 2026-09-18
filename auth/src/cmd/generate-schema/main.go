package main

import (
	"flag"
	"fmt"
	"go/format"
	"os"
	"sort"
	"strings"

	auth "github.com/brick-org/brick/auth/src"
)

type fieldDef struct {
	GoName     string
	ColumnName string
	GoType     string
	TagParts   []string
}

type relDef struct {
	GoName   string // e.g. "Organization"
	GoType   string // e.g. "*AuthOrganization"
	JoinFrom string // e.g. "organization_id"
	JoinTo   string // e.g. "id"
}

type modelDef struct {
	Name         string
	StructName   string
	TableName    string
	Fields       []fieldDef
	Relations    []relDef
	Dependencies []string // model names this model depends on (for ordering)
	Indexes      []auth.ResolvedDBTableIndex
}

func main() {
	pkg := flag.String("package", "main", "package name for the generated Go file")
	prefix := flag.String("prefix", "Auth", "prefix for generated struct names")
	migrateFunc := flag.String("migrate-func", "AuthModels", "name of generated migration helper")
	pluginsFlag := flag.String("plugins", "", "comma-separated registered plugin schema IDs to include (core-only: built-ins removed)")
	orgTeams := flag.Bool("org-teams", false, "include org team tables and session.activeTeamId")
	modelNames := flag.String("model-names", "", "comma-separated logical=physical model renames, e.g. user=app_users")
	fieldNames := flag.String("field-names", "", "comma-separated model.field=column renames, e.g. user.email=email_address")
	withRateLimit := flag.Bool("with-rate-limit", false, "include the rateLimit storage table (rateLimit.storage=database)")
	secondaryStorage := flag.Bool("secondary-storage", false, "omit secondary-stored tables per get-tables.ts inclusion rules")
	storeSession := flag.Bool("store-session-in-database", false, "keep the session table when -secondary-storage is set")
	storeVerification := flag.Bool("store-verification-in-database", false, "keep the verification table when -secondary-storage is set")
	dialectFlag := flag.String("dialect", "sqlite", "SQL dialect for -sql output (sqlite, postgres, mysql, mssql)")
	sqlOut := flag.Bool("sql", false, "emit a SQL migration script for -dialect instead of Go models")
	idType := flag.String("id-type", "string", "id column flavor for -sql output (string, uuid, serial)")
	configPath := flag.String("config", "", "path to a JSON generator config file (plugins, plugin options, inline schemas, renames, flags); explicit CLI flags override file values")
	fromPath := flag.String("from", "", "path to a JSON schema snapshot of the current schema for current-vs-desired diffing; with -sql emits ALTER TABLE ADD COLUMN units for the gap, with -check only reports drift")
	populatedFlag := flag.String("populated", "", "comma-separated physical table names holding rows; when non-empty it replaces the -from snapshot populated info with exactly this set (an explicit empty list lives in the snapshot file as \"populated\": [])")
	checkOnly := flag.Bool("check", false, "report current-vs-desired drift from -from without emitting; exits 2 when the diff is non-empty")
	throwOnUnsafe := flag.Bool("throw-on-unsafe", false, "refuse to emit when the plan carries unsafe changes (migrate-like refusal); otherwise warn and prefix the banner (generate-like)")
	flag.Parse()

	var fileCfg *GeneratorConfig
	if strings.TrimSpace(*configPath) != "" {
		var err error
		fileCfg, err = LoadGeneratorConfig(*configPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	// File-backed defaults: explicit flags win (strings when they differ
	// from the flag default, bools by OR, maps merged with flag entries
	// winning per key).
	dialectRaw, idTypeRaw := *dialectFlag, *idType
	pkgName, prefixName, migrateFuncName := *pkg, *prefix, *migrateFunc
	if fileCfg != nil {
		if *dialectFlag == "sqlite" && fileCfg.Dialect != "" {
			dialectRaw = fileCfg.Dialect
		}
		if *idType == "string" && fileCfg.IDType != "" {
			idTypeRaw = fileCfg.IDType
		}
		if *pkg == "main" && fileCfg.Package != "" {
			pkgName = fileCfg.Package
		}
		if *prefix == "Auth" && fileCfg.Prefix != "" {
			prefixName = fileCfg.Prefix
		}
		if *migrateFunc == "AuthModels" && fileCfg.MigrateFunc != "" {
			migrateFuncName = fileCfg.MigrateFunc
		}
	}

	dialect, err := parseDialect(dialectRaw)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := validateIDType(idTypeRaw); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if err := validateMigrateFunc(migrateFuncName); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	var pluginSpecs []string
	if strings.TrimSpace(*pluginsFlag) != "" {
		pluginSpecs = strings.Split(*pluginsFlag, ",")
	}
	plugins, err := buildPluginsExtended(pluginSpecs, fileCfg, *orgTeams)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	cfg := parseAdapterConfig(*modelNames, *fieldNames)
	if fileCfg != nil {
		mergeAdapterConfig(cfg, fileCfg)
	}

	opts := auth.Options{Plugins: plugins}
	schema := auth.GetAuthTablesWithSecondaryStorage(opts, *secondaryStorage || boolFlag(fileCfg, "secondaryStorage"), *storeSession || boolFlag(fileCfg, "storeSessionInDatabase"), *storeVerification || boolFlag(fileCfg, "storeVerificationInDatabase"))
	if *withRateLimit || boolFlag(fileCfg, "withRateLimit") {
		schema = auth.MergeSchemas(schema, auth.RateLimitSchema())
	}
	// Complete index validation (unknown/duplicate/unindexable fields,
	// nullable unique columns, name collisions, multi-table aliasing),
	// mirroring upstream resolveDatabaseSchemaIndexes. Fail before emitting.
	if err := auth.ValidateSchemaIndexes(schema, cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *checkOnly && strings.TrimSpace(*fromPath) == "" {
		fmt.Fprintln(os.Stderr, "-check requires -from")
		os.Exit(1)
	}
	if strings.TrimSpace(*fromPath) != "" && !*sqlOut && !*checkOnly {
		fmt.Fprintln(os.Stderr, "-from requires -sql or -check")
		os.Exit(1)
	}
	if strings.TrimSpace(*fromPath) != "" {
		runFromDiff(*fromPath, *populatedFlag, schema, cfg, dialect, idTypeRaw, *sqlOut, *checkOnly, *throwOnUnsafe)
		return
	}
	if *sqlOut {
		plan, err := BuildMigrationPlan(schema, cfg, dialect, idTypeRaw)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if len(plan.UnsafeChanges) > 0 && *throwOnUnsafe {
			for _, warn := range plan.UnsafeChanges {
				fmt.Fprintf(os.Stderr, "unsafe change: %s\n", warn)
			}
			fmt.Fprintln(os.Stderr, "refusing to emit: rerun without -throw-on-unsafe to inspect the plan")
			os.Exit(1)
		}
		for _, warn := range plan.UnsafeChanges {
			fmt.Fprintf(os.Stderr, "warning: unsafe change: %s\n", warn)
		}
		out := plan.Script()
		if len(plan.UnsafeChanges) > 0 {
			out = unsafeBanner(plan.UnsafeChanges) + out
		}
		if _, err := os.Stdout.Write([]byte(out)); err != nil {
			fmt.Fprintf(os.Stderr, "write generated SQL: %v\n", err)
			os.Exit(1)
		}
		return
	}
	models, err := buildModels(prefixName, schema, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	source := renderModels(pkgName, migrateFuncName, models)
	formatted, err := format.Source([]byte(source))
	if err != nil {
		fmt.Fprintln(os.Stderr, source)
		fmt.Fprintf(os.Stderr, "format generated source: %v\n", err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(formatted); err != nil {
		fmt.Fprintf(os.Stderr, "write generated source: %v\n", err)
		os.Exit(1)
	}
}

// validateMigrateFunc rejects empty or non-identifier -migrate-func values so
// the generated helper name is always a valid exported Go identifier.
func validateMigrateFunc(name string) error {
	if name == "" {
		return fmt.Errorf("invalid -migrate-func %q: name must not be empty", name)
	}
	for i, r := range name {
		ok := r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (i > 0 && r >= '0' && r <= '9')
		if !ok {
			return fmt.Errorf("invalid -migrate-func %q: must be a valid Go identifier", name)
		}
	}
	return nil
}

func parseAdapterConfig(modelNames, fieldNames string) auth.AdapterConfig {
	cfg := auth.AdapterConfig{}
	if strings.TrimSpace(modelNames) != "" {
		cfg.ModelNames = map[string]string{}
		for _, pair := range strings.Split(modelNames, ",") {
			kv := strings.SplitN(strings.TrimSpace(pair), "=", 2)
			if len(kv) != 2 || kv[0] == "" || kv[1] == "" {
				fmt.Fprintf(os.Stderr, "warning: ignoring malformed -model-names entry %q\n", pair)
				continue
			}
			cfg.ModelNames[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	if strings.TrimSpace(fieldNames) != "" {
		cfg.FieldNames = map[string]string{}
		for _, pair := range strings.Split(fieldNames, ",") {
			kv := strings.SplitN(strings.TrimSpace(pair), "=", 2)
			if len(kv) != 2 || kv[0] == "" || kv[1] == "" || !strings.Contains(kv[0], ".") {
				fmt.Fprintf(os.Stderr, "warning: ignoring malformed -field-names entry %q (want model.field=column)\n", pair)
				continue
			}
			cfg.FieldNames[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	return cfg
}

// boolFlag reads a bool from the file config (nil-safe for the
// pre-config path).
func boolFlag(cfg *GeneratorConfig, field string) bool {
	if cfg == nil {
		return false
	}
	switch field {
	case "secondaryStorage":
		return cfg.SecondaryStorage
	case "storeSessionInDatabase":
		return cfg.StoreSessionInDatabase
	case "storeVerificationInDatabase":
		return cfg.StoreVerificationInDatabase
	case "withRateLimit":
		return cfg.WithRateLimit
	}
	return false
}

// mergeAdapterConfig overlays file-configured renames under already-parsed
// flag renames (flag entries win per key).
func mergeAdapterConfig(cfg auth.AdapterConfig, fileCfg *GeneratorConfig) {
	if fileCfg == nil {
		return
	}
	if len(fileCfg.ModelNames) > 0 {
		if cfg.ModelNames == nil {
			cfg.ModelNames = map[string]string{}
		}
		for k, v := range fileCfg.ModelNames {
			if _, ok := cfg.ModelNames[k]; !ok {
				cfg.ModelNames[k] = v
			}
		}
	}
	if len(fileCfg.FieldNames) > 0 {
		if cfg.FieldNames == nil {
			cfg.FieldNames = map[string]string{}
		}
		for k, v := range fileCfg.FieldNames {
			if _, ok := cfg.FieldNames[k]; !ok {
				cfg.FieldNames[k] = v
			}
		}
	}
}

// runFromDiff executes the current-vs-desired diff flow for -from: it
// loads the snapshot, reports findings with upstream fix hints, and either
// checks drift (-check, exit 2 when non-empty) or emits the incremental
// SQL plan (-sql).
func runFromDiff(fromPath, populatedFlag string, desired auth.PluginSchema, cfg auth.AdapterConfig, dialect Dialect, idKind string, sqlOut, checkOnly, throwOnUnsafe bool) {
	current, populated, err := loadSnapshotFile(fromPath, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if strings.TrimSpace(populatedFlag) != "" {
		populated = map[string]bool{}
		for _, name := range strings.Split(populatedFlag, ",") {
			if trimmed := strings.TrimSpace(name); trimmed != "" {
				populated[trimmed] = true
			}
		}
	}
	diff, err := auth.DiffSchemas(current, desired, cfg, populated, auth.SupportsTimestampColumnDefault(string(dialect)))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	plan, err := DiffMigrationPlan(current, desired, cfg, dialect, idKind, populated)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if checkOnly {
		for _, finding := range diff.Findings {
			fmt.Fprintf(os.Stderr, "%s\n", auth.FormatSchemaFinding(finding, auth.SchemaSourceDatabase))
		}
		for _, warn := range plan.UnsafeChanges {
			fmt.Fprintf(os.Stderr, "unsafe change: %s\n", warn)
		}
		if len(diff.Findings) == 0 && len(plan.UnsafeChanges) == 0 {
			fmt.Fprintln(os.Stderr, "schema is up to date")
			return
		}
		os.Exit(2)
	}
	if len(plan.UnsafeChanges) > 0 && throwOnUnsafe {
		for _, warn := range plan.UnsafeChanges {
			fmt.Fprintf(os.Stderr, "unsafe change: %s\n", warn)
		}
		fmt.Fprintln(os.Stderr, "refusing to emit: rerun without -throw-on-unsafe to inspect the plan")
		os.Exit(1)
	}
	for _, warn := range plan.UnsafeChanges {
		fmt.Fprintf(os.Stderr, "warning: unsafe change: %s\n", warn)
	}
	for _, finding := range diff.Findings {
		fmt.Fprintf(os.Stderr, "drift: %s\n", auth.FormatSchemaFinding(finding, auth.SchemaSourceDatabase))
	}
	out := plan.Script()
	if len(plan.UnsafeChanges) > 0 {
		out = unsafeBanner(plan.UnsafeChanges) + out
	}
	if _, err := os.Stdout.Write([]byte(out)); err != nil {
		fmt.Fprintf(os.Stderr, "write generated SQL: %v\n", err)
		os.Exit(1)
	}
}

func buildPlugins(raw string, orgTeams bool) ([]auth.Plugin, error) {
	// Empty -plugins emits the default schema. Only registered schema IDs
	// resolve. orgTeams is accepted for CLI compatibility and ignored.
	_ = orgTeams
	// Empty -plugins emits the core-only schema, mirroring the upstream
	// default (no plugins). Only unknown plugin names are fatal.
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	ids := strings.Split(raw, ",")
	plugins := make([]auth.Plugin, 0, len(ids))
	for _, id := range ids {
		switch strings.TrimSpace(id) {
		case "admin", "org":
			return nil, fmt.Errorf("unsupported plugin %q: built-in plugins are not available (registered: %s)", strings.TrimSpace(id), strings.Join(auth.RegisteredPluginSchemaIDs(), ", "))
		case "":
			continue
		default:
			clean := strings.TrimSpace(id)
			// Arbitrary plugin schemas (see auth.RegisterPluginSchema):
			// out-of-module plugins that only supply schemas are wrapped
			// as schema-only plugins so the full schema pipeline
			// (GetAuthTables, validation, DDL) sees their tables. This
			// mirrors upstream generate, which reads schemas from the
			// configured plugin objects.
			schema, err := auth.PluginSchemasForIDs([]string{clean})
			if err != nil {
				return nil, fmt.Errorf("unsupported plugin %q (registered: %s)", clean, strings.Join(auth.RegisteredPluginSchemaIDs(), ", "))
			}
			plugins = append(plugins, schemaOnlyPlugin{id: clean, schema: schema})
		}
	}
	return plugins, nil
}

// schemaOnlyPlugin adapts an arbitrary auth.PluginSchemaProvider to the
// auth.Plugin interface for schema generation. Endpoints/hooks/error codes
// are empty: generation only reads Schema().
type schemaOnlyPlugin struct {
	id     string
	schema auth.PluginSchema
}

func (p schemaOnlyPlugin) ID() string { return p.id }

func (p schemaOnlyPlugin) Init(auth.AuthContext) error { return nil }

func (p schemaOnlyPlugin) Endpoints() []auth.Endpoint { return nil }

func (p schemaOnlyPlugin) Schema() auth.PluginSchema { return p.schema }

func (p schemaOnlyPlugin) Hooks() auth.DBHooks { return nil }

func (p schemaOnlyPlugin) RouteHooks() auth.PluginRouteHooks { return auth.PluginRouteHooks{} }

func (p schemaOnlyPlugin) ErrorCodes() map[string]string { return nil }

func buildModels(prefix string, schema auth.PluginSchema, cfg auth.AdapterConfig) ([]modelDef, error) {
	core, err := coreModels(prefix, schema, cfg)
	if err != nil {
		return nil, err
	}
	modelMap := map[string]modelDef{}
	for _, model := range core {
		// Secondary-storage inclusion rules may drop core tables
		// (session/verification); only emit models present in the schema.
		if _, ok := schema[model.Name]; !ok {
			continue
		}
		modelMap[model.Name] = model
	}

	// Index metadata (declared table indexes plus field-level index/unique
	// flags), resolved to physical columns via cfg.
	resolvedIndexes := auth.ResolveSchemaIndexes(schema, cfg)

	modelNames := mapsKeys(schema)
	sort.Strings(modelNames)
	for _, name := range modelNames {
		table := schema[name]
		// Tables with migration disabled are skipped (presence-safe
		// DisableMigrationsEffective: explicit *bool wins, legacy bool
		// OR-accumulates). main.go performs no merge of its own:
		// merging lives in auth.MergeSchemas; by the time the schema
		// reaches buildModels the flag is already resolved.
		if table.DisableMigrationsEffective() {
			continue
		}
		model, ok := modelMap[name]
		if !ok {
			idCol := auth.PhysicalColumnName(name, table, "id", cfg)
			model = modelDef{
				Name:       name,
				StructName: prefix + camel(name),
				TableName:  auth.PhysicalTableName(name, table, cfg),
				Fields: []fieldDef{
					{
						GoName:     "ID",
						ColumnName: idCol,
						GoType:     "string",
						TagParts:   []string{idCol, "pk"},
					},
				},
			}
		} else {
			model.TableName = auth.PhysicalTableName(name, table, cfg)
		}

		fieldNames := mapsKeys(table.Fields)
		sort.Strings(fieldNames)
		for _, fieldName := range fieldNames {
			// Core fields are already emitted by coreModels; option
			// additionalFields and plugin fields are appended.
			if isCoreField(name, fieldName) {
				continue
			}
			field, err := fieldFromSchema(name, table, fieldName, cfg)
			if err != nil {
				return nil, err
			}
			model.Fields = append(model.Fields, field)
			attr := table.Fields[fieldName]
			if attr.References != nil {
				ref := attr.References
				rel := relDef{
					GoName:   relGoName(fieldName),
					GoType:   "*" + prefix + camel(ref.Model),
					JoinFrom: auth.PhysicalColumnName(name, table, fieldName, cfg),
					JoinTo:   refColumn(schema, ref.Model, ref.Field, cfg),
				}
				model.Relations = append(model.Relations, rel)
				model.Dependencies = append(model.Dependencies, ref.Model)
			}
		}
		modelMap[name] = model
	}

	for table, indexes := range resolvedIndexes {
		for name, model := range modelMap {
			if model.TableName == table {
				model.Indexes = indexes
				modelMap[name] = model
			}
		}
	}

	models := make([]modelDef, 0, len(modelMap))
	for _, name := range orderedModelNames(modelMap) {
		models = append(models, modelMap[name])
	}
	return models, nil
}

// refColumn resolves the physical column of a referenced field, honoring a
// declared field name on the referenced table when the schema knows it.
func refColumn(schema auth.PluginSchema, model, field string, cfg auth.AdapterConfig) string {
	if table, ok := schema[model]; ok {
		return auth.PhysicalColumnName(model, table, field, cfg)
	}
	return auth.ResolveColumnName(model, field, cfg)
}

// isCoreField reports whether the logical field is part of the canonical
// core table definition (already emitted by coreModels).
func isCoreField(model, field string) bool {
	core := auth.CoreSchema()
	tbl, ok := core[model]
	if !ok {
		return false
	}
	_, ok = tbl.Fields[field]
	return ok
}

func renderModels(pkg, migrateFunc string, models []modelDef) string {
	indexesFuncName := migrateFunc + "Indexes"
	indexStructName := migrateFunc + "Index"

	var b strings.Builder
	b.WriteString("// Code generated by auth/cmd/generate-schema. DO NOT EDIT.\n\n")
	b.WriteString("package " + pkg + "\n\n")
	b.WriteString("import (\n")
	b.WriteString("\t\"time\"\n\n")
	b.WriteString("\t\"github.com/uptrace/bun\"\n")
	b.WriteString(")\n\n")
	b.WriteString("// " + migrateFunc + " returns all auth table models for migration.\n")
	b.WriteString("func " + migrateFunc + "() []any {\n")
	b.WriteString("\treturn []any{\n")
	for _, model := range models {
		b.WriteString(fmt.Sprintf("\t\t(*%s)(nil),\n", model.StructName))
	}
	b.WriteString("\t}\n")
	b.WriteString("}\n\n")
	b.WriteString("// " + indexStructName + " describes one plain (non-unique) database index\n")
	b.WriteString("// in physical table/column names.\n")
	b.WriteString("type " + indexStructName + " struct {\n")
	b.WriteString("\tTable string\n")
	b.WriteString("\tName string\n")
	b.WriteString("\tColumns []string\n")
	b.WriteString("\tUnique bool\n")
	b.WriteString("}\n\n")
	b.WriteString("// " + indexesFuncName + " returns every resolved non-unique index spec for the\n")
	b.WriteString("// models above, in physical table/column names.\n")
	b.WriteString("//\n")
	b.WriteString("// Bun's NewCreateTable does not create plain indexes or foreign keys from\n")
	b.WriteString("// bare model structs: apply these specs with db.NewCreateIndex() after\n")
	b.WriteString("// creating the tables. Single-column unique constraints are already\n")
	b.WriteString("// enforced via `unique` struct tags and need no separate index call.\n")
	b.WriteString("func " + indexesFuncName + "() []" + indexStructName + " {\n")
	indexes := collectPlainIndexes(models)
	if len(indexes) == 0 {
		b.WriteString("\treturn nil\n")
	} else {
		b.WriteString("\treturn []" + indexStructName + "{\n")
		for _, idx := range indexes {
			cols := make([]string, 0, len(idx.Columns))
			for _, c := range idx.Columns {
				cols = append(cols, fmt.Sprintf("%q", c))
			}
			b.WriteString(fmt.Sprintf("\t\t{Table: %q, Name: %q, Columns: []string{%s}},\n", idx.Table, idx.Name, strings.Join(cols, ", ")))
		}
		b.WriteString("\t}\n")
	}
	b.WriteString("}\n\n")
	for _, model := range models {
		if len(model.Indexes) > 0 {
			for _, idx := range model.Indexes {
				unique := ""
				if idx.Unique {
					unique = " UNIQUE"
				}
				b.WriteString(fmt.Sprintf("// Index %s ON %s(%s)%s.\n", idx.Name, model.TableName, strings.Join(idx.Columns, ", "), unique))
			}
		}
		b.WriteString(fmt.Sprintf("type %s struct {\n", model.StructName))
		b.WriteString(fmt.Sprintf("\tbun.BaseModel `bun:\"table:%s\"`\n", model.TableName))
		for _, field := range dedupeFields(model.Fields) {
			b.WriteString(fmt.Sprintf("\t%s %s `bun:\"%s\"`\n", field.GoName, field.GoType, strings.Join(field.TagParts, ",")))
		}
		if len(model.Relations) > 0 {
			b.WriteString("\n")
			rels := make([]relDef, len(model.Relations))
			copy(rels, model.Relations)
			sort.Slice(rels, func(i, j int) bool { return rels[i].GoName < rels[j].GoName })
			for _, rel := range rels {
				tag := fmt.Sprintf("rel:belongs-to,join:%s=%s", rel.JoinFrom, rel.JoinTo)
				b.WriteString(fmt.Sprintf("\t%s %s `bun:\"%s\"`\n", rel.GoName, rel.GoType, tag))
			}
		}
		b.WriteString("}\n\n")
	}
	return b.String()
}

// plainIndex is a non-unique resolved index with its physical table name.
type plainIndex struct {
	Table   string
	Name    string
	Columns []string
}

// collectPlainIndexes gathers every resolved non-unique index across models
// for the generated <MigrateFunc>Indexes helper. Unique indexes are omitted
// because NewCreateTable already enforces them via `unique` struct tags.
func collectPlainIndexes(models []modelDef) []plainIndex {
	var out []plainIndex
	for _, model := range models {
		for _, idx := range model.Indexes {
			if idx.Unique {
				continue
			}
			cols := append([]string(nil), idx.Columns...)
			out = append(out, plainIndex{Table: model.TableName, Name: idx.Name, Columns: cols})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Table != out[j].Table {
			return out[i].Table < out[j].Table
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func dedupeFields(fields []fieldDef) []fieldDef {
	// Last wins per column, preserving first-seen order.
	order := []string{}
	last := map[string]fieldDef{}
	for _, f := range fields {
		if _, ok := last[f.ColumnName]; !ok {
			order = append(order, f.ColumnName)
		}
		last[f.ColumnName] = f
	}
	out := make([]fieldDef, 0, len(order))
	for _, col := range order {
		out = append(out, last[col])
	}
	return out
}

func coreModels(prefix string, schema auth.PluginSchema, cfg auth.AdapterConfig) ([]modelDef, error) {
	// Canonical logical field order per core model (ID is synthetic).
	orders := map[string][]string{
		"user":         {"name", "email", "emailVerified", "image", "createdAt", "updatedAt"},
		"session":      {"userId", "token", "expiresAt", "ipAddress", "userAgent", "createdAt", "updatedAt"},
		"account":      {"userId", "providerId", "accountId", "accessToken", "refreshToken", "idToken", "accessTokenExpiresAt", "refreshTokenExpiresAt", "scope", "password", "createdAt", "updatedAt"},
		"verification": {"identifier", "value", "expiresAt", "createdAt", "updatedAt"},
	}
	build := func(model string) (modelDef, bool, error) {
		table, ok := schema[model]
		if !ok {
			// Secondary-storage inclusion rules may drop core tables
			// (session/verification); buildModels discards absent core
			// models, so skip field expansion here instead of failing on
			// the zero-value table's missing field types.
			return modelDef{Name: model}, false, nil
		}
		idCol := auth.PhysicalColumnName(model, table, "id", cfg)
		def := modelDef{
			Name:       model,
			StructName: prefix + camel(model),
			TableName:  auth.PhysicalTableName(model, table, cfg),
			Fields: []fieldDef{
				{GoName: "ID", ColumnName: idCol, GoType: "string", TagParts: []string{idCol, "pk"}},
			},
		}
		for _, logical := range orders[model] {
			field, err := fieldFromSchema(model, table, logical, cfg)
			if err != nil {
				return modelDef{}, false, err
			}
			def.Fields = append(def.Fields, field)
		}
		return def, true, nil
	}
	out := make([]modelDef, 0, 4)
	user, ok, err := build("user")
	if err != nil {
		return nil, err
	}
	if ok {
		out = append(out, user)
	}
	session, ok, err := build("session")
	if err != nil {
		return nil, err
	}
	if ok {
		session.Relations = []relDef{
			{GoName: "User", GoType: "*" + prefix + "User", JoinFrom: auth.PhysicalColumnName("session", schema["session"], "userId", cfg), JoinTo: refColumn(schema, "user", "id", cfg)},
		}
		out = append(out, session)
	}
	account, ok, err := build("account")
	if err != nil {
		return nil, err
	}
	if ok {
		account.Relations = []relDef{
			{GoName: "User", GoType: "*" + prefix + "User", JoinFrom: auth.PhysicalColumnName("account", schema["account"], "userId", cfg), JoinTo: refColumn(schema, "user", "id", cfg)},
		}
		out = append(out, account)
	}
	verification, ok, err := build("verification")
	if err != nil {
		return nil, err
	}
	if ok {
		out = append(out, verification)
	}
	return out, nil
}

func fieldFromSchema(model string, table auth.TableSchema, name string, cfg auth.AdapterConfig) (fieldDef, error) {
	attr := table.Fields[name]
	column := auth.PhysicalColumnName(model, table, name, cfg)
	tagParts := []string{column}
	if attr.Unique {
		tagParts = append(tagParts, "unique")
	}
	if attr.Required == nil || *attr.Required {
		tagParts = append(tagParts, "notnull")
	}
	// Static scalar defaults render inline; func factories (timestamp
	// defaults like DateNowDefault) have no static tag rendering and are
	// carried as metadata for dialect DDL (see BuildMigrationPlan) instead
	// of emitting garbage tags.
	if attr.DefaultValue != nil && !auth.HasFuncDefault(attr) {
		tagParts = append(tagParts, "default:"+defaultTagValue(attr.DefaultValue))
	}
	if attr.Type == auth.FieldTypeJSON {
		// Postgres/bun-only: other dialects store JSON differently
		// (e.g. TEXT on SQLite, json on MySQL/MSSQL per get-migration.ts).
		tagParts = append(tagParts, "type:jsonb")
	}
	goType, err := goTypeForField(model, name, attr)
	if err != nil {
		return fieldDef{}, err
	}
	return fieldDef{
		GoName:     goFieldName(name),
		ColumnName: column,
		GoType:     goType,
		TagParts:   tagParts,
	}, nil
}

func goTypeForField(model, field string, attr auth.FieldAttribute) (string, error) {
	required := attr.Required == nil || *attr.Required
	switch attr.Type {
	case auth.FieldTypeBoolean:
		if required {
			return "bool", nil
		}
		return "*bool", nil
	case auth.FieldTypeDate:
		if required {
			return "time.Time", nil
		}
		return "*time.Time", nil
	case auth.FieldTypeNumber:
		if required {
			return "int64", nil
		}
		return "*int64", nil
	case auth.FieldTypeJSON:
		return "map[string]any", nil
	case auth.FieldTypeString:
		if required {
			return "string", nil
		}
		return "*string", nil
	case "":
		return "", fmt.Errorf("unsupported field type for %s.%s: missing type (want one of string, number, boolean, date, json)", model, field)
	default:
		// Upstream DBFieldType also admits string[]/number[] (and custom
		// array literals) which have no bun-struct representation; reject
		// them explicitly instead of silently emitting string.
		if strings.HasSuffix(string(attr.Type), "[]") {
			return "", fmt.Errorf("unsupported field type for %s.%s: array type %q has no bun-struct representation", model, field, string(attr.Type))
		}
		return "", fmt.Errorf("unsupported field type for %s.%s: %q (want one of string, number, boolean, date, json)", model, field, string(attr.Type))
	}
}

// orderedModelNames returns model names with core models first (in declaration
// order) followed by plugin models in topological dependency order.
func orderedModelNames(models map[string]modelDef) []string {
	coreOrder := []string{"user", "session", "account", "verification"}
	seen := map[string]bool{}
	names := make([]string, 0, len(models))
	for _, name := range coreOrder {
		if _, ok := models[name]; ok {
			names = append(names, name)
			seen[name] = true
		}
	}
	pluginNames := make([]string, 0)
	for name := range models {
		if !seen[name] {
			pluginNames = append(pluginNames, name)
		}
	}
	sort.Strings(pluginNames)
	return append(names, pluginTopoOrder(pluginNames, models)...)
}

// pluginTopoOrder sorts plugin model names so that a model is emitted only
// after all plugin models it depends on. Core model dependencies are ignored
// since core models are always emitted first.
func pluginTopoOrder(pluginNames []string, models map[string]modelDef) []string {
	pluginSet := map[string]bool{}
	for _, name := range pluginNames {
		pluginSet[name] = true
	}

	inDegree := map[string]int{}
	dependents := map[string][]string{} // X → models that depend on X
	for _, name := range pluginNames {
		inDegree[name] = 0
	}
	for _, name := range pluginNames {
		for _, dep := range models[name].Dependencies {
			if !pluginSet[dep] {
				continue
			}
			inDegree[name]++
			dependents[dep] = append(dependents[dep], name)
		}
	}

	queue := make([]string, 0)
	for _, name := range pluginNames {
		if inDegree[name] == 0 {
			queue = append(queue, name)
		}
	}
	sort.Strings(queue)

	result := make([]string, 0, len(pluginNames))
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		result = append(result, node)
		next := dependents[node]
		sort.Strings(next)
		for _, dep := range next {
			inDegree[dep]--
			if inDegree[dep] == 0 {
				queue = append(queue, dep)
				sort.Strings(queue)
			}
		}
	}
	return result
}

// relGoName derives the relation field name from a foreign key field name.
// "organizationId" → "Organization", "inviterId" → "Inviter", "userId" → "User".
func relGoName(fieldName string) string {
	name := fieldName
	if strings.HasSuffix(name, "Id") {
		name = name[:len(name)-2]
	} else if strings.HasSuffix(name, "ID") {
		name = name[:len(name)-2]
	}
	return goFieldName(name)
}

// goFieldName maps a logical field name to its exported Go struct field name,
// aligning with adapters/bun/models.go (UserID, IPAddress, IDToken style):
// word segments split on _/- plus camelCase boundaries, common initialisms
// (ID, IP, URL, HTTP, API, UUID, etc.) upper-cased, other words title-cased.
func goFieldName(logical string) string {
	words := splitFieldWords(logical)
	if len(words) == 0 {
		return ""
	}
	var b strings.Builder
	for _, w := range words {
		lower := strings.ToLower(w)
		if isGoInitialism(lower) {
			b.WriteString(strings.ToUpper(lower))
			continue
		}
		b.WriteString(strings.ToUpper(lower[:1]) + lower[1:])
	}
	return b.String()
}

func splitFieldWords(s string) []string {
	var words []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			words = append(words, cur.String())
			cur.Reset()
		}
	}
	runes := []rune(s)
	for i, r := range runes {
		if r == '_' || r == '-' {
			flush()
			continue
		}
		if i > 0 && r >= 'A' && r <= 'Z' && runes[i-1] >= 'a' && runes[i-1] <= 'z' {
			flush()
		}
		cur.WriteRune(r)
	}
	flush()
	return words
}

func isGoInitialism(lower string) bool {
	switch lower {
	case "id", "ip", "url", "uri", "http", "https", "api", "uuid", "oauth", "jwt", "json", "db", "ui":
		return true
	}
	return false
}

func camel(value string) string {
	var out strings.Builder
	upperNext := true
	for _, r := range value {
		if r == '_' || r == '-' {
			upperNext = true
			continue
		}
		if upperNext && r >= 'a' && r <= 'z' {
			out.WriteRune(r - ('a' - 'A'))
			upperNext = false
			continue
		}
		upperNext = false
		out.WriteRune(r)
	}
	return out.String()
}

func defaultTagValue(value any) string {
	switch v := value.(type) {
	case string:
		return "'" + strings.ReplaceAll(v, "'", "''") + "'"
	case bool:
		if v {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprint(v)
	}
}

func mapsKeys[K comparable, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}

// Dialect selects the SQL flavor for migration DDL, mirroring the
// KyselyDatabaseType branches in upstream get-migration.ts
// (postgres/mysql/sqlite/mssql).
type Dialect string

const (
	DialectSQLite   Dialect = "sqlite"
	DialectPostgres Dialect = "postgres"
	DialectMySQL    Dialect = "mysql"
	DialectMSSQL    Dialect = "mssql"
)

// parseDialect validates the -dialect flag. "postgresql" is accepted as an
// alias of "postgres" (matching the CLI --dialect vocabulary).
func parseDialect(raw string) (Dialect, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "sqlite":
		return DialectSQLite, nil
	case "postgres", "postgresql":
		return DialectPostgres, nil
	case "mysql":
		return DialectMySQL, nil
	case "mssql", "sqlserver":
		return DialectMSSQL, nil
	default:
		return "", fmt.Errorf("invalid -dialect %q: want one of sqlite, postgres, mysql, mssql", raw)
	}
}

// validateIDType validates the -id-type flag, mirroring upstream
// advanced.database.generateId ("uuid" / "serial" / default string ids).
func validateIDType(raw string) error {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "string", "uuid", "serial":
		return nil
	default:
		return fmt.Errorf("invalid -id-type %q: want one of string, uuid, serial", raw)
	}
}

// quoteIdent quotes a table/column identifier per dialect (double quotes for
// sqlite/postgres, backticks for mysql, brackets for mssql).
func quoteIdent(d Dialect, name string) string {
	switch d {
	case DialectMySQL:
		return "`" + strings.ReplaceAll(name, "`", "``") + "`"
	case DialectMSSQL:
		return "[" + strings.ReplaceAll(name, "]", "]]") + "]"
	default:
		return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
	}
}

// ddlColumnType maps one field to its DDL column type, mirroring the getType
// branches in upstream get-migration.ts. idKind selects the id flavor
// (-id-type: string/uuid/serial); isID marks the synthetic id column and
// isFK marks foreign-key columns (references to id). indexLen carries the
// mysql/mssql bounded string length when the column is indexed, nil for
// unbounded text.
func ddlColumnType(d Dialect, attr auth.FieldAttribute, isID, isFK bool, indexLen *int, idKind string) string {
	serial := strings.EqualFold(idKind, "serial")
	uuid := strings.EqualFold(idKind, "uuid")
	if isID {
		switch d {
		case DialectPostgres:
			if serial {
				return "integer GENERATED BY DEFAULT AS IDENTITY"
			}
			if uuid {
				return "uuid"
			}
			return "text"
		case DialectMySQL:
			if serial {
				return "integer"
			}
			return "varchar(36)"
		case DialectMSSQL:
			if serial {
				return "integer"
			}
			return "varchar(36)"
		default:
			if serial {
				return "integer"
			}
			return "text"
		}
	}
	if isFK {
		switch d {
		case DialectPostgres:
			if serial {
				return "integer"
			}
			if uuid {
				return "uuid"
			}
			return "text"
		case DialectMySQL, DialectMSSQL:
			return "varchar(36)"
		default:
			if serial {
				return "integer"
			}
			return "text"
		}
	}
	switch attr.Type {
	case auth.FieldTypeBoolean:
		switch d {
		case DialectPostgres, DialectMySQL:
			return "boolean"
		case DialectMSSQL:
			return "smallint"
		default:
			return "integer"
		}
	case auth.FieldTypeNumber:
		if attr.BigInt {
			return "bigint"
		}
		return "integer"
	case auth.FieldTypeDate:
		switch d {
		case DialectPostgres:
			return "timestamptz"
		case DialectMySQL:
			return "timestamp(3)"
		case DialectMSSQL:
			return "datetime2(3)"
		default:
			return "date"
		}
	case auth.FieldTypeJSON:
		switch d {
		case DialectPostgres:
			return "jsonb"
		case DialectMySQL:
			return "json"
		case DialectMSSQL:
			return "varchar(8000)"
		default:
			return "text"
		}
	default: // strings (arrays are rejected by buildModels before DDL)
		switch d {
		case DialectPostgres:
			return "text"
		case DialectMySQL:
			if indexLen != nil {
				return fmt.Sprintf("varchar(%d)", *indexLen)
			}
			if attr.Unique || attr.Sortable || attr.Index || attr.References != nil {
				return "varchar(255)"
			}
			return "text"
		case DialectMSSQL:
			if indexLen != nil {
				return fmt.Sprintf("varchar(%d)", *indexLen)
			}
			if attr.Unique || attr.Sortable {
				return "varchar(255)"
			}
			if attr.References != nil {
				return "varchar(36)"
			}
			return "varchar(8000)"
		default:
			return "text"
		}
	}
}

// ddlDefault renders the inline DEFAULT clause for static and timestamp
// defaults, mirroring the create/alter paths in get-migration.ts. Func
// timestamp defaults become CURRENT_TIMESTAMP on postgres/mysql/mssql and
// no clause on sqlite; static booleans map to 1/0 where the dialect lacks
// a native boolean. It returns "" when the field carries no DDL default.
func ddlDefault(d Dialect, attr auth.FieldAttribute) string {
	if auth.HasTimestampColumnDefault(attr) {
		switch d {
		case DialectMySQL:
			return " DEFAULT CURRENT_TIMESTAMP(3)"
		case DialectPostgres, DialectMSSQL:
			return " DEFAULT CURRENT_TIMESTAMP"
		default:
			return ""
		}
	}
	if !auth.HasStaticColumnDefault(attr) {
		return ""
	}
	switch v := attr.DefaultValue.(type) {
	case bool:
		if v {
			if d == DialectSQLite || d == DialectMSSQL {
				return " DEFAULT 1"
			}
			return " DEFAULT true"
		}
		if d == DialectSQLite || d == DialectMSSQL {
			return " DEFAULT 0"
		}
		return " DEFAULT false"
	case string:
		return " DEFAULT '" + strings.ReplaceAll(v, "'", "''") + "'"
	default:
		return fmt.Sprintf(" DEFAULT %v", v)
	}
}

// indexStringLength ports upstream getDatabaseIndexStringLength for the
// byte-limited dialects (mysql 3072-byte budget, mssql 1700-byte budget):
// it returns the safe generated varchar length for column across the
// table's resolved indexes, or nil when the column needs no bound (or the
// dialect is not byte-limited). columns maps physical column names to field
// attributes.
func indexStringLength(d Dialect, columns map[string]auth.FieldAttribute, indexes []auth.ResolvedDBTableIndex, column string) *int {
	if d != DialectMySQL && d != DialectMSSQL {
		return nil
	}
	containing := make([]auth.ResolvedDBTableIndex, 0)
	for _, index := range indexes {
		for _, c := range index.Columns {
			if c == column {
				containing = append(containing, index)
				break
			}
		}
	}
	if len(containing) == 0 {
		return nil
	}
	var byteBudget, bytesPerChar, defaultLength int
	if d == DialectMySQL {
		byteBudget, bytesPerChar, defaultLength = 3072, 4, 191
	} else {
		byteBudget, bytesPerChar, defaultLength = 1700, 1, 255
	}
	length := defaultLength
	for _, index := range containing {
		stringCols := 0
		for _, c := range index.Columns {
			if attr, ok := columns[c]; ok && attr.Type == auth.FieldTypeString {
				stringCols++
			}
		}
		if stringCols == 0 {
			continue
		}
		nonStringBytes := (len(index.Columns) - stringCols) * 16
		budget := byteBudget - nonStringBytes
		if budget < 1 {
			budget = 1
		}
		safe := budget / bytesPerChar / stringCols
		if safe < length {
			length = safe
		}
	}
	if length < 1 {
		length = 1
	}
	return &length
}

// plannedColumn is one ordered DDL column definition.
type plannedColumn struct {
	Name       string
	Definition string
}

// plannedTable is one ordered CREATE TABLE unit.
type plannedTable struct {
	Name    string
	Columns []plannedColumn
}

// plannedIndex is one deferred CREATE INDEX unit (deferred so referenced
// tables/columns always exist first, like upstream deferredIndexes).
type plannedIndex struct {
	Table   string
	Name    string
	Columns []string
	Unique  bool
	// Where holds an optional index predicate (e.g. MSSQL NULL-filtered
	// unique indexes on nullable columns in the ALTER path, mirroring
	// upstream `.where(fieldName, "is not", null)`).
	Where string
}

// MigrationPlan is the safe, ordered migration for a schema: CREATE TABLEs
// in dependency order (core first, then plugin topological order via the
// shared model ordering), ALTER TABLE ADD COLUMN units for incremental
// diffs (see DiffMigrationPlan; empty for fresh-install plans), FK/cascade
// references inline, plain and multi-column unique indexes deferred last.
// UnsafeChanges carries fresh-install advisories in the upstream generate
// spirit (kysely unsafeChanges); Script renders statements joined like
// compileMigrations (";\n\n" + ";").
type MigrationPlan struct {
	Dialect       Dialect
	Tables        []plannedTable
	Alters        []plannedAlter
	Indexes       []plannedIndex
	UnsafeChanges []string
}

// plannedAlter is one ALTER TABLE ADD COLUMN unit for incremental diffs
// (see DiffMigrationPlan). SQLite cannot add a column with an inline
// UNIQUE constraint, so unique fields are enforced with a separate
// deferred index, mirroring the upstream ALTER path.
type plannedAlter struct {
	Table      string
	Column     string
	Definition string
}

// Script renders the plan as executable SQL, mirroring the
// compileMigrations join.
func (p *MigrationPlan) Script() string {
	stmts := make([]string, 0, len(p.Tables)+len(p.Alters)+len(p.Indexes))
	for _, table := range p.Tables {
		cols := make([]string, 0, len(table.Columns))
		for _, col := range table.Columns {
			cols = append(cols, "\t"+quoteIdent(p.Dialect, col.Name)+" "+col.Definition)
		}
		stmts = append(stmts, fmt.Sprintf("create table %s (\n%s\n);", quoteIdent(p.Dialect, table.Name), strings.Join(cols, ",\n")))
	}
	for _, alter := range p.Alters {
		stmts = append(stmts, fmt.Sprintf("alter table %s add column %s %s;", quoteIdent(p.Dialect, alter.Table), quoteIdent(p.Dialect, alter.Column), alter.Definition))
	}
	for _, index := range p.Indexes {
		cols := make([]string, 0, len(index.Columns))
		for _, c := range index.Columns {
			cols = append(cols, quoteIdent(p.Dialect, c))
		}
		unique := ""
		if index.Unique {
			unique = "unique "
		}
		where := ""
		if index.Where != "" {
			where = " " + index.Where
		}
		stmts = append(stmts, fmt.Sprintf("create %sindex %s on %s (%s)%s;", unique, quoteIdent(p.Dialect, index.Name), quoteIdent(p.Dialect, index.Table), strings.Join(cols, ", "), where))
	}
	return strings.Join(stmts, "\n\n") + "\n"
}

// unsafeBanner prefixes generated SQL with the upstream generate-style
// DO-NOT-RUN warning (see generateKyselySchema commentBanner) when the plan
// carries unsafe changes.
func unsafeBanner(unsafeChanges []string) string {
	rule := "-- " + strings.Repeat("-", 77)
	lines := []string{
		rule,
		"-- DO NOT RUN THIS SCRIPT AS IT IS.",
		"-- Applying it to a populated database corrupts the rows it touches:",
	}
	for _, change := range unsafeChanges {
		lines = append(lines, "--", "-- "+change)
	}
	lines = append(lines, rule, "")
	return strings.Join(lines, "\n")
}

// BuildMigrationPlan validates the schema indexes and builds the ordered,
// dialect-specific migration plan: executable CREATE TABLEs with PK, NOT NULL,
// UNIQUE, timestamp/static defaults, and FK/cascade references, plus
// deferred CREATE INDEX units for plain and multi-column unique indexes
// (single-column unique fields ride inline like upstream col.unique()).
// idKind selects the id flavor ("string", "uuid", "serial").
//
// Upstream references: getMigrations/getSchema/getType (get-migration.ts),
// resolveDatabaseSchemaIndexes (database-index.ts).
func BuildMigrationPlan(schema auth.PluginSchema, cfg auth.AdapterConfig, dialect Dialect, idKind string) (*MigrationPlan, error) {
	if err := auth.ValidateSchemaIndexes(schema, cfg); err != nil {
		return nil, err
	}
	resolvedIndexes := auth.ResolveSchemaIndexes(schema, cfg)

	ordered := orderSchemaNames(schema)

	plan := &MigrationPlan{Dialect: dialect}
	for _, name := range ordered {
		table := schema[name]
		if table.DisableMigrationsEffective() {
			continue
		}
		pt, advisories := buildCreateTable(name, table, schema, cfg, dialect, idKind, resolvedIndexes)
		plan.Tables = append(plan.Tables, pt)
		plan.UnsafeChanges = append(plan.UnsafeChanges, advisories...)

		tableName := auth.PhysicalTableName(name, table, cfg)
		for _, index := range resolvedIndexes[tableName] {
			if index.Unique && len(index.Columns) == 1 {
				continue // inline UNIQUE above
			}
			plan.Indexes = append(plan.Indexes, plannedIndex{
				Table:   tableName,
				Name:    index.Name,
				Columns: append([]string(nil), index.Columns...),
				Unique:  index.Unique,
			})
		}
	}
	sort.Slice(plan.Indexes, func(i, j int) bool {
		if plan.Indexes[i].Table != plan.Indexes[j].Table {
			return plan.Indexes[i].Table < plan.Indexes[j].Table
		}
		return plan.Indexes[i].Name < plan.Indexes[j].Name
	})
	return plan, nil
}

// orderSchemaNames orders logical model names core-first then in plugin
// dependency order (FK targets before dependents), mirroring
// orderedModelNames. Referenced tables are always created before the
// tables that reference them; indexes are deferred to Script() so they
// execute after every table exists.
func orderSchemaNames(schema auth.PluginSchema) []string {
	names := mapsKeys(schema)
	sort.Strings(names)
	order := map[string]int{"user": 0, "session": 1, "account": 2, "verification": 3}
	rest := make([]string, 0)
	for _, name := range names {
		if _, ok := order[name]; !ok {
			rest = append(rest, name)
		}
	}
	sort.Strings(rest)
	ordered := make([]string, 0, len(names))
	for _, core := range []string{"user", "session", "account", "verification"} {
		if _, ok := schema[core]; ok {
			ordered = append(ordered, core)
		}
	}
	return append(ordered, pluginTopoNames(rest, schema)...)
}

// buildCreateTable builds one ordered CREATE TABLE unit with PK, NOT NULL,
// UNIQUE (single-column unique fields ride inline like upstream
// col.unique()), timestamp/static defaults, and FK/cascade references.
// resolved carries the schema-wide resolved indexes for UNIQUE and
// index-length lookups. It returns advisories for required unique static
// defaults (upstream ALTER-path warning applied to fresh installs: the
// shared backfill cannot satisfy the unique index on multi-row tables).
func buildCreateTable(name string, table auth.TableSchema, schema auth.PluginSchema, cfg auth.AdapterConfig, dialect Dialect, idKind string, resolvedIndexes map[string][]auth.ResolvedDBTableIndex) (plannedTable, []string) {
	tableName := auth.PhysicalTableName(name, table, cfg)
	// Columns by physical name for index-length lookup.
	byColumn := map[string]auth.FieldAttribute{}
	for logical, attr := range table.Fields {
		byColumn[auth.PhysicalColumnName(name, table, logical, cfg)] = attr
	}
	resolved := resolvedIndexes[tableName]
	idCol := auth.PhysicalColumnName(name, table, "id", cfg)
	pt := plannedTable{Name: tableName}
	idDef := ddlColumnType(dialect, auth.FieldAttribute{}, true, false, nil, idKind)
	if strings.EqualFold(idKind, "serial") && dialect == DialectMSSQL {
		idDef += " IDENTITY(1,1)"
	}
	pt.Columns = append(pt.Columns, plannedColumn{Name: idCol, Definition: idDef + " PRIMARY KEY NOT NULL"})

	var advisories []string
	fieldNames := mapsKeys(table.Fields)
	sort.Strings(fieldNames)
	for _, logical := range fieldNames {
		attr := table.Fields[logical]
		column := auth.PhysicalColumnName(name, table, logical, cfg)
		if column == idCol {
			continue
		}
		isFK := attr.References != nil
		var bound *int
		if attr.Type == auth.FieldTypeString {
			bound = indexStringLength(dialect, byColumn, resolved, column)
		}
		def := ddlColumnType(dialect, attr, false, isFK, bound, idKind)
		if attr.Required == nil || *attr.Required {
			def += " NOT NULL"
		}
		if attr.Unique && isSingleColumnUnique(resolved, column) {
			def += " UNIQUE"
		}
		def += ddlDefault(dialect, attr)
		if isFK {
			ref := attr.References
			refTable := ref.Model
			refCol := ref.Field
			if rt, ok := schema[ref.Model]; ok {
				refTable = auth.PhysicalTableName(ref.Model, rt, cfg)
				refCol = auth.PhysicalColumnName(ref.Model, rt, ref.Field, cfg)
			}
			action := ref.OnDelete
			if action == "" {
				action = "cascade"
			}
			def += fmt.Sprintf(" REFERENCES %s (%s) ON DELETE %s", quoteIdent(dialect, refTable), quoteIdent(dialect, refCol), strings.ToUpper(action))
		}
		pt.Columns = append(pt.Columns, plannedColumn{Name: column, Definition: def})
		// Fresh-install advisory mirroring the upstream ALTER-path
		// warning: a required unique static default backfills every
		// existing row with one value, failing the unique index.
		if attr.Unique && auth.HasStaticColumnDefault(attr) {
			advisories = append(advisories,
				fmt.Sprintf("Required unique column %q on table %q declares a static default: every existing row backfills the same value, so creating its unique index fails on tables with more than one row. Backfill distinct values instead.", column, tableName))
		}
	}
	return pt, advisories
}

// isSingleColumnUnique reports whether column's uniqueness is enforced by a
// single-column unique resolved index (those ride inline in CREATE TABLE).
func isSingleColumnUnique(resolved []auth.ResolvedDBTableIndex, column string) bool {
	for _, index := range resolved {
		if index.Unique && len(index.Columns) == 1 && index.Columns[0] == column {
			return true
		}
	}
	return false
}

// pluginTopoNames orders plugin model names so referenced plugin tables are
// created first (Kahn's algorithm over References edges; core-table targets
// are ignored since core tables are always emitted first). Cycles fall back
// to sorted order for the remainder.
func pluginTopoNames(pluginNames []string, schema auth.PluginSchema) []string {
	set := map[string]bool{}
	for _, name := range pluginNames {
		set[name] = true
	}
	inDegree := map[string]int{}
	dependents := map[string][]string{}
	for _, name := range pluginNames {
		inDegree[name] = 0
	}
	for _, name := range pluginNames {
		seen := map[string]bool{}
		for _, attr := range schema[name].Fields {
			if attr.References == nil || !set[attr.References.Model] || seen[attr.References.Model] {
				continue
			}
			seen[attr.References.Model] = true
			inDegree[name]++
			dependents[attr.References.Model] = append(dependents[attr.References.Model], name)
		}
	}
	queue := make([]string, 0)
	for _, name := range pluginNames {
		if inDegree[name] == 0 {
			queue = append(queue, name)
		}
	}
	sort.Strings(queue)
	out := make([]string, 0, len(pluginNames))
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		out = append(out, node)
		next := dependents[node]
		sort.Strings(next)
		for _, dep := range next {
			inDegree[dep]--
			if inDegree[dep] == 0 {
				queue = append(queue, dep)
				sort.Strings(queue)
			}
		}
	}
	if len(out) != len(pluginNames) {
		// Cycle: emit the remainder in sorted order for determinism.
		emitted := map[string]bool{}
		for _, name := range out {
			emitted[name] = true
		}
		for _, name := range pluginNames {
			if !emitted[name] {
				out = append(out, name)
			}
		}
	}
	return out
}
