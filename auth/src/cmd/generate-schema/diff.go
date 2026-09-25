package main

// Current-vs-desired migration diffing.
//
// BuildMigrationPlan (main.go) emits the fresh-install plan: CREATE TABLEs
// plus deferred indexes. This file plans the incremental path that upstream
// getMigrations takes against a live database: tables absent from current
// are created, columns absent from current are added with ALTER TABLE ADD
// COLUMN, and indexes absent from current are created last. Adding a
// required column with no default to a populated table is refused as an
// unsafe change (data, or an error with ThrowOnUnsafe), mirroring the
// upstream UnsafeMigrationError guard.

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	auth "github.com/brick-org/brick/auth/src"
)

// DiffMigrationPlan diffs current against desired without a live database
// and builds the ordered, dialect-specific migration plan: CREATE TABLEs
// for missing tables (dependency-ordered via orderSchemaNames, FK targets
// first), ALTER TABLE ADD COLUMN units for missing columns on existing
// tables, and deferred CREATE INDEX units for missing indexes. Tables
// execute before alters, alters before indexes, so referenced
// tables/columns always exist first (like upstream deferredIndexes).
//
// populated maps physical table names to whether they hold rows; a nil map
// assumes every existing table is populated (conservative offline
// default). Index-definition conflicts (same name, different definition)
// are an error mirroring the upstream BetterAuthError refusal.
func DiffMigrationPlan(current, desired auth.PluginSchema, cfg auth.AdapterConfig, dialect Dialect, idKind string, populated map[string]bool) (*MigrationPlan, error) {
	if err := auth.ValidateSchemaIndexes(desired, cfg); err != nil {
		return nil, err
	}
	diff, err := auth.DiffSchemas(current, desired, cfg, populated, auth.SupportsTimestampColumnDefault(string(dialect)))
	if err != nil {
		return nil, err
	}
	resolvedIndexes := auth.ResolveSchemaIndexes(desired, cfg)
	plan := &MigrationPlan{Dialect: dialect}
	plan.UnsafeChanges = append(plan.UnsafeChanges, diff.UnsafeChanges...)

	// Planned indexes dedupe by (table, name), mirroring the upstream
	// plannedIndexes map: the ALTER loop wins over the desired-vs-current
	// index diff (it carries the MSSQL NULL filter where applicable).
	plannedIndexNames := map[string]bool{}
	created := map[string]bool{}
	for _, name := range diff.ToBeCreated {
		table := desired[name]
		pt, advisories := buildCreateTable(name, table, desired, cfg, dialect, idKind, resolvedIndexes)
		plan.Tables = append(plan.Tables, pt)
		plan.UnsafeChanges = append(plan.UnsafeChanges, advisories...)
		tableName := auth.PhysicalTableName(name, table, cfg)
		created[tableName] = true
		// Freshly created tables carry their deferred indexes like a
		// fresh install (single-column unique fields ride inline).
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
			plannedIndexNames[tableName+"\x00"+strings.ToLower(index.Name)] = true
		}
	}

	// Columns by physical name (desired) for index-length lookup.
	byTableColumn := map[string]map[string]auth.FieldAttribute{}
	for _, key := range orderSchemaNames(desired) {
		table := desired[key]
		tableName := auth.PhysicalTableName(key, table, cfg)
		byColumn := map[string]auth.FieldAttribute{}
		for logical, attr := range table.Fields {
			byColumn[auth.PhysicalColumnName(key, table, logical, cfg)] = attr
		}
		byTableColumn[tableName] = byColumn
	}

	for _, added := range diff.ToBeAdded {
		byColumn := byTableColumn[added.Table]
		resolved := resolvedIndexes[added.Table]
		attr := added.Attr
		var bound *int
		if attr.Type == auth.FieldTypeString {
			bound = indexStringLength(dialect, byColumn, resolved, added.Column)
		}
		def := ddlColumnType(dialect, attr, false, attr.References != nil, bound, idKind)
		if attr.Required == nil || *attr.Required {
			def += " NOT NULL"
		}
		// No inline UNIQUE: SQLite rejects ADD COLUMN ... UNIQUE, so a
		// unique field is enforced with a separate deferred index,
		// mirroring the upstream ALTER path.
		def += ddlDefault(dialect, attr)
		if attr.References != nil {
			ref := attr.References
			refTable := ref.Model
			refCol := ref.Field
			if rt, ok := desired[ref.Model]; ok {
				refTable = auth.PhysicalTableName(ref.Model, rt, cfg)
				refCol = auth.PhysicalColumnName(ref.Model, rt, ref.Field, cfg)
			}
			action := ref.OnDelete
			if action == "" {
				action = "cascade"
			}
			def += fmt.Sprintf(" REFERENCES %s (%s) ON DELETE %s", quoteIdent(dialect, refTable), quoteIdent(dialect, refCol), strings.ToUpper(action))
		}
		plan.Alters = append(plan.Alters, plannedAlter{Table: added.Table, Column: added.Column, Definition: def})

		// Upstream ALTER-path warning: a unique column with a static
		// default backfills every existing row with one value, failing
		// the unique index on multi-row tables.
		if attr.Unique && auth.HasStaticColumnDefault(attr) {
			plan.UnsafeChanges = append(plan.UnsafeChanges,
				fmt.Sprintf("Adding unique column %q to existing table %q backfills every existing row with its default value. If the table has more than one row, creating the unique index will fail; backfill distinct values manually, then re-run the migration or create the index yourself.", added.Column, added.Table))
		}

		// Unique/indexed fields are enforced with a separate deferred
		// index in the ALTER path (never inline).
		if attr.Index || attr.Unique {
			indexName := auth.GetDatabaseIndexName(added.Table, auth.TableIndex{Fields: []string{added.Column}, Unique: attr.Unique})
			where := ""
			if attr.Unique && attr.Required != nil && !*attr.Required && dialect == DialectMSSQL {
				// MSSQL unique indexes treat NULLs as duplicates, so
				// the NULL backfill on existing rows would abort the
				// index build. Filtering NULLs matches the other
				// dialects (upstream ALTER path).
				where = fmt.Sprintf("where %s is not null", quoteIdent(dialect, added.Column))
			}
			plan.Indexes = append(plan.Indexes, plannedIndex{
				Table:   added.Table,
				Name:    indexName,
				Columns: []string{added.Column},
				Unique:  attr.Unique,
				Where:   where,
			})
			plannedIndexNames[added.Table+"\x00"+strings.ToLower(indexName)] = true
		}
	}

	for _, added := range diff.ToBeAddedIndexes {
		// Indexes on freshly created tables are covered by the CREATE
		// path above (inline single-column UNIQUE, deferred rest via
		// the fresh loop in BuildMigrationPlan); port the upstream rule
		// that planned indexes dedupe by (table, name).
		if created[added.Table] {
			continue
		}
		key := added.Table + "\x00" + strings.ToLower(added.Index.Name)
		if plannedIndexNames[key] {
			continue
		}
		plannedIndexNames[key] = true
		plan.Indexes = append(plan.Indexes, plannedIndex{
			Table:   added.Table,
			Name:    added.Index.Name,
			Columns: append([]string(nil), added.Index.Columns...),
			Unique:  added.Index.Unique,
		})
	}
	// Newly created tables must sort with the fresh-install ordering so FK
	// targets precede dependents even when current is non-empty.
	sort.SliceStable(plan.Tables, func(i, j int) bool {
		return tableOrderIndex(plan.Tables[i].Name, desired, cfg) < tableOrderIndex(plan.Tables[j].Name, desired, cfg)
	})
	sort.Slice(plan.Alters, func(i, j int) bool {
		if plan.Alters[i].Table != plan.Alters[j].Table {
			return plan.Alters[i].Table < plan.Alters[j].Table
		}
		return plan.Alters[i].Column < plan.Alters[j].Column
	})
	sort.Slice(plan.Indexes, func(i, j int) bool {
		if plan.Indexes[i].Table != plan.Indexes[j].Table {
			return plan.Indexes[i].Table < plan.Indexes[j].Table
		}
		return plan.Indexes[i].Name < plan.Indexes[j].Name
	})
	return plan, nil
}

// tableOrderIndex ranks a physical table by the shared dependency order so
// freshly created tables in a diff keep FK-safe order.
func tableOrderIndex(physical string, schema auth.PluginSchema, cfg auth.AdapterConfig) int {
	for i, name := range orderSchemaNames(schema) {
		if auth.PhysicalTableName(name, schema[name], cfg) == physical {
			return i
		}
	}
	return len(mapsKeys(schema)) + 1
}

// ThrowOnUnsafe returns the unsafe changes as an UnsafeMigrationError,
// mirroring the throwing getMigrations path (migrate command refusal).
// Read-only callers (generate) keep the plan plus UnsafeChanges instead.
func (p *MigrationPlan) ThrowOnUnsafe() error {
	if len(p.UnsafeChanges) == 0 {
		return nil
	}
	return &auth.UnsafeMigrationError{Message: strings.Join(p.UnsafeChanges, "\n")}
}

// snapshotFile is the JSON shape of a -from current-schema snapshot: the
// logical tables (same TableSchemaJSON shape as extraSchemas) plus which
// tables hold rows. rowCounts values above zero mark a table populated;
// populated lists physical table names explicitly. When neither key is
// present the caller assumes every table is populated (nil map).
type snapshotFile struct {
	Tables map[string]TableSchemaJSON `json:"tables"`
	// Populated lists populated physical table names.
	Populated []string `json:"populated"`
	// RowCounts maps physical table names to row counts (>0 is
	// populated).
	RowCounts map[string]int `json:"rowCounts"`
	// populatedKey/rowCountsKey record key presence so an explicit empty
	// list (no populated tables) differs from an absent key (unknown).
	populatedKey bool
	rowCountsKey bool
}

// loadSnapshotFile reads a -from JSON snapshot into a current logical
// PluginSchema plus the effective populated map (nil means assume every
// table is populated). Physical names in populated/rowCounts resolve
// through cfg at diff time, so logical renames in the snapshot stay
// consistent with the desired schema.
func loadSnapshotFile(path string, cfg auth.AdapterConfig) (auth.PluginSchema, map[string]bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read -from file: %w", err)
	}
	var shadow map[string]json.RawMessage
	if err := json.Unmarshal(raw, &shadow); err != nil {
		return nil, nil, fmt.Errorf("parse -from file: %w", err)
	}
	var file snapshotFile
	if _, ok := shadow["populated"]; ok {
		file.populatedKey = true
	}
	if _, ok := shadow["rowCounts"]; ok {
		file.rowCountsKey = true
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, nil, fmt.Errorf("parse -from file: %w", err)
	}
	current := auth.PluginSchema{}
	for name, declared := range file.Tables {
		table, err := declared.ToPluginSchema()
		if err != nil {
			return nil, nil, fmt.Errorf("parse -from file: invalid table %q: %w", name, err)
		}
		current[name] = table
	}
	physicalPopulated := func(names []string, present bool) map[string]bool {
		out := map[string]bool{}
		for _, name := range names {
			out[name] = present
		}
		return out
	}
	var populated map[string]bool
	switch {
	case file.rowCountsKey:
		populated = map[string]bool{}
		for name, count := range file.RowCounts {
			populated[name] = count > 0
		}
		for key, table := range current {
			physical := auth.PhysicalTableName(key, table, cfg)
			if _, ok := populated[physical]; !ok {
				populated[physical] = false
			}
		}
	case file.populatedKey:
		populated = physicalPopulated(file.Populated, true)
		for key, table := range current {
			physical := auth.PhysicalTableName(key, table, cfg)
			if _, ok := populated[physical]; !ok {
				populated[physical] = false
			}
		}
	default:
		populated = nil // unknown: caller assumes populated
	}
	return current, populated, nil
}
