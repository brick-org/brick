// Package db is Brick's PostgreSQL query layer over bun.
//
// Frappe owns the schema: this package performs DML only (SELECT / INSERT /
// UPDATE / DELETE). There is deliberately no migrate / create-table /
// add-column helper — running DDL from Go against shared Frappe tables would
// fork schema ownership away from `bench migrate`. A grep-test in db_test.go
// locks this in: no DDL symbols in non-test source.
//
// Injection discipline (normative):
//   - identifiers via bun.Ident (Where/Sort) or quoteIdent (InsertMap, which
//     builds its INSERT as a string) — never raw interpolation;
//   - values via `?` placeholders or bun.In — never into query text;
//   - LIKE/ILIKE patterns escaped (escapeLike) with an explicit ESCAPE clause;
//   - Sort allowlisted against ListOptions.Sortable, Limit clamped;
//   - DeleteWhere refuses an empty filter; Raw keeps placeholder discipline.
package db

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/uptrace/bun"
)

// DB provides database operations for brick, backed by bun. The idb field
// is the active query target (either the root *bun.DB or a tx-bound bun.Tx);
// callers obtain a tx-bound copy via RunInTx.
type DB struct {
	bun *bun.DB
	idb bun.IDB
}

// New creates a DB backed by bun.
func New(bunDB *bun.DB) *DB {
	return &DB{bun: bunDB, idb: bunDB}
}

// Bun returns the underlying bun.DB. Note: when this DB is tx-bound (via
// RunInTx) it returns the ROOT *bun.DB, so queries through it would escape
// the transaction — use methods on *DB, not Bun(), inside RunInTx to
// participate in the transaction. Legitimate users: VerifyFrappeSchema (boot
// gate, app-side) and test cleanup deletes.
func (d *DB) Bun() *bun.DB {
	return d.bun
}

// withTx returns a copy of d bound to tx. Internal: produced by RunInTx and
// handed to the user callback.
func (d *DB) withTx(tx bun.Tx) *DB {
	return &DB{bun: d.bun, idb: tx}
}

// RunInTx runs fn inside a single bun transaction. If fn returns an error
// the transaction is rolled back; otherwise it is committed. The *DB
// passed to fn is tx-bound — all of its query methods participate in the
// same transaction.
func (d *DB) RunInTx(ctx context.Context, opts *sql.TxOptions, fn func(ctx context.Context, txDB *DB) error) error {
	return d.bun.RunInTx(ctx, opts, func(ctx context.Context, tx bun.Tx) error {
		return fn(ctx, d.withTx(tx))
	})
}

// quoteIdent double-quotes a table/column identifier, doubling embedded
// quotes. Injection-proof for any input (including Frappe's spaced table
// names like `tabCRM View Settings`), without any formatted-string SQL.
func quoteIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

// Create inserts the typed model and returns it.
func (d *DB) Create(ctx context.Context, model any) (any, error) {
	if _, ok := model.(map[string]any); ok {
		return nil, fmt.Errorf("Create for map requires InsertMap")
	}
	_, err := d.idb.NewInsert().Model(model).Returning("*").Exec(ctx)
	if err != nil {
		return nil, err
	}
	return model, nil
}

// InsertMap inserts a row given as a map[string]any and returns the inserted
// row. Use this for dynamic map-based inserts where no typed bun model
// exists. Columns are sorted so the SQL text is deterministic; every
// identifier is quoted via quoteIdent; every value is a `?` placeholder.
// Writes exactly the columns given — no timestamp magic (Frappe tables use
// creation/modified, not created_at/updated_at; stamping belongs to M5
// hooks). Empty maps are rejected loudly.
func (d *DB) InsertMap(ctx context.Context, table string, m map[string]any) (map[string]any, error) {
	if len(m) == 0 {
		return nil, fmt.Errorf("InsertMap: no columns to insert into %q", table)
	}
	cols := make([]string, 0, len(m))
	for k := range m {
		cols = append(cols, k)
	}
	sort.Strings(cols)
	quoted := make([]string, 0, len(cols))
	placeholders := make([]string, 0, len(cols))
	values := make([]any, 0, len(cols))
	for _, k := range cols {
		quoted = append(quoted, quoteIdent(k))
		placeholders = append(placeholders, "?")
		values = append(values, m[k])
	}
	query := "INSERT INTO " + quoteIdent(table) +
		" (" + strings.Join(quoted, ", ") + ") VALUES (" + strings.Join(placeholders, ", ") + ") RETURNING *"
	var result map[string]any
	if err := d.idb.NewRaw(query, values...).Scan(ctx, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// FindByID looks up a typed model by primary key.
func (d *DB) FindByID(ctx context.Context, id string, model any) (any, error) {
	if _, ok := model.(map[string]any); ok {
		return nil, fmt.Errorf("FindByID for map requires FindByIDTable")
	}
	instance := allocPtr(model)
	err := d.idb.NewSelect().Model(instance).
		Where("? = ?", bun.Ident("id"), id).Scan(ctx)
	if err != nil {
		return nil, err
	}
	return instance, nil
}

// FindByIDTable looks up a row by primary key in the table.
// Unguarded convenience for internal use — guard-scoped reads go through
// FindByIDTableWhere / FindByFieldTableWhere.
func (d *DB) FindByIDTable(ctx context.Context, table, id string) (map[string]any, error) {
	return d.FindByIDTableWhere(ctx, table, id, nil)
}

// FindByIDTableWhere looks up a row by primary key plus extra WHERE clauses.
// Used by access-control guards to scope the read at the SQL level.
func (d *DB) FindByIDTableWhere(ctx context.Context, table, id string, where []Where) (map[string]any, error) {
	return d.FindByFieldTableWhere(ctx, table, "id", id, where)
}

// FindByFieldTableWhere looks up a row by an arbitrary field value plus extra
// WHERE clauses. The workhorse for Frappe shared tables (whose PK is `name`,
// not `id`): pass field "name" explicitly.
func (d *DB) FindByFieldTableWhere(ctx context.Context, table, field, value string, where []Where) (map[string]any, error) {
	q := d.idb.NewSelect().Table(table).Where("? = ?", bun.Ident(field), value)
	var err error
	if q, err = applyWhere(q, where); err != nil {
		return nil, err
	}
	var result map[string]any
	if err := q.Scan(ctx, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// FindFirst returns the first model matching where.
func (d *DB) FindFirst(ctx context.Context, model any, where []Where) (any, error) {
	instance := allocPtr(model)
	q := d.idb.NewSelect().Model(instance)
	var err error
	if q, err = applyWhere(q, where); err != nil {
		return nil, err
	}
	if err := q.Limit(1).Scan(ctx); err != nil {
		return nil, err
	}
	return instance, nil
}

// Update modifies a typed model by primary key.
func (d *DB) Update(ctx context.Context, model any, id string, data map[string]any) (any, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("no data to update")
	}
	q := d.idb.NewUpdate().Model(model).Where("? = ?", bun.Ident("id"), id)
	for col, val := range data {
		q = q.Set("? = ?", bun.Ident(col), val)
	}
	if _, err := q.Returning("*").Exec(ctx); err != nil {
		return nil, err
	}
	return model, nil
}

// UpdateTable updates a row by primary key in the table.
// Hook-internal convenience — route/store code prefers Patch (PK writes
// rejected) or UpdateTableWhere (guard-scoped).
func (d *DB) UpdateTable(ctx context.Context, table, id string, data map[string]any) (map[string]any, error) {
	return d.UpdateTableWhere(ctx, table, id, data, nil)
}

// UpdateTableWhere updates a row by primary key plus extra WHERE clauses.
// Returns (nil, sql.ErrNoRows) when no row matches — used to enforce access
// control at the SQL level (no read-then-write race window).
func (d *DB) UpdateTableWhere(ctx context.Context, table, id string, data map[string]any, where []Where) (map[string]any, error) {
	return d.UpdateByFieldTableWhere(ctx, table, "id", id, data, where)
}

// UpdateByFieldTableWhere updates a row matched by an arbitrary field plus
// extra WHERE clauses. Writes exactly the columns in data — no timestamp
// injection (stamping belongs to M5 hooks).
func (d *DB) UpdateByFieldTableWhere(ctx context.Context, table, field, value string, data map[string]any, where []Where) (map[string]any, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("no data to update")
	}
	q := d.idb.NewUpdate().Table(table).Where("? = ?", bun.Ident(field), value)
	var err error
	if q, err = applyUpdateWhere(q, where); err != nil {
		return nil, err
	}
	for col, val := range data {
		q = q.Set("? = ?", bun.Ident(col), val)
	}
	var result map[string]any
	if err := q.Returning("*").Scan(ctx, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// Patch updates a row by primary key, refusing primary-key writes loudly.
// Route/store entry point: hook-internal code that must rewrite keys keeps
// using UpdateTable. Schema-level readonly enforcement stays in M5 — Patch
// guards the PK columns only ("id", "name").
func (d *DB) Patch(ctx context.Context, table, id string, vals map[string]any) (map[string]any, error) {
	for _, pk := range []string{"id", "name"} {
		if _, ok := vals[pk]; ok {
			return nil, fmt.Errorf("Patch: refusing to update primary key column %q", pk)
		}
	}
	return d.UpdateTable(ctx, table, id, vals)
}

// Delete deletes a typed model by primary key.
func (d *DB) Delete(ctx context.Context, model any) error {
	_, err := d.idb.NewDelete().Model(model).WherePK().Exec(ctx)
	return err
}

// DeleteByID deletes a typed model by primary key.
func (d *DB) DeleteByID(ctx context.Context, model any, id string) error {
	if _, ok := model.(map[string]any); ok {
		return fmt.Errorf("DeleteByID for map requires DeleteByIDTable")
	}
	_, err := d.idb.NewDelete().Model(model).Where("? = ?", bun.Ident("id"), id).Exec(ctx)
	return err
}

// DeleteByIDTable deletes a row by primary key from the table.
// Unguarded convenience for internal use — guard-scoped deletes go through
// DeleteByIDTableWhere and check the affected count.
func (d *DB) DeleteByIDTable(ctx context.Context, table, id string) error {
	_, err := d.DeleteByIDTableWhere(ctx, table, id, nil)
	return err
}

// DeleteByIDTableWhere deletes a row by primary key plus extra WHERE clauses.
// Returns the number of rows actually deleted so callers can distinguish
// "no such row" from "row exists but access denied" (0, nil maps to 404).
func (d *DB) DeleteByIDTableWhere(ctx context.Context, table, id string, where []Where) (int64, error) {
	return d.DeleteByFieldTableWhere(ctx, table, "id", id, where)
}

// DeleteByFieldTableWhere deletes a row matched by an arbitrary field plus
// extra WHERE clauses.
func (d *DB) DeleteByFieldTableWhere(ctx context.Context, table, field, value string, where []Where) (int64, error) {
	q := d.idb.NewDelete().Table(table).Where("? = ?", bun.Ident(field), value)
	var err error
	if q, err = applyDeleteWhere(q, where); err != nil {
		return 0, err
	}
	res, err := q.Exec(ctx)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// DeleteWhere removes rows from table matching the given filters and
// returns the number of rows affected. Refuses an empty filter slice
// to prevent accidental full-table deletes — callers wanting that
// behavior should be explicit (e.g. truncate via Raw).
func (d *DB) DeleteWhere(ctx context.Context, table string, where []Where) (int64, error) {
	if len(where) == 0 {
		return 0, fmt.Errorf("DeleteWhere: refusing to delete with empty filter")
	}
	q := d.idb.NewDelete().Table(table)
	var err error
	if q, err = applyDeleteWhere(q, where); err != nil {
		return 0, err
	}
	res, err := q.Exec(ctx)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// Count returns the number of rows matching where.
func (d *DB) Count(ctx context.Context, model any, where []Where) (int64, error) {
	q := d.idb.NewSelect().Model(model)
	var err error
	if q, err = applyWhere(q, where); err != nil {
		return 0, err
	}
	n, err := q.Count(ctx)
	return int64(n), err
}

// withListFilter appends the Search group (ILIKE across Searchable) to a
// copy of the caller filter. Never mutates the caller's slice.
func withListFilter(filter []Where, search string, searchable []string) []Where {
	out := make([]Where, 0, len(filter)+1)
	out = append(out, filter...)
	if g := searchGroup(search, searchable); g != nil {
		out = append(out, *g)
	}
	return out
}

// applySortList applies ORDER BY from a Sort string ("col" ASC, "-col" DESC)
// allowlisted against sortable. Anything else — empty, bad identifier,
// unknown column — silently applies no ordering (never user input as SQL).
func applySortList(q *bun.SelectQuery, sort string, sortable []string) *bun.SelectQuery {
	col, dir, ok := normalizeSort(sort, sortable)
	if !ok {
		return q
	}
	return q.OrderExpr("? ?", bun.Ident(col), bun.Safe(dir))
}

// List returns a paginated list of typed models plus the total match count.
// Count and page are built from one shared filter/search so they cannot
// diverge (no atomicity claim across concurrent writes — documented,
// acceptable). Pagination is always applied: Limit<=0 → DefaultLimit,
// Limit>MaxLimit → MaxLimit, Page<=0 → 1.
func (d *DB) List(ctx context.Context, dest any, opts ListOptions) (int64, error) {
	page, limit := normalizePageLimit(opts.Page, opts.Limit)
	filter := withListFilter(opts.Filter, opts.Search, opts.Searchable)

	countQ := d.idb.NewSelect().Model(dest)
	var err error
	if countQ, err = applyWhere(countQ, filter); err != nil {
		return 0, err
	}
	total, err := countQ.Count(ctx)
	if err != nil {
		return 0, err
	}

	q := d.idb.NewSelect().Model(dest)
	if q, err = applyWhere(q, filter); err != nil {
		return 0, err
	}
	q = applySortList(q, opts.Sort, opts.Sortable)
	q = q.Limit(limit).Offset((page - 1) * limit)
	if err := q.Scan(ctx); err != nil {
		return 0, err
	}
	return int64(total), nil
}

// Raw executes a raw SQL query — the escape hatch for queries the builder
// cannot express (COALESCE team-fallback, INSERT … ON CONFLICT upserts,
// UNION ALL permission aggregation, advisory locks).
//
// Placeholder mandate: every value through `?` args (bun.In for slices,
// bun.Ident for the rare dynamic identifier). Never assemble query text
// with formatted printing — a grep-test enforces this package-wide.
func (d *DB) Raw(ctx context.Context, dest any, query string, args ...any) error {
	return d.idb.NewRaw(query, args...).Scan(ctx, dest)
}

// ListMap returns rows from a table as a slice of maps — the map-based
// counterpart to List. Used when there is no typed bun model (all Frappe
// shared tables + custom routes). Honors Filter, Search (ILIKE across
// Searchable), Sort (allowlisted), Page, Limit; same clamp rules as List.
func (d *DB) ListMap(ctx context.Context, table string, opts ListOptions) ([]map[string]any, int64, error) {
	page, limit := normalizePageLimit(opts.Page, opts.Limit)
	filter := withListFilter(opts.Filter, opts.Search, opts.Searchable)

	countQ := d.idb.NewSelect().Table(table)
	var err error
	if countQ, err = applyWhere(countQ, filter); err != nil {
		return nil, 0, err
	}
	total, err := countQ.Count(ctx)
	if err != nil {
		return nil, 0, err
	}

	q := d.idb.NewSelect().Table(table)
	if q, err = applyWhere(q, filter); err != nil {
		return nil, 0, err
	}
	q = applySortList(q, opts.Sort, opts.Sortable)
	q = q.Limit(limit).Offset((page - 1) * limit)
	var rows []map[string]any
	if err := q.Scan(ctx, &rows); err != nil {
		return nil, 0, err
	}
	return rows, int64(total), nil
}

// allocPtr allocates a fresh pointer of the model's type for Scan targets.
func allocPtr(model any) any {
	if model == nil {
		return nil
	}
	if _, ok := model.(map[string]any); ok {
		return map[string]any{}
	}
	rv := reflect.ValueOf(model)
	if rv.Kind() == reflect.Ptr {
		return reflect.New(rv.Type().Elem()).Interface()
	}
	return reflect.New(rv.Type()).Interface()
}
