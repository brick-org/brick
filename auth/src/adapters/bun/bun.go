package bunadapter

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	authdb "github.com/brick-org/brick/auth/src/db"
	"github.com/uptrace/bun"
)

// Config maps Better Auth model and field names to database names.
type Config = authdb.Config

// defaultFindManyLimit mirrors upstream's findMany default
// (options.advanced.database.defaultFindManyLimit ?? 100). It is applied
// when FindMany is called with limit == 0. Pass a negative limit to request
// an explicitly unbounded read (needed by internal pre-fetch paths such as
// hook fan-out that must observe every matching row).
const defaultFindManyLimit = 100

// InvalidWhereError reports a malformed Where clause, e.g. an in/not_in
// operator whose Value is not a slice/array.
type InvalidWhereError struct {
	Field    string
	Operator authdb.Operator
	Reason   string
}

func (e *InvalidWhereError) Error() string {
	return fmt.Sprintf("bun: invalid where %q operator %q: %s", e.Field, string(e.Operator), e.Reason)
}

// Adapter implements authdb.Adapter using Bun ORM.
//
// Row-key contract: rows returned to callers use logical camelCase keys
// (for example "userId") with type revival per contract (ids stringified;
// pg/sqlite return native JSON/dates/bools). Logical camelCase input (Where
// fields, data keys, select entries, SortBy) maps to physical columns via
// cfg with a camelToSnake fallback; custom FieldNames reverse to logical on
// reads (transformOutput key part).
//
// LIKE portability: pattern operators (contains/starts_with/ends_with) use
// case-sensitive LIKE by default on all dialects (including PostgreSQL),
// matching upstream's sensitive mode (upstream like-on-pg).
// ILIKE is used only on PostgreSQL in insensitive mode; other dialects use
// LOWER(col) LIKE LOWER(?) for insensitive mode. LIKE patterns do not escape
// caller-supplied "%" or "_" (matching upstream drizzle `like` behavior);
// callers needing literal matches must escape them. Where.Mode "insensitive"
// is honored as described; empty mode means "sensitive".
//
// Transforms: when Options.Models registers the target model, the adapter
// ports the factory input/output transforms (date, boolean, JSON, array,
// and numeric-ID coercions, defaultValue/onUpdate application, and custom
// field/hook transforms) driven by the effective Capabilities. Without a
// registered model the adapter keeps its historical passthrough behavior.
// Create returns the persisted row (RETURNING * on PostgreSQL/SQLite, a
// cascading re-read on MySQL/MSSQL); nested Transaction calls use savepoints.
type Adapter struct {
	db      bun.IDB
	raw     *bun.DB // needed for RunInTx
	cfg     authdb.Config
	dialect string // "pg" (default), "sqlite", "mysql", "mssql", ...
	opts    Options
	inTx    bool // true inside a Transaction callback (nested calls use savepoints)
}

// requireDB reports a descriptive error when the adapter was constructed
// without a database (nil DB is for SQL-generation/offline use only).
// Query execution cannot run, so fail with an error instead of panicking
// on a nil-pointer dereference.
func (a *Adapter) requireDB(op string) error {
	if a.db == nil {
		return fmt.Errorf("bun %s: no database configured (nil DB is for SQL-generation/offline use only)", op)
	}
	return nil
}

var (
	_ authdb.Adapter            = (*Adapter)(nil)
	_ authdb.Joiner             = (*Adapter)(nil)
	_ authdb.CapabilityReporter = (*Adapter)(nil)
)

// FieldType is the logical field type vocabulary, mirroring upstream's
// DBFieldAttribute type ("string", "number", "boolean", "date", "json",
// "string[]", "number[]", ...). Only the listed constants drive transforms;
// unknown values behave as opaque (no coercion, still validated for
// membership when the model is registered).
type FieldType string

const (
	FieldTypeString      FieldType = "string"
	FieldTypeNumber      FieldType = "number"
	FieldTypeBoolean     FieldType = "boolean"
	FieldTypeDate        FieldType = "date"
	FieldTypeJSON        FieldType = "json"
	FieldTypeStringArray FieldType = "string[]"
	FieldTypeNumberArray FieldType = "number[]"
)

// FieldReference names the target of a foreign key, mirroring upstream's
// references ({ model, field, onDelete }). Model and Field are logical
// names; see DefaultModelDefs for the core-table registry.
type FieldReference struct {
	Model string
	Field string
}

// FieldTransform carries per-field custom transforms, mirroring upstream's
// field transform ({ input, output }): Input runs after defaultValue
// resolution and before capability coercions; Output runs first on reads,
// before capability revival.
type FieldTransform struct {
	Input  func(any) (any, error)
	Output func(any) (any, error)
}

// FieldDef describes one logical field, mirroring the upstream
// DBFieldAttribute subset the adapter transforms consume (type, unique,
// required, defaultValue, onUpdate, references, transform).
//
// DefaultValue and OnUpdate accept either a literal or a func() any
// (mirroring upstream's value-or-function defaultValue/onUpdate).
type FieldDef struct {
	Type         FieldType
	Unique       bool
	Required     bool
	DefaultValue any
	OnUpdate     any
	References   *FieldReference
	Transform    *FieldTransform
}

// ModelDef describes one logical model's fields, keyed by logical
// (camelCase) field name.
type ModelDef struct {
	Fields map[string]FieldDef
}

// TransformContext identifies the field a custom transform hook runs for,
// mirroring upstream's customTransformInput/customTransformOutput props
// (field, fieldAttributes, model, action subset).
type TransformContext struct {
	// Model is the logical model name.
	Model string
	// Field is the logical field name.
	Field string
	// Action is one of "create", "update", or a read action
	// ("findOne", "findMany", "updateMany", "delete", "deleteMany",
	// "consumeOne", "incrementOne", "count").
	Action string
	// Def is the field definition (zero value for the synthesized id).
	Def FieldDef
}

// Options configures transforms, capabilities, and strict validation.
//
// Models is keyed by logical model name, with fields keyed by logical field
// name (see DefaultModelDefs for the core-table registry). When Models
// holds the target model, the adapter validates model/field membership
// (unknown names error instead of hitting the database) and runs the
// factory-equivalent transforms; without a registered model, behavior is
// the historical passthrough. Capabilities overrides the per-dialect
// defaults (see Capabilities); NumericIDs enables serial-ID coercion
// (upstream generateId "serial").
type Options struct {
	Capabilities *authdb.Capabilities
	Models       map[string]ModelDef
	// NumericIDs coerces id and id-reference values with Number() on input
	// while reads still stringify ids, mirroring upstream's useNumberId
	// handling. It also enables the LAST_INSERT_ID()/SCOPE_IDENTITY()
	// step of the non-RETURNING Create fallback.
	NumericIDs            bool
	CustomTransformInput  func(TransformContext, any) any
	CustomTransformOutput func(TransformContext, any) any
}

// New wraps a *bun.DB as a authdb.Adapter.
func New(db *bun.DB, cfg authdb.Config) authdb.Adapter {
	return &Adapter{db: db, raw: db, cfg: cfg, dialect: dialectName(db)}
}

// NewWithOptions wraps a *bun.DB as an authdb.Adapter with transform,
// capability, and validation options. A nil db is allowed for
// SQL-generation/offline use; query execution will fail naturally and
// Transaction falls back to sequential execution (upstream
// createAsIsTransaction).
func NewWithOptions(db *bun.DB, cfg authdb.Config, opts Options) authdb.Adapter {
	return &Adapter{db: db, raw: db, cfg: cfg, dialect: dialectName(db), opts: opts}
}

// NewWithDialect wraps db with an explicit SQL dialect label. It exists for
// unit tests and for drivers whose dialect cannot be inferred; production
// code should prefer New.
func NewWithDialect(db bun.IDB, raw *bun.DB, cfg authdb.Config, dialect string) authdb.Adapter {
	if dialect == "" {
		dialect = "pg"
	}
	return &Adapter{db: db, raw: raw, cfg: cfg, dialect: strings.ToLower(dialect)}
}

// NewWithDialectOptions is NewWithDialect with transform, capability, and
// validation options (see NewWithOptions).
func NewWithDialectOptions(db bun.IDB, raw *bun.DB, cfg authdb.Config, dialect string, opts Options) authdb.Adapter {
	if dialect == "" {
		dialect = "pg"
	}
	return &Adapter{db: db, raw: raw, cfg: cfg, dialect: strings.ToLower(dialect), opts: opts}
}

// Capabilities reports the effective capability flags: the configured
// Options.Capabilities, or per-dialect defaults otherwise (see
// defaultCapabilities). Upstream TypeScript name: AdapterFactoryConfig
// (capability subset).
func (a *Adapter) Capabilities() authdb.Capabilities {
	if a.opts.Capabilities != nil {
		caps := *a.opts.Capabilities
		if caps.AdapterID == "" {
			caps.AdapterID = "bun"
		}
		if caps.AdapterName == "" {
			caps.AdapterName = "Bun Adapter"
		}
		return caps
	}
	return defaultCapabilities(a.Dialect())
}

// caps returns the effective capability flags backing Capabilities.
func (a *Adapter) caps() authdb.Capabilities { return a.Capabilities() }

// defaultCapabilities ports the kysely adapter's per-dialect capability
// matrix (kysely-adapter.ts adapterOptions.config): PostgreSQL supports
// JSON/UUIDs/dates/booleans; MySQL supports dates but not booleans/JSON;
// SQLite and MSSQL support neither dates nor booleans natively; no dialect
// supports native arrays here (values stringify, matching kysely's
// supportsArrays: false).
func defaultCapabilities(dialect string) authdb.Capabilities {
	caps := authdb.DefaultCapabilities()
	caps.AdapterID = "bun"
	caps.AdapterName = "Bun Adapter"
	caps.SupportsArrays = false
	switch dialect {
	case "pg", "postgres", "postgresql", "pgdialect":
		caps.SupportsJSON = true
		caps.SupportsUUIDs = true
	case "mysql":
		caps.SupportsBooleans = false
	case "sqlite", "sqliteshim", "mssql":
		caps.SupportsBooleans = false
		caps.SupportsDates = false
	default:
		caps.SupportsBooleans = false
		caps.SupportsDates = false
	}
	return caps
}

// Dialect reports the SQL dialect label used for LIKE/RETURNING decisions.
func (a *Adapter) Dialect() string {
	if a.dialect == "" {
		return "pg"
	}
	return a.dialect
}

func (a *Adapter) isPostgres() bool { return isPostgresDialect(a.Dialect()) }

// returningGuardRetries bounds re-execution of a ctid/rowid-guarded
// single-row RETURNING statement when it matches nothing while the row still
// exists. A concurrent writer moves the row (new ctid/rowid), so the guard
// goes stale: PostgreSQL serializes the writers on the row lock, then the
// waiter's pinned ctid no longer matches the committed version and the
// statement affects 0 rows. Without a retry the increment/consume silently
// vanishes (proven by live PG concurrency in AUTH-V10-03: 132 of 160
// concurrent increments returned (nil, nil)). Each failed attempt implies
// another writer committed, so a small bound converges; exhaustion reports
// contention instead of dropping the write.
const returningGuardRetries = 10

// execReturningFast runs a single-row ...RETURNING statement, reporting the
// matched row or nil when nothing matched (sql.ErrNoRows and empty maps both
// mean "no row").
func execReturningFast(ctx context.Context, db bun.IDB, query string, args []any) (map[string]any, error) {
	row := map[string]any{}
	if err := db.NewRaw(query, args...).Scan(ctx, &row); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if len(row) == 0 {
		return nil, nil
	}
	return row, nil
}

// pgLockedIncrement applies a single-row increment holding the row lock
// (PostgreSQL only; SQLite has no FOR UPDATE): SELECT ctid ... FOR UPDATE in
// a transaction, then UPDATE by the locked ctid. The lock serializes
// concurrent writers, so the guard cannot go stale and at most one row is
// ever touched. A missing row is a genuine miss (nil, nil).
func (a *Adapter) pgLockedIncrement(ctx context.Context, table, setList, clause string, setArgs, whereArgs []any) (map[string]any, error) {
	quoted := quoteIdent(table)
	var out map[string]any
	found := false
	err := a.raw.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		var ctid string
		sel := fmt.Sprintf(`SELECT ctid FROM %s WHERE %s LIMIT 1 FOR UPDATE`, quoted, clause)
		if err := tx.NewRaw(sel, whereArgs...).Scan(ctx, &ctid); err != nil {
			if err == sql.ErrNoRows {
				return nil
			}
			return err
		}
		upd := fmt.Sprintf(`UPDATE %s SET %s WHERE ctid = ?::tid RETURNING *`, quoted, setList)
		uargs := append(append([]any(nil), setArgs...), ctid)
		row, err := execReturningFast(ctx, tx, upd, uargs)
		if err != nil {
			return err
		}
		if row == nil {
			return fmt.Errorf("bun IncrementOne: locked row vanished mid-transaction")
		}
		out, found = row, true
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return out, nil
}

// pgLockedConsume deletes a single row holding the row lock (PostgreSQL
// only), mirroring pgLockedIncrement: at most one concurrent consumer wins,
// and a racing updater can no longer turn the consume into a false miss.
func (a *Adapter) pgLockedConsume(ctx context.Context, table, clause string, args []any) (map[string]any, error) {
	quoted := quoteIdent(table)
	var out map[string]any
	found := false
	err := a.raw.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		var ctid string
		sel := fmt.Sprintf(`SELECT ctid FROM %s WHERE %s LIMIT 1 FOR UPDATE`, quoted, clause)
		if err := tx.NewRaw(sel, args...).Scan(ctx, &ctid); err != nil {
			if err == sql.ErrNoRows {
				return nil
			}
			return err
		}
		del := fmt.Sprintf(`DELETE FROM %s WHERE ctid = ?::tid RETURNING *`, quoted)
		row, err := execReturningFast(ctx, tx, del, []any{ctid})
		if err != nil {
			return err
		}
		if row == nil {
			return fmt.Errorf("bun ConsumeOne: locked row vanished mid-transaction")
		}
		out, found = row, true
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return out, nil
}

// pgLockedPathAvailable reports whether the deterministic row-lock slow path
// can run: PostgreSQL, outside a caller transaction (nesting a new
// transaction around our own row locks could self-deadlock), with a live
// *bun.DB to begin on.
func (a *Adapter) pgLockedPathAvailable() bool {
	return a.isPostgres() && !a.inTx && a.raw != nil
}

func (a *Adapter) supportsReturning() bool {
	// RETURNING * works on PostgreSQL and SQLite; MySQL/MSSQL need a
	// follow-up read instead.
	d := a.Dialect()
	return d == "pg" || d == "postgres" || d == "postgresql" || d == "pgdialect" || d == "sqlite" || d == "sqliteshim"
}

func dialectName(db *bun.DB) string {
	if db == nil {
		return "pg"
	}
	name := ""
	func() {
		defer func() { _ = recover() }()
		name = fmt.Sprint(db.Dialect().Name())
	}()
	switch strings.ToLower(name) {
	case "", "pg", "postgres", "postgresql", "pgdialect":
		if name == "" {
			return "pg"
		}
		return "pg"
	case "sqlite", "sqliteshim":
		return "sqlite"
	case "mysql":
		return "mysql"
	case "mssql":
		return "mssql"
	default:
		if name == "" {
			return "pg"
		}
		return strings.ToLower(name)
	}
}

// tableName resolves the logical model to its physical table and rejects
// identifiers that are not safe to interpolate into raw table expressions,
// porting the configured-identifier validation gap (raw ModelNames were
// trusted verbatim). Custom ModelNames may be schema-qualified
// ("schema.table"); anything else must match
// [A-Za-z_][A-Za-z0-9_]* per part.
func (a *Adapter) tableName(model string) (string, error) {
	table := a.cfg.ModelName(model)
	if table == model {
		// Default physical tables are lowercase plurals
		// ("oauthRefreshToken" -> "oauthrefreshtokens"). Lowercasing here
		// matters: quoted raw-SQL paths (IncrementOne/ConsumeOne
		// RETURNING) preserve case, while unquoted TableExpr paths fold
		// silently — an unresolved-case name breaks only the former.
		// Explicitly configured ModelNames keep their spelling.
		table = strings.ToLower(model) + "s"
	}
	if err := authdb.ValidateIdentifier(table); err != nil {
		return "", &authdb.InvalidIdentifierError{Name: table, Kind: "table"}
	}
	return table, nil
}

// colName resolves the logical field to its physical column and rejects
// identifiers that are not safe to interpolate, mirroring tableName for
// configured FieldNames and derived snake_case columns.
func (a *Adapter) colName(model, field string) (string, error) {
	custom := a.cfg.FieldName(model, field)
	col := custom
	if custom == field {
		col = camelToSnake(field)
	}
	if err := authdb.ValidateIdentifier(col); err != nil {
		return "", &authdb.InvalidIdentifierError{Name: col, Kind: "column"}
	}
	return col, nil
}

// selectColumns maps logical select entries to physical columns, skipping
// blanks and duplicates. On strict adapters (registered model) unknown
// fields are an error, mirroring upstream's getFieldAttributes validation.
func (a *Adapter) selectColumns(model string, sel []string) ([]string, error) {
	if len(sel) == 0 {
		return nil, nil
	}
	if err := a.validateFields(model, sel); err != nil {
		return nil, err
	}
	cols := make([]string, 0, len(sel))
	seen := map[string]struct{}{}
	for _, field := range sel {
		if field == "" {
			continue
		}
		col, err := a.colName(model, field)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[col]; ok {
			continue
		}
		seen[col] = struct{}{}
		cols = append(cols, col)
	}
	return cols, nil
}

func (a *Adapter) applySelect(q *bun.SelectQuery, model string, sel []string) (*bun.SelectQuery, error) {
	cols, err := a.selectColumns(model, sel)
	if err != nil {
		return nil, err
	}
	if len(cols) == 0 {
		return q, nil
	}
	table, err := a.tableName(model)
	if err != nil {
		return nil, err
	}
	return q.ColumnExpr("?", bun.Safe(qualifiedColumnList(table, cols))), nil
}

func qualifiedColumnList(table string, cols []string) string {
	quotedTable := `"` + strings.ReplaceAll(table, `"`, `""`) + `"`
	parts := make([]string, 0, len(cols))
	for _, c := range cols {
		parts = append(parts, quotedTable+`.`+`"`+strings.ReplaceAll(c, `"`, `""`)+`"`)
	}
	return strings.Join(parts, ", ")
}

// --- model registry, strict validation, and transforms ---
//
// The registry (Options.Models, keyed by logical model/field names) ports
// the factory's schema-driven behavior: strict model/field/value
// validation plus date, boolean, JSON, array, and numeric-ID transforms
// (factory.ts transformInput/transformOutput/transformWhereClause). Without
// a registered model the adapter keeps its historical passthrough behavior
// so unregistered callers observe no change.

// strict reports whether model/field/value validation and transforms apply.
// Only registered models are strict; unknown models on an adapter with a
// non-empty registry are rejected.
func (a *Adapter) strict() bool { return len(a.opts.Models) > 0 }

// modelDef returns the registry entry for a logical model.
func (a *Adapter) modelDef(model string) (ModelDef, bool) {
	md, ok := a.opts.Models[model]
	return md, ok
}

// fieldDef returns the registry entry for a logical field. The id field is
// synthesized when absent, mirroring upstream's injected fields.id.
func (a *Adapter) fieldDef(model, field string) (FieldDef, bool) {
	if md, ok := a.opts.Models[model]; ok {
		if def, ok := md.Fields[field]; ok {
			return def, true
		}
		if field == "id" {
			return FieldDef{}, true
		}
	}
	return FieldDef{}, false
}

// validateModel rejects unknown models on strict adapters, mirroring
// upstream's getFieldAttributes model membership check.
func (a *Adapter) validateModel(model string) error {
	if a.strict() {
		if _, ok := a.opts.Models[model]; !ok {
			return &authdb.InvalidModelError{Model: model}
		}
	}
	return nil
}

// validateFields rejects unknown (non-blank) fields on strict adapters.
func (a *Adapter) validateFields(model string, fields []string) error {
	if !a.strict() {
		return nil
	}
	if err := a.validateModel(model); err != nil {
		return err
	}
	for _, field := range fields {
		if field == "" {
			continue
		}
		if _, ok := a.fieldDef(model, field); !ok {
			return &authdb.InvalidFieldError{Model: model, Field: field}
		}
	}
	return nil
}

// isIDReference reports id and id-reference fields, mirroring upstream's
// `defaultFieldName === "id" || fieldAttr.references?.field === "id"`.
func isIDReference(field string, def FieldDef) bool {
	return field == "id" || (def.References != nil && def.References.Field == "id")
}

// resolveDefault unwraps value-or-function defaults (upstream defaultValue
// and onUpdate accept either a literal or a thunk).
func resolveDefault(v any) any {
	if fn, ok := v.(func() any); ok {
		return fn()
	}
	return v
}

// transformInputData ports factory transformInput for one payload: it
// resolves defaultValue (create) and onUpdate (update) for absent fields,
// normalizes date strings, runs custom field transforms, applies
// capability coercions (JSON/array stringify, date/boolean encodings,
// numeric-ID coercion), and runs the custom input hook. Keys are logical
// on input and physical on output. Without a registered model (and without
// a custom input hook) this is the historical encodeRow mapping.
func (a *Adapter) transformInputData(model string, data map[string]any, action string) (map[string]any, error) {
	if !a.strict() && a.opts.CustomTransformInput == nil {
		return a.encodeRow(model, data)
	}
	if err := a.validateModel(model); err != nil {
		return nil, err
	}
	md, _ := a.modelDef(model)
	caps := a.caps()
	out := make(map[string]any, len(data))
	for k, v := range data {
		def, ok := md.Fields[k]
		if !ok {
			if k == "id" {
				def = FieldDef{}
			} else {
				return nil, &authdb.InvalidFieldError{Model: model, Field: k}
			}
		}
		nv, err := a.applyInputValue(model, k, v, def, action, true, caps)
		if err != nil {
			return nil, err
		}
		col, err := a.colName(model, k)
		if err != nil {
			return nil, err
		}
		out[col] = nv
	}
	// Absent fields: defaultValue on create (including required+null, per
	// withApplyDefault), onUpdate on update.
	for k, def := range md.Fields {
		if _, present := data[k]; present {
			continue
		}
		if action == "create" && def.DefaultValue != nil {
			nv, err := a.applyInputValue(model, k, resolveDefault(def.DefaultValue), def, action, false, caps)
			if err != nil {
				return nil, err
			}
			col, err := a.colName(model, k)
			if err != nil {
				return nil, err
			}
			out[col] = nv
		} else if action == "update" && def.OnUpdate != nil {
			nv, err := a.applyInputValue(model, k, resolveDefault(def.OnUpdate), def, action, false, caps)
			if err != nil {
				return nil, err
			}
			col, err := a.colName(model, k)
			if err != nil {
				return nil, err
			}
			out[col] = nv
		}
	}
	return out, nil
}

// applyInputValue runs one logical value through default resolution,
// custom field input, capability coercions, and the custom input hook.
// present reports whether the caller supplied the key (explicit nulls stay
// null except for required fields on create, per withApplyDefault).
func (a *Adapter) applyInputValue(model, field string, value any, def FieldDef, action string, present bool, caps authdb.Capabilities) (any, error) {
	// Date strings normalize to time.Time (signUpEmail-style payloads carry
	// dates as strings upstream).
	if def.Type == FieldTypeDate {
		if s, ok := value.(string); ok {
			parsed, err := parseDateTime(s)
			if err != nil {
				return nil, &authdb.InvalidValueError{Model: model, Field: field, Reason: fmt.Sprintf("cannot parse date %q", s)}
			}
			value = parsed
		}
	}
	// withApplyDefault: create fills defaults for absent values (and for
	// explicit nulls on required fields); update fills onUpdate for absent
	// values.
	if action == "create" && (!present || (value == nil && def.Required)) && def.DefaultValue != nil {
		value = resolveDefault(def.DefaultValue)
	} else if action == "update" && !present && def.OnUpdate != nil {
		value = resolveDefault(def.OnUpdate)
	}
	// Custom field transform input runs before the default capability
	// coercions, matching factory ordering.
	if def.Transform != nil && def.Transform.Input != nil {
		nv, err := def.Transform.Input(value)
		if err != nil {
			return nil, &authdb.InvalidValueError{Model: model, Field: field, Reason: err.Error()}
		}
		value = nv
	}
	if isIDReference(field, def) && a.opts.NumericIDs {
		value = coerceNumeric(value)
	} else if !caps.SupportsJSON && def.Type == FieldTypeJSON && isJSONObject(value) {
		raw, err := json.Marshal(value)
		if err != nil {
			return nil, &authdb.InvalidValueError{Model: model, Field: field, Reason: "cannot stringify JSON value"}
		}
		value = string(raw)
	} else if !caps.SupportsArrays && (def.Type == FieldTypeStringArray || def.Type == FieldTypeNumberArray) && isSliceValue(value) {
		raw, err := json.Marshal(value)
		if err != nil {
			return nil, &authdb.InvalidValueError{Model: model, Field: field, Reason: "cannot stringify array value"}
		}
		value = string(raw)
	} else if !caps.SupportsDates && def.Type == FieldTypeDate {
		if t, ok := value.(time.Time); ok {
			value = t.UTC().Format(time.RFC3339Nano)
		}
	} else if !caps.SupportsBooleans && def.Type == FieldTypeBoolean {
		if b, ok := value.(bool); ok {
			if b {
				value = 1
			} else {
				value = 0
			}
		}
	}
	if a.opts.CustomTransformInput != nil {
		value = a.opts.CustomTransformInput(TransformContext{Model: model, Field: field, Action: action, Def: def}, value)
	}
	return value, nil
}

// coerceWhereValue ports factory transformWhereClause value handling: it
// validates the field/operator on strict adapters and coerces where values
// to the field type (boolean/number strings, non-capable date/boolean/JSON
// encodings, numeric IDs), then runs the custom input hook.
func (a *Adapter) coerceWhereValue(model string, w authdb.Where, action string) (any, error) {
	value := w.Value
	if op := string(w.Operator); op != "" && !isKnownOperator(authdb.Operator(op)) {
		if a.strict() {
			return nil, &authdb.InvalidValueError{Model: model, Field: w.Field, Reason: fmt.Sprintf("unknown operator %q", op)}
		}
	}
	var def FieldDef
	if a.strict() {
		if err := a.validateModel(model); err != nil {
			return nil, err
		}
		d, ok := a.fieldDef(model, w.Field)
		if !ok {
			return nil, &authdb.InvalidFieldError{Model: model, Field: w.Field}
		}
		def = d
	} else if a.opts.CustomTransformInput == nil {
		return value, nil
	}
	caps := a.caps()
	if def.Type == FieldTypeBoolean && typeofString(value) {
		value = value == "true"
	}
	if def.Type == FieldTypeNumber {
		if s, ok := value.(string); ok && strings.TrimSpace(s) != "" {
			if parsed, err := strconv.ParseFloat(s, 64); err == nil {
				value = parsed
			}
		} else if arr, ok := value.([]any); ok {
			parsed := make([]any, len(arr))
			allNumeric := true
			for i, v := range arr {
				if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
					if f, err := strconv.ParseFloat(s, 64); err == nil {
						parsed[i] = f
						continue
					}
				}
				parsed[i] = v
				if _, ok := toNumber(v); !ok {
					allNumeric = false
				}
			}
			if allNumeric {
				value = parsed
			}
		}
	}
	if def.Type == FieldTypeDate {
		if t, ok := value.(time.Time); ok && !caps.SupportsDates {
			value = t.UTC().Format(time.RFC3339Nano)
		}
	}
	if def.Type == FieldTypeBoolean {
		if b, ok := value.(bool); ok && !caps.SupportsBooleans {
			if b {
				value = 1
			} else {
				value = 0
			}
		}
	}
	if def.Type == FieldTypeJSON && isJSONObject(value) && !caps.SupportsJSON {
		raw, err := json.Marshal(value)
		if err != nil {
			return nil, &authdb.InvalidValueError{Model: model, Field: w.Field, Reason: fmt.Sprintf("cannot stringify JSON value for field %q", w.Field)}
		}
		value = string(raw)
	}
	if isIDReference(w.Field, def) && a.opts.NumericIDs {
		if arr, ok := value.([]any); ok {
			out := make([]any, len(arr))
			for i, v := range arr {
				out[i] = coerceNumeric(v)
			}
			value = out
		} else {
			value = coerceNumeric(value)
		}
	}
	if a.opts.CustomTransformInput != nil {
		value = a.opts.CustomTransformInput(TransformContext{Model: model, Field: w.Field, Action: action, Def: def}, value)
	}
	return value, nil
}

func typeofString(v any) bool {
	_, ok := v.(string)
	return ok
}

// coerceNumeric mirrors upstream Number(x): numeric strings become numbers,
// nulls stay null, everything else passes through.
func coerceNumeric(v any) any {
	switch n := v.(type) {
	case nil:
		return nil
	case string:
		if strings.TrimSpace(n) == "" {
			return v
		}
		if i, err := strconv.ParseInt(n, 10, 64); err == nil {
			return i
		}
		if f, err := strconv.ParseFloat(n, 64); err == nil {
			return f
		}
		return v
	default:
		return v
	}
}

// isJSONObject reports map/slice values that need JSON stringification on
// stores without native JSON support. Plain strings (already encoded) pass
// through untouched.
func isJSONObject(v any) bool {
	if v == nil {
		return false
	}
	kind := reflect.ValueOf(v).Kind()
	return kind == reflect.Map || kind == reflect.Slice || kind == reflect.Array
}

var dateParseLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05.999999999Z07:00",
	"2006-01-02 15:04:05",
	"2006-01-02",
}

// parseDateTime parses the date layouts the adapter may read back from
// stores without native date support.
func parseDateTime(s string) (time.Time, error) {
	for _, layout := range dateParseLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unparseable date %q", s)
}

// safeJSONParse mirrors upstream safeJSONParse: strings that do not parse
// come back unchanged instead of erroring.
func safeJSONParse(s string) any {
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return s
	}
	return v
}

func (a *Adapter) Create(ctx context.Context, model string, data map[string]any, select_ []string) (map[string]any, error) {
	// Return the persisted row (generated IDs, defaults, trigger values),
	// not the input echo: RETURNING * where supported, a cascading re-read
	// otherwise (porting the kysely/drizzle withReturning fallback).
	encoded, err := a.transformInputData(model, data, "create")
	if err != nil {
		return nil, fmt.Errorf("bun Create %s: %w", model, err)
	}
	if len(encoded) == 0 {
		return nil, fmt.Errorf("bun Create %s: no columns to insert", model)
	}
	if err := a.validateModel(model); err != nil {
		return nil, fmt.Errorf("bun Create %s: %w", model, err)
	}
	table, err := a.tableName(model)
	if err != nil {
		return nil, fmt.Errorf("bun Create %s: %w", model, err)
	}
	if err := a.requireDB("Create"); err != nil {
		return nil, err
	}
	var persisted map[string]any
	if a.supportsReturning() {
		persisted, err = a.createReturning(ctx, table, encoded)
		if err != nil {
			// Map constraint violations to the typed DuplicateKey error at
			// the adapter layer (routes branch on IsDuplicateKeyError);
			// anything else passes through unchanged.
			return nil, fmt.Errorf("bun Create %s: %w", model, authdb.MapDuplicateKeyError(model, err))
		}
		if len(persisted) == 0 {
			return nil, nil
		}
	} else {
		persisted, err = a.createFallback(ctx, model, table, encoded)
		if err != nil {
			return nil, fmt.Errorf("bun Create %s: %w", model, authdb.MapDuplicateKeyError(model, err))
		}
		if persisted == nil {
			return nil, nil
		}
	}
	decoded, err := a.decodeRow(model, persisted)
	if err != nil {
		return nil, fmt.Errorf("bun Create %s: %w", model, err)
	}
	return a.projectRow(model, decoded, select_), nil
}

// createReturning inserts one row and returns the stored row.
func (a *Adapter) createReturning(ctx context.Context, table string, encoded map[string]any) (map[string]any, error) {
	out := map[string]any{}
	if err := a.db.NewInsert().TableExpr(table).Model(&encoded).Returning("*").Scan(ctx, &out); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return out, nil
}

// createFallback inserts one row on dialects without RETURNING and reads it
// back. The insert and the cascading lookup run inside one transaction when
// the adapter owns the connection (connection-scoped steps like
// LAST_INSERT_ID require it); inside a transaction callback the ambient
// transaction is reused.
func (a *Adapter) createFallback(ctx context.Context, model, table string, encoded map[string]any) (map[string]any, error) {
	insertAndFetch := func(ctx context.Context, db bun.IDB) (map[string]any, error) {
		row := encoded
		if _, err := db.NewInsert().TableExpr(table).Model(&row).Exec(ctx); err != nil {
			return nil, err
		}
		return a.fetchInserted(ctx, db, model, table, encoded)
	}
	if a.inTx || a.raw == nil {
		return insertAndFetch(ctx, a.db)
	}
	var out map[string]any
	if err := a.raw.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		fetched, err := insertAndFetch(ctx, tx)
		if err != nil {
			return err
		}
		out = fetched
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// fetchInserted ports the kysely/drizzle MySQL inserted-row cascade:
//  1. known id from the payload,
//  2. serial auto-increment via LAST_INSERT_ID()/SCOPE_IDENTITY() (best
//     effort: connection-scoped steps that fail fall through),
//  3. unique-column lookup from the field registry,
//  4. full-field match that must be unambiguous (LIMIT 2).
//
// It returns (nil, nil) with no error when no strategy identifies the row,
// matching upstream's warn-and-null behavior.
func (a *Adapter) fetchInserted(ctx context.Context, db bun.IDB, model, table string, encoded map[string]any) (map[string]any, error) {
	idCol, err := a.colName(model, "id")
	if err != nil {
		return nil, err
	}
	selectByID := func(id any) (map[string]any, error) {
		rows, err := selectPhysicalRows(ctx, db, table, map[string]any{idCol: id}, 1)
		if err != nil {
			return nil, err
		}
		if len(rows) == 0 {
			return nil, nil
		}
		return rows[0], nil
	}
	// 1. Known id from the payload.
	if id, ok := encoded[idCol]; ok && id != nil {
		return selectByID(id)
	}
	// 2. Serial auto-increment (connection-scoped; best effort).
	if a.opts.NumericIDs {
		var query string
		switch a.Dialect() {
		case "mysql":
			query = `SELECT LAST_INSERT_ID() AS id`
		case "mssql":
			query = `SELECT SCOPE_IDENTITY() AS id`
		}
		if query != "" {
			last := map[string]any{}
			if err := db.NewRaw(query).Scan(ctx, &last); err == nil {
				if id, ok := last["id"]; ok && id != nil {
					if row, err := selectByID(id); err == nil && row != nil {
						return row, nil
					}
				}
			}
		}
	}
	// 3. Unique-column lookup from the registry.
	if md, ok := a.modelDef(model); ok {
		for _, logical := range sortedFieldNames(md.Fields) {
			def := md.Fields[logical]
			if !def.Unique {
				continue
			}
			col, err := a.colName(model, logical)
			if err != nil {
				return nil, err
			}
			val, ok := encoded[col]
			if !ok || val == nil {
				continue
			}
			rows, err := selectPhysicalRows(ctx, db, table, map[string]any{col: val}, 1)
			if err != nil {
				return nil, err
			}
			if len(rows) > 0 {
				return rows[0], nil
			}
		}
	}
	// 4. Full-field match (last resort): exactly one of at most two rows.
	if len(encoded) > 0 {
		rows, err := selectPhysicalRows(ctx, db, table, encoded, 2)
		if err != nil {
			return nil, err
		}
		if len(rows) == 1 {
			return rows[0], nil
		}
	}
	return nil, nil
}

// selectPhysicalRows reads raw rows by physical column equality (nil matches
// IS NULL), ordered by column name for deterministic SQL.
func selectPhysicalRows(ctx context.Context, db bun.IDB, table string, equals map[string]any, limit int) ([]map[string]any, error) {
	q := db.NewSelect().TableExpr(table)
	for _, col := range sortedKeys(equals) {
		val := equals[col]
		if val == nil {
			q = q.Where("? IS NULL", bun.Ident(col))
		} else {
			q = q.Where("? = ?", bun.Ident(col), val)
		}
	}
	if limit > 0 {
		q = q.Limit(limit)
	}
	var rows []map[string]any
	if err := q.Scan(ctx, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

// isKnownOperator reports upstream whereOperators membership. The zero
// value "" is not upstream vocabulary; adapters normalize it (and unknown
// values, unless strict) to "eq".
func isKnownOperator(op authdb.Operator) bool {
	switch op {
	case authdb.OpEq, authdb.OpNe, authdb.OpLt, authdb.OpLte, authdb.OpGt,
		authdb.OpGte, authdb.OpIn, authdb.OpNotIn, authdb.OpContains,
		authdb.OpStartsWith, authdb.OpEndsWith:
		return true
	default:
		return false
	}
}

func (a *Adapter) FindOne(ctx context.Context, model string, where []authdb.Where, select_ []string) (map[string]any, error) {
	if err := a.validateModel(model); err != nil {
		return nil, fmt.Errorf("bun FindOne %s: %w", model, err)
	}
	table, err := a.tableName(model)
	if err != nil {
		return nil, fmt.Errorf("bun FindOne %s: %w", model, err)
	}
	row := map[string]any{}
	if err := a.requireDB("FindOne"); err != nil {
		return nil, err
	}
	q := a.db.NewSelect().TableExpr(table).Limit(1)
	clause, args, err := a.buildWhereClause(model, where, "findOne")
	if err != nil {
		return nil, fmt.Errorf("bun FindOne %s: %w", model, err)
	}
	if clause != "" {
		q = q.Where(clause, args...)
	}
	q, err = a.applySelect(q, model, select_)
	if err != nil {
		return nil, fmt.Errorf("bun FindOne %s: %w", model, err)
	}
	if err := q.Scan(ctx, &row); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("bun FindOne %s: %w", model, err)
	}
	decoded, err := a.decodeRow(model, row)
	if err != nil {
		return nil, fmt.Errorf("bun FindOne %s: %w", model, err)
	}
	return a.projectRow(model, decoded, select_), nil
}

func (a *Adapter) FindMany(ctx context.Context, model string, where []authdb.Where, limit, offset int, sortBy *authdb.SortBy, select_ []string) ([]map[string]any, error) {
	if err := a.validateModel(model); err != nil {
		return nil, fmt.Errorf("bun FindMany %s: %w", model, err)
	}
	table, err := a.tableName(model)
	if err != nil {
		return nil, fmt.Errorf("bun FindMany %s: %w", model, err)
	}
	var rows []map[string]any
	clause, args, err := a.buildWhereClause(model, where, "findMany")
	if err != nil {
		return nil, fmt.Errorf("bun FindMany %s: %w", model, err)
	}
	if err := a.requireDB("FindMany"); err != nil {
		return nil, err
	}
	q := a.db.NewSelect().TableExpr(table)
	if clause != "" {
		q = q.Where(clause, args...)
	}
	effectiveLimit := limit
	if effectiveLimit == 0 {
		effectiveLimit = defaultFindManyLimit
	}
	if effectiveLimit > 0 {
		q = q.Limit(effectiveLimit)
	}
	if offset > 0 {
		q = q.Offset(offset)
	}
	if sortBy != nil {
		if err := a.validateFields(model, []string{sortBy.Field}); err != nil {
			return nil, fmt.Errorf("bun FindMany %s: %w", model, err)
		}
		sortCol, err := a.colName(model, sortBy.Field)
		if err != nil {
			return nil, fmt.Errorf("bun FindMany %s: %w", model, err)
		}
		dir := "ASC"
		if strings.EqualFold(sortBy.Direction, "desc") {
			dir = "DESC"
		}
		q = q.OrderExpr("? ?", bun.Ident(sortCol), bun.Safe(dir))
	} else if offset > 0 && a.Dialect() == "mssql" {
		// MSSQL requires ORDER BY when OFFSET is used (port kysely
		// :645-653). Fall back to ordering by id.
		idCol, err := a.colName(model, "id")
		if err != nil {
			return nil, fmt.Errorf("bun FindMany %s: %w", model, err)
		}
		q = q.OrderExpr("? ?", bun.Ident(idCol), bun.Safe("ASC"))
	}
	q, err = a.applySelect(q, model, select_)
	if err != nil {
		return nil, fmt.Errorf("bun FindMany %s: %w", model, err)
	}
	if err := q.Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("bun FindMany %s: %w", model, err)
	}
	result := make([]map[string]any, len(rows))
	for i, r := range rows {
		decoded, err := a.decodeRow(model, r)
		if err != nil {
			return nil, fmt.Errorf("bun FindMany %s: %w", model, err)
		}
		result[i] = a.projectRow(model, decoded, select_)
	}
	return result, nil
}

func (a *Adapter) Count(ctx context.Context, model string, where []authdb.Where) (int, error) {
	if err := a.validateModel(model); err != nil {
		return 0, fmt.Errorf("bun Count %s: %w", model, err)
	}
	table, err := a.tableName(model)
	if err != nil {
		return 0, fmt.Errorf("bun Count %s: %w", model, err)
	}
	if err := a.requireDB("Count"); err != nil {
		return 0, err
	}
	q := a.db.NewSelect().TableExpr(table)
	clause, args, err := a.buildWhereClause(model, where, "count")
	if err != nil {
		return 0, fmt.Errorf("bun Count %s: %w", model, err)
	}
	if clause != "" {
		q = q.Where(clause, args...)
	}
	n, err := q.Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("bun Count %s: %w", model, err)
	}
	return n, nil
}

func (a *Adapter) Update(ctx context.Context, model string, where []authdb.Where, data map[string]any) (map[string]any, error) {
	// Upstream `update` targets a single row: empty predicates return null
	// without touching the database.
	if len(where) == 0 {
		return nil, nil
	}
	if err := a.validateModel(model); err != nil {
		return nil, fmt.Errorf("bun Update %s: %w", model, err)
	}
	encoded, err := a.transformInputData(model, data, "update")
	if err != nil {
		return nil, fmt.Errorf("bun Update %s: %w", model, err)
	}
	if len(encoded) == 0 {
		return a.FindOne(ctx, model, where, nil)
	}
	table, err := a.tableName(model)
	if err != nil {
		return nil, fmt.Errorf("bun Update %s: %w", model, err)
	}
	clause, args, err := a.buildWhereClause(model, where, "update")
	if err != nil {
		return nil, fmt.Errorf("bun Update %s: %w", model, err)
	}
	if err := a.requireDB("Update"); err != nil {
		return nil, err
	}
	setCols := sortedKeys(encoded)
	if a.supportsReturning() {
		q := a.db.NewUpdate().TableExpr(table).Returning("*")
		for _, col := range setCols {
			q = q.Set("? = ?", bun.Ident(col), encoded[col])
		}
		if clause != "" {
			q = q.Where(clause, args...)
		}
		// Note: single-row Update is best-effort (no LIMIT: PostgreSQL
		// UPDATE does not support it). Callers must use unique
		// predicates; the first returned row is decoded.
		row := map[string]any{}
		if err := q.Scan(ctx, &row); err != nil {
			if err == sql.ErrNoRows {
				return nil, nil
			}
			return nil, fmt.Errorf("bun Update %s: %w", model, err)
		}
		if len(row) == 0 {
			return nil, nil
		}
		decoded, err := a.decodeRow(model, row)
		if err != nil {
			return nil, fmt.Errorf("bun Update %s: %w", model, err)
		}
		return decoded, nil
	}
	// Dialects without RETURNING: update then read back a single row.
	// Reselect by the updated values (not the stale predicate): any where
	// field present in the update payload is replaced with its new value,
	// porting the kysely/drizzle reselect approach.
	q := a.db.NewUpdate().TableExpr(table)
	for _, col := range setCols {
		q = q.Set("? = ?", bun.Ident(col), encoded[col])
	}
	if clause != "" {
		q = q.Where(clause, args...)
	}
	if _, err := q.Exec(ctx); err != nil {
		return nil, fmt.Errorf("bun Update %s: %w", model, err)
	}
	reselect, err := a.reselectWhere(model, where, encoded)
	if err != nil {
		return nil, fmt.Errorf("bun Update %s: %w", model, err)
	}
	return a.FindOne(ctx, model, reselect, nil)
}

// reselectWhere rewrites where predicates that overlap the update payload to
// their new values so the post-update read targets the updated row.
func (a *Adapter) reselectWhere(model string, where []authdb.Where, encoded map[string]any) ([]authdb.Where, error) {
	out := make([]authdb.Where, len(where))
	for i, w := range where {
		col, err := a.colName(model, w.Field)
		if err != nil {
			return nil, err
		}
		if v, ok := encoded[col]; ok {
			w.Value = v
		}
		out[i] = w
	}
	return out, nil
}

func (a *Adapter) UpdateMany(ctx context.Context, model string, where []authdb.Where, data map[string]any) (int, error) {
	if err := a.validateModel(model); err != nil {
		return 0, fmt.Errorf("bun UpdateMany %s: %w", model, err)
	}
	encoded, err := a.transformInputData(model, data, "update")
	if err != nil {
		return 0, fmt.Errorf("bun UpdateMany %s: %w", model, err)
	}
	if len(encoded) == 0 {
		n, err := a.Count(ctx, model, where)
		if err != nil {
			return 0, fmt.Errorf("bun UpdateMany %s: %w", model, err)
		}
		return n, nil
	}
	table, err := a.tableName(model)
	if err != nil {
		return 0, fmt.Errorf("bun UpdateMany %s: %w", model, err)
	}
	clause, args, err := a.buildWhereClause(model, where, "updateMany")
	if err != nil {
		return 0, fmt.Errorf("bun UpdateMany %s: %w", model, err)
	}
	if err := a.requireDB("UpdateMany"); err != nil {
		return 0, err
	}
	if clause == "" {
		// Match-all bulk update: bun builders require at least one WHERE,
		// so an empty predicate compiles to a raw unqualified UPDATE
		// (documented match-all semantics; the singular Update path keeps
		// its empty-where guard instead).
		setCols := sortedKeys(encoded)
		setFrags := make([]string, 0, len(setCols))
		setArgs := make([]any, 0, len(setCols))
		for _, col := range setCols {
			setFrags = append(setFrags, quoteIdent(col)+` = ?`)
			setArgs = append(setArgs, encoded[col])
		}
		res, err := a.db.NewRaw(fmt.Sprintf(`UPDATE %s SET %s`, quoteIdent(table), strings.Join(setFrags, ", ")), setArgs...).Exec(ctx)
		if err != nil {
			return 0, fmt.Errorf("bun UpdateMany %s: %w", model, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("bun UpdateMany %s rows affected: %w", model, err)
		}
		return int(n), nil
	}
	q := a.db.NewUpdate().TableExpr(table)
	for _, col := range sortedKeys(encoded) {
		q = q.Set("? = ?", bun.Ident(col), encoded[col])
	}
	if clause != "" {
		q = q.Where(clause, args...)
	}
	res, err := q.Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("bun UpdateMany %s: %w", model, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("bun UpdateMany %s rows affected: %w", model, err)
	}
	return int(n), nil
}

func sortedKeys(m map[string]any) []string {
	cols := make([]string, 0, len(m))
	for col := range m {
		cols = append(cols, col)
	}
	sort.Strings(cols)
	return cols
}

// sortedFieldNames sorts registry field names for deterministic lookups.
func sortedFieldNames(m map[string]FieldDef) []string {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

func (a *Adapter) Delete(ctx context.Context, model string, where []authdb.Where) error {
	// Singular Delete mirrors Update's empty-where guard: empty predicates
	// do nothing. Whole-table deletes stay available via DeleteMany, which
	// treats empty where as match-all.
	if len(where) == 0 {
		return nil
	}
	if err := a.validateModel(model); err != nil {
		return fmt.Errorf("bun Delete %s: %w", model, err)
	}
	table, err := a.tableName(model)
	if err != nil {
		return fmt.Errorf("bun Delete %s: %w", model, err)
	}
	clause, args, err := a.buildWhereClause(model, where, "delete")
	if err != nil {
		return fmt.Errorf("bun Delete %s: %w", model, err)
	}
	if err := a.requireDB("Delete"); err != nil {
		return err
	}
	q := a.db.NewDelete().TableExpr(table)
	if clause != "" {
		q = q.Where(clause, args...)
	}
	if _, err := q.Exec(ctx); err != nil {
		return fmt.Errorf("bun Delete %s: %w", model, err)
	}
	return nil
}

// DeleteMany removes all matching rows and returns the affected count.
// An empty/nil where matches all rows (match-all semantics); use singular
// Delete (which no-ops on empty where) when a predicate is required.
func (a *Adapter) DeleteMany(ctx context.Context, model string, where []authdb.Where) (int, error) {
	if err := a.validateModel(model); err != nil {
		return 0, fmt.Errorf("bun DeleteMany %s: %w", model, err)
	}
	table, err := a.tableName(model)
	if err != nil {
		return 0, fmt.Errorf("bun DeleteMany %s: %w", model, err)
	}
	clause, args, err := a.buildWhereClause(model, where, "deleteMany")
	if err != nil {
		return 0, fmt.Errorf("bun DeleteMany %s: %w", model, err)
	}
	if err := a.requireDB("DeleteMany"); err != nil {
		return 0, err
	}
	if clause == "" {
		// Match-all bulk delete (documented semantics; the singular Delete
		// path keeps its empty-where guard instead).
		res, err := a.db.NewRaw(fmt.Sprintf(`DELETE FROM %s`, quoteIdent(table))).Exec(ctx)
		if err != nil {
			return 0, fmt.Errorf("bun DeleteMany %s: %w", model, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("bun DeleteMany %s rows affected: %w", model, err)
		}
		return int(n), nil
	}
	q := a.db.NewDelete().TableExpr(table)
	if clause != "" {
		q = q.Where(clause, args...)
	}
	res, err := q.Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("bun DeleteMany %s: %w", model, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("bun DeleteMany %s rows affected: %w", model, err)
	}
	return int(n), nil
}

// ConsumeOne atomically consumes a single row matching where.
//
// On PostgreSQL/SQLite it issues a single DELETE...RETURNING guarded to one
// row via ctid/rowid (DELETE...RETURNING on pg, locked fallback otherwise).
// Other dialects use a snapshot-guarded delete (read + id-guarded
// DeleteMany, returning the snapshot only when exactly one row was removed).
// Empty where returns (nil, nil) without touching the database.
// Upstream TypeScript name: consumeOne.
// consumeOneReturningQuery builds the single-row DELETE...RETURNING query:
// ctid-guarded on PostgreSQL, rowid-guarded on other RETURNING-capable
// dialects (SQLite). Extracted so SQL-generation tests can assert the
// per-dialect shape without a live database.
func consumeOneReturningQuery(dialect, table, clause string) string {
	quoted := quoteIdent(table)
	if isPostgresDialect(dialect) {
		return fmt.Sprintf(`DELETE FROM %s WHERE ctid = (SELECT ctid FROM %s WHERE %s LIMIT 1) RETURNING *`, quoted, quoted, clause)
	}
	return fmt.Sprintf(`DELETE FROM %s WHERE rowid = (SELECT rowid FROM %s WHERE %s LIMIT 1) RETURNING *`, quoted, quoted, clause)
}

// incrementOneReturningQuery builds the single-row UPDATE...RETURNING query
// with setList as the pre-quoted SET assignments. Extracted for
// SQL-generation tests alongside consumeOneReturningQuery.
func incrementOneReturningQuery(dialect, table, setList, clause string) string {
	quoted := quoteIdent(table)
	if isPostgresDialect(dialect) {
		return fmt.Sprintf(`UPDATE %s SET %s WHERE ctid = (SELECT ctid FROM %s WHERE %s LIMIT 1) RETURNING *`, quoted, setList, quoted, clause)
	}
	return fmt.Sprintf(`UPDATE %s SET %s WHERE rowid = (SELECT rowid FROM %s WHERE %s LIMIT 1) RETURNING *`, quoted, setList, quoted, clause)
}

// isPostgresDialect reports the PostgreSQL dialect family, backing both the
// LIKE/RETURNING decisions and the raw single-row guards.
func isPostgresDialect(dialect string) bool {
	switch dialect {
	case "pg", "postgres", "postgresql", "pgdialect":
		return true
	default:
		return false
	}
}

func (a *Adapter) ConsumeOne(ctx context.Context, model string, where []authdb.Where) (map[string]any, error) {
	if len(where) == 0 {
		return nil, nil
	}
	if err := a.validateModel(model); err != nil {
		return nil, fmt.Errorf("bun ConsumeOne %s: %w", model, err)
	}
	table, err := a.tableName(model)
	if err != nil {
		return nil, fmt.Errorf("bun ConsumeOne %s: %w", model, err)
	}
	clause, args, err := a.buildWhereClause(model, where, "consumeOne")
	if err != nil {
		return nil, fmt.Errorf("bun ConsumeOne %s: %w", model, err)
	}
	if err := a.requireDB("ConsumeOne"); err != nil {
		return nil, err
	}
	if a.supportsReturning() {
		query := consumeOneReturningQuery(a.Dialect(), table, clause)
		// Stale-guard recovery (see returningGuardRetries): a concurrent
		// writer can move the row between the guard subselect and the
		// delete, matching nothing while the row still exists. Re-read to
		// tell a genuine miss (nil, nil) from a stale guard; on
		// PostgreSQL the row-lock slow path resolves it deterministically.
		for attempt := 0; attempt < returningGuardRetries; attempt++ {
			row, err := execReturningFast(ctx, a.db, query, args)
			if err != nil {
				return nil, fmt.Errorf("bun ConsumeOne %s: %w", model, err)
			}
			if row != nil {
				decoded, err := a.decodeRow(model, row)
				if err != nil {
					return nil, fmt.Errorf("bun ConsumeOne %s: %w", model, err)
				}
				return decoded, nil
			}
			still, err := a.FindOne(ctx, model, where, nil)
			if err != nil {
				return nil, err
			}
			if still == nil {
				return nil, nil
			}
			if a.pgLockedPathAvailable() {
				locked, err := a.pgLockedConsume(ctx, table, clause, args)
				if err != nil {
					return nil, fmt.Errorf("bun ConsumeOne %s: %w", model, err)
				}
				if locked == nil {
					return nil, nil
				}
				decoded, err := a.decodeRow(model, locked)
				if err != nil {
					return nil, fmt.Errorf("bun ConsumeOne %s: %w", model, err)
				}
				return decoded, nil
			}
		}
		return nil, fmt.Errorf("bun ConsumeOne %s: could not consume the row due to contention (retry the operation)", model)
	}
	// Locked fallback: snapshot-guarded delete.
	row, err := a.FindOne(ctx, model, where, nil)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, nil
	}
	id, ok := row["id"]
	if !ok || id == nil {
		return nil, fmt.Errorf("bun ConsumeOne %s: adapter must return the row id for atomic fallbacks", model)
	}
	guard := consumeGuard(where, id)
	n, err := a.DeleteMany(ctx, model, guard)
	if err != nil {
		return nil, err
	}
	if n != 0 && n != 1 {
		return nil, fmt.Errorf("bun ConsumeOne %s: adapter must return an affected row count of 0 or 1, got %d", model, n)
	}
	if n == 0 {
		return nil, nil
	}
	return row, nil
}

// consumeGuard builds the snapshot guard for the fallback consume: the
// original where plus an id equality, or id-only when an OR is present (to
// avoid widening the selector). Keys stay logical; DeleteMany maps them.
func consumeGuard(where []authdb.Where, id any) []authdb.Where {
	for _, w := range where {
		if strings.EqualFold(w.Connector, "OR") {
			return []authdb.Where{{Field: "id", Value: id}}
		}
	}
	guard := make([]authdb.Where, 0, len(where)+1)
	guard = append(guard, where...)
	guard = append(guard, authdb.Where{Field: "id", Value: id})
	return guard
}

func isORConnector(s string) bool { return strings.EqualFold(s, "OR") }

func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// IncrementOne atomically applies guarded counter deltas to a single row.
//
// On PostgreSQL/SQLite it issues a single UPDATE...RETURNING guarded to one
// row via ctid/rowid, re-executed (bounded) when a concurrent writer moves
// the row and the guard goes stale; a re-read distinguishes a genuine miss
// (nil, nil) from contention. Other dialects use bounded compare-and-swap retries
// (read, compute, id+snapshot-guarded UpdateMany, retry on contention, up to
// 5 attempts). Empty increment+set is an error. Empty where matches nothing
// (nil, nil). Upstream TypeScript name: incrementOne.
func (a *Adapter) IncrementOne(ctx context.Context, model string, where []authdb.Where, increment map[string]int, set map[string]any) (map[string]any, error) {
	if len(increment) == 0 && len(set) == 0 {
		return nil, fmt.Errorf("bun IncrementOne %s: incrementOne requires a non-empty `increment` or `set`; both were empty", model)
	}
	if len(where) == 0 {
		return nil, nil
	}
	if err := a.validateModel(model); err != nil {
		return nil, fmt.Errorf("bun IncrementOne %s: %w", model, err)
	}
	if err := a.validateFields(model, incrementFieldNames(increment, set)); err != nil {
		return nil, fmt.Errorf("bun IncrementOne %s: %w", model, err)
	}
	// Absolute `set` assignments run through the update input transforms
	// (mirroring the factory, which transformInputs set with "update",
	// including onUpdate synthesis for absent fields). Keys stay logical;
	// both the RETURNING and CAS paths map them to columns.
	transformedSet, err := a.transformSetValues(model, set)
	if err != nil {
		return nil, fmt.Errorf("bun IncrementOne %s: %w", model, err)
	}
	encodedSet := make(map[string]any, len(transformedSet))
	for logical, v := range transformedSet {
		col, err := a.colName(model, logical)
		if err != nil {
			return nil, fmt.Errorf("bun IncrementOne %s: %w", model, err)
		}
		encodedSet[col] = v
	}
	table, err := a.tableName(model)
	if err != nil {
		return nil, fmt.Errorf("bun IncrementOne %s: %w", model, err)
	}
	if err := a.requireDB("IncrementOne"); err != nil {
		return nil, err
	}
	if a.supportsReturning() {
		clause, whereArgs, err := a.buildWhereClause(model, where, "incrementOne")
		if err != nil {
			return nil, fmt.Errorf("bun IncrementOne %s: %w", model, err)
		}
		// Deterministic SET order: increments (sorted logical keys) then
		// sets (sorted physical columns).
		var setFrags []string
		var setArgs []any
		for _, logical := range sortedStringKeys(increment) {
			col, err := a.colName(model, logical)
			if err != nil {
				return nil, fmt.Errorf("bun IncrementOne %s: %w", model, err)
			}
			setFrags = append(setFrags, quoteIdent(col)+` = `+quoteIdent(col)+` + ?`)
			setArgs = append(setArgs, increment[logical])
		}
		for _, col := range sortedKeys(encodedSet) {
			setFrags = append(setFrags, quoteIdent(col)+` = ?`)
			setArgs = append(setArgs, encodedSet[col])
		}
		if len(setFrags) == 0 {
			return nil, fmt.Errorf("bun IncrementOne %s: incrementOne resolved to an empty update", model)
		}
		query := incrementOneReturningQuery(a.Dialect(), table, strings.Join(setFrags, ", "), clause)
		args := append(append([]any(nil), setArgs...), whereArgs...)
		// Stale-guard recovery (see returningGuardRetries): concurrent
		// increments serialize on the row lock while each waiter's pinned
		// ctid/rowid goes stale, so the statement can match nothing even
		// though the row exists. Re-read to tell a genuine miss (nil, nil)
		// from a stale guard; on PostgreSQL the row-lock slow path
		// resolves it deterministically.
		for attempt := 0; attempt < returningGuardRetries; attempt++ {
			row, err := execReturningFast(ctx, a.db, query, args)
			if err != nil {
				return nil, fmt.Errorf("bun IncrementOne %s: %w", model, err)
			}
			if row != nil {
				decoded, err := a.decodeRow(model, row)
				if err != nil {
					return nil, fmt.Errorf("bun IncrementOne %s: %w", model, err)
				}
				return decoded, nil
			}
			still, err := a.FindOne(ctx, model, where, nil)
			if err != nil {
				return nil, err
			}
			if still == nil {
				return nil, nil
			}
			if a.pgLockedPathAvailable() {
				locked, err := a.pgLockedIncrement(ctx, table, strings.Join(setFrags, ", "), clause, setArgs, whereArgs)
				if err != nil {
					return nil, fmt.Errorf("bun IncrementOne %s: %w", model, err)
				}
				if locked == nil {
					return nil, nil
				}
				decoded, err := a.decodeRow(model, locked)
				if err != nil {
					return nil, fmt.Errorf("bun IncrementOne %s: %w", model, err)
				}
				return decoded, nil
			}
		}
		return nil, fmt.Errorf("bun IncrementOne %s: could not complete an atomic increment due to contention (retry the operation)", model)
	}
	// CAS fallback with bounded retries.
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		row, err := a.FindOne(ctx, model, where, nil)
		if err != nil {
			return nil, err
		}
		if row == nil {
			return nil, nil
		}
		update, err := computeIncrementUpdate(row, increment, transformedSet)
		if err != nil {
			return nil, fmt.Errorf("bun IncrementOne %s: %w", model, err)
		}
		if isNoopUpdate(row, update) {
			return row, nil
		}
		guard := incrementGuard(model, a, row, where, increment, transformedSet)
		n, err := a.UpdateMany(ctx, model, guard, update)
		if err != nil {
			return nil, err
		}
		if n != 0 && n != 1 {
			return nil, fmt.Errorf("bun IncrementOne %s: adapter must return an affected row count of 0 or 1, got %d", model, n)
		}
		if n == 1 {
			merged := make(map[string]any, len(row)+len(update))
			for k, v := range row {
				merged[k] = v
			}
			for k, v := range update {
				merged[k] = v
			}
			// update keys are logical; rows are logical.
			return merged, nil
		}
		lastErr = fmt.Errorf("contention")
	}
	return nil, fmt.Errorf("bun IncrementOne %s: could not complete an atomic increment due to contention (retry the operation): %v", model, lastErr)
}

func sortedStringKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// incrementFieldNames collects the logical fields an increment touches for
// strict membership validation.
func incrementFieldNames(increment map[string]int, set map[string]any) []string {
	names := make([]string, 0, len(increment)+len(set))
	for k := range increment {
		names = append(names, k)
	}
	for k := range set {
		names = append(names, k)
	}
	return names
}

// transformSetValues runs absolute `set` assignments through the update
// input transforms with logical keys preserved (factory transformInputs set
// with "update", including onUpdate synthesis for absent fields). It backs
// IncrementOne on both the RETURNING and CAS paths.
func (a *Adapter) transformSetValues(model string, set map[string]any) (map[string]any, error) {
	if !a.strict() && a.opts.CustomTransformInput == nil {
		out := make(map[string]any, len(set))
		for k, v := range set {
			out[k] = v
		}
		return out, nil
	}
	if err := a.validateModel(model); err != nil {
		return nil, err
	}
	md, _ := a.modelDef(model)
	caps := a.caps()
	out := make(map[string]any, len(set)+len(md.Fields))
	for k, v := range set {
		def, ok := md.Fields[k]
		if !ok {
			if k == "id" {
				def = FieldDef{}
			} else {
				return nil, &authdb.InvalidFieldError{Model: model, Field: k}
			}
		}
		nv, err := a.applyInputValue(model, k, v, def, "update", true, caps)
		if err != nil {
			return nil, err
		}
		out[k] = nv
	}
	for k, def := range md.Fields {
		if _, present := set[k]; present {
			continue
		}
		if def.OnUpdate == nil {
			continue
		}
		nv, err := a.applyInputValue(model, k, resolveDefault(def.OnUpdate), def, "update", false, caps)
		if err != nil {
			return nil, err
		}
		out[k] = nv
	}
	return out, nil
}

// computeIncrementUpdate applies deltas to a snapshot row, returning the
// update map (logical keys) with absolute values. Nil counters start at 0.
func computeIncrementUpdate(row map[string]any, increment map[string]int, set map[string]any) (map[string]any, error) {
	update := make(map[string]any, len(increment)+len(set))
	for logical, delta := range increment {
		// Rows are logical camelCase.
		old, ok := row[logical]
		var cur float64
		var hasNum bool
		if !ok || old == nil {
			cur, hasNum = 0, true
		} else {
			cur, hasNum = toNumber(old)
		}
		if !hasNum {
			return nil, fmt.Errorf("counter field %q must be numeric or null, got %#v", logical, old)
		}
		next := cur + float64(delta)
		if !isFiniteNumber(next) || (delta != 0 && next == cur) {
			return nil, fmt.Errorf("cannot represent counter increment for field %q safely", logical)
		}
		// Preserve integer shape when possible.
		if isIntegral(cur) && delta == int(float64(delta)) {
			update[logical] = int(next)
		} else {
			update[logical] = next
		}
	}
	for k, v := range set {
		update[k] = v
	}
	return update, nil
}

func toNumber(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int8:
		return float64(n), true
	case int16:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint:
		return float64(n), true
	case uint8:
		return float64(n), true
	case uint16:
		return float64(n), true
	case uint32:
		return float64(n), true
	case uint64:
		return float64(n), true
	case float32:
		return float64(n), true
	case float64:
		return n, true
	default:
		return 0, false
	}
}

func isFiniteNumber(f float64) bool {
	// Avoid importing math for a single check: NaN != itself, Inf bounds.
	return f == f && f < 1e308 && f > -1e308
}

func isIntegral(f float64) bool { return f == float64(int64(f)) }

func isNoopUpdate(row map[string]any, update map[string]any) bool {
	for logical, v := range update {
		old, ok := row[logical]
		if !ok {
			return false
		}
		if !valuesEqual(old, v) {
			return false
		}
	}
	return true
}

func valuesEqual(a, b any) bool {
	// Numeric-aware equality for counters; otherwise deep-ish via == for scalars.
	an, aok := toNumber(a)
	bn, bok := toNumber(b)
	if aok && bok {
		return an == bn
	}
	return fmt.Sprintf("%#v", a) == fmt.Sprintf("%#v", b)
}

// incrementGuard builds the CAS guard: id plus old scalar values for
// touched fields, or id-only when an OR is present. A missing id reads as
// nil, which matches no row (fail-closed guard).
func incrementGuard(model string, a *Adapter, row map[string]any, where []authdb.Where, increment map[string]int, set map[string]any) []authdb.Where {
	_, ok := row["id"]
	id := row["id"]
	_ = model
	for _, w := range where {
		if isORConnector(w.Connector) {
			return []authdb.Where{{Field: "id", Value: id}}
		}
	}
	guard := make([]authdb.Where, 0, len(where)+len(increment)+len(set)+1)
	guard = append(guard, where...)
	if ok && id != nil {
		guard = append(guard, authdb.Where{Field: "id", Value: id})
	}
	// Snapshot touched fields with scalar values to detect races.
	touched := make([]string, 0, len(increment)+len(set))
	for k := range increment {
		touched = append(touched, k)
	}
	for k := range set {
		touched = append(touched, k)
	}
	sort.Strings(touched)
	seen := map[string]struct{}{"id": {}}
	for _, logical := range touched {
		if _, dup := seen[logical]; dup {
			continue
		}
		seen[logical] = struct{}{}
		if v, ok := row[logical]; ok {
			if _, isNum := toNumber(v); isNum || v == nil || isScalar(v) {
				guard = append(guard, authdb.Where{Field: logical, Value: v})
			}
		}
	}
	return guard
}

func isScalar(v any) bool {
	switch v.(type) {
	case string, bool:
		return true
	default:
		if _, ok := toNumber(v); ok {
			return true
		}
		return false
	}
}

// --- joins ---
//
// FindOneWithJoin/FindManyWithJoin implement authdb.Joiner with the
// factory's fallback strategy (handleFallbackJoin): the base row is read
// first, then each joined model is queried separately by the resolved
// foreign key. Joined rows attach under the requested join key (null for
// empty one-to-one, empty array for empty one-to-many). Foreign keys resolve
// from the field registry exactly like upstream's transformJoinClause: a
// forward key (joined model references the base) wins, otherwise a backward
// key (base references the joined model); zero or multiple keys are an
// error. Unique joins cap at 1 row, others at the requested limit
// (DefaultFindManyLimit when unset).

// resolvedJoin is one validated join: logical model/column names plus the
// effective limit and relation.
type resolvedJoin struct {
	joinModel   string
	fromLogical string
	toLogical   string
	limit       int
	relation    authdb.JoinRelation
}

func (a *Adapter) FindOneWithJoin(ctx context.Context, model string, where []authdb.Where, select_ []string, join authdb.JoinOption) (map[string]any, error) {
	if len(join) == 0 {
		return a.FindOne(ctx, model, where, select_)
	}
	base, err := a.FindOne(ctx, model, where, nil)
	if err != nil {
		return nil, err
	}
	if base == nil {
		return nil, nil
	}
	merged, err := a.attachJoins(ctx, model, base, join)
	if err != nil {
		return nil, err
	}
	return a.projectJoinRow(model, merged, select_, join), nil
}

func (a *Adapter) FindManyWithJoin(ctx context.Context, model string, where []authdb.Where, limit, offset int, sortBy *authdb.SortBy, select_ []string, join authdb.JoinOption) ([]map[string]any, error) {
	if len(join) == 0 {
		return a.FindMany(ctx, model, where, limit, offset, sortBy, select_)
	}
	rows, err := a.FindMany(ctx, model, where, limit, offset, sortBy, nil)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		merged, err := a.attachJoins(ctx, model, row, join)
		if err != nil {
			return nil, err
		}
		out = append(out, a.projectJoinRow(model, merged, select_, join))
	}
	return out, nil
}

// projectJoinRow applies the logical select projection to base fields while
// preserving attached join keys (mirroring upstream, which filters the base
// output but keeps joined models).
func (a *Adapter) projectJoinRow(model string, merged map[string]any, select_ []string, join authdb.JoinOption) map[string]any {
	if len(select_) == 0 {
		return merged
	}
	base := make(map[string]any, len(merged))
	attached := make(map[string]any, len(join))
	for k, v := range merged {
		if _, isJoin := join[k]; isJoin {
			attached[k] = v
		} else {
			base[k] = v
		}
	}
	out := a.projectRow(model, base, select_)
	for k, v := range attached {
		out[k] = v
	}
	return out
}

// attachJoins resolves join and runs one fallback query per joined model.
func (a *Adapter) attachJoins(ctx context.Context, baseModel string, base map[string]any, join authdb.JoinOption) (map[string]any, error) {
	resolved, err := a.resolveJoins(baseModel, join)
	if err != nil {
		return nil, err
	}
	out := make(map[string]any, len(base)+len(resolved))
	for k, v := range base {
		out[k] = v
	}
	for _, key := range sortedKeysJoin(resolved) {
		r := resolved[key]
		fromVal := base[r.fromLogical]
		if fromVal == nil {
			// A missing join key means the select omitted it or the row is
			// empty: upstream returns null/empty rather than querying.
			if r.relation == authdb.JoinOneToOne {
				out[key] = nil
			} else {
				out[key] = []map[string]any{}
			}
			continue
		}
		w := []authdb.Where{{Field: r.toLogical, Value: fromVal}}
		if r.relation == authdb.JoinOneToOne {
			row, err := a.FindOne(ctx, r.joinModel, w, nil)
			if err != nil {
				return nil, err
			}
			out[key] = row
		} else {
			rows, err := a.FindMany(ctx, r.joinModel, w, r.limit, 0, nil, nil)
			if err != nil {
				return nil, err
			}
			if rows == nil {
				rows = []map[string]any{}
			}
			out[key] = rows
		}
	}
	return out, nil
}

func sortedKeysJoin(m map[string]resolvedJoin) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// resolveJoins validates the requested joins against the field registry,
// mirroring upstream transformJoinClause (forward key first, then backward;
// exactly one key required; unique joins collapse to one-to-one/limit 1).
func (a *Adapter) resolveJoins(baseModel string, join authdb.JoinOption) (map[string]resolvedJoin, error) {
	if len(join) == 0 {
		return nil, nil
	}
	if !a.strict() {
		return nil, fmt.Errorf("bun: joins require a registered model schema (Options.Models) for model %q", baseModel)
	}
	if _, ok := a.opts.Models[baseModel]; !ok {
		return nil, &authdb.InvalidModelError{Model: baseModel}
	}
	resolved := make(map[string]resolvedJoin, len(join))
	for _, key := range sortedJoinKeys(join) {
		opt := join[key]
		joinMD, ok := a.opts.Models[key]
		if !ok {
			return nil, &authdb.InvalidModelError{Model: key}
		}
		baseMD := a.opts.Models[baseModel]
		// Forward: joined model holds the FK to the base model.
		type fkHit struct {
			field string
			def   FieldDef
		}
		var forward []fkHit
		for field, def := range joinMD.Fields {
			if def.References != nil && def.References.Model == baseModel {
				forward = append(forward, fkHit{field, def})
			}
		}
		var fromLogical, toLogical string
		var fkDef FieldDef
		if len(forward) > 0 {
			if len(forward) > 1 {
				return nil, fmt.Errorf("bun: multiple foreign keys found for model %s and base model %s while performing join operation. Only one foreign key is supported.", key, baseModel)
			}
			fkDef = forward[0].def
			refField := fkDef.References.Field
			if refField == "" {
				refField = "id"
			}
			fromLogical = refField
			toLogical = forward[0].field
		} else {
			// Backward: base model holds the FK to the joined model.
			var backward []fkHit
			for field, def := range baseMD.Fields {
				if def.References != nil && def.References.Model == key {
					backward = append(backward, fkHit{field, def})
				}
			}
			if len(backward) == 0 {
				return nil, fmt.Errorf("bun: no foreign key found for model %s and base model %s while performing join operation.", key, baseModel)
			}
			if len(backward) > 1 {
				return nil, fmt.Errorf("bun: multiple foreign keys found for model %s and base model %s while performing join operation. Only one foreign key is supported.", key, baseModel)
			}
			fkDef = backward[0].def
			refField := fkDef.References.Field
			if refField == "" {
				refField = "id"
			}
			fromLogical = backward[0].field
			toLogical = refField
		}
		isUnique := toLogical == "id" || fkDef.Unique
		relation := authdb.JoinOneToMany
		limit := opt.JoinLimit()
		if isUnique {
			relation = authdb.JoinOneToOne
			limit = 1
		}
		resolved[key] = resolvedJoin{joinModel: key, fromLogical: fromLogical, toLogical: toLogical, limit: limit, relation: relation}
	}
	return resolved, nil
}

func sortedJoinKeys(join authdb.JoinOption) []string {
	keys := make([]string, 0, len(join))
	for k := range join {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (a *Adapter) Transaction(ctx context.Context, fn func(tx authdb.Adapter) error) error {
	if a.raw == nil {
		// Transaction-incapable store (offline/unit-test adapter): run the
		// callback directly against the adapter, mirroring upstream's
		// sequential fallback (createAsIsTransaction). This is explicitly
		// non-atomic; callers needing atomicity must provide a live *bun.DB.
		return fn(a)
	}
	// Nested transactions run in a savepoint via bun's Tx.RunInTx (which
	// issues SAVEPOINT/RELEASE/ROLLBACK TO, or SAVE TRANSACTION on MSSQL),
	// so inner failures roll back to the savepoint without aborting the
	// outer transaction. This replaces the previous nested-transaction
	// error: upstream adapters scope nested work to the ambient
	// transaction rather than rejecting it.
	if tx, ok := a.db.(bun.Tx); ok {
		return tx.RunInTx(ctx, nil, func(ctx context.Context, ntx bun.Tx) error {
			return fn(&Adapter{db: ntx, raw: a.raw, cfg: a.cfg, dialect: a.Dialect(), opts: a.opts, inTx: true})
		})
	}
	if ptx, ok := a.db.(*bun.Tx); ok {
		return ptx.RunInTx(ctx, nil, func(ctx context.Context, ntx bun.Tx) error {
			return fn(&Adapter{db: ntx, raw: a.raw, cfg: a.cfg, dialect: a.Dialect(), opts: a.opts, inTx: true})
		})
	}
	if a.inTx {
		return fmt.Errorf("bun Transaction: nested transaction without a live bun.Tx")
	}
	return a.raw.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		txAdapter := &Adapter{db: tx, raw: a.raw, cfg: a.cfg, dialect: a.Dialect(), opts: a.opts, inTx: true}
		return fn(txAdapter)
	})
}

// --- where clause helpers ---

// buildWhereClause is the single helper lowering Where predicates to one
// parenthesized SQL clause plus args. It validates in/not_in values (typed
// error otherwise), maps empty IN to no-rows (1 = 0) and empty NOT IN to
// all-rows (1 = 1), coerces values to the registered field types when a
// model registry is present (see coerceWhereValue), and partitions clauses
// into an AND-group (missing/AND) and an OR-group (OR), emitting
// (AND-group) AND (OR-group) per upstream.
func (a *Adapter) buildWhereClause(model string, where []authdb.Where, action string) (string, []any, error) {
	if len(where) == 0 {
		return "", nil, nil
	}
	var andFrags []string
	var andArgs []any
	var orFrags []string
	var orArgs []any
	for _, w := range where {
		isOR := strings.EqualFold(w.Connector, "OR")
		if w.Operator == authdb.OpIn || w.Operator == authdb.OpNotIn {
			if !isSliceValue(w.Value) {
				return "", nil, &InvalidWhereError{Field: w.Field, Operator: w.Operator, Reason: "Value must be an array/slice"}
			}
			if isEmptySliceValue(w.Value) {
				if w.Operator == authdb.OpIn {
					// Empty IN matches no rows.
					if isOR {
						orFrags = append(orFrags, "1 = 0")
					} else {
						andFrags = append(andFrags, "1 = 0")
					}
				} else {
					// Empty NOT IN matches all rows.
					if isOR {
						orFrags = append(orFrags, "1 = 1")
					} else {
						andFrags = append(andFrags, "1 = 1")
					}
				}
				continue
			}
		}
		coerced, err := a.coerceWhereValue(model, w, action)
		if err != nil {
			return "", nil, err
		}
		w.Value = coerced
		op, col, val, err := a.resolveWhere(model, w)
		if err != nil {
			return "", nil, err
		}
		frag, args := whereFragment(op, col, val)
		if isOR {
			orFrags = append(orFrags, frag)
			orArgs = append(orArgs, args...)
		} else {
			andFrags = append(andFrags, frag)
			andArgs = append(andArgs, args...)
		}
	}
	switch {
	case len(andFrags) > 0 && len(orFrags) > 0:
		andSQL := strings.Join(andFrags, " AND ")
		orSQL := strings.Join(orFrags, " OR ")
		return "(" + andSQL + ") AND (" + orSQL + ")", append(andArgs, orArgs...), nil
	case len(andFrags) > 0:
		return strings.Join(andFrags, " AND "), andArgs, nil
	case len(orFrags) > 0:
		return strings.Join(orFrags, " OR "), orArgs, nil
	default:
		return "", nil, nil
	}
}

// whereFragment maps a resolved (op, col, value) triple to a SQL fragment
// plus args. Identifiers go through bun.Ident; values through placeholders.
func whereFragment(op, col string, val any) (string, []any) {
	switch op {
	case "IS NULL", "IS NOT NULL":
		return "? " + op, []any{bun.Ident(col)}
	case "LOWER_LIKE":
		pattern, _ := val.(string)
		return "LOWER(?) LIKE LOWER(?)", []any{bun.Ident(col), pattern}
	case "LOWER_EQ":
		return "LOWER(?) = LOWER(?)", []any{bun.Ident(col), val}
	case "LOWER_NE":
		return "LOWER(?) != LOWER(?)", []any{bun.Ident(col), val}
	case "LOWER_IN":
		return "LOWER(?) IN (?)", []any{bun.Ident(col), bun.List(val)}
	case "LOWER_NOT_IN":
		return "LOWER(?) NOT IN (?)", []any{bun.Ident(col), bun.List(val)}
	default:
		return "? " + op, []any{bun.Ident(col), val}
	}
}

// resolveWhere maps a logical Where clause to (sqlOp, physicalCol, value).
// It returns "IS NULL"/"IS NOT NULL" for nil equality, "LOWER_LIKE" for
// portable case-insensitive patterns, "LOWER_EQ"/"LOWER_NE"/"LOWER_IN"/
// "LOWER_NOT_IN" for case-insensitive string comparisons, and
// "LIKE ?"/"ILIKE ?" for patterns otherwise (ILIKE only for pg-insensitive;
// sensitive is LIKE on all dialects including pg).
func (a *Adapter) resolveWhere(model string, w authdb.Where) (string, string, any, error) {
	col, err := a.colName(model, w.Field)
	if err != nil {
		return "", "", nil, err
	}
	insensitive := strings.EqualFold(w.Mode, "insensitive")
	switch w.Operator {
	case authdb.OpNe:
		if w.Value == nil {
			return "IS NOT NULL", col, nil, nil
		}
		if insensitive {
			if s, ok := w.Value.(string); ok {
				return "LOWER_NE", col, s, nil
			}
		}
		return "!= ?", col, w.Value, nil
	case authdb.OpLt:
		return "< ?", col, w.Value, nil
	case authdb.OpLte:
		return "<= ?", col, w.Value, nil
	case authdb.OpGt:
		return "> ?", col, w.Value, nil
	case authdb.OpGte:
		return ">= ?", col, w.Value, nil
	case authdb.OpIn:
		if insensitive {
			if lowered, ok := lowerStringSlice(w.Value); ok {
				return "LOWER_IN", col, lowered, nil
			}
		}
		return "IN (?)", col, bun.List(w.Value), nil
	case authdb.OpNotIn:
		if insensitive {
			if lowered, ok := lowerStringSlice(w.Value); ok {
				return "LOWER_NOT_IN", col, lowered, nil
			}
		}
		return "NOT IN (?)", col, bun.List(w.Value), nil
	case authdb.OpContains, authdb.OpStartsWith, authdb.OpEndsWith:
		pattern := likePattern(w.Operator, w.Value)
		if insensitive {
			if a.isPostgres() {
				return "ILIKE ?", col, pattern, nil
			}
			return "LOWER_LIKE", col, pattern, nil
		}
		return "LIKE ?", col, pattern, nil
	default:
		if w.Value == nil {
			return "IS NULL", col, nil, nil
		}
		if insensitive {
			if s, ok := w.Value.(string); ok {
				return "LOWER_EQ", col, s, nil
			}
		}
		return "= ?", col, w.Value, nil
	}
}

func isSliceValue(v any) bool {
	if v == nil {
		return false
	}
	kind := reflect.ValueOf(v).Kind()
	return kind == reflect.Slice || kind == reflect.Array
}

func isEmptySliceValue(v any) bool {
	if v == nil {
		return false
	}
	rv := reflect.ValueOf(v)
	return (rv.Kind() == reflect.Slice || rv.Kind() == reflect.Array) && rv.Len() == 0
}

// lowerStringSlice lowers a slice/array of strings, returning the lowered
// []string and true only when every element is a string.
func lowerStringSlice(v any) (any, bool) {
	if v == nil {
		return nil, false
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array {
		return nil, false
	}
	if rv.Len() == 0 {
		return nil, false
	}
	out := make([]string, 0, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		elem := rv.Index(i)
		if elem.Kind() == reflect.Interface && !elem.IsNil() {
			elem = elem.Elem()
		}
		if elem.Kind() != reflect.String {
			return nil, false
		}
		out = append(out, strings.ToLower(elem.String()))
	}
	return out, true
}

func likePattern(op authdb.Operator, value any) string {
	s := fmt.Sprintf("%v", value)
	switch op {
	case authdb.OpContains:
		return "%" + s + "%"
	case authdb.OpStartsWith:
		return s + "%"
	case authdb.OpEndsWith:
		return "%" + s
	default:
		return s
	}
}

func (a *Adapter) encodeRow(model string, data map[string]any) (map[string]any, error) {
	out := make(map[string]any, len(data))
	for k, v := range data {
		col, err := a.colName(model, k)
		if err != nil {
			return nil, err
		}
		out[col] = v
	}
	return out, nil
}

// decodeRow maps physical columns to logical camelCase keys per contract
// (transformOutput): custom FieldNames reverse to logical, default snake
// folds via snakeToCamel, and values revive per field type (ids stringify;
// JSON/array strings parse when the store lacks native support; date
// strings parse; 0/1 revive to bools when the store lacks native support).
// Unknown columns pass through unchanged (an intentional deviation from the
// factory, which drops off-schema keys, so extra selected columns survive).
// Upstream TypeScript name: transformOutput (key part).
func (a *Adapter) decodeRow(model string, row map[string]any) (map[string]any, error) {
	if len(row) == 0 {
		return row, nil
	}
	reverse := map[string]string{}
	prefix := model + "."
	for key, physical := range a.cfg.FieldNames {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		logical := strings.TrimPrefix(key, prefix)
		reverse[physical] = logical
	}
	out := make(map[string]any, len(row))
	for k, v := range row {
		logical, ok := reverse[k]
		if !ok {
			logical = snakeToCamel(k)
		}
		revived, err := a.reviveField(model, logical, v)
		if err != nil {
			return nil, err
		}
		out[logical] = revived
	}
	return out, nil
}

// reviveField ports factory transformOutput for one logical value: custom
// field output first, then id stringification (ids always read back as
// strings, even with numeric ids), JSON/array revival on stores without
// native support, date revival, boolean revival on stores without native
// support, and finally the custom output hook.
func (a *Adapter) reviveField(model, logical string, v any) (any, error) {
	def, known := a.fieldDef(model, logical)
	if !known {
		// Unregistered field (extra selected column or lenient adapter):
		// legacy revival.
		return reviveValue(logical, v), nil
	}
	if def.Transform != nil && def.Transform.Output != nil {
		nv, err := def.Transform.Output(v)
		if err != nil {
			return nil, &authdb.InvalidValueError{Model: model, Field: logical, Reason: err.Error()}
		}
		v = nv
	}
	caps := a.caps()
	if logical == "id" || isIDReference(logical, def) {
		// Even with numeric ids, output is always a string id.
		if v != nil {
			if _, ok := v.(string); !ok {
				v = fmt.Sprintf("%v", v)
			}
		}
	} else if !caps.SupportsJSON && def.Type == FieldTypeJSON {
		if s, ok := v.(string); ok {
			v = safeJSONParse(s)
		}
	} else if !caps.SupportsArrays && (def.Type == FieldTypeStringArray || def.Type == FieldTypeNumberArray) {
		if s, ok := v.(string); ok {
			v = safeJSONParse(s)
		}
	} else if def.Type == FieldTypeDate {
		if s, ok := v.(string); ok {
			if parsed, err := parseDateTime(s); err == nil {
				v = parsed
			}
		}
	} else if !caps.SupportsBooleans && def.Type == FieldTypeBoolean {
		if n, ok := toNumber(v); ok {
			v = n == 1
		}
	}
	if a.opts.CustomTransformOutput != nil {
		v = a.opts.CustomTransformOutput(TransformContext{Model: model, Field: logical, Action: "findOne", Def: def}, v)
	}
	return v, nil
}

// reviveValue revives logical field values per contract: ids always return
// as strings (even with numeric ids); other types pass through (pg/sqlite
// return native JSON/dates/bools, so no string parsing is needed; custom
// transforms remain manual).
func reviveValue(logical string, v any) any {
	if logical == "id" && v != nil {
		if _, ok := v.(string); !ok {
			return fmt.Sprintf("%v", v)
		}
	}
	return v
}

// projectRow filters a decoded (logical) row to the logical select set.
// An empty select returns the row unchanged.
func (a *Adapter) projectRow(_ string, row map[string]any, sel []string) map[string]any {
	if len(sel) == 0 || row == nil {
		return row
	}
	keep := map[string]struct{}{}
	for _, field := range sel {
		if field == "" {
			continue
		}
		keep[field] = struct{}{}
	}
	out := make(map[string]any, len(keep))
	for k, v := range row {
		if _, ok := keep[k]; ok {
			out[k] = v
		}
	}
	return out
}

func snakeToCamel(s string) string {
	var b strings.Builder
	upperNext := false
	for i, r := range s {
		if r == '_' {
			upperNext = i > 0
			continue
		}
		if upperNext && r >= 'a' && r <= 'z' {
			b.WriteRune(r - ('a' - 'A'))
			upperNext = false
			continue
		}
		upperNext = false
		b.WriteRune(r)
	}
	return b.String()
}

func camelToSnake(s string) string {
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
