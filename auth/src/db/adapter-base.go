// Package db defines the framework-agnostic database contract used by auth.
// Concrete adapters live under auth/adapters and auth itself has no Brick
// dependency, so it can be mounted on any Huma-compatible HTTP stack.
//
// File boundary: this file is auth/src/db/adapter-base.go, mirroring the
// upstream src/db/adapter-base.ts boundary. It additionally carries the full
// Adapter contract (upstream @better-auth/core db/adapter), which has no
// narrower Go file yet.
//
// Row-key contract: rows exchanged with callers use logical camelCase keys
// (for example "userId", "emailVerified") with type revival per contract
// (ids stringified; native JSON/dates/bools pass through). The public
// adapter API accepts logical camelCase fields on input (Where.Field,
// Create/Update data keys, select entries, SortBy.Field) and maps them to
// physical columns via Config.FieldNames (explicit overrides) with a
// camelToSnake fallback. Custom FieldNames reverse to logical on reads
// (transformOutput key part). See PARITY_V2.md.
//
// Upstream-divergence summary (see Adapter for per-method detail):
//   - No join parameter on FindOne/FindMany (upstream JoinOption/JoinConfig).
//   - Transaction returns only error (upstream returns generic R) and has no
//     sequential fallback for transaction-incapable stores.
//   - FindMany has no automatic limit default; pass DefaultFindManyLimit
//     explicitly to match upstream's default of 100.
//   - Connector/Mode/Direction fields remain plain strings for backward
//     compatibility; unknown values silently normalize to defaults (AND,
//     sensitive, ASC). The Connector, WhereMode, and SortDirection kinds
//     document the valid vocabulary and provide Normalize helpers for new code.
package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Operator is a where-clause comparison operator.
//
// Vocabulary is 1:1 with upstream's whereOperators
// ("eq", "ne", "lt", "lte", "gt", "gte", "in", "not_in", "contains",
// "starts_with", "ends_with"). The zero value ("") is NOT an upstream value;
// adapters normalize it to "eq" (see Where.Operator). Unknown non-empty
// operators are also treated as "eq" by current adapters instead of erroring;
// callers should only use the constants below.
type Operator string

const (
	OpEq         Operator = "eq"
	OpNe         Operator = "ne"
	OpLt         Operator = "lt"
	OpLte        Operator = "lte"
	OpGt         Operator = "gt"
	OpGte        Operator = "gte"
	OpIn         Operator = "in"
	OpNotIn      Operator = "not_in"
	OpContains   Operator = "contains"
	OpStartsWith Operator = "starts_with"
	OpEndsWith   Operator = "ends_with"

	// Short aliases match Better Auth's adapter vocabulary.
	Eq         = OpEq
	Ne         = OpNe
	Lt         = OpLt
	Lte        = OpLte
	Gt         = OpGt
	Gte        = OpGte
	In         = OpIn
	NotIn      = OpNotIn
	Contains   = OpContains
	StartsWith = OpStartsWith
	EndsWith   = OpEndsWith
)

// DefaultFindManyLimit documents upstream's findMany limit default.
//
// Upstream resolves the effective limit as
// `unsafeLimit ?? options.advanced.database.defaultFindManyLimit ?? 100`
// (see vendor/better-auth/packages/core/src/db/adapter/factory.ts), and join
// fallback queries default to the same 100 when no per-join limit applies.
//
// This contract does NOT apply the default automatically: Adapter.FindMany
// passes limit through as-is and the bun adapter maps limit == 0 to
// DefaultFindManyLimit while a negative limit requests an explicitly
// unbounded read. Callers that need every row (e.g. hook fan-out) pass a
// negative limit; callers that want upstream parity pass
// DefaultFindManyLimit explicitly when no limit is specified. The constant is
// provided so call sites share one documented value; method signatures are
// unchanged.
const DefaultFindManyLimit = 100

// Connector is the valid Where.Connector vocabulary ("AND", "OR").
//
// It is a distinct kind for documentation and for new code that wants a
// typed value. Where.Connector itself remains a plain string for backward
// compatibility (existing callers pass untyped literals like Connector:"OR",
// the empty string, or string variables, and adapters compare with
// strings.EqualFold), so assigning a Connector variable to Where.Connector
// still requires an explicit string() conversion and passing Where.Connector
// to string parameters requires string() as well. Unknown or empty values
// silently normalize to AND (only EqualFold("OR") selects OR); use
// NormalizeConnector or (Connector).Normalize to validate.
type Connector string

const (
	// ConnectorAND is the default conjunction. The zero value "" normalizes
	// to this (upstream default "AND").
	ConnectorAND = "AND"
	// ConnectorOR selects disjunction when EqualFold(value, "OR").
	ConnectorOR = "OR"
)

// Normalize maps any input to the effective connector: "OR"
// (case-insensitive) yields ConnectorOR, everything else (including "" and
// garbage) yields ConnectorAND, matching current adapter behavior.
func NormalizeConnector(s string) Connector {
	if strings.EqualFold(s, ConnectorOR) {
		return Connector(ConnectorOR)
	}
	return Connector(ConnectorAND)
}

// Normalize reports the effective connector for c.
func (c Connector) Normalize() Connector {
	return NormalizeConnector(string(c))
}

// IsValid reports whether c is exactly "AND" or "OR" (case-insensitive).
// Empty and unknown values are invalid but still normalize to AND.
func (c Connector) IsValid() bool {
	return strings.EqualFold(string(c), ConnectorAND) || strings.EqualFold(string(c), ConnectorOR)
}

// WhereMode is the valid Where.Mode vocabulary ("sensitive", "insensitive").
//
// Where.Mode itself remains a plain string for backward compatibility; the
// untyped WhereModeSensitive/WhereModeInsensitive constants below stay usable
// as both string and WhereMode. Unknown or empty values silently normalize
// to sensitive (only EqualFold("insensitive") selects insensitive); use
// NormalizeWhereMode or (WhereMode).Normalize to validate.
//
// Upstream default (documented): "sensitive".
type WhereMode string

const (
	// WhereModeSensitiveKind is the typed spelling of the default mode.
	// WhereModeSensitive (untyped, below) remains the canonical literal for
	// string fields; this typed alias serves WhereMode-typed code.
	WhereModeSensitiveKind WhereMode = "sensitive"
	// WhereModeInsensitiveKind is the typed spelling of case-insensitive mode.
	WhereModeInsensitiveKind WhereMode = "insensitive"
)

// NormalizeWhereMode maps any input to the effective mode: "insensitive"
// (case-insensitive) yields insensitive, everything else (including "" and
// garbage) yields sensitive, matching current adapter behavior.
func NormalizeWhereMode(s string) WhereMode {
	if strings.EqualFold(s, WhereModeInsensitive) {
		return WhereModeInsensitiveKind
	}
	return WhereModeSensitiveKind
}

// Normalize reports the effective mode for m.
func (m WhereMode) Normalize() WhereMode {
	return NormalizeWhereMode(string(m))
}

// IsValid reports whether m is exactly "sensitive" or "insensitive"
// (case-insensitive). Empty and unknown values are invalid but still
// normalize to sensitive.
func (m WhereMode) IsValid() bool {
	return strings.EqualFold(string(m), WhereModeSensitive) || strings.EqualFold(string(m), WhereModeInsensitive)
}

// SortDirection is the valid SortBy.Direction vocabulary ("asc", "desc").
//
// SortBy.Direction itself remains a plain string for backward compatibility
// (existing callers pass string variables and adapters compare with
// strings.EqualFold), so assigning a SortDirection variable to
// SortBy.Direction still requires an explicit string() conversion. Unknown
// or empty values silently normalize to ASC (only EqualFold("desc") selects
// DESC); use NormalizeSortDirection or (SortDirection).Normalize to validate.
//
// Upstream type (documented): "asc" | "desc".
type SortDirection string

const (
	// SortDirectionAsc selects ascending order.
	SortDirectionAsc = "asc"
	// SortDirectionDesc selects descending order when EqualFold(value, "desc").
	SortDirectionDesc = "desc"
)

// NormalizeSortDirection maps any input to the effective direction: "desc"
// (case-insensitive) yields desc, everything else (including "" and garbage)
// yields asc, matching current adapter behavior.
func NormalizeSortDirection(s string) SortDirection {
	if strings.EqualFold(s, SortDirectionDesc) {
		return SortDirection(SortDirectionDesc)
	}
	return SortDirection(SortDirectionAsc)
}

// Normalize reports the effective direction for d.
func (d SortDirection) Normalize() SortDirection {
	return NormalizeSortDirection(string(d))
}

// IsValid reports whether d is exactly "asc" or "desc" (case-insensitive).
// Empty and unknown values are invalid but still normalize to asc.
func (d SortDirection) IsValid() bool {
	return strings.EqualFold(string(d), SortDirectionAsc) || strings.EqualFold(string(d), SortDirectionDesc)
}

// Where comparison modes, mirroring better-auth's `mode` field.
// "sensitive" is the default. "insensitive" requests case-insensitive
// string matching. Adapters that cannot honor "insensitive" natively must
// document the fallback they use.
//
// These constants are intentionally untyped string constants so they remain
// assignable to both the plain-string Where.Mode field and the WhereMode
// kind. Empty Mode means "sensitive" (upstream default); any other unknown
// value also behaves as "sensitive" instead of erroring.
const (
	WhereModeSensitive   = "sensitive"
	WhereModeInsensitive = "insensitive"
)

// Where is a partial mirror of Better Auth's adapter Where type.
//
// Divergences from upstream (intentional, documented here instead of
// claiming parity):
//   - Connector and Mode are plain strings (not "AND"|"OR" /
//     "sensitive"|"insensitive" unions). Only EqualFold("OR") selects OR
//     (everything else, including "" and garbage, behaves as AND); only
//     EqualFold("insensitive") selects insensitive (everything else behaves
//     as sensitive). See Connector, WhereMode, and the Normalize helpers.
//   - Operator zero value "" is not upstream vocabulary; adapters normalize
//     it (and any unknown operator) to "eq" instead of erroring.
//   - Value is any, wider than upstream's
//     string|number|boolean|string[]|number[]|Date|null. Callers should
//     restrict themselves to that narrow set (plus nil for IS NULL/IS NOT
//     NULL with eq/ne); other types are silently misparsed (pattern ops
//     stringify via %v, in/not_in pass through to bun.List without element
//     validation, dates/bools rely on adapter coercion).
//   - Upstream applies operator="in" validation ("Value must be an array")
//     in the factory; this contract performs no validation.
type Where struct {
	Field string `json:"field"`
	// Value is intentionally any (see Where docs): restrict to upstream's
	// string|number|boolean|string[]|number[]|time.Time|null subset. nil with
	// eq matches IS NULL; nil with ne matches IS NOT NULL.
	Value     any      `json:"value"`
	Operator  Operator `json:"operator,omitempty"`
	Connector string   `json:"connector,omitempty"`
	// Mode selects case sensitivity for string comparisons.
	// Empty means "sensitive" (upstream default). Unknown values also behave
	// as "sensitive" instead of erroring; see WhereMode.
	Mode string `json:"mode,omitempty"`
}

// SortBy is a partial mirror of upstream's findMany sortBy
// ({ field: string; direction: "asc" | "desc" }).
//
// Direction remains a plain string for backward compatibility. Only
// EqualFold(direction, "desc") selects DESC; empty and unknown values
// silently behave as ASC. See SortDirection and NormalizeSortDirection.
type SortBy struct {
	Field     string `json:"field"`
	Direction string `json:"direction"`
}

// Adapter is the database contract implemented by ORM-specific adapters.
//
// Partial mirror of better-auth's factory-wrapped adapter (NOT full parity).
// Known divergences from upstream, in addition to the snake_case row-key
// contract documented on package db:
//   - No join support: FindOne/FindMany take no join parameter, unlike
//     upstream's JoinOption/JoinConfig (with fallback separate queries when
//     advanced.database.joins is off). Callers needing related rows must
//     issue separate queries. Join-capable adapters additionally implement
//     the optional Joiner interface (separate-query fallback joins resolved
//     from the adapter's field registry); see JoinOption and JoinConfig.
//   - Transaction is error-only with no sequential fallback: upstream's
//     transaction callback returns generic R and, when the store has no
//     transaction implementation (config.transaction false), runs the
//     callback directly against the adapter (sequential fallback). Here the
//     callback returns only error and adapters must provide a real
//     transaction (bun RunInTx); there is no sequential fallback and no
//     return-value channel.
//   - FindMany limit has no automatic default: upstream defaults to
//     options.advanced.database.defaultFindManyLimit ?? 100, but this
//     contract passes limit through as-is and current adapters treat
//     limit <= 0 as unbounded. Pass DefaultFindManyLimit for parity.
//   - Config below is only a name/field map, not upstream's capability
//     object (supportsJSON/supportsDates/transaction/etc.). Capability flags
//     live in the separate Capabilities value, reported by adapters that
//     implement the optional CapabilityReporter interface.
//
// Shared semantics (matching better-auth's factory-wrapped adapter where
// stated, adapter-enforced otherwise):
//   - select entries are logical field names. Adapters apply the projection
//     and return rows filtered to the selected columns (in logical-key
//     shape). An empty/nil select returns the full row.
//   - Update targets a single row: empty where returns (nil, nil) without
//     touching the database; no matching row returns (nil, nil) and no error.
//   - UpdateMany/DeleteMany return the affected row count (0 when nothing
//     matched). UpdateMany/DeleteMany must return a finite count.
//   - FindOne returns (nil, nil) when nothing matches.
//   - contains/starts_with/ends_with are case-sensitive LIKE by default.
//     ILIKE is a PostgreSQL-only optimization; portable adapters use
//     LOWER(col) LIKE LOWER(?) for insensitive mode and LIKE otherwise.
//   - eq with a nil value matches IS NULL; ne with nil matches IS NOT NULL.
type Adapter interface {
	// Create inserts one row and returns it (projected to select when
	// non-empty). select entries are logical field names; empty/nil select
	// returns the full row in logical shape. No join support.
	Create(context.Context, string, map[string]any, []string) (map[string]any, error)
	// FindOne returns the first matching row or (nil, nil) when nothing
	// matches. No join support: related rows are never included; issue
	// separate queries. select follows the Adapter projection rule.
	FindOne(context.Context, string, []Where, []string) (map[string]any, error)
	// FindMany returns matching rows. limit <= 0 is currently unbounded
	// (no LIMIT clause); pass DefaultFindManyLimit (100) for upstream
	// parity — signatures are frozen so the default is NOT applied here.
	// offset <= 0 means no offset; nil sortBy means database order. No join
	// support. select follows the Adapter projection rule.
	FindMany(context.Context, string, []Where, int, int, *SortBy, []string) ([]map[string]any, error)
	// Count returns the number of rows matching where.
	Count(context.Context, string, []Where) (int, error)
	// Update targets a single row: empty where returns (nil, nil) without
	// touching the database; no matching row returns (nil, nil) and no
	// error. This is NOT the race-safe guarded-update primitive; use
	// IncrementOne for guarded counter transitions.
	Update(context.Context, string, []Where, map[string]any) (map[string]any, error)
	// UpdateMany applies update to all matching rows and returns the
	// affected count (0 when nothing matched, always finite).
	UpdateMany(context.Context, string, []Where, map[string]any) (int, error)
	// Delete removes a single row's worth of matches. Empty where returns nil
	// without touching the database (unlike upstream delete, which deletes
	// every row; use DeleteMany for intentional bulk deletes). This is the
	// whole-table guard for the singular path: pass explicit predicates.
	Delete(context.Context, string, []Where) error
	// DeleteMany removes all matching rows and returns the affected count
	// (0 when nothing matched, always finite). For single-use destructive
	// reads under concurrency, use ConsumeOne: it deletes at most one row
	// atomically, while DeleteMany may delete every matching row.
	DeleteMany(context.Context, string, []Where) (int, error)
	// ConsumeOne atomically consumes a single row matching where: it deletes
	// at most one row and returns it, or (nil, nil) when nothing matched.
	// Under concurrent invocation against the same row, exactly one caller
	// receives the row; racers receive (nil, nil). This is the race-safe
	// primitive for single-use credentials (verification tokens,
	// authorization codes). Upstream TypeScript name: consumeOne.
	ConsumeOne(context.Context, string, []Where) (map[string]any, error)
	// IncrementOne atomically applies signed numeric deltas to a single row
	// matching where (`field = field + delta` per increment entry; negative
	// deltas decrement) plus absolute assignments from set, in one step.
	// Where is both selector AND guard (comparison operators honored); when
	// the guard matches no row, it makes no change and returns (nil, nil).
	// At least one of increment/set must be non-empty, else an error.
	// Returns the updated row. Upstream TypeScript name: incrementOne.
	IncrementOne(context.Context, string, []Where, map[string]int, map[string]any) (map[string]any, error)
	// Transaction runs fn inside a real database transaction. Error-only
	// (upstream returns generic R) with no sequential fallback for
	// transaction-incapable stores: fn must return its result via closure
	// capture, and adapters must fail (not silently run non-atomically) when
	// transactions are unavailable.
	Transaction(context.Context, func(Adapter) error) error
}

// Config maps Better Auth model/field names to database names.
//
// Name-collision note: upstream's capability object is also called "config"
// (AdapterFactoryConfig: adapterId, supportsJSON, supportsDates,
// transaction, usePlural, ...). This Config is NOT that object; it carries
// only name/field mappings and no capability flags.
//
// Silent pass-through: ModelName/FieldName return their input unchanged when
// no mapping exists; unknown models/fields are never validated and never
// error. Callers must not rely on these helpers to detect typos or to
// enforce schema membership.
type Config struct {
	ModelNames map[string]string
	FieldNames map[string]string
}

func (c Config) ModelName(model string) string {
	if name, ok := c.ModelNames[model]; ok {
		return name
	}
	return model
}

func (c Config) FieldName(model, field string) string {
	if name, ok := c.FieldNames[model+"."+field]; ok {
		return name
	}
	return field
}

// Capabilities carries the adapter capability flags, mirroring upstream's
// AdapterFactoryConfig capability subset (packages/core/src/db/adapter).
//
// Upstream factory defaults (ported by DefaultCapabilities): supportsDates,
// supportsBooleans, and supportsNumericIds default to true; supportsJSON,
// supportsArrays, and supportsUUIDs default to false. Concrete adapters may
// report dialect-specific values (for example a SQLite adapter reports
// SupportsBooleans/SupportsDates false, matching the kysely adapter's
// per-dialect matrix) and use them to drive input/output transforms.
type Capabilities struct {
	// AdapterID identifies the adapter ("bun", ...).
	AdapterID string
	// AdapterName is the human-readable adapter name.
	AdapterName string
	// SupportsJSON reports native JSON column support. When false, adapters
	// stringify JSON values on write and parse them on read.
	SupportsJSON bool
	// SupportsDates reports native date/timestamp support. When false,
	// adapters persist dates as ISO-8601 strings and revive them on read.
	SupportsDates bool
	// SupportsBooleans reports native boolean support. When false, adapters
	// persist booleans as 0/1 and revive them on read.
	SupportsBooleans bool
	// SupportsArrays reports native array column support. When false,
	// adapters persist string[]/number[] as JSON strings.
	SupportsArrays bool
	// SupportsNumericIDs reports auto-increment/serial ID support.
	SupportsNumericIDs bool
	// SupportsUUIDs reports native UUID generation support.
	SupportsUUIDs bool
	// UsePlural reports pluralized physical table names.
	UsePlural bool
}

// DefaultCapabilities returns the upstream factory capability defaults:
// dates, booleans, and numeric IDs are supported; JSON, arrays, and UUIDs
// are not; table names are singular unless the adapter pluralizes.
func DefaultCapabilities() Capabilities {
	return Capabilities{
		SupportsDates:      true,
		SupportsBooleans:   true,
		SupportsNumericIDs: true,
	}
}

// CapabilityReporter is an optional interface for adapters that report
// their capability flags. It is separate from Adapter so existing
// implementations keep compiling; capability-aware callers type-assert.
type CapabilityReporter interface {
	Capabilities() Capabilities
}

// JoinRelation is the valid join cardinality vocabulary, mirroring
// upstream's JoinConfig relation ("one-to-one" | "one-to-many").
//
// Upstream also declares "many-to-many" in the type, but the factory only
// ever produces "one-to-one" (unique/1-row joins) and "one-to-many"; this
// contract matches that effective vocabulary.
type JoinRelation string

const (
	// JoinOneToOne yields a single joined object (or null).
	JoinOneToOne JoinRelation = "one-to-one"
	// JoinOneToMany yields an array of joined objects.
	JoinOneToMany JoinRelation = "one-to-many"
)

// IsValid reports whether r is a known join relation.
func (r JoinRelation) IsValid() bool {
	return r == JoinOneToOne || r == JoinOneToMany
}

// JoinModelOption configures the join of one model, mirroring upstream's
// per-model JoinOption value (boolean | { limit?: number }): the zero value
// enables the join with the default row cap; Limit overrides it for
// one-to-many joins (ignored for one-to-one, which always returns 1 row).
type JoinModelOption struct {
	Limit *int
}

// JoinLimit returns the effective row cap for option o: the configured
// limit, or DefaultFindManyLimit (100, matching upstream's join fallback
// default) when unset.
func (o JoinModelOption) JoinLimit() int {
	if o.Limit != nil {
		return *o.Limit
	}
	return DefaultFindManyLimit
}

// JoinOption mirrors upstream's JoinOption: each key names a logical model
// to join, each value configures that join.
type JoinOption map[string]JoinModelOption

// JoinOn names the join columns, mirroring upstream JoinConfig on
// ({ from, to }): From is the base-model column, To the joined-model column.
type JoinOn struct {
	From string
	To   string
}

// JoinSpec is one resolved join, mirroring upstream's JoinConfig entry
// ({ on: { from, to }, limit, relation }).
type JoinSpec struct {
	On       JoinOn
	Limit    int
	Relation JoinRelation
}

// JoinConfig mirrors upstream's JoinConfig: physical joined-model name to
// resolved join spec.
type JoinConfig map[string]JoinSpec

// Joiner is an optional interface for adapters with join support,
// mirroring upstream's join-enabled FindOne/FindMany. It is separate from
// Adapter (whose signatures are frozen) so existing implementations keep
// compiling; join-aware callers type-assert. Like upstream's fallback path,
// implementations may resolve joins with separate queries; joined rows
// attach under the requested join key.
type Joiner interface {
	Adapter
	// FindOneWithJoin returns the first matching row with joined models
	// attached under their join keys (null/empty when nothing joined).
	FindOneWithJoin(ctx context.Context, model string, where []Where, select_ []string, join JoinOption) (map[string]any, error)
	// FindManyWithJoin returns matching rows with joined models attached
	// under their join keys.
	FindManyWithJoin(ctx context.Context, model string, where []Where, limit, offset int, sortBy *SortBy, select_ []string, join JoinOption) ([]map[string]any, error)
}

// InvalidModelError reports an unknown model name on a strict adapter
// (one with a registered model/field schema, mirroring upstream's
// getFieldAttributes "Field ... not found in model ..." validation).
type InvalidModelError struct {
	Model string
}

func (e *InvalidModelError) Error() string {
	return fmt.Sprintf("db: unknown model %q", e.Model)
}

// InvalidFieldError reports an unknown field name on a strict adapter.
type InvalidFieldError struct {
	Model string
	Field string
}

func (e *InvalidFieldError) Error() string {
	return fmt.Sprintf("db: unknown field %q for model %q", e.Field, e.Model)
}

// InvalidValueError reports a value that cannot be coerced to the field
// type on a strict adapter (for example an unparseable date string, or a
// non-slice value for in/not_in).
type InvalidValueError struct {
	Model  string
	Field  string
	Reason string
}

func (e *InvalidValueError) Error() string {
	return fmt.Sprintf("db: invalid value for field %q of model %q: %s", e.Field, e.Model, e.Reason)
}

// InvalidIdentifierError reports a configured (or derived) table/column
// identifier that is not a safe SQL identifier. Adapters must reject such
// identifiers instead of interpolating them into raw SQL.
type InvalidIdentifierError struct {
	Name string
	Kind string
}

func (e *InvalidIdentifierError) Error() string {
	return fmt.Sprintf("db: invalid %s identifier %q: must match [A-Za-z_][A-Za-z0-9_]* (one optional schema qualifier)", e.Kind, e.Name)
}

// ValidateIdentifier reports whether name is a safe SQL identifier: one or
// two dot-separated parts (optional schema qualifier), each matching
// [A-Za-z_][A-Za-z0-9_]*. It mirrors the identifier trust boundary the
// SQL adapters enforce on configured ModelNames/FieldNames before
// interpolating them into raw table expressions.
func ValidateIdentifier(name string) error {
	parts := strings.Split(name, ".")
	if len(parts) < 1 || len(parts) > 2 {
		return &InvalidIdentifierError{Name: name, Kind: "identifier"}
	}
	for _, part := range parts {
		if !isIdentifierPart(part) {
			return &InvalidIdentifierError{Name: name, Kind: "identifier"}
		}
	}
	return nil
}

func isIdentifierPart(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (i > 0 && c >= '0' && c <= '9') {
			continue
		}
		return false
	}
	return true
}

// DuplicateKeyError is the typed constraint-violation error for unique /
// primary-key conflicts, porting the duplicate detection the upstream
// reserveVerificationValue needs without matching adapter-specific errors
// at the call site (internal-adapter.ts re-reads the row instead).
//
// Adapters map their driver errors to this type at the adapter layer
// (see MapDuplicateKeyError; the bun adapter maps Create failures), so
// route code can branch on IsDuplicateKeyError instead of string-matching
// wrapped driver errors. It unwraps to the original driver error.
type DuplicateKeyError struct {
	// Model is the logical model the conflicting write targeted.
	Model string
	// Cause is the original driver error.
	Cause error
}

func (e *DuplicateKeyError) Error() string {
	if e == nil {
		return "db: duplicate key"
	}
	if e.Cause == nil {
		return fmt.Sprintf("db: duplicate key on %q", e.Model)
	}
	return fmt.Sprintf("db: duplicate key on %q: %v", e.Model, e.Cause)
}

// Unwrap returns the original driver error.
func (e *DuplicateKeyError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// IsDuplicateKeyError reports whether err (through %w wrapping) is a typed
// unique/primary-key conflict. Routes map this to conflict responses.
func IsDuplicateKeyError(err error) bool {
	if err == nil {
		return false
	}
	var dup *DuplicateKeyError
	return errors.As(err, &dup)
}

// MapDuplicateKeyError maps a driver constraint-violation error to a typed
// *DuplicateKeyError, passing anything else (including nil) through
// unchanged. Already-typed errors pass through as-is.
//
// Matched codes/phrases (case-insensitive), one per supported dialect:
//   - PostgreSQL 23505 (unique_violation) / "duplicate key";
//   - SQLite SQLITE_CONSTRAINT gated on a uniqueness signal ("unique",
//     "primary key", extended codes 1555/1552; see isDuplicateKeyMessage),
//     plus "unique/primary key constraint failed" for drivers that omit the
//     code prefix (SQLITE_CONSTRAINT alone also covers NOT NULL/CHECK/FOREIGN
//     KEY, so it never matches by itself);
//   - MySQL 1062 (ER_DUP_ENTRY) / "duplicate entry";
//   - MSSQL 2601 (unique index) / 2627 (unique constraint/PK).
//
// Matching is string-based so adapters stay import-free of driver packages;
// see isDuplicateKeyMessage for the exact rules.
func MapDuplicateKeyError(model string, err error) error {
	if err == nil {
		return nil
	}
	var dup *DuplicateKeyError
	if errors.As(err, &dup) {
		return err
	}
	if isDuplicateKeyMessage(err.Error()) {
		return &DuplicateKeyError{Model: model, Cause: err}
	}
	return err
}

// isDuplicateKeyMessage reports whether a driver error string describes a
// unique/primary-key conflict. Comparison is case-insensitive.
func isDuplicateKeyMessage(msg string) bool {
	lowered := strings.ToLower(msg)
	// Strong per-dialect codes/phrases.
	for _, needle := range []string{
		"23505",                         // PostgreSQL unique_violation (SQLSTATE).
		"duplicate key",                 // PostgreSQL "duplicate key value ..." / MSSQL "cannot insert duplicate key ...".
		"duplicate entry",               // MySQL ER_DUP_ENTRY text.
		"1062",                          // MySQL ER_DUP_ENTRY code.
		"2601",                          // MSSQL unique-index violation.
		"2627",                          // MSSQL unique-constraint/PK violation.
		"unique constraint failed",      // SQLite (no code prefix).
		"primary key constraint failed", // SQLite PK (no code prefix).
	} {
		if strings.Contains(lowered, needle) {
			return true
		}
	}
	// SQLite SQLITE_CONSTRAINT alone is ambiguous (also NOT NULL/CHECK/
	// FOREIGN KEY), so it only counts with a uniqueness signal: the code
	// names or the extended codes 1555 (UNIQUE) / 1552 (PRIMARYKEY).
	if strings.Contains(lowered, "sqlite_constraint") || strings.Contains(lowered, "constraint failed") {
		for _, signal := range []string{"unique", "primary key", "1555", "1552"} {
			if strings.Contains(lowered, signal) {
				return true
			}
		}
	}
	return false
}
