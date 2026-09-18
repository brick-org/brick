package types

import authdb "github.com/brick-org/brick/auth/src/db"

// Adapter types are defined in db and re-exported here to keep the public
// Options surface aligned with Better Auth's types package.
//
// Every exported symbol in auth/db/adapter-base.go is reachable via this package
// (type alias, constant, or function re-export), so types is the single
// public import for the adapter contract. Method sets on aliased types
// (Adapter, Config, Connector, WhereMode, SortDirection) come along with
// the alias; there is no wrapper to drift.
//
// Upstream TypeScript names (vendor/better-auth/packages/core/src/db/adapter):
// WhereOperator/Where -> WhereOperator/Where, DBAdapter -> Adapter,
// SortBy direction "asc"|"desc" -> SortDirection, the factory limit default
// (100) -> DefaultFindManyLimit.
//
// Join absence: upstream FindOne/FindMany accept JoinOption (resolved to
// JoinConfig by the factory, with separate-query fallback when
// advanced.database.joins is off). This contract has no join parameter and
// no JoinOption/JoinConfig equivalent; callers needing related rows issue
// separate queries. See auth/db.Adapter for the full divergence list.
type (
	// Operator is a where-clause comparison operator ("eq", "ne", ...).
	//
	// Upstream TypeScript name: WhereOperator
	// (packages/core/src/db/adapter/index.ts).
	Operator = authdb.Operator
	// WhereOperator is the historical alias for Operator, matching
	// upstream's WhereOperator name directly.
	WhereOperator = authdb.Operator
	// Connector is the valid Where.Connector vocabulary ("AND", "OR").
	Connector = authdb.Connector
	// WhereMode is the valid Where.Mode vocabulary
	// ("sensitive", "insensitive").
	WhereMode = authdb.WhereMode
	// SortDirection is the valid SortBy.Direction vocabulary
	// ("asc", "desc").
	SortDirection = authdb.SortDirection
	// Where is a partial mirror of Better Auth's adapter Where type.
	Where = authdb.Where
	// SortBy is a partial mirror of upstream's findMany sortBy.
	SortBy = authdb.SortBy
	// Adapter is the database contract implemented by ORM-specific adapters.
	Adapter = authdb.Adapter
	// AdapterConfig maps Better Auth model/field names to database names.
	//
	// Upstream name note: this is NOT upstream's AdapterFactoryConfig
	// capability object; see auth/db.Config.
	AdapterConfig = authdb.Config
)

const (
	OpEq         = authdb.OpEq
	OpNe         = authdb.OpNe
	OpLt         = authdb.OpLt
	OpLte        = authdb.OpLte
	OpGt         = authdb.OpGt
	OpGte        = authdb.OpGte
	OpIn         = authdb.OpIn
	OpNotIn      = authdb.OpNotIn
	OpContains   = authdb.OpContains
	OpStartsWith = authdb.OpStartsWith
	OpEndsWith   = authdb.OpEndsWith
)

// Short operator aliases match Better Auth's adapter vocabulary.
const (
	Eq         = authdb.Eq
	Ne         = authdb.Ne
	Lt         = authdb.Lt
	Lte        = authdb.Lte
	Gt         = authdb.Gt
	Gte        = authdb.Gte
	In         = authdb.In
	NotIn      = authdb.NotIn
	Contains   = authdb.Contains
	StartsWith = authdb.StartsWith
	EndsWith   = authdb.EndsWith
)

// DefaultFindManyLimit documents upstream's findMany limit default
// (options.advanced.database.defaultFindManyLimit ?? 100). The contract
// does not apply it automatically; pass it explicitly for upstream parity.
const DefaultFindManyLimit = authdb.DefaultFindManyLimit

const (
	// ConnectorAND is the default conjunction (upstream default "AND").
	ConnectorAND = authdb.ConnectorAND
	// ConnectorOR selects disjunction.
	ConnectorOR = authdb.ConnectorOR
)

const (
	// WhereModeSensitiveKind is the typed spelling of the default mode.
	WhereModeSensitiveKind = authdb.WhereModeSensitiveKind
	// WhereModeInsensitiveKind is the typed spelling of case-insensitive mode.
	WhereModeInsensitiveKind = authdb.WhereModeInsensitiveKind
	// WhereModeSensitive is the canonical literal for string fields
	// (upstream default). Unknown/empty Mode values behave as sensitive.
	WhereModeSensitive = authdb.WhereModeSensitive
	// WhereModeInsensitive requests case-insensitive string matching.
	WhereModeInsensitive = authdb.WhereModeInsensitive
)

const (
	// SortDirectionAsc selects ascending order (upstream "asc").
	SortDirectionAsc = authdb.SortDirectionAsc
	// SortDirectionDesc selects descending order (upstream "desc").
	SortDirectionDesc = authdb.SortDirectionDesc
)

// NormalizeConnector maps any input to the effective connector ("OR"
// case-insensitive yields ConnectorOR, everything else ConnectorAND),
// matching current adapter behavior.
func NormalizeConnector(s string) Connector {
	return authdb.NormalizeConnector(s)
}

// NormalizeWhereMode maps any input to the effective mode ("insensitive"
// case-insensitive yields insensitive, everything else sensitive), matching
// current adapter behavior.
func NormalizeWhereMode(s string) WhereMode {
	return authdb.NormalizeWhereMode(s)
}

// NormalizeSortDirection maps any input to the effective direction ("desc"
// case-insensitive yields desc, everything else asc), matching current
// adapter behavior.
func NormalizeSortDirection(s string) SortDirection {
	return authdb.NormalizeSortDirection(s)
}
