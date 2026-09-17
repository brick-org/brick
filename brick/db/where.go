package db

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/uptrace/bun"
)

// Operator selects the SQL comparison for a Where predicate.
type Operator string

const (
	OpEq         Operator = "eq"
	OpNe         Operator = "ne"
	OpGt         Operator = "gt"
	OpGte        Operator = "gte"
	OpLt         Operator = "lt"
	OpLte        Operator = "lte"
	OpIn         Operator = "in"
	OpNotIn      Operator = "not_in"
	OpContains   Operator = "contains"
	OpStartsWith Operator = "starts_with"
	OpEndsWith   Operator = "ends_with"
	OpIsNull     Operator = "is_null"
	OpIsNotNull  Operator = "is_not_null"
)

// Where is one filter predicate. The zero Operator means OpEq.
// Predicates in a slice are ANDed; set Connector to "OR" for a top-level
// OR (same as beta). Or holds an any-of group, parenthesized inside the
// surrounding AND chain; Not negates its operand. Group nesting is
// capped at maxWhereDepth.
type Where struct {
	Field     string   `json:"field"`
	Value     any      `json:"value"`
	Operator  Operator `json:"operator,omitempty"`
	Connector string   `json:"connector,omitempty"`
	Or        []Where  `json:"or,omitempty"`
	Not       *Where   `json:"not,omitempty"`
}

// maxWhereDepth caps Or/Not nesting. Deeper trees are rejected loudly
// rather than emitted as pathological SQL.
const maxWhereDepth = 8

// ListOptions drives List/ListMap.
type ListOptions struct {
	Page   int
	Limit  int // 0 = default; clamped, see normalizePageLimit
	Search string
	Filter []Where
	Sort   string // "col" ASC, "-col" DESC; allowlisted against Sortable
	// Sortable lists columns legal in Sort. Empty means no ORDER BY is
	// ever applied (Sort is ignored, not an error).
	Sortable []string
	// Searchable lists columns OR-searched by Search. Empty means Search
	// is ignored.
	Searchable []string
}

// DefaultLimit is applied when Limit <= 0. MaxLimit caps any request.
const (
	DefaultLimit = 50
	MaxLimit     = 500
)

var validIdent = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// normalizePageLimit clamps pagination. Pure — unit-tested without a DB.
func normalizePageLimit(page, limit int) (int, int) {
	if page <= 0 {
		page = 1
	}
	if limit <= 0 {
		limit = DefaultLimit
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}
	return page, limit
}

// normalizeSort resolves a Sort string against the allowlist. Returns
// ok=false when no ORDER BY should be applied (empty sort, bad
// identifier, or column not in Sortable) — never an error, never raw
// SQL from user input. Pure — unit-tested without a DB.
func normalizeSort(sort string, sortable []string) (col, dir string, ok bool) {
	if sort == "" {
		return "", "", false
	}
	dir = "ASC"
	col = sort
	if strings.HasPrefix(col, "-") {
		dir = "DESC"
		col = col[1:]
	}
	if col == "" || !validIdent.MatchString(col) {
		return "", "", false
	}
	for _, allowed := range sortable {
		if allowed == col {
			return col, dir, true
		}
	}
	return "", "", false
}

// searchGroup lowers Search to an OR of ILIKE-contains across Searchable.
// Returns nil when there is nothing to search (no-op for the caller).
func searchGroup(search string, searchable []string) *Where {
	if search == "" || len(searchable) == 0 {
		return nil
	}
	ors := make([]Where, 0, len(searchable))
	for _, col := range searchable {
		ors = append(ors, Where{Field: col, Value: search, Operator: OpContains})
	}
	return &Where{Or: ors}
}

// escapeLike escapes LIKE/ILIKE metacharacters so user input matches
// literally. Always paired with an explicit ESCAPE clause. Pure.
func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// whereable is any bun query type with Where/WhereOr — Select/Update/Delete.
type whereable[Q any] interface {
	Where(query string, args ...any) Q
	WhereOr(query string, args ...any) Q
}

// applyWhereGeneric ANDs every predicate (OR only via Connector:"OR" or
// Or-groups). Every identifier goes through bun.Ident, every value
// through placeholders. Unknown non-empty operators are loud errors —
// never silent wrong-filter.
func applyWhereGeneric[Q whereable[Q]](q Q, where []Where) (Q, error) {
	for _, w := range where {
		frag, args, err := buildCondition(w, 0)
		if err != nil {
			var zero Q
			return zero, err
		}
		if strings.EqualFold(w.Connector, "OR") {
			q = q.WhereOr(frag, args...)
		} else {
			q = q.Where(frag, args...)
		}
	}
	return q, nil
}

// buildCondition lowers one Where (leaf or group) to a fragment + args.
func buildCondition(w Where, depth int) (string, []any, error) {
	if depth > maxWhereDepth {
		return "", nil, fmt.Errorf("db: where nesting exceeds depth %d", maxWhereDepth)
	}
	if w.Not != nil {
		frag, args, err := buildCondition(*w.Not, depth+1)
		if err != nil {
			return "", nil, err
		}
		return "NOT (" + frag + ")", args, nil
	}
	if w.Or != nil {
		if len(w.Or) == 0 {
			return "FALSE", nil, nil // empty Any() matches nothing (deny-safe)
		}
		parts := make([]string, 0, len(w.Or))
		var args []any
		for _, sub := range w.Or {
			frag, subArgs, err := buildCondition(sub, depth+1)
			if err != nil {
				return "", nil, err
			}
			parts = append(parts, frag)
			args = append(args, subArgs...)
		}
		return "(" + strings.Join(parts, " OR ") + ")", args, nil
	}
	return buildLeaf(w)
}

// buildLeaf lowers a single-column predicate. Identifiers via bun.Ident,
// values via placeholders — no string interpolation, ever.
func buildLeaf(w Where) (string, []any, error) {
	col := bun.Ident(w.Field)
	op := w.Operator
	if op == "" {
		op = OpEq
	}
	switch op {
	case OpEq:
		if w.Value == nil {
			return "? IS NULL", []any{col}, nil
		}
		return "? = ?", []any{col, w.Value}, nil
	case OpNe:
		if w.Value == nil {
			return "? IS NOT NULL", []any{col}, nil
		}
		return "? != ?", []any{col, w.Value}, nil
	case OpGt:
		return "? > ?", []any{col, w.Value}, nil
	case OpGte:
		return "? >= ?", []any{col, w.Value}, nil
	case OpLt:
		return "? < ?", []any{col, w.Value}, nil
	case OpLte:
		return "? <= ?", []any{col, w.Value}, nil
	case OpIn:
		if isEmptySlice(w.Value) {
			return "FALSE", nil, nil
		}
		return "? IN (?)", []any{col, bun.In(w.Value)}, nil
	case OpNotIn:
		if isEmptySlice(w.Value) {
			return "TRUE", nil, nil
		}
		return "? NOT IN (?)", []any{col, bun.In(w.Value)}, nil
	case OpContains:
		return "? ILIKE ? ESCAPE '\\'", []any{col, "%" + escapeLike(fmt.Sprint(w.Value)) + "%"}, nil
	case OpStartsWith:
		return "? ILIKE ? ESCAPE '\\'", []any{col, escapeLike(fmt.Sprint(w.Value)) + "%"}, nil
	case OpEndsWith:
		return "? ILIKE ? ESCAPE '\\'", []any{col, "%" + escapeLike(fmt.Sprint(w.Value))}, nil
	case OpIsNull:
		return "? IS NULL", []any{col}, nil
	case OpIsNotNull:
		return "? IS NOT NULL", []any{col}, nil
	}
	return "", nil, fmt.Errorf("db: unknown operator %q on field %q", w.Operator, w.Field)
}

func isEmptySlice(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	return (rv.Kind() == reflect.Slice || rv.Kind() == reflect.Array) && rv.Len() == 0
}

func applyUpdateWhere(q *bun.UpdateQuery, where []Where) (*bun.UpdateQuery, error) {
	return applyWhereGeneric(q, where)
}

func applyDeleteWhere(q *bun.DeleteQuery, where []Where) (*bun.DeleteQuery, error) {
	return applyWhereGeneric(q, where)
}

func applyWhere(q *bun.SelectQuery, where []Where) (*bun.SelectQuery, error) {
	return applyWhereGeneric(q, where)
}
