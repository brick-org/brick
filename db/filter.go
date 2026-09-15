package db

import (
	"reflect"
	"time"
)

// QueryFilter is a fluent builder for []Where, for custom routes and
// generated stores that assemble filters conditionally. The zero value is
// ready to use; every method returns a copy so partially-built filters are
// safely reusable.
//
// Lowering: Wheres() for ListOptions.Filter, SearchQuery for
// ListOptions.Search, or ApplyTo/Options to fill a ListOptions in one step.
// Ordering and limits travel as ListOpt (Order/OrderDesc/Limit) so call
// sites read `Store.List(f, Order("DueAt"), Limit(100))`.
type QueryFilter struct {
	where  []Where
	search string
}

// Filter starts a new QueryFilter.
func Filter() QueryFilter { return QueryFilter{} }

// Eq adds a Field = value predicate.
func (f QueryFilter) Eq(field string, value any) QueryFilter {
	f.where = append(f.where, Where{Field: field, Value: value})
	return f
}

// EqIf adds Field = value unless value is "zero" — "", 0, nil, empty
// slice/map, zero time.Time. `false` is NOT zero: booleans are meaningful
// filters (see the M3 pointer-filter fix) and are always kept.
func (f QueryFilter) EqIf(field string, value any) QueryFilter {
	if isZeroFilterValue(value) {
		return f
	}
	return f.Eq(field, value)
}

// Ne adds a Field != value predicate.
func (f QueryFilter) Ne(field string, value any) QueryFilter {
	f.where = append(f.where, Where{Field: field, Operator: OpNe, Value: value})
	return f
}

// Where adds a predicate with an explicit operator.
func (f QueryFilter) Where(field string, op Operator, value any) QueryFilter {
	f.where = append(f.where, Where{Field: field, Operator: op, Value: value})
	return f
}

// Between adds Field >= from AND Field <= to.
func (f QueryFilter) Between(field string, from, to any) QueryFilter {
	f.where = append(f.where,
		Where{Field: field, Operator: OpGte, Value: from},
		Where{Field: field, Operator: OpLte, Value: to},
	)
	return f
}

// Search sets the free-text query (lowered to ListOptions.Search: ILIKE
// across Searchable).
func (f QueryFilter) Search(q string) QueryFilter {
	f.search = q
	return f
}

// Or combines sub-filters into one parenthesized any-of group inside the
// surrounding AND chain: Any(team-X, owner-Y) matches either. Each
// sub-filter's predicates flatten into the group (multi-condition subs
// become any-of their leaves); sub-searches are ignored — set Search on the
// outer filter.
func (f QueryFilter) Or(filters ...QueryFilter) QueryFilter {
	var ors []Where
	for _, sub := range filters {
		ors = append(ors, sub.where...)
	}
	f.where = append(f.where, Where{Or: ors})
	return f
}

// Not negates a sub-filter to NOT (...). Multi-predicate subs join with OR
// inside the negation (De Morgan: NOT(a AND b) is not directly
// representable — prefer single-predicate subs).
func (f QueryFilter) Not(sub QueryFilter) QueryFilter {
	inner := Where{Or: append([]Where(nil), sub.where...)}
	f.where = append(f.where, Where{Not: &inner})
	return f
}

// Wheres lowers the builder to ListOptions.Filter. (Named Wheres, not Where,
// because Where(field, op, value) is the predicate adder.)
func (f QueryFilter) Wheres() []Where { return f.where }

// SearchQuery lowers the builder to ListOptions.Search.
func (f QueryFilter) SearchQuery() string { return f.search }

// ApplyTo copies filter + search into opts, preserving the caller's
// Sortable/Searchable/Sort/Limit. Never mutates shared backing arrays.
func (f QueryFilter) ApplyTo(opts ListOptions) ListOptions {
	out := make([]Where, 0, len(opts.Filter)+len(f.where))
	out = append(out, opts.Filter...)
	out = append(out, f.where...)
	opts.Filter = out
	if f.search != "" {
		opts.Search = f.search
	}
	return opts
}

// Options builds a ListOptions from the filter plus ordering/limit opts.
func (f QueryFilter) Options(extra ...ListOpt) ListOptions {
	return ApplyListOpts(ListOptions{Filter: f.Wheres(), Search: f.search}, extra...)
}

// ListOpt modifies a ListOptions (ordering, limits).
type ListOpt interface{ applyTo(*ListOptions) }

// SortOpt sets ListOptions.Sort. Validated against Sortable at exec;
// unknown columns apply no ordering (never an error, never SQL).
type SortOpt struct{ sort string }

// Order sorts ascending by field.
func Order(field string) SortOpt { return SortOpt{sort: field} }

// OrderDesc sorts descending by field.
func OrderDesc(field string) SortOpt { return SortOpt{sort: "-" + field} }

func (o SortOpt) applyTo(opts *ListOptions) { opts.Sort = o.sort }

// LimitOpt sets ListOptions.Limit. Clamped by normalizePageLimit at exec.
type LimitOpt struct{ limit int }

// Limit caps the page size (clamped to MaxLimit at exec).
func Limit(n int) LimitOpt { return LimitOpt{limit: n} }

func (o LimitOpt) applyTo(opts *ListOptions) { opts.Limit = o.limit }

// ApplyListOpts folds opts into a copy of base.
func ApplyListOpts(base ListOptions, opts ...ListOpt) ListOptions {
	for _, o := range opts {
		o.applyTo(&base)
	}
	return base
}

// isZeroFilterValue reports EqIf-skippable values. False is meaningful and
// never skipped; nil, "", numerics == 0, empty slices/maps, zero time.Time,
// and nil ptr/interface are skipped.
func isZeroFilterValue(v any) bool {
	if v == nil {
		return true
	}
	if t, ok := v.(time.Time); ok {
		return t.IsZero()
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.String:
		return rv.Len() == 0
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return rv.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return rv.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return rv.Float() == 0
	case reflect.Slice, reflect.Map, reflect.Array:
		return rv.Len() == 0
	case reflect.Ptr, reflect.Interface:
		return rv.IsNil()
	}
	return false
}
