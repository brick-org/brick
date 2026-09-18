package bunadapter

import (
	"context"
	"testing"

	authdb "github.com/brick-org/brick/auth/src/db"
)

// runAdapterContractSuite exercises the shared authdb.Adapter contract
// (CRUD, projection, single-row guards, bulk counts, atomics, operators)
// against any adapter implementation. All assertions use portable semantics
// that hold for the in-memory reference, SQLite, and PostgreSQL; dialect or
// capability-specific behavior (type revival, RETURNING fallbacks, joins)
// lives in the dedicated integration tests.
//
// Callers seed model "widget" with string fields id/name/role plus numeric
// age; adapters under test must accept those fields (strict adapters should
// register them).
func runAdapterContractSuite(t *testing.T, name string, adapter authdb.Adapter) {
	t.Helper()
	ctx := context.Background()

	seed := func(t *testing.T) {
		t.Helper()
		for _, w := range []map[string]any{
			{"id": "w1", "name": "alpha", "role": "member", "age": 3},
			{"id": "w2", "name": "beta", "role": "member", "age": 7},
			{"id": "w3", "name": "gamma", "role": "admin", "age": 5},
		} {
			if _, err := adapter.Create(ctx, "widget", w, nil); err != nil {
				t.Fatalf("%s: seed Create: %v", name, err)
			}
		}
	}
	eq := func(field string, value any) []authdb.Where {
		return []authdb.Where{{Field: field, Value: value}}
	}
	clean := func(t *testing.T) {
		t.Helper()
		if _, err := adapter.DeleteMany(ctx, "widget", nil); err != nil {
			t.Fatalf("%s: clean: %v", name, err)
		}
	}

	t.Run(name+"/CreateFindOneRoundTrip", func(t *testing.T) {
		clean(t)
		row, err := adapter.Create(ctx, "widget", map[string]any{"id": "r1", "name": "solo", "role": "member"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if row["id"] != "r1" || row["name"] != "solo" {
			t.Fatalf("Create must return the persisted row: %v", row)
		}
		got, err := adapter.FindOne(ctx, "widget", eq("id", "r1"), nil)
		if err != nil {
			t.Fatal(err)
		}
		if got == nil || got["name"] != "solo" {
			t.Fatalf("FindOne must return the created row: %v", got)
		}
		miss, err := adapter.FindOne(ctx, "widget", eq("id", "missing"), nil)
		if err != nil || miss != nil {
			t.Fatalf("FindOne miss must be (nil,nil): %v %v", miss, err)
		}
	})

	t.Run(name+"/SelectProjection", func(t *testing.T) {
		clean(t)
		created, err := adapter.Create(ctx, "widget", map[string]any{"id": "p1", "name": "proj", "role": "member"}, []string{"id"})
		if err != nil {
			t.Fatal(err)
		}
		if len(created) != 1 || created["id"] != "p1" {
			t.Fatalf("Create select must project: %v", created)
		}
		one, err := adapter.FindOne(ctx, "widget", eq("id", "p1"), []string{"name"})
		if err != nil {
			t.Fatal(err)
		}
		if len(one) != 1 || one["name"] != "proj" {
			t.Fatalf("FindOne select must project: %v", one)
		}
		rows, err := adapter.FindMany(ctx, "widget", eq("id", "p1"), 0, 0, nil, []string{"role"})
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || len(rows[0]) != 1 || rows[0]["role"] != "member" {
			t.Fatalf("FindMany select must project every row: %v", rows)
		}
	})

	t.Run(name+"/FindManyLimitOffsetSort", func(t *testing.T) {
		clean(t)
		seed(t)
		rows, err := adapter.FindMany(ctx, "widget", []authdb.Where{{Field: "role", Value: "member"}}, 1, 0, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("limit 1 must return one row: %v", rows)
		}
		asc, err := adapter.FindMany(ctx, "widget", nil, -1, 0, &authdb.SortBy{Field: "name", Direction: "asc"}, []string{"name"})
		if err != nil {
			t.Fatal(err)
		}
		if len(asc) < 3 || asc[0]["name"] != "alpha" || asc[1]["name"] != "beta" || asc[2]["name"] != "gamma" {
			t.Fatalf("asc sort by name: %v", asc)
		}
		desc, err := adapter.FindMany(ctx, "widget", nil, -1, 0, &authdb.SortBy{Field: "name", Direction: "desc"}, []string{"name"})
		if err != nil {
			t.Fatal(err)
		}
		if len(desc) < 3 || desc[0]["name"] != "gamma" {
			t.Fatalf("desc sort by name: %v", desc)
		}
		paged, err := adapter.FindMany(ctx, "widget", nil, 100, 1, &authdb.SortBy{Field: "name", Direction: "asc"}, []string{"name"})
		if err != nil {
			t.Fatal(err)
		}
		if len(paged) < 2 || paged[0]["name"] != "beta" {
			t.Fatalf("offset 1 must skip the first row: %v", paged)
		}
	})

	t.Run(name+"/Count", func(t *testing.T) {
		clean(t)
		seed(t)
		n, err := adapter.Count(ctx, "widget", []authdb.Where{{Field: "role", Value: "member"}})
		if err != nil || n != 2 {
			t.Fatalf("Count members = %d, %v; want 2", n, err)
		}
	})

	t.Run(name+"/UpdateSingleRowGuards", func(t *testing.T) {
		clean(t)
		seed(t)
		updated, err := adapter.Update(ctx, "widget", eq("id", "w1"), map[string]any{"role": "admin"})
		if err != nil || updated == nil || updated["role"] != "admin" {
			t.Fatalf("Update must return the updated row: %v %v", updated, err)
		}
		miss, err := adapter.Update(ctx, "widget", eq("id", "missing"), map[string]any{"role": "x"})
		if err != nil || miss != nil {
			t.Fatalf("Update miss must be (nil,nil): %v %v", miss, err)
		}
		noop, err := adapter.Update(ctx, "widget", nil, map[string]any{"role": "x"})
		if err != nil || noop != nil {
			t.Fatalf("Update empty where must be (nil,nil): %v %v", noop, err)
		}
		kept, err := adapter.FindOne(ctx, "widget", eq("id", "w2"), []string{"role"})
		if err != nil {
			t.Fatal(err)
		}
		if kept["role"] != "member" {
			t.Fatalf("empty-where Update must not mutate: %v", kept)
		}
	})

	t.Run(name+"/BulkCounts", func(t *testing.T) {
		clean(t)
		seed(t)
		n, err := adapter.UpdateMany(ctx, "widget", []authdb.Where{{Field: "role", Value: "member"}}, map[string]any{"role": "admin"})
		if err != nil || n != 2 {
			t.Fatalf("UpdateMany = %d, %v; want 2", n, err)
		}
		n, err = adapter.UpdateMany(ctx, "widget", []authdb.Where{{Field: "role", Value: "nobody"}}, map[string]any{"role": "x"})
		if err != nil || n != 0 {
			t.Fatalf("UpdateMany miss = %d, %v; want 0", n, err)
		}
		n, err = adapter.DeleteMany(ctx, "widget", []authdb.Where{{Field: "role", Value: "admin"}})
		if err != nil {
			t.Fatal(err)
		}
		if n < 1 {
			t.Fatalf("DeleteMany must report affected rows: %d", n)
		}
		n, err = adapter.DeleteMany(ctx, "widget", []authdb.Where{{Field: "role", Value: "admin"}})
		if err != nil || n != 0 {
			t.Fatalf("DeleteMany miss = %d, %v; want 0", n, err)
		}
	})

	t.Run(name+"/DeletePredicate", func(t *testing.T) {
		clean(t)
		seed(t)
		if err := adapter.Delete(ctx, "widget", eq("id", "w1")); err != nil {
			t.Fatal(err)
		}
		if got, _ := adapter.FindOne(ctx, "widget", eq("id", "w1"), nil); got != nil {
			t.Fatalf("Delete must remove the row: %v", got)
		}
		if err := adapter.Delete(ctx, "widget", nil); err != nil {
			t.Fatal(err)
		}
		left, err := adapter.Count(ctx, "widget", nil)
		if err != nil {
			t.Fatal(err)
		}
		if left != 2 {
			t.Fatalf("empty-where Delete must not touch the table: %d rows", left)
		}
	})

	t.Run(name+"/ConsumeOne", func(t *testing.T) {
		clean(t)
		if _, err := adapter.Create(ctx, "widget", map[string]any{"id": "c1", "name": "once", "role": "member"}, nil); err != nil {
			t.Fatal(err)
		}
		row, err := adapter.ConsumeOne(ctx, "widget", eq("id", "c1"))
		if err != nil || row == nil || row["name"] != "once" {
			t.Fatalf("ConsumeOne must return the row: %v %v", row, err)
		}
		again, err := adapter.ConsumeOne(ctx, "widget", eq("id", "c1"))
		if err != nil || again != nil {
			t.Fatalf("second ConsumeOne must be (nil,nil): %v %v", again, err)
		}
		empty, err := adapter.ConsumeOne(ctx, "widget", nil)
		if err != nil || empty != nil {
			t.Fatalf("empty-where ConsumeOne must be (nil,nil): %v %v", empty, err)
		}
	})

	t.Run(name+"/IncrementOne", func(t *testing.T) {
		clean(t)
		// Seed an explicit counter: native single-statement increments
		// compute `field = field + delta` in SQL, where NULL + delta stays
		// NULL on every dialect (matching the kysely/drizzle native path;
		// only the compare-and-swap fallback starts null counters at 0).
		if _, err := adapter.Create(ctx, "widget", map[string]any{"id": "i1", "name": "ctr", "role": "member", "age": 1}, nil); err != nil {
			t.Fatal(err)
		}
		row, err := adapter.IncrementOne(ctx, "widget", eq("id", "i1"), map[string]int{"age": 4}, nil)
		if err != nil || row == nil {
			t.Fatalf("IncrementOne must return the row: %v %v", row, err)
		}
		if asFloat(row["age"]) != 5 {
			t.Fatalf("counter must add the delta: %v", row)
		}
		row, err = adapter.IncrementOne(ctx, "widget", eq("id", "i1"), map[string]int{"age": -1}, map[string]any{"role": "admin"})
		if err != nil || row == nil || asFloat(row["age"]) != 4 || row["role"] != "admin" {
			t.Fatalf("delta+set must apply together: %v %v", row, err)
		}
		if _, err := adapter.IncrementOne(ctx, "widget", eq("id", "i1"), nil, nil); err == nil {
			t.Fatal("empty increment+set must error")
		}
		miss, err := adapter.IncrementOne(ctx, "widget", eq("id", "missing"), map[string]int{"age": 1}, nil)
		if err != nil || miss != nil {
			t.Fatalf("guarded miss must be (nil,nil): %v %v", miss, err)
		}
	})

	t.Run(name+"/Operators", func(t *testing.T) {
		clean(t)
		seed(t)
		older, err := adapter.FindMany(ctx, "widget", []authdb.Where{{Field: "age", Operator: authdb.OpGt, Value: 4}}, -1, 0, nil, []string{"id"})
		if err != nil || len(older) != 2 {
			t.Fatalf("gt filter: %v %v", older, err)
		}
		in, err := adapter.FindMany(ctx, "widget", []authdb.Where{{Field: "id", Operator: authdb.OpIn, Value: []any{"w1", "w3"}}}, -1, 0, nil, []string{"id"})
		if err != nil || len(in) != 2 {
			t.Fatalf("in filter: %v %v", in, err)
		}
		if _, err := adapter.FindMany(ctx, "widget", []authdb.Where{{Field: "id", Operator: authdb.OpIn, Value: "w1"}}, -1, 0, nil, nil); err == nil {
			t.Fatal("non-slice in value must error")
		}
		none, err := adapter.FindMany(ctx, "widget", []authdb.Where{{Field: "id", Operator: authdb.OpIn, Value: []any{}}}, -1, 0, nil, nil)
		if err != nil || len(none) != 0 {
			t.Fatalf("empty in matches no rows: %v %v", none, err)
		}
		hit, err := adapter.FindOne(ctx, "widget", []authdb.Where{{Field: "name", Operator: authdb.OpContains, Value: "alp"}}, []string{"id"})
		if err != nil || hit == nil || hit["id"] != "w1" {
			t.Fatalf("contains: %v %v", hit, err)
		}
		hit, err = adapter.FindOne(ctx, "widget", []authdb.Where{{Field: "name", Operator: authdb.OpStartsWith, Value: "bet"}}, []string{"id"})
		if err != nil || hit == nil || hit["id"] != "w2" {
			t.Fatalf("starts_with: %v %v", hit, err)
		}
		hit, err = adapter.FindOne(ctx, "widget", []authdb.Where{{Field: "name", Operator: authdb.OpEndsWith, Value: "mma"}}, []string{"id"})
		if err != nil || hit == nil || hit["id"] != "w3" {
			t.Fatalf("ends_with: %v %v", hit, err)
		}
		hit, err = adapter.FindOne(ctx, "widget", []authdb.Where{{Field: "name", Value: "ALPHA", Mode: "insensitive"}}, []string{"id"})
		if err != nil || hit == nil || hit["id"] != "w1" {
			t.Fatalf("insensitive eq: %v %v", hit, err)
		}
		// OR predicates group separately from AND predicates: upstream
		// emits (AND-group) AND (OR-group), so a lone AND plus two ORs
		// matches only rows satisfying both groups.
		or, err := adapter.FindMany(ctx, "widget", []authdb.Where{
			{Field: "role", Value: "member"},
			{Field: "id", Value: "w1", Connector: "OR"},
			{Field: "id", Value: "w3", Connector: "OR"},
		}, -1, 0, nil, []string{"id"})
		if err != nil || len(or) != 1 || or[0]["id"] != "w1" {
			t.Fatalf("AND/OR grouping: %v %v", or, err)
		}
		// A pure OR group matches either side.
		or, err = adapter.FindMany(ctx, "widget", []authdb.Where{
			{Field: "id", Value: "w1", Connector: "OR"},
			{Field: "id", Value: "w2", Connector: "OR"},
		}, -1, 0, nil, []string{"id"})
		if err != nil || len(or) != 2 {
			t.Fatalf("OR connector: %v %v", or, err)
		}
	})

	t.Run(name+"/TransactionCommitRollback", func(t *testing.T) {
		clean(t)
		err := adapter.Transaction(ctx, func(tx authdb.Adapter) error {
			_, err := tx.Create(ctx, "widget", map[string]any{"id": "t1", "name": "tx", "role": "member"}, nil)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := adapter.FindOne(ctx, "widget", eq("id", "t1"), nil); got == nil {
			t.Fatal("committed transaction must persist")
		}
		_ = adapter.Transaction(ctx, func(tx authdb.Adapter) error {
			_, _ = tx.Create(ctx, "widget", map[string]any{"id": "t2", "name": "rollback", "role": "member"}, nil)
			return context.Canceled
		})
		if got, _ := adapter.FindOne(ctx, "widget", eq("id", "t2"), nil); got != nil {
			t.Fatal("rolled-back transaction must not persist")
		}
	})
}

func asFloat(v any) float64 {
	switch n := v.(type) {
	case nil:
		return 0
	case int:
		return float64(n)
	case int8:
		return float64(n)
	case int16:
		return float64(n)
	case int32:
		return float64(n)
	case int64:
		return float64(n)
	case uint:
		return float64(n)
	case uint8:
		return float64(n)
	case uint16:
		return float64(n)
	case uint32:
		return float64(n)
	case uint64:
		return float64(n)
	case float32:
		return float64(n)
	case float64:
		return n
	default:
		return 0
	}
}
