package bunadapter

// Wave 4 conformance: remaining upstream adapter where-clause cases, fuzz targets, race tests, limits.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	authdb "github.com/brick-org/brick/auth/src/db"
)

func wave4OfflineAdapter(dialect string) *Adapter {
	a, ok := NewWithDialect(nil, nil, authdb.Config{}, dialect).(*Adapter)
	if !ok {
		panic("bunadapter: NewWithDialect must return *Adapter")
	}
	return a
}

// Upstream factory: in/not_in with a non-array value throws ("Value must be an array").
func TestWhereConformance_WhereInRequiresArray(t *testing.T) {
	a := wave4OfflineAdapter("sqlite")
	for _, op := range []authdb.Operator{authdb.OpIn, authdb.OpNotIn} {
		for _, bad := range []any{"x", 42, true, nil, map[string]any{}} {
			_, _, err := a.buildWhereClause("widget", []authdb.Where{{Field: "name", Operator: op, Value: bad}}, "findMany")
			if err == nil {
				t.Errorf("%s with %T must error", op, bad)
			}
		}
		for _, good := range []any{[]string{"a"}, []any{"a", 1}, []int{1, 2}, [2]string{"a", "b"}} {
			if _, _, err := a.buildWhereClause("widget", []authdb.Where{{Field: "name", Operator: op, Value: good}}, "findMany"); err != nil {
				t.Errorf("%s with %T must build: %v", op, good, err)
			}
		}
	}
}

// Upstream: empty IN matches no rows, empty NOT IN matches all rows.
func TestWhereConformance_WhereEmptyInSemantics(t *testing.T) {
	a := wave4OfflineAdapter("sqlite")
	clause, _, err := a.buildWhereClause("widget", []authdb.Where{{Field: "name", Operator: authdb.OpIn, Value: []string{}}}, "findMany")
	if err != nil || clause != "1 = 0" {
		t.Errorf("empty IN = %q, %v; want \"1 = 0\"", clause, err)
	}
	clause, _, err = a.buildWhereClause("widget", []authdb.Where{{Field: "name", Operator: authdb.OpNotIn, Value: []string{}}}, "findMany")
	if err != nil || clause != "1 = 1" {
		t.Errorf("empty NOT IN = %q, %v; want \"1 = 1\"", clause, err)
	}
	clause, _, err = a.buildWhereClause("widget", []authdb.Where{
		{Field: "a", Operator: authdb.OpEq, Value: "1"},
		{Field: "b", Operator: authdb.OpIn, Value: []string{}, Connector: "OR"},
	}, "findMany")
	if err != nil || clause != "(? = ?) AND (1 = 0)" {
		t.Errorf("mixed empty-OR grouping = %q, %v", clause, err)
	}
}

// Upstream mixed-where: AND and OR predicates group separately, joined as (AND-group) AND (OR-group).
func TestWhereConformance_WhereMixedGrouping(t *testing.T) {
	a := wave4OfflineAdapter("sqlite")
	clause, args, err := a.buildWhereClause("widget", []authdb.Where{
		{Field: "a", Operator: authdb.OpEq, Value: "1"},
		{Field: "b", Operator: authdb.OpEq, Value: "2"},
		{Field: "c", Operator: authdb.OpEq, Value: "3", Connector: "OR"},
		{Field: "d", Operator: authdb.OpEq, Value: "4", Connector: "or"},
	}, "findMany")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if clause != "(? = ? AND ? = ?) AND (? = ? OR ? = ?)" {
		t.Errorf("grouping = %q", clause)
	}
	if len(args) != 8 {
		t.Errorf("args = %d, want 8 (values travel as placeholders)", len(args))
	}
	if clause, args, err := a.buildWhereClause("widget", nil, "findMany"); err != nil || clause != "" || args != nil {
		t.Errorf("empty where = %q %v %v", clause, args, err)
	}
}

// Upstream operator vocabulary: every documented operator builds a parameterized fragment.
func TestWhereConformance_WhereOperatorVocabulary(t *testing.T) {
	a := wave4OfflineAdapter("sqlite")
	marker := "INJECT') OR ('1'='1"
	cases := []struct {
		op    authdb.Operator
		value any
		want  string
	}{
		{authdb.OpEq, marker, "= ?"},
		{authdb.OpNe, marker, "!= ?"},
		{authdb.OpLt, marker, "< ?"},
		{authdb.OpLte, marker, "<= ?"},
		{authdb.OpGt, marker, "> ?"},
		{authdb.OpGte, marker, ">= ?"},
		{authdb.OpIn, []string{marker}, "IN (?)"},
		{authdb.OpNotIn, []string{marker}, "NOT IN (?)"},
		{authdb.OpContains, marker, "LIKE ?"},
		{authdb.OpStartsWith, marker, "LIKE ?"},
		{authdb.OpEndsWith, marker, "LIKE ?"},
		{"", marker, "= ?"},
		{"bogus", marker, "= ?"},
	}
	for _, c := range cases {
		clause, _, err := a.buildWhereClause("widget", []authdb.Where{{Field: "name", Operator: c.op, Value: c.value}}, "findMany")
		if err != nil {
			t.Errorf("%q: build error %v", c.op, err)
			continue
		}
		if !strings.Contains(clause, c.want) {
			t.Errorf("%q: clause %q lacks %q", c.op, clause, c.want)
		}
		if strings.Contains(clause, marker) {
			t.Errorf("%q: value interpolated into SQL text: %q", c.op, clause)
		}
	}
	clause, _, _ := a.buildWhereClause("widget", []authdb.Where{{Field: "name", Operator: authdb.OpEq, Value: nil}}, "findMany")
	if clause != "? IS NULL" {
		t.Errorf("nil eq = %q", clause)
	}
	clause, _, _ = a.buildWhereClause("widget", []authdb.Where{{Field: "name", Operator: authdb.OpNe, Value: nil}}, "findMany")
	if clause != "? IS NOT NULL" {
		t.Errorf("nil ne = %q", clause)
	}
}

func TestWhereConformance_WhereMalformedInputLimits(t *testing.T) {
	a := wave4OfflineAdapter("sqlite")
	big := make([]authdb.Where, 0, 10000)
	for i := 0; i < 10000; i++ {
		big = append(big, authdb.Where{Field: "name", Operator: authdb.OpEq, Value: "v"})
	}
	if _, args, err := a.buildWhereClause("widget", big, "findMany"); err != nil || len(args) != 20000 {
		t.Errorf("10k predicates: %v %d", err, len(args))
	}
	huge := strings.Repeat("x", 1<<20) + `"; DROP TABLE widgets;--`
	var idErr *authdb.InvalidIdentifierError
	_, findErr := a.FindOne(context.Background(), huge, []authdb.Where{{Field: "name", Value: "v"}}, nil)
	if !errors.As(findErr, &idErr) {
		t.Errorf("hostile model must fail identifier validation, got %v", findErr)
	}
	bigValue := strings.Repeat("y", 1<<20)
	clause, _, err := a.buildWhereClause("widget", []authdb.Where{{Field: "name", Value: bigValue}}, "findMany")
	if err != nil {
		t.Fatalf("1MB value must stay parameterized, not error: %v", err)
	}
	if strings.Contains(clause, bigValue) {
		t.Error("1MB value interpolated into SQL text")
	}
	for _, field := range []string{"a\" OR \"1\"=\"1", "a; DROP TABLE widgets;--", "a\nb", "a\x00b", "sch.tab.col", ""} {
		_, _, err := a.buildWhereClause("widget", []authdb.Where{{Field: field, Value: "v"}}, "findMany")
		if field == "" && err == nil {
			t.Error("empty field should fail validation")
		}
		_ = err
	}
}

func TestWhereConformance_WhereBuilderConcurrentUse(t *testing.T) {
	a := wave4OfflineAdapter("sqlite")
	where := []authdb.Where{
		{Field: "name", Operator: authdb.OpContains, Value: "x"},
		{Field: "age", Operator: authdb.OpGte, Value: 3},
		{Field: "role", Operator: authdb.OpIn, Value: []string{"a", "b"}, Connector: "OR"},
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				if _, _, err := a.buildWhereClause("widget", where, "findMany"); err != nil {
					t.Errorf("build: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// Concurrent reads against one shared SQLite adapter exercise the query path under -race.
func TestWhereConformance_SQLiteConcurrentReads(t *testing.T) {
	a := sqliteAdapter(t, "sqlite", Options{Models: widgetRegistry()})
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		if _, err := a.Create(ctx, "widget", map[string]any{"id": "w" + itoaWave4Bun(i), "name": "n"}, nil); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				if _, err := a.FindMany(ctx, "widget", []authdb.Where{{Field: "name", Operator: authdb.OpEq, Value: "n"}}, 100, 0, nil, nil); err != nil {
					t.Errorf("find: %v", err)
					return
				}
				if _, err := a.Count(ctx, "widget", nil); err != nil {
					t.Errorf("count: %v", err)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

func itoaWave4Bun(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}

func FuzzBuildWhereClause(f *testing.F) {
	f.Add("widget", "name", "eq", "AND", "sensitive", "needle")
	f.Add("widget", "age", "gte", "OR", "insensitive", "42")
	f.Add("widget", "name", "contains", "", "", "a'b\"c")
	f.Add("widget", "name", "in", "AND", "", "x")
	f.Add("", "", "", "", "", "")
	f.Fuzz(func(t *testing.T, model, field, op, connector, mode, value string) {
		for _, dialect := range []string{"sqlite", "pg"} {
			a := wave4OfflineAdapter(dialect)
			inVal := any(value)
			if op == "in" || op == "not_in" {
				inVal = []string{value, value + "!"}
			}
			where := []authdb.Where{{
				Field:     field,
				Operator:  authdb.Operator(op),
				Connector: connector,
				Mode:      mode,
				Value:     inVal,
			}}
			clause, args, err := a.buildWhereClause(model, where, "findMany")
			if err != nil {
				continue
			}
			if op != "in" && op != "not_in" {
				want := value
				switch op {
				case "contains":
					want = "%" + value + "%"
				case "starts_with":
					want = value + "%"
				case "ends_with":
					want = "%" + value
				}
				found := false
				for _, arg := range args {
					if s, ok := arg.(string); ok && s == want {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("[%s] value %q missing from args (clause=%q)", dialect, value, clause)
				}
				if value != "" && strings.Contains(clause, "'"+value+"'") {
					t.Fatalf("[%s] value quoted into SQL text: clause=%q value=%q", dialect, clause, value)
				}
			}
			if clause != "" && len(args) == 0 {
				t.Fatalf("[%s] non-empty clause with no args: %q", dialect, clause)
			}
			clause2, args2, err2 := a.buildWhereClause(model, where, "findMany")
			if (err2 == nil) != (err == nil) || clause2 != clause || len(args2) != len(args) {
				t.Fatalf("[%s] nondeterministic build for %+v", dialect, where)
			}
		}
	})
}

func TestWhereConformance_NilDBQueryOpsError(t *testing.T) {
	t.Parallel()
	a := wave4OfflineAdapter("sqlite")
	ctx := context.Background()
	where := []authdb.Where{{Field: "id", Operator: authdb.OpEq, Value: "1"}}
	if _, err := a.FindOne(ctx, "user", where, nil); err == nil {
		t.Fatal("FindOne on nil DB must error")
	}
	if _, err := a.FindMany(ctx, "user", where, 0, 0, nil, nil); err == nil {
		t.Fatal("FindMany on nil DB must error")
	}
	if _, err := a.Count(ctx, "user", where); err == nil {
		t.Fatal("Count on nil DB must error")
	}
	if _, err := a.Create(ctx, "user", map[string]any{"id": "1"}, nil); err == nil {
		t.Fatal("Create on nil DB must error")
	}
	if _, err := a.Update(ctx, "user", where, map[string]any{"id": "1"}); err == nil {
		t.Fatal("Update on nil DB must error")
	}
	if _, err := a.DeleteMany(ctx, "user", where); err == nil {
		t.Fatal("DeleteMany on nil DB must error")
	}
	if err := a.Delete(ctx, "user", where); err == nil {
		t.Fatal("Delete on nil DB must error")
	}
	if _, err := a.ConsumeOne(ctx, "user", where); err == nil {
		t.Fatal("ConsumeOne on nil DB must error")
	}
}
