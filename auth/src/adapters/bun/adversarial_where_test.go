package bunadapter

// AUTH-V10-02 — adversarial and cross-language conformance (tests only).

import (
	"strings"
	"sync"
	"testing"

	authdb "github.com/brick-org/brick/auth/src/db"
)

// Hostile where clauses under burst: builds either error or stay parameterized on every dialect.
func TestAdversarialWhere_WhereBurstHostile(t *testing.T) {
	hostiles := [][]authdb.Where{
		{{Field: "name", Operator: authdb.OpEq, Value: "INJECT') OR ('1'='1"}},
		{{Field: "name", Operator: authdb.OpContains, Value: "%_\"'; DROP TABLE widgets;--"}},
		{{Field: "age", Operator: authdb.OpGte, Value: strings.Repeat("9", 512)}},
		{{Field: "blob", Operator: authdb.OpEq, Value: strings.Repeat("y", 1<<16)}},
		{
			{Field: "a", Operator: authdb.OpEq, Value: "1"},
			{Field: "b", Operator: authdb.OpIn, Value: []string{"x", "y'); DROP--"}},
			{Field: "c", Operator: authdb.OpContains, Value: "z", Connector: "OR"},
		},
	}
	for _, dialect := range []string{"sqlite", "pg"} {
		a := wave4OfflineAdapter(dialect)
		var wg sync.WaitGroup
		errs := make(chan string, 256)
		for g := 0; g < 8; g++ {
			wg.Add(1)
			go func(g int) {
				defer wg.Done()
				for i := 0; i < 25; i++ {
					where := hostiles[(g+i)%len(hostiles)]
					clause, _, err := a.buildWhereClause("widget", where, "findMany")
					if err != nil {
						continue
					}
					for _, w := range where {
						if s, ok := w.Value.(string); ok && s != "" {
							if strings.Contains(clause, "'"+s+"'") {
								errs <- "value quoted into SQL text"
								return
							}
						}
					}
				}
			}(g)
		}
		wg.Wait()
		close(errs)
		for e := range errs {
			t.Fatalf("[%s] %s", dialect, e)
		}
	}
}

// FuzzWave10_WhereInjection fuzzes field/value pairs through the clause builder on both offline dialects.
func FuzzWave10_WhereInjection(f *testing.F) {
	f.Add("name", "needle", "eq")
	f.Add("name", "a'b\"c; DROP TABLE x;--", "contains")
	f.Add("age", "42", "gte")
	f.Add("name", "%_%", "starts_with")
	f.Add("x", " ", "ends_with")
	f.Fuzz(func(t *testing.T, field, value, op string) {
		if len(field) > 512 || len(value) > 512 {
			t.Skip("over wave10 512B cap")
		}
		for _, dialect := range []string{"sqlite", "pg"} {
			a := wave4OfflineAdapter(dialect)
			clause, args, err := a.buildWhereClause("widget", []authdb.Where{{
				Field:    field,
				Operator: authdb.Operator(op),
				Value:    value,
			}}, "findMany")
			if err != nil {
				continue
			}
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
			clause2, args2, err2 := a.buildWhereClause("widget", []authdb.Where{{
				Field:    field,
				Operator: authdb.Operator(op),
				Value:    value,
			}}, "findMany")
			if (err2 == nil) != (err == nil) || clause2 != clause || len(args2) != len(args) {
				t.Fatalf("[%s] nondeterministic build for %q %q %q", dialect, field, value, op)
			}
		}
	})
}
