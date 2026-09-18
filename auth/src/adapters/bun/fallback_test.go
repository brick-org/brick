package bunadapter

import (
	"context"
	"strings"
	"testing"

	authdb "github.com/brick-org/brick/auth/src/db"
	"github.com/uptrace/bun"
)

// The non-RETURNING fallback paths (MySQL/MSSQL labels) execute against
// in-memory SQLite here: the fallback SQL is portable enough to run, which
// proves the cascade logic end to end, while the dialect-specific query
// shapes are asserted as strings below and via the capture hook.

func TestFallback_CreateCascade(t *testing.T) {
	ctx := context.Background()
	for _, dialect := range []string{"mysql", "mssql"} {
		t.Run(dialect+"/knownID", func(t *testing.T) {
			a := sqliteAdapter(t, dialect, Options{Models: profileRegistry()})
			row, err := a.Create(ctx, "profile", map[string]any{"id": "k1", "email": "k@x.y"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if row["id"] != "k1" || row["email"] != "k@x.y" {
				t.Fatalf("known-id fallback must return the row: %v", row)
			}
		})
		t.Run(dialect+"/uniqueColumn", func(t *testing.T) {
			a := sqliteAdapter(t, dialect, Options{Models: profileRegistry()})
			// No id: the unique email column identifies the inserted row.
			row, err := a.Create(ctx, "profile", map[string]any{"email": "u@x.y", "score": 9.5}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if row == nil || row["email"] != "u@x.y" || asFloat(row["score"]) != 9.5 {
				t.Fatalf("unique-column fallback must return the row: %v", row)
			}
		})
		t.Run(dialect+"/fullFieldMatch", func(t *testing.T) {
			a := sqliteAdapter(t, dialect, Options{Models: widgetRegistry()})
			// No id and no unique registry columns: the full-field match
			// identifies the single inserted row.
			row, err := a.Create(ctx, "widget", map[string]any{"name": "solo", "role": "member"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if row == nil || row["name"] != "solo" {
				t.Fatalf("full-field fallback must return the row: %v", row)
			}
		})
		t.Run(dialect+"/ambiguousMatchIsNull", func(t *testing.T) {
			a := sqliteAdapter(t, dialect, Options{Models: widgetRegistry()})
			for i := 0; i < 2; i++ {
				if _, err := a.Create(ctx, "widget", map[string]any{"name": "dup", "role": "member"}, nil); err != nil {
					t.Fatal(err)
				}
			}
			// Two identical rows make the full-field match ambiguous, so
			// the third insert resolves to null (upstream warn-and-null).
			row, err := a.Create(ctx, "widget", map[string]any{"name": "dup", "role": "member"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if row != nil {
				t.Fatalf("ambiguous fallback must be (nil,nil): %v", row)
			}
		})
		t.Run(dialect+"/lenientKnownID", func(t *testing.T) {
			a := sqliteAdapter(t, dialect, Options{})
			row, err := a.Create(ctx, "widget", map[string]any{"id": "L1", "name": "lenient"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if row["id"] != "L1" {
				t.Fatalf("lenient fallback must return the row: %v", row)
			}
		})
	}
}

func TestFallback_UpdateReselectsByNewValues(t *testing.T) {
	ctx := context.Background()
	for _, dialect := range []string{"mysql", "mssql"} {
		a := sqliteAdapter(t, dialect, Options{Models: widgetRegistry()})
		if _, err := a.Create(ctx, "widget", map[string]any{"id": "r1", "name": "old", "role": "member"}, nil); err != nil {
			t.Fatal(err)
		}
		// The predicate selects by the stale value; the post-update read
		// must use the new value (kysely/drizzle reselect approach).
		updated, err := a.Update(ctx, "widget",
			[]authdb.Where{{Field: "name", Value: "old"}},
			map[string]any{"name": "new"})
		if err != nil {
			t.Fatal(err)
		}
		if updated == nil || updated["name"] != "new" || updated["id"] != "r1" {
			t.Fatalf("reselect must target the updated row: %v", updated)
		}
	}
}

func TestFallback_NullCounterStartsAtZero(t *testing.T) {
	ctx := context.Background()
	// The compare-and-swap fallback (non-RETURNING dialects) starts null
	// counters at 0, mirroring the factory atomic fallback.
	for _, dialect := range []string{"mysql", "mssql"} {
		a := sqliteAdapter(t, dialect, Options{Models: widgetRegistry()})
		if _, err := a.Create(ctx, "widget", map[string]any{"id": "z1", "name": "ctr"}, nil); err != nil {
			t.Fatal(err)
		}
		row, err := a.IncrementOne(ctx, "widget", []authdb.Where{{Field: "id", Value: "z1"}}, map[string]int{"age": 4}, nil)
		if err != nil || row == nil || asFloat(row["age"]) != 4 {
			t.Fatalf("CAS null counter starts at 0: %v %v", row, err)
		}
	}
}

func TestFallback_RawSQLShapes(t *testing.T) {
	clause := `"users"."id" = 'u1'`
	pg := consumeOneReturningQuery("pg", "users", clause)
	if !strings.Contains(pg, "ctid") || !strings.Contains(pg, "RETURNING *") || strings.Contains(pg, "rowid") {
		t.Fatalf("pg consume must be ctid-guarded with RETURNING: %q", pg)
	}
	for _, alias := range []string{"postgres", "postgresql", "pgdialect"} {
		if got := consumeOneReturningQuery(alias, "users", clause); got != pg {
			t.Fatalf("postgres alias %q must match pg: %q", alias, got)
		}
	}
	lite := consumeOneReturningQuery("sqlite", "users", clause)
	if !strings.Contains(lite, "rowid") || !strings.Contains(lite, "RETURNING *") {
		t.Fatalf("sqlite consume must be rowid-guarded with RETURNING: %q", lite)
	}
	for _, d := range []string{"mysql", "mssql", "other"} {
		if got := consumeOneReturningQuery(d, "users", clause); got != lite {
			t.Fatalf("non-pg consume %q must use the rowid shape: %q", d, got)
		}
	}
	setList := `"age" = "age" + ?`
	upg := incrementOneReturningQuery("pg", "users", setList, clause)
	if !strings.Contains(upg, "ctid") || !strings.Contains(upg, setList) || !strings.Contains(upg, "RETURNING *") {
		t.Fatalf("pg increment must be ctid-guarded with RETURNING: %q", upg)
	}
	ulite := incrementOneReturningQuery("sqlite", "users", setList, clause)
	if !strings.Contains(ulite, "rowid") || !strings.Contains(ulite, setList) {
		t.Fatalf("sqlite increment must be rowid-guarded: %q", ulite)
	}
	if got := incrementOneReturningQuery("mssql", "users", setList, clause); got != ulite {
		t.Fatalf("mssql increment must use the rowid shape: %q", got)
	}
	// Identifiers with quotes are doubled, never raw.
	if got := quoteIdent(`a"b`); got != `"a""b"` {
		t.Fatalf("quoteIdent must escape quotes: %q", got)
	}
}

func TestFallback_CapabilitiesMatrix(t *testing.T) {
	pg := defaultCapabilities("pg")
	if !pg.SupportsJSON || !pg.SupportsDates || !pg.SupportsBooleans || !pg.SupportsUUIDs || pg.SupportsArrays {
		t.Fatalf("pg capabilities: %+v", pg)
	}
	lite := defaultCapabilities("sqlite")
	if lite.SupportsJSON || lite.SupportsDates || lite.SupportsBooleans {
		t.Fatalf("sqlite capabilities: %+v", lite)
	}
	my := defaultCapabilities("mysql")
	if my.SupportsBooleans || !my.SupportsDates || my.SupportsJSON {
		t.Fatalf("mysql capabilities (dates yes, bools/JSON no): %+v", my)
	}
	ms := defaultCapabilities("mssql")
	if ms.SupportsBooleans || ms.SupportsDates {
		t.Fatalf("mssql capabilities: %+v", ms)
	}
	unknown := defaultCapabilities("cockroach")
	if unknown.SupportsBooleans || unknown.SupportsDates {
		t.Fatalf("unknown dialects stay conservative: %+v", unknown)
	}
	for d, want := range map[string]bool{"pg": true, "sqlite": true, "mysql": false, "mssql": false} {
		a := testAdapter(authdb.Config{}, d)
		if got := a.supportsReturning(); got != want {
			t.Fatalf("supportsReturning(%q) = %v, want %v", d, got, want)
		}
		if got := a.Capabilities(); got.AdapterID != "bun" || got.AdapterName == "" {
			t.Fatalf("Capabilities(%q) must identify the adapter: %+v", d, got)
		}
	}
	// Explicit capabilities override the dialect defaults.
	custom := authdb.Capabilities{SupportsJSON: true, SupportsDates: true, SupportsBooleans: true}
	a := NewWithDialectOptions(nil, nil, authdb.Config{}, "sqlite", Options{Capabilities: &custom})
	if got := a.(authdb.CapabilityReporter).Capabilities(); !got.SupportsJSON {
		t.Fatalf("explicit capabilities must win: %+v", got)
	}
}

func TestFallback_ReselectWhere(t *testing.T) {
	a := testAdapter(authdb.Config{}, "mysql")
	out, err := a.reselectWhere("user",
		[]authdb.Where{{Field: "email", Value: "old@x.y"}, {Field: "name", Value: "Al"}},
		map[string]any{"email": "new@x.y"})
	if err != nil {
		t.Fatal(err)
	}
	if out[0].Value != "new@x.y" || out[1].Value != "Al" {
		t.Fatalf("reselect must substitute updated values: %+v", out)
	}
}

func TestFallback_JoinResolution(t *testing.T) {
	strict := func(models map[string]ModelDef) *Adapter {
		return NewWithDialectOptions(nil, nil, authdb.Config{}, "pg", Options{Models: models}).(*Adapter)
	}
	t.Run("requiresRegistry", func(t *testing.T) {
		a := testAdapter(authdb.Config{}, "pg")
		if _, err := a.resolveJoins("user", authdb.JoinOption{"session": {}}); err == nil {
			t.Fatal("joins without a registry must error")
		}
	})
	t.Run("unknownModel", func(t *testing.T) {
		a := strict(DefaultModelDefs())
		if _, err := a.resolveJoins("nope", authdb.JoinOption{"session": {}}); err == nil {
			t.Fatal("unknown base model must error")
		}
		if _, err := a.resolveJoins("user", authdb.JoinOption{"nope": {}}); err == nil {
			t.Fatal("unknown join model must error")
		}
	})
	t.Run("forwardOneToMany", func(t *testing.T) {
		a := strict(DefaultModelDefs())
		resolved, err := a.resolveJoins("user", authdb.JoinOption{"session": {}})
		if err != nil {
			t.Fatal(err)
		}
		r := resolved["session"]
		if r.fromLogical != "id" || r.toLogical != "userId" || r.relation != authdb.JoinOneToMany || r.limit != authdb.DefaultFindManyLimit {
			t.Fatalf("forward join: %+v", r)
		}
	})
	t.Run("backwardOneToOne", func(t *testing.T) {
		a := strict(DefaultModelDefs())
		resolved, err := a.resolveJoins("session", authdb.JoinOption{"user": {}})
		if err != nil {
			t.Fatal(err)
		}
		r := resolved["user"]
		if r.fromLogical != "userId" || r.toLogical != "id" || r.relation != authdb.JoinOneToOne || r.limit != 1 {
			t.Fatalf("backward join: %+v", r)
		}
	})
	t.Run("noForeignKey", func(t *testing.T) {
		a := strict(DefaultModelDefs())
		if _, err := a.resolveJoins("user", authdb.JoinOption{"verification": {}}); err == nil {
			t.Fatal("join without a foreign key must error")
		}
	})
	t.Run("multipleForeignKeys", func(t *testing.T) {
		a := strict(map[string]ModelDef{
			"base": {Fields: map[string]FieldDef{"id": {}}},
			"j": {Fields: map[string]FieldDef{
				"id":  {},
				"aId": {References: &FieldReference{Model: "base", Field: "id"}},
				"bId": {References: &FieldReference{Model: "base", Field: "id"}},
			}},
		})
		if _, err := a.resolveJoins("base", authdb.JoinOption{"j": {}}); err == nil {
			t.Fatal("multiple foreign keys must error")
		}
	})
}

func TestFallback_MatchAllBulkWrites(t *testing.T) {
	ctx := context.Background()
	a := sqliteAdapter(t, "sqlite", Options{})
	for _, w := range []map[string]any{{"id": "m1", "name": "a"}, {"id": "m2", "name": "b"}} {
		if _, err := a.Create(ctx, "widget", w, nil); err != nil {
			t.Fatal(err)
		}
	}
	// Empty-where bulk writes are match-all (bun builders reject WHERE-less
	// statements, so these compile to raw unqualified writes).
	n, err := a.UpdateMany(ctx, "widget", nil, map[string]any{"role": "admin"})
	if err != nil || n != 2 {
		t.Fatalf("match-all UpdateMany = %d, %v; want 2", n, err)
	}
	n, err = a.DeleteMany(ctx, "widget", nil)
	if err != nil || n != 2 {
		t.Fatalf("match-all DeleteMany = %d, %v; want 2", n, err)
	}
	left, err := a.Count(ctx, "widget", nil)
	if err != nil || left != 0 {
		t.Fatalf("table must be empty: %d %v", left, err)
	}
}

func TestFallback_SequentialTransaction(t *testing.T) {
	ctx := context.Background()
	// Offline adapters (nil database) run the callback directly and
	// non-atomically, mirroring upstream's sequential fallback.
	a := NewWithDialect(nil, nil, authdb.Config{}, "pg")
	called := false
	if err := a.Transaction(ctx, func(tx authdb.Adapter) error {
		called = true
		return nil
	}); err != nil || !called {
		t.Fatalf("sequential fallback must run the callback: %v", err)
	}
	if err := a.Transaction(ctx, func(tx authdb.Adapter) error {
		return context.DeadlineExceeded
	}); err != context.DeadlineExceeded {
		t.Fatalf("callback errors must propagate: %v", err)
	}
}

func TestFallback_InvalidWhereError(t *testing.T) {
	err := &InvalidWhereError{Field: "id", Operator: authdb.OpIn, Reason: "Value must be an array/slice"}
	if !strings.Contains(err.Error(), `"id"`) || !strings.Contains(err.Error(), `"in"`) {
		t.Fatalf("typed where error must name field and operator: %q", err.Error())
	}
}

// captureHook records generated SQL for generation assertions.
type captureHook struct {
	queries []string
}

func (h *captureHook) BeforeQuery(ctx context.Context, _ *bun.QueryEvent) context.Context {
	return ctx
}

func (h *captureHook) AfterQuery(_ context.Context, event *bun.QueryEvent) {
	h.queries = append(h.queries, event.Query)
}

func TestFallback_GeneratedSQL(t *testing.T) {
	ctx := context.Background()
	t.Run("mysqlInsertHasNoReturning", func(t *testing.T) {
		db := openSQLiteDB(t)
		hook := &captureHook{}
		db.AddQueryHook(hook)
		a := NewWithDialectOptions(db, db, authdb.Config{}, "mysql", Options{Models: widgetRegistry()})
		if _, err := a.Create(ctx, "widget", map[string]any{"id": "g1", "name": "gen"}, nil); err != nil {
			t.Fatal(err)
		}
		sawInsert := false
		for _, q := range hook.queries {
			if strings.Contains(q, "RETURNING") {
				t.Fatalf("mysql fallback must not emit RETURNING: %q", q)
			}
			if strings.Contains(strings.ToUpper(q), "INSERT INTO") {
				sawInsert = true
			}
		}
		if !sawInsert {
			t.Fatalf("expected an INSERT among: %v", hook.queries)
		}
	})
	t.Run("sqliteInsertUsesReturning", func(t *testing.T) {
		db := openSQLiteDB(t)
		hook := &captureHook{}
		db.AddQueryHook(hook)
		a := NewWithOptions(db, authdb.Config{}, Options{})
		if _, err := a.Create(ctx, "widget", map[string]any{"id": "g2", "name": "gen"}, nil); err != nil {
			t.Fatal(err)
		}
		sawReturning := false
		for _, q := range hook.queries {
			if strings.Contains(q, "RETURNING") {
				sawReturning = true
			}
		}
		if !sawReturning {
			t.Fatalf("sqlite create must use RETURNING: %v", hook.queries)
		}
	})
	t.Run("mssqlOffsetAddsOrderBy", func(t *testing.T) {
		db := openSQLiteDB(t)
		hook := &captureHook{}
		db.AddQueryHook(hook)
		a := NewWithDialectOptions(db, db, authdb.Config{}, "mssql", Options{})
		if _, err := a.FindMany(ctx, "widget", nil, 100, 5, nil, nil); err != nil {
			t.Fatal(err)
		}
		sawOrder := false
		for _, q := range hook.queries {
			if strings.Contains(strings.ToUpper(q), "ORDER BY") {
				sawOrder = true
			}
		}
		if !sawOrder {
			t.Fatalf("mssql offset query must carry ORDER BY: %v", hook.queries)
		}
	})
}
