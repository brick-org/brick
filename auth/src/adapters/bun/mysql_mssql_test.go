package bunadapter

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"

	authdb "github.com/brick-org/brick/auth/src/db"
)

// AUTH-D6-01 live MySQL/MSSQL contract runs + MSSQL persisted-row exclusion.

func mysqlDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("MYSQL_DATABASE_URL")
	if dsn == "" {
		t.Skip("MYSQL_DATABASE_URL not set; skipping live MySQL conformance (see file header for Docker)")
	}
	return dsn
}

func mssqlDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("MSSQL_DATABASE_URL")
	if dsn == "" {
		t.Skip("MSSQL_DATABASE_URL not set; skipping live MSSQL conformance (see file header for Docker)")
	}
	return dsn
}

// TestMySQL_ContractSuite: live run INTENTIONALLY SKIPPED (AUTH-V10-03, no mysql driver in go.mod).
func TestMySQL_ContractSuite(t *testing.T) {
	dsn := mysqlDSN(t)
	_ = dsn
	t.Skip("live MySQL run requires a mysql driver in go.mod (absent by decision) + server; wire conformance covers shapes (see TestFallback_GeneratedSQL + cmd/generate-schema goldens)")
}

// TestMSSQL_ContractSuite: live run INTENTIONALLY SKIPPED (AUTH-V10-03, no mssql driver in go.mod).
func TestMSSQL_ContractSuite(t *testing.T) {
	dsn := mssqlDSN(t)
	_ = dsn
	t.Skip("live MSSQL run requires an mssql driver in go.mod (absent by decision) + server; wire conformance covers shapes (see TestMSSQL_PersistedRowExclusion)")
}

// TestWireConformance_MatrixCoversSkippedLive pins the AUTH-V10-03 skipped-live wire matrix.
func TestWireConformance_MatrixCoversSkippedLive(t *testing.T) {
	ctx := context.Background()

	for _, dialect := range []string{"mysql", "mssql"} {
		t.Run(dialect+"/noReturningNoOutput", func(t *testing.T) {
			db := openSQLiteDB(t)
			hook := &captureHook{}
			db.AddQueryHook(hook)
			a := NewWithDialectOptions(db, db, authdb.Config{}, dialect, Options{Models: widgetRegistry()})
			inner, ok := a.(*Adapter)
			if !ok {
				t.Fatalf("%s adapter must be *Adapter", dialect)
			}
			if inner.supportsReturning() {
				t.Fatalf("%s must not use RETURNING/OUTPUT (fallback cascade instead)", dialect)
			}
			row, err := a.Create(ctx, "widget", map[string]any{"id": "w1", "name": "wire"}, nil)
			if err != nil || row == nil || row["name"] != "wire" {
				t.Fatalf("%s fallback create must return the row: %v %v", dialect, row, err)
			}
			for _, q := range hook.queries {
				upper := strings.ToUpper(q)
				if strings.Contains(q, "RETURNING") {
					t.Fatalf("%s fallback must not emit RETURNING: %q", dialect, q)
				}
				if strings.Contains(upper, "OUTPUT") {
					t.Fatalf("%s fallback must never emit OUTPUT: %q", dialect, q)
				}
			}
		})
	}

	t.Run("mssql/offsetRequiresOrderBy", func(t *testing.T) {
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

	for _, dialect := range []string{"mysql", "mssql"} {
		t.Run(dialect+"/likePortability", func(t *testing.T) {
			a := testAdapter(authdb.Config{}, dialect)
			op, _, _ := mustResolveWire(t, a, authdb.Where{Field: "name", Operator: authdb.OpContains, Value: "ali"})
			if op != "LIKE ?" {
				t.Fatalf("%s contains must be LIKE, got %q", dialect, op)
			}
			op, _, _ = mustResolveWire(t, a, authdb.Where{Field: "name", Operator: authdb.OpContains, Value: "ali", Mode: "insensitive"})
			if op != "LOWER_LIKE" {
				t.Fatalf("%s insensitive must be LOWER_LIKE, got %q", dialect, op)
			}
		})
	}

	t.Run("fallback/casConverges", func(t *testing.T) {
		for _, dialect := range []string{"mysql", "mssql"} {
			a := sqliteAdapter(t, dialect, Options{Models: widgetRegistry()})
			if _, err := a.Create(ctx, "widget", map[string]any{"id": "ctr", "name": "c"}, nil); err != nil {
				t.Fatal(err)
			}
			row, err := a.IncrementOne(ctx, "widget", []authdb.Where{{Field: "id", Value: "ctr"}}, map[string]int{"age": 7}, nil)
			if err != nil || row == nil || asFloat(row["age"]) != 7 {
				t.Fatalf("%s CAS must converge from null: %v %v", dialect, row, err)
			}
		}
	})
	t.Run("capabilities/conservative", func(t *testing.T) {
		if got := defaultCapabilities("mysql"); got.SupportsBooleans || !got.SupportsDates || got.SupportsJSON {
			t.Fatalf("mysql capabilities must stay dates-only: %+v", got)
		}
		if got := defaultCapabilities("mssql"); got.SupportsBooleans || got.SupportsDates {
			t.Fatalf("mssql capabilities must stay conservative: %+v", got)
		}
	})

	t.Run("mssql/updateReselectWithoutOutput", func(t *testing.T) {
		a := sqliteAdapter(t, "mssql", Options{Models: widgetRegistry()})
		if _, err := a.Create(ctx, "widget", map[string]any{"id": "r1", "name": "old"}, nil); err != nil {
			t.Fatal(err)
		}
		updated, err := a.Update(ctx, "widget",
			[]authdb.Where{{Field: "name", Value: "old"}},
			map[string]any{"name": "new"})
		if err != nil || updated == nil || updated["name"] != "new" || updated["id"] != "r1" {
			t.Fatalf("mssql update reselect: %v %v", updated, err)
		}
	})
}

func mustResolveWire(t *testing.T, a *Adapter, w authdb.Where) (string, string, any) {
	t.Helper()
	op, col, val, err := a.resolveWhere("user", w)
	if err != nil {
		t.Fatalf("resolveWhere(%v): %v", w, err)
	}
	return op, col, val
}

// TestMSSQL_PersistedRowExclusion: MSSQL never emits OUTPUT (upstream kysely outputAll); fallback cascade returns rows.
func TestMSSQL_PersistedRowExclusion(t *testing.T) {
	ctx := context.Background()
	a := testAdapter(authdb.Config{}, "mssql")
	if a.supportsReturning() {
		t.Fatal("mssql must not use RETURNING (OUTPUT excluded by decision; fallback cascade instead)")
	}
	db := openSQLiteDB(t)
	hook := &captureHook{}
	db.AddQueryHook(hook)
	mssql := NewWithDialectOptions(db, db, authdb.Config{}, "mssql", Options{Models: widgetRegistry()})
	if _, err := mssql.Create(ctx, "widget", map[string]any{"id": "m1", "name": "persisted"}, nil); err != nil {
		t.Fatal(err)
	}
	for _, q := range hook.queries {
		if strings.Contains(strings.ToUpper(q), "OUTPUT") {
			t.Fatalf("mssql fallback must never emit OUTPUT: %q", q)
		}
	}
	row, err := mssql.FindOne(ctx, "widget", []authdb.Where{{Field: "id", Value: "m1"}}, nil)
	if err != nil || row == nil || row["name"] != "persisted" {
		t.Fatalf("fallback must return the persisted row: %v %v", row, err)
	}
	updated, err := mssql.Update(ctx, "widget",
		[]authdb.Where{{Field: "name", Value: "persisted"}},
		map[string]any{"name": "new"})
	if err != nil || updated == nil || updated["name"] != "new" {
		t.Fatalf("mssql update reselect: %v %v", updated, err)
	}
	ctr, err := mssql.IncrementOne(ctx, "widget", []authdb.Where{{Field: "id", Value: "m1"}}, map[string]int{"age": 2}, nil)
	if err != nil {
		t.Fatalf("mssql CAS increment: %v", err)
	}
	_ = ctr
	_ = sql.ErrNoRows
}
