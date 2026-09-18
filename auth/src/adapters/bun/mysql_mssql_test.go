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
// AUTH-V10-03 live-vs-wire matrix recertification (2026-09-21):
//
// LIVE STATUS: neither dialect runs live from Go here. go.mod declares only
// pgdriver + modernc sqlite; no mysql/mssql driver exists, and adding a
// module dependency is out of scope (disclosure required). Environment
// probes: mysql:8 pulls, boots, and answers `mysqladmin ping`
// (docker -p 5434:3306); mcr.microsoft.com/mssql/server:2022-latest pulls
// but does not start on this arm64 host (amd64-only image, entrypoint exec
// fails), and no mssql driver exists either way. A forced-label SQLite run
// is NOT live evidence, so the tests below pin wire conformance instead.
//
// WIRE EVIDENCE (all hermetic, all green):
//   - Fallback cascades execute end to end on SQLite under the mysql/mssql
//     labels: TestFallback_CreateCascade (knownID/unique/fullField/
//     ambiguous→null/lenient), TestFallback_UpdateReselectsByNewValues,
//     TestFallback_NullCounterStartsAtZero, TestFallback_MatchAllBulkWrites,
//     TestFallback_SequentialTransaction.
//   - SQL shapes: TestFallback_GeneratedSQL (mysql insert has no RETURNING;
//     mssql offset carries ORDER BY), TestFallback_RawSQLShapes (consume/
//     increment shapes, identifier escaping), TestFallback_CapabilitiesMatrix
//     (supportsReturning false for mysql+mssql; date/bool/JSON matrix).
//   - MSSQL OUTPUT exclusion: TestMSSQL_PersistedRowExclusion below.
//   - Dialect DDL: cmd/generate-schema golden fixtures golden_mysql.sql +
//     golden_mssql.sql (byte-exact planner output incl. backtick/bracket
//     quoting, bounded varchar keys, MSSQL NULL-filtered unique indexes).
//   - Matrix guard: TestWireConformance_MatrixCoversSkippedLive re-asserts
//     every skipped live capability's wire property so the matrix cannot
//     drift silently.
//
// Live runs (kept for servers with drivers; skipped here by design):
//   MYSQL_DATABASE_URL='mysql://user:pass@tcp(localhost:3306)/auth_test' \
//     GOWORK=off go test -count=1 ./adapters/bun/ -run TestMySQL_ -v
//   MSSQL_DATABASE_URL='sqlserver://sa:Pass@word@localhost:1433?database=master' \
//     GOWORK=off go test -count=1 ./adapters/bun/ -run TestMSSQL_ -v
//
// Docker examples:
//   docker run -d --name auth-mysql -e MYSQL_ROOT_PASSWORD=pass \
//     -e MYSQL_DATABASE=auth_test -p 3306:3306 mysql:8
//   docker run -d --name auth-mssql -e ACCEPT_EULA=Y -e SA_PASSWORD='Pass@word' \
//     -p 1433:1433 mcr.microsoft.com/mssql/server:2022-latest
//
// Without a live server the wire-conformance tests below (SQL shapes, DDL
// goldens via cmd/generate-schema, fallback cascades against SQLite) are the
// evidence; live runs are recorded in the D6 report, never gated in CI.

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

// TestMySQL_ContractSuite runs the shared contract against live MySQL with a
// unique table prefix per test so parallel package execution never shares
// tables. INTENTIONALLY SKIPPED (AUTH-V10-03): go.mod declares no mysql
// driver (pgdriver + modernc sqlite only) and adding a module dependency is
// out of scope; wire conformance (TestWireConformance_MatrixCoversSkippedLive
// + TestFallback_* mysql subtests + golden_mysql.sql) is the evidence.
func TestMySQL_ContractSuite(t *testing.T) {
	dsn := mysqlDSN(t)
	_ = dsn
	t.Skip("live MySQL run requires a mysql driver in go.mod (absent by decision) + server; wire conformance covers shapes (see TestFallback_GeneratedSQL + cmd/generate-schema goldens)")
}

// TestMSSQL_ContractSuite runs the shared contract against live MSSQL with a
// unique schema per test. INTENTIONALLY SKIPPED (AUTH-V10-03): go.mod
// declares no mssql driver and the server image does not start on this
// arm64 host; wire conformance (TestWireConformance_MatrixCoversSkippedLive
// + TestMSSQL_PersistedRowExclusion) is the evidence.
func TestMSSQL_ContractSuite(t *testing.T) {
	dsn := mssqlDSN(t)
	_ = dsn
	t.Skip("live MSSQL run requires an mssql driver in go.mod (absent by decision) + server; wire conformance covers shapes (see TestMSSQL_PersistedRowExclusion)")
}

// TestWireConformance_MatrixCoversSkippedLive pins the AUTH-V10-03
// live-vs-wire matrix as executable assertions: every skipped live
// capability has named wire evidence, and the decisive wire properties are
// re-asserted here so the matrix cannot drift silently. A forced-label
// SQLite run is documented as NOT live evidence; these assertions pin the
// SQL/capability contract the labels guarantee.
func TestWireConformance_MatrixCoversSkippedLive(t *testing.T) {
	ctx := context.Background()

	// Skipped live: MySQL + MSSQL contract CRUD (no drivers in go.mod).
	// Wire: neither label may emit RETURNING or OUTPUT; inserts still
	// persist and re-read (fallback cascade).
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

	// Skipped live: MSSQL OFFSET paging. Wire: every offset query carries
	// ORDER BY (SQL Server requires it).
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

	// Skipped live: LIKE portability on both labels. Wire: sensitive path is
	// portable LIKE (never ILIKE off postgres); insensitive path is
	// LOWER() LIKE (never ILIKE).
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

	// Skipped live: atomic counters on both labels. Wire: the
	// compare-and-swap fallback converges (null counters start at 0) and
	// the capability matrix stays conservative.
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

	// Skipped live: MSSQL OUTPUT inserted (intentional exclusion, see
	// TestMSSQL_PersistedRowExclusion). Wire: update-then-reselect still
	// targets the updated row without OUTPUT.
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

// TestMSSQL_PersistedRowExclusion registers the exact intentional exclusion:
// upstream kysely uses OUTPUT inserted (outputAll("inserted")) for MSSQL
// creates/updates/deletes/increments
// (vendor/.../kysely-adapter/src/kysely-adapter.ts:287-288,841-852,966-968),
// while this adapter uses the portable fallback cascade (insert + re-read by
// id / unique column / full-field match, update-then-reselect,
// snapshot-guarded CAS) and never emits OUTPUT.
//
// The fallback still returns the persisted row (generated IDs, defaults,
// trigger values) or (nil, nil) when unidentifiable, matching upstream's
// warn-and-null. This test pins the exclusion: supportsReturning is false
// for mssql, no generated SQL contains OUTPUT, and the cascade returns rows.
func TestMSSQL_PersistedRowExclusion(t *testing.T) {
	ctx := context.Background()
	a := testAdapter(authdb.Config{}, "mssql")
	if a.supportsReturning() {
		t.Fatal("mssql must not use RETURNING (OUTPUT excluded by decision; fallback cascade instead)")
	}
	// No generated query may contain OUTPUT (the excluded upstream primitive).
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
	// Update-then-reselect still targets the updated row (no OUTPUT).
	updated, err := mssql.Update(ctx, "widget",
		[]authdb.Where{{Field: "name", Value: "persisted"}},
		map[string]any{"name": "new"})
	if err != nil || updated == nil || updated["name"] != "new" {
		t.Fatalf("mssql update reselect: %v %v", updated, err)
	}
	// CAS increment still converges without native atomics.
	ctr, err := mssql.IncrementOne(ctx, "widget", []authdb.Where{{Field: "id", Value: "m1"}}, map[string]int{"age": 2}, nil)
	if err != nil {
		t.Fatalf("mssql CAS increment: %v", err)
	}
	_ = ctr
	_ = sql.ErrNoRows
}
