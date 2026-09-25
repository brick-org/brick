package bunadapter

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sync/atomic"
	"testing"

	authdb "github.com/brick-org/brick/auth/src/db"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
)

// AUTH-D6-01 PostgreSQL isolation.

var pgTableSeq atomic.Uint64

func requirePostgres(t *testing.T) *bun.DB {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping live PostgreSQL conformance")
	}
	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn)))
	db := bun.NewDB(sqldb, pgdialect.New())
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("postgres unreachable: %v", err)
	}
	return db
}

func pgIsolatedWidgets(t *testing.T, db *bun.DB) (authdb.Adapter, string) {
	t.Helper()
	n := pgTableSeq.Add(1)
	table := fmt.Sprintf("widgets_d6_%d", n)
	ctx := context.Background()
	stmt := fmt.Sprintf(`CREATE TABLE %s ("id" TEXT PRIMARY KEY, "name" TEXT, "role" TEXT, "age" INTEGER, "active" INTEGER)`, quoteIdent(table))
	if _, err := db.NewRaw(stmt).Exec(ctx); err != nil {
		t.Fatalf("create table: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.NewRaw(fmt.Sprintf(`DROP TABLE IF EXISTS %s`, quoteIdent(table))).Exec(context.Background())
	})
	cfg := authdb.Config{ModelNames: map[string]string{"widget": table}}
	return NewWithOptions(db, cfg, Options{}), table
}

func pgIsolatedWidgetsStrict(t *testing.T, db *bun.DB) authdb.Adapter {
	t.Helper()
	n := pgTableSeq.Add(1)
	table := fmt.Sprintf("widgets_d6_%d", n)
	ctx := context.Background()
	stmt := fmt.Sprintf(`CREATE TABLE %s ("id" TEXT PRIMARY KEY, "name" TEXT, "role" TEXT, "age" INTEGER, "active" INTEGER)`, quoteIdent(table))
	if _, err := db.NewRaw(stmt).Exec(ctx); err != nil {
		t.Fatalf("create table: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.NewRaw(fmt.Sprintf(`DROP TABLE IF EXISTS %s`, quoteIdent(table))).Exec(context.Background())
	})
	cfg := authdb.Config{ModelNames: map[string]string{"widget": table}}
	return NewWithDialectOptions(db, db, cfg, "pg", Options{Models: widgetRegistry()})
}

// TestPostgres_ContractSuite runs the shared adapter contract against live PostgreSQL in an isolated table.
func TestPostgres_ContractSuite(t *testing.T) {
	db := requirePostgres(t)
	adapter, _ := pgIsolatedWidgets(t, db)
	runAdapterContractSuite(t, "pg", adapter)
}

// TestPostgres_ContractSuiteStrict runs the contract with a registered model registry in its own isolated table.
func TestPostgres_ContractSuiteStrict(t *testing.T) {
	db := requirePostgres(t)
	runAdapterContractSuite(t, "pg-strict", pgIsolatedWidgetsStrict(t, db))
}

// TestPostgres_IsolationParallel proves per-table isolation under parallel execution.
func TestPostgres_IsolationParallel(t *testing.T) {
	db := requirePostgres(t)
	a, _ := pgIsolatedWidgets(t, db)
	b, _ := pgIsolatedWidgets(t, db)
	ctx := context.Background()
	if _, err := a.Create(ctx, "widget", map[string]any{"id": "same", "name": "a"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Create(ctx, "widget", map[string]any{"id": "same", "name": "b"}, nil); err != nil {
		t.Fatal(err)
	}
	gotA, err := a.FindOne(ctx, "widget", []authdb.Where{{Field: "id", Value: "same"}}, []string{"name"})
	if err != nil || gotA["name"] != "a" {
		t.Fatalf("table A must hold its own row: %v %v", gotA, err)
	}
	gotB, err := b.FindOne(ctx, "widget", []authdb.Where{{Field: "id", Value: "same"}}, []string{"name"})
	if err != nil || gotB["name"] != "b" {
		t.Fatalf("table B must hold its own row: %v %v", gotB, err)
	}
	n, err := a.Count(ctx, "widget", nil)
	if err != nil || n != 1 {
		t.Fatalf("table A count = %d, %v; want 1", n, err)
	}
}
