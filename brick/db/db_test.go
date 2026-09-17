package db_test

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/brick-org/brick/brick/db"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
)

// ─── Gating (verbatim from apps/go/integration_test.go:458-476) ────────────
// Pure-unit tests below run un-gated; PG tests call integrationBunDB.

func integrationDatabaseURL(t testing.TB) string {
	t.Helper()
	if os.Getenv("CRM_GO_INTEGRATION_SITE") != "crm2.localhost" {
		t.Skip("set CRM_GO_INTEGRATION_SITE=crm2.localhost to run shared-database tests")
	}
	databaseURL := os.Getenv("DATABASE_URL")
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatalf("invalid DATABASE_URL: %v", err)
	}
	host := parsed.Hostname()
	if host != "localhost" && host != "127.0.0.1" && host != "::1" {
		t.Fatalf("refusing integration test against non-local database host %q", host)
	}
	if strings.Trim(parsed.Path, "/") == "" || strings.Trim(parsed.Path, "/") == "postgres" {
		t.Fatalf("refusing integration test against database %q", parsed.Path)
	}
	return databaseURL
}

func integrationBunDB(t testing.TB) (*db.DB, *bun.DB) {
	t.Helper()
	databaseURL := integrationDatabaseURL(t)
	sqlDB := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(databaseURL)))
	t.Cleanup(func() { _ = sqlDB.Close() })
	bunDB := bun.NewDB(sqlDB, pgdialect.New())
	t.Cleanup(func() { _ = bunDB.Close() })
	return db.New(bunDB), bunDB
}

// scratchTable creates a uniquely-named table, registers DROP cleanup, and
// returns its name. Sequential tests only (no t.Parallel anywhere here).
func scratchTable(t testing.TB, bunDB *bun.DB, ddl string) string {
	t.Helper()
	name := fmt.Sprintf("brick_m4_%d", time.Now().UnixNano())
	ctx := context.Background()
	if _, err := bunDB.NewRaw("CREATE TABLE \"" + name + "\" (" + ddl + ")").Exec(ctx); err != nil {
		t.Fatalf("create scratch table: %v", err)
	}
	t.Cleanup(func() {
		_, _ = bunDB.NewRaw("DROP TABLE IF EXISTS \"" + name + "\"").Exec(context.Background())
	})
	return name
}

const itemDDL = `"id" text PRIMARY KEY, "team" text NOT NULL, "owner" text, "qty" integer NOT NULL DEFAULT 0, "active" boolean NOT NULL DEFAULT false, "title" text NOT NULL`

// seedItems inserts rows via InsertMap and returns the table name.
func seedItems(t testing.TB, database *db.DB, bunDB *bun.DB, rows []map[string]any) string {
	t.Helper()
	table := scratchTable(t, bunDB, itemDDL)
	ctx := context.Background()
	for i, row := range rows {
		if _, err := database.InsertMap(ctx, table, row); err != nil {
			t.Fatalf("seed row %d: %v", i, err)
		}
	}
	return table
}

// ─── Pure-unit: pagination / sort / escaping ────────────────────────────────

func TestNormalizePageLimit(t *testing.T) {
	for _, tc := range []struct{ page, limit, wantPage, wantLimit int }{
		{0, 0, 1, db.DefaultLimit},
		{-3, -5, 1, db.DefaultLimit},
		{2, 10, 2, 10},
		{1, 99999, 1, db.MaxLimit},
		{1, db.MaxLimit + 1, 1, db.MaxLimit},
	} {
		if gotP, gotL := db.NormalizePageLimitForTest(tc.page, tc.limit); gotP != tc.wantPage || gotL != tc.wantLimit {
			t.Errorf("normalizePageLimit(%d,%d) = (%d,%d), want (%d,%d)",
				tc.page, tc.limit, gotP, gotL, tc.wantPage, tc.wantLimit)
		}
	}
	if db.DefaultLimit != 50 || db.MaxLimit != 500 {
		t.Errorf("clamp consts drifted: Default=%d Max=%d", db.DefaultLimit, db.MaxLimit)
	}
}

func TestNormalizeSort(t *testing.T) {
	sortable := []string{"qty", "title"}
	if col, dir, ok := db.NormalizeSortForTest("-qty", sortable); !ok || col != "qty" || dir != "DESC" {
		t.Errorf("desc sort: got %q %q %v", col, dir, ok)
	}
	if col, dir, ok := db.NormalizeSortForTest("title", sortable); !ok || col != "title" || dir != "ASC" {
		t.Errorf("asc sort: got %q %q %v", col, dir, ok)
	}
	for _, bad := range []string{"", "-", "team", "qty; DROP TABLE x", "qty DESC", `"qty"`, "-"} {
		if _, _, ok := db.NormalizeSortForTest(bad, sortable); ok {
			t.Errorf("sort %q must not order (unknown/injection)", bad)
		}
	}
	if _, _, ok := db.NormalizeSortForTest("qty", nil); ok {
		t.Error("empty allowlist must apply no ordering")
	}
}

func TestEscapeLike(t *testing.T) {
	if got := db.EscapeLikeForTest(`100%_off\literal`); got != `100\%\_off\\literal` {
		t.Errorf("escapeLike: got %q", got)
	}
}

func TestSearchGroupShape(t *testing.T) {
	if g := db.SearchGroupForTest("", []string{"title"}); g != nil {
		t.Error("empty search must lower to nil")
	}
	if g := db.SearchGroupForTest("x", nil); g != nil {
		t.Error("empty searchable must lower to nil")
	}
	g := db.SearchGroupForTest("x", []string{"a", "b"})
	if g == nil || len(g.Or) != 2 {
		t.Fatalf("search group shape: %+v", g)
	}
	for _, sub := range g.Or {
		if sub.Operator != db.OpContains || sub.Value != "x" {
			t.Errorf("search leaf: %+v", sub)
		}
	}
}

// ─── Pure-unit: QueryFilter ─────────────────────────────────────────────────

func TestQueryFilterEqIf(t *testing.T) {
	f := db.Filter().
		EqIf("a", "").
		EqIf("b", 0).
		EqIf("c", nil).
		EqIf("d", time.Time{}).
		EqIf("e", []string{}).
		EqIf("f", false). // meaningful — must be kept
		EqIf("g", "x").
		EqIf("h", 5)
	wheres := f.Wheres()
	fields := map[string]bool{}
	for _, w := range wheres {
		fields[w.Field] = true
	}
	for _, skipped := range []string{"a", "b", "c", "d", "e"} {
		if fields[skipped] {
			t.Errorf("EqIf kept zero value for %q", skipped)
		}
	}
	for _, kept := range []string{"f", "g", "h"} {
		if !fields[kept] {
			t.Errorf("EqIf dropped meaningful value for %q", kept)
		}
	}
}

func TestQueryFilterCombinators(t *testing.T) {
	f := db.Filter().
		Eq("team", "sales").
		Ne("owner", "x").
		Where("qty", db.OpGte, 3).
		Between("qty2", 1, 9).
		Search("hello").
		Or(db.Filter().Eq("a", 1), db.Filter().Eq("b", 2))
	wheres := f.Wheres()
	if len(wheres) != 6 { // eq, ne, gte, gte+lte, or-group
		t.Fatalf("expected 6 predicates, got %d: %+v", len(wheres), wheres)
	}
	orGroup := wheres[5]
	if len(orGroup.Or) != 2 {
		t.Fatalf("Or group shape: %+v", orGroup)
	}
	if f.SearchQuery() != "hello" {
		t.Errorf("search: got %q", f.SearchQuery())
	}

	opts := f.Options(db.Order("qty"), db.Limit(10))
	if opts.Sort != "qty" || opts.Limit != 10 || opts.Search != "hello" || len(opts.Filter) != 6 {
		t.Errorf("Options: %+v", opts)
	}
	desc := db.Filter().Options(db.OrderDesc("qty"))
	if desc.Sort != "-qty" {
		t.Errorf("OrderDesc: %+v", desc)
	}

	// ApplyTo preserves the caller's allowlists and appends.
	base := db.ListOptions{Sortable: []string{"qty"}, Searchable: []string{"title"}, Sort: "-qty"}
	merged := db.Filter().Eq("team", "t").ApplyTo(base)
	if len(merged.Filter) != 1 || len(merged.Sortable) != 1 || merged.Sort != "-qty" {
		t.Errorf("ApplyTo: %+v", merged)
	}

	// Caller slice must not be mutated through aliasing.
	before := len(base.Filter)
	_ = db.Filter().Eq("x", 1).Eq("y", 2).ApplyTo(base)
	if len(base.Filter) != before {
		t.Error("ApplyTo mutated caller's Filter backing array")
	}
}

// ─── Pure-unit: package hygiene (Frappe-owns-schema + Raw discipline) ───────

func packageSources(t testing.TB) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") {
			files = append(files, name)
		}
	}
	if len(files) == 0 {
		t.Fatal("no non-test sources found")
	}
	return files
}

func TestPackageHasNoDDLSymbols(t *testing.T) {
	for _, banned := range []string{"NewCreateTable", "NewAddColumn", "CreateTablesWithFK", "syncColumns", "NewDropTable", "NewTruncateTable"} {
		for _, file := range packageSources(t) {
			body, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(body), banned) {
				t.Errorf("%s contains DDL symbol %q — Go never migrates (Frappe owns schema)", file, banned)
			}
		}
	}
}

func TestPackageHasNoSprintfSQL(t *testing.T) {
	for _, file := range packageSources(t) {
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), "Sprintf") {
			t.Errorf("%s uses fmt.Sprintf — query text must use placeholders/quoteIdent, never Sprintf", file)
		}
	}
}

// ─── PG-gated: round-trip ───────────────────────────────────────────────────

func TestRoundTrip(t *testing.T) {
	database, bunDB := integrationBunDB(t)
	ctx := context.Background()
	table := scratchTable(t, bunDB, itemDDL)

	inserted, err := database.InsertMap(ctx, table, map[string]any{
		"id": "r1", "team": "sales", "owner": "ada", "qty": 3, "active": true, "title": "first",
	})
	if err != nil {
		t.Fatalf("InsertMap: %v", err)
	}
	if inserted["title"] != "first" {
		t.Errorf("InsertMap RETURNING: %+v", inserted)
	}
	if _, err := database.InsertMap(ctx, table, map[string]any{}); err == nil {
		t.Error("InsertMap empty map must error")
	}

	found, err := database.FindByIDTable(ctx, table, "r1")
	if err != nil {
		t.Fatalf("FindByIDTable: %v", err)
	}
	if found["owner"] != "ada" {
		t.Errorf("FindByIDTable: %+v", found)
	}
	if _, err := database.FindByIDTable(ctx, table, "missing"); err != sql.ErrNoRows {
		t.Errorf("miss must be sql.ErrNoRows, got %v", err)
	}

	// Guard-scoped read: wrong team → miss, right team → hit.
	if _, err := database.FindByIDTableWhere(ctx, table, "r1", []db.Where{{Field: "team", Value: "support"}}); err != sql.ErrNoRows {
		t.Errorf("guarded miss must be sql.ErrNoRows, got %v", err)
	}
	if _, err := database.FindByIDTableWhere(ctx, table, "r1", []db.Where{{Field: "team", Value: "sales"}}); err != nil {
		t.Errorf("guarded hit: %v", err)
	}

	updated, err := database.UpdateTableWhere(ctx, table, "r1",
		map[string]any{"qty": 7}, []db.Where{{Field: "team", Value: "sales"}})
	if err != nil {
		t.Fatalf("UpdateTableWhere: %v", err)
	}
	if updated["qty"] != int32(7) && updated["qty"] != int64(7) && updated["qty"] != 7 {
		t.Errorf("UpdateTableWhere RETURNING: %+v", updated)
	}
	if _, err := database.UpdateTableWhere(ctx, table, "r1",
		map[string]any{"qty": 9}, []db.Where{{Field: "team", Value: "support"}}); err != sql.ErrNoRows {
		t.Errorf("guarded update miss must be sql.ErrNoRows, got %v", err)
	}
	if _, err := database.UpdateTable(ctx, table, "r1", map[string]any{}); err == nil {
		t.Error("empty update must error")
	}

	n, err := database.DeleteByIDTableWhere(ctx, table, "r1", []db.Where{{Field: "team", Value: "support"}})
	if err != nil || n != 0 {
		t.Errorf("guarded delete must be (0, nil), got (%d, %v)", n, err)
	}
	n, err = database.DeleteByIDTableWhere(ctx, table, "r1", []db.Where{{Field: "team", Value: "sales"}})
	if err != nil || n != 1 {
		t.Errorf("delete must be (1, nil), got (%d, %v)", n, err)
	}
	if _, err := database.FindByIDTable(ctx, table, "r1"); err != sql.ErrNoRows {
		t.Errorf("deleted row must miss, got %v", err)
	}
}

// ─── PG-gated: operator matrix ──────────────────────────────────────────────

func TestOperatorMatrix(t *testing.T) {
	database, bunDB := integrationBunDB(t)
	ctx := context.Background()
	table := seedItems(t, database, bunDB, []map[string]any{
		{"id": "a", "team": "sales", "owner": "ada", "qty": 0, "active": false, "title": "alpha"},
		{"id": "b", "team": "sales", "owner": nil, "qty": 5, "active": true, "title": "bravo"},
		{"id": "c", "team": "support", "owner": "ada", "qty": 10, "active": true, "title": "charlie"},
	})

	count := func(where []db.Where) int64 {
		t.Helper()
		rows, total, err := database.ListMap(ctx, table, db.ListOptions{Filter: where, Limit: 100})
		if err != nil {
			t.Fatalf("ListMap %+v: %v", where, err)
		}
		if int64(len(rows)) != total {
			t.Fatalf("len(rows)=%d != total=%d", len(rows), total)
		}
		return total
	}

	for _, tc := range []struct {
		name  string
		where []db.Where
		want  int64
	}{
		{"eq", []db.Where{{Field: "team", Value: "sales"}}, 2},
		{"default-empty-op-is-eq", []db.Where{{Field: "team", Value: "support"}}, 1},
		{"eq-nil-is-null", []db.Where{{Field: "owner", Value: nil}}, 1},
		{"ne", []db.Where{{Field: "team", Operator: db.OpNe, Value: "sales"}}, 1},
		{"ne-nil-is-not-null", []db.Where{{Field: "owner", Operator: db.OpNe, Value: nil}}, 2},
		{"gt", []db.Where{{Field: "qty", Operator: db.OpGt, Value: 5}}, 1},
		{"gte", []db.Where{{Field: "qty", Operator: db.OpGte, Value: 5}}, 2},
		{"lt", []db.Where{{Field: "qty", Operator: db.OpLt, Value: 5}}, 1},
		{"lte", []db.Where{{Field: "qty", Operator: db.OpLte, Value: 5}}, 2},
		{"in", []db.Where{{Field: "id", Operator: db.OpIn, Value: []string{"a", "c"}}}, 2},
		{"in-empty-matches-nothing", []db.Where{{Field: "id", Operator: db.OpIn, Value: []string{}}}, 0},
		{"not-in", []db.Where{{Field: "id", Operator: db.OpNotIn, Value: []string{"a"}}}, 2},
		{"not-in-empty-matches-all", []db.Where{{Field: "id", Operator: db.OpNotIn, Value: []string{}}}, 3},
		{"contains", []db.Where{{Field: "title", Operator: db.OpContains, Value: "rav"}}, 1},
		{"starts-with", []db.Where{{Field: "title", Operator: db.OpStartsWith, Value: "br"}}, 1},
		{"ends-with", []db.Where{{Field: "title", Operator: db.OpEndsWith, Value: "ha"}}, 1},
		{"is-null", []db.Where{{Field: "owner", Operator: db.OpIsNull}}, 1},
		{"is-not-null", []db.Where{{Field: "owner", Operator: db.OpIsNotNull}}, 2},
		{"bool-false-filterable", []db.Where{{Field: "active", Value: false}}, 1},
		{"bool-true-filterable", []db.Where{{Field: "active", Value: true}}, 2},
		{"zero-int-filterable", []db.Where{{Field: "qty", Value: 0}}, 1},
		{"and-chain", []db.Where{{Field: "team", Value: "sales"}, {Field: "active", Value: true}}, 1},
		{"or-connector", []db.Where{{Field: "id", Value: "a"}, {Field: "id", Value: "c", Connector: "OR"}}, 2},
		{"or-group", []db.Where{{Or: []db.Where{{Field: "id", Value: "a"}, {Field: "id", Value: "c"}}}}, 2},
		{"or-group-empty-denies", []db.Where{{Or: []db.Where{}}}, 0},
		{"not", []db.Where{{Not: &db.Where{Field: "team", Value: "sales"}}}, 1},
	} {
		if got := count(tc.where); got != tc.want {
			t.Errorf("%s: got %d, want %d", tc.name, got, tc.want)
		}
	}

	if _, _, err := database.ListMap(ctx, table, db.ListOptions{
		Filter: []db.Where{{Field: "team", Operator: "bogus", Value: "x"}}, Limit: 10,
	}); err == nil {
		t.Error("unknown operator must error loudly, not silently filter")
	}
}

// ─── PG-gated: LIKE escaping ────────────────────────────────────────────────
// Fails against unescaped builders (beta brick/db): the %/_ wildcards would
// over-match.

func TestLikeEscaping(t *testing.T) {
	database, bunDB := integrationBunDB(t)
	ctx := context.Background()
	table := seedItems(t, database, bunDB, []map[string]any{
		{"id": "a", "team": "t", "qty": 0, "title": `100%_sale`},
		{"id": "b", "team": "t", "qty": 0, "title": "100Xsale"},
		{"id": "c", "team": "t", "qty": 0, "title": `a\b`},
		{"id": "d", "team": "t", "qty": 0, "title": "aXb"},
	})

	rows, _, err := database.ListMap(ctx, table, db.ListOptions{
		Filter: []db.Where{{Field: "title", Operator: db.OpContains, Value: `100%_sale`}}, Limit: 10,
	})
	if err != nil {
		t.Fatalf("contains: %v", err)
	}
	if len(rows) != 1 || rows[0]["id"] != "a" {
		t.Errorf("escaped contains over-matched: %+v", rows)
	}

	rows, _, err = database.ListMap(ctx, table, db.ListOptions{
		Filter: []db.Where{{Field: "title", Operator: db.OpContains, Value: `a\b`}}, Limit: 10,
	})
	if err != nil {
		t.Fatalf("backslash contains: %v", err)
	}
	if len(rows) != 1 || rows[0]["id"] != "c" {
		t.Errorf("backslash contains matched: %+v", rows)
	}
}

// ─── PG-gated: guard composition ────────────────────────────────────────────
// Guard Where ANDed after user filters: conflicting client filter yields
// zero rows (never cross-team), narrowing filter narrows.

func TestGuardComposition(t *testing.T) {
	database, bunDB := integrationBunDB(t)
	ctx := context.Background()
	table := seedItems(t, database, bunDB, []map[string]any{
		{"id": "a", "team": "sales", "owner": "ada", "qty": 1, "title": "a"},
		{"id": "b", "team": "support", "owner": "ada", "qty": 1, "title": "b"},
		{"id": "c", "team": "sales", "owner": "bob", "qty": 1, "title": "c"},
	})
	guard := []db.Where{{Field: "team", Value: "sales"}}

	rows, total, err := database.ListMap(ctx, table, db.ListOptions{
		Filter: append(guard, db.Where{Field: "team", Value: "support"}), Limit: 10,
	})
	if err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("conflicting client filter must yield zero rows, got (%d, %v)", total, err)
	}

	rows, total, err = database.ListMap(ctx, table, db.ListOptions{
		Filter: append(append([]db.Where{}, guard...), db.Where{Field: "owner", Value: "ada"}), Limit: 10,
	})
	if err != nil || total != 1 || rows[0]["id"] != "a" {
		t.Errorf("narrowing filter must narrow, got %+v (%d, %v)", rows, total, err)
	}

	// Deny-by-default sentinels behave as ordinary OpEq values (match nothing).
	rows, total, err = database.ListMap(ctx, table, db.ListOptions{
		Filter: []db.Where{{Field: "team", Value: "__no_selected_team__"}}, Limit: 10,
	})
	if err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("deny sentinel must match nothing, got (%d, %v)", total, err)
	}
}

// ─── PG-gated: clamp / allowlist / search ───────────────────────────────────

func TestClampAndSortAllowlist(t *testing.T) {
	database, bunDB := integrationBunDB(t)
	ctx := context.Background()
	table := scratchTable(t, bunDB, itemDDL)
	if _, err := bunDB.NewRaw(`INSERT INTO "` + table + `" ("id","team","qty","title") ` +
		`SELECT 'seed-' || g, 't', g, 'row-' || g FROM generate_series(1, 60) g`).Exec(ctx); err != nil {
		t.Fatalf("bulk seed: %v", err)
	}

	rows, total, err := database.ListMap(ctx, table, db.ListOptions{Limit: 0})
	if err != nil || total != 60 || len(rows) != db.DefaultLimit {
		t.Errorf("Limit 0 must default to %d, got len=%d total=%d (%v)", db.DefaultLimit, len(rows), total, err)
	}
	rows, _, err = database.ListMap(ctx, table, db.ListOptions{Page: 0, Limit: 5})
	if err != nil || len(rows) != 5 {
		t.Errorf("Page 0 must behave as page 1, got len=%d (%v)", len(rows), err)
	}
	rows, _, err = database.ListMap(ctx, table, db.ListOptions{Limit: 99999})
	if err != nil || len(rows) != 60 {
		t.Errorf("huge limit clamps to %d, got len=%d (%v)", db.MaxLimit, len(rows), err)
	}

	rows, _, err = database.ListMap(ctx, table, db.ListOptions{
		Sort: "-qty", Sortable: []string{"qty"}, Limit: 3,
	})
	if err != nil || len(rows) != 3 || rows[0]["qty"] != int32(60) && rows[0]["qty"] != int64(60) {
		t.Errorf("desc sort: %+v (%v)", rows, err)
	}

	for _, bad := range []string{"qty; DROP TABLE x", "team", `"qty"`, "-"} {
		rows, total, err = database.ListMap(ctx, table, db.ListOptions{Sort: bad, Sortable: []string{"qty"}, Limit: 5})
		if err != nil || total != 60 || len(rows) != 5 {
			t.Errorf("sort %q must be ignored without error, got (%d, %v)", bad, total, err)
		}
	}
	if _, err := bunDB.NewRaw("SELECT COUNT(*) FROM \"" + table + "\"").Exec(ctx); err != nil {
		t.Errorf("injection sort damaged table: %v", err)
	}
}

func TestSearchWiring(t *testing.T) {
	database, bunDB := integrationBunDB(t)
	ctx := context.Background()
	table := seedItems(t, database, bunDB, []map[string]any{
		{"id": "a", "team": "Sales", "qty": 0, "title": "Quarterly Report"},
		{"id": "b", "team": "support", "qty": 0, "title": "sales playbook"},
		{"id": "c", "team": "support", "qty": 0, "title": "unrelated"},
	})

	rows, total, err := database.ListMap(ctx, table, db.ListOptions{
		Search: "sales", Searchable: []string{"title", "team"}, Limit: 10,
	})
	if err != nil || total != 2 {
		t.Errorf("case-insensitive search across Searchable: got %d (%v) %+v", total, err, rows)
	}

	rows, total, err = database.ListMap(ctx, table, db.ListOptions{Search: "sales", Limit: 10})
	if err != nil || total != 3 {
		t.Errorf("empty Searchable must ignore Search, got %d (%v)", total, err)
	}

	rows, total, err = database.ListMap(ctx, table, db.ListOptions{
		Search: "100%_", Searchable: []string{"title"}, Limit: 10,
	})
	if err != nil || total != 0 {
		t.Errorf("search metachars must be escaped, got %d (%v) %+v", total, err, rows)
	}
}

// ─── PG-gated: empty-delete refusal + tx rollback ───────────────────────────

func TestEmptyDeleteRefusal(t *testing.T) {
	database, bunDB := integrationBunDB(t)
	ctx := context.Background()
	table := seedItems(t, database, bunDB, []map[string]any{
		{"id": "a", "team": "sales", "qty": 0, "title": "a"},
	})

	if _, err := database.DeleteWhere(ctx, table, nil); err == nil ||
		!strings.Contains(err.Error(), "refusing to delete") {
		t.Errorf("empty DeleteWhere must refuse loudly, got %v", err)
	}
	if _, err := database.DeleteWhere(ctx, table, []db.Where{}); err == nil {
		t.Error("empty-slice DeleteWhere must refuse")
	}
	rows, total, err := database.ListMap(ctx, table, db.ListOptions{Limit: 10})
	if err != nil || total != 1 || len(rows) != 1 {
		t.Errorf("refused delete must touch zero rows, got %d (%v)", total, err)
	}

	n, err := database.DeleteWhere(ctx, table, []db.Where{{Field: "team", Value: "support"}})
	if err != nil || n != 0 {
		t.Errorf("cross-team delete must be (0, nil), got (%d, %v)", n, err)
	}
}

func TestTxRollback(t *testing.T) {
	database, bunDB := integrationBunDB(t)
	ctx := context.Background()
	table := scratchTable(t, bunDB, itemDDL)

	err := database.RunInTx(ctx, nil, func(ctx context.Context, txDB *db.DB) error {
		if _, err := txDB.InsertMap(ctx, table, map[string]any{"id": "tx1", "team": "t", "title": "x"}); err != nil {
			return err
		}
		var n int64
		if err := txDB.Raw(ctx, &n, `SELECT COUNT(*) FROM "`+table+`"`); err != nil {
			return err
		}
		if n != 1 {
			t.Errorf("tx must see its own write, got %d", n)
		}
		return fmt.Errorf("boom")
	})
	if err == nil || err.Error() != "boom" {
		t.Fatalf("RunInTx must propagate fn error, got %v", err)
	}
	rows, total, err := database.ListMap(ctx, table, db.ListOptions{Limit: 10})
	if err != nil || total != 0 || len(rows) != 0 {
		t.Errorf("rolled-back row must be absent, got %d (%v)", total, err)
	}

	if err := database.RunInTx(ctx, nil, func(ctx context.Context, txDB *db.DB) error {
		_, err := txDB.InsertMap(ctx, table, map[string]any{"id": "tx2", "team": "t", "title": "y"})
		return err
	}); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if _, err := database.FindByIDTable(ctx, table, "tx2"); err != nil {
		t.Errorf("committed row must persist: %v", err)
	}
}

// ─── PG-gated: NextFrappeIntPK ──────────────────────────────────────────────

func TestNextFrappeIntPKConcurrency(t *testing.T) {
	database, bunDB := integrationBunDB(t)
	ctx := context.Background()
	table := scratchTable(t, bunDB, `"name" bigint PRIMARY KEY`)

	const n = 8
	names := make([]int64, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			err := database.RunInTx(ctx, nil, func(ctx context.Context, txDB *db.DB) error {
				next, err := txDB.NextFrappeIntPK(ctx, table)
				if err != nil {
					return err
				}
				names[i] = next
				var inserted int64
				return txDB.Raw(ctx, &inserted, `INSERT INTO "`+table+`" ("name") VALUES (?) RETURNING "name"`, next)
			})
			errs[i] = err
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("worker %d: %v", i, err)
		}
	}
	seen := map[int64]bool{}
	for _, name := range names {
		if name < 1 || name > n || seen[name] {
			t.Fatalf("names must be distinct 1..%d, got %v", n, names)
		}
		seen[name] = true
	}
}

// ─── PG-gated: Patch ────────────────────────────────────────────────────────

func TestPatch(t *testing.T) {
	database, bunDB := integrationBunDB(t)
	ctx := context.Background()
	table := seedItems(t, database, bunDB, []map[string]any{
		{"id": "p1", "team": "t", "qty": 1, "title": "orig"},
	})

	patched, err := database.Patch(ctx, table, "p1", map[string]any{"title": "new", "qty": 2})
	if err != nil || patched["title"] != "new" {
		t.Errorf("Patch: %+v (%v)", patched, err)
	}
	for _, pk := range []string{"id", "name"} {
		if _, err := database.Patch(ctx, table, "p1", map[string]any{pk: "x"}); err == nil {
			t.Errorf("Patch must refuse PK column %q", pk)
		}
	}
	if _, err := database.Patch(ctx, table, "p1", map[string]any{}); err == nil {
		t.Error("Patch with empty vals must error")
	}
}

// ─── PG-gated: custom-route expressibility (§9 backbone) ────────────────────
// Each subtest mirrors a live call shape in apps/go/resources so the M5
// import swap is mechanical.

func TestExpressibilityRawScalarFallback(t *testing.T) {
	database, bunDB := integrationBunDB(t)
	ctx := context.Background()
	table := scratchTable(t, bunDB, `"name" text PRIMARY KEY, "dt" text, "type" text, "team" text, "layout" text`)
	seed := []map[string]any{
		{"name": "global", "dt": "Lead", "type": "Quick Entry", "team": nil, "layout": `{"a":1}`},
		{"name": "team-one", "dt": "Lead", "type": "Quick Entry", "team": "one", "layout": `{"b":2}`},
	}
	for _, row := range seed {
		if _, err := database.InsertMap(ctx, table, row); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	// findFieldsLayout shape: team-fallback COALESCE + CASE ORDER.
	lookup := func(team string) string {
		t.Helper()
		var layout string
		err := database.Raw(ctx, &layout,
			`SELECT COALESCE((SELECT "layout" FROM "`+table+`" WHERE "dt" = ? AND "type" = ? `+
				`AND (COALESCE("team", '') = ? OR COALESCE("team", '') = '') `+
				`ORDER BY CASE WHEN COALESCE("team", '') = ? THEN 0 ELSE 1 END LIMIT 1), '')`,
			"Lead", "Quick Entry", team, team)
		if err != nil {
			t.Fatalf("fallback lookup: %v", err)
		}
		return layout
	}
	if got := lookup("one"); got != `{"b":2}` {
		t.Errorf("team layout: got %s", got)
	}
	if got := lookup("missing"); got != `{"a":1}` {
		t.Errorf("global fallback: got %s", got)
	}
}

func TestExpressibilityUpsertInTx(t *testing.T) {
	database, bunDB := integrationBunDB(t)
	ctx := context.Background()
	table := scratchTable(t, bunDB, `"name" text PRIMARY KEY, "dt" text, "type" text, "team" text, "layout" text`)

	// saveFieldsLayout shape: lookup + INSERT … ON CONFLICT … RETURNING,
	// wrapped in RunInTx (new vs today — atomic).
	upsert := func(dt, typ, team, layout string) string {
		t.Helper()
		var saved string
		err := database.RunInTx(ctx, nil, func(ctx context.Context, txDB *db.DB) error {
			var name string
			if err := txDB.Raw(ctx, &name,
				`SELECT COALESCE((SELECT "name" FROM "`+table+`" WHERE "dt" = ? AND "type" = ? AND COALESCE("team", '') = ? LIMIT 1), ?)`,
				dt, typ, team, dt+"-"+typ); err != nil {
				return err
			}
			return txDB.Raw(ctx, &saved,
				`INSERT INTO "`+table+`" ("name","dt","type","team","layout") VALUES (?,?,?,?,?) `+
					`ON CONFLICT ("name") DO UPDATE SET "layout" = EXCLUDED."layout" RETURNING "layout"`,
				name, dt, typ, team, layout)
		})
		if err != nil {
			t.Fatalf("upsert: %v", err)
		}
		return saved
	}
	if got := upsert("Lead", "Quick Entry", "", `{"v":1}`); got != `{"v":1}` {
		t.Errorf("insert: got %s", got)
	}
	if got := upsert("Lead", "Quick Entry", "", `{"v":2}`); got != `{"v":2}` {
		t.Errorf("conflict-update: got %s", got)
	}
}

func TestExpressibilityMapSelectsAndPerms(t *testing.T) {
	database, bunDB := integrationBunDB(t)
	ctx := context.Background()
	table := scratchTable(t, bunDB, `"name" text PRIMARY KEY, "role" text, "perm" integer`)

	for _, row := range []map[string]any{
		{"name": "f1", "role": "admin", "perm": 1},
		{"name": "f2", "role": "user", "perm": 0},
	} {
		if _, err := database.InsertMap(ctx, table, row); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	// loadFrappeFields shape: Raw → []map with ORDER BY.
	var fields []map[string]any
	if err := database.Raw(ctx, &fields, `SELECT * FROM "`+table+`" ORDER BY "name"`); err != nil {
		t.Fatalf("map select: %v", err)
	}
	if len(fields) != 2 {
		t.Fatalf("map select rows: %+v", fields)
	}

	// applyFieldPermissions shape: bun.In(roles) inside Raw.
	var allowed bool
	if err := database.Raw(ctx, &allowed,
		`SELECT COUNT(*) > 0 FROM "`+table+`" WHERE "role" IN (?) AND "perm" = 1`, bun.In([]string{"admin"})); err != nil {
		t.Fatalf("bun.In raw: %v", err)
	}
	if !allowed {
		t.Error("bun.In(raw) must find the admin row")
	}

	// appendForecastingSection shape: Raw → bool.
	var exists bool
	if err := database.Raw(ctx, &exists, `SELECT EXISTS(SELECT 1 FROM "`+table+`" WHERE "name" = ?)`, "f1"); err != nil {
		t.Fatalf("bool raw: %v", err)
	}
	if !exists {
		t.Error("EXISTS must be true")
	}
}

func TestExpressibilityPublicPageLookup(t *testing.T) {
	database, bunDB := integrationBunDB(t)
	ctx := context.Background()
	table := scratchTable(t, bunDB, `"id" text PRIMARY KEY, "slug" text, "is_public" boolean`)

	for _, row := range []map[string]any{
		{"id": "1", "slug": "hello", "is_public": true},
		{"id": "2", "slug": "secret", "is_public": false},
	} {
		if _, err := database.InsertMap(ctx, table, row); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	// routes.go / render.go shape: FindByFieldTableWhere(slug + is_public).
	row, err := database.FindByFieldTableWhere(ctx, table, "slug", "hello",
		[]db.Where{{Field: "is_public", Value: true}})
	if err != nil || row["id"] != "1" {
		t.Errorf("public lookup: %+v (%v)", row, err)
	}
	if _, err := database.FindByFieldTableWhere(ctx, table, "slug", "secret",
		[]db.Where{{Field: "is_public", Value: true}}); err != sql.ErrNoRows {
		t.Errorf("private page must miss, got %v", err)
	}
}

// ─── PG-gated: typed-model paths ────────────────────────────────────────────

type m4Item struct {
	bun.BaseModel `bun:"table:m4_typed"`
	ID            string `bun:"id,pk" json:"id"`
	Team          string `bun:"team,notnull" json:"team"`
	Qty           int32  `bun:"qty,notnull" json:"qty"`
	Active        bool   `bun:"active,notnull" json:"active"`
	Title         string `bun:"title,notnull" json:"title"`
}

func typedTable(t testing.TB, bunDB *bun.DB) {
	t.Helper()
	ctx := context.Background()
	if _, err := bunDB.NewRaw("DROP TABLE IF EXISTS m4_typed").Exec(ctx); err != nil {
		t.Fatalf("drop: %v", err)
	}
	if _, err := bunDB.NewRaw(`CREATE TABLE m4_typed ("id" text PRIMARY KEY, "team" text NOT NULL, "qty" integer NOT NULL, "active" boolean NOT NULL, "title" text NOT NULL)`).Exec(ctx); err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() {
		_, _ = bunDB.NewRaw("DROP TABLE IF EXISTS m4_typed").Exec(context.Background())
	})
}

func TestTypedPaths(t *testing.T) {
	database, bunDB := integrationBunDB(t)
	ctx := context.Background()
	typedTable(t, bunDB)

	if _, err := database.Create(ctx, map[string]any{"x": 1}); err == nil {
		t.Error("Create(map) must direct to InsertMap")
	}
	created, err := database.Create(ctx, &m4Item{ID: "t1", Team: "sales", Qty: 4, Active: true, Title: "typed"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.(*m4Item).ID != "t1" {
		t.Errorf("Create: %+v", created)
	}

	got, err := database.FindByID(ctx, "t1", &m4Item{})
	if err != nil || got.(*m4Item).Title != "typed" {
		t.Errorf("FindByID: %+v (%v)", got, err)
	}
	if _, err := database.FindByID(ctx, "t1", map[string]any{}); err == nil {
		t.Error("FindByID(map) must error")
	}

	first, err := database.FindFirst(ctx, &m4Item{}, []db.Where{{Field: "team", Value: "sales"}})
	if err != nil || first.(*m4Item).ID != "t1" {
		t.Errorf("FindFirst: %+v (%v)", first, err)
	}
	if _, err := database.FindFirst(ctx, &m4Item{}, []db.Where{{Field: "team", Value: "nope"}}); err != sql.ErrNoRows {
		t.Errorf("FindFirst miss must be sql.ErrNoRows, got %v", err)
	}

	n, err := database.Count(ctx, &m4Item{}, []db.Where{{Field: "active", Value: true}})
	if err != nil || n != 1 {
		t.Errorf("Count: got %d (%v)", n, err)
	}

	var items []m4Item
	total, err := database.List(ctx, &items, db.ListOptions{
		Filter: []db.Where{{Field: "team", Value: "sales"}}, Sort: "id", Sortable: []string{"id"}, Limit: 10,
	})
	if err != nil || total != 1 || len(items) != 1 || items[0].ID != "t1" {
		t.Errorf("List: total=%d items=%+v (%v)", total, items, err)
	}

	if _, err := database.Update(ctx, &m4Item{}, "t1", map[string]any{}); err == nil {
		t.Error("Update empty must error")
	}
	if _, err := database.Update(ctx, &m4Item{}, "t1", map[string]any{"qty": 9}); err != nil {
		t.Errorf("Update: %v", err)
	}
	after, err := database.FindByID(ctx, "t1", &m4Item{})
	if err != nil || after.(*m4Item).Qty != 9 {
		t.Errorf("Update persisted: %+v (%v)", after, err)
	}

	if err := database.DeleteByID(ctx, map[string]any{}, "t1"); err == nil {
		t.Error("DeleteByID(map) must error")
	}
	if err := database.DeleteByID(ctx, &m4Item{ID: "t1"}, "t1"); err != nil {
		t.Errorf("DeleteByID: %v", err)
	}
	if _, err := database.FindByID(ctx, "t1", &m4Item{}); err != sql.ErrNoRows {
		t.Errorf("deleted typed row must miss, got %v", err)
	}

	if _, err := database.Create(ctx, &m4Item{ID: "t2", Team: "t", Title: "x"}); err != nil {
		t.Fatalf("re-create: %v", err)
	}
	if err := database.Delete(ctx, &m4Item{ID: "t2"}); err != nil {
		t.Errorf("Delete: %v", err)
	}
}
