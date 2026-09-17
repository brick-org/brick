package brick

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/brick-org/brick/db"
	"github.com/brick-org/brick/schema"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
)

// ─── Gating (same rule as apps/go + brick/db) ──────────────────────────────

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

func integrationBrickDB(t testing.TB) (*db.DB, *bun.DB) {
	t.Helper()
	databaseURL := integrationDatabaseURL(t)
	sqlDB := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(databaseURL)))
	t.Cleanup(func() { _ = sqlDB.Close() })
	bunDB := bun.NewDB(sqlDB, pgdialect.New())
	t.Cleanup(func() { _ = bunDB.Close() })
	return db.New(bunDB), bunDB
}

// ─── Test app ─────────────────────────────────────────────────────────────
// Mirrors apps/go/resources: team-scoped resource, auth Check, server-side
// team/user stamping hook, int-PK resource for autoname concurrency.

type m5Ctx struct {
	AppCtx
	Team string
}

func m5AuthedCtx(team string) context.Context {
	return storeAppCtx(context.Background(), &m5Ctx{
		AppCtx: AppCtx{Actor: &User{ID: "ada", Email: "ada@example.com", Name: "Ada"}, Session: &Session{ID: "s", UserID: "ada"}},
		Team:   team,
	})
}

func m5AuthCheck() Guard[map[string]any] {
	return Guard[map[string]any]{
		Check: func(ac AccessCtx[map[string]any]) error {
			if GetAppCtx[m5Ctx](ac.Context) == nil {
				return Unauthorized("sign in required")
			}
			return nil
		},
	}
}

func m5TeamFilter() Guard[map[string]any] {
	return Guard[map[string]any]{
		Filter: func(ac AccessCtx[map[string]any]) []db.Where {
			ctx := GetAppCtx[m5Ctx](ac.Context)
			if ctx == nil || ctx.Team == "" {
				return []db.Where{{Field: "team", Value: "__no_team__"}}
			}
			return []db.Where{{Field: "team", Value: ctx.Team}}
		},
	}
}

func m5StampHook() Hooks[map[string]any, map[string]any] {
	return Hooks[map[string]any, map[string]any]{
		BeforeCreate: func(hc HookCtx[map[string]any, map[string]any]) error {
			input := *hc.Input
			if ctx := GetAppCtx[m5Ctx](hc.Context); ctx != nil {
				input["team"] = ctx.Team
				input["owner"] = ctx.Actor.ID
			}
			return nil
		},
	}
}

type wRow struct {
	bun.BaseModel `bun:"table:brick_m5_widget"`
	ID            string `bun:"id,pk" json:"id"`
	Team          string `bun:"team,notnull" json:"team"`
	Owner         string `bun:"owner" json:"owner"`
	Slug          string `bun:"slug,unique,notnull" json:"slug"`
	Title         string `bun:"title,notnull" json:"title"`
	Kind          string `bun:"kind,notnull,default:'a'" json:"kind"`
	Qty           int32  `bun:"qty,notnull,default:0" json:"qty"`
	Active        bool   `bun:"active,notnull,default:false" json:"active"`
}

type wResp struct {
	ID     string `json:"id"`
	Team   string `json:"team"`
	Owner  string `json:"owner"`
	Slug   string `json:"slug"`
	Title  string `json:"title"`
	Kind   string `json:"kind"`
	Qty    int32  `json:"qty"`
	Active bool   `json:"active"`
}

type wCreate struct {
	Team   string `json:"team"`
	Owner  string `json:"owner,omitempty"`
	Slug   string `json:"slug"`
	Title  string `json:"title"`
	Kind   string `json:"kind,omitempty"`
	Qty    int32  `json:"qty,omitempty"`
	Active bool   `json:"active,omitempty"`
}

type wUpdate struct {
	Title  *string `json:"title,omitempty"`
	Kind   *string `json:"kind,omitempty"`
	Qty    *int32  `json:"qty,omitempty"`
	Team   *string `json:"team,omitempty"`
	Owner  *string `json:"owner,omitempty"`
	Ro     *string `json:"ro,omitempty"`
	ID     *string `json:"id,omitempty"`
	Secret *string `json:"secret,omitempty"`
}

type wList struct {
	Page   int    `query:"page"`
	Limit  int    `query:"limit"`
	Sort   string `query:"sort"`
	Search string `query:"search"`
	Slug   string `query:"slug"`
	Team   string `query:"team"`
	Active bool   `query:"active"`
}

func (in *wList) ToListOptions() db.ListOptions {
	opts := db.ListOptions{Page: in.Page, Limit: in.Limit, Sort: in.Sort, Search: in.Search}
	if in.Slug != "" {
		opts.Filter = append(opts.Filter, db.Where{Field: "slug", Value: in.Slug})
	}
	if in.Team != "" {
		opts.Filter = append(opts.Filter, db.Where{Field: "team", Value: in.Team})
	}
	// Scalar bool (huma panics on pointer query params): only true is
	// expressible — the documented false/0 CRUD-list limitation.
	if in.Active {
		opts.Filter = append(opts.Filter, db.Where{Field: "active", Value: true})
	}
	return opts
}

type wSchema = Schema[wRow, wResp, wCreate, wUpdate, wList]

func m5WidgetResource() ResourceConfig {
	authed, team := m5AuthCheck(), m5TeamFilter()
	teamAccess := Access{
		List:   []Guard[map[string]any]{authed, team},
		Get:    []Guard[map[string]any]{authed, team},
		Create: []Guard[map[string]any]{authed},
		Update: []Guard[map[string]any]{authed, team},
		Delete: []Guard[map[string]any]{authed, team},
	}
	return Resource("widget", "brick_m5_widget", wSchema{
		Fields: schema.Fields{
			"id":     schema.String().Readonly(),
			"team":   schema.String().Required().Filterable(),
			"owner":  schema.String().From("session.userId"),
			"slug":   schema.String().Required().Unique(),
			"title":  schema.String().Required().Searchable().MaxLen(12),
			"kind":   schema.Enum("a", "b").Default("a"),
			"qty":    schema.Int().Sortable(),
			"active": schema.Bool().Filterable(),
			"secret": schema.String().Hidden(),
			"ro":     schema.String().Readonly(),
		},
		Access: teamAccess,
		Hooks:  m5StampHook(),
	})
}

// Int-PK resource for autoname concurrency + 200-path via HTTP.

type sRow struct {
	bun.BaseModel `bun:"table:brick_m5_seq"`
	Name          int64  `bun:"name,pk" json:"name"`
	Team          string `bun:"team,notnull" json:"team"`
	Title         string `bun:"title,notnull" json:"title"`
}

type sResp struct {
	Name  int64  `json:"name"`
	Team  string `json:"team"`
	Title string `json:"title"`
}

type sCreate struct {
	Team  string `json:"team"`
	Title string `json:"title"`
}

type sUpdate struct {
	Title *string `json:"title,omitempty"`
}

type sList struct {
	Page  int    `query:"page"`
	Limit int    `query:"limit"`
	Sort  string `query:"sort"`
}

func (in *sList) ToListOptions() db.ListOptions {
	return db.ListOptions{Page: in.Page, Limit: in.Limit, Sort: in.Sort}
}

type sSchema = Schema[sRow, sResp, sCreate, sUpdate, sList]

func m5SeqResource() ResourceConfig {
	authed := m5AuthCheck()
	return Resource("seq", "brick_m5_seq", sSchema{
		Fields: schema.Fields{
			"name":  schema.Int().Readonly(),
			"team":  schema.String().Required().Filterable(),
			"title": schema.String().Required(),
		},
		PK:     AutoincPK("name"),
		Access: Access{List: []Guard[map[string]any]{authed}, Get: []Guard[map[string]any]{authed}, Create: []Guard[map[string]any]{authed}, Update: []Guard[map[string]any]{authed}, Delete: []Guard[map[string]any]{authed}},
		Hooks: Hooks[map[string]any, map[string]any]{
			BeforeCreate: func(hc HookCtx[map[string]any, map[string]any]) error {
				if ctx := GetAppCtx[m5Ctx](hc.Context); ctx != nil {
					(*hc.Input)["team"] = ctx.Team
				}
				return nil
			},
		},
	})
}

const widgetDDL = `"id" text PRIMARY KEY, "team" text NOT NULL, "owner" text, "slug" text UNIQUE NOT NULL, "title" text NOT NULL, "kind" text NOT NULL DEFAULT 'a', "qty" integer NOT NULL DEFAULT 0, "active" boolean NOT NULL DEFAULT false`
const seqDDL = `"name" bigint PRIMARY KEY, "team" text NOT NULL, "title" text NOT NULL`

func m5Table(t testing.TB, bunDB *bun.DB, name, ddl string) {
	t.Helper()
	ctx := context.Background()
	if _, err := bunDB.NewRaw("DROP TABLE IF EXISTS \"" + name + "\"").Exec(ctx); err != nil {
		t.Fatalf("drop: %v", err)
	}
	if _, err := bunDB.NewRaw("CREATE TABLE \"" + name + "\" (" + ddl + ")").Exec(ctx); err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() {
		_, _ = bunDB.NewRaw("DROP TABLE IF EXISTS \"" + name + "\"").Exec(context.Background())
	})
}

func m5TestAPI(t testing.TB, database *db.DB, resources ...ResourceConfig) humatest.TestAPI {
	t.Helper()
	_, api := humatest.New(t)
	if _, err := New(Config[m5Ctx]{Title: "t", Version: "0", DB: database.Bun(), API: api, Resources: resources}); err != nil {
		t.Fatalf("New: %v", err)
	}
	return api
}

func decodeBody(t testing.TB, resp *httptest.ResponseRecorder, out any) {
	t.Helper()
	if err := json.Unmarshal(resp.Body.Bytes(), out); err != nil {
		t.Fatalf("decode %d: %v\n%s", resp.Code, err, resp.Body.String())
	}
}

// ─── Matrix: authn/authz ────────────────────────────────────────────────────

func TestHandlerAuthnAuthz(t *testing.T) {
	database, bunDB := integrationBrickDB(t)
	m5Table(t, bunDB, "brick_m5_widget", widgetDDL)
	api := m5TestAPI(t, database, m5WidgetResource())
	authed := m5AuthedCtx("sales")

	// Anonymous → 401 everywhere.
	if resp := api.Get("/api/widget"); resp.Code != http.StatusUnauthorized {
		t.Errorf("anon list: got %d", resp.Code)
	}
	if resp := api.Get("/api/widget/x"); resp.Code != http.StatusUnauthorized {
		t.Errorf("anon get: got %d", resp.Code)
	}
	if resp := api.Post("/api/widget", map[string]any{"slug": "s", "title": "t", "team": "sales"}); resp.Code != http.StatusUnauthorized {
		t.Errorf("anon create: got %d", resp.Code)
	}

	// Create in team sales.
	resp := api.PostCtx(authed, "/api/widget", map[string]any{"slug": "one", "title": "First", "team": "sales"})
	if resp.Code != http.StatusOK {
		t.Fatalf("create: got %d: %s", resp.Code, resp.Body.String())
	}
	var created wResp
	decodeBody(t, resp, &created)
	if created.ID == "" || created.Team != "sales" || created.Owner != "ada" || created.Kind != "a" {
		t.Fatalf("created: %+v", created)
	}

	// Wrong team → 404 (not 403), list omits.
	other := m5AuthedCtx("support")
	if resp := api.GetCtx(other, "/api/widget/"+created.ID); resp.Code != http.StatusNotFound {
		t.Errorf("cross-team get: got %d", resp.Code)
	}
	resp = api.GetCtx(other, "/api/widget?limit=100")
	var list ListResponse[wResp]
	decodeBody(t, resp, &list)
	if list.Total != 0 || len(list.Data) != 0 {
		t.Errorf("cross-team list leaked: %+v", list)
	}

	// Random ID → 404.
	if resp := api.GetCtx(authed, "/api/widget/does-not-exist"); resp.Code != http.StatusNotFound {
		t.Errorf("miss get: got %d", resp.Code)
	}

	// Right team round-trips.
	resp = api.GetCtx(authed, "/api/widget/"+created.ID)
	if resp.Code != http.StatusOK {
		t.Fatalf("get: got %d: %s", resp.Code, resp.Body.String())
	}
}

// ─── Validation + mass-assignment + from-override ───────────────────────────

func TestHandlerValidation(t *testing.T) {
	database, bunDB := integrationBrickDB(t)
	m5Table(t, bunDB, "brick_m5_widget", widgetDDL)
	api := m5TestAPI(t, database, m5WidgetResource())
	authed := m5AuthedCtx("sales")

	// Missing required slug/title → 422.
	if resp := api.PostCtx(authed, "/api/widget", map[string]any{"team": "sales"}); resp.Code != 422 {
		t.Errorf("missing required: got %d: %s", resp.Code, resp.Body.String())
	}
	// Bad enum → 422.
	if resp := api.PostCtx(authed, "/api/widget", map[string]any{"team": "sales", "slug": "e1", "title": "t", "kind": "zzz"}); resp.Code != 422 {
		t.Errorf("bad enum: got %d: %s", resp.Code, resp.Body.String())
	}
	// Over maxlen (12) → 422.
	if resp := api.PostCtx(authed, "/api/widget", map[string]any{"team": "sales", "slug": "e2", "title": "way too long title"}); resp.Code != 422 {
		t.Errorf("over maxlen: got %d: %s", resp.Code, resp.Body.String())
	}

	// Unknown keys never reach the typed handler (huma drops them at
	// decode); spoofed team/owner are overridden by hook + from: stamps.
	resp := api.PostCtx(authed, "/api/widget", map[string]any{
		"team": "other", "owner": "mallory", "slug": "spoof", "title": "Spoof",
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("spoofed create: got %d: %s", resp.Code, resp.Body.String())
	}
	var created wResp
	decodeBody(t, resp, &created)
	if created.Team != "sales" || created.Owner != "ada" {
		t.Errorf("hook stamp overridden by spoof: %+v", created)
	}
	row, err := database.FindByIDTable(context.Background(), "brick_m5_widget", created.ID)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if row["team"] != "sales" || row["owner"] != "ada" {
		t.Errorf("stored row not stamped: %+v", row)
	}

	// Update: readonly + PK ignored; team IS writable in this schema
	// (prod freezes it via hook) so it is left untouched here.
	resp = api.PatchCtx(authed, "/api/widget/"+created.ID, map[string]any{
		"title": "New", "ro": "hack", "id": "hack",
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("update: got %d: %s", resp.Code, resp.Body.String())
	}
	var updated wResp
	decodeBody(t, resp, &updated)
	if updated.Title != "New" || updated.Team != "sales" {
		t.Errorf("update applied wrong: %+v", updated)
	}
	after, _ := database.FindByIDTable(context.Background(), "brick_m5_widget", created.ID)
	if _, ok := after["ro"]; ok {
		t.Error("readonly key persisted on update")
	}
	if after["id"] != created.ID {
		t.Error("PK changed on update")
	}

	// Update with bad enum → 422.
	if resp := api.PatchCtx(authed, "/api/widget/"+created.ID, map[string]any{"kind": "zzz"}); resp.Code != 422 {
		t.Errorf("update bad enum: got %d", resp.Code)
	}
	// Empty PATCH still fills from: owner, so it writes (200). The 400
	// empty-update path is covered white-box below on a from-less resource.
	if resp := api.PatchCtx(authed, "/api/widget/"+created.ID, map[string]any{}); resp.Code != http.StatusOK {
		t.Errorf("empty update with from-fill: got %d", resp.Code)
	}

	// Cross-team update/delete → 404.
	other := m5AuthedCtx("support")
	if resp := api.PatchCtx(other, "/api/widget/"+created.ID, map[string]any{"title": "X"}); resp.Code != http.StatusNotFound {
		t.Errorf("cross-team update: got %d", resp.Code)
	}
	if resp := api.DeleteCtx(other, "/api/widget/"+created.ID); resp.Code != http.StatusNotFound {
		t.Errorf("cross-team delete: got %d", resp.Code)
	}
	if resp := api.DeleteCtx(authed, "/api/widget/"+created.ID); resp.Code != http.StatusNoContent && resp.Code != http.StatusOK {
		t.Errorf("delete: got %d", resp.Code)
	}
	if resp := api.GetCtx(authed, "/api/widget/"+created.ID); resp.Code != http.StatusNotFound {
		t.Errorf("deleted get: got %d", resp.Code)
	}

	// Writable columns stay writable: team changes when no hook freezes it
	// (prod view_setting freezes team in BeforeUpdate; guards scope ROWS,
	// not columns).
	resp = api.PostCtx(authed, "/api/widget", map[string]any{"team": "sales", "slug": "moveme", "title": "Move"})
	if resp.Code != http.StatusOK {
		t.Fatalf("second create: %d %s", resp.Code, resp.Body.String())
	}
	var moved wResp
	decodeBody(t, resp, &moved)
	resp = api.PatchCtx(authed, "/api/widget/"+moved.ID, map[string]any{"team": "other"})
	if resp.Code != http.StatusOK {
		t.Fatalf("team change: %d %s", resp.Code, resp.Body.String())
	}
	var movedAfter wResp
	decodeBody(t, resp, &movedAfter)
	if movedAfter.Team != "other" {
		t.Errorf("writable column must update: %+v", movedAfter)
	}
	// The row left the sales scope: sales reads 404 (scope-hiding).
	if resp := api.GetCtx(authed, "/api/widget/"+moved.ID); resp.Code != http.StatusNotFound {
		t.Errorf("out-of-scope get: got %d", resp.Code)
	}
}

// ─── List: clamp / sort-400 / search / filters ─────────────────────────────

func TestHandlerListHardening(t *testing.T) {
	database, bunDB := integrationBrickDB(t)
	m5Table(t, bunDB, "brick_m5_widget", widgetDDL)
	api := m5TestAPI(t, database, m5WidgetResource())
	authed := m5AuthedCtx("sales")

	for _, s := range []struct{ slug, title string }{{"a1", "Alpha"}, {"b2", "Beta"}, {"c3", "Gamma"}} {
		if resp := api.PostCtx(authed, "/api/widget", map[string]any{"team": "sales", "slug": s.slug, "title": s.title}); resp.Code != http.StatusOK {
			t.Fatalf("seed %s: %d %s", s.slug, resp.Code, resp.Body.String())
		}
	}

	// Unknown sort → 400.
	if resp := api.GetCtx(authed, "/api/widget?sort=bogus"); resp.Code != http.StatusBadRequest {
		t.Errorf("bogus sort: got %d", resp.Code)
	}
	// Sortable-only sort works both directions.
	resp := api.GetCtx(authed, "/api/widget?sort=-qty&limit=10")
	var desc ListResponse[wResp]
	decodeBody(t, resp, &desc)
	if resp.Code != http.StatusOK || len(desc.Data) != 3 {
		t.Fatalf("desc sort: %d %+v", resp.Code, desc)
	}

	// Limit clamps; echo is effective.
	resp = api.GetCtx(authed, "/api/widget?limit=100000")
	var clamped ListResponse[wResp]
	decodeBody(t, resp, &clamped)
	if clamped.Limit != db.MaxLimit || clamped.Total != 3 {
		t.Errorf("clamp echo: %+v", clamped)
	}

	// Search across searchable title (case-insensitive).
	resp = api.GetCtx(authed, "/api/widget?search=alp")
	var found ListResponse[wResp]
	decodeBody(t, resp, &found)
	if found.Total != 1 || found.Data[0].Slug != "a1" {
		t.Errorf("search: %+v", found)
	}

	// Scalar bool filter: ?active=true narrows (false is unfilterable —
	// the documented huma scalar limitation).
	resp = api.GetCtx(authed, "/api/widget?active=true")
	var inactive ListResponse[wResp]
	decodeBody(t, resp, &inactive)
	if inactive.Total != 0 {
		t.Errorf("active=true filter: %+v", inactive)
	}
}

// ─── Hooks + unique → 409 ───────────────────────────────────────────────────

func TestHandlerUniqueConflict(t *testing.T) {
	database, bunDB := integrationBrickDB(t)
	m5Table(t, bunDB, "brick_m5_widget", widgetDDL)
	api := m5TestAPI(t, database, m5WidgetResource())
	authed := m5AuthedCtx("sales")

	body := map[string]any{"team": "sales", "slug": "dup", "title": "One"}
	if resp := api.PostCtx(authed, "/api/widget", body); resp.Code != http.StatusOK {
		t.Fatalf("first create: %d", resp.Code)
	}
	if resp := api.PostCtx(authed, "/api/widget", body); resp.Code != http.StatusConflict {
		t.Errorf("dup slug: got %d: %s", resp.Code, resp.Body.String())
	}
}

// ─── Autoincrement PK: HTTP 200-path + concurrent distinct names ────────────

func TestHandlerAutoincConcurrency(t *testing.T) {
	database, bunDB := integrationBrickDB(t)
	m5Table(t, bunDB, "brick_m5_seq", seqDDL)
	api := m5TestAPI(t, database, m5SeqResource())
	authed := m5AuthedCtx("sales")

	resp := api.PostCtx(authed, "/api/seq", map[string]any{"team": "sales", "title": "first"})
	if resp.Code != http.StatusOK {
		t.Fatalf("seq create: %d %s", resp.Code, resp.Body.String())
	}
	var first sResp
	decodeBody(t, resp, &first)
	if first.Name != 1 || first.Team != "sales" {
		t.Fatalf("seq first: %+v", first)
	}

	const n = 8
	names := make([]int64, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec, err := execCreate(m5AuthedCtx("sales"), database, m5SeqResource(), map[string]any{"team": "sales", "title": fmt.Sprintf("w%d", i)})
			if err != nil {
				errs[i] = err
				return
			}
			names[i], _ = rec["name"].(int64)
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
		if name < 2 || name > n+1 || seen[name] {
			t.Fatalf("names must be distinct 2..%d, got %v", n+1, names)
		}
		seen[name] = true
	}
}

// ─── Dynamic (untyped-model) resource rides the ListMap path ────────────────

func TestExecUpdateEmptyBody400(t *testing.T) {
	// No DB is touched: guards/strip/validate precede any query, so a nil
	// *db.DB is safe on this exact path.
	res := ResourceConfig{Name: "w", Table: "t", Schema: &schema.DynamicSchema{
		Fields: schema.Fields{"title": schema.String()},
	}}
	err := func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panicked (nil DB dereferenced): %v", r)
			}
		}()
		_, err = execUpdate(context.Background(), nil, res, "x", map[string]any{})
		return err
	}()
	se, ok := err.(huma.StatusError)
	if !ok || se.GetStatus() != http.StatusBadRequest {
		t.Errorf("empty update must be 400, got %T %v", err, err)
	}
}

func TestHandlerDynamicResource(t *testing.T) {
	database, bunDB := integrationBrickDB(t)
	m5Table(t, bunDB, "brick_m5_dyn", `"id" text PRIMARY KEY, "team" text NOT NULL, "title" text NOT NULL`)
	authed, team := m5AuthCheck(), m5TeamFilter()
	access := Access{
		List:   []Guard[map[string]any]{authed, team},
		Get:    []Guard[map[string]any]{authed, team},
		Create: []Guard[map[string]any]{authed},
		Update: []Guard[map[string]any]{authed, team},
		Delete: []Guard[map[string]any]{authed, team},
	}

	// A literal ResourceConfig has no typed handlers; register the map
	// bridge the same way Resource() does for Model==nil via exec fns.
	_, api := humatest.New(t)
	if _, err := New(Config[m5Ctx]{Title: "t", Version: "0", DB: database.Bun(), API: api}); err != nil {
		t.Fatalf("New: %v", err)
	}
	mapRes := ResourceConfig{
		Name: "dyn", Table: "brick_m5_dyn",
		Schema:     &schema.DynamicSchema{Fields: schema.Fields{"id": schema.String().Readonly(), "team": schema.String().Required(), "title": schema.String().Required()}},
		Operations: schema.Operations{},
		Access:     access,
	}
	huma.Register(api, huma.Operation{Method: http.MethodPost, Path: "/api/dyn", OperationID: "createDyn", Tags: []string{"dyn"}}, func(ctx context.Context, input *struct {
		Body map[string]any
	}) (*struct{ Body map[string]any }, error) {
		m, err := execCreate(ctx, database, mapRes, input.Body)
		if err != nil {
			return nil, err
		}
		return &struct{ Body map[string]any }{Body: m}, nil
	})
	huma.Register(api, huma.Operation{Method: http.MethodGet, Path: "/api/dyn", OperationID: "listDyn", Tags: []string{"dyn"}}, func(ctx context.Context, input *struct {
		Limit int `query:"limit"`
	}) (*struct{ Body ListResponse[map[string]any] }, error) {
		return execList(ctx, database, mapRes, db.ListOptions{Limit: input.Limit})
	})

	authedCtx := m5AuthedCtx("sales")
	resp := api.PostCtx(authedCtx, "/api/dyn", map[string]any{"team": "sales", "title": "hello", "attacker_key": "x"})
	if resp.Code != http.StatusOK {
		t.Fatalf("dyn create: %d %s", resp.Code, resp.Body.String())
	}
	var createdDyn struct {
		Body map[string]any
	}
	decodeBody(t, resp, &createdDyn)
	if _, ok := createdDyn.Body["attacker_key"]; ok {
		t.Error("unknown key persisted through map bridge (mass assignment)")
	}
	resp = api.GetCtx(authedCtx, "/api/dyn?limit=10")
	var list ListResponse[map[string]any]
	decodeBody(t, resp, &list)
	if list.Total != 1 {
		t.Errorf("dyn list: %+v", list)
	}
}

// ─── Concurrent duplicate slug: exactly one 200, rest 409 ──────────────────

func TestHandlerConcurrentDuplicate(t *testing.T) {
	database, bunDB := integrationBrickDB(t)
	m5Table(t, bunDB, "brick_m5_widget", widgetDDL)
	api := m5TestAPI(t, database, m5WidgetResource())

	const n = 6
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp := api.PostCtx(m5AuthedCtx("sales"), "/api/widget", map[string]any{"team": "sales", "slug": "race", "title": "Race"})
			codes[i] = resp.Code
		}(i)
	}
	wg.Wait()
	var ok, conflict int
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			ok++
		case http.StatusConflict:
			conflict++
		default:
			t.Fatalf("unexpected code %d", c)
		}
	}
	if ok != 1 || conflict != n-1 {
		t.Errorf("race: ok=%d conflict=%d codes=%v", ok, conflict, codes)
	}
}
