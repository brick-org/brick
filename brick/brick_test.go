package brick

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brick-org/brick/db"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
)

func TestNewRejectsNilDB(t *testing.T) {
	_, api := humatest.New(t)
	if _, err := New(Config[AppCtx]{API: api}); err == nil {
		t.Error("New with nil DB must error, never panic")
	}
}

// TestOpenAPISpecContents runs without a database: registration and spec
// marshal touch no rows. The bun.DB wraps a lazy, never-connected pool.
func TestOpenAPISpecContents(t *testing.T) {
	_, api := humatest.New(t)
	sqlDB := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN("postgres://localhost:1/unused?sslmode=disable")))
	defer sqlDB.Close()
	bunDB := bun.NewDB(sqlDB, pgdialect.New())
	defer bunDB.Close()
	b, err := New(Config[m5Ctx]{
		Title: "t", Version: "0",
		DB:        bunDB,
		API:       api,
		Resources: []ResourceConfig{m5WidgetResource(), m5SeqResource()},
		Routes: func(api huma.API, db *db.DB) {
			huma.Register(api, huma.Operation{Method: "GET", Path: "/api/custom", OperationID: "getCustom"}, func(ctx context.Context, _ *struct{}) (*struct{}, error) {
				return nil, nil
			})
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	spec, err := b.OpenAPISpec()
	if err != nil {
		t.Fatalf("OpenAPISpec: %v", err)
	}
	var doc struct {
		Paths map[string]map[string]struct {
			OperationID string   `json:"operationId"`
			Tags        []string `json:"tags"`
		} `json:"paths"`
	}
	// OpenAPI nests under "paths" at top level; decode loosely.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(spec, &top); err != nil {
		t.Fatalf("spec JSON: %v", err)
	}
	if err := json.Unmarshal(top["paths"], &doc.Paths); err != nil {
		t.Fatalf("spec paths: %v", err)
	}
	opIDs := map[string]bool{}
	for path, ops := range doc.Paths {
		for method, op := range ops {
			opIDs[method+" "+path+" "+op.OperationID] = true
		}
	}
	for _, want := range []string{
		"get /api/widget/{id} getWidget",
		"get /api/widget listWidget",
		"post /api/widget createWidget",
		"patch /api/widget/{id} updateWidget",
		"delete /api/widget/{id} deleteWidget",
		"get /api/custom getCustom",
	} {
		if !opIDs[want] {
			t.Errorf("spec missing %q (have %v)", want, opIDs)
		}
	}
}

// TestInternalErrorCarriesRequestID drives a broken-DB create with a fixed
// request ID and asserts the 500 envelope correlates (no PG internals).
func TestInternalErrorCarriesRequestID(t *testing.T) {
	database, bunDB := integrationBrickDB(t)
	m5Table(t, bunDB, "brick_m5_widget", widgetDDL)
	// Poison the pool: further queries fail.
	_ = bunDB.Close()

	ctx := context.WithValue(m5AuthedCtx("sales"), requestIDKey{}, "rid-123")
	_, err := execCreate(ctx, database, m5WidgetResource(), map[string]any{"team": "sales", "slug": "x", "title": "X"})
	if err == nil {
		t.Fatal("broken DB must error")
	}
	se, ok := err.(huma.StatusError)
	if !ok || se.GetStatus() != 500 {
		t.Fatalf("must be 500 StatusError, got %T %v", err, err)
	}
	if !strings.Contains(se.Error(), "rid-123") {
		t.Errorf("500 envelope must carry request_id, got %q", se.Error())
	}
	if strings.Contains(se.Error(), "connection refused") || strings.Contains(se.Error(), "closed") {
		t.Errorf("500 envelope must not leak internals: %q", se.Error())
	}
}

// ─── Package hygiene ────────────────────────────────────────────────────────
// Zero log.Printf / panic( anywhere in the module (plan §10.4). slog is the
// only logger; constructors return errors.

func moduleSources(t testing.TB) []string {
	t.Helper()
	var files []string
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no sources found")
	}
	return files
}

func TestNoLogPrintfOrPanic(t *testing.T) {
	for _, banned := range []string{"log.Printf", "panic("} {
		for _, file := range moduleSources(t) {
			body, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(body), banned) {
				t.Errorf("%s contains %q", file, banned)
			}
		}
	}
}
