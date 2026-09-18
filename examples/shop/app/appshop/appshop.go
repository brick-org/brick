// Package appshop builds the shop Brick instance shared by every
// entrypoint: the long-lived server (main.go) and the Vercel Serverless
// Function (api/). Keeping construction here guarantees local,
// preview, and production all serve identical routes, docs, and OpenAPI.
package appshop

import (
	"database/sql"
	"net/http"
	"time"

	brick "github.com/brick-org/brick/brick"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
	"github.com/uptrace/bunrouter"

	gen "github.com/brick-org/brick/examples/shop/app/gen"
)

// DefaultDSN is the local-dev fallback when DATABASE_URL is unset.
// Serverless entrypoints must NOT fall back: a missing DATABASE_URL is a
// deployment error and must surface as a 500, never silently target localhost.
const DefaultDSN = "postgres://localhost:5432/shop?sslmode=disable"

// OpenDB opens the shared bun pool for dsn. The pool is tuned for
// serverless: a single connection that a pooled Postgres endpoint (Neon,
// Supabase pooler, pgbouncer) absorbs across many concurrent function
// instances. The connector is lazy — no connection happens here, so this
// is safe to call at import/request time without a live database.
//
// Lifecycle: keep the result for the process lifetime. main.go Closes on
// exit; the serverless function intentionally never Closes — per-request
// open/close exhausts the database under concurrency.
func OpenDB(dsn string) *bun.DB {
	sqlDB := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn)))
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)
	sqlDB.SetConnMaxIdleTime(time.Minute)
	return bun.NewDB(sqlDB, pgdialect.New())
}

// New builds the shop Brick over dsn and mounts the Scalar reference viewer
// (/openapi.json and /docs come from Huma itself). The caller owns the
// returned *bun.DB: Close it on process exit in long-lived servers, leave
// it open in functions.
func New(dsn string) (*brick.Brick[any], *bun.DB, error) {
	bunDB := OpenDB(dsn)
	b, err := brick.New(brick.Config[any]{
		Title:   "Shop API",
		Version: "0.1.0",
		DB:      bunDB,
		Resources: []brick.ResourceConfig{
			brick.Resource("deal", "deals", gen.DealSchema{
				Fields: gen.DealSchemaFields,
			}),
			brick.Resource("note", "notes", gen.NoteSchema{
				Fields: gen.NoteSchemaFields,
			}),
		},
	})
	if err != nil {
		_ = bunDB.Close()
		return nil, nil, err
	}
	// NOTE: no /openapi.json registration here — huma already serves its
	// spec there (same bytes as OpenAPISpec) and bunrouter panics on
	// duplicate routes. We only add the Scalar viewer below.
	// The Scalar viewer embeds the spec URL, and scalar-go only accepts
	// absolute http(s) URLs — which the app cannot know at build time
	// (localhost vs *.vercel.app vs custom domain). Render per request
	// from the incoming host; X-Forwarded-Proto carries the edge scheme
	// behind Vercel's TLS-terminating proxy.
	b.Router().GET("/reference", func(w http.ResponseWriter, req bunrouter.Request) error {
		html, err := brick.ScalarDocsHTML(specURLFor(req.Request))
		if err != nil {
			http.Error(w, "reference unavailable", http.StatusInternalServerError)
			return nil
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(html))
		return nil
	})
	return b, bunDB, nil
}

// specURLFor returns the absolute URL of the served OpenAPI spec for this
// request's host, honoring the edge proxy's scheme when present.
func specURLFor(r *http.Request) string {
	scheme := r.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		scheme = "http"
		if r.TLS != nil {
			scheme = "https"
		}
	}
	host := r.Host
	if host == "" {
		host = "localhost:8080"
	}
	return scheme + "://" + host + "/openapi.json"
}
