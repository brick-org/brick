// Vercel Serverless Function for the shop app (functions-style alternative
// to the default Go server preset — see ../vercel.json and
// /docs/deployment/vercel for when to pick which).
//
// Vercel maps this file to /api/* and runs Handler per request. Function
// instances freeze between invocations, so the Brick app and its
// single-connection pool are built ONCE per instance (sync.OnceValues)
// and reused across warm requests. Never open/close the DB per request.
//
// A missing DATABASE_URL fails at REQUEST time with a 500, never at build
// time: Vercel builds without runtime env vars.
package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"sync"

	"github.com/brick-org/brick/examples/shop/app/appshop"
)

var errMissingDatabaseURL = errors.New("DATABASE_URL is not set")

func build() (http.Handler, error) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return nil, errMissingDatabaseURL
	}
	b, _, err := appshop.New(dsn)
	if err != nil {
		return nil, err
	}
	// The *bun.DB is intentionally left open for the instance lifetime.
	return b.Handler(), nil
}

// cached is a var (not a direct OnceValues call site) so tests can reset it
// per case; production never resets it.
var cached = sync.OnceValues(build)

type problem struct {
	Status int    `json:"status"`
	Title  string `json:"title"`
}

// Handler is the Vercel entrypoint: serve the cached Brick handler, or a
// 500 problem JSON when the instance failed to build (missing/unreachable env).
func Handler(w http.ResponseWriter, r *http.Request) {
	h, err := cached()
	if err != nil {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(problem{Status: 500, Title: "shop: " + err.Error()})
		return
	}
	h.ServeHTTP(w, r)
}
