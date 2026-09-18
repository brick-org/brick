// Main app for the shop example: Brick runtime over committed gen/ code.
//
// The app imports brick, brick/db, brick/schema (via gen) — never the DSL
// toolchain (no dsl, codegen, or yaml in this binary).
//
// Local run:
//
//	DATABASE_URL=postgres://localhost:5432/shop?sslmode=disable go run .
//
// Deploy: see ../vercel.json (Go server preset, project root = this
// directory) and /docs/deployment/vercel. Construction lives in appshop
// so the server and the api/ function serve identical routes.
package main

import (
	"log"
	"os"

	"github.com/brick-org/brick/examples/shop/app/appshop"
)

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = appshop.DefaultDSN
	}
	b, bunDB, err := appshop.New(dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer bunDB.Close()

	// Vercel's Go server preset sets PORT; ADDR stays as the local override.
	addr := os.Getenv("PORT")
	if addr != "" {
		addr = ":" + addr
	} else {
		addr = os.Getenv("ADDR")
		if addr == "" {
			addr = ":8080"
		}
	}
	log.Printf("shop listening on %s", addr)
	log.Fatal(b.ListenAndServe(addr))
}
