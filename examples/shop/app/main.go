// Main app for the shop example: Brick runtime over committed gen/ code.
//
// The app imports brick, brick/db, brick/schema (via gen) — never the DSL
// toolchain (no dsl, codegen, or yaml in this binary).
//
// Run: DATABASE_URL=postgres://localhost:5432/shop?sslmode=disable go run .
package main

import (
	"database/sql"
	"log"
	"os"

	brick "github.com/brick-org/brick/brick"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"

	gen "github.com/brick-org/brick/examples/shop/app/gen"
)

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://localhost:5432/shop?sslmode=disable"
	}
	sqlDB := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn)))
	bunDB := bun.NewDB(sqlDB, pgdialect.New())
	defer bunDB.Close()

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
		log.Fatal(err)
	}

	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}
	log.Printf("shop listening on %s", addr)
	log.Fatal(b.ListenAndServe(addr))
}
