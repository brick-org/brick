// DSL app for the shop example: typed resource definitions + codegen.
//
// Run from this directory:
//
//	go run . --out ../app/gen --pkg gen
//
// Output (../app/gen/brick_db.go + brick_crud.go) is committed: diffs
// stay reviewable and the main app builds without the DSL toolchain.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/brick-org/brick/dsl"
	"github.com/brick-org/brick/dsl/schema"
)

// Resources returns every resource definition for the shop app.
func Resources() []schema.ResourceDef {
	return []schema.ResourceDef{
		schema.Define("deal", "deals", schema.Fields{
			"id":     schema.UUID().Readonly(),
			"title":  schema.String().Required().Searchable(),
			"status": schema.Enum("open", "won", "lost").Default("open").Filterable(),
			"value":  schema.Int().Default(0),
		}, schema.WithTitle("title")),

		schema.Define("note", "notes", schema.Fields{
			"id":   schema.UUID().Readonly(),
			"body": schema.Text().Required(),
		}, schema.WithParent(schema.NewParent("deal", schema.Cascade))),
	}
}

func main() {
	out := flag.String("out", "../app/gen", "main app gen/ directory")
	pkg := flag.String("pkg", "gen", "package name for emitted files")
	flag.Parse()
	if err := dsl.Run(Resources(), dsl.RunOptions{
		OutDir:     *out,
		Package:    *pkg,
		Aggregates: true,
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
