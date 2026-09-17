// Package dsl is brick's Go-DSL toolchain: the code a DSL app runs to
// validate resource definitions and emit code into the main app.
//
//   - Run (runner.go): validate defs + write brick_db.go/brick_crud.go.
//     Called from the DSL app's main.go (`dsl run` = `go run ./dsl`).
//   - EmitGo (emit.go): render defs back as schema.Define source.
//     One-shot migration aid; the YAML frontend it served is removed.
//
// The main app never imports this package: it builds only on the
// committed gen/ output (brick, brick/db, brick/schema).
package dsl
