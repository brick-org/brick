package dsl

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/brick-org/brick/dsl/codegen"
	"github.com/brick-org/brick/dsl/schema"
)

// Run validates every def (fail fast, resource named) and writes the DB +
// CRUD files. Output is gofmt-clean and deterministic (sorted by name);
// files are overwritten in place so diffs stay reviewable.
//
// A DSL app's main.go calls Run — the typed replacement for the removed
// YAML pipeline:
//
//	func main() {
//		out := flag.String("out", "../app/gen", "output directory")
//		pkg := flag.String("pkg", "gen", "package name")
//		flag.Parse()
//		if err := dsl.Run(Resources(), dsl.RunOptions{OutDir: *out, Package: *pkg, Aggregates: true}); err != nil {
//			fmt.Fprintln(os.Stderr, err)
//			os.Exit(1)
//		}
//	}

// RunOptions controls Run.
type RunOptions struct {
	// OutDir is the main app's gen/ directory. Created if missing.
	OutDir string
	// Package is the package name written into both emitted files.
	Package string
	// Aggregates emits BusinessModels/BusinessIndexes (migrations +
	// cross-resource indexes). The main app almost always wants true.
	Aggregates bool
}

// Generated file names inside OutDir. Prefixed so they never collide with
// hand-written files in the same directory.
const (
	DBFileName   = "brick_db.go"
	CRUDFileName = "brick_crud.go"
)

// Run validates every def (fail fast, resource named) and writes the DB +
// CRUD files. Output is gofmt-clean and deterministic (sorted by name);
// files are overwritten in place so diffs stay reviewable.
func Run(defs []schema.ResourceDef, opts RunOptions) error {
	if opts.OutDir == "" {
		return fmt.Errorf("dsl: run: OutDir is required")
	}
	if opts.Package == "" {
		return fmt.Errorf("dsl: run: Package is required")
	}
	for _, d := range defs {
		if err := d.Validate(); err != nil {
			return fmt.Errorf("dsl: run: %w", err)
		}
	}
	inputs := make([]codegen.ResourceDef, len(defs))
	copy(inputs, defs)
	sort.Slice(inputs, func(i, j int) bool { return inputs[i].Name < inputs[j].Name })

	dbOut, err := codegen.GenerateDB(opts.Package, inputs, codegen.Options{Aggregates: opts.Aggregates})
	if err != nil {
		return fmt.Errorf("dsl: run: generate db: %w", err)
	}
	crudOut, err := codegen.GenerateCRUD(opts.Package, inputs)
	if err != nil {
		return fmt.Errorf("dsl: run: generate crud: %w", err)
	}
	if err := os.MkdirAll(opts.OutDir, 0o755); err != nil {
		return fmt.Errorf("dsl: run: mkdir %s: %w", opts.OutDir, err)
	}
	if err := os.WriteFile(filepath.Join(opts.OutDir, DBFileName), []byte(dbOut), 0o644); err != nil {
		return fmt.Errorf("dsl: run: write %s: %w", DBFileName, err)
	}
	if err := os.WriteFile(filepath.Join(opts.OutDir, CRUDFileName), []byte(crudOut), 0o644); err != nil {
		return fmt.Errorf("dsl: run: write %s: %w", CRUDFileName, err)
	}
	return nil
}
