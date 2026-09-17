// Command dsl scaffolds new brick DSL apps:
//
//	dsl init ./dsl
//
// The DSL app itself is plain Go (schema.Define + dsl.Run); no CLI is
// involved in the daily loop (`dsl run` = `go run ./dsl --out ../app/gen`).
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 3 || os.Args[1] != "init" {
		fmt.Fprint(os.Stderr, "usage: dsl init ./dsl\n")
		os.Exit(2)
	}
	if err := cmdInit(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "dsl: %v\n", err)
		os.Exit(1)
	}
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("init: usage: dsl init ./dsl")
	}
	dir := fs.Arg(0)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("init: mkdir %s: %w", dir, err)
	}
	path := dir + "/main.go"
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("init: %s already exists", path)
	}
	if err := os.WriteFile(path, []byte(dslMainTemplate), 0o644); err != nil {
		return fmt.Errorf("init: write %s: %w", path, err)
	}
	fmt.Printf(`ok: %s written.

Next:
  1. cd %s && go mod init <module>/dsl   (or add to your go.work)
  2. go mod tidy
  3. Edit Resources() in main.go, then:
     go run . --out ../app/gen --pkg gen
`, path, dir)
	return nil
}

const dslMainTemplate = `// DSL app: typed resource definitions + codegen into the main app.
// Run: go run . --out ../app/gen --pkg gen
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/brick-org/brick/dsl"
	"github.com/brick-org/brick/dsl/schema"
)

// Resources returns every resource definition for the main app.
func Resources() []schema.ResourceDef {
	return []schema.ResourceDef{
		schema.Define("deal", "deals", schema.Fields{
			"title":  schema.String().Required().Searchable(),
			"status": schema.Enum("open", "won", "lost").Default("open").Filterable(),
			"value":  schema.Int().Default(0),
		}, schema.WithTitle("title")),
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
`
