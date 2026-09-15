package codegen_test

import (
	"flag"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/brick-org/brick/codegen"
	"github.com/brick-org/brick/dsl"
	"github.com/brick-org/brick/schema"
)

var updateGolden = flag.Bool("update", false, "update golden files in testdata/")

func goldenFile(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *updateGolden {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s (run with -update to seed): %v", name, err)
	}
	if got != string(want) {
		t.Fatalf("golden %s mismatch (run with -update to refresh):\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

func mustParse(t *testing.T, src string) string {
	t.Helper()
	fset := token.NewFileSet()
	if _, err := parser.ParseFile(fset, "gen.go", src, parser.AllErrors); err != nil {
		t.Fatalf("emitted code does not parse: %v\n%s", err, src)
	}
	return src
}

func TestGenerateRowStruct(t *testing.T) {
	s := &schema.DynamicSchema{
		Fields: schema.Fields{
			"id":     schema.String(),
			"title":  schema.String().Required(),
			"amount": schema.Int().Filterable().Sortable(),
		},
	}

	output, err := codegen.GenerateDB("models", []codegen.ResourceDef{{
		Name: "Deal", Table: "deals", Schema: s,
	}}, codegen.Options{})
	if err != nil {
		t.Fatalf("GenerateDB: %v", err)
	}
	mustParse(t, output)

	if !strings.Contains(output, "type DealRow struct") {
		t.Fatal("expected DealRow struct")
	}
	if !strings.Contains(output, "bun:\"table:deals\"") {
		t.Fatal("expected bun table tag")
	}
	if !regexp.MustCompile(`Id\s+string`).MatchString(output) {
		t.Fatal("expected Id field")
	}
	if !strings.Contains(output, "Title") {
		t.Fatal("expected Title field")
	}
	if !strings.Contains(output, "Amount") {
		t.Fatal("expected Amount field")
	}
}

func TestGenerateCRUD_ResponseAndInputs(t *testing.T) {
	s := &schema.DynamicSchema{
		Fields: schema.Fields{
			"id":     schema.String(),
			"title":  schema.String().Required(),
			"amount": schema.Int().Filterable().Sortable(),
		},
	}

	output, err := codegen.GenerateCRUD("models", []codegen.ResourceDef{{
		Name: "Deal", Table: "deals", Schema: s,
	}})
	if err != nil {
		t.Fatalf("GenerateCRUD: %v", err)
	}
	mustParse(t, output)

	for _, want := range []string{
		"type DealResponse struct",
		"type DealCreateBody struct",
		"type DealUpdateBody struct",
		"type DealSchema",
		"type DealAccess",
		"type DealHooks",
		"var DealSchemaFields",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("expected %s", want)
		}
	}
}

func TestGenerateDB_EmitsCompositeIndexForPolyFK(t *testing.T) {
	s := &schema.DynamicSchema{
		Fields: schema.Fields{
			"id":          schema.UUID(),
			"target_type": schema.String().Required(),
			"target_id":   schema.String().Required(),
			"body":        schema.String().Required(),
		},
	}

	out, err := codegen.GenerateDB("resources", []codegen.ResourceDef{{
		Name:   "comment",
		Table:  "comment",
		Schema: s,
		PolyFKs: []schema.PolyFKDef{{
			TypeField: "target_type",
			IDField:   "target_id",
		}},
	}}, codegen.Options{Aggregates: true})
	if err != nil {
		t.Fatalf("GenerateDB: %v", err)
	}

	if !strings.Contains(out, "func BusinessIndexes(") {
		t.Fatalf("expected BusinessIndexes function emitted; got:\n%s", out)
	}
	if !strings.Contains(out, `Column("target_type", "target_id")`) {
		t.Fatalf("expected composite Column(\"target_type\", \"target_id\"); got:\n%s", out)
	}
	if !strings.Contains(out, `Table("comment")`) {
		t.Fatalf("expected Table(\"comment\") in index creation; got:\n%s", out)
	}
}

func TestGenerateDB_EmitsEmptyBusinessIndexesWhenNoPolyFKs(t *testing.T) {
	s := &schema.DynamicSchema{
		Fields: schema.Fields{
			"id":    schema.UUID(),
			"title": schema.String().Required(),
		},
	}

	out, err := codegen.GenerateDB("resources", []codegen.ResourceDef{{
		Name: "note", Table: "notes", Schema: s,
	}}, codegen.Options{Aggregates: true})
	if err != nil {
		t.Fatalf("GenerateDB: %v", err)
	}
	if !strings.Contains(out, "func BusinessIndexes(ctx context.Context, bunDB *bun.DB) error {\n\treturn nil\n}") {
		t.Fatalf("expected empty BusinessIndexes stub; got:\n%s", out)
	}
}

func TestGenerateDB_EmitsCompositeUniquesAndIndexes(t *testing.T) {
	s := &schema.DynamicSchema{
		Fields: schema.Fields{
			"id":    schema.UUID(),
			"team":  schema.String().Required(),
			"label": schema.String().Required(),
			"owner": schema.String(),
		},
		CompositeUniques: [][]string{{"team", "label"}},
		CompositeIndexes: [][]string{{"owner", "team"}},
	}

	out, err := codegen.GenerateDB("resources", []codegen.ResourceDef{{
		Name: "widget", Table: "widgets", Schema: s,
	}}, codegen.Options{Aggregates: true})
	if err != nil {
		t.Fatalf("GenerateDB: %v", err)
	}
	mustParse(t, "package resources\nimport (\n\"context\"\n\"github.com/uptrace/bun\"\n)\n"+out[strings.Index(out, "func BusinessIndexes"):])
	for _, want := range []string{
		`NewCreateIndex().Unique().IfNotExists().Index("widgets_team_label_uidx")`,
		`Column("team", "label")`,
		`NewCreateIndex().IfNotExists().Index("widgets_owner_team_idx")`,
		`Column("owner", "team")`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %s in BusinessIndexes output", want)
		}
	}
}

// ─── Zero-value filter fix (B3/B4) ────────────────────────────────────────

func TestListInput_PointerFilters(t *testing.T) {
	s := &schema.DynamicSchema{
		Fields: schema.Fields{
			"id":        schema.String(),
			"is_public": schema.Bool().Filterable(),
			"count":     schema.Int().Filterable(),
			"price":     schema.Float().Filterable(),
			"meta":      schema.JSON(),
			"name":      schema.String().Filterable(),
		},
	}

	out, err := codegen.GenerateCRUD("models", []codegen.ResourceDef{{
		Name: "item", Table: "items", Schema: s,
	}})
	if err != nil {
		t.Fatalf("GenerateCRUD: %v", err)
	}

	// NOTE: gofmt aligns struct columns, so match with \s+ (see matchField).
	for _, want := range []struct{ field, typ, query string }{
		{"IsPublic", `\*bool`, "is_public"},
		{"Count", `\*int32`, "count"},
		{"Price", `\*float64`, "price"},
		{"Meta", `\*json\.RawMessage`, "meta"},
		{"Name", `string`, "name"},
	} {
		matchField(t, out, want.field, want.typ, want.query)
	}
	for _, want := range []string{
		"if in.IsPublic != nil {",
		"Value: *in.IsPublic",
		"if in.Count != nil {",
		"Value: *in.Count",
		"if in.Meta != nil {",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in ListInput output", want)
		}
	}
	// Old buggy guards must be gone.
	for _, gone := range []string{"if in.IsPublic {", "if in.Count != 0 {"} {
		if strings.Contains(out, gone) {
			t.Errorf("found stale zero-value guard %q", gone)
		}
	}
}

func TestListInput_AutoincPKIsInt64Pointer(t *testing.T) {
	s := &schema.DynamicSchema{
		Fields: schema.Fields{"subject": schema.String()},
	}
	s.ApplyPK(&schema.PK{Column: "name", Type: schema.FieldInt, Autoname: schema.Autoname{Strategy: schema.AutonameAutoinc}})

	out, err := codegen.GenerateCRUD("models", []codegen.ResourceDef{{
		Name: "ticket", Table: "tickets", Schema: s,
	}})
	if err != nil {
		t.Fatalf("GenerateCRUD: %v", err)
	}
	if !fieldRe(t, out, "Name", `\*int64`, "name") {
		t.Fatalf("expected *int64 autoinc filter; got:\n%s", out)
	}
}

// fieldRe asserts a struct field declaration modulo gofmt column padding.
func fieldRe(t *testing.T, out, field, typ, query string) bool {
	t.Helper()
	re := regexp.MustCompile(`(?m)^\t` + field + `\s+` + typ + `\s+` + "`query:\"" + query + "\"`$")
	if !re.MatchString(out) {
		t.Errorf("expected field %s %s query:%q", field, typ, query)
		return false
	}
	return true
}

func matchField(t *testing.T, out, field, typ, query string) {
	t.Helper()
	if !fieldRe(t, out, field, typ, query) {
		t.Fatalf("missing field %s (see error above)", field)
	}
}

// ─── Golden tests ─────────────────────────────────────────────────────────

func loadTestResources(t *testing.T) []codegen.ResourceDef {
	t.Helper()
	files, err := dsl.LoadDir("testdata/dsl")
	if err != nil {
		t.Fatalf("LoadDir testdata/dsl: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no DSL fixtures in testdata/dsl")
	}
	defs := make([]codegen.ResourceDef, 0, len(files))
	for _, f := range files {
		def, err := f.ToResourceDef()
		if err != nil {
			t.Fatalf("%s: ToResourceDef: %v", f.Name, err)
		}
		defs = append(defs, def)
	}
	return defs
}

func TestGolden_DB(t *testing.T) {
	defs := loadTestResources(t)
	out, err := codegen.GenerateDB("resources", defs, codegen.Options{Aggregates: true})
	if err != nil {
		t.Fatalf("GenerateDB: %v", err)
	}
	mustParse(t, out)
	// Split per-resource: goldens are per resource to keep diffs reviewable.
	byName := map[string]codegen.ResourceDef{}
	for _, d := range defs {
		byName[d.Name] = d
	}
	for _, d := range defs {
		single, err := codegen.GenerateDB("resources", []codegen.ResourceDef{byName[d.Name]}, codegen.Options{Aggregates: true})
		if err != nil {
			t.Fatalf("GenerateDB %s: %v", d.Name, err)
		}
		mustParse(t, single)
		goldenFile(t, "db_"+d.Name+".golden", single)
	}
}

func TestGolden_CRUD(t *testing.T) {
	defs := loadTestResources(t)
	for _, d := range defs {
		single, err := codegen.GenerateCRUD("resources", []codegen.ResourceDef{d})
		if err != nil {
			t.Fatalf("GenerateCRUD %s: %v", d.Name, err)
		}
		mustParse(t, single)
		goldenFile(t, "crud_"+d.Name+".golden", single)
	}
}

func TestGolden_Deal(t *testing.T) {
	s := &schema.DynamicSchema{
		Fields: schema.Fields{
			"id":     schema.UUID(),
			"title":  schema.String().Required(),
			"amount": schema.Int().Filterable().Sortable(),
			"notes":  schema.Text(),
			"status": schema.String().Default("draft"),
		},
	}
	db, err := codegen.GenerateDB("models", []codegen.ResourceDef{{Name: "Invoice", Table: "invoices", Schema: s}}, codegen.Options{Aggregates: true})
	if err != nil {
		t.Fatalf("GenerateDB: %v", err)
	}
	mustParse(t, db)
	goldenFile(t, "db_deal.golden", db)

	crud, err := codegen.GenerateCRUD("models", []codegen.ResourceDef{{Name: "Invoice", Table: "invoices", Schema: s}})
	if err != nil {
		t.Fatalf("GenerateCRUD: %v", err)
	}
	mustParse(t, crud)
	goldenFile(t, "crud_deal.golden", crud)
}

func TestOutput_ByteStableAcrossInputOrder(t *testing.T) {
	defs := loadTestResources(t)
	shuffled := make([]codegen.ResourceDef, len(defs))
	copy(shuffled, defs)
	sort.Slice(shuffled, func(i, j int) bool { return shuffled[i].Name > shuffled[j].Name })

	a, err := codegen.GenerateDB("resources", defs, codegen.Options{Aggregates: true})
	if err != nil {
		t.Fatalf("GenerateDB: %v", err)
	}
	b, err := codegen.GenerateDB("resources", shuffled, codegen.Options{Aggregates: true})
	if err != nil {
		t.Fatalf("GenerateDB shuffled: %v", err)
	}
	if a != b {
		t.Fatal("GenerateDB output depends on input order")
	}

	c, err := codegen.GenerateCRUD("resources", defs)
	if err != nil {
		t.Fatalf("GenerateCRUD: %v", err)
	}
	d, err := codegen.GenerateCRUD("resources", shuffled)
	if err != nil {
		t.Fatalf("GenerateCRUD shuffled: %v", err)
	}
	if c != d {
		t.Fatal("GenerateCRUD output depends on input order")
	}
}
