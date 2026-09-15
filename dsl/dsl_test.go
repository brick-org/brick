package dsl

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/brick-org/brick/schema"
)

const dealYAML = `
name: deal
table: deals

fields:
  id:              { type: uuid, readonly: true }
  name:            { type: string, required: true, searchable: true, sortable: true }
  client_name:     { type: string, required: true, searchable: true }
  status:
    type: enum
    values: [active, closed, archived]
    default: active
    filterable: true
  owner_id:        { type: foreign, model: workspace_member, required: true }
  organization_id: { type: string, from: session.activeOrganizationId }
  created_at:      { type: timestamp, readonly: true }
  updated_at:      { type: timestamp, readonly: true }
`

func TestParseDeal(t *testing.T) {
	rf, err := Parse(strings.NewReader(dealYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if rf.Name != "deal" {
		t.Errorf("name = %q, want %q", rf.Name, "deal")
	}
	if rf.Table != "deals" {
		t.Errorf("table = %q, want %q", rf.Table, "deals")
	}
	if len(rf.Fields) != 8 {
		t.Errorf("fields count = %d, want 8", len(rf.Fields))
	}

	id, ok := rf.Fields["id"]
	if !ok {
		t.Fatal("missing id field")
	}
	if id.Type != "uuid" {
		t.Errorf("id.type = %q, want uuid", id.Type)
	}
	if !id.Readonly {
		t.Error("id should be readonly")
	}

	status, ok := rf.Fields["status"]
	if !ok {
		t.Fatal("missing status field")
	}
	if status.Type != "enum" {
		t.Errorf("status.type = %q, want enum", status.Type)
	}
	if len(status.Values) != 3 {
		t.Errorf("status.values = %v, want 3 items", status.Values)
	}

	orgID, ok := rf.Fields["organization_id"]
	if !ok {
		t.Fatal("missing organization_id field")
	}
	if orgID.From != "session.activeOrganizationId" {
		t.Errorf("organization_id.from = %q, want session.activeOrganizationId", orgID.From)
	}

	ownerID, ok := rf.Fields["owner_id"]
	if !ok {
		t.Fatal("missing owner_id field")
	}
	if ownerID.Type != "foreign" {
		t.Errorf("owner_id.type = %q, want foreign", ownerID.Type)
	}
	if ownerID.Model != "workspace_member" {
		t.Errorf("owner_id.model = %q, want workspace_member", ownerID.Model)
	}
}

func TestParseRejectsUnknownFieldType(t *testing.T) {
	_, err := Parse(strings.NewReader(`
name: bad
table: bads
fields:
  id: { type: bogus }
`))
	if err == nil {
		t.Fatal("expected error for unknown field type")
	}
}

func TestParseRequiresName(t *testing.T) {
	_, err := Parse(strings.NewReader(`
table: deals
fields:
  id: { type: uuid }
`))
	if err == nil {
		t.Fatal("expected error for missing name")
	}
}

func TestParseRequiresTable(t *testing.T) {
	_, err := Parse(strings.NewReader(`
name: deal
fields:
  id: { type: uuid }
`))
	if err == nil {
		t.Fatal("expected error for missing table")
	}
}

func TestParseRequiresFields(t *testing.T) {
	_, err := Parse(strings.NewReader(`
name: deal
table: deals
`))
	if err == nil {
		t.Fatal("expected error for missing fields")
	}
}

func TestParseEnumRequiresValues(t *testing.T) {
	_, err := Parse(strings.NewReader(`
name: bad
table: bads
fields:
  status: { type: enum }
`))
	if err == nil {
		t.Fatal("expected error for enum without values")
	}
}

func TestParseForeignRequiresModel(t *testing.T) {
	_, err := Parse(strings.NewReader(`
name: bad
table: bads
fields:
  parent_id: { type: foreign }
`))
	if err == nil {
		t.Fatal("expected error for foreign without model")
	}
}

func TestToResourceDef(t *testing.T) {
	rf, err := Parse(strings.NewReader(dealYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	def, err := rf.ToResourceDef()
	if err != nil {
		t.Fatalf("ToResourceDef: %v", err)
	}

	if def.Name != "deal" {
		t.Errorf("def.Name = %q", def.Name)
	}
	if def.Table != "deals" {
		t.Errorf("def.Table = %q", def.Table)
	}
	if def.Schema == nil {
		t.Fatal("def.Schema is nil")
	}
	if len(def.Schema.Fields) != 8 {
		t.Errorf("def.Schema.Fields count = %d, want 8", len(def.Schema.Fields))
	}

	f := def.Schema.Fields["status"]
	if f.Type != schema.FieldEnum {
		t.Errorf("status type = %q", f.Type)
	}

	orgF := def.Schema.Fields["organization_id"]
	if orgF.FromSource != "session.activeOrganizationId" {
		t.Errorf("organization_id from = %q", orgF.FromSource)
	}

	ownerF := def.Schema.Fields["owner_id"]
	if ownerF.ForeignModel != "workspace_member" {
		t.Errorf("owner_id model = %q", ownerF.ForeignModel)
	}

	if def.Operations.List != nil {
		t.Error("List should be nil (enabled by default)")
	}
}

func TestToResourceDef_DisabledOps(t *testing.T) {
	rf, err := Parse(strings.NewReader(`
name: log
table: logs
operations:
  get:    true
  list:   true
  create: true
  update: false
  delete: false
fields:
  id: { type: uuid, readonly: true }
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	def, err := rf.ToResourceDef()
	if err != nil {
		t.Fatalf("ToResourceDef: %v", err)
	}

	if def.Operations.Update == nil || *def.Operations.Update {
		t.Error("Update should be disabled")
	}
	if def.Operations.Delete == nil || *def.Operations.Delete {
		t.Error("Delete should be disabled")
	}
}

func TestKnownFields_RejectsUnknown(t *testing.T) {
	_, err := Parse(strings.NewReader(`
name: deal
table: deals
fields:
  id: { type: uuid }
bogus_extra_key: true
`))
	if err == nil {
		t.Fatal("expected error for unknown top-level key")
	}
}

func TestParsePKNamingSeries(t *testing.T) {
	yaml := `
name: ticket
table: tickets

pk:
  column: name
  strategy: naming_series
  template: "TICKET-.YYYY.-.####"

fields:
  subject: { type: string, required: true }
`
	rf, err := Parse(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	def, err := rf.ToResourceDef()
	if err != nil {
		t.Fatalf("ToResourceDef: %v", err)
	}

	pk := def.Schema.PK
	if pk == nil {
		t.Fatal("expected PK on DynamicSchema")
	}
	if pk.Column != "name" || pk.Autoname.Template != "TICKET-.YYYY.-.####" {
		t.Fatalf("unexpected pk: %+v", pk)
	}
	fd, ok := def.Schema.Fields["name"]
	if !ok {
		t.Fatal("expected pk column injected into fields")
	}
	if !fd.IsReadonly {
		t.Fatal("expected injected pk field to be readonly")
	}
}

func TestParsePKRejectsUnknownStrategy(t *testing.T) {
	// Behavior change vs beta: fail fast at Parse with resource context,
	// not later at ToResourceDef.
	_, err := Parse(strings.NewReader(`
name: ticket
table: tickets

pk:
  column: name
  strategy: bogus

fields:
  subject: { type: string }
`))
	if err == nil {
		t.Fatal("expected error for unknown pk strategy")
	}
}

func TestParseChildrenField(t *testing.T) {
	yaml := `
name: lead
table: leads

fields:
  id:     { type: uuid, readonly: true }
  title:  { type: string, required: true }
  products: { type: children, of: product, order_by: position }
`
	rf, err := Parse(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	def, err := rf.ToResourceDef()
	if err != nil {
		t.Fatalf("ToResourceDef: %v", err)
	}
	fd, ok := def.Schema.Fields["products"]
	if !ok {
		t.Fatal("expected products field")
	}
	if fd.ChildrenOf != "product" || fd.ChildOrderBy != "position" {
		t.Fatalf("children: %+v", fd)
	}
	if fd.Type != schema.FieldChildren {
		t.Fatal("expected children field type")
	}
}

func TestParseChildrenRejectsMissingOf(t *testing.T) {
	_, err := Parse(strings.NewReader(`
name: lead
table: leads

fields:
  products: { type: children }
`))
	if err == nil {
		t.Fatal("expected error for children without of")
	}
}

func TestParseParent(t *testing.T) {
	yaml := `
name: product
table: products

parent:
  resource: lead
  on_delete: CASCADE

fields:
  id: { type: uuid, readonly: true }
  product_name: { type: string, required: true }
`
	rf, err := Parse(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	def, err := rf.ToResourceDef()
	if err != nil {
		t.Fatalf("ToResourceDef: %v", err)
	}
	if def.Schema.Parent == nil {
		t.Fatal("expected parent ref")
	}
	if def.Schema.Parent.Resource != "lead" {
		t.Fatalf("parent resource=%q, want lead", def.Schema.Parent.Resource)
	}
	if def.Schema.Parent.OnDelete != schema.Cascade {
		t.Fatalf("parent on_delete=%q, want CASCADE", def.Schema.Parent.OnDelete)
	}
	if _, ok := def.Schema.Fields["lead_id"]; !ok {
		t.Fatal("expected lead_id injected into fields")
	}
}

func TestParseParentRejectsBadOnDelete(t *testing.T) {
	_, err := Parse(strings.NewReader(`
name: product
table: products
parent:
  resource: lead
  on_delete: BOGUS
fields:
  id: { type: uuid }
`))
	if err == nil {
		t.Fatal("expected error for bad parent on_delete")
	}
}

func TestPolyFKOnDeletePreserved(t *testing.T) {
	// Regression for beta B2: YAML on_delete silently became PolyNone.
	rf, err := Parse(strings.NewReader(`
name: note
table: notes
polymorphic:
  - id_field: ref_id
    type_field: ref_type
    allowed: [CRM Lead]
    on_delete: CASCADE
fields:
  id: { type: uuid }
  ref_id: { type: string }
  ref_type: { type: string }
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	def, err := rf.ToResourceDef()
	if err != nil {
		t.Fatalf("ToResourceDef: %v", err)
	}
	if len(def.PolyFKs) != 1 {
		t.Fatalf("expected 1 polyfk, got %d", len(def.PolyFKs))
	}
	p := def.PolyFKs[0]
	if p.IDField != "ref_id" || p.TypeField != "ref_type" ||
		!reflect.DeepEqual(p.AllowedTargets, []string{"CRM Lead"}) ||
		p.OnDelete != schema.Cascade {
		t.Fatalf("polyfk not preserved: %+v", p)
	}
}

// ─── New: operations forms ──────────────────────────────────────────────

func TestOperationsAllowList(t *testing.T) {
	rf, err := Parse(strings.NewReader(`
name: ro
table: ros
operations: [get, list]
fields:
  id: { type: uuid }
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	def, err := rf.ToResourceDef()
	if err != nil {
		t.Fatalf("ToResourceDef: %v", err)
	}
	if !def.Operations.Enabled("get") || !def.Operations.Enabled("list") {
		t.Fatal("expected get+list enabled")
	}
	for _, op := range []string{"create", "update", "delete"} {
		if def.Operations.Enabled(op) {
			t.Errorf("expected %s disabled by allow-list", op)
		}
	}
}

func TestOperationsRejectsUnknownName(t *testing.T) {
	for _, doc := range []string{
		"name: x\ntable: xs\noperations: [get, frobnicate]\nfields:\n  id: { type: uuid }\n",
		"name: x\ntable: xs\noperations:\n  frobnicate: true\nfields:\n  id: { type: uuid }\n",
	} {
		if _, err := Parse(strings.NewReader(doc)); err == nil {
			t.Fatalf("expected error for unknown operation in %q", doc)
		}
	}
}

// ─── New: resource keys ─────────────────────────────────────────────────

func TestTenantTitleMapping(t *testing.T) {
	rf, err := Parse(strings.NewReader(`
name: widget
table: widgets
tenant: team
title: label
fields:
  team: { type: string }
  label: { type: string }
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	def, err := rf.ToResourceDef()
	if err != nil {
		t.Fatalf("ToResourceDef: %v", err)
	}
	if def.Schema.TenantColumn != "team" || def.Schema.TitleField != "label" {
		t.Fatalf("tenant/title not mapped: %+v", def.Schema)
	}
}

func TestTenantRejectsUnknownField(t *testing.T) {
	_, err := Parse(strings.NewReader(`
name: widget
table: widgets
tenant: nope
fields:
  team: { type: string }
`))
	if err == nil {
		t.Fatal("expected error for tenant naming unknown field")
	}
}

func TestCompositeGroupsMapping(t *testing.T) {
	rf, err := Parse(strings.NewReader(`
name: widget
table: widgets
unique:
  - [team, label]
indexes:
  - [owner, status]
fields:
  team: { type: string }
  label: { type: string }
  owner: { type: string }
  status: { type: string }
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	def, err := rf.ToResourceDef()
	if err != nil {
		t.Fatalf("ToResourceDef: %v", err)
	}
	if !reflect.DeepEqual(def.Schema.CompositeUniques, [][]string{{"team", "label"}}) {
		t.Fatalf("uniques: %v", def.Schema.CompositeUniques)
	}
	if !reflect.DeepEqual(def.Schema.CompositeIndexes, [][]string{{"owner", "status"}}) {
		t.Fatalf("indexes: %v", def.Schema.CompositeIndexes)
	}
}

func TestLifecycleKeysBrickTable(t *testing.T) {
	rf, err := Parse(strings.NewReader(`
name: widget
table: widgets
soft_delete: archived_at
audit: true
versioned: true
writable_on_update: [status]
fields:
  status: { type: string }
  archived_at: { type: timestamp }
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	def, err := rf.ToResourceDef()
	if err != nil {
		t.Fatalf("ToResourceDef: %v", err)
	}
	s := def.Schema
	if s.SoftDeleteColumn != "archived_at" || !s.Audited || !s.Versioned ||
		!reflect.DeepEqual(s.UpdateWritable, []string{"status"}) {
		t.Fatalf("lifecycle not mapped: %+v", s)
	}
}

func TestLifecycleKeysRejectedOnFrappeTable(t *testing.T) {
	for _, doc := range []string{
		"name: w\ntable: tabWidget\nsoft_delete: archived_at\nfields:\n  archived_at: { type: timestamp }\n",
		"name: w\ntable: tabWidget\naudit: true\nfields:\n  id: { type: uuid }\n",
		"name: w\ntable: tabWidget\nversioned: true\nfields:\n  id: { type: uuid }\n",
	} {
		if _, err := Parse(strings.NewReader(doc)); err == nil {
			t.Fatalf("expected lifecycle rejection for Frappe table in %q", doc)
		}
	}
}

func TestSoftDeleteRequiresTimestamp(t *testing.T) {
	_, err := Parse(strings.NewReader(`
name: w
table: ws
soft_delete: status
fields:
  status: { type: string }
`))
	if err == nil {
		t.Fatal("expected error for non-timestamp soft_delete")
	}
}

func TestWritableOnUpdateRejectsBadFields(t *testing.T) {
	for _, doc := range []string{
		"name: w\ntable: ws\nwritable_on_update: [nope]\nfields:\n  status: { type: string }\n",
		"name: w\ntable: ws\nwritable_on_update: [owner]\nfields:\n  owner: { type: string, readonly: true }\n",
	} {
		if _, err := Parse(strings.NewReader(doc)); err == nil {
			t.Fatalf("expected writable_on_update rejection in %q", doc)
		}
	}
}

func TestPKStrategyKeys(t *testing.T) {
	bad := map[string]string{
		"naming_series without template": "pk: {column: name, strategy: naming_series}",
		"field without source":           "pk: {column: name, strategy: field}",
		"hash with zero length":          "pk: {column: name, strategy: hash, length: 0}",
	}
	for name, pkLine := range bad {
		doc := "name: t\ntable: ts\n" + pkLine + "\nfields:\n  subject: { type: string }\n"
		if _, err := Parse(strings.NewReader(doc)); err == nil {
			t.Errorf("expected error for %s", name)
		}
	}
}

func TestLookupAndAutoCreateCarried(t *testing.T) {
	rf, err := Parse(strings.NewReader(`
name: page
table: pages
lookup_field: slug
auto_create: true
fields:
  id: { type: uuid }
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	def, err := rf.ToResourceDef()
	if err != nil {
		t.Fatalf("ToResourceDef: %v", err)
	}
	if def.LookupField != "slug" || !def.AutoCreate {
		t.Fatalf("lookup/autocreate not carried: %+v", def)
	}
}

// ─── Fixture-driven tests ───────────────────────────────────────────────

func TestValidFixtures(t *testing.T) {
	entries, err := os.ReadDir("testdata/valid")
	if err != nil {
		t.Fatalf("read valid dir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no valid fixtures")
	}
	for _, e := range entries {
		path := filepath.Join("testdata/valid", e.Name())
		rf, err := ParseFile(path)
		if err != nil {
			t.Errorf("%s: ParseFile: %v", e.Name(), err)
			continue
		}
		def, err := rf.ToResourceDef()
		if err != nil {
			t.Errorf("%s: ToResourceDef: %v", e.Name(), err)
			continue
		}
		if def.Schema == nil || len(def.Schema.Fields) == 0 {
			t.Errorf("%s: empty schema", e.Name())
		}
	}
}

func TestFullFixtureMapping(t *testing.T) {
	rf, err := ParseFile("testdata/valid/full.resource.yaml")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	def, err := rf.ToResourceDef()
	if err != nil {
		t.Fatalf("ToResourceDef: %v", err)
	}
	s := def.Schema
	if def.Name != "widget" || def.Table != "widgets" {
		t.Fatalf("identity: %+v", def)
	}
	if s.TenantColumn != "team" || s.TitleField != "label" {
		t.Fatalf("tenant/title: %+v", s)
	}
	if !reflect.DeepEqual(s.CompositeUniques, [][]string{{"team", "label"}}) {
		t.Fatalf("uniques: %v", s.CompositeUniques)
	}
	if s.PK == nil || s.PK.Autoname.Strategy != schema.AutonameHash || s.PK.Autoname.HashLen != 10 {
		t.Fatalf("pk: %+v", s.PK)
	}
	if s.Parent == nil || s.Parent.Resource != "gadget" {
		t.Fatalf("parent: %+v", s.Parent)
	}
	if s.Singleton == nil || !s.Singleton.Enabled || s.Singleton.Scope == nil {
		t.Fatalf("singleton: %+v", s.Singleton)
	}
	if len(def.PolyFKs) != 1 || def.PolyFKs[0].OnDelete != schema.Cascade {
		t.Fatalf("polyfks: %+v", def.PolyFKs)
	}
	if fd := s.Fields["legacy_id"]; fd.Type != schema.FieldForeign || fd.ForeignModel != "legacy" {
		t.Fatalf("foreignkey alias not normalized: %+v", fd)
	}
	if fd := s.Fields["organization_id"]; !fd.IsReadonly || fd.FromSource != "session.activeOrganizationId" {
		t.Fatalf("from: %+v", fd)
	}
	if !s.Audited || !s.Versioned || s.SoftDeleteColumn != "archived_at" {
		t.Fatalf("lifecycle: %+v", s)
	}
}

func TestAllowlistFixture(t *testing.T) {
	def, err := loadDef("testdata/valid/allowlist.resource.yaml")
	if err != nil {
		t.Fatalf("%v", err)
	}
	for _, op := range []string{"get", "list"} {
		if !def.Operations.Enabled(op) {
			t.Errorf("expected %s enabled", op)
		}
	}
	for _, op := range []string{"create", "update", "delete"} {
		if def.Operations.Enabled(op) {
			t.Errorf("expected %s disabled", op)
		}
	}
}

func TestInvalidFixtures(t *testing.T) {
	entries, err := os.ReadDir("testdata/invalid")
	if err != nil {
		t.Fatalf("read invalid dir: %v", err)
	}
	if len(entries) < 10 {
		t.Fatalf("expected >= 10 invalid fixtures, got %d", len(entries))
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names) // deterministic iteration
	for _, n := range names {
		path := filepath.Join("testdata/invalid", n)
		rf, err := ParseFile(path)
		if err == nil {
			// A fixture may pass Parse only if ToResourceDef rejects it;
			// today all fixtures must fail at Parse.
			if _, err2 := rf.ToResourceDef(); err2 == nil {
				t.Errorf("%s: expected rejection, got none", n)
			}
			continue
		}
		// Error must name the file (ParseFile wraps with path).
		if !strings.Contains(err.Error(), n) {
			t.Errorf("%s: error lacks file context: %v", n, err)
		}
	}
}

func TestLoadDirSortsByName(t *testing.T) {
	dir := t.TempDir()
	write := func(filename, name string) {
		t.Helper()
		doc := "name: " + name + "\ntable: " + name + "s\nfields:\n  id: { type: uuid }\n"
		if err := os.WriteFile(filepath.Join(dir, filename), []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("c.resource.yaml", "zebra")
	write("a.resource.yaml", "alpha")
	write("b.resource.yaml", "mango")
	write("notes.txt", "ignored")

	defs, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	var names []string
	for _, d := range defs {
		names = append(names, d.Name)
	}
	if want := []string{"alpha", "mango", "zebra"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("LoadDir order = %v, want %v", names, want)
	}
}

func TestLoadDirDeterministic(t *testing.T) {
	first, err := LoadDir("testdata/valid")
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	second, err := LoadDir("testdata/valid")
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("LoadDir not deterministic across runs")
	}
}

func TestLoadDirFailsFastWithPath(t *testing.T) {
	dir := t.TempDir()
	ok := "name: ok\ntable: oks\nfields:\n  id: { type: uuid }\n"
	bad := "name: bad\ntable: bads\nfields:\n  id: { type: bogus }\n"
	if err := os.WriteFile(filepath.Join(dir, "a-ok.resource.yaml"), []byte(ok), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "z-bad.resource.yaml"), []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadDir(dir)
	if err == nil {
		t.Fatal("expected LoadDir error")
	}
	if !strings.Contains(err.Error(), "z-bad.resource.yaml") {
		t.Fatalf("error lacks file path: %v", err)
	}
}

func loadDef(path string) (schema.ResourceDef, error) {
	rf, err := ParseFile(path)
	if err != nil {
		return schema.ResourceDef{}, err
	}
	return rf.ToResourceDef()
}
