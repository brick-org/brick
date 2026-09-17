package schema_test

import (
	"reflect"
	"testing"

	"github.com/brick-org/brick/dsl/schema"
)

func TestDefine_Basic(t *testing.T) {
	def := schema.Define("deal", "deals", schema.Fields{
		"title": schema.String().Required(),
	})
	if def.Name != "deal" || def.Table != "deals" {
		t.Fatalf("identity: %+v", def)
	}
	if def.Schema == nil || def.Schema.Fields["title"] == nil {
		t.Fatal("expected schema with title field")
	}
	if !def.Operations.Enabled("list") || !def.Operations.Enabled("delete") {
		t.Fatal("expected all operations enabled by default")
	}
	if def.LookupField != "" || def.AutoCreate || len(def.PolyFKs) != 0 {
		t.Fatalf("expected zero extras: %+v", def)
	}
}

func TestDefine_FullResource(t *testing.T) {
	def := schema.Define("widget", "widgets", schema.Fields{
		"slug":        schema.String().Required().Unique().Searchable(),
		"label":       schema.String().Required().Filterable(),
		"team":        schema.String().Required().Filterable(),
		"owner":       schema.String().Filterable(),
		"status":      schema.Enum("open", "closed").Default("open").Filterable(),
		"owner_id":    schema.ForeignKey("workspace_member").Required(),
		"archived_at": schema.Timestamp(),
	},
		schema.WithTitle("label"),
		schema.WithTenant("team"),
		schema.WithLookup("slug"),
		schema.WithPK(schema.HashPK("name", 10)),
		schema.WithUnique("team", "label"),
		schema.WithIndex("owner", "status"),
		schema.WithSoftDelete("archived_at"),
		schema.WithAudit(),
		schema.WithVersioned(),
		schema.WithWritableOnUpdate("status", "owner"),
		schema.WithPolyFKs(schema.NewPolyFK("ref_id", "ref_type", []string{"CRM Lead"}, schema.Cascade)),
	)
	if err := def.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	s := def.Schema
	if s.TitleField != "label" || s.TenantColumn != "team" {
		t.Fatalf("tenant/title: %+v", s)
	}
	if def.LookupField != "slug" {
		t.Fatalf("lookup: %q", def.LookupField)
	}
	if s.PK == nil || s.PK.Autoname.Strategy != schema.AutonameHash || s.PK.Autoname.HashLen != 10 {
		t.Fatalf("pk: %+v", s.PK)
	}
	if _, ok := s.Fields["name"]; !ok {
		t.Fatal("expected pk column injected into fields")
	}
	if !reflect.DeepEqual(s.CompositeUniques, [][]string{{"team", "label"}}) {
		t.Fatalf("uniques: %v", s.CompositeUniques)
	}
	if len(def.PolyFKs) != 1 || def.PolyFKs[0].OnDelete != schema.Cascade {
		t.Fatalf("polyfks: %+v", def.PolyFKs)
	}
	if s.SoftDeleteColumn != "archived_at" || !s.Audited || !s.Versioned {
		t.Fatalf("lifecycle: %+v", s)
	}
}

func TestDefine_DerivesHidden(t *testing.T) {
	def := schema.Define("w", "ws", schema.Fields{
		"secret": schema.String().Hidden(),
		"name":   schema.String(),
	})
	if !reflect.DeepEqual(def.Schema.HiddenFields, []string{"secret"}) {
		t.Fatalf("hidden: %v", def.Schema.HiddenFields)
	}
}

func TestPKConstructors(t *testing.T) {
	cases := []struct {
		pk       *schema.PK
		column   string
		typ      schema.FieldType
		strategy schema.AutonameStrategy
	}{
		{schema.UUIDPK("id"), "id", schema.FieldUUID, schema.AutonameUUID},
		{schema.SeriesPK("name", "T-.####"), "name", schema.FieldString, schema.AutonameSeries},
		{schema.FieldPK("name", "title"), "name", schema.FieldString, schema.AutonameFromField},
		{schema.FormatPK("name", "S-{team}"), "name", schema.FieldString, schema.AutonameFormat},
		{schema.HashPK("name", 10), "name", schema.FieldString, schema.AutonameHash},
		{schema.PromptPK("name"), "name", schema.FieldString, schema.AutonamePrompt},
		{schema.AutoincPK("name"), "name", schema.FieldInt, schema.AutonameAutoinc},
	}
	for _, c := range cases {
		if c.pk.Column != c.column || c.pk.Type != c.typ || c.pk.Autoname.Strategy != c.strategy {
			t.Errorf("pk %+v: got %+v", c.strategy, c.pk)
		}
	}
	if pk := schema.SeriesPK("n", "T-.####"); pk.Autoname.Template != "T-.####" {
		t.Errorf("series template: %+v", pk)
	}
	if pk := schema.FieldPK("n", "title"); pk.Autoname.Source != "title" {
		t.Errorf("field source: %+v", pk)
	}
	if pk := schema.HashPK("n", 10); pk.Autoname.HashLen != 10 {
		t.Errorf("hash len: %+v", pk)
	}
}

func TestParentSingletonPolyConstructors(t *testing.T) {
	p := schema.NewParent("deal", schema.Cascade)
	if p.Resource != "deal" || p.OnDelete != schema.Cascade {
		t.Fatalf("parent: %+v", p)
	}
	if sc := schema.Singleton(); !sc.Enabled || sc.Scope != nil {
		t.Fatalf("global singleton: %+v", sc)
	}
	if sc := schema.ScopedSingleton("team", "teams"); !sc.Enabled || sc.Scope == nil ||
		sc.Scope.Column != "team" || sc.Scope.Model != "teams" {
		t.Fatalf("scoped singleton: %+v", sc)
	}
	fk := schema.NewPolyFK("ref_id", "ref_type", []string{"CRM Lead"}, schema.Cascade)
	if fk.IDField != "ref_id" || fk.TypeField != "ref_type" ||
		!reflect.DeepEqual(fk.AllowedTargets, []string{"CRM Lead"}) || fk.OnDelete != schema.Cascade {
		t.Fatalf("polyfk: %+v", fk)
	}
}

func TestWithParent_InjectsFK(t *testing.T) {
	def := schema.Define("product", "products", schema.Fields{
		"name": schema.String().Required(),
	}, schema.WithParent(schema.NewParent("deal", schema.Cascade)))
	if def.Schema.Parent == nil || def.Schema.Parent.Resource != "deal" {
		t.Fatalf("parent: %+v", def.Schema.Parent)
	}
	if _, ok := def.Schema.Fields["deal_id"]; !ok {
		t.Fatal("expected deal_id injected")
	}
}

func TestWithSingleton_DisablesWriteOps(t *testing.T) {
	def := schema.Define("settings", "settings", schema.Fields{
		"theme": schema.String(),
	}, schema.WithSingleton(schema.Singleton()))
	if def.Schema.Singleton == nil || !def.Schema.Singleton.Enabled {
		t.Fatal("expected singleton set")
	}
	for _, op := range []string{"create", "list", "delete"} {
		if def.Operations.Enabled(op) {
			t.Errorf("expected %s disabled for singleton", op)
		}
	}
	for _, op := range []string{"get", "update"} {
		if !def.Operations.Enabled(op) {
			t.Errorf("expected %s enabled for singleton", op)
		}
	}
}

func TestDisableOps(t *testing.T) {
	ops := schema.DisableOps("update", "delete")
	if ops.Enabled("update") || ops.Enabled("delete") {
		t.Fatal("expected update+delete disabled")
	}
	if !ops.Enabled("get") || !ops.Enabled("list") || !ops.Enabled("create") {
		t.Fatal("expected get+list+create enabled")
	}
	// Unknown names are ignored, never disable everything by accident.
	ops = schema.DisableOps("frobnicate")
	for _, op := range []string{"get", "list", "create", "update", "delete"} {
		if !ops.Enabled(op) {
			t.Errorf("expected %s enabled", op)
		}
	}
}

func TestOnlyOps(t *testing.T) {
	ops := schema.OnlyOps("get", "list")
	if !ops.Enabled("get") || !ops.Enabled("list") {
		t.Fatal("expected get+list enabled")
	}
	for _, op := range []string{"create", "update", "delete"} {
		if ops.Enabled(op) {
			t.Errorf("expected %s disabled", op)
		}
	}
}

func TestWithOperations_Lookup_AutoCreate(t *testing.T) {
	def := schema.Define("page", "pages", schema.Fields{
		"slug": schema.String().Required(),
	},
		schema.WithOperations(schema.OnlyOps("get", "update")),
		schema.WithLookup("slug"),
		schema.WithAutoCreate(),
	)
	if !def.Operations.Enabled("get") || def.Operations.Enabled("list") || !def.AutoCreate {
		t.Fatalf("ops/autocreate: %+v", def.Operations)
	}
	if def.LookupField != "slug" {
		t.Fatalf("lookup: %q", def.LookupField)
	}
}
