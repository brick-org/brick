package schema_test

import (
	"strings"
	"testing"

	"github.com/brick-org/brick/dsl/schema"
)

func validDef() schema.ResourceDef {
	return schema.Define("widget", "widgets", schema.Fields{
		"name":        schema.String().Readonly(),
		"slug":        schema.String().Required().Unique(),
		"label":       schema.String().Required().Filterable(),
		"team":        schema.String().Required(),
		"status":      schema.Enum("open", "closed").Default("open"),
		"owner_id":    schema.ForeignKey("member").Required(),
		"archived_at": schema.Timestamp(),
	},
		schema.WithTitle("label"),
		schema.WithTenant("team"),
		schema.WithUnique("team", "label"),
	)
}

func TestValidate_OK(t *testing.T) {
	if err := validDef().Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_MinimalOK(t *testing.T) {
	def := schema.Define("m", "ms", schema.Fields{"id": schema.UUID()})
	if err := def.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_Rejects(t *testing.T) {
	cases := []struct {
		name string
		def  schema.ResourceDef
		want string
	}{
		{"no name", schema.Define("", "ws", schema.Fields{"id": schema.UUID()}), "name is required"},
		{"no table", schema.Define("w", "", schema.Fields{"id": schema.UUID()}), "table is required"},
		{"no fields", schema.Define("w", "ws", schema.Fields{}), "at least one entry"},
		{"nil field", schema.ResourceDef{Name: "w", Table: "ws", Schema: &schema.DynamicSchema{Fields: schema.Fields{"id": nil}}}, "nil field"},
		{"enum no values", schema.Define("w", "ws", schema.Fields{"s": schema.String()}), ""}, // placeholder, replaced below
		{"foreign no model", schema.Define("w", "ws", schema.Fields{"f": schema.ForeignKey("")}), "requires model"},
		{"children no of", schema.Define("w", "ws", schema.Fields{"c": schema.Children("")}), "requires of"},
		{"bad on_delete", schema.Define("w", "ws", schema.Fields{"f": schema.ForeignKey("m").OnDelete("BOGUS")}), "invalid on_delete"},
		{"pk no column", schema.Define("w", "ws", schema.Fields{"id": schema.UUID()}, schema.WithPK(&schema.PK{})), "pk: column is required"},
		{"pk bad strategy", schema.Define("w", "ws", schema.Fields{"id": schema.UUID()}, schema.WithPK(&schema.PK{Column: "n", Autoname: schema.Autoname{Strategy: "bogus"}})), "unknown strategy"},
		{"series no template", schema.Define("w", "ws", schema.Fields{"id": schema.UUID()}, schema.WithPK(schema.SeriesPK("n", ""))), "requires template"},
		{"field no source", schema.Define("w", "ws", schema.Fields{"id": schema.UUID()}, schema.WithPK(schema.FieldPK("n", ""))), "requires source"},
		{"hash zero length", schema.Define("w", "ws", schema.Fields{"id": schema.UUID()}, schema.WithPK(schema.HashPK("n", 0))), "requires length"},
		{"parent no resource", schema.Define("w", "ws", schema.Fields{"id": schema.UUID()}, schema.WithParent(schema.NewParent("", schema.Cascade))), "parent: resource is required"},
		{"parent bad on_delete", schema.Define("w", "ws", schema.Fields{"id": schema.UUID()}, schema.WithParent(schema.NewParent("deal", "BOGUS"))), "parent: invalid on_delete"},
		{"poly missing fields", schema.Define("w", "ws", schema.Fields{"id": schema.UUID()}, schema.WithPolyFKs(schema.NewPolyFK("", "", nil, ""))), "id_field and type_field are required"},
		{"poly bad on_delete", schema.Define("w", "ws", schema.Fields{"id": schema.UUID()}, schema.WithPolyFKs(schema.NewPolyFK("a", "b", nil, "BOGUS"))), "invalid on_delete"},
		{"tenant unknown", schema.Define("w", "ws", schema.Fields{"id": schema.UUID()}, schema.WithTenant("nope")), "tenant"},
		{"title unknown", schema.Define("w", "ws", schema.Fields{"id": schema.UUID()}, schema.WithTitle("nope")), "title"},
		{"unique unknown", schema.Define("w", "ws", schema.Fields{"id": schema.UUID()}, schema.WithUnique("nope")), "unique[0]"},
		{"unique empty", schema.Define("w", "ws", schema.Fields{"id": schema.UUID()}, schema.WithUnique()), "unique[0] is empty"},
		{"index unknown", schema.Define("w", "ws", schema.Fields{"id": schema.UUID()}, schema.WithIndex("nope")), "indexes[0]"},
		{"soft_delete unknown", schema.Define("w", "ws", schema.Fields{"id": schema.UUID()}, schema.WithSoftDelete("nope")), "soft_delete"},
		{"soft_delete non-timestamp", schema.Define("w", "ws", schema.Fields{"s": schema.String()}, schema.WithSoftDelete("s")), "must be a timestamp"},
		{"writable unknown", schema.Define("w", "ws", schema.Fields{"id": schema.UUID()}, schema.WithWritableOnUpdate("nope")), "writable_on_update names unknown"},
		{"writable readonly", schema.Define("w", "ws", schema.Fields{"r": schema.String().Readonly()}, schema.WithWritableOnUpdate("r")), "names readonly field"},
		{"frappe soft_delete", schema.Define("w", "tabW", schema.Fields{"a": schema.Timestamp()}, schema.WithSoftDelete("a")), "rejected for Frappe-owned"},
		{"frappe audit", schema.Define("w", "tabW", schema.Fields{"id": schema.UUID()}, schema.WithAudit()), "rejected for Frappe-owned"},
		{"frappe versioned", schema.Define("w", "tabW", schema.Fields{"id": schema.UUID()}, schema.WithVersioned()), "rejected for Frappe-owned"},
	}
	// enum without values needs a raw FieldDef (Enum() always sets values).
	cases[4].def = schema.ResourceDef{Name: "w", Table: "ws",
		Schema: schema.NewDynamicSchema(schema.Fields{"s": {Type: schema.FieldEnum}})}
	cases[4].want = "enum type requires values"

	for _, c := range cases {
		if err := c.def.Validate(); err == nil {
			t.Errorf("%s: expected rejection, got none", c.name)
		} else if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q lacks %q", c.name, err, c.want)
		}
	}
}

func TestValidate_FullParity(t *testing.T) {
	// Every YAML full-fixture feature expressed in Go must validate.
	def := schema.Define("widget", "widgets", schema.Fields{
		"slug":            schema.String().Required().Unique().Searchable().Sortable(),
		"label":           schema.String().Required().Filterable(),
		"team":            schema.String().Required().Filterable(),
		"owner":           schema.String().Filterable(),
		"status":          schema.Enum("open", "closed").Default("open").Filterable(),
		"owner_id":        schema.ForeignKey("workspace_member").Required(),
		"organization_id": schema.String().From("session.activeOrganizationId"),
		"score":           schema.Int().Default(0),
		"ratio":           schema.Float(),
		"active":          schema.Bool().Default(false),
		"created_at":      schema.Timestamp().Readonly(),
		"meta":            schema.JSON(),
		"email":           schema.String().Email().MaxLen(255),
		"notes":           schema.Text(),
		"secret":          schema.String().Hidden(),
		"archived_at":     schema.Timestamp(),
		"child_ids":       schema.Children("widget_part").OrderBy("position").Index(),
	},
		schema.WithTenant("team"),
		schema.WithTitle("label"),
		schema.WithLookup("slug"),
		schema.WithUnique("team", "label"),
		schema.WithIndex("owner", "status"),
		schema.WithSoftDelete("archived_at"),
		schema.WithAudit(),
		schema.WithVersioned(),
		schema.WithWritableOnUpdate("status", "owner"),
		schema.WithPK(schema.HashPK("name", 10)),
		schema.WithParent(schema.NewParent("gadget", schema.Cascade)),
		schema.WithSingleton(schema.ScopedSingleton("team", "teams")),
		schema.WithPolyFKs(schema.NewPolyFK("ref_id", "ref_type", []string{"CRM Lead", "CRM Deal"}, schema.Cascade)),
	)
	if err := def.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}
