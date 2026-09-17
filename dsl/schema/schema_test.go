package schema_test

import (
	"reflect"
	"testing"

	"github.com/brick-org/brick/dsl/schema"
)

// ─── Ported beta builder tests (import path only) ─────────────────────────

func TestString_ReturnsFieldOfTypeString(t *testing.T) {
	f := schema.String()
	if f.Type != schema.FieldString {
		t.Fatalf("expected type string, got %q", f.Type)
	}
}

func TestInt_ReturnsFieldOfTypeInt(t *testing.T) {
	f := schema.Int()
	if f.Type != schema.FieldInt {
		t.Fatalf("expected type int, got %q", f.Type)
	}
}

func TestBool_ReturnsFieldOfTypeBool(t *testing.T) {
	f := schema.Bool()
	if f.Type != schema.FieldBool {
		t.Fatalf("expected type bool, got %q", f.Type)
	}
}

func TestText_ReturnsFieldOfTypeText(t *testing.T) {
	f := schema.Text()
	if f.Type != schema.FieldText {
		t.Fatalf("expected type text, got %q", f.Type)
	}
}

func TestFloat_ReturnsFieldOfTypeFloat(t *testing.T) {
	f := schema.Float()
	if f.Type != schema.FieldFloat {
		t.Fatalf("expected type float, got %q", f.Type)
	}
}

func TestTimestamp_ReturnsFieldOfTypeTimestamp(t *testing.T) {
	f := schema.Timestamp()
	if f.Type != schema.FieldTimestamp {
		t.Fatalf("expected type timestamp, got %q", f.Type)
	}
}

func TestUUID_ReturnsFieldOfTypeUUID(t *testing.T) {
	f := schema.UUID()
	if f.Type != schema.FieldUUID {
		t.Fatalf("expected type uuid, got %q", f.Type)
	}
}

func TestJSON_ReturnsFieldOfTypeJSON(t *testing.T) {
	f := schema.JSON()
	if f.Type != schema.FieldJSON {
		t.Fatalf("expected type json, got %q", f.Type)
	}
}

func TestEnum_StoresValues(t *testing.T) {
	f := schema.Enum("a", "b")
	if f.Type != schema.FieldEnum {
		t.Fatalf("expected type enum, got %q", f.Type)
	}
	if !reflect.DeepEqual(f.EnumValues, []string{"a", "b"}) {
		t.Fatalf("expected values [a b], got %v", f.EnumValues)
	}
}

func TestForeignKey_StoresModel(t *testing.T) {
	f := schema.ForeignKey("deal")
	if f.Type != schema.FieldForeign {
		t.Fatalf("expected type foreignkey, got %q", f.Type)
	}
	if f.ForeignModel != "deal" {
		t.Fatalf("expected model deal, got %q", f.ForeignModel)
	}
}

func TestRequired_SetsRequiredFlag(t *testing.T) {
	f := schema.String().Required()
	if !f.IsRequired || f.IsOptional {
		t.Fatal("expected Required=true, Optional=false")
	}
}

func TestOptional_SetsOptionalFlag(t *testing.T) {
	f := schema.String().Optional()
	if !f.IsOptional || f.IsRequired {
		t.Fatal("expected Optional=true, Required=false")
	}
}

func TestDefault_SetsDefaultValue(t *testing.T) {
	f := schema.Int().Default(0)
	if f.DefaultValue != 0 {
		t.Fatalf("expected default 0, got %v", f.DefaultValue)
	}
}

func TestUnique_SetsUniqueFlag(t *testing.T) {
	if !schema.String().Unique().IsUnique {
		t.Fatal("expected IsUnique to be true")
	}
}

func TestMaxLen_SetsMaxLength(t *testing.T) {
	if schema.String().MaxLen(100).MaxLength != 100 {
		t.Fatal("expected max length 100")
	}
}

func TestEmail_SetsEmailFlag(t *testing.T) {
	if !schema.String().Email().IsEmail {
		t.Fatal("expected IsEmail to be true")
	}
}

func TestSearchable_SetsSearchableFlag(t *testing.T) {
	if !schema.String().Searchable().IsSearchable {
		t.Fatal("expected IsSearchable to be true")
	}
}

func TestFilterable_SetsFilterableFlag(t *testing.T) {
	if !schema.String().Filterable().IsFilterable {
		t.Fatal("expected IsFilterable to be true")
	}
}

func TestSortable_SetsSortableFlag(t *testing.T) {
	if !schema.String().Sortable().IsSortable {
		t.Fatal("expected IsSortable to be true")
	}
}

func TestHidden_SetsHiddenFlag(t *testing.T) {
	if !schema.String().Hidden().IsHidden {
		t.Fatal("expected IsHidden to be true")
	}
}

func TestReadonly_SetsReadonlyFlag(t *testing.T) {
	if !schema.String().Readonly().IsReadonly {
		t.Fatal("expected IsReadonly to be true")
	}
}

func TestIndex_SetsIndexFlag(t *testing.T) {
	if !schema.String().Index().IsIndex {
		t.Fatal("expected IsIndex to be true")
	}
}

func TestOnDelete_SetsAction(t *testing.T) {
	if schema.String().OnDelete(schema.Cascade).OnDeleteAct != schema.Cascade {
		t.Fatal("expected CASCADE")
	}
}

func TestModifierChaining(t *testing.T) {
	f := schema.String().Required().Default("hi").MaxLen(100).Unique().Searchable()
	if !f.IsRequired {
		t.Fatal("expected IsRequired to be true")
	}
	if f.DefaultValue != "hi" {
		t.Fatalf("expected default 'hi', got %v", f.DefaultValue)
	}
	if f.MaxLength != 100 {
		t.Fatalf("expected max length 100, got %d", f.MaxLength)
	}
	if !f.IsUnique {
		t.Fatal("expected IsUnique to be true")
	}
	if !f.IsSearchable {
		t.Fatal("expected IsSearchable to be true")
	}
}

func TestSchema_GenericStruct(t *testing.T) {
	type MyRow struct{}
	type MyCreate struct{}
	type MyUpdate struct{}
	s := schema.Schema[MyRow, MyCreate, MyUpdate]{
		Fields: schema.Fields{
			"name": schema.String().Required(),
		},
	}
	if s.Fields["name"] == nil {
		t.Fatal("expected name field in schema")
	}
	if !s.Fields["name"].IsRequired {
		t.Fatal("expected name field to be required")
	}
}

func TestDynamicSchema_MapBasedVariant(t *testing.T) {
	s := schema.DynamicSchema{
		Fields: schema.Fields{
			"title": schema.String().Required(),
		},
	}
	if s.Fields["title"] == nil {
		t.Fatal("expected title field in dynamic schema")
	}
}

func TestOperations_AllEnabledByDefault(t *testing.T) {
	ops := schema.Operations{}
	for _, op := range []string{"list", "get", "create", "update", "delete"} {
		if !ops.Enabled(op) {
			t.Fatalf("expected %s enabled by default", op)
		}
	}
	if ops.List != nil || ops.Get != nil || ops.Create != nil || ops.Update != nil || ops.Delete != nil {
		t.Fatal("expected all slots nil by default")
	}
}

func TestOperations_CanDisableSpecificOps(t *testing.T) {
	disabled := false
	ops := schema.Operations{Delete: &disabled}
	if ops.Delete == nil || *ops.Delete {
		t.Fatal("expected Delete to be false (disabled)")
	}
	if !ops.Enabled("list") || ops.Enabled("delete") || ops.Enabled("bogus") {
		t.Fatal("expected list on, delete off, bogus off")
	}
}

// ─── New: from + computed + normalize ─────────────────────────────────────

func TestFrom_ForcesReadonly(t *testing.T) {
	f := schema.String().From("session.userId")
	if f.FromSource != "session.userId" || !f.IsReadonly {
		t.Fatalf("expected from+readonly, got %+v", f)
	}
}

func TestComputed_IsResponseOnly(t *testing.T) {
	f := schema.Float().Computed()
	if !f.IsComputed || !f.IsReadonly {
		t.Fatalf("expected computed+readonly, got %+v", f)
	}
}

func TestNormalize_StoresRule(t *testing.T) {
	if schema.String().Normalize("email").NormalizeWith != "email" {
		t.Fatal("expected normalize rule email")
	}
}

// ─── New: casing table (must match beta outputs byte-for-byte) ────────────

func TestCasing(t *testing.T) {
	cases := []struct{ in, title, goName, listName string }{
		{"name", "Name", "Name", "Name"},
		{"modified_by", "Modified_by", "ModifiedBy", "ModifiedBy"},
		{"content_type", "Content_type", "ContentType", "ContentType"},
		{"group_by_field", "Group_by_field", "GroupByField", "GroupByField"},
		{"kanban_columns", "Kanban_columns", "KanbanColumns", "KanbanColumns"},
		{"user_id", "User_id", "UserId", "UserId"},
		{"dt", "Dt", "Dt", "Dt"},
		{"page", "Page", "Page", "FilterPage"},
		{"limit", "Limit", "Limit", "FilterLimit"},
		{"sort", "Sort", "Sort", "FilterSort"},
		{"search", "Search", "Search", "FilterSearch"},
		{"body", "Body", "Body", "FilterBody"},
		{"", "", "", ""},
		{"2fa", "2fa", "2fa", "2fa"},
	}
	for _, c := range cases {
		if got := schema.Title(c.in); got != c.title {
			t.Errorf("Title(%q) = %q, want %q", c.in, got, c.title)
		}
		if got := schema.GoFieldName(c.in); got != c.goName {
			t.Errorf("GoFieldName(%q) = %q, want %q", c.in, got, c.goName)
		}
		if got := schema.ListInputFieldName(c.in); got != c.listName {
			t.Errorf("ListInputFieldName(%q) = %q, want %q", c.in, got, c.listName)
		}
	}
}

func TestGoType(t *testing.T) {
	cases := []struct {
		def  *schema.FieldDef
		want string
	}{
		{schema.String(), "string"},
		{schema.Text(), "string"},
		{schema.Enum("a"), "string"},
		{schema.UUID(), "string"},
		{schema.ForeignKey("deal"), "string"},
		{schema.Int(), "int32"},
		{schema.Float(), "float64"},
		{schema.Bool(), "bool"},
		{schema.Timestamp(), "time.Time"},
		{schema.JSON(), "json.RawMessage"},
	}
	for _, c := range cases {
		if got := schema.GoType(c.def); got != c.want {
			t.Errorf("GoType(%s) = %q, want %q", c.def.Type, got, c.want)
		}
	}
}

func TestGoTypeFor_AutoincPKIsInt64(t *testing.T) {
	pk := &schema.PK{Column: "name", Type: schema.FieldInt, Autoname: schema.Autoname{Strategy: schema.AutonameAutoinc}}
	def := schema.Int()
	if got := schema.GoTypeFor("name", def, pk); got != "int64" {
		t.Fatalf("GoTypeFor autoinc pk = %q, want int64", got)
	}
	if got := schema.GoTypeFor("idx", def, pk); got != "int32" {
		t.Fatalf("GoTypeFor regular int = %q, want int32", got)
	}
	if got := schema.GoTypeFor("name", def, nil); got != "int32" {
		t.Fatalf("GoTypeFor nil pk = %q, want int32", got)
	}
}

func TestSortedFields_PKFirstThenAlpha(t *testing.T) {
	fields := schema.Fields{
		"team":     schema.String(),
		"name":     schema.Int(),
		"creation": schema.Timestamp(),
		"dt":       schema.String(),
	}
	if got, want := schema.SortedFields(fields, "name"), []string{"name", "creation", "dt", "team"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("SortedFields = %v, want %v", got, want)
	}
	if got, want := schema.SortedFields(fields, "missing"), []string{"creation", "dt", "name", "team"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("SortedFields missing pk = %v, want %v", got, want)
	}
	// Deterministic across runs (map order must not leak).
	for i := 0; i < 50; i++ {
		if got := schema.SortedFields(fields, "name"); !reflect.DeepEqual(got, []string{"name", "creation", "dt", "team"}) {
			t.Fatalf("unstable order on iteration %d: %v", i, got)
		}
	}
}

// ─── New: ApplyPK per strategy ────────────────────────────────────────────

func TestApplyPK(t *testing.T) {
	strategies := []struct {
		strategy     schema.AutonameStrategy
		wantRequired bool
		wantReadonly bool
	}{
		{schema.AutonamePrompt, true, false},
		{schema.AutonameUUID, false, true},
		{schema.AutonameHash, false, true},
		{schema.AutonameAutoinc, false, true},
		{schema.AutonameSeries, false, true},
		{schema.AutonameFormat, false, true},
		{schema.AutonameFromField, false, true},
	}
	for _, s := range strategies {
		ds := &schema.DynamicSchema{Fields: schema.Fields{}}
		ds.ApplyPK(&schema.PK{Column: "name", Type: schema.FieldString, Autoname: schema.Autoname{Strategy: s.strategy}})
		fd := ds.Fields["name"]
		if fd == nil {
			t.Fatalf("%s: expected injected pk field", s.strategy)
		}
		if fd.IsRequired != s.wantRequired || fd.IsReadonly != s.wantReadonly {
			t.Errorf("%s: required=%v readonly=%v, want %v/%v", s.strategy, fd.IsRequired, fd.IsReadonly, s.wantRequired, s.wantReadonly)
		}
		if ds.PK == nil || ds.PK.Column != "name" {
			t.Errorf("%s: PK not recorded", s.strategy)
		}
	}
}

func TestApplyPK_DoesNotOverwriteDeclaredField(t *testing.T) {
	ds := &schema.DynamicSchema{Fields: schema.Fields{"name": schema.Int().Required()}}
	ds.ApplyPK(&schema.PK{Column: "name", Type: schema.FieldInt, Autoname: schema.Autoname{Strategy: schema.AutonameAutoinc}})
	if !ds.Fields["name"].IsRequired {
		t.Fatal("expected declared field to survive ApplyPK")
	}
}

// ─── New: ApplyParent ─────────────────────────────────────────────────────

func TestApplyParent_InjectsFK(t *testing.T) {
	ds := &schema.DynamicSchema{Fields: schema.Fields{}}
	ds.ApplyParent(&schema.ParentRef{Resource: "deal", OnDelete: schema.Cascade})
	fd := ds.Fields["deal_id"]
	if fd == nil {
		t.Fatal("expected injected deal_id field")
	}
	if fd.Type != schema.FieldForeign || fd.ForeignModel != "deal" || !fd.IsRequired || !fd.IsFilterable || fd.OnDeleteAct != schema.Cascade {
		t.Fatalf("unexpected injected field: %+v", fd)
	}
	if schema.ChildParentColumn("deal") != "deal_id" {
		t.Fatal("expected deal_id")
	}
}

// ─── New: resource-level slots (tenant/title/indexes/lifecycle) ───────────

func TestResourceBuilders(t *testing.T) {
	ds := &schema.DynamicSchema{Fields: schema.Fields{}}
	ds.Tenant("team").Title("label").Unique("team", "label").Index("owner", "status").
		SoftDelete("archived_at").Audit().WithVersioned().WritableOnUpdate("status", "owner")
	if ds.TenantColumn != "team" || ds.TitleField != "label" {
		t.Fatalf("tenant/title not recorded: %+v", ds)
	}
	if !reflect.DeepEqual(ds.CompositeUniques, [][]string{{"team", "label"}}) {
		t.Fatalf("uniques: %v", ds.CompositeUniques)
	}
	if !reflect.DeepEqual(ds.CompositeIndexes, [][]string{{"owner", "status"}}) {
		t.Fatalf("indexes: %v", ds.CompositeIndexes)
	}
	if ds.SoftDeleteColumn != "archived_at" || !ds.Audited || !ds.Versioned {
		t.Fatalf("lifecycle flags: %+v", ds)
	}
	if !reflect.DeepEqual(ds.UpdateWritable, []string{"status", "owner"}) {
		t.Fatalf("writable: %v", ds.UpdateWritable)
	}
}

func TestResourceDef_Shape(t *testing.T) {
	def := schema.ResourceDef{
		Name:  "view_setting",
		Table: "tabCRM View Settings",
		Schema: &schema.DynamicSchema{
			Fields: schema.Fields{"team": schema.String().Required().Filterable()},
		},
		PolyFKs: []schema.PolyFKDef{{TypeField: "ref_type", IDField: "ref_id", AllowedTargets: []string{"CRM Lead"}, OnDelete: schema.Cascade}},
	}
	if def.PolyFKs[0].OnDelete != schema.Cascade {
		t.Fatal("expected PolyFK OnDelete preserved (beta B2 regression)")
	}
}
