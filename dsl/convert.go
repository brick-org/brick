package dsl

import (
	"fmt"
	"strings"

	"github.com/brick-org/brick/schema"
)

// ToResourceDef converts a parsed ResourceFile into a schema.ResourceDef.
// Access and hooks are NOT set — they belong in resources.go (M5).
// LookupField and AutoCreate are carried so M5 can adapt them.
// The input is re-validated defensively; Parse already validates.
func (rf *ResourceFile) ToResourceDef() (schema.ResourceDef, error) {
	if err := validate(rf); err != nil {
		return schema.ResourceDef{}, err
	}
	fields, err := rf.toSchemaFields()
	if err != nil {
		return schema.ResourceDef{}, err
	}

	ds := buildDynamicSchema(fields)
	ds.TenantColumn = rf.Tenant
	ds.TitleField = rf.Title
	ds.CompositeUniques = rf.Uniques
	ds.CompositeIndexes = rf.Indexes
	ds.SoftDeleteColumn = rf.SoftDelete
	ds.Audited = rf.Audited
	ds.Versioned = rf.Versioned
	ds.UpdateWritable = rf.WritableOnUpdate

	if rf.PK != nil {
		pk, err := rf.PK.toPK()
		if err != nil {
			return schema.ResourceDef{}, err
		}
		ds.ApplyPK(pk)
	}
	if rf.Parent != nil {
		ds.ApplyParent(&schema.ParentRef{
			Resource: rf.Parent.Resource,
			OnDelete: schema.OnDeleteAction(strings.ToUpper(rf.Parent.OnDelete)),
		})
	}
	if rf.Singleton != nil {
		ds.Singleton = toSingletonConfig(rf.Singleton)
		// Singletons never get create/list/delete routes.
		disabled := false
		rf.Ops.Create = &disabled
		rf.Ops.List = &disabled
		rf.Ops.Delete = &disabled
	}

	return schema.ResourceDef{
		Name:        rf.Name,
		Table:       rf.Table,
		Schema:      ds,
		Operations:  rf.toOperations(),
		PolyFKs:     rf.toPolyFKs(),
		LookupField: rf.LookupField,
		AutoCreate:  rf.AutoCreate,
	}, nil
}

func (p *PKDef) toPK() (*schema.PK, error) {
	if p.Column == "" {
		return nil, fmt.Errorf("pk: column is required")
	}
	pk := &schema.PK{Column: p.Column, Type: schema.FieldString}
	switch p.Strategy {
	case "uuid":
		pk.Type = schema.FieldUUID
		pk.Autoname.Strategy = schema.AutonameUUID
	case "naming_series":
		pk.Autoname = schema.Autoname{Strategy: schema.AutonameSeries, Template: p.Template}
	case "field":
		pk.Autoname = schema.Autoname{Strategy: schema.AutonameFromField, Source: p.Source}
	case "format":
		pk.Autoname = schema.Autoname{Strategy: schema.AutonameFormat, Template: p.Template}
	case "hash":
		pk.Autoname = schema.Autoname{Strategy: schema.AutonameHash, HashLen: p.Length}
	case "prompt":
		pk.Autoname.Strategy = schema.AutonamePrompt
	case "autoincrement":
		pk.Type = schema.FieldInt
		pk.Autoname.Strategy = schema.AutonameAutoinc
	default:
		return nil, fmt.Errorf("pk: unknown strategy %q", p.Strategy)
	}
	return pk, nil
}

func (rf *ResourceFile) toSchemaFields() (schema.Fields, error) {
	fields := make(schema.Fields, len(rf.Fields))
	for name, def := range rf.Fields {
		fd, err := def.toFieldDef()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		fields[name] = fd
	}
	return fields, nil
}

func (d *FieldDef) toFieldDef() (*schema.FieldDef, error) {
	fd, err := newFieldDef(d.Type)
	if err != nil {
		return nil, err
	}

	if d.Required {
		fd.IsRequired = true
	}
	if d.Optional {
		fd.IsOptional = true
	}
	if d.Unique {
		fd.IsUnique = true
	}
	if d.MaxLength > 0 {
		fd.MaxLength = d.MaxLength
	}
	if d.Email {
		fd.IsEmail = true
	}
	if d.Searchable {
		fd.IsSearchable = true
	}
	if d.Filterable {
		fd.IsFilterable = true
	}
	if d.Sortable {
		fd.IsSortable = true
	}
	if d.Readonly {
		fd.IsReadonly = true
	}
	if d.Hidden {
		fd.IsHidden = true
	}
	if d.Index {
		fd.IsIndex = true
	}
	if d.From != "" {
		fd.FromSource = d.From
		fd.IsReadonly = true
	}
	if d.Default != nil {
		fd.DefaultValue = d.Default
	}
	if d.OnDelete != "" {
		fd.OnDeleteAct = schema.OnDeleteAction(strings.ToUpper(d.OnDelete))
	}
	if len(d.Values) > 0 {
		fd.EnumValues = d.Values
	}
	if d.Model != "" {
		fd.ForeignModel = d.Model
	}
	if d.Of != "" {
		fd.ChildrenOf = d.Of
	}
	if d.OrderBy != "" {
		fd.ChildOrderBy = d.OrderBy
	}

	return fd, nil
}

func newFieldDef(t string) (*schema.FieldDef, error) {
	switch t {
	case "uuid":
		return schema.UUID(), nil
	case "string":
		return schema.String(), nil
	case "text":
		return schema.Text(), nil
	case "int":
		return schema.Int(), nil
	case "float":
		return schema.Float(), nil
	case "bool":
		return schema.Bool(), nil
	case "timestamp":
		return schema.Timestamp(), nil
	case "json":
		return schema.JSON(), nil
	case "enum":
		return schema.Enum(), nil
	case "foreign", "foreignkey":
		return schema.ForeignKey(""), nil
	case "children":
		return schema.Children(""), nil
	}
	return nil, fmt.Errorf("unknown field type %q", t)
}

func (rf *ResourceFile) toOperations() schema.Operations {
	if len(rf.Ops.allowlist) > 0 {
		// Allow-list form: enable only the named operations.
		enabled := map[string]bool{}
		for _, n := range rf.Ops.allowlist {
			enabled[n] = true
		}
		flag := func(name string) *bool {
			if enabled[name] {
				return nil
			}
			disabled := false
			return &disabled
		}
		return schema.Operations{
			Get:    flag("get"),
			List:   flag("list"),
			Create: flag("create"),
			Update: flag("update"),
			Delete: flag("delete"),
		}
	}
	disableIf := func(b *bool) *bool {
		if b != nil && !*b {
			disabled := false
			return &disabled
		}
		return nil
	}
	return schema.Operations{
		Get:    disableIf(rf.Ops.Get),
		List:   disableIf(rf.Ops.List),
		Create: disableIf(rf.Ops.Create),
		Update: disableIf(rf.Ops.Update),
		Delete: disableIf(rf.Ops.Delete),
	}
}

// toPolyFKs maps polymorphic FK declarations, preserving OnDelete
// (upper-cased; validate.go guarantees membership in the 5-action set).
func (rf *ResourceFile) toPolyFKs() []schema.PolyFKDef {
	if len(rf.PolyFKs) == 0 {
		return nil
	}
	out := make([]schema.PolyFKDef, len(rf.PolyFKs))
	for i, p := range rf.PolyFKs {
		out[i] = schema.PolyFKDef{
			IDField:        p.IDField,
			TypeField:      p.TypeField,
			AllowedTargets: p.Allowed,
			OnDelete:       schema.OnDeleteAction(strings.ToUpper(p.OnDelete)),
		}
	}
	return out
}

func toSingletonConfig(v any) *schema.SingletonConfig {
	if b, ok := v.(bool); ok && b {
		return &schema.SingletonConfig{Enabled: true}
	}
	if m, ok := v.(map[string]any); ok {
		sc := &schema.SingletonConfig{Enabled: true}
		if col, _ := m["scope_column"].(string); col != "" {
			model, _ := m["scope_model"].(string)
			sc.Scope = &schema.ScopeConfig{Column: col, Model: model}
		}
		return sc
	}
	return nil
}

func buildDynamicSchema(fields schema.Fields) *schema.DynamicSchema {
	hidden := make([]string, 0)
	for name, def := range fields {
		if def.IsHidden {
			hidden = append(hidden, name)
		}
	}
	return &schema.DynamicSchema{
		Fields:       fields,
		HiddenFields: hidden,
	}
}
