package schema

import (
	"fmt"
	"strings"
)

// Validate enforces every structural rule the YAML validator used to own,
// now against the typed definition. Run it before codegen (dsl.Run does)
// so bad definitions fail fast with the resource and field named.
//
// Constructors in define.go make most of these unrepresentable (PK strategy
// args are required parameters, field types are typed constructors); the
// checks that remain are cross-references (tenant/title/unique/indexes /
// soft_delete / writable_on_update must name declared fields), enum/foreign
// /children payloads, on_delete membership, and Frappe-table gating.
func (d ResourceDef) Validate() error {
	if d.Name == "" {
		return fmt.Errorf("schema: name is required")
	}
	if d.Table == "" {
		return fmt.Errorf("schema: table is required")
	}
	if len(d.Schema.Fields) == 0 {
		return fmt.Errorf("schema: %s: fields must have at least one entry", d.Name)
	}
	// PK and parent first: they own their injected columns (validated
	// here), so the field loop below skips those columns instead of
	// blaming derived state for an authoring error.
	if err := validatePKDef(d.Name, d.Schema.PK); err != nil {
		return err
	}
	if err := validateParentRef(d.Name, d.Schema.Parent); err != nil {
		return err
	}
	skip := map[string]bool{}
	if pk := d.Schema.PK; pk != nil {
		skip[pk.Column] = true
	}
	if p := d.Schema.Parent; p != nil {
		skip[ChildParentColumn(p.Resource)] = true
	}
	for fieldName, def := range d.Schema.Fields {
		if skip[fieldName] {
			continue
		}
		if err := validateFieldDef(d.Name, fieldName, def); err != nil {
			return err
		}
	}
	if err := validatePolyFKDefs(d.Name, d.PolyFKs); err != nil {
		return err
	}
	if err := validateResourceSlots(d.Name, d.Table, d.Schema); err != nil {
		return err
	}
	return nil
}

var validFieldTypeSet = map[FieldType]bool{
	FieldUUID: true, FieldString: true, FieldText: true,
	FieldInt: true, FieldFloat: true, FieldBool: true,
	FieldTimestamp: true, FieldJSON: true, FieldEnum: true,
	FieldForeign: true, FieldChildren: true,
}

var validOnDeleteSet = map[OnDeleteAction]bool{
	Cascade: true, SetNull: true, SetDefault: true,
	Restrict: true, NoAction: true,
}

// validParentOnDelete is the subset Frappe parent links support.
var validParentOnDeleteSet = map[OnDeleteAction]bool{
	Cascade: true, SetNull: true, Restrict: true,
}

var validAutonameSet = map[AutonameStrategy]bool{
	AutonameUUID: true, AutonameSeries: true, AutonameFromField: true,
	AutonameFormat: true, AutonameHash: true, AutonamePrompt: true,
	AutonameAutoinc: true,
}

// isFrappeTable reports whether the table is Frappe-owned. Lifecycle
// behavior (soft-delete, audit, versioning) is rejected for these —
// Frappe owns that semantics via bench migrate.
func isFrappeTable(table string) bool {
	return strings.HasPrefix(table, "tab")
}

func validateFieldDef(res, fieldName string, def *FieldDef) error {
	if def == nil {
		return fmt.Errorf("schema: %s.%s: nil field definition", res, fieldName)
	}
	if !validFieldTypeSet[def.Type] {
		return fmt.Errorf("schema: %s.%s: unknown field type %q", res, fieldName, def.Type)
	}
	if def.Type == FieldEnum && len(def.EnumValues) == 0 {
		return fmt.Errorf("schema: %s.%s: enum type requires values", res, fieldName)
	}
	if def.Type == FieldForeign && def.ForeignModel == "" {
		return fmt.Errorf("schema: %s.%s: foreign type requires model", res, fieldName)
	}
	if def.Type == FieldChildren && def.ChildrenOf == "" {
		return fmt.Errorf("schema: %s.%s: children type requires of (child resource name)", res, fieldName)
	}
	if def.OnDeleteAct != "" && !validOnDeleteSet[OnDeleteAction(strings.ToUpper(string(def.OnDeleteAct)))] {
		return fmt.Errorf("schema: %s.%s: invalid on_delete %q", res, fieldName, def.OnDeleteAct)
	}
	return nil
}

func validatePKDef(res string, pk *PK) error {
	if pk == nil {
		return nil
	}
	if pk.Column == "" {
		return fmt.Errorf("schema: %s.pk: column is required", res)
	}
	if !validAutonameSet[pk.Autoname.Strategy] {
		return fmt.Errorf("schema: %s.pk: unknown strategy %q", res, pk.Autoname.Strategy)
	}
	switch pk.Autoname.Strategy {
	case AutonameSeries, AutonameFormat:
		if pk.Autoname.Template == "" {
			return fmt.Errorf("schema: %s.pk: strategy %q requires template", res, pk.Autoname.Strategy)
		}
	case AutonameFromField:
		if pk.Autoname.Source == "" {
			return fmt.Errorf("schema: %s.pk: strategy %q requires source", res, pk.Autoname.Strategy)
		}
	case AutonameHash:
		if pk.Autoname.HashLen <= 0 {
			return fmt.Errorf("schema: %s.pk: strategy %q requires length > 0", res, pk.Autoname.Strategy)
		}
	}
	return nil
}

func validateParentRef(res string, p *ParentRef) error {
	if p == nil {
		return nil
	}
	if p.Resource == "" {
		return fmt.Errorf("schema: %s.parent: resource is required", res)
	}
	if p.OnDelete != "" && !validParentOnDeleteSet[OnDeleteAction(strings.ToUpper(string(p.OnDelete)))] {
		return fmt.Errorf("schema: %s.parent: invalid on_delete %q (valid: CASCADE, SET NULL, RESTRICT)", res, p.OnDelete)
	}
	return nil
}

func validatePolyFKDefs(res string, fks []PolyFKDef) error {
	for i, p := range fks {
		where := fmt.Sprintf("schema: %s.polymorphic[%d]", res, i)
		if p.IDField == "" || p.TypeField == "" {
			return fmt.Errorf("%s: id_field and type_field are required", where)
		}
		if p.OnDelete != "" && !validOnDeleteSet[OnDeleteAction(strings.ToUpper(string(p.OnDelete)))] {
			return fmt.Errorf("%s: invalid on_delete %q", where, p.OnDelete)
		}
	}
	return nil
}

// validateResourceSlots checks the resource-level ergonomics keys:
// tenant/title membership, composite groups, lifecycle gating.
func validateResourceSlots(res, table string, s *DynamicSchema) error {
	fieldExists := func(name string) bool {
		_, ok := s.Fields[name]
		return ok
	}
	if s.TenantColumn != "" && !fieldExists(s.TenantColumn) {
		return fmt.Errorf("schema: %s: tenant %q names no declared field", res, s.TenantColumn)
	}
	if s.TitleField != "" && !fieldExists(s.TitleField) {
		return fmt.Errorf("schema: %s: title %q names no declared field", res, s.TitleField)
	}
	for i, group := range s.CompositeUniques {
		if len(group) == 0 {
			return fmt.Errorf("schema: %s: unique[%d] is empty", res, i)
		}
		for _, col := range group {
			if !fieldExists(col) {
				return fmt.Errorf("schema: %s: unique[%d] names unknown field %q", res, i, col)
			}
		}
	}
	for i, group := range s.CompositeIndexes {
		if len(group) == 0 {
			return fmt.Errorf("schema: %s: indexes[%d] is empty", res, i)
		}
		for _, col := range group {
			if !fieldExists(col) {
				return fmt.Errorf("schema: %s: indexes[%d] names unknown field %q", res, i, col)
			}
		}
	}
	if s.SoftDeleteColumn != "" {
		def, ok := s.Fields[s.SoftDeleteColumn]
		if !ok {
			return fmt.Errorf("schema: %s: soft_delete %q names no declared field", res, s.SoftDeleteColumn)
		}
		if def.Type != FieldTimestamp {
			return fmt.Errorf("schema: %s: soft_delete %q must be a timestamp field", res, s.SoftDeleteColumn)
		}
	}
	for _, col := range s.UpdateWritable {
		def, ok := s.Fields[col]
		if !ok {
			return fmt.Errorf("schema: %s: writable_on_update names unknown field %q", res, col)
		}
		if def.IsReadonly {
			return fmt.Errorf("schema: %s: writable_on_update names readonly field %q", res, col)
		}
	}
	if isFrappeTable(table) {
		if s.SoftDeleteColumn != "" {
			return fmt.Errorf("schema: %s: soft_delete is rejected for Frappe-owned table %q", res, table)
		}
		if s.Audited {
			return fmt.Errorf("schema: %s: audit is rejected for Frappe-owned table %q", res, table)
		}
		if s.Versioned {
			return fmt.Errorf("schema: %s: versioned is rejected for Frappe-owned table %q", res, table)
		}
	}
	return nil
}
