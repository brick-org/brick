package dsl

import (
	"fmt"
	"strings"
)

// validFieldTypes is the set of legal field type values. The legacy alias
// "foreignkey" is accepted and normalized to "foreign" at convert time.
// There is deliberately no "fk".
var validFieldTypes = map[string]bool{
	"uuid": true, "string": true, "text": true,
	"int": true, "float": true, "bool": true,
	"timestamp": true, "json": true, "enum": true,
	"foreign": true, "foreignkey": true, "children": true,
}

var validOnDelete = map[string]bool{
	"CASCADE": true, "SET NULL": true, "SET DEFAULT": true,
	"RESTRICT": true, "NO ACTION": true,
}

// parentOnDelete is the subset Frappe parent links support.
var validParentOnDelete = map[string]bool{
	"CASCADE": true, "SET NULL": true, "RESTRICT": true,
}

var validStrategies = map[string]bool{
	"uuid": true, "naming_series": true, "field": true,
	"format": true, "hash": true, "prompt": true, "autoincrement": true,
}

// isFrappeTable reports whether the table is Frappe-owned. Lifecycle
// behavior (soft-delete, audit, versioning) is rejected for these —
// Frappe owns that semantics via bench migrate.
func isFrappeTable(table string) bool {
	return strings.HasPrefix(table, "tab")
}

// validate enforces every structural rule. convert.go trusts validated
// input (ToResourceDef re-runs validate defensively). Every error names
// the resource and, where applicable, the field.
func validate(rf *ResourceFile) error {
	if rf.Name == "" {
		return fmt.Errorf("dsl: name is required")
	}
	if rf.Table == "" {
		return fmt.Errorf("dsl: table is required")
	}
	if len(rf.Fields) == 0 {
		return fmt.Errorf("dsl: fields must have at least one entry")
	}
	for fieldName, def := range rf.Fields {
		if err := validateField(rf.Name, fieldName, def); err != nil {
			return err
		}
	}
	if err := validatePK(rf); err != nil {
		return err
	}
	if err := validateParent(rf); err != nil {
		return err
	}
	if err := validatePolyFKs(rf); err != nil {
		return err
	}
	if err := validateResourceKeys(rf); err != nil {
		return err
	}
	return nil
}

func validateField(res, fieldName string, def *FieldDef) error {
	if !validFieldTypes[def.Type] {
		return fmt.Errorf("dsl: %s.%s: unknown field type %q (valid: uuid, string, text, int, float, bool, timestamp, json, enum, foreign, children)", res, fieldName, def.Type)
	}
	if def.Type == "enum" && len(def.Values) == 0 {
		return fmt.Errorf("dsl: %s.%s: enum type requires values", res, fieldName)
	}
	if def.Type == "foreign" && def.Model == "" {
		return fmt.Errorf("dsl: %s.%s: foreign type requires model", res, fieldName)
	}
	if def.Type == "children" && def.Of == "" {
		return fmt.Errorf("dsl: %s.%s: children type requires of (child resource name)", res, fieldName)
	}
	if def.OnDelete != "" && !validOnDelete[strings.ToUpper(def.OnDelete)] {
		return fmt.Errorf("dsl: %s.%s: invalid on_delete %q (valid: CASCADE, SET NULL, SET DEFAULT, RESTRICT, NO ACTION)", res, fieldName, def.OnDelete)
	}
	return nil
}

func validatePK(rf *ResourceFile) error {
	p := rf.PK
	if p == nil {
		return nil
	}
	if p.Column == "" {
		return fmt.Errorf("dsl: %s.pk: column is required", rf.Name)
	}
	if !validStrategies[p.Strategy] {
		return fmt.Errorf("dsl: %s.pk: unknown strategy %q (valid: uuid, naming_series, field, format, hash, prompt, autoincrement)", rf.Name, p.Strategy)
	}
	switch p.Strategy {
	case "naming_series", "format":
		if p.Template == "" {
			return fmt.Errorf("dsl: %s.pk: strategy %q requires template", rf.Name, p.Strategy)
		}
	case "field":
		if p.Source == "" {
			return fmt.Errorf("dsl: %s.pk: strategy %q requires source", rf.Name, p.Strategy)
		}
	case "hash":
		if p.Length <= 0 {
			return fmt.Errorf("dsl: %s.pk: strategy %q requires length > 0", rf.Name, p.Strategy)
		}
	}
	return nil
}

func validateParent(rf *ResourceFile) error {
	p := rf.Parent
	if p == nil {
		return nil
	}
	if p.Resource == "" {
		return fmt.Errorf("dsl: %s.parent: resource is required", rf.Name)
	}
	if p.OnDelete != "" && !validParentOnDelete[strings.ToUpper(p.OnDelete)] {
		return fmt.Errorf("dsl: %s.parent: invalid on_delete %q (valid: CASCADE, SET NULL, RESTRICT)", rf.Name, p.OnDelete)
	}
	return nil
}

func validatePolyFKs(rf *ResourceFile) error {
	for i, p := range rf.PolyFKs {
		where := fmt.Sprintf("dsl: %s.polymorphic[%d]", rf.Name, i)
		if p.IDField == "" || p.TypeField == "" {
			return fmt.Errorf("%s: id_field and type_field are required", where)
		}
		if p.OnDelete != "" && !validOnDelete[strings.ToUpper(p.OnDelete)] {
			return fmt.Errorf("%s: invalid on_delete %q (valid: CASCADE, SET NULL, SET DEFAULT, RESTRICT, NO ACTION)", where, p.OnDelete)
		}
	}
	return nil
}

// validateResourceKeys checks the resource-level ergonomics keys:
// tenant/title membership, composite groups, lifecycle gating.
func validateResourceKeys(rf *ResourceFile) error {
	fieldExists := func(name string) bool {
		_, ok := rf.Fields[name]
		return ok
	}
	if rf.Tenant != "" && !fieldExists(rf.Tenant) {
		return fmt.Errorf("dsl: %s: tenant %q names no declared field", rf.Name, rf.Tenant)
	}
	if rf.Title != "" && !fieldExists(rf.Title) {
		return fmt.Errorf("dsl: %s: title %q names no declared field", rf.Name, rf.Title)
	}
	for i, group := range rf.Uniques {
		if len(group) == 0 {
			return fmt.Errorf("dsl: %s: unique[%d] is empty", rf.Name, i)
		}
		for _, col := range group {
			if !fieldExists(col) {
				return fmt.Errorf("dsl: %s: unique[%d] names unknown field %q", rf.Name, i, col)
			}
		}
	}
	for i, group := range rf.Indexes {
		if len(group) == 0 {
			return fmt.Errorf("dsl: %s: indexes[%d] is empty", rf.Name, i)
		}
		for _, col := range group {
			if !fieldExists(col) {
				return fmt.Errorf("dsl: %s: indexes[%d] names unknown field %q", rf.Name, i, col)
			}
		}
	}
	if rf.SoftDelete != "" {
		def, ok := rf.Fields[rf.SoftDelete]
		if !ok {
			return fmt.Errorf("dsl: %s: soft_delete %q names no declared field", rf.Name, rf.SoftDelete)
		}
		if def.Type != "timestamp" {
			return fmt.Errorf("dsl: %s: soft_delete %q must be a timestamp field", rf.Name, rf.SoftDelete)
		}
	}
	for _, col := range rf.WritableOnUpdate {
		def, ok := rf.Fields[col]
		if !ok {
			return fmt.Errorf("dsl: %s: writable_on_update names unknown field %q", rf.Name, col)
		}
		if def.Readonly {
			return fmt.Errorf("dsl: %s: writable_on_update names readonly field %q", rf.Name, col)
		}
	}
	if isFrappeTable(rf.Table) {
		if rf.SoftDelete != "" {
			return fmt.Errorf("dsl: %s: soft_delete is rejected for Frappe-owned table %q", rf.Name, rf.Table)
		}
		if rf.Audited {
			return fmt.Errorf("dsl: %s: audit is rejected for Frappe-owned table %q", rf.Name, rf.Table)
		}
		if rf.Versioned {
			return fmt.Errorf("dsl: %s: versioned is rejected for Frappe-owned table %q", rf.Name, rf.Table)
		}
	}
	return nil
}
