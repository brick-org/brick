package codegen_test

import (
	"github.com/brick-org/brick/dsl/codegen"
	"github.com/brick-org/brick/dsl/schema"
)

// testResourceDefs mirrors the pre-Go-DSL YAML fixtures
// (fields_layout, page, view_setting) 1:1 in typed Go. The golden files
// pin the emitter output, so any drift between the old YAML conversion
// and schema.Define fails loudly here.
func testResourceDefs() []codegen.ResourceDef {
	return []codegen.ResourceDef{
		schema.Define("fields_layout", "tabCRM Fields Layout", schema.Fields{
			"creation":    schema.Timestamp().Readonly(),
			"modified":    schema.Timestamp().Readonly(),
			"modified_by": schema.String().Readonly(),
			"owner":       schema.String().Readonly(),
			"docstatus":   schema.Int().Default(0).Readonly(),
			"idx":         schema.Int().Default(0).Readonly(),
			"dt":          schema.String().Required().Filterable(),
			"type":        schema.Enum("Quick Entry", "Side Panel", "Data Fields", "Grid Row", "Required Fields").Required().Filterable(),
			"team":        schema.String().Filterable(),
			"layout":      schema.Text(),
		},
			schema.WithPK(schema.HashPK("name", 10)),
			schema.WithOperations(schema.DisableOps("create", "update", "delete")),
		),
		schema.Define("page", "pages", schema.Fields{
			"id":           schema.UUID().Readonly(),
			"slug":         schema.String().Required().Unique().Searchable(),
			"title":        schema.String().Required().Searchable(),
			"content":      schema.Text().Required(),
			"content_type": schema.Enum("html", "markdown").Default("markdown").Filterable(),
			"is_public":    schema.Bool().Default(false).Filterable(),
			"theme":        schema.Enum("github-dark", "github-light", "dracula", "nord").Default("github-dark"),
			"user_id":      schema.String().From("session.userId"),
			"created_at":   schema.Timestamp().Readonly(),
			"updated_at":   schema.Timestamp().Readonly(),
		}),
		schema.Define("view_setting", "tabCRM View Settings", schema.Fields{
			"creation":             schema.Timestamp().Readonly(),
			"modified":             schema.Timestamp().Readonly(),
			"modified_by":          schema.String().Readonly(),
			"owner":                schema.String().Readonly(),
			"docstatus":            schema.Int().Default(0).Readonly(),
			"idx":                  schema.Int().Default(0).Readonly(),
			"team":                 schema.String().Required().Filterable(),
			"label":                schema.String().Required().Filterable(),
			"icon":                 schema.String(),
			"user":                 schema.String().Filterable(),
			"is_standard":          schema.Int().Default(0).Filterable(),
			"is_default":           schema.Int().Default(0).Filterable(),
			"type":                 schema.Enum("list", "group_by", "kanban").Default("list").Filterable(),
			"dt":                   schema.String().Required().Filterable(),
			"route_name":           schema.String(),
			"pinned":               schema.Int().Default(0).Filterable(),
			"public":               schema.Int().Default(0).Filterable(),
			"filters":              schema.Text(),
			"order_by":             schema.Text(),
			"group_by_field":       schema.String(),
			"column_field":         schema.String(),
			"title_field":          schema.String(),
			"load_default_columns": schema.Int().Default(0),
			"columns":              schema.Text(),
			"rows":                 schema.Text(),
			"kanban_columns":       schema.Text(),
			"kanban_fields":        schema.Text(),
		}, schema.WithPK(schema.AutoincPK("name"))),
	}
}
