package schema

import "maps"

// ChildParentColumn returns the FK column name on child tables linking to
// the parent row's primary key. It follows the pattern "{parent}_id", e.g.
// for a child of "deal" the column is "deal_id".
func ChildParentColumn(parentRes string) string {
	return parentRes + "_id"
}

// ParentRef declares that a resource is owned by a parent resource — its
// rows are embedded in the parent's API shape and written through the
// parent's create/update endpoints.
type ParentRef struct {
	Resource string         `json:"resource"`
	OnDelete OnDeleteAction `json:"onDelete,omitempty"`
}

// ApplyParent marks the schema as parent-owned and injects the parent FK
// column into Fields (copied before mutation) so it flows through codegen,
// migrations, and list filters.
func (ds *DynamicSchema) ApplyParent(p *ParentRef) {
	ds.Parent = p
	col := ChildParentColumn(p.Resource)
	if _, ok := ds.Fields[col]; ok {
		return
	}
	fields := make(Fields, len(ds.Fields)+1)
	maps.Copy(fields, ds.Fields)
	fields[col] = &FieldDef{
		Type:         FieldForeign,
		ForeignModel: p.Resource,
		IsRequired:   true,
		IsFilterable: true,
		OnDeleteAct:  p.OnDelete,
	}
	ds.Fields = fields
}
