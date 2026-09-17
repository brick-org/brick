package schema

// Children declares a virtual field embedding rows of a child resource.
func Children(resource string) *FieldDef {
	return &FieldDef{Type: FieldChildren, ChildrenOf: resource}
}

// OrderBy sets the column child rows are sorted to when embedded or listed.
// Only meaningful on Children fields.
func (f *FieldDef) OrderBy(col string) *FieldDef {
	f.ChildOrderBy = col
	return f
}
