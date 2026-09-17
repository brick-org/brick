package schema

func String() *FieldDef    { return &FieldDef{Type: FieldString} }
func Text() *FieldDef      { return &FieldDef{Type: FieldText} }
func Int() *FieldDef       { return &FieldDef{Type: FieldInt} }
func Float() *FieldDef     { return &FieldDef{Type: FieldFloat} }
func Bool() *FieldDef      { return &FieldDef{Type: FieldBool} }
func Timestamp() *FieldDef { return &FieldDef{Type: FieldTimestamp} }
func UUID() *FieldDef      { return &FieldDef{Type: FieldUUID} }
func JSON() *FieldDef      { return &FieldDef{Type: FieldJSON} }

func Enum(values ...string) *FieldDef {
	return &FieldDef{Type: FieldEnum, EnumValues: values}
}

func ForeignKey(model string) *FieldDef {
	return &FieldDef{Type: FieldForeign, ForeignModel: model}
}

func (f *FieldDef) Required() *FieldDef {
	f.IsRequired = true
	f.IsOptional = false
	return f
}

func (f *FieldDef) Optional() *FieldDef {
	f.IsOptional = true
	f.IsRequired = false
	return f
}

func (f *FieldDef) Unique() *FieldDef {
	f.IsUnique = true
	return f
}

func (f *FieldDef) Default(v any) *FieldDef {
	f.DefaultValue = v
	return f
}

func (f *FieldDef) MaxLen(n int) *FieldDef {
	f.MaxLength = n
	return f
}

func (f *FieldDef) Email() *FieldDef {
	f.IsEmail = true
	return f
}

func (f *FieldDef) Searchable() *FieldDef {
	f.IsSearchable = true
	return f
}

func (f *FieldDef) Filterable() *FieldDef {
	f.IsFilterable = true
	return f
}

func (f *FieldDef) Sortable() *FieldDef {
	f.IsSortable = true
	return f
}

func (f *FieldDef) Hidden() *FieldDef {
	f.IsHidden = true
	return f
}

func (f *FieldDef) Readonly() *FieldDef {
	f.IsReadonly = true
	return f
}

func (f *FieldDef) Index() *FieldDef {
	f.IsIndex = true
	return f
}

func (f *FieldDef) OnDelete(action OnDeleteAction) *FieldDef {
	f.OnDeleteAct = action
	return f
}

// From declares that the field value is resolved from the request context at create time.
// The path is a dot-separated path into BrickCtx, e.g. "session.userId".
// Fields with From are implicitly readonly — they cannot be set by the client.
func (f *FieldDef) From(path string) *FieldDef {
	f.FromSource = path
	f.IsReadonly = true
	return f
}

// Computed marks a response-only derived field. It is excluded from
// create/update bodies; evaluation is app-side (M5 hook).
func (f *FieldDef) Computed() *FieldDef {
	f.IsComputed = true
	f.IsReadonly = true
	return f
}

// Normalize records a normalization rule applied before validation
// (e.g. "email"). Rules are app-defined; M5 validation dispatches on
// the name.
func (f *FieldDef) Normalize(rule string) *FieldDef {
	f.NormalizeWith = rule
	return f
}
