package codegen

import (
	"fmt"
	"strings"

	"github.com/brick-org/brick/schema"
)

// ─── CRUD file ────────────────────────────────────────────────────────────

func emitCRUD(b *strings.Builder, r ResourceDef, byName map[string]ResourceDef) {
	goName := schema.Title(r.Name)
	s := r.Schema
	ops := r.Operations

	// --- Response ---
	b.WriteString(fmt.Sprintf("// %sResponse is the API response for %s.\n", goName, r.Table))
	b.WriteString(fmt.Sprintf("type %sResponse struct {\n", goName))
	for _, field := range schema.SortedFields(s.Fields, pkColumn(r)) {
		if isHidden(field, s.HiddenFields) {
			continue
		}
		def := s.Fields[field]
		if def.Type == schema.FieldChildren {
			b.WriteString(fmt.Sprintf("\t%s []%s `%s`\n", schema.GoFieldName(field), childTypeRef(def, byName, "Response"), jsonTagOptional(field)))
			continue
		}
		b.WriteString(fmt.Sprintf("\t%s %s", schema.GoFieldName(field), schema.GoTypeFor(field, def, pkDef(r))))
		if jt := jsonTag(field, def, pkColumn(r)); jt != "" {
			b.WriteString(fmt.Sprintf(" `%s`", jt))
		}
		b.WriteString("\n")
	}
	b.WriteString("}\n\n")

	// --- ChildInput (resources that are parent-owned) ---
	if s.Parent != nil {
		emitChildInput(b, goName, r)
	}

	// --- Create body ---
	if ops.Create == nil || *ops.Create {
		emitCreateBody(b, goName, r, byName)
	}

	// --- Update body ---
	if ops.Update == nil || *ops.Update {
		emitUpdateBody(b, goName, r, byName)
	}

	// --- ListInput + ToListOptions ---
	if ops.List == nil || *ops.List {
		emitListInput(b, goName, r)
	}

	// --- Type aliases ---
	createType := fmt.Sprintf("%sCreateBody", goName)
	if ops.Create != nil && !*ops.Create {
		createType = "struct{}"
	}
	updateType := fmt.Sprintf("%sUpdateBody", goName)
	if ops.Update != nil && !*ops.Update {
		updateType = "struct{}"
	}
	listType := fmt.Sprintf("%sListInput", goName)
	if ops.List != nil && !*ops.List {
		listType = "struct{}"
	}

	b.WriteString(fmt.Sprintf("// %sSchema is the typed schema for %s.\n", goName, r.Name))
	b.WriteString(fmt.Sprintf("type %sSchema = brick.Schema[%sRow, %sResponse, %s, %s, %s]\n\n",
		goName, goName, goName, createType, updateType, listType))
	b.WriteString(fmt.Sprintf("// %sAccess is the typed access control for %s.\n", goName, r.Name))
	b.WriteString(fmt.Sprintf("type %sAccess = brick.Access\n\n", goName))
	b.WriteString(fmt.Sprintf("// %sHooks is the typed hooks for %s.\n", goName, r.Name))
	b.WriteString(fmt.Sprintf("type %sHooks = brick.Hooks[map[string]any, map[string]any]\n\n", goName))

	// --- SchemaFields var ---
	emitSchemaFields(b, goName, r)

	// --- PK var ---
	if pk := pkDef(r); pk != nil {
		emitPKVar(b, goName, r, pk)
	}

	// --- Parent var ---
	if s.Parent != nil {
		emitParentVar(b, goName, r, s.Parent)
	}

	// --- Singleton var ---
	if s.Singleton != nil {
		emitSingletonVar(b, goName, r, s.Singleton)
	}
}

// emitSingletonVar writes the generated *schema.SingletonConfig so
// resources.go can wire the DSL-declared singleton: Schema{..., Singleton: XxxSingleton}.
func emitSingletonVar(b *strings.Builder, goName string, r ResourceDef, sg *schema.SingletonConfig) {
	if sg.Scope != nil {
		b.WriteString(fmt.Sprintf("// %sSingleton is the generated singleton config for %s.\n", goName, r.Name))
		b.WriteString(fmt.Sprintf("var %sSingleton = &schema.SingletonConfig{Enabled: true, Scope: &schema.ScopeConfig{Column: %q, Model: %q}}\n\n",
			goName, sg.Scope.Column, sg.Scope.Model))
	} else {
		b.WriteString(fmt.Sprintf("// %sSingleton is the generated singleton config for %s.\n", goName, r.Name))
		b.WriteString(fmt.Sprintf("var %sSingleton = &schema.SingletonConfig{Enabled: true}\n\n", goName))
	}
}

// emitParentVar writes the generated *schema.ParentRef so resources.go can
// reference the DSL-declared parent: Schema{..., Parent: XxxParent}.
func emitParentVar(b *strings.Builder, goName string, r ResourceDef, p *schema.ParentRef) {
	onDeleteConst := map[schema.OnDeleteAction]string{
		schema.Cascade:    "Cascade",
		schema.SetNull:    "SetNull",
		schema.SetDefault: "SetDefault",
		schema.Restrict:   "Restrict",
		schema.NoAction:   "NoAction",
	}[p.OnDelete]

	b.WriteString(fmt.Sprintf("// %sParent is the generated parent ownership config for %s.\n", goName, r.Name))
	b.WriteString(fmt.Sprintf("var %sParent = &schema.ParentRef{Resource: %q", goName, p.Resource))
	if onDeleteConst != "" {
		b.WriteString(fmt.Sprintf(", OnDelete: schema.%s", onDeleteConst))
	}
	b.WriteString("}\n\n")
}

// emitPKVar writes the generated *schema.PK so resources.go can reference
// the DSL-declared PK without re-typing it: Schema{..., PK: XxxPK}.
func emitPKVar(b *strings.Builder, goName string, r ResourceDef, pk *schema.PK) {
	strategyConst := map[schema.AutonameStrategy]string{
		schema.AutonameUUID:      "AutonameUUID",
		schema.AutonameSeries:    "AutonameSeries",
		schema.AutonameFromField: "AutonameFromField",
		schema.AutonameFormat:    "AutonameFormat",
		schema.AutonameHash:      "AutonameHash",
		schema.AutonamePrompt:    "AutonamePrompt",
		schema.AutonameAutoinc:   "AutonameAutoinc",
	}[pk.Autoname.Strategy]
	typeConst := map[schema.FieldType]string{
		schema.FieldString: "FieldString",
		schema.FieldUUID:   "FieldUUID",
		schema.FieldInt:    "FieldInt",
	}[pk.Type]

	b.WriteString(fmt.Sprintf("// %sPK is the generated primary key config for %s.\n", goName, r.Name))
	b.WriteString(fmt.Sprintf("var %sPK = &schema.PK{Column: %q, Type: schema.%s, Autoname: schema.Autoname{Strategy: schema.%s", goName, pk.Column, typeConst, strategyConst))
	if pk.Autoname.Template != "" {
		b.WriteString(fmt.Sprintf(", Template: %q", pk.Autoname.Template))
	}
	if pk.Autoname.Source != "" {
		b.WriteString(fmt.Sprintf(", Source: %q", pk.Autoname.Source))
	}
	if pk.Autoname.HashLen > 0 {
		b.WriteString(fmt.Sprintf(", HashLen: %d", pk.Autoname.HashLen))
	}
	b.WriteString("}}\n\n")
}

func emitCreateBody(b *strings.Builder, goName string, r ResourceDef, byName map[string]ResourceDef) {
	b.WriteString(fmt.Sprintf("// %sCreateBody is the input for creating a %s.\n", goName, r.Table))
	b.WriteString(fmt.Sprintf("type %sCreateBody struct {\n", goName))
	for _, field := range schema.SortedFields(r.Schema.Fields, pkColumn(r)) {
		if isHidden(field, r.Schema.HiddenFields) || isReadonly(r.Schema.Fields[field]) || isAuto(field, autoPKColumn(r)) {
			continue
		}
		def := r.Schema.Fields[field]
		if def.Type == schema.FieldChildren {
			b.WriteString(fmt.Sprintf("\t%s []%s `%s`\n", schema.GoFieldName(field), childTypeRef(def, byName, "ChildInput"), jsonTagOptional(field)))
			continue
		}
		b.WriteString(fmt.Sprintf("\t%s %s", schema.GoFieldName(field), schema.GoType(def)))
		if jt := jsonTag(field, def, pkColumn(r)); jt != "" {
			b.WriteString(fmt.Sprintf(" `%s`", jt))
		}
		b.WriteString("\n")
	}
	b.WriteString("}\n\n")
}

// emitChildInput writes the nested write shape for a parent-owned resource:
// the create fields plus an optional PK for replace-set matching, minus the
// parent FK column (the runtime sets it from the parent row).
func emitChildInput(b *strings.Builder, goName string, r ResourceDef) {
	b.WriteString(fmt.Sprintf("// %sChildInput is the nested write shape for %s rows embedded in a parent.\n", goName, r.Table))
	b.WriteString(fmt.Sprintf("type %sChildInput struct {\n", goName))
	pkCol := pkColumn(r)
	b.WriteString(fmt.Sprintf("\t%s string `%s`\n", schema.GoFieldName(pkCol), jsonTagOptional(pkCol)))
	var parentCol string
	if r.Schema != nil && r.Schema.Parent != nil {
		parentCol = schema.ChildParentColumn(r.Schema.Parent.Resource)
	}
	for _, field := range schema.SortedFields(r.Schema.Fields, pkCol) {
		if field == pkCol || (parentCol != "" && field == parentCol) {
			continue
		}
		def := r.Schema.Fields[field]
		if isHidden(field, r.Schema.HiddenFields) || isReadonly(def) || isAuto(field, autoPKColumn(r)) || def.Type == schema.FieldChildren {
			continue
		}
		b.WriteString(fmt.Sprintf("\t%s %s `%s`\n", schema.GoFieldName(field), schema.GoType(def), jsonTagOptional(field)))
	}
	b.WriteString("}\n\n")
}

func emitUpdateBody(b *strings.Builder, goName string, r ResourceDef, byName map[string]ResourceDef) {
	b.WriteString(fmt.Sprintf("// %sUpdateBody is the input for updating a %s.\n", goName, r.Table))
	b.WriteString(fmt.Sprintf("type %sUpdateBody struct {\n", goName))
	for _, field := range schema.SortedFields(r.Schema.Fields, pkColumn(r)) {
		// The PK is never updatable, even with the prompt strategy.
		if field == pkColumn(r) {
			continue
		}
		if isHidden(field, r.Schema.HiddenFields) || isReadonly(r.Schema.Fields[field]) || isAuto(field, autoPKColumn(r)) {
			continue
		}
		if def := r.Schema.Fields[field]; def.Type == schema.FieldChildren {
			b.WriteString(fmt.Sprintf("\t%s []%s `%s`\n", schema.GoFieldName(field), childTypeRef(def, byName, "ChildInput"), jsonTagOptional(field)))
			continue
		}
		b.WriteString(fmt.Sprintf("\t%s *%s", schema.GoFieldName(field), schema.GoType(r.Schema.Fields[field])))
		if jt := jsonTagOptional(field); jt != "" {
			b.WriteString(fmt.Sprintf(" `%s`", jt))
		}
		b.WriteString("\n")
	}
	b.WriteString("}\n\n")
}

func emitListInput(b *strings.Builder, goName string, r ResourceDef) {
	s := r.Schema

	b.WriteString(fmt.Sprintf("type %sListInput struct {\n", goName))
	b.WriteString("\tPage   int    `query:\"page\"`\n")
	b.WriteString("\tLimit  int    `query:\"limit\"`\n")
	b.WriteString("\tSort   string `query:\"sort\"`\n")
	b.WriteString("\tSearch string `query:\"search\"`\n")
	for _, field := range schema.SortedFields(s.Fields, pkColumn(r)) {
		if isHidden(field, s.HiddenFields) || s.Fields[field].Type == schema.FieldChildren {
			continue
		}
		def := s.Fields[field]
		b.WriteString(fmt.Sprintf("\t%s %s `query:\"%s\"`\n", schema.ListInputFieldName(field), listInputGoType(field, def, pkDef(r)), field))
	}
	b.WriteString("}\n\n")

	b.WriteString(fmt.Sprintf("func (in *%sListInput) ToListOptions() db.ListOptions {\n", goName))
	b.WriteString("\topts := db.ListOptions{\n")
	b.WriteString("\t\tPage:   in.Page,\n\t\tLimit:  in.Limit,\n\t\tSort:   in.Sort,\n\t\tSearch: in.Search,\n\t}\n")
	for _, field := range schema.SortedFields(s.Fields, pkColumn(r)) {
		if isHidden(field, s.HiddenFields) || s.Fields[field].Type == schema.FieldChildren {
			continue
		}
		def := s.Fields[field]
		gfn := schema.ListInputFieldName(field)
		switch def.Type {
		case schema.FieldJSON:
			b.WriteString(fmt.Sprintf("\tif in.%s != nil {\n\t\topts.Filter = append(opts.Filter, db.Where{Field: \"%s\", Value: *in.%s, Operator: db.OpEq})\n\t}\n", gfn, field, gfn))
		case schema.FieldBool:
			b.WriteString(fmt.Sprintf("\tif in.%s != nil {\n\t\topts.Filter = append(opts.Filter, db.Where{Field: \"%s\", Value: *in.%s, Operator: db.OpEq})\n\t}\n", gfn, field, gfn))
		case schema.FieldTimestamp:
			b.WriteString(fmt.Sprintf("\tif !in.%s.IsZero() {\n\t\topts.Filter = append(opts.Filter, db.Where{Field: \"%s\", Value: in.%s, Operator: db.OpEq})\n\t}\n", gfn, field, gfn))
		case schema.FieldInt, schema.FieldFloat:
			b.WriteString(fmt.Sprintf("\tif in.%s != nil {\n\t\topts.Filter = append(opts.Filter, db.Where{Field: \"%s\", Value: *in.%s, Operator: db.OpEq})\n\t}\n", gfn, field, gfn))
		default:
			b.WriteString(fmt.Sprintf("\tif in.%s != \"\" {\n\t\topts.Filter = append(opts.Filter, db.Where{Field: \"%s\", Value: in.%s, Operator: db.OpEq})\n\t}\n", gfn, field, gfn))
		}
	}
	b.WriteString("\treturn opts\n")
	b.WriteString("}\n\n")
}

// listInputGoType is the ListInput field type. Scalar bool/int/float/json
// filters are pointers so zero values (false, 0) stay filterable —
// presence is nil, not the zero value. Strings and timestamps keep their
// existing guards ("" / IsZero).
func listInputGoType(field string, def *schema.FieldDef, pk *schema.PK) string {
	switch def.Type {
	case schema.FieldBool:
		return "*bool"
	case schema.FieldInt:
		if pk != nil && field == pk.Column && pk.Autoname.Strategy == schema.AutonameAutoinc {
			return "*int64"
		}
		return "*int32"
	case schema.FieldFloat:
		return "*float64"
	case schema.FieldJSON:
		return "*json.RawMessage"
	}
	return schema.GoTypeFor(field, def, pk)
}

// emitSchemaFields writes a var that constructs the schema.Fields builder
// chain so callers can embed it into a typed Schema literal without
// duplicating the field definitions.
func emitSchemaFields(b *strings.Builder, goName string, r ResourceDef) {
	b.WriteString(fmt.Sprintf("// %sSchemaFields is the generated schema.Fields for %s.\n", goName, r.Name))
	b.WriteString(fmt.Sprintf("// Use with a typed Schema literal: %sSchema{Fields: %sSchemaFields, ...}\n", goName, goName))
	b.WriteString(fmt.Sprintf("var %sSchemaFields = schema.Fields{\n", goName))
	for _, field := range schema.SortedFields(r.Schema.Fields, pkColumn(r)) {
		def := r.Schema.Fields[field]
		b.WriteString("\t")
		b.WriteString(fmt.Sprintf("%q: ", field))
		b.WriteString(fieldToBuilderExpr(def))
		b.WriteString(",\n")
	}
	b.WriteString("}\n\n")
}

func fieldToBuilderExpr(def *schema.FieldDef) string {
	var w strings.Builder

	switch def.Type {
	case schema.FieldUUID:
		w.WriteString("schema.UUID()")
	case schema.FieldString:
		if len(def.EnumValues) > 0 {
			w.WriteString(fmt.Sprintf("schema.Enum(%s)", quoteSlice(def.EnumValues)))
		} else {
			w.WriteString("schema.String()")
		}
	case schema.FieldText:
		w.WriteString("schema.Text()")
	case schema.FieldInt:
		w.WriteString("schema.Int()")
	case schema.FieldFloat:
		w.WriteString("schema.Float()")
	case schema.FieldBool:
		w.WriteString("schema.Bool()")
	case schema.FieldTimestamp:
		w.WriteString("schema.Timestamp()")
	case schema.FieldJSON:
		w.WriteString("schema.JSON()")
	case schema.FieldEnum:
		w.WriteString(fmt.Sprintf("schema.Enum(%s)", quoteSlice(def.EnumValues)))
	case schema.FieldForeign:
		w.WriteString(fmt.Sprintf("schema.ForeignKey(%q)", def.ForeignModel))
	case schema.FieldChildren:
		w.WriteString(fmt.Sprintf("schema.Children(%q)", def.ChildrenOf))
		if def.ChildOrderBy != "" {
			w.WriteString(fmt.Sprintf(".OrderBy(%q)", def.ChildOrderBy))
		}
	}

	if def.IsRequired {
		w.WriteString(".Required()")
	}
	if def.IsOptional {
		w.WriteString(".Optional()")
	}
	if def.IsUnique {
		w.WriteString(".Unique()")
	}
	if def.IsReadonly {
		w.WriteString(".Readonly()")
	}
	if def.IsHidden {
		w.WriteString(".Hidden()")
	}
	if def.IsSearchable {
		w.WriteString(".Searchable()")
	}
	if def.IsFilterable {
		w.WriteString(".Filterable()")
	}
	if def.IsSortable {
		w.WriteString(".Sortable()")
	}
	if def.IsIndex {
		w.WriteString(".Index()")
	}
	if def.IsEmail {
		w.WriteString(".Email()")
	}
	if def.MaxLength > 0 {
		w.WriteString(fmt.Sprintf(".MaxLen(%d)", def.MaxLength))
	}
	if def.FromSource != "" {
		w.WriteString(fmt.Sprintf(".From(%q)", def.FromSource))
	}
	if def.DefaultValue != nil {
		w.WriteString(fmt.Sprintf(".Default(%s)", formatDefaultCode(def)))
	}
	if def.OnDeleteAct != "" {
		onDeleteGo := map[schema.OnDeleteAction]string{
			schema.Cascade:    "Cascade",
			schema.SetNull:    "SetNull",
			schema.SetDefault: "SetDefault",
			schema.Restrict:   "Restrict",
			schema.NoAction:   "NoAction",
		}[def.OnDeleteAct]
		if onDeleteGo == "" {
			onDeleteGo = string(def.OnDeleteAct)
		}
		w.WriteString(fmt.Sprintf(".OnDelete(schema.%s)", onDeleteGo))
	}
	if def.IsComputed {
		w.WriteString(".Computed()")
	}
	if def.NormalizeWith != "" {
		w.WriteString(fmt.Sprintf(".Normalize(%q)", def.NormalizeWith))
	}

	return w.String()
}

func formatDefaultCode(def *schema.FieldDef) string {
	switch v := def.DefaultValue.(type) {
	case string:
		if def.Type == schema.FieldEnum || def.Type == schema.FieldString || def.Type == schema.FieldText {
			return fmt.Sprintf("%q", v)
		}
		return fmt.Sprintf("%q", v)
	case bool:
		if v {
			return "true"
		}
		return "false"
	case float64:
		return fmt.Sprintf("%v", v)
	case nil:
		return "nil"
	default:
		return fmt.Sprintf("%v", def.DefaultValue)
	}
}

func quoteSlice(vals []string) string {
	quoted := make([]string, len(vals))
	for i, v := range vals {
		quoted[i] = fmt.Sprintf("%q", v)
	}
	return strings.Join(quoted, ", ")
}
