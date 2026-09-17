package codegen

import (
	"fmt"
	"strings"

	"github.com/brick-org/brick/dsl/schema"
)

// ─── DB file ──────────────────────────────────────────────────────────────

func emitRow(b *strings.Builder, r ResourceDef) {
	goName := schema.Title(r.Name)
	s := r.Schema

	b.WriteString(fmt.Sprintf("// %sRow is the bun model for %s.\n", goName, r.Table))
	b.WriteString(fmt.Sprintf("type %sRow struct {\n", goName))
	b.WriteString(fmt.Sprintf("\tbun.BaseModel `bun:\"table:%s\"`\n", r.Table))
	for _, field := range schema.SortedFields(s.Fields, pkColumn(r)) {
		def := s.Fields[field]
		if def.Type == schema.FieldChildren {
			continue // virtual — no column
		}
		b.WriteString(fmt.Sprintf("\t%s %s", schema.GoFieldName(field), schema.GoTypeFor(field, def, pkDef(r))))
		bt := bunTag(field, def, pkDef(r))
		jt := jsonTag(field, def, pkColumn(r))
		if bt != "" || jt != "" {
			b.WriteString(fmt.Sprintf(" `%s %s`", bt, jt))
		}
		b.WriteString("\n")
	}
	b.WriteString("}\n\n")

	if _, ok := s.Fields["owner_id"]; ok {
		fn := schema.GoFieldName("owner_id")
		b.WriteString(fmt.Sprintf("func (r %sRow) GetOwnerID() string { return r.%s }\n\n", goName, fn))
	}
}

func emitNamingCounterRow(b *strings.Builder) {
	b.WriteString("// NamingSeriesCounterRow backs race-safe NamingSeries/AutonameFormat counters.\n")
	b.WriteString("type NamingSeriesCounterRow struct {\n")
	b.WriteString("\tbun.BaseModel `bun:\"table:naming_series_counter\"`\n")
	b.WriteString("\tKey   string `bun:\"key,pk\" json:\"key\"`\n")
	b.WriteString("\tValue int64  `bun:\"value,notnull\" json:\"value\"`\n")
	b.WriteString("}\n\n")
}

// needsNamingCounter reports whether any resource uses a counter-backed
// autoname strategy, requiring the naming_series_counter table.
func needsNamingCounter(resources []ResourceDef) bool {
	for _, r := range resources {
		if pk := pkDef(r); pk != nil {
			if pk.Autoname.Strategy == schema.AutonameSeries || pk.Autoname.Strategy == schema.AutonameFormat {
				return true
			}
		}
	}
	return false
}

func writeBusinessIndexes(b *strings.Builder, resources []ResourceDef) {
	b.WriteString("// BusinessIndexes creates composite indexes that can't be expressed\n")
	b.WriteString("// as bun struct tags. Safe to call repeatedly — uses IfNotExists.\n")
	b.WriteString("func BusinessIndexes(ctx context.Context, bunDB *bun.DB) error {\n")
	for _, r := range resources {
		for _, pf := range r.PolyFKs {
			idxName := fmt.Sprintf("%s_%s_%s_idx", r.Table, pf.TypeField, pf.IDField)
			b.WriteString(fmt.Sprintf(
				"\tif _, err := bunDB.NewCreateIndex().IfNotExists().Index(%q).Table(%q).Column(%q, %q).Exec(ctx); err != nil {\n",
				idxName, r.Table, pf.TypeField, pf.IDField,
			))
			b.WriteString("\t\treturn err\n")
			b.WriteString("\t}\n")
		}
		for _, group := range r.Schema.CompositeUniques {
			idxName := fmt.Sprintf("%s_%s_uidx", r.Table, strings.Join(group, "_"))
			quoted := make([]string, len(group))
			for i, c := range group {
				quoted[i] = fmt.Sprintf("%q", c)
			}
			b.WriteString(fmt.Sprintf(
				"\tif _, err := bunDB.NewCreateIndex().Unique().IfNotExists().Index(%q).Table(%q).Column(%s).Exec(ctx); err != nil {\n",
				idxName, r.Table, strings.Join(quoted, ", "),
			))
			b.WriteString("\t\treturn err\n")
			b.WriteString("\t}\n")
		}
		for _, group := range r.Schema.CompositeIndexes {
			idxName := fmt.Sprintf("%s_%s_idx", r.Table, strings.Join(group, "_"))
			quoted := make([]string, len(group))
			for i, c := range group {
				quoted[i] = fmt.Sprintf("%q", c)
			}
			b.WriteString(fmt.Sprintf(
				"\tif _, err := bunDB.NewCreateIndex().IfNotExists().Index(%q).Table(%q).Column(%s).Exec(ctx); err != nil {\n",
				idxName, r.Table, strings.Join(quoted, ", "),
			))
			b.WriteString("\t\treturn err\n")
			b.WriteString("\t}\n")
		}
	}
	b.WriteString("\treturn nil\n")
	b.WriteString("}\n\n")
}

func bunTag(field string, def *schema.FieldDef, pk *schema.PK) string {
	pkCol := "id"
	if pk != nil {
		pkCol = pk.Column
	}
	parts := []string{field}
	if field == pkCol {
		parts = append(parts, "pk")
		if pk != nil && pk.Autoname.Strategy == schema.AutonameAutoinc {
			parts = append(parts, "autoincrement")
		}
	}
	if def.IsUnique {
		parts = append(parts, "unique")
	}
	if def.IsRequired {
		parts = append(parts, "notnull")
	}
	if field == pkCol || field == "created_at" || field == "updated_at" {
		if field == pkCol && def.Type == schema.FieldUUID {
			parts = append(parts, "default:gen_random_uuid()")
		}
		if !def.IsRequired {
			parts = append(parts, "notnull")
		}
	}
	if field == "created_at" || field == "updated_at" {
		parts = append(parts, "default:current_timestamp")
	}
	if def.DefaultValue != nil {
		filtered := make([]string, 0, len(parts))
		for _, p := range parts {
			if len(p) >= 8 && p[:8] == "default:" {
				continue
			}
			filtered = append(filtered, p)
		}
		parts = append(filtered, "default:"+formatDefault(def))
	}
	return fmt.Sprintf("bun:\"%s\"", strings.Join(parts, ","))
}

func formatDefault(def *schema.FieldDef) string {
	switch def.Type {
	case schema.FieldString, schema.FieldText, schema.FieldEnum:
		return fmt.Sprintf("'%v'", def.DefaultValue)
	case schema.FieldBool:
		if b, ok := def.DefaultValue.(bool); ok && b {
			return "true"
		}
		return "false"
	case schema.FieldTimestamp:
		return "current_timestamp"
	}
	return fmt.Sprintf("'%v'", def.DefaultValue)
}

func jsonTag(field string, def *schema.FieldDef, pkCol string) string {
	tag := fmt.Sprintf("json:\"%s", field)
	if !def.IsRequired && !isAuto(field, pkCol) && def.Type != schema.FieldBool {
		tag += ",omitempty"
	}
	tag += "\""
	return tag
}

func jsonTagOptional(field string) string {
	return fmt.Sprintf("json:\"%s,omitempty\"", field)
}
