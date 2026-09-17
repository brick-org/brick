package schema

import "sort"

// This file centralizes the YAML/Go naming rules so codegen, docs, and
// hand-written extensions agree. Outputs are byte-identical to the beta
// helpers they replace (which used a hand-rolled bubble sort).

// Title uppercases a leading ASCII lowercase letter, leaving everything
// else byte-identical: "view_setting" resource names become View_setting,
// Page stays Page.
func Title(s string) string {
	if s == "" {
		return s
	}
	c := s[0]
	if c >= 'a' && c <= 'z' {
		c -= 'a' - 'A'
	}
	return string([]byte{c}) + s[1:]
}

// GoFieldName maps snake_case columns to CamelCase Go fields:
// modified_by → ModifiedBy, group_by_field → GroupByField.
func GoFieldName(field string) string {
	parts := splitSnake(field)
	for i, p := range parts {
		parts[i] = Title(p)
	}
	return joinStrings(parts, "")
}

// ListInputFieldName maps a column to its ListInput struct field, escaping
// the pagination/search envelope names: page → FilterPage.
func ListInputFieldName(field string) string {
	switch field {
	case "page", "limit", "sort", "search", "body":
		return "Filter" + GoFieldName(field)
	}
	return GoFieldName(field)
}

// GoType maps a field definition to its Go type in generated structs.
func GoType(def *FieldDef) string {
	switch def.Type {
	case FieldString, FieldText, FieldEnum, FieldUUID:
		return "string"
	case FieldInt:
		return "int32"
	case FieldFloat:
		return "float64"
	case FieldBool:
		return "bool"
	case FieldTimestamp:
		return "time.Time"
	case FieldJSON:
		return "json.RawMessage"
	case FieldForeign:
		return "string"
	}
	return "string"
}

// GoTypeFor is GoType plus the one PK special case: autoincrement PKs are
// bigint (int64), not the int32 used for regular int fields.
func GoTypeFor(field string, def *FieldDef, pk *PK) string {
	if pk != nil && field == pk.Column && pk.Autoname.Strategy == AutonameAutoinc {
		return "int64"
	}
	return GoType(def)
}

// SortedFields returns field names PK-column-first, then alphabetical.
// Deterministic output must never depend on Go map iteration order.
func SortedFields(fields Fields, pkCol string) []string {
	result := make([]string, 0, len(fields))
	if _, ok := fields[pkCol]; ok {
		result = append(result, pkCol)
	}
	rest := make([]string, 0, len(fields)-len(result))
	for k := range fields {
		if k != pkCol {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	result = append(result, rest...)
	return result
}

func splitSnake(s string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '_' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return append(parts, s[start:])
}

func joinStrings(parts []string, sep string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += sep
		}
		out += p
	}
	return out
}
