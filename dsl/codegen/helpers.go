package codegen

import (
	"fmt"
	"go/format"

	"github.com/brick-org/brick/dsl/schema"
)

func formatOutput(src string) (string, error) {
	out, err := format.Source([]byte(src))
	if err != nil {
		return "", fmt.Errorf("codegen: format.Source: %w", err)
	}
	return string(out), nil
}

func isHidden(field string, hidden []string) bool {
	for _, h := range hidden {
		if h == field {
			return true
		}
	}
	return false
}

func isReadonly(def *schema.FieldDef) bool { return def.IsReadonly }

// isAuto reports whether a field is populated by Brick/the DB and therefore
// excluded from create/update bodies. pkCol is the brick-managed PK column —
// empty when the client supplies the PK (AutonamePrompt).
func isAuto(field, pkCol string) bool {
	return (pkCol != "" && field == pkCol) || field == "created_at" || field == "updated_at"
}

// autoPKColumn returns the PK column when Brick manages its value, or ""
// when the client must send it (AutonamePrompt).
func autoPKColumn(r ResourceDef) string {
	if pk := pkDef(r); pk != nil && pk.Autoname.Strategy == schema.AutonamePrompt {
		return ""
	}
	return pkColumn(r)
}

// pkDef returns the resource's PK config, or nil for the legacy UUID "id".
func pkDef(r ResourceDef) *schema.PK {
	if r.Schema == nil {
		return nil
	}
	return r.Schema.PK
}

func pkColumn(r ResourceDef) string {
	if pk := pkDef(r); pk != nil {
		return pk.Column
	}
	return "id"
}
