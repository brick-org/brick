package jwt

import (
	"testing"

	"github.com/brick-org/brick/auth/src/types"
)

func TestSchemaFields(t *testing.T) {
	schema := Schema()
	if len(schema) != 1 {
		t.Fatalf("Schema() has %d models, want 1", len(schema))
	}
	table, ok := schema["jwks"]
	if !ok {
		t.Fatal(`Schema() is missing model "jwks"`)
	}
	if table.ModelName != "" {
		t.Errorf("jwks ModelName = %q, want default model name", table.ModelName)
	}

	wantFields := map[string]struct {
		typ      types.FieldType
		required bool
		returned *bool
	}{
		"publicKey":  {typ: types.FieldTypeString, required: true},
		"privateKey": {typ: types.FieldTypeString, required: true, returned: jwtBool(false)},
		"createdAt":  {typ: types.FieldTypeDate, required: true},
		"expiresAt":  {typ: types.FieldTypeDate},
		"alg":        {typ: types.FieldTypeString},
		"crv":        {typ: types.FieldTypeString},
	}
	if len(table.Fields) != len(wantFields) {
		t.Fatalf("jwks has %d fields, want exactly %d", len(table.Fields), len(wantFields))
	}
	for name, want := range wantFields {
		field, ok := table.Fields[name]
		if !ok {
			t.Errorf("jwks is missing field %q", name)
			continue
		}
		if field.Type != want.typ {
			t.Errorf("jwks.%s type = %q, want %q", name, field.Type, want.typ)
		}
		if field.Required == nil || *field.Required != want.required {
			t.Errorf("jwks.%s Required = %v, want %t", name, field.Required, want.required)
		}
		if want.returned == nil {
			if field.Returned != nil {
				t.Errorf("jwks.%s Returned = %v, want default (nil)", name, *field.Returned)
			}
		} else if field.Returned == nil || *field.Returned != *want.returned {
			t.Errorf("jwks.%s Returned = %v, want %t", name, field.Returned, *want.returned)
		}
	}
}

func TestSchemaLegacyAlgorithmFieldsAreOptionalAndNullable(t *testing.T) {
	fields := Schema()["jwks"].Fields
	for _, name := range []string{"alg", "crv"} {
		field := fields[name]
		if field.Type != types.FieldTypeString {
			t.Errorf("jwks.%s type = %q, want string", name, field.Type)
		}
		// Required=false is the schema contract for an optional, nullable column.
		if field.Required == nil || *field.Required {
			t.Errorf("jwks.%s Required = %v, want false for legacy null fallback", name, field.Required)
		}
	}
}
