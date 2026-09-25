package routes

import (
	"errors"
	"strings"
	"testing"

	"github.com/brick-org/brick/auth/src/types"
)

var (
	errTestValidation = errors.New("test validation failed")
	errTestTransform  = errors.New("test transform failed")
)

func boolPtr(v bool) *bool { return &v }

func intPtr(v int) *int { return &v }

func testSessionFullFields() map[string]types.FieldAttribute {
	return map[string]types.FieldAttribute{
		"token":     {Type: types.FieldTypeString},
		"expiresAt": {Type: types.FieldTypeDate},
		"role":      {Type: types.FieldTypeString},
		"secret":    {Type: types.FieldTypeString, Input: boolPtr(false)},
		"code":      {Type: types.FieldTypeString, Returned: boolPtr(false)},
		"name":      {Type: types.FieldTypeString, Required: boolPtr(false)},
	}
}

func TestParseInputData_CreateAppliesDefaultsAndRequires(t *testing.T) {
	fields := map[string]types.FieldAttribute{
		"name":  {Type: types.FieldTypeString},
		"nick":  {Type: types.FieldTypeString, Required: boolPtr(false), DefaultValue: "anon"},
		"email": {Type: types.FieldTypeString, Required: boolPtr(false)},
	}
	got, err := ParseInputData(map[string]any{"name": "a"}, fields, "create")
	if err != nil {
		t.Fatalf("create must succeed: %v", err)
	}
	if got["name"] != "a" || got["nick"] != "anon" {
		t.Fatalf("defaults must apply: %v", got)
	}
	if _, err := ParseInputData(map[string]any{}, fields, "create"); err == nil {
		t.Fatal("missing required field must fail on create")
	} else if !strings.Contains(err.Error(), "name") {
		t.Fatalf("missing-field error must name the field: %v", err)
	}
	// Update never enforces required/defaults.
	got, err = ParseInputData(map[string]any{"email": "e"}, fields, "update")
	if err != nil {
		t.Fatalf("update must succeed: %v", err)
	}
	if _, ok := got["name"]; ok {
		t.Fatalf("update must not backfill: %v", got)
	}
}

func TestParseInputData_InputFalse(t *testing.T) {
	fields := map[string]types.FieldAttribute{
		"emailVerified": {Type: types.FieldTypeBoolean, Input: boolPtr(false)},
		"role":          {Type: types.FieldTypeString, Input: boolPtr(false), DefaultValue: "user"},
	}
	// Falsy values for input:false are dropped silently (upstream behavior).
	got, err := ParseInputData(map[string]any{"emailVerified": false}, fields, "create")
	if err != nil {
		t.Fatalf("falsy input:false must be dropped: %v", err)
	}
	if _, ok := got["emailVerified"]; ok {
		t.Fatalf("input:false field must be dropped: %v", got)
	}
	// Default applies on create for input:false with a default.
	if got["role"] != "user" {
		t.Fatalf("input:false default must apply on create: %v", got)
	}
	// Truthy values for input:false are rejected.
	if _, err := ParseInputData(map[string]any{"emailVerified": true}, fields, "update"); err == nil {
		t.Fatal("truthy input:false must be rejected")
	}
}

func TestParseInputData_ValidatorAndTransform(t *testing.T) {
	fields := map[string]types.FieldAttribute{
		"age": {
			Type: types.FieldTypeNumber,
			Validator: types.NewFieldValidator(func(v any) error {
				if n, ok := v.(int); !ok || n < 0 {
					return errTestValidation
				}
				return nil
			}, nil),
		},
		"email": {
			Type:      types.FieldTypeString,
			Transform: types.NewFieldTransform(func(v any) (any, error) { return "x:" + v.(string), nil }, nil),
		},
		"upper": {
			Type:      types.FieldTypeString,
			Required:  boolPtr(false),
			Transform: types.NewFieldTransform(func(v any) (any, error) { return nil, errTestTransform }, nil),
		},
	}
	got, err := ParseInputData(map[string]any{"age": 3, "email": "a@b.c"}, fields, "create")
	if err != nil {
		t.Fatalf("valid input must pass: %v", err)
	}
	if got["email"] != "x:a@b.c" {
		t.Fatalf("transform must apply: %v", got)
	}
	if _, err := ParseInputData(map[string]any{"age": -1, "email": "a"}, fields, "create"); err == nil {
		t.Fatal("validator rejection must fail")
	}
	if _, err := ParseInputData(map[string]any{"age": 1, "email": "a", "upper": "z"}, fields, "create"); err == nil {
		t.Fatal("transform error must abort")
	}
	// Unknown keys are ignored (upstream iterates schema fields).
	got, err = ParseInputData(map[string]any{"age": 1, "email": "a", "unknown": 1}, fields, "create")
	if err != nil {
		t.Fatalf("unknown keys must be ignored: %v", err)
	}
	if _, ok := got["unknown"]; ok {
		t.Fatalf("unknown keys must not be copied: %v", got)
	}
}

func TestCanonicalInputKey_FieldNameAlias(t *testing.T) {
	fields := map[string]types.FieldAttribute{
		"email": {Type: types.FieldTypeString, FieldName: "email_address"},
		"name":  {Type: types.FieldTypeString},
	}
	if got, ok := CanonicalInputKey("email_address", fields); !ok || got != "email" {
		t.Fatalf("FieldName alias must resolve: %q %v", got, ok)
	}
	if got, ok := CanonicalInputKey("email", fields); !ok || got != "email" {
		t.Fatalf("logical name must resolve: %q %v", got, ok)
	}
	if _, ok := CanonicalInputKey("nope", fields); ok {
		t.Fatal("unknown key must not resolve")
	}
}

func TestFilterOutputFields_DropsReturnedFalseOnly(t *testing.T) {
	fields := testSessionFullFields()
	row := map[string]any{"token": "t", "secret": "s", "role": "r", "code": "c", "undeclared": "u"}
	got := FilterOutputFields(row, fields)
	if _, ok := got["code"]; ok {
		t.Fatal("returned:false must be stripped")
	}
	// input:false alone does not strip output; unknown keys pass through
	// untouched (upstream keeps everything except returned:false).
	for _, k := range []string{"token", "secret", "role", "undeclared"} {
		if _, ok := got[k]; !ok {
			t.Fatalf("key %q must survive output filtering", k)
		}
	}
}

func TestExtractAdditionalFieldsFull_SupersetOfLegacy(t *testing.T) {
	fields := testSessionFullFields()
	row := map[string]any{
		"token": "t", "role": "r", "secret": "s",
		"custom_thing": "c", "user_id": "u",
	}
	legacy := extractAdditionalFields(row, map[string]types.FieldAttribute{"role": fields["role"]}, isCoreSessionColumn)
	full := ExtractAdditionalFieldsFull(row, fields, isCoreSessionColumn)
	for k := range legacy {
		if _, ok := full[k]; !ok {
			t.Fatalf("full schema must not reject legacy field %q", k)
		}
	}
	if _, ok := full["customThing"]; !ok {
		t.Fatal("full schema must keep previously dropped undeclared fields (upstream keeps unknown output; keys fold to logical camelCase like the legacy helper)")
	}
	if _, ok := full["secret"]; !ok {
		t.Fatal("input:false fields are still returned by default")
	}
	if _, ok := full["code"]; ok {
		t.Fatal("returned:false must be stripped")
	}
	_ = full["role"]
}

func TestFilterSessionUpdateFieldsFull_SafeMigration(t *testing.T) {
	fields := testSessionFullFields()
	// Known fields get full-schema semantics: input:false rejected when truthy.
	if _, err := FilterSessionUpdateFieldsFull(map[string]any{"secret": "x"}, fields); err == nil {
		t.Fatal("truthy input:false must be rejected under the full schema")
	}
	// Falsy input:false dropped.
	got, err := FilterSessionUpdateFieldsFull(map[string]any{"secret": ""}, fields)
	if err != nil {
		t.Fatalf("falsy input:false must be dropped: %v", err)
	}
	if _, ok := got["secret"]; ok {
		t.Fatalf("input:false must be dropped: %v", got)
	}
	// Undeclared fields keep legacy passthrough (never newly rejected).
	got, err = FilterSessionUpdateFieldsFull(map[string]any{"brand_new_field": "v", "role": "r"}, fields)
	if err != nil {
		t.Fatalf("passthrough must succeed: %v", err)
	}
	if got["brand_new_field"] != "v" || got["role"] != "r" {
		t.Fatalf("fields must pass through: %v", got)
	}
	// Core columns are never writable.
	got, err = FilterSessionUpdateFieldsFull(map[string]any{"token": "x", "userId": "u"}, fields)
	if err != nil {
		t.Fatalf("core-only body must succeed: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("core columns must be dropped: %v", got)
	}
	// Physical/snake spellings of known non-core fields resolve to logical names.
	snakeFields := map[string]types.FieldAttribute{
		"displayName": {Type: types.FieldTypeString, Required: boolPtr(false)},
	}
	got, err = FilterSessionUpdateFieldsFull(map[string]any{"display_name": "v"}, snakeFields)
	if err != nil {
		t.Fatalf("snake spelling must resolve: %v", err)
	}
	if got["displayName"] != "v" {
		t.Fatalf("resolved field must use the logical name: %v", got)
	}
}
