package routes

// AUTH-S6-01 route-side failing-first suite (owned file:
// auth/api/routes/schema_fields.go).
//
// Ports db/to-zod.test.ts (returned:false input vs output, required:false
// nullish) and db/schema.ts parseInputData update/create + alias behavior
// against the explicit full-schema helper APIs Wave 7 consumes. The helpers
// must union — never intersect — with legacy acceptance.

import (
	"errors"
	"testing"

	"github.com/brick-org/brick/auth/src/types"
)

func TestS6Route_FullFieldsAreExplicitMigrationTargets(t *testing.T) {
	opts := types.Options{}
	opts.Schema = map[string]types.TableSchema{
		"user": {Fields: map[string]types.FieldAttribute{
			"pluginField": {Type: types.FieldTypeString, Required: boolPtr(false)},
		}},
		"session": {Fields: map[string]types.FieldAttribute{
			"pluginSess": {Type: types.FieldTypeString, Required: boolPtr(false)},
		}},
		"account": {Fields: map[string]types.FieldAttribute{}},
	}
	opts.User.Model.AdditionalFields = map[string]types.FieldAttribute{
		"tenant": {Type: types.FieldTypeString, Required: boolPtr(false)},
	}
	opts.Session.Model.AdditionalFields = map[string]types.FieldAttribute{
		"sessExtra": {Type: types.FieldTypeString, Required: boolPtr(false)},
	}
	opts.Account.Model.AdditionalFields = map[string]types.FieldAttribute{
		"acctExtra": {Type: types.FieldTypeString, Required: boolPtr(false)},
	}

	userFields := FullUserFields(opts)
	if _, ok := userFields["pluginField"]; !ok {
		t.Fatal("FullUserFields must include plugin-declared user fields")
	}
	if _, ok := userFields["tenant"]; !ok {
		t.Fatal("FullUserFields must include option additionalFields")
	}
	sessFields := FullSessionFields(opts)
	if _, ok := sessFields["pluginSess"]; !ok {
		t.Fatal("FullSessionFields must include plugin-declared session fields")
	}
	if _, ok := sessFields["sessExtra"]; !ok {
		t.Fatal("FullSessionFields must include option additionalFields")
	}
	acctFields := FullAccountFields(opts)
	if _, ok := acctFields["acctExtra"]; !ok {
		t.Fatal("FullAccountFields must include option additionalFields")
	}
}

func TestS6Route_ParseModelInputFullUsesFullSchema(t *testing.T) {
	opts := types.Options{}
	opts.Schema = map[string]types.TableSchema{
		"user": {Fields: map[string]types.FieldAttribute{
			"role": {Type: types.FieldTypeString, Required: boolPtr(false), DefaultValue: "member"},
		}},
		"session": {Fields: map[string]types.FieldAttribute{}},
		"account": {Fields: map[string]types.FieldAttribute{}},
	}
	_ = opts
	// Full parse: unknown keys ignored, defaults applied on create only,
	// required enforced on create only.
	fields := map[string]types.FieldAttribute{
		"name": {Type: types.FieldTypeString},
		"nick": {Type: types.FieldTypeString, Required: boolPtr(false), DefaultValue: "anon"},
	}
	got, err := ParseUserInputFull(map[string]any{"name": "a", "unknown": 1}, fields, "create")
	if err != nil {
		t.Fatalf("full user parse must succeed: %v", err)
	}
	if got["nick"] != "anon" {
		t.Fatalf("full parse must apply defaults on create: %v", got)
	}
	if _, ok := got["unknown"]; ok {
		t.Fatalf("unknown keys must be ignored: %v", got)
	}
	if _, err := ParseUserInputFull(map[string]any{}, fields, "create"); err == nil {
		t.Fatal("missing required must fail on create")
	}
	got, err = ParseUserInputFull(map[string]any{"nick": "x"}, fields, "update")
	if err != nil {
		t.Fatalf("update must succeed: %v", err)
	}
	if _, ok := got["name"]; ok {
		t.Fatal("update must not enforce required")
	}
}

func TestS6Route_FilterModelOutputFullStripsReturnedFalse(t *testing.T) {
	fields := map[string]types.FieldAttribute{
		"name":   {Type: types.FieldTypeString},
		"secret": {Type: types.FieldTypeString, Returned: boolPtr(false)},
	}
	row := map[string]any{"name": "n", "secret": "s", "extra": "e"}
	got := FilterUserOutputFull(row, fields)
	if _, ok := got["secret"]; ok {
		t.Fatal("returned:false must be stripped by full output filter")
	}
	if got["name"] != "n" || got["extra"] != "e" {
		t.Fatalf("other keys must survive: %v", got)
	}
}

func TestS6Route_ValidateUserInfoRedirectVs403(t *testing.T) {
	// Browser flows redirect with ?error=&error_description=.
	url := ValidateUserInfoRedirectURL("https://app.example/error", "email_not_allowed", "Only company emails are allowed")
	if url == "" || len(url) == 0 {
		t.Fatal("redirect URL must be built")
	}
	contains := func(s, sub string) bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}
	if !contains(url, "error=email_not_allowed") {
		t.Fatalf("redirect must carry error code, got %q", url)
	}
	if !contains(url, "error_description=") {
		t.Fatalf("redirect must carry error_description, got %q", url)
	}

	// Programmatic flows surface 403 with the gate code/message.
	err := NewValidateUserInfoError("email_not_allowed", "Only company emails are allowed")
	if err.Code == "" {
		t.Fatal("gate error must be built")
	}
	if err.Status != 403 {
		t.Fatalf("gate error status must be 403, got %d", err.Status)
	}
	if err.Code != "email_not_allowed" {
		t.Fatalf("gate error code must pass through, got %q", err.Code)
	}
	var _ = errors.New
}
