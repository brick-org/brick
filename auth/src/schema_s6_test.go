package auth_test

// AUTH-S6-01 failing-first suite: full schema + identity admission pipeline.
//
// Upstream evidence (Better Auth v1.7.5, commit 5468e6bf):
//   - db/get-schema.ts (getSchema: modelName-keyed, fieldName-keyed, refs
//     rewritten, indexes attached)
//   - core get-tables.ts (buildAuthTables core->plugin->options precedence,
//     getAuthTablesWithResolvedIndexes)
//   - db/schema.ts parseInputData/parseUserInput/filterOutputFields +
//     db/to-zod.test.ts (returned:false input vs output, required:false
//     nullish)
//   - core database-index.ts + database-index.test.ts
//     (resolveDatabaseSchemaIndexes validation)
//   - db/with-hooks.ts + core context/transaction.ts:170
//     (queueAfterTransactionHook rejects outside transactions)
//   - user.validateUserInfo (core init-options.ts:970) + call sites:
//     internal-adapter.ts createUser (action create-user, 403), link-account.ts
//     handleOAuthUserInfo (link-account + sign-in, 403), callback.ts link
//     branch (redirect ?error=&error_description=), sign-up.ts generic-duplicate
//     hiding of 403s.
//
// This file ports the schema/admission behavior first; implementation lands
// in auth/schema.go (GetSchema, Input/Output field helpers, ValidateUserInfo
// seam helpers) and auth/hooked_adapter.go (D05 throw alignment).

import (
	"context"
	"errors"
	"strings"
	"testing"

	auth "github.com/brick-org/brick/auth/src"
	routes "github.com/brick-org/brick/auth/src/api/routes"
	"github.com/brick-org/brick/auth/src/types"
)

// ---------------------------------------------------------------------------
// 1. One resolved schema drives everything.
// ---------------------------------------------------------------------------

func TestS6_GetSchemaMirrorsUpstreamGetSchema(t *testing.T) {
	falseVal := false
	plugin := &parityPlugin{
		id: "s6",
		schema: auth.PluginSchema{
			"user": {Fields: map[string]auth.FieldAttribute{
				"role": {Type: auth.FieldTypeString, Required: &falseVal},
			}},
			"member": {
				ModelName: "members",
				Fields: map[string]auth.FieldAttribute{
					"userId": {
						Type:       auth.FieldTypeString,
						References: &auth.FieldReference{Model: "user", Field: "id", OnDelete: "cascade"},
					},
				},
			},
		},
	}
	opts := auth.Options{Plugins: []auth.Plugin{plugin}}
	opts.User.Model.ModelName = "app_users"
	opts.User.Model.Fields = map[string]string{"email": "email_address"}

	schema := auth.GetSchema(opts)
	// Keyed by physical modelName, not logical key.
	if _, ok := schema["app_users"]; !ok {
		t.Fatalf("GetSchema must key by modelName app_users, got keys %v", schemaKeys(schema))
	}
	userEntry, ok := schema["app_users"]
	if !ok {
		t.Fatal("missing app_users entry")
	}
	// Fields keyed by physical column (fieldName||logical).
	if _, ok := userEntry.Fields["email_address"]; !ok {
		t.Fatalf("user fields must key by fieldName email_address, got %v", fieldKeys(userEntry.Fields))
	}
	if _, ok := userEntry.Fields["role"]; !ok {
		t.Fatal("plugin field role must survive GetSchema")
	}
	// References rewrite to the target modelName.
	memberEntry, ok := schema["members"]
	if !ok {
		t.Fatalf("GetSchema must key plugin table by modelName members, got %v", schemaKeys(schema))
	}
	ref := memberEntry.Fields["userId"].References
	if ref == nil {
		t.Fatal("member.userId references must survive GetSchema")
	}
	if ref.Model != "app_users" {
		t.Fatalf("references.model must rewrite to target modelName app_users, got %q", ref.Model)
	}
	// Order + indexes attached.
	if userEntry.Order == 0 {
		t.Fatal("GetSchema user entry must carry order")
	}
	if _, ok := schema["app_users"]; !ok {
		t.Fatal("unreachable")
	}
}

func TestS6_OneResolvedSchemaDrivesAll(t *testing.T) {
	falseVal := false
	plugin := &parityPlugin{
		id: "s6drive",
		schema: auth.PluginSchema{
			"user": {Fields: map[string]auth.FieldAttribute{
				"role": {Type: auth.FieldTypeString, Required: &falseVal},
			}},
		},
	}
	opts := auth.Options{Plugins: []auth.Plugin{plugin}}
	opts.User.Model.AdditionalFields = map[string]auth.FieldAttribute{
		"tenant": {Type: auth.FieldTypeString, Required: &falseVal},
		"role":   {Type: auth.FieldTypeString, Required: &falseVal, DefaultValue: "option-wins"},
	}

	full := auth.FullSchema(opts)
	// Option additionalFields win over same-named plugin fields.
	if got := full["user"].Fields["role"].DefaultValue; got != "option-wins" {
		t.Fatalf("option additionalFields must win over plugin fields, got %#v", got)
	}
	if _, ok := full["user"].Fields["tenant"]; !ok {
		t.Fatal("option additionalFields must merge into FullSchema")
	}
	if _, ok := full["user"].Fields["email"]; !ok {
		t.Fatal("core fields must survive in FullSchema")
	}

	// Input/output field maps derive from the SAME resolved schema.
	inFields := auth.UserInputFields(opts)
	outFields := auth.UserOutputFields(opts)
	if _, ok := inFields["tenant"]; !ok {
		t.Fatal("UserInputFields must include option additionalFields")
	}
	if _, ok := outFields["tenant"]; !ok {
		t.Fatal("UserOutputFields must include option additionalFields")
	}
	if _, ok := outFields["email"]; !ok {
		t.Fatal("UserOutputFields must include core fields")
	}

	// Adapter mapping derives from the same schema.
	cfg := auth.AdapterConfig{}
	if got := auth.PhysicalTableName("user", full["user"], cfg); got == "" {
		t.Fatal("PhysicalTableName must resolve")
	}

	// Field validator/transform execution uses the same schema: wire the
	// resolved user fields into the hooked adapter and prove a rejection
	// aborts with no write.
	boom := errors.New("s6 validator boom")
	fields := map[string]map[string]types.FieldAttribute{
		"user": {
			"tenant": {
				Type:      types.FieldTypeString,
				Validator: types.NewFieldValidator(types.FieldValidatorFunc(func(v any) error { return boom }), nil),
			},
		},
	}
	inner := newMemoryAdapter()
	wrapped := auth.NewHookedAdapterWithOptions(inner, nil, nil, auth.HookedAdapterOptions{FieldSchemas: fields})
	if _, err := wrapped.Create(context.Background(), "user", map[string]any{"id": "1", "tenant": "x"}, nil); !errors.Is(err, boom) {
		t.Fatalf("resolved validator must abort the write, got %v", err)
	}

	// Migrations validate the same schema.
	if err := auth.ValidateSchemaIndexes(full, cfg); err != nil {
		t.Fatalf("FullSchema must validate: %v", err)
	}

	// Route helpers consume the same schema (Wave 7 contract): the exported
	// full field maps must be the FullSchema non-core subset.
	routeUser := routes.FullUserFieldsForOptions(optsToTypes(opts))
	fullUser := full["user"].Fields
	for name := range routeUser {
		if _, ok := fullUser[name]; !ok {
			t.Fatalf("route full field %q must exist in FullSchema", name)
		}
	}
	if _, ok := routeUser["tenant"]; !ok {
		t.Fatal("route full fields must include option additionalFields")
	}
}

// ---------------------------------------------------------------------------
// 2. Additional-field pipeline (to-zod + parseInputData semantics).
// ---------------------------------------------------------------------------

func TestS6_AdditionalFieldDefaultsTransformsValidators(t *testing.T) {
	// Static default applies on create, not update.
	fields := map[string]types.FieldAttribute{
		"name": {Type: types.FieldTypeString},
		"nick": {Type: types.FieldTypeString, Required: boolPtrS6(false), DefaultValue: "anon"},
	}
	got, err := routes.ParseInputData(map[string]any{"name": "a"}, fields, "create")
	if err != nil {
		t.Fatalf("create must succeed: %v", err)
	}
	if got["nick"] != "anon" {
		t.Fatalf("static default must apply on create: %v", got)
	}
	got, err = routes.ParseInputData(map[string]any{"name": "a"}, fields, "update")
	if err != nil {
		t.Fatalf("update must succeed: %v", err)
	}
	if _, ok := got["nick"]; ok {
		t.Fatalf("update must not backfill defaults: %v", got)
	}

	// Func default with a non-func()any signature must still evaluate
	// (upstream () => Date.now() / () => new Date() factories).
	funcFields := map[string]types.FieldAttribute{
		"name": {Type: types.FieldTypeString},
		"code": {Type: types.FieldTypeString, Required: boolPtrS6(false), DefaultValue: func() string { return "gen" }},
	}
	got, err = routes.ParseInputData(map[string]any{"name": "a"}, funcFields, "create")
	if err != nil {
		t.Fatalf("create with func default must succeed: %v", err)
	}
	if got["code"] != "gen" {
		t.Fatalf("func default must evaluate, got %#v", got["code"])
	}

	// Validator rejection surfaces VALIDATION_ERROR; transform applies;
	// validator wins over transform per field (parseInputData branches).
	vtFields := map[string]types.FieldAttribute{
		"age": {
			Type: types.FieldTypeNumber,
			Validator: types.NewFieldValidator(types.FieldValidatorFunc(func(v any) error {
				if n, ok := v.(int); !ok || n < 0 {
					return errors.New("bad age")
				}
				return nil
			}), nil),
			Transform: types.NewFieldTransform(types.FieldTransformFunc(func(v any) (any, error) { return "t", nil }), nil),
		},
		"email": {
			Type:      types.FieldTypeString,
			Transform: types.NewFieldTransform(types.FieldTransformFunc(func(v any) (any, error) { return "x:" + v.(string), nil }), nil),
		},
	}
	if _, err := routes.ParseInputData(map[string]any{"age": -1, "email": "a"}, vtFields, "create"); err == nil {
		t.Fatal("validator rejection must fail")
	} else if !strings.Contains(err.Error(), "bad age") {
		t.Fatalf("validator error must surface, got %v", err)
	}
	got, err = routes.ParseInputData(map[string]any{"age": 3, "email": "a@b.c"}, vtFields, "create")
	if err != nil {
		t.Fatalf("valid input must pass: %v", err)
	}
	if got["email"] != "x:a@b.c" {
		t.Fatalf("transform must apply: %v", got)
	}

	// Nullability mirrors upstream parseInputData (which copies present keys
	// without null checks; to-zod nullish is an API-schema concern): a
	// present null passes through for both required and optional fields.
	nullFields := map[string]types.FieldAttribute{
		"name": {Type: types.FieldTypeString},
		"nick": {Type: types.FieldTypeString, Required: boolPtrS6(false)},
	}
	got, err = routes.ParseInputData(map[string]any{"name": "a", "nick": nil}, nullFields, "create")
	if err != nil {
		t.Fatalf("present null for optional field must pass (upstream copies): %v", err)
	}

	// Aliases: explicit FieldName reverse map + snake_case folding.
	aliasFields := map[string]types.FieldAttribute{
		"email":       {Type: types.FieldTypeString, FieldName: "email_address"},
		"displayName": {Type: types.FieldTypeString, Required: boolPtrS6(false)},
	}
	if name, ok := routes.CanonicalInputKey("email_address", aliasFields); !ok || name != "email" {
		t.Fatalf("FieldName alias must resolve: %q %v", name, ok)
	}
	if name, ok := routes.CanonicalInputKey("display_name", aliasFields); !ok || name != "displayName" {
		t.Fatalf("snake alias must resolve: %q %v", name, ok)
	}

	// Output stripping: only returned:false is dropped; unknown keys survive
	// (upstream filterOutputFields keeps everything except returned:false).
	outFields := map[string]types.FieldAttribute{
		"token":  {Type: types.FieldTypeString},
		"secret": {Type: types.FieldTypeString, Input: boolPtrS6(false)},
		"code":   {Type: types.FieldTypeString, Returned: boolPtrS6(false)},
	}
	filtered := routes.FilterOutputFields(map[string]any{
		"token": "t", "secret": "s", "code": "c", "undeclared": "u",
	}, outFields)
	if _, ok := filtered["code"]; ok {
		t.Fatal("returned:false must be stripped from output")
	}
	for _, k := range []string{"token", "secret", "undeclared"} {
		if _, ok := filtered[k]; !ok {
			t.Fatalf("output key %q must survive (input:false and unknown keys are kept)", k)
		}
	}

	// input:false: falsy dropped, truthy rejected with FIELD_NOT_ALLOWED.
	inFalse := map[string]types.FieldAttribute{
		"emailVerified": {Type: types.FieldTypeBoolean, Input: boolPtrS6(false)},
	}
	if _, err := routes.ParseInputData(map[string]any{"emailVerified": true}, inFalse, "update"); err == nil {
		t.Fatal("truthy input:false must be rejected")
	}
	got, err = routes.ParseInputData(map[string]any{"emailVerified": false}, inFalse, "create")
	if err != nil {
		t.Fatalf("falsy input:false must be dropped: %v", err)
	}
	if _, ok := got["emailVerified"]; ok {
		t.Fatalf("input:false field must be dropped: %v", got)
	}
}

// ---------------------------------------------------------------------------
// 3. ValidateUserInfo at every seam: exact redirect vs 403.
// ---------------------------------------------------------------------------

func TestS6_ValidateUserInfoSourceValidation(t *testing.T) {
	// Missing method fails closed.
	if err := auth.AssertValidUserInfoSource(types.ValidateUserInfoSource{}); err == nil {
		t.Fatal("missing method must fail closed")
	} else if codeOf(err) != "validation_source_missing" {
		t.Fatalf("missing method must report validation_source_missing, got code %q (%v)", codeOf(err), err)
	}
	// OAuth without providerId fails closed.
	src := types.ValidateUserInfoSource{Action: types.ValidateUserInfoActionCreateUser, Method: types.ValidateUserInfoMethodOAuth}
	if err := auth.AssertValidUserInfoSource(src); err == nil {
		t.Fatal("oauth without provider must fail closed")
	} else if codeOf(err) != "validation_source_missing" {
		t.Fatalf("oauth without provider must report validation_source_missing, got %v", err)
	}
	// SSO without provider fails closed.
	src = types.ValidateUserInfoSource{Action: types.ValidateUserInfoActionCreateUser, Method: types.ValidateUserInfoMethodSSOOIDC}
	if err := auth.AssertValidUserInfoSource(src); err == nil {
		t.Fatal("sso-oidc without provider must fail closed")
	} else if codeOf(err) != "validation_source_missing" {
		t.Fatalf("sso without provider must report validation_source_missing, got %v", err)
	}
	// Well-formed sources pass.
	okSrc := auth.OAuthProvisioningSource("google", nil).WithAction(types.ValidateUserInfoActionCreateUser)
	if err := auth.AssertValidUserInfoSource(okSrc); err != nil {
		t.Fatalf("well-formed oauth source must pass: %v", err)
	}
}

func TestS6_ValidateUserInfoSeams(t *testing.T) {
	ctx := context.Background()
	// Gate that rejects one domain.
	gate := types.ValidateUserInfoFunc(func(data types.ValidateUserInfoData, _ types.EndpointContext) (*types.ValidateUserInfoResult, error) {
		if email, _ := data.User["email"].(string); strings.HasSuffix(email, "@blocked.com") {
			return &types.ValidateUserInfoResult{Error: "email_not_allowed", ErrorDescription: "Only company emails are allowed"}, nil
		}
		return nil, nil
	})
	epCtx := types.RequestEndpointContext(nil, types.AuthContext{}, "POST", "/sign-up/email")

	// create-user seam (email-password): programmatic 403, nothing written.
	createSrc := types.ValidateUserInfoSource{Action: types.ValidateUserInfoActionCreateUser, Method: types.ValidateUserInfoMethodEmailPassword}
	err := auth.AssertValidUserInfo(ctx, gate, epCtx, map[string]any{"email": "a@blocked.com"}, createSrc)
	if err == nil {
		t.Fatal("create-user gate rejection must fail")
	}
	var httpErr types.HttpError
	if !errors.As(err, &httpErr) {
		t.Fatalf("create-user rejection must be a 403 HttpError, got %T %v", err, err)
	}
	if codeOf(err) != "email_not_allowed" {
		t.Fatalf("create-user rejection must carry code email_not_allowed, got %v", err)
	}
	if httpErr.Status != 403 {
		t.Fatalf("programmatic gate rejection must be 403, got %d (%v)", httpErr.Status, err)
	}
	if err := auth.AssertValidUserInfo(ctx, gate, epCtx, map[string]any{"email": "a@ok.com"}, createSrc); err != nil {
		t.Fatalf("allowed identity must pass: %v", err)
	}

	// link-account seam (oauth): same 403 for programmatic callers...
	linkSrc := auth.OAuthProvisioningSource("google", map[string]any{"sub": "1"}).WithAction(types.ValidateUserInfoActionLinkAccount)
	if linkSrc.Method != types.ValidateUserInfoMethodOAuth {
		t.Fatalf("link source method must be oauth, got %q", linkSrc.Method)
	}
	err = auth.AssertValidUserInfo(ctx, gate, epCtx, map[string]any{"email": "a@blocked.com", "id": "u1"}, linkSrc)
	if err == nil || codeOf(err) != "email_not_allowed" {
		t.Fatalf("link-account rejection must carry the gate code, got %v", err)
	}

	// ...but browser flows redirect to the error URL with
	// ?error=<code>&error_description=<msg> (callback.ts redirectOnError).
	redirect := auth.ValidateUserInfoRedirectURL("https://app.example/error", "email_not_allowed", "Only company emails are allowed")
	if !strings.Contains(redirect, "error=email_not_allowed") {
		t.Fatalf("browser redirect must carry error code, got %q", redirect)
	}
	if !strings.Contains(redirect, "error_description=") {
		t.Fatalf("browser redirect must carry error_description, got %q", redirect)
	}

	// sign-in seam (oauth returning user, fresh provider data).
	signInSrc := auth.OAuthProvisioningSource("google", map[string]any{"sub": "1"}).WithAction(types.ValidateUserInfoActionSignIn)
	err = auth.AssertValidUserInfo(ctx, gate, epCtx, map[string]any{"email": "moved@blocked.com", "id": "u1"}, signInSrc)
	if err == nil || codeOf(err) != "email_not_allowed" {
		t.Fatalf("sign-in gate must see fresh provider email, got %v", err)
	}

	// Hook throw fails closed as validation_failed (never silently allowed).
	throwing := types.ValidateUserInfoFunc(func(types.ValidateUserInfoData, types.EndpointContext) (*types.ValidateUserInfoResult, error) {
		return nil, errors.New("hook exploded")
	})
	if err := auth.AssertValidUserInfo(ctx, throwing, epCtx, map[string]any{"email": "a@ok.com"}, createSrc); err == nil {
		t.Fatal("throwing hook must fail closed")
	} else if codeOf(err) != "validation_failed" {
		t.Fatalf("throwing hook must map to validation_failed, got %v", err)
	}

	// Nil hook allows everything (no gate configured).
	if err := auth.AssertValidUserInfo(ctx, nil, epCtx, map[string]any{"email": "a@blocked.com"}, createSrc); err != nil {
		t.Fatalf("nil hook must allow: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 4. D05: non-transactional after-hook errors must throw (upstream
// transaction.ts:170 rejects). The write stays committed; the call fails.
// ---------------------------------------------------------------------------

func TestS6_D05_NonTransactionalAfterHookThrows(t *testing.T) {
	ctx := context.Background()
	hookErr := errors.New("s6 after failed")

	for _, op := range []string{"create", "update", "updateMany", "delete", "deleteMany"} {
		inner := newMemoryAdapter()
		if _, err := inner.Create(ctx, "user", map[string]any{"id": "seed-" + op}, nil); err != nil {
			t.Fatal(err)
		}
		var wrapped auth.Adapter
		switch op {
		case "create":
			wrapped = auth.NewHookedAdapter(inner, nil, auth.DBHooks{
				"user": {Create: auth.OperationHooks{After: func(context.Context, map[string]any) error { return hookErr }}},
			})
			row, err := wrapped.Create(ctx, "user", map[string]any{"id": "n-" + op}, nil)
			if !errors.Is(err, hookErr) {
				t.Fatalf("%s: after-hook error must propagate, got row=%v err=%v", op, row, err)
			}
			if n, _ := inner.Count(ctx, "user", nil); n != 2 {
				t.Fatalf("%s: write must stay committed despite after-hook failure", op)
			}
		case "update":
			wrapped = auth.NewHookedAdapter(inner, nil, auth.DBHooks{
				"user": {Update: auth.OperationHooks{After: func(context.Context, map[string]any) error { return hookErr }}},
			})
			if _, err := wrapped.Update(ctx, "user", []auth.Where{{Field: "id", Value: "seed-" + op}}, map[string]any{"name": "x"}); !errors.Is(err, hookErr) {
				t.Fatalf("%s: after-hook error must propagate, got %v", op, err)
			}
		case "updateMany":
			wrapped = auth.NewHookedAdapter(inner, nil, auth.DBHooks{
				"user": {Update: auth.OperationHooks{After: func(context.Context, map[string]any) error { return hookErr }}},
			})
			if _, err := wrapped.UpdateMany(ctx, "user", []auth.Where{{Field: "id", Value: "seed-" + op}}, map[string]any{"name": "x"}); !errors.Is(err, hookErr) {
				t.Fatalf("%s: after-hook error must propagate, got %v", op, err)
			}
		case "delete":
			wrapped = auth.NewHookedAdapter(inner, nil, auth.DBHooks{
				"user": {Delete: auth.OperationHooks{After: func(context.Context, map[string]any) error { return hookErr }}},
			})
			if err := wrapped.Delete(ctx, "user", []auth.Where{{Field: "id", Value: "seed-" + op}}); !errors.Is(err, hookErr) {
				t.Fatalf("%s: after-hook error must propagate, got %v", op, err)
			}
			if n, _ := inner.Count(ctx, "user", nil); n != 0 {
				t.Fatalf("%s: delete must stay committed despite after-hook failure", op)
			}
		case "deleteMany":
			wrapped = auth.NewHookedAdapter(inner, nil, auth.DBHooks{
				"user": {Delete: auth.OperationHooks{After: func(context.Context, map[string]any) error { return hookErr }}},
			})
			if _, err := wrapped.DeleteMany(ctx, "user", []auth.Where{{Field: "id", Value: "seed-" + op}}); !errors.Is(err, hookErr) {
				t.Fatalf("%s: after-hook error must propagate, got %v", op, err)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func schemaKeys(s auth.PluginSchema) []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	return out
}

func fieldKeys(m map[string]auth.FieldAttribute) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func boolPtrS6(v bool) *bool { return &v }

func codeOf(err error) string {
	var httpErr types.HttpError
	if errors.As(err, &httpErr) {
		return httpErr.Code
	}
	return ""
}

func optsToTypes(o auth.Options) types.Options { return types.Options(o) }
