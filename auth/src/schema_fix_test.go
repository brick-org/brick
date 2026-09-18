package auth_test

import (
	"reflect"
	"testing"

	auth "github.com/brick-org/brick/auth/src"
	"github.com/brick-org/brick/auth/src/types"
)

// schemaFixPlugin is a minimal auth.Plugin stub for schema-fix regression
// tests (kept separate from parityPlugin so this file is self-contained).
type schemaFixPlugin struct {
	id     string
	schema auth.PluginSchema
}

func (p *schemaFixPlugin) ID() string { return p.id }

func (p *schemaFixPlugin) Init(_ auth.AuthContext) error { return nil }

func (p *schemaFixPlugin) Endpoints() []auth.Endpoint { return nil }

func (p *schemaFixPlugin) Schema() auth.PluginSchema { return p.schema }

func (p *schemaFixPlugin) Hooks() auth.DBHooks { return nil }

func (p *schemaFixPlugin) RouteHooks() auth.PluginRouteHooks { return auth.PluginRouteHooks{} }

func (p *schemaFixPlugin) ErrorCodes() map[string]string { return nil }

// GetModelName must resolve physical aliases through GetDefaultModelName so
// they round-trip instead of double-pluralizing (app_users → app_userss).
func TestSchemaFix_GetModelNameAliasRoundTrip(t *testing.T) {
	opts := auth.Options{}
	opts.User.Model.ModelName = "app_users"
	schema := auth.GetAuthTables(opts)
	cfg := auth.AdapterConfig{}

	if got := auth.GetModelName(schema, cfg, "app_users"); got != "app_users" {
		t.Fatalf("alias must round-trip: got %q, want %q", got, "app_users")
	}
	if got := auth.GetModelName(schema, cfg, "user"); got != "app_users" {
		t.Fatalf("canonical key must map to physical name: got %q", got)
	}
	if got := auth.GetModelName(schema, cfg, "sessions"); got != "sessions" {
		t.Fatalf("plural alias must round-trip: got %q", got)
	}
	if got := auth.GetModelName(schema, cfg, "unknown_model"); got != "unknown_models" {
		t.Fatalf("unknown model must keep plural fallback: got %q", got)
	}
}

// Options additionalFields must merge AFTER plugin fields (upstream order
// core→plugin→options) so options win on name collisions.
func TestSchemaFix_OptionAdditionalFieldsWinOverPlugin(t *testing.T) {
	plugin := &schemaFixPlugin{
		id: "test",
		schema: auth.PluginSchema{
			"user": {Fields: map[string]auth.FieldAttribute{
				"role":        {Type: auth.FieldTypeString},
				"pluginOnly":  {Type: auth.FieldTypeString},
				"overridden":  {Type: auth.FieldTypeString},
				"pluginEmail": {Type: auth.FieldTypeString},
			}},
		},
	}
	opts := auth.Options{Plugins: []auth.Plugin{plugin}}
	opts.User.Model.AdditionalFields = map[string]auth.FieldAttribute{
		"role":       {Type: auth.FieldTypeNumber},
		"overridden": {Type: auth.FieldTypeBoolean},
		"optionOnly": {Type: auth.FieldTypeString},
	}
	user := auth.GetAuthTables(opts)["user"]
	if user.Fields["role"].Type != auth.FieldTypeNumber {
		t.Fatalf("option additionalField must win: role type %q", user.Fields["role"].Type)
	}
	if user.Fields["overridden"].Type != auth.FieldTypeBoolean {
		t.Fatalf("option additionalField must win: overridden type %q", user.Fields["overridden"].Type)
	}
	for _, field := range []string{"pluginOnly", "pluginEmail", "optionOnly", "email", "name"} {
		if _, ok := user.Fields[field]; !ok {
			t.Fatalf("field %q must survive the merge", field)
		}
	}
}

// Plugin entries on core tables must contribute only Fields and Indexes:
// ModelName, Order, and DisableMigration from plugins are ignored there,
// while non-core tables still merge fully.
func TestSchemaFix_PluginContainedOnCoreTables(t *testing.T) {
	plugin := &schemaFixPlugin{
		id: "test",
		schema: auth.PluginSchema{
			"user": {
				ModelName:        "evil_users",
				Order:            99,
				DisableMigration: true,
				Fields:           map[string]auth.FieldAttribute{"role": {Type: auth.FieldTypeString}},
				Indexes:          []auth.TableIndex{{Fields: []string{"role"}}},
			},
			"organization": {
				ModelName: "orgs",
				Order:     7,
				Fields:    map[string]auth.FieldAttribute{"name": {Type: auth.FieldTypeString}},
			},
		},
	}
	opts := auth.Options{Plugins: []auth.Plugin{plugin}}
	opts.User.Model.ModelName = "app_users"
	tables := auth.GetAuthTables(opts)

	user := tables["user"]
	if user.ModelName != "app_users" {
		t.Fatalf("plugin ModelName on core must be ignored: got %q", user.ModelName)
	}
	if user.Order != 1 {
		t.Fatalf("plugin Order on core must be ignored: got %d", user.Order)
	}
	if user.DisableMigration {
		t.Fatal("plugin DisableMigration on core must be ignored")
	}
	if _, ok := user.Fields["role"]; !ok {
		t.Fatal("plugin fields on core must still merge")
	}
	if len(user.Indexes) == 0 {
		t.Fatal("plugin indexes on core must still merge")
	}

	org := tables["organization"]
	if org.ModelName != "orgs" {
		t.Fatalf("non-core ModelName must be honored: got %q", org.ModelName)
	}
	if org.Order != 7 {
		t.Fatalf("non-core Order must be honored: got %d", org.Order)
	}
}

// id/_id short-circuit to "id" (plugin schemas never declare their own id;
// it is auto-provided upstream).
func TestSchemaFix_GetDefaultFieldNameID(t *testing.T) {
	schema := auth.GetAuthTables(auth.Options{})
	cfg := auth.AdapterConfig{}
	if got := auth.GetDefaultFieldName("user", cfg, schema, "id"); got != "id" {
		t.Fatalf("id must resolve to id: got %q", got)
	}
	if got := auth.GetDefaultFieldName("user", cfg, schema, "_id"); got != "id" {
		t.Fatalf("_id must resolve to id: got %q", got)
	}
	if got := auth.GetDefaultFieldName("user", cfg, schema, "email"); got != "email" {
		t.Fatalf("logical field must resolve to itself: got %q", got)
	}
}

// Long generated names must strip "_<kind>" before truncating to 63 bytes
// and re-append "_<fnv1a32>_<kind>". Golden value computed from the upstream
// algorithm (FNV-1a/32 over the full generated name):
// generated = "app_organization_invitations_organization_id_email_expires_at_idx"
// (65 bytes) → base minus "_idx", cut to 50 bytes, + "_d28bd6a5_idx".
func TestSchemaFix_DatabaseIndexNameTruncationGolden(t *testing.T) {
	got := auth.GetDatabaseIndexName("app_organization_invitations", auth.TableIndex{
		Fields: []string{"organization_id", "email", "expires_at"},
	})
	want := "app_organization_invitations_organization_id_email_d28bd6a5_idx"
	if got != want {
		t.Fatalf("truncated index name:\n got %q\nwant %q", got, want)
	}
	if len(got) > 63 {
		t.Fatalf("truncated name exceeds 63 bytes: %d", len(got))
	}

	uidx := auth.GetDatabaseIndexName("app_organization_invitations", auth.TableIndex{
		Fields: []string{"organization_id", "email", "expires_at"},
		Unique: true,
	})
	if len(uidx) > 63 {
		t.Fatalf("truncated unique name exceeds 63 bytes: %q", uidx)
	}
	wantSuffix := "_uidx"
	if len(uidx) < len(wantSuffix) || uidx[len(uidx)-len(wantSuffix):] != wantSuffix {
		t.Fatalf("truncated unique name must keep _uidx suffix: %q", uidx)
	}
	// The kind tail must be replaced by the hash suffix, not merely cut:
	// base keeps the full column prefix minus "_uidx" (suffix is 14 bytes,
	// so the prefix is 63-14 = 49 bytes here).
	if uidx[:49] != "app_organization_invitations_organization_id_emai" {
		t.Fatalf("unique truncation must keep the column prefix: %q", uidx)
	}
}

// The index dedup key must not collide between one field "a,b" and two
// fields ["a","b"].
func TestSchemaFix_MergeTableIndexesNoFieldCollision(t *testing.T) {
	merged := auth.MergeTableIndexes(
		[]auth.TableIndex{{Fields: []string{"a,b"}}},
		[]auth.TableIndex{{Fields: []string{"a", "b"}}},
	)
	if len(merged) != 2 {
		t.Fatalf("distinct field tuples must not dedupe: %v", merged)
	}
	deduped := auth.MergeTableIndexes(
		[]auth.TableIndex{{Fields: []string{"a", "b"}}},
		[]auth.TableIndex{{Fields: []string{"a", "b"}}},
	)
	if len(deduped) != 1 {
		t.Fatalf("identical indexes must dedupe: %v", deduped)
	}
}

// CloneSchema must deep-copy nested References pointers and index field
// slices; hook funcs and func-valued DefaultValues stay shared (documented
// in CloneSchema: funcs cannot be cloned).
func TestSchemaFix_CloneSchemaDeepCopiesReferences(t *testing.T) {
	defaultFn := func() any { return "default" }
	onUpdate := func() any { return "updated" }
	schema := auth.PluginSchema{
		"session": {
			Fields: map[string]auth.FieldAttribute{
				"userId": {
					Type:         auth.FieldTypeString,
					References:   &auth.FieldReference{Model: "user", Field: "id", OnDelete: "cascade"},
					DefaultValue: defaultFn,
					OnUpdate:     onUpdate,
					Transform:    &types.FieldTransform{},
					Validator:    &types.FieldValidator{},
				},
			},
			Indexes: []auth.TableIndex{{Fields: []string{"userId"}}},
		},
	}
	cloned := auth.CloneSchema(schema)

	// Mutate the source through its nested pointers/slices.
	schema["session"].Fields["userId"].References.Model = "evil"
	schema["session"].Indexes[0].Fields[0] = "evil"

	got := cloned["session"].Fields["userId"]
	if got.References.Model != "user" {
		t.Fatalf("clone References must be independent: got %q", got.References.Model)
	}
	if cloned["session"].Indexes[0].Fields[0] != "userId" {
		t.Fatalf("clone index fields must be independent: got %q", cloned["session"].Indexes[0].Fields[0])
	}
	// Funcs stay shared by design.
	if reflect.ValueOf(got.DefaultValue).Pointer() != reflect.ValueOf(defaultFn).Pointer() {
		t.Fatal("func-valued DefaultValue must stay shared")
	}
	if reflect.ValueOf(got.OnUpdate).Pointer() != reflect.ValueOf(onUpdate).Pointer() {
		t.Fatal("OnUpdate must stay shared")
	}
	if got.Transform != schema["session"].Fields["userId"].Transform {
		t.Fatal("Transform must stay shared")
	}
	if got.Validator != schema["session"].Fields["userId"].Validator {
		t.Fatal("Validator must stay shared")
	}
}

// Ambiguous aliases must resolve deterministically (schema keys are scanned
// in sorted order).
func TestSchemaFix_AmbiguousAliasResolutionDeterministic(t *testing.T) {
	schema := auth.PluginSchema{
		"beta":  {ModelName: "shared"},
		"alpha": {ModelName: "shared"},
	}
	cfg := auth.AdapterConfig{}
	want, err := auth.GetDefaultModelName(schema, cfg, "shared")
	if err != nil {
		t.Fatalf("alias must resolve: %v", err)
	}
	if want != "alpha" {
		t.Fatalf("ambiguous alias must resolve to sorted-first key: got %q", want)
	}
	for i := 0; i < 50; i++ {
		got, err := auth.GetDefaultModelName(schema, cfg, "shared")
		if err != nil || got != want {
			t.Fatalf("alias resolution unstable on iteration %d: %q %v", i, got, err)
		}
	}
}

func boolPtrForTest(v bool) *bool { return &v }

func TestSchemaFix_DisableMigrationsPresenceLastWins(t *testing.T) {
	base := auth.PluginSchema{
		"m": {Fields: map[string]auth.FieldAttribute{"a": {Type: auth.FieldTypeString}}},
	}
	withTrue := auth.PluginSchema{
		"m": {Fields: map[string]auth.FieldAttribute{}, DisableMigrations: boolPtrForTest(true)},
	}
	withFalse := auth.PluginSchema{
		"m": {Fields: map[string]auth.FieldAttribute{}, DisableMigrations: boolPtrForTest(false)},
	}
	merged := auth.MergeSchemas(base, withTrue)
	if !merged["m"].DisableMigrationsEffective() {
		t.Fatal("explicit true must win")
	}
	merged = auth.MergeSchemas(merged, withFalse)
	if merged["m"].DisableMigrationsEffective() {
		t.Fatal("explicit false must win last-wins")
	}
	if merged["m"].DisableMigration {
		t.Fatal("legacy bool must sync from explicit false")
	}
	// Legacy true sticks for backwards compat.
	legacy := auth.PluginSchema{
		"m": {Fields: map[string]auth.FieldAttribute{}, DisableMigration: true},
	}
	mergedLegacy := auth.MergeSchemas(base, legacy)
	if !mergedLegacy["m"].DisableMigrationsEffective() {
		t.Fatal("legacy true must imply skip")
	}
}

func TestSchemaFix_SchemasForProvidersMergesArbitrary(t *testing.T) {
	p1 := &schemaFixPlugin{id: "p1", schema: auth.PluginSchema{
		"custom": {Fields: map[string]auth.FieldAttribute{"a": {Type: auth.FieldTypeString}}},
	}}
	p2 := &schemaFixPlugin{id: "p2", schema: auth.PluginSchema{
		"custom": {Fields: map[string]auth.FieldAttribute{"b": {Type: auth.FieldTypeString}}},
	}}
	merged := auth.SchemasForProviders([]auth.PluginSchemaProvider{p1, p2})
	fields := merged["custom"].Fields
	if _, ok := fields["a"]; !ok {
		t.Fatal("provider schemas must merge: missing a")
	}
	if _, ok := fields["b"]; !ok {
		t.Fatal("provider schemas must merge: missing b")
	}
}
