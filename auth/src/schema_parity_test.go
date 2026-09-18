package auth_test

import (
	"testing"

	auth "github.com/brick-org/brick/auth/src"
)

// parityPlugin is a minimal auth.Plugin stub for schema-resolution tests.
type parityPlugin struct {
	id     string
	schema auth.PluginSchema
}

func (p *parityPlugin) ID() string { return p.id }

func (p *parityPlugin) Init(_ auth.AuthContext) error { return nil }

func (p *parityPlugin) Endpoints() []auth.Endpoint { return nil }

func (p *parityPlugin) Schema() auth.PluginSchema { return p.schema }

func (p *parityPlugin) Hooks() auth.DBHooks { return nil }

func (p *parityPlugin) RouteHooks() auth.PluginRouteHooks { return auth.PluginRouteHooks{} }

func (p *parityPlugin) ErrorCodes() map[string]string { return nil }

func TestSchemaParity_CoreTablesPresent(t *testing.T) {
	tables := auth.GetAuthTables(auth.Options{})
	for _, model := range []string{"user", "session", "account", "verification"} {
		if _, ok := tables[model]; !ok {
			t.Fatalf("GetAuthTables missing core table %q", model)
		}
	}
	userFields := tables["user"].Fields
	for _, field := range []string{"email", "emailVerified", "createdAt"} {
		if _, ok := userFields[field]; !ok {
			t.Fatalf("core user table missing field %q", field)
		}
	}
	if !tables["user"].Fields["email"].Unique {
		t.Fatal("core user.email must be unique")
	}
}

func TestSchemaParity_PluginFieldsMergeOverCore(t *testing.T) {
	plugin := &parityPlugin{
		id: "test",
		schema: auth.PluginSchema{
			"user": {Fields: map[string]auth.FieldAttribute{
				"role": {Type: auth.FieldTypeString},
			}},
			"organization": {Fields: map[string]auth.FieldAttribute{
				"name": {Type: auth.FieldTypeString},
			}},
		},
	}
	tables := auth.GetAuthTables(auth.Options{Plugins: []auth.Plugin{plugin}})
	if _, ok := tables["user"].Fields["role"]; !ok {
		t.Fatal("plugin user extension must merge over the core table")
	}
	if _, ok := tables["user"].Fields["email"]; !ok {
		t.Fatal("core user fields must survive plugin merge")
	}
	if _, ok := tables["organization"]; !ok {
		t.Fatal("plugin tables must be included")
	}
	// ResolveSchema stays compatible with the full table set.
	resolved := auth.ResolveSchema(auth.Options{Plugins: []auth.Plugin{plugin}})
	if _, ok := resolved["organization"]; !ok {
		t.Fatal("ResolveSchema must include plugin tables")
	}
}

func TestSchemaParity_SecondaryStorageInclusionRules(t *testing.T) {
	// No secondary storage → session and verification are included.
	full := auth.GetAuthTablesWithSecondaryStorage(auth.Options{}, false, false, false)
	if _, ok := full["session"]; !ok {
		t.Fatal("session must be included without secondary storage")
	}
	if _, ok := full["verification"]; !ok {
		t.Fatal("verification must be included without secondary storage")
	}
	// Secondary storage without database overrides → both omitted
	// (mirrors get-tables.ts spread conditionals).
	secondary := auth.GetAuthTablesWithSecondaryStorage(auth.Options{}, true, false, false)
	if _, ok := secondary["session"]; ok {
		t.Fatal("session must be omitted under secondary storage without storeSessionInDatabase")
	}
	if _, ok := secondary["verification"]; ok {
		t.Fatal("verification must be omitted under secondary storage without storeVerificationInDatabase")
	}
	kept := auth.GetAuthTablesWithSecondaryStorage(auth.Options{}, true, true, true)
	if _, ok := kept["session"]; !ok {
		t.Fatal("storeSessionInDatabase must keep the session table")
	}
	if _, ok := kept["verification"]; !ok {
		t.Fatal("storeVerificationInDatabase must keep the verification table")
	}
	if !auth.ShouldIncludeSessionTable(false, false) || auth.ShouldIncludeSessionTable(true, false) {
		t.Fatal("ShouldIncludeSessionTable must mirror the TS conditional")
	}
	if !auth.ShouldIncludeVerificationTable(false, false) || auth.ShouldIncludeVerificationTable(true, false) {
		t.Fatal("ShouldIncludeVerificationTable must mirror the TS conditional")
	}
}

func TestSchemaParity_RateLimitTable(t *testing.T) {
	if !auth.ShouldAddRateLimitTable("database") {
		t.Fatal("storage=database must add the rate-limit table")
	}
	if auth.ShouldAddRateLimitTable("memory") || auth.ShouldAddRateLimitTable("") {
		t.Fatal("non-database storage must not add the rate-limit table")
	}
	tables := auth.GetAuthTables(auth.Options{})
	if _, ok := tables["rateLimit"]; ok {
		t.Fatal("rateLimit table must be excluded by default (no storage slot in Options)")
	}
	withRL := auth.GetAuthTablesWithRateLimit(auth.Options{}, "database")
	rl, ok := withRL["rateLimit"]
	if !ok {
		t.Fatal("GetAuthTablesWithRateLimit(database) must include rateLimit")
	}
	for _, field := range []string{"key", "count", "lastRequest"} {
		if _, ok := rl.Fields[field]; !ok {
			t.Fatalf("rateLimit table missing field %q", field)
		}
	}
}

func TestSchemaParity_ConfiguredNames(t *testing.T) {
	cfg := auth.AdapterConfig{
		ModelNames: map[string]string{"user": "app_users"},
		FieldNames: map[string]string{"user.email": "email_address"},
	}
	if got := auth.ResolveTableName("user", cfg); got != "app_users" {
		t.Fatalf("ResolveTableName custom: got %q", got)
	}
	if got := auth.ResolveTableName("session", cfg); got != "sessions" {
		t.Fatalf("ResolveTableName plural fallback: got %q", got)
	}
	if got := auth.ResolveColumnName("user", "email", cfg); got != "email_address" {
		t.Fatalf("ResolveColumnName custom: got %q", got)
	}
	if got := auth.ResolveColumnName("user", "userId", cfg); got != "user_id" {
		t.Fatalf("ResolveColumnName snake fallback: got %q", got)
	}
}

func TestSchemaParity_GetDefaultModelName(t *testing.T) {
	schema := auth.GetAuthTables(auth.Options{})
	cfg := auth.AdapterConfig{ModelNames: map[string]string{"user": "app_users"}}
	// Exact schema-key matches win over ModelName aliases (upstream #8111).
	got, err := auth.GetDefaultModelName(schema, cfg, "user")
	if err != nil || got != "user" {
		t.Fatalf("exact key must win: %q %v", got, err)
	}
	got, err = auth.GetDefaultModelName(schema, cfg, "app_users")
	if err != nil || got != "user" {
		t.Fatalf("alias must resolve to canonical key: %q %v", got, err)
	}
	if _, err := auth.GetDefaultModelName(schema, cfg, "nope"); err == nil {
		t.Fatal("unknown model must error")
	}
	if got := auth.GetFieldName("user", "email", auth.AdapterConfig{FieldNames: map[string]string{"user.email": "email_address"}}); got != "email_address" {
		t.Fatalf("GetFieldName: got %q", got)
	}
}

func TestSchemaParity_Indexes(t *testing.T) {
	if len(auth.CoreTableIndexes()) == 0 {
		t.Fatal("core index metadata must not be empty")
	}
	merged := auth.MergeTableIndexes(
		[]auth.TableIndex{{Fields: []string{"a"}}},
		[]auth.TableIndex{{Fields: []string{"a"}}},
		[]auth.TableIndex{{Fields: []string{"b"}, Unique: true}},
	)
	if len(merged) != 2 {
		t.Fatalf("MergeTableIndexes must dedupe: %v", merged)
	}
	name := auth.GetDatabaseIndexName("users", auth.TableIndex{Fields: []string{"email"}, Unique: true})
	if name != "users_email_uidx" {
		t.Fatalf("generated index name: got %q", name)
	}
	explicit := auth.GetDatabaseIndexName("users", auth.TableIndex{Fields: []string{"email"}, Name: "custom_idx"})
	if explicit != "custom_idx" {
		t.Fatalf("explicit index name must be preserved: got %q", explicit)
	}
	tables, indexes := auth.GetAuthTablesWithResolvedIndexes(auth.Options{}, auth.AdapterConfig{})
	if len(tables) == 0 {
		t.Fatal("resolved tables must not be empty")
	}
	if len(indexes) == 0 {
		t.Fatal("resolved indexes must include core metadata")
	}
}

// paritySecondaryStorage is a minimal SecondaryStorage stub so table
// inclusion rules can be exercised through Options directly.
type paritySecondaryStorage struct{}

func (paritySecondaryStorage) Get(key string) (any, error) { return nil, nil }

func (paritySecondaryStorage) GetAndDelete(key string) (any, error) { return nil, nil }

func (paritySecondaryStorage) Increment(key string, ttl int) (int64, error) { return 1, nil }

func (paritySecondaryStorage) Set(key, value string, ttl *int) error { return nil }

func (paritySecondaryStorage) Delete(key string) error { return nil }

func TestSchemaParity_ModelOptionsHonored(t *testing.T) {
	falseVal := false
	opts := auth.Options{}
	opts.User.Model.ModelName = "app_users"
	opts.User.Model.Fields = map[string]string{"email": "email_address"}
	opts.User.Model.AdditionalFields = map[string]auth.FieldAttribute{
		"role": {Type: auth.FieldTypeString, Required: &falseVal},
	}
	tables := auth.GetAuthTables(opts)
	user := tables["user"]
	if user.ModelName != "app_users" {
		t.Fatalf("user ModelName: got %q", user.ModelName)
	}
	if user.Fields["email"].FieldName != "email_address" {
		t.Fatalf("user email FieldName: got %q", user.Fields["email"].FieldName)
	}
	if _, ok := user.Fields["role"]; !ok {
		t.Fatal("user additionalFields must merge into the core table")
	}
	if _, ok := user.Fields["name"]; !ok {
		t.Fatal("core user fields must survive model options")
	}
	if got := auth.PhysicalTableName("user", user, auth.AdapterConfig{}); got != "app_users" {
		t.Fatalf("PhysicalTableName must honor ModelName: got %q", got)
	}
	if got := auth.PhysicalColumnName("user", user, "email", auth.AdapterConfig{}); got != "email_address" {
		t.Fatalf("PhysicalColumnName must honor FieldName: got %q", got)
	}
}

func TestSchemaParity_OptionsSecondaryStorage(t *testing.T) {
	opts := auth.Options{SecondaryStorage: paritySecondaryStorage{}}
	tables := auth.GetAuthTables(opts)
	if _, ok := tables["session"]; ok {
		t.Fatal("session must be omitted when SecondaryStorage is set")
	}
	if _, ok := tables["verification"]; ok {
		t.Fatal("verification must be omitted when SecondaryStorage is set")
	}
	opts.Session.StoreSessionInDatabase = true
	opts.Verification.StoreInDatabase = true
	kept := auth.GetAuthTables(opts)
	if _, ok := kept["session"]; !ok {
		t.Fatal("StoreSessionInDatabase must keep the session table")
	}
	if _, ok := kept["verification"]; !ok {
		t.Fatal("StoreInDatabase must keep the verification table")
	}
}

func TestSchemaParity_OptionsRateLimitStorage(t *testing.T) {
	opts := auth.Options{}
	opts.RateLimit.Storage = "database"
	opts.RateLimit.ModelName = "app_rate_limits"
	opts.RateLimit.Fields = map[string]string{"key": "rl_key"}
	tables := auth.GetAuthTables(opts)
	rl, ok := tables["rateLimit"]
	if !ok {
		t.Fatal("rateLimit table must be included when Storage=database")
	}
	if rl.ModelName != "app_rate_limits" {
		t.Fatalf("rateLimit ModelName: got %q", rl.ModelName)
	}
	if rl.Fields["key"].FieldName != "rl_key" {
		t.Fatalf("rateLimit key FieldName: got %q", rl.Fields["key"].FieldName)
	}
}
