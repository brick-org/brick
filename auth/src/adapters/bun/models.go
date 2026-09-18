package bunadapter

import (
	"time"

	"github.com/uptrace/bun"
)

// Default core table models for the Bun adapter.
//
// Scope: these structs cover the default Better Auth core tables and columns
// only (see vendor/better-auth/packages/core/src/db/get-tables.ts). They do
// not model plugin tables/fields, additionalFields, custom ModelNames /
// FieldNames, secondary-storage inclusion rules, or optional schema changes;
// see auth/PARITY.md ("adapters/bun/models.go") for the tracked gaps. The
// live row-key contract (logical camelCase <-> physical snake_case mapping
// and the stable snake_case shape returned to callers) is owned by the
// Adapter in bun.go (encodeRow/decodeRow), not by these tags.
//
// Table identity: each struct embeds bun.BaseModel with an explicit
// table:<name> tag so schema/migration use does not depend on Bun's implicit
// inflection. The defaults (users/sessions/accounts/verifications) match the
// Adapter.table fallback (model + "s"); custom ModelNames are resolved at
// query time by Adapter.table and are out of scope here.
//
// Out of scope for these structs (owned by app code and cmd/generate-schema,
// which emits index comments): standalone indexes (e.g.
// verification.identifier, session.userId, account.userId), foreign-key
// relations and onDelete:cascade rules, and createdAt/updatedAt
// default/onUpdate population (callers set timestamps in route code).
//
// Note: Go field names here use UserID/URL-style initialisms, matching
// cmd/generate-schema's goFieldName helper, which emits the same identifiers
// for the same columns. Column tags are identical either way.

type User struct {
	bun.BaseModel `bun:"table:users"`
	ID            string    `bun:"id,pk"`
	Email         string    `bun:"email,unique,notnull"`
	EmailVerified bool      `bun:"email_verified,notnull,default:false"`
	Name          string    `bun:"name,notnull"`
	Image         *string   `bun:"image"`
	CreatedAt     time.Time `bun:"created_at,notnull"`
	UpdatedAt     time.Time `bun:"updated_at,notnull"`
}

type Session struct {
	bun.BaseModel `bun:"table:sessions"`
	ID            string    `bun:"id,pk"`
	UserID        string    `bun:"user_id,notnull"`
	Token         string    `bun:"token,unique,notnull"`
	ExpiresAt     time.Time `bun:"expires_at,notnull"`
	IPAddress     *string   `bun:"ip_address"`
	UserAgent     *string   `bun:"user_agent"`
	CreatedAt     time.Time `bun:"created_at,notnull"`
	UpdatedAt     time.Time `bun:"updated_at,notnull"`
}

type Account struct {
	bun.BaseModel         `bun:"table:accounts"`
	ID                    string     `bun:"id,pk"`
	UserID                string     `bun:"user_id,notnull"`
	ProviderID            string     `bun:"provider_id,notnull"`
	AccountID             string     `bun:"account_id,notnull"`
	AccessToken           *string    `bun:"access_token"`
	RefreshToken          *string    `bun:"refresh_token"`
	IDToken               *string    `bun:"id_token"`
	AccessTokenExpiresAt  *time.Time `bun:"access_token_expires_at"`
	RefreshTokenExpiresAt *time.Time `bun:"refresh_token_expires_at"`
	Scope                 *string    `bun:"scope"`
	Password              *string    `bun:"password"`
	CreatedAt             time.Time  `bun:"created_at,notnull"`
	UpdatedAt             time.Time  `bun:"updated_at,notnull"`
}

type Verification struct {
	bun.BaseModel `bun:"table:verifications"`
	ID            string    `bun:"id,pk"`
	Identifier    string    `bun:"identifier,notnull"`
	Value         string    `bun:"value,notnull"`
	ExpiresAt     time.Time `bun:"expires_at,notnull"`
	CreatedAt     time.Time `bun:"created_at,notnull"`
	UpdatedAt     time.Time `bun:"updated_at,notnull"`
}

// nowUTC is the defaultValue/onUpdate thunk for core timestamp fields,
// mirroring upstream's () => new Date() defaults.
func nowUTC() any { return time.Now().UTC() }

// DefaultModelDefs returns the field registry for the default core tables,
// mirroring the upstream core schema (packages/core/src/db/get-tables.ts):
// logical field types, required flags, unique markers (user.email,
// session.token), foreign-key references (session.userId and
// account.userId reference user.id), and createdAt/updatedAt
// defaultValue/onUpdate thunks.
//
// Pass it as Options.Models (via NewWithOptions) to enable strict
// model/field/value validation, factory-equivalent transforms, unique-aware
// Create fallback lookup, and registry-resolved joins. Keys are logical
// model and field names; physical mapping still flows through Config.
func DefaultModelDefs() map[string]ModelDef {
	userIDRef := &FieldReference{Model: "user", Field: "id"}
	return map[string]ModelDef{
		"user": {Fields: map[string]FieldDef{
			"id":            {Type: FieldTypeString},
			"name":          {Type: FieldTypeString, Required: true},
			"email":         {Type: FieldTypeString, Required: true, Unique: true},
			"emailVerified": {Type: FieldTypeBoolean, Required: true, DefaultValue: false},
			"image":         {Type: FieldTypeString},
			"createdAt":     {Type: FieldTypeDate, Required: true, DefaultValue: nowUTC},
			"updatedAt":     {Type: FieldTypeDate, Required: true, DefaultValue: nowUTC, OnUpdate: nowUTC},
		}},
		"session": {Fields: map[string]FieldDef{
			"id":        {Type: FieldTypeString},
			"userId":    {Type: FieldTypeString, Required: true, References: userIDRef},
			"token":     {Type: FieldTypeString, Required: true, Unique: true},
			"expiresAt": {Type: FieldTypeDate, Required: true},
			"ipAddress": {Type: FieldTypeString},
			"userAgent": {Type: FieldTypeString},
			"createdAt": {Type: FieldTypeDate, Required: true, DefaultValue: nowUTC},
			"updatedAt": {Type: FieldTypeDate, Required: true, DefaultValue: nowUTC, OnUpdate: nowUTC},
		}},
		"account": {Fields: map[string]FieldDef{
			"id":                    {Type: FieldTypeString},
			"userId":                {Type: FieldTypeString, Required: true, References: userIDRef},
			"providerId":            {Type: FieldTypeString, Required: true},
			"accountId":             {Type: FieldTypeString, Required: true},
			"accessToken":           {Type: FieldTypeString},
			"refreshToken":          {Type: FieldTypeString},
			"idToken":               {Type: FieldTypeString},
			"accessTokenExpiresAt":  {Type: FieldTypeDate},
			"refreshTokenExpiresAt": {Type: FieldTypeDate},
			"scope":                 {Type: FieldTypeString},
			"password":              {Type: FieldTypeString},
			"createdAt":             {Type: FieldTypeDate, Required: true, DefaultValue: nowUTC},
			"updatedAt":             {Type: FieldTypeDate, Required: true, DefaultValue: nowUTC, OnUpdate: nowUTC},
		}},
		"verification": {Fields: map[string]FieldDef{
			"id":         {Type: FieldTypeString},
			"identifier": {Type: FieldTypeString, Required: true},
			"value":      {Type: FieldTypeString, Required: true},
			"expiresAt":  {Type: FieldTypeDate, Required: true},
			"createdAt":  {Type: FieldTypeDate, Required: true, DefaultValue: nowUTC},
			"updatedAt":  {Type: FieldTypeDate, Required: true, DefaultValue: nowUTC, OnUpdate: nowUTC},
		}},
	}
}
