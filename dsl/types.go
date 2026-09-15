// Package dsl defines the YAML resource DSL types and parser/loader.
//
// A .resource.yaml file describes a single brick resource — its identity,
// database table, field schema, CRUD operations, access controls, and
// polymorphic foreign keys.
//
// Editor support: add this at the top of every .resource.yaml file:
//
//	# yaml-language-server: $schema=https://raw.githubusercontent.com/brick-org/brick/main/schemas/resource.schema.json
//
// Example:
//
//	# yaml-language-server: $schema=https://raw.githubusercontent.com/brick-org/brick/main/schemas/resource.schema.json
//	name: deal
//	table: deals
//	fields:
//	  id:   { type: uuid, readonly: true }
//	  name: { type: string, required: true, searchable: true }
package dsl

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// ResourceFile is the YAML representation of a brick resource.
// Access controls and hooks are set in resources.go, not here.
type ResourceFile struct {
	Name    string         `yaml:"name"`
	Table   string         `yaml:"table"`
	Ops     OperationFlags `yaml:"operations,omitempty"`
	Fields  Fields         `yaml:"fields"`
	PolyFKs []PolyFKDef    `yaml:"polymorphic,omitempty"`
	// LookupField overrides the default "id" lookup column (used for
	// resources accessed by slug or token).
	LookupField string `yaml:"lookup_field,omitempty"`
	// AutoCreate, when true, auto-creates a row on GET 404 (pattern:
	// per-user settings / per-deal config singletons).
	AutoCreate bool `yaml:"auto_create,omitempty"`
	// PK overrides the default UUID "id" primary key with a configurable
	// column + autoname strategy (Frappe-style string PKs).
	PK *PKDef `yaml:"pk,omitempty"`
	// Parent marks this resource as a child table owned by another resource.
	// A parent_id FK column is injected automatically.
	Parent *ParentDef `yaml:"parent,omitempty"`
	// Singleton, when non-nil, declares a singleton resource (accessed by
	// name, not ID). Only GET + PATCH routes are registered. Boolean true
	// for global singletons; object for scoped singletons.
	Singleton any `yaml:"singleton,omitempty"`
	// Tenant names the team-scoping column. The runtime generates the
	// equivalent of a team-membership guard from it. Must name a
	// declared field.
	Tenant string `yaml:"tenant,omitempty"`
	// Title names the display field, used for search results and
	// OpenAPI descriptions. Must name a declared field.
	Title string `yaml:"title,omitempty"`
	// Uniques lists composite uniqueness groups, e.g. [[team, label]].
	// Every entry must name declared fields.
	Uniques [][]string `yaml:"unique,omitempty"`
	// Indexes lists composite index groups, e.g. [[owner, status]].
	// Every entry must name declared fields.
	Indexes [][]string `yaml:"indexes,omitempty"`
	// SoftDelete names a nullable timestamp column marking logical
	// deletion. Brick-owned tables only (rejected for tab* tables).
	SoftDelete string `yaml:"soft_delete,omitempty"`
	// Audited / Versioned request audit-trail and optimistic-lock
	// behavior. Brick-owned tables only.
	Audited   bool `yaml:"audit,omitempty"`
	Versioned bool `yaml:"versioned,omitempty"`
	// WritableOnUpdate allowlists fields writable on update when set
	// (approval-style flows). Each must name a declared non-readonly
	// field. Empty means all non-readonly fields.
	WritableOnUpdate []string `yaml:"writable_on_update,omitempty"`
}

// ParentDef declares parent ownership for a child resource.
type ParentDef struct {
	Resource string `yaml:"resource"`
	OnDelete string `yaml:"on_delete,omitempty"` // CASCADE, SET NULL, RESTRICT
}

// PKDef declares the primary key column and autoname strategy.
type PKDef struct {
	Column string `yaml:"column"`
	// Strategy: uuid, naming_series, field, format, hash, prompt, autoincrement.
	Strategy string `yaml:"strategy"`
	Template string `yaml:"template,omitempty"` // naming_series / format
	Source   string `yaml:"source,omitempty"`   // field
	Length   int    `yaml:"length,omitempty"`   // hash
}

// validOperations is the set of legal operation names, in both the
// deny-map and allow-list forms of `operations:`.
var validOperations = map[string]bool{
	"get": true, "list": true, "create": true, "update": true, "delete": true,
}

// OperationFlags controls which CRUD endpoints are registered.
// Each field is a bool pointer: nil = enabled (default), &false = disabled.
//
// Two YAML forms are accepted. Deny-map (default-deny nothing):
//
//	operations:
//	  create: false
//	  update: false
//
// Allow-list (everything unlisted is disabled):
//
//	operations: [get, list]
type OperationFlags struct {
	Get    *bool `yaml:"get,omitempty"`
	List   *bool `yaml:"list,omitempty"`
	Create *bool `yaml:"create,omitempty"`
	Update *bool `yaml:"update,omitempty"`
	Delete *bool `yaml:"delete,omitempty"`

	// allowlist records the sequence form. Non-empty means "enable only
	// these"; the *bool slots are then ignored.
	allowlist []string
}

// UnmarshalYAML accepts the deny-map or the allow-list sequence form.
// KnownFields(true) does not inspect nodes with a custom unmarshaler,
// so map keys are validated here.
func (o *OperationFlags) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.SequenceNode {
		var names []string
		if err := value.Decode(&names); err != nil {
			return fmt.Errorf("dsl: operations: %w", err)
		}
		for _, n := range names {
			if !validOperations[n] {
				return fmt.Errorf("dsl: operations: unknown operation %q (valid: get, list, create, update, delete)", n)
			}
		}
		o.allowlist = names
		return nil
	}
	raw := map[string]*bool{}
	if err := value.Decode(&raw); err != nil {
		return fmt.Errorf("dsl: operations: %w", err)
	}
	for k, v := range raw {
		if !validOperations[k] {
			return fmt.Errorf("dsl: operations: unknown operation %q (valid: get, list, create, update, delete)", k)
		}
		switch k {
		case "get":
			o.Get = v
		case "list":
			o.List = v
		case "create":
			o.Create = v
		case "update":
			o.Update = v
		case "delete":
			o.Delete = v
		}
	}
	return nil
}

// Fields maps field names onto their definitions.
type Fields map[string]*FieldDef

// FieldDef describes a single column/field on a resource.
type FieldDef struct {
	// Type is the brick field type: uuid, string, text, int, float, bool,
	// timestamp, json, enum, foreign, or children. The legacy alias
	// "foreignkey" is accepted and normalized to "foreign".
	Type string `yaml:"type"`

	// --- Nullability ---
	Required bool `yaml:"required,omitempty"`
	Optional bool `yaml:"optional,omitempty"` // explicit nullable

	// --- Constraints ---
	Unique    bool `yaml:"unique,omitempty"`
	MaxLength int  `yaml:"max_length,omitempty"`

	// --- Default value ---
	Default any `yaml:"default,omitempty"`

	// --- Type-specific ---
	Email    bool     `yaml:"email,omitempty"`     // for string
	Values   []string `yaml:"values,omitempty"`    // for enum
	Model    string   `yaml:"model,omitempty"`     // for foreign (target resource name)
	OnDelete string   `yaml:"on_delete,omitempty"` // CASCADE, SET NULL, RESTRICT
	Of       string   `yaml:"of,omitempty"`        // for children (child resource name)
	OrderBy  string   `yaml:"order_by,omitempty"`  // for children (sort column)

	// --- Brick modifiers ---
	Searchable bool `yaml:"searchable,omitempty"`
	Filterable bool `yaml:"filterable,omitempty"`
	Sortable   bool `yaml:"sortable,omitempty"`
	Readonly   bool `yaml:"readonly,omitempty"`
	Hidden     bool `yaml:"hidden,omitempty"`
	Index      bool `yaml:"index,omitempty"`

	// --- Context binding ---
	// From resolves the field value from the request context at create time.
	// Path is dot-separated, e.g. "session.activeOrganizationId".
	// Fields with from are implicitly readonly.
	From string `yaml:"from,omitempty"`
}

// PolyFKDef declares a polymorphic foreign key relationship.
// The owning resource has two columns: TypeField ("deals" or "documents")
// and IDField (the target row's primary key).
type PolyFKDef struct {
	IDField   string   `yaml:"id_field"`
	TypeField string   `yaml:"type_field"`
	Allowed   []string `yaml:"allowed"`
	OnDelete  string   `yaml:"on_delete,omitempty"` // CASCADE, SET NULL, SET DEFAULT, RESTRICT, NO ACTION
}
