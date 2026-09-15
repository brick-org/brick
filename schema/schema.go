package schema

type FieldType string

const (
	FieldString    FieldType = "string"
	FieldText      FieldType = "text"
	FieldInt       FieldType = "int"
	FieldFloat     FieldType = "float"
	FieldBool      FieldType = "bool"
	FieldTimestamp FieldType = "timestamp"
	FieldUUID      FieldType = "uuid"
	FieldJSON      FieldType = "json"
	FieldEnum      FieldType = "enum"
	FieldForeign   FieldType = "foreignkey"
	FieldChildren  FieldType = "children"
)

type OnDeleteAction string

const (
	Cascade    OnDeleteAction = "CASCADE"
	SetNull    OnDeleteAction = "SET NULL"
	SetDefault OnDeleteAction = "SET DEFAULT"
	Restrict   OnDeleteAction = "RESTRICT"
	NoAction   OnDeleteAction = "NO ACTION"
)

type FieldDef struct {
	Type         FieldType      `json:"type"`
	IsRequired   bool           `json:"required,omitempty"`
	IsOptional   bool           `json:"optional,omitempty"`
	IsUnique     bool           `json:"unique,omitempty"`
	DefaultValue any            `json:"default,omitempty"`
	MaxLength    int            `json:"maxLength,omitempty"`
	IsEmail      bool           `json:"email,omitempty"`
	IsHidden     bool           `json:"hidden,omitempty"`
	IsReadonly   bool           `json:"readonly,omitempty"`
	IsSearchable bool           `json:"searchable,omitempty"`
	IsFilterable bool           `json:"filterable,omitempty"`
	IsSortable   bool           `json:"sortable,omitempty"`
	IsIndex      bool           `json:"index,omitempty"`
	EnumValues   []string       `json:"enumValues,omitempty"`
	ForeignModel string         `json:"foreignModel,omitempty"`
	OnDeleteAct  OnDeleteAction `json:"onDelete,omitempty"`
	FromSource   string         `json:"from,omitempty"`
	ChildrenOf   string         `json:"childrenOf,omitempty"`   // children: child resource name
	ChildOrderBy string         `json:"childOrderBy,omitempty"` // children: sort column
	// IsComputed marks a response-only field whose value is derived
	// server-side (never stored, never accepted on write). Evaluation is
	// app-side (M5 hook); the schema layer only carries the marker so
	// codegen excludes it from create/update bodies.
	IsComputed bool `json:"computed,omitempty"`
	// NormalizeWith names a normalization rule applied before validation
	// (e.g. "email"). Rules are app-defined; the schema layer only carries
	// the name so validation (M5) can dispatch on it.
	NormalizeWith string `json:"normalize,omitempty"`
}

type Fields map[string]*FieldDef

type Map map[string]any

type Operations struct {
	List   *bool
	Get    *bool
	Create *bool
	Update *bool
	Delete *bool
}

// Enabled reports whether an operation is on. A nil slot means enabled
// (opt-out, matching the YAML `operations:` map where only `false`
// entries are written).
func (o Operations) Enabled(op string) bool {
	var slot *bool
	switch op {
	case "list":
		slot = o.List
	case "get":
		slot = o.Get
	case "create":
		slot = o.Create
	case "update":
		slot = o.Update
	case "delete":
		slot = o.Delete
	default:
		return false
	}
	return slot == nil || *slot
}

type Schema[Row any, CreateBody any, UpdateBody any] struct {
	Fields       Fields
	HiddenFields []string
	Operations   Operations
	Access       any
	Hooks        any
}

type DynamicSchema struct {
	Fields       Fields
	HiddenFields []string
	Operations   Operations
	Access       any
	Hooks        any
	PK           *PK
	Parent       *ParentRef
	Singleton    *SingletonConfig
	// TenantColumn names the team-scoping column (YAML `tenant:`). M5
	// generates the equivalent of an InSelectedTeam guard from it.
	// Empty means unscoped (auth-only).
	TenantColumn string `json:"tenantColumn,omitempty"`
	// TitleField names the display field (YAML `title:`), used for search
	// results and OpenAPI descriptions.
	TitleField string `json:"titleField,omitempty"`
	// CompositeUniques holds multi-column uniqueness groups
	// (YAML `unique: [[a, b]]`). Enforced via BusinessIndexes + a
	// validation pre-check; races still resolve to 409 on 23505.
	CompositeUniques [][]string `json:"compositeUniques,omitempty"`
	// CompositeIndexes holds multi-column index groups
	// (YAML `indexes: [[a, b]]`), emitted by BusinessIndexes.
	CompositeIndexes [][]string `json:"compositeIndexes,omitempty"`
	// SoftDeleteColumn names a nullable timestamp marking logical
	// deletion (YAML `soft_delete:`). Brick-owned tables only — rejected
	// for `tab*` tables at DSL validation time.
	SoftDeleteColumn string `json:"softDeleteColumn,omitempty"`
	// Audited / Versioned request audit-trail and optimistic-lock
	// behavior (YAML `audit: true`, `versioned: true`). Lowered to M5
	// hooks; brick-owned tables only.
	Audited   bool `json:"audited,omitempty"`
	Versioned bool `json:"versioned,omitempty"`
	// UpdateWritable allowlists fields writable on update when set
	// (YAML `writable_on_update: [...]`, approval-style flows).
	// Empty means all non-readonly fields.
	UpdateWritable []string `json:"updateWritable,omitempty"`
}

// Tenant scopes the resource to a team column (e.g. "team"). The guard
// itself is generated at runtime (M5); this only records the column.
func (ds *DynamicSchema) Tenant(column string) *DynamicSchema {
	ds.TenantColumn = column
	return ds
}

// Title records the display field (e.g. "label").
func (ds *DynamicSchema) Title(field string) *DynamicSchema {
	ds.TitleField = field
	return ds
}

// Unique adds a composite uniqueness group over existing fields.
func (ds *DynamicSchema) Unique(columns ...string) *DynamicSchema {
	ds.CompositeUniques = append(ds.CompositeUniques, columns)
	return ds
}

// Index adds a composite index group over existing fields.
func (ds *DynamicSchema) Index(columns ...string) *DynamicSchema {
	ds.CompositeIndexes = append(ds.CompositeIndexes, columns)
	return ds
}

// SoftDelete marks the logical-deletion timestamp column.
func (ds *DynamicSchema) SoftDelete(column string) *DynamicSchema {
	ds.SoftDeleteColumn = column
	return ds
}

// Audit requests audit-trail hooks for the resource.
func (ds *DynamicSchema) Audit() *DynamicSchema {
	ds.Audited = true
	return ds
}

// WithVersioned requests optimistic-lock version handling.
func (ds *DynamicSchema) WithVersioned() *DynamicSchema {
	ds.Versioned = true
	return ds
}

// WritableOnUpdate restricts update writes to the named fields.
func (ds *DynamicSchema) WritableOnUpdate(fields ...string) *DynamicSchema {
	ds.UpdateWritable = append(ds.UpdateWritable, fields...)
	return ds
}

// PolyFKDef declares a polymorphic foreign key: IDField holds the row id,
// TypeField names the target resource, restricted to AllowedTargets.
// OnDelete applies when a referenced row is deleted.
type PolyFKDef struct {
	TypeField      string         `json:"typeField"`
	IDField        string         `json:"idField"`
	AllowedTargets []string       `json:"allowedTargets,omitempty"`
	OnDelete       OnDeleteAction `json:"onDelete,omitempty"`
}

// ResourceDef is the DSL output contract: everything codegen and the
// runtime need about one resource. It replaces the beta pair
// (brick.ResourceConfig, codegen.ResourceDef) so the DSL never imports
// the M5 runtime.
type ResourceDef struct {
	Name       string
	Table      string
	Schema     *DynamicSchema
	Operations Operations
	PolyFKs    []PolyFKDef
	// LookupField overrides the default "id" lookup column (slug/token
	// resources). Consumed by M5 route registration.
	LookupField string
	// AutoCreate auto-creates a row on GET 404. Consumed by M5.
	AutoCreate bool
}
