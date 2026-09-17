// Go DSL: typed resource definitions. Define + options are the only way
// to author resources: every former YAML key maps to a constructor or
// option here, checked by the compiler instead of a schema validator.
// Pair with ResourceDef.Validate (validate.go) for the semantic rules
// (field cross-references, PK strategy args, Frappe gating) and with
// dsl.Run to validate + emit DB/CRUD code into a main app's gen/ directory.
//
// Example:
//
//	def := schema.Define("deal", "deals", schema.Fields{
//		"title":  schema.String().Required().Searchable(),
//		"status": schema.Enum("open", "won", "lost").Default("open").Filterable(),
//		"value":  schema.Int().Default(0),
//	},
//		schema.WithTitle("title"),
//		schema.WithPK(schema.HashPK("name", 10)),
//	)
package schema

// Define builds a ResourceDef from a name, table, field map, and options.
// It never fails: semantic checks live in ResourceDef.Validate, run by
// dsl.Run (fail fast) or by hand. The DynamicSchema is created from
// fields (hidden derivation included); options then layer PK, parent,
// singleton, operations, and resource-level slots on top.
func Define(name, table string, fields Fields, opts ...ResourceOption) ResourceDef {
	def := ResourceDef{
		Name:   name,
		Table:  table,
		Schema: NewDynamicSchema(fields),
	}
	for _, opt := range opts {
		opt(&def)
	}
	return def
}

// ResourceOption mutates a ResourceDef under construction. Use the With*
// constructors; a raw func works for one-off slots.
type ResourceOption func(*ResourceDef)

// NewDynamicSchema builds a schema from fields, deriving HiddenFields the
// same way the runtime does (single source: both brick's Resource and the
// DSL share this, so hidden can never drift between definition and exec).
func NewDynamicSchema(fields Fields) *DynamicSchema {
	hidden := make([]string, 0)
	for name, def := range fields {
		if def.IsHidden {
			hidden = append(hidden, name)
		}
	}
	return &DynamicSchema{
		Fields:       fields,
		HiddenFields: hidden,
	}
}

// ─── ResourceDef-level options ──────────────────────────────────────────

// WithOperations sets which CRUD endpoints are registered (default: all).
// Build the value with DisableOps / OnlyOps.
func WithOperations(ops Operations) ResourceOption {
	return func(d *ResourceDef) { d.Operations = ops }
}

// WithLookup overrides the default "id" lookup column (slug/token resources).
func WithLookup(column string) ResourceOption {
	return func(d *ResourceDef) { d.LookupField = column }
}

// WithAutoCreate auto-creates a row on GET 404 (per-user settings pattern).
func WithAutoCreate() ResourceOption {
	return func(d *ResourceDef) { d.AutoCreate = true }
}

// WithPolyFKs declares polymorphic foreign keys on the resource.
func WithPolyFKs(fks ...PolyFKDef) ResourceOption {
	return func(d *ResourceDef) { d.PolyFKs = append(d.PolyFKs, fks...) }
}

// WithPK sets the primary key (replaces the default UUID "id") and injects
// its column into Fields via ApplyPK. Build with UUIDPK / SeriesPK /
// FieldPK / FormatPK / HashPK / PromptPK / AutoincPK.
func WithPK(pk *PK) ResourceOption {
	return func(d *ResourceDef) { d.Schema.ApplyPK(pk) }
}

// WithParent marks the resource as parent-owned and injects the parent FK
// column via ApplyParent. Build with NewParent.
func WithParent(p *ParentRef) ResourceOption {
	return func(d *ResourceDef) { d.Schema.ApplyParent(p) }
}

// WithSingleton declares a singleton and disables create/list/delete,
// matching the old YAML behavior (singletons never get those routes).
// Build with Singleton / ScopedSingleton.
func WithSingleton(sc *SingletonConfig) ResourceOption {
	return func(d *ResourceDef) {
		d.Schema.Singleton = sc
		d.Operations = d.Operations.withDisabled("create", "list", "delete")
	}
}

// ─── DynamicSchema passthrough options ──────────────────────────────────

// WithTenant scopes the resource to a team column (runtime guard input).
func WithTenant(column string) ResourceOption {
	return func(d *ResourceDef) { d.Schema.Tenant(column) }
}

// WithTitle records the display field (search results, OpenAPI descriptions).
func WithTitle(field string) ResourceOption {
	return func(d *ResourceDef) { d.Schema.Title(field) }
}

// WithUnique adds one composite uniqueness group over existing fields.
func WithUnique(columns ...string) ResourceOption {
	return func(d *ResourceDef) { d.Schema.Unique(columns...) }
}

// WithIndex adds one composite index group over existing fields.
func WithIndex(columns ...string) ResourceOption {
	return func(d *ResourceDef) { d.Schema.Index(columns...) }
}

// WithSoftDelete marks the logical-deletion timestamp column.
// Brick-owned tables only (Validate rejects tab* tables).
func WithSoftDelete(column string) ResourceOption {
	return func(d *ResourceDef) { d.Schema.SoftDelete(column) }
}

// WithAudit requests audit-trail hooks. Brick-owned tables only.
func WithAudit() ResourceOption {
	return func(d *ResourceDef) { d.Schema.Audit() }
}

// WithVersioned requests optimistic-lock version handling.
// Brick-owned tables only.
func WithVersioned() ResourceOption {
	return func(d *ResourceDef) { d.Schema.WithVersioned() }
}

// WithWritableOnUpdate restricts update writes to the named fields
// (approval-style flows). Empty means all non-readonly fields.
func WithWritableOnUpdate(fields ...string) ResourceOption {
	return func(d *ResourceDef) { d.Schema.WritableOnUpdate(fields...) }
}

// ─── Operations helpers ─────────────────────────────────────────────────

// DisableOps returns Operations with exactly the named operations off
// (get, list, create, update, delete). Unknown names are ignored.
func DisableOps(ops ...string) Operations {
	var o Operations
	return o.withDisabled(ops...)
}

func (o Operations) withDisabled(ops ...string) Operations {
	disabled := false
	for _, op := range ops {
		switch op {
		case "get":
			o.Get = &disabled
		case "list":
			o.List = &disabled
		case "create":
			o.Create = &disabled
		case "update":
			o.Update = &disabled
		case "delete":
			o.Delete = &disabled
		}
	}
	return o
}

// OnlyOps returns Operations with exactly the named operations on, the
// rest off — the typed form of the YAML allow-list (operations: [get, list]).
func OnlyOps(ops ...string) Operations {
	enabled := map[string]bool{}
	for _, op := range ops {
		enabled[op] = true
	}
	flag := func(name string) *bool {
		if enabled[name] {
			return nil
		}
		disabled := false
		return &disabled
	}
	return Operations{
		Get:    flag("get"),
		List:   flag("list"),
		Create: flag("create"),
		Update: flag("update"),
		Delete: flag("delete"),
	}
}

// ─── PK constructors ────────────────────────────────────────────────────
// Each bakes in the correct column type so invalid combinations (e.g. a
// hash PK on an int column) are unrepresentable. Strategy-specific args
// (template/source/length) are required parameters — the "strategy X
// requires Y" YAML errors cannot happen. A zero-value misuse (empty
// column) is still caught by Validate.

// UUIDPK is the Brick default: a random UUIDv4 column.
func UUIDPK(column string) *PK {
	return &PK{Column: column, Type: FieldUUID, Autoname: Autoname{Strategy: AutonameUUID}}
}

// SeriesPK uses a Frappe naming_series template, e.g. "CRM-LEAD-.YYYY.-.#####".
func SeriesPK(column, template string) *PK {
	return &PK{Column: column, Type: FieldString, Autoname: Autoname{Strategy: AutonameSeries, Template: template}}
}

// FieldPK slugifies another field's value, appending -2, -3, … on collisions.
func FieldPK(column, source string) *PK {
	return &PK{Column: column, Type: FieldString, Autoname: Autoname{Strategy: AutonameFromField, Source: source}}
}

// FormatPK interpolates body fields into a template, e.g. "SUB-{team}-{####}".
func FormatPK(column, template string) *PK {
	return &PK{Column: column, Type: FieldString, Autoname: Autoname{Strategy: AutonameFormat, Template: template}}
}

// HashPK generates length random lowercase base-36 characters.
func HashPK(column string, length int) *PK {
	return &PK{Column: column, Type: FieldString, Autoname: Autoname{Strategy: AutonameHash, HashLen: length}}
}

// PromptPK requires the client to send the PK in the create body.
func PromptPK(column string) *PK {
	return &PK{Column: column, Type: FieldString, Autoname: Autoname{Strategy: AutonamePrompt}}
}

// AutoincPK lets the database assign an auto-incrementing integer (bigint).
func AutoincPK(column string) *PK {
	return &PK{Column: column, Type: FieldInt, Autoname: Autoname{Strategy: AutonameAutoinc}}
}

// ─── Parent / singleton / poly-FK constructors ──────────────────────────

// NewParent declares parent ownership: rows embed in the parent's API
// shape. onDelete is optional (Cascade, SetNull, Restrict; default "").
func NewParent(resource string, onDelete ...OnDeleteAction) *ParentRef {
	p := &ParentRef{Resource: resource}
	if len(onDelete) > 0 {
		p.OnDelete = onDelete[0]
	}
	return p
}

// Singleton declares a global singleton (one row, accessed by name).
func Singleton() *SingletonConfig {
	return &SingletonConfig{Enabled: true}
}

// ScopedSingleton declares a per-scope singleton (e.g. one row per team).
// model is the optional FK target of the scope column.
func ScopedSingleton(column, model string) *SingletonConfig {
	return &SingletonConfig{Enabled: true, Scope: &ScopeConfig{Column: column, Model: model}}
}

// NewPolyFK declares a polymorphic foreign key: idField holds the row id,
// typeField names the target resource (restricted to allowed). onDelete is
// optional (Cascade, SetNull, SetDefault, Restrict, NoAction; default "").
func NewPolyFK(idField, typeField string, allowed []string, onDelete ...OnDeleteAction) PolyFKDef {
	fk := PolyFKDef{
		IDField:        idField,
		TypeField:      typeField,
		AllowedTargets: allowed,
	}
	if len(onDelete) > 0 {
		fk.OnDelete = onDelete[0]
	}
	return fk
}
