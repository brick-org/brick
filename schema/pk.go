package schema

import "maps"

// AutonameStrategy selects how a primary key value is produced at create time.
// The strategies mirror Frappe's autoname options so existing data keeps its
// primary keys during a migration.
type AutonameStrategy string

const (
	// AutonameUUID generates a random UUIDv4 (current Brick default).
	AutonameUUID AutonameStrategy = "uuid"
	// AutonameSeries uses a Frappe naming_series template, e.g.
	// "CRM-LEAD-.YYYY.-.#####" with a race-safe per-series counter.
	AutonameSeries AutonameStrategy = "naming_series"
	// AutonameFromField slugifies another field's value, appending -2, -3, …
	// on uniqueness collisions.
	AutonameFromField AutonameStrategy = "field"
	// AutonameFormat interpolates body fields into a template, e.g.
	// "SUB-{team}-{####}" where {####} is a per-prefix counter.
	AutonameFormat AutonameStrategy = "format"
	// AutonameHash generates N random lowercase base-36 characters.
	AutonameHash AutonameStrategy = "hash"
	// AutonamePrompt requires the client to send the PK in the create body.
	AutonamePrompt AutonameStrategy = "prompt"
	// AutonameAutoinc lets the database assign an auto-incrementing integer.
	AutonameAutoinc AutonameStrategy = "autoincrement"
)

// Autoname configures a PK generation strategy.
type Autoname struct {
	Strategy AutonameStrategy `json:"strategy,omitempty"`
	Template string           `json:"template,omitempty"` // series / format
	Source   string           `json:"source,omitempty"`   // field strategy
	HashLen  int              `json:"hashLen,omitempty"`  // hash strategy
}

// PK declares a resource's primary key column, type, and autoname strategy.
// When nil, Brick falls back to the legacy behaviour: a UUID "id" column.
type PK struct {
	Column   string    `json:"column"`
	Type     FieldType `json:"type"`
	Autoname Autoname  `json:"autoname"`
}

// ApplyPK sets the schema's PK and makes its column visible to the
// field-driven paths (readonly strip, codegen, list filters) without the
// caller declaring it twice. The Fields map is copied before mutation.
func (ds *DynamicSchema) ApplyPK(pk *PK) {
	ds.PK = pk
	if _, ok := ds.Fields[pk.Column]; ok {
		return
	}
	fields := make(Fields, len(ds.Fields)+1)
	maps.Copy(fields, ds.Fields)
	fd := &FieldDef{Type: pk.Type}
	if pk.Autoname.Strategy == AutonamePrompt {
		fd.IsRequired = true
	} else {
		fd.IsReadonly = true
	}
	fields[pk.Column] = fd
	ds.Fields = fields
}
