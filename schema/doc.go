// Package schema is brick's in-code resource vocabulary: field types,
// chainable field builders, PK strategies, and the ResourceDef contract
// that the DSL (brick/dsl) produces and codegen (brick/codegen) consumes.
//
// Field schemas for shared Frappe tables are authored in
// dsl/*.resource.yaml; this package is the typed form of that surface.
// Keep the two in sync: every YAML key maps to a FieldDef flag or a
// DynamicSchema slot, and codegen emits builder chains from this package.
package schema
