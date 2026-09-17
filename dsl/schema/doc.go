// Package schema is brick's in-code resource vocabulary: typed resource
// definitions (Define + options, define.go), validation (validate.go),
// field types, chainable field builders, PK strategies, and the
// ResourceDef contract that the DSL produces and codegen consumes.
//
// Codegen emits builder chains from this package, so generated
// SchemaFields read like hand-written definitions.
package schema
