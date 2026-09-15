package schema

// SingletonConfig declares that a resource is a singleton: one row per table
// (or per scope), accessed by name, not ID.
type SingletonConfig struct {
	Enabled bool
	// Scope, when non-nil, means one row per scope value, e.g. one per team.
	// The route becomes GET /api/{scope}/{scope_value}/settings/{name}.
	Scope *ScopeConfig
}

// ScopeConfig defines a per-scope singleton key.
type ScopeConfig struct {
	Column string `json:"column"`
	Model  string `json:"model,omitempty"` // foreign key target (optional)
}
