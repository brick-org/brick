package auth

import (
	authcontext "github.com/brick-org/brick/auth/src/context"
	"github.com/brick-org/brick/auth/src/types"
)

// Thin shim over auth/src/context/secret-utils.go.
const DefaultSecret = types.DefaultSecret

// SecretConfig re-exports the versioned secret config.
type SecretConfig = types.SecretConfig

// PluginInitPatch re-exports the init option/context patch shape.
type PluginInitPatch = types.PluginInitPatch

// PluginInitPatches re-exports the optional init-patch interface.
type PluginInitPatches = types.PluginInitPatches

// ParseSecretsEnv parses BETTER_AUTH_SECRETS ("<version>:<secret>,...") into
// versioned secrets. Delegates to context.ParseSecretsEnv.
// Upstream TypeScript name: parseSecretsEnv.
func ParseSecretsEnv(envValue string) ([]Secret, error) {
	return authcontext.ParseSecretsEnv(envValue)
}

// ValidateSecretsArray validates a versioned secrets list. Delegates to
// context.ValidateSecretsArray.
func ValidateSecretsArray(secrets []Secret, warnf func(string, ...any)) error {
	return authcontext.ValidateSecretsArray(secrets, warnf)
}

// BuildSecretConfig builds the versioned secret config. Delegates to
// context.BuildSecretConfig.
func BuildSecretConfig(secrets []Secret, legacySecret string) SecretConfig {
	return authcontext.BuildSecretConfig(secrets, legacySecret)
}

// resolveSecrets resolves the current secret and versioned config with
// upstream precedence. Delegates to context.ResolveSecrets; see its godoc
// for the precedence and error contract.
func resolveSecrets(opts Options) (Options, string, SecretConfig, error) {
	return authcontext.ResolveSecrets(opts)
}
