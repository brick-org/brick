// Package context carries the auth context construction helpers,
// mirroring the upstream src/context/ boundary.
//
// File boundary: auth/src/context/secret-utils.go mirrors upstream
// src/context/secret-utils.ts (parseSecretsEnv, validateSecretsArray,
// buildSecretConfig, plus the secret-resolution precedence owned by
// create-context.ts). Moved from the former auth root secrets.go per
// SOURCE_LAYOUT_MOVE_LIST.md (src/secrets.go -> src/context/secret-utils.go);
// the auth root keeps a thin delegating shim so the public auth API and the
// unexported resolveSecrets call site are unchanged.
package context

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"

	"github.com/brick-org/brick/auth/src/types"
)

// ParseSecretsEnv parses BETTER_AUTH_SECRETS ("<version>:<secret>,...") into
// versioned secrets. Mirrors parseSecretsEnv in
// vendor/.../src/context/secret-utils.ts. Returns nil when env is exactly
// empty (upstream falsy); any other input — including whitespace-only, which
// upstream throws on — must be a well-formed entry list.
// Upstream TypeScript name: parseSecretsEnv.
//
// DEVIATION (strictness, loud): the version token is parsed strictly
// (strconv.Atoi), while upstream parseInt is lenient (e.g. "1abc" parses as
// 1). Trailing-garbage versions fail closed here. Pinned by
// TestF6ParseSecretsEnvStrictVersion.
func ParseSecretsEnv(envValue string) ([]types.Secret, error) {
	if envValue == "" {
		return nil, nil
	}
	entries := strings.Split(envValue, ",")
	out := make([]types.Secret, 0, len(entries))
	for _, entry := range entries {
		trimmed := strings.TrimSpace(entry)
		colon := strings.Index(trimmed, ":")
		if colon == -1 {
			return nil, fmt.Errorf("auth: Invalid BETTER_AUTH_SECRETS entry: %q. Expected format: \"<version>:<secret>\"", trimmed)
		}
		versionStr := strings.TrimSpace(trimmed[:colon])
		version, err := strconv.Atoi(versionStr)
		if err != nil || version < 0 {
			return nil, fmt.Errorf("auth: Invalid version in BETTER_AUTH_SECRETS: %q. Version must be a non-negative integer.", versionStr)
		}
		value := strings.TrimSpace(trimmed[colon+1:])
		if value == "" {
			return nil, fmt.Errorf("auth: Empty secret value for version %d in BETTER_AUTH_SECRETS.", version)
		}
		out = append(out, types.Secret{Version: version, Value: value})
	}
	return out, nil
}

// ValidateSecretsArray validates a versioned secrets list: non-empty,
// unique non-negative integer versions, non-empty values. Warns when the
// current (first) secret is <32 chars. Mirrors validateSecretsArray.
// Upstream TypeScript name: validateSecretsArray.
func ValidateSecretsArray(secrets []types.Secret, warnf func(string, ...any)) error {
	if len(secrets) == 0 {
		return fmt.Errorf("auth: `secrets` array must contain at least one entry.")
	}
	seen := map[int]struct{}{}
	for _, s := range secrets {
		if s.Version < 0 {
			return fmt.Errorf("auth: Invalid version %d in `secrets`. Version must be a non-negative integer.", s.Version)
		}
		if s.Value == "" {
			return fmt.Errorf("auth: Empty secret value for version %d in `secrets`.", s.Version)
		}
		if _, dup := seen[s.Version]; dup {
			return fmt.Errorf("auth: Duplicate version %d in `secrets`. Each version must be unique.", s.Version)
		}
		seen[s.Version] = struct{}{}
	}
	if len(secrets[0].Value) < 32 && warnf != nil {
		warnf("[better-auth] Warning: the current secret (version %d) should be at least 32 characters long for adequate security.", secrets[0].Version)
	}
	if estimateEntropy(secrets[0].Value) < 120 && warnf != nil {
		warnf("[better-auth] Warning: the current secret appears low-entropy. Use a randomly generated secret for production.")
	}
	return nil
}

// BuildSecretConfig builds the versioned secret config honoring numeric
// Version: Keys maps version->value, CurrentVersion is the first entry's
// version, LegacySecret is the non-versioned secret when present.
// Mirrors buildSecretConfig. Upstream TypeScript name: buildSecretConfig.
func BuildSecretConfig(secrets []types.Secret, legacySecret string) types.SecretConfig {
	keys := make(map[int]string, len(secrets))
	for _, s := range secrets {
		keys[s.Version] = s.Value
	}
	current := 0
	if len(secrets) > 0 {
		current = secrets[0].Version
	}
	cfg := types.SecretConfig{Keys: keys, CurrentVersion: current}
	if legacySecret != "" && legacySecret != types.DefaultSecret {
		cfg.LegacySecret = legacySecret
	}
	return cfg
}

// secretWarnf returns a warnf that logs via Options.Logger when configured,
// or nil (quiet) by default. Short-secret warnings stay quiet unless the
// caller opts into logging, preserving the historical quiet default.
// Warnings are "warn" level and honor the configured minimum level
// (types.ShouldPublishLog, default "warn" — mirroring upstream createLogger
// filtering, where logger.warn is suppressed at level "error").
func secretWarnf(opts types.Options) func(string, ...any) {
	if opts.Logger.Disabled || opts.Logger.Log == nil {
		return nil
	}
	if !types.ShouldPublishLog(opts.Logger.Level, types.LogLevelWarn) {
		return nil
	}
	logFn := opts.Logger.Log
	return func(format string, args ...any) {
		msg := format
		if len(args) > 0 {
			msg = fmt.Sprintf(format, args...)
		}
		logFn("warn", msg)
	}
}

// estimateEntropy approximates a secret's entropy in bits, mirroring
// estimateEntropy in vendor/.../src/context/create-context.ts:46-50 and
// secret-utils.ts:10-14: log2(uniqueChars^length). It detects low-entropy
// secrets that meet the length floor but carry little randomness.
func estimateEntropy(secret string) float64 {
	runes := []rune(secret)
	if len(runes) == 0 {
		return 0
	}
	unique := make(map[rune]struct{}, len(runes))
	for _, r := range runes {
		unique[r] = struct{}{}
	}
	if len(unique) == 0 {
		return 0
	}
	return math.Log2(float64(len(unique))) * float64(len(runes))
}

// warnLowEntropy warns when a secret's estimated entropy falls below
// upstream's 120-bit floor (secret-utils.ts:84-89, create-context.ts:87-92).
// A nil warnf stays quiet.
func warnLowEntropy(secret string, warnf func(string, ...any)) {
	if warnf == nil || secret == "" {
		return
	}
	if estimateEntropy(secret) < 120 {
		warnf("[better-auth] Warning: your BETTER_AUTH_SECRET appears low-entropy. Use a randomly generated secret for production.")
	}
}

// ResolveSecrets resolves the current secret and versioned config with
// upstream precedence (secret-utils.ts + create-context.ts):
//
//	secretsArray = Options.Secrets ?? parse(BETTER_AUTH_SECRETS)
//	legacy = Options.Secret || BETTER_AUTH_SECRET || AUTH_SECRET || ""
//
// If versioned secrets exist: validate (non-empty, unique versions,
// non-empty values, warn <32) and build config honoring numeric Version;
// current is the first entry. Otherwise: require non-empty legacy (error
// when empty after env), warn <32, and build a single-key config.
//
// It returns the updated Options (Secret set to current, Secrets preserved
// when versioned), the current secret, and the config surfaced on context.
// An empty resolved secret is an error (behavior change from the old
// empty-accepted default; documented in BetterAuth godoc).
func ResolveSecrets(opts types.Options) (types.Options, string, types.SecretConfig, error) {
	var secretsArray []types.Secret
	if len(opts.Secrets) > 0 {
		secretsArray = append([]types.Secret(nil), opts.Secrets...)
	} else if envVal, ok := os.LookupEnv("BETTER_AUTH_SECRETS"); ok && envVal != "" {
		// Mirror upstream `options.secrets ?? parseSecretsEnv(env)`: an
		// explicitly set (even whitespace-only) value parses and throws on
		// malformed entries; only unset/empty falls through to the legacy
		// secret (upstream falsy).
		parsed, err := ParseSecretsEnv(envVal)
		if err != nil {
			return types.Options{}, "", types.SecretConfig{}, err
		}
		secretsArray = parsed
	}
	legacy := opts.Secret
	if legacy == "" {
		if v := os.Getenv("BETTER_AUTH_SECRET"); v != "" {
			legacy = v
		} else if v := os.Getenv("AUTH_SECRET"); v != "" {
			legacy = v
		}
	}
	warnf := secretWarnf(opts)
	if len(secretsArray) > 0 {
		if err := ValidateSecretsArray(secretsArray, warnf); err != nil {
			return types.Options{}, "", types.SecretConfig{}, err
		}
		current := secretsArray[0].Value
		cfg := BuildSecretConfig(secretsArray, legacy)
		opts.Secrets = secretsArray
		opts.Secret = current
		return opts, current, cfg, nil
	}
	if legacy == "" {
		return types.Options{}, "", types.SecretConfig{}, fmt.Errorf("auth: BETTER_AUTH_SECRET is missing. Set it in your environment or pass `secret` to betterAuth({ secret }).")
	}
	// Upstream validateSecret rejects the documented default secret in
	// production (create-context.ts:68-72); NODE_ENV mirrors upstream's
	// isProduction gate. An empty resolved secret stays an error in every
	// environment (fail-closed deviation from upstream's DEFAULT_SECRET
	// fallback; see the BetterAuth godoc).
	if legacy == types.DefaultSecret && os.Getenv("NODE_ENV") == "production" {
		return types.Options{}, "", types.SecretConfig{}, fmt.Errorf("auth: You are using the default secret. Please set `BETTER_AUTH_SECRET` in your environment variables or pass `secret` in your auth config.")
	}
	if len(legacy) < 32 && warnf != nil {
		warnf("[better-auth] Warning: your BETTER_AUTH_SECRET should be at least 32 characters long for adequate security. Generate one with `npx auth secret` or `openssl rand -base64 32`.")
	}
	warnLowEntropy(legacy, warnf)
	cfg := types.SecretConfig{Keys: map[int]string{0: legacy}, CurrentVersion: 0}
	opts.Secret = legacy
	return opts, legacy, cfg, nil
}
