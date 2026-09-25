package auth

import (
	"os"
	"strings"

	"github.com/brick-org/brick/auth/src/types"
)

// Telemetry in this runtime (AUTH-F6-03).
// EXCLUSION: no network publication and no host fingerprints; when enabled,
// construction publishes a local "init" diagnostic via Options.Logger.
// What IS preserved exactly: event shape TelemetryEvent{Type, AnonymousID,
// Payload}; enable via Options.Telemetry.Enabled OR BETTER_AUTH_TELEMETRY;
// debug via Debug or BETTER_AUTH_TELEMETRY_DEBUG.
//
// Upstream TypeScript names: createTelemetry, publish.

// telemetryBoolEnv mirrors getBooleanEnvVar: an unset or empty variable
// yields the fallback; otherwise any value except "0" and "false" enables.
func telemetryBoolEnv(key string, fallback bool) bool {
	value, ok := os.LookupEnv(key)
	if !ok || value == "" {
		return fallback
	}
	return value != "0" && !strings.EqualFold(value, "false")
}

// telemetryEnabled reports whether local telemetry diagnostics publish,
// mirroring upstream createTelemetry's enablement: the option wins when set,
// otherwise BETTER_AUTH_TELEMETRY opts in (getBooleanEnvVar semantics).
//
// DEVIATION (documented): upstream additionally suppresses all publication
// while isTest() (NODE_ENV=test) unless the platform passes skipTestCheck.
// Go applies no implicit test-environment suppression: explicit
// Enabled/env controls are the whole gate, so test binaries observe the same
// behavior as production when enabled. Pinned by TestInitTelemetryEnvTruthiness.
func telemetryEnabled(opts Options) bool {
	if opts.Telemetry.Enabled {
		return true
	}
	return telemetryBoolEnv("BETTER_AUTH_TELEMETRY", false)
}

// newTelemetryPublisher returns the AuthContext.PublishTelemetry function: a
// no-network local diagnostic. It never fails the caller.
func newTelemetryPublisher(opts Options) func(types.TelemetryEvent) {
	if !telemetryEnabled(opts) {
		return func(types.TelemetryEvent) {}
	}
	debug := opts.Telemetry.Enabled && opts.Telemetry.Debug
	if !debug {
		debug = telemetryBoolEnv("BETTER_AUTH_TELEMETRY_DEBUG", false)
	}
	return func(event types.TelemetryEvent) {
		if debug {
			authNotef(opts, "info", "auth: telemetry event %q (anonymousId %q): %+v", event.Type, event.AnonymousID, event.Payload)
			return
		}
		authNotef(opts, "info", "auth: telemetry event %q published (local diagnostic only)", event.Type)
	}
}

// telemetryInitPayload builds the local "init" diagnostic payload: plugin
// IDs plus the resolved rate-limit storage backend.
func telemetryInitPayload(opts Options) map[string]any {
	pluginIDs := make([]string, 0, len(opts.Plugins))
	for _, p := range opts.Plugins {
		if p == nil {
			continue
		}
		pluginIDs = append(pluginIDs, p.ID())
	}
	return map[string]any{
		"plugins":           pluginIDs,
		"rateLimitStorage":  string(resolveRateLimitContext(opts).Storage),
		"dynamicBaseURL":    opts.DynamicBaseURL != nil,
		"secondaryStorage":  opts.SecondaryStorage != nil,
		"hasDatabase":       opts.DB != nil,
		"betterAuthVersion": BetterAuthVersion,
	}
}
