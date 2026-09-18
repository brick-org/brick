package auth

import (
	"os"
	"strings"

	"github.com/brick-org/brick/auth/src/types"
)

// Telemetry in this runtime (AUTH-F6-03).
//
// Pinned upstream: createTelemetry in
// vendor/better-auth/packages/telemetry/src/index.ts.
//
// Upstream createTelemetry returns a noop publisher when neither a telemetry
// endpoint (BETTER_AUTH_TELEMETRY_ENDPOINT) nor a custom track function is
// configured; otherwise it POSTs events (or calls customTrack) with an
// init-event fingerprint (config/runtime/database/framework fingerprints plus
// an anonymous project ID) once enabled.
//
// EXCLUSION (explicit, privacy/platform): the Go runtime performs no network
// publication and collects no host fingerprints (no endpoint plumbing, no
// custom-track hook, no project-ID hashing). When enabled, construction
// publishes a local "init" diagnostic and AuthContext.PublishTelemetry
// reports per-event diagnostics via Options.Logger (level-gated; Debug logs
// the full event). What IS preserved exactly:
//   - event shape: TelemetryEvent{Type, AnonymousID, Payload} (upstream
//     TelemetryEvent).
//   - disable controls: publish is a noop unless enabled via
//     Options.Telemetry.Enabled OR the BETTER_AUTH_TELEMETRY env var.
//   - debug controls: payloads log only when Debug is set (option or
//     BETTER_AUTH_TELEMETRY_DEBUG env).
//
// Upstream TypeScript names: createTelemetry, publish.

// telemetryBoolEnv mirrors getBooleanEnvVar
// (vendor/.../core/src/env/env-impl.ts:89-94): an unset or empty variable
// yields the fallback; otherwise any value except "0" and case-insensitive
// "false" enables.
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
// behavior as production when enabled. Pinned by TestF6TelemetryEnvTruthiness.
func telemetryEnabled(opts Options) bool {
	if opts.Telemetry.Enabled {
		return true
	}
	return telemetryBoolEnv("BETTER_AUTH_TELEMETRY", false)
}

// newTelemetryPublisher returns the AuthContext.PublishTelemetry function: a
// no-network local diagnostic (see the package exclusion note above). When
// telemetry is disabled it discards events; when enabled it notes the event
// type via Options.Logger (level-gated info), and with Debug it logs the
// full event shape (type, anonymous ID, payload) as well. It never fails the
// caller.
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
// IDs plus the resolved rate-limit storage backend. Upstream's init payload
// carries config/runtime/database/framework fingerprints gathered from the
// host environment; the Go runtime reports only what it configures (part of
// the no-host-fingerprinting exclusion above).
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
