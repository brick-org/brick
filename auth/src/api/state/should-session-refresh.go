package state

import (
	"context"
)

// --- Session-refresh skip flag (upstream
// `src/api/state/should-session-refresh.ts`) ---
//
// Upstream keeps a per-request boolean (default `false`) behind
// `defineRequestState`: SSR-style callers set it to skip the session refresh
// so database session data and cookie session data cannot diverge within one
// request (`getShouldSkipSessionRefresh` / `setShouldSkipSessionRefresh`).
//
// Go has no `AsyncLocalStorage`; the flag travels by explicit context
// propagation, like the sibling request-state stores in `routes/hooks.go`.
// The zero value (no flag installed) reads as `false`, matching the upstream
// default. Installing the flag never mutates shared state, so concurrent
// requests stay isolated. Session handlers consult it via
// ShouldSkipSessionRefresh; no existing handler behavior changes (the flag
// is opt-in per request).

type shouldSkipSessionRefreshKey struct{}

// SetShouldSkipSessionRefresh returns ctx carrying the session-refresh skip
// flag for this request, mirroring upstream `setShouldSkipSessionRefresh`.
func SetShouldSkipSessionRefresh(ctx context.Context, skip bool) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, shouldSkipSessionRefreshKey{}, skip)
}

// GetShouldSkipSessionRefresh reports whether the current request skips the
// session refresh, mirroring upstream `getShouldSkipSessionRefresh`. It
// returns false when no flag was installed (including a nil context).
func GetShouldSkipSessionRefresh(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	skip, _ := ctx.Value(shouldSkipSessionRefreshKey{}).(bool)
	return skip
}

// ShouldSkipSessionRefresh is an alias of GetShouldSkipSessionRefresh kept
// for call sites that read more naturally without the Get prefix.
func ShouldSkipSessionRefresh(ctx context.Context) bool {
	return GetShouldSkipSessionRefresh(ctx)
}

// --- Stateless cookie-cache refresh resolution (upstream
// `src/context/create-context.ts:318-351`) ---
//
// Upstream resolves `session.cookieCache.refreshCache` at context creation:
// `refreshCache` is intended for fully stateless / DB-less setups, so when a
// server-side session store is configured (`hasServerSessionStore` =
// database or secondaryStorage configured,
// `src/context/store-capabilities.ts:3-5`) an enabled `refreshCache` logs a
// warning and resolves to disabled (`false`); an unset `refreshCache`
// resolves to disabled without warning; otherwise it resolves to enabled
// with `updateAge` defaulting to `Math.floor(maxAge * 0.2)`.
//
// ResolveCookieRefreshCache is the pure Go mirror of that resolution.
// configured reports whether the operator set refreshCache at all (any of
// Enabled, a non-zero UpdateAge, or a ShouldRefresh gate — mirroring
// upstream's truthiness of `true | { updateAge }`); updateAge and maxAge are
// in seconds (non-positive maxAge falls back to upstream's 300 default);
// hasServerStore mirrors hasServerSessionStore. It returns the effective
// enabled flag, the effective threshold in seconds (0 when disabled), and
// whether the caller must log upstream's warn-disable note.
//
// Construction wiring (auth.BetterAuth) and the route read path are owned by
// sibling packages; this helper pins the decision table here so the state
// package owns the upstream semantics.
func ResolveCookieRefreshCache(configured bool, updateAge, maxAge int, hasServerStore bool) (enabled bool, effectiveUpdateAge int, warnDisable bool) {
	if !configured {
		return false, 0, false
	}
	if hasServerStore {
		return false, 0, true
	}
	effective := maxAge
	if effective <= 0 {
		effective = 300
	}
	if updateAge > 0 {
		return true, updateAge, false
	}
	return true, effective * 2 / 10, false
}
