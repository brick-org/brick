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
