package auth_test

import (
	"strings"
	"testing"

	auth "github.com/brick-org/brick/auth/src"
	"github.com/brick-org/brick/auth/src/types"
)

// G10 construction wiring: ResolveCookieRefreshCache table exists but
// Upstream: create-context.ts:318-351 + store-capabilities.ts.
func TestRefreshCacheConstruction_RefreshCacheConstruction_StatelessKeepsEnabled(t *testing.T) {
	api := newTestAPI(t)
	var logs []string
	a, err := auth.BetterAuth(auth.Options{
		Secret:  "test-secret",
		Adapter: api.Adapter(),
		Logger: auth.LoggerOptions{
			Level: "warn",
			Log: func(level, message string, args ...any) {
				logs = append(logs, level+":"+message)
			},
		},
		Session: auth.SessionOptions{
			CookieCache: auth.SessionCookieCacheOptions{
				MaxAge:       300,
				RefreshCache: types.SessionCookieCacheRefresh{Enabled: true},
			},
		},
	})
	if err != nil {
		t.Fatalf("BetterAuth: %v", err)
	}
	rc := a.Context.Options.Session.CookieCache.RefreshCache
	if !rc.Enabled {
		t.Fatal("stateless refreshCache=true must stay enabled")
	}
	if rc.UpdateAge != 60 {
		t.Fatalf("stateless default threshold must be floor(300*0.2)=60, got %d", rc.UpdateAge)
	}
	for _, l := range logs {
		if strings.Contains(l, "refreshCache") {
			t.Fatalf("stateless honor must not warn, got %q", l)
		}
	}
}

func TestRefreshCacheConstruction_RefreshCacheConstruction_StatefulDBWarnDisable(t *testing.T) {
	api := newTestAPI(t)
	var logs []string
	a, err := auth.BetterAuth(auth.Options{
		Secret:  "test-secret",
		Adapter: api.Adapter(),
		DB:      newMemoryAdapter(),
		Logger: auth.LoggerOptions{
			Level: "warn",
			Log: func(level, message string, args ...any) {
				logs = append(logs, level+":"+message)
			},
		},
		Session: auth.SessionOptions{
			CookieCache: auth.SessionCookieCacheOptions{
				MaxAge:       300,
				RefreshCache: types.SessionCookieCacheRefresh{Enabled: true},
			},
		},
	})
	if err != nil {
		t.Fatalf("BetterAuth: %v", err)
	}
	rc := a.Context.Options.Session.CookieCache.RefreshCache
	if rc.Enabled {
		t.Fatal("stateful store must disable refreshCache")
	}
	if rc.UpdateAge != 0 {
		t.Fatalf("disabled refreshCache must carry no threshold, got %d", rc.UpdateAge)
	}
	found := false
	for _, l := range logs {
		if strings.Contains(l, "`session.cookieCache.refreshCache` is enabled while `database` or `secondaryStorage` is configured") {
			found = true
		}
	}
	if !found {
		t.Fatalf("stateful disable must warn, got %q", logs)
	}
}

func TestRefreshCacheConstruction_RefreshCacheConstruction_StatefulSecondaryWarnDisable(t *testing.T) {
	api := newTestAPI(t)
	var logs []string
	a, err := auth.BetterAuth(auth.Options{
		Secret:           "test-secret",
		Adapter:          api.Adapter(),
		SecondaryStorage: newStubSecondaryStorage(),
		Logger: auth.LoggerOptions{
			Level: "warn",
			Log: func(level, message string, args ...any) {
				logs = append(logs, level+":"+message)
			},
		},
		Session: auth.SessionOptions{
			CookieCache: auth.SessionCookieCacheOptions{
				MaxAge:       300,
				RefreshCache: types.SessionCookieCacheRefresh{Enabled: true},
			},
		},
	})
	if err != nil {
		t.Fatalf("BetterAuth: %v", err)
	}
	rc := a.Context.Options.Session.CookieCache.RefreshCache
	if rc.Enabled {
		t.Fatal("secondary-storage store must disable refreshCache")
	}
	found := false
	for _, l := range logs {
		if strings.Contains(l, "`session.cookieCache.refreshCache` is enabled while `database` or `secondaryStorage` is configured") {
			found = true
		}
	}
	if !found {
		t.Fatalf("secondary disable must warn, got %q", logs)
	}
}

func TestRefreshCacheConstruction_RefreshCacheConstruction_UnsetStaysQuiet(t *testing.T) {
	api := newTestAPI(t)
	var logs []string
	a, err := auth.BetterAuth(auth.Options{
		Secret:  "test-secret",
		Adapter: api.Adapter(),
		DB:      newMemoryAdapter(),
		Logger: auth.LoggerOptions{
			Level: "warn",
			Log: func(level, message string, args ...any) {
				logs = append(logs, level+":"+message)
			},
		},
		Session: auth.SessionOptions{
			CookieCache: auth.SessionCookieCacheOptions{MaxAge: 300},
		},
	})
	if err != nil {
		t.Fatalf("BetterAuth: %v", err)
	}
	rc := a.Context.Options.Session.CookieCache.RefreshCache
	if rc.Enabled {
		t.Fatal("unset refreshCache must stay disabled")
	}
	for _, l := range logs {
		if strings.Contains(l, "refreshCache") {
			t.Fatalf("unset refreshCache must stay quiet, got %q", l)
		}
	}
}
