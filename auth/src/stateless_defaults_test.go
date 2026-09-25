package auth_test

import (
	"strings"
	"testing"

	auth "github.com/brick-org/brick/auth/src"
	"github.com/brick-org/brick/auth/src/types"
)

const f8Secret = "f8-test-secret-that-is-long-enough-1234567890"

func f8CaptureLogger(level types.LogLevel) (*[]string, types.LoggerOptions) {
	var got []string
	return &got, types.LoggerOptions{
		Level: level,
		Log: func(lvl, msg string, args ...any) {
			got = append(got, lvl+":"+msg)
		},
	}
}

// Stateless (no DB, no secondary) must get defu defaults:
// cookieCache{enabled:true, strategy:jwe, refreshCache:true, maxAge:expiresIn||7d}
// and storeAccountCookie:true.
// Upstream: create-context.ts:106-128 @ 5468e6bf.
func TestStatelessDefaults_StatelessDefaultsJweCache(t *testing.T) {
	api := newTestAPI(t)
	a, err := auth.BetterAuth(auth.Options{
		Secret:  f8Secret,
		Adapter: api.Adapter(),
		BaseURL: "https://app.example.com",
	})
	if err != nil {
		t.Fatalf("BetterAuth: %v", err)
	}
	cc := a.Context.Options.Session.CookieCache
	if !cc.Enabled {
		t.Fatal("stateless must default cookieCache.enabled=true")
	}
	if cc.Strategy != types.SessionCookieCacheJWE {
		t.Fatalf("stateless must default cookieCache.strategy=jwe, got %q", cc.Strategy)
	}
	if !cc.RefreshCache.Enabled {
		t.Fatal("stateless must default cookieCache.refreshCache=true (Enabled)")
	}
	if cc.MaxAge != 60*60*24*7 {
		t.Fatalf("stateless default maxAge must be 7d (604800), got %d", cc.MaxAge)
	}
	if !a.Context.Options.Account.StoreAccountCookie {
		t.Fatal("stateless (no database) must default storeAccountCookie=true")
	}
}

func TestStatelessDefaults_StatelessMaxAgeFollowsExpiresIn(t *testing.T) {
	api := newTestAPI(t)
	a, err := auth.BetterAuth(auth.Options{
		Secret:  f8Secret,
		Adapter: api.Adapter(),
		BaseURL: "https://app.example.com",
		Session: auth.SessionOptions{ExpiresIn: 3600},
	})
	if err != nil {
		t.Fatalf("BetterAuth: %v", err)
	}
	if got := a.Context.Options.Session.CookieCache.MaxAge; got != 3600 {
		t.Fatalf("stateless maxAge must follow expiresIn (3600), got %d", got)
	}
}

// Stateful (DB or secondary) stays opt-in: no auto cookieCache.
func TestStatelessDefaults_StatefulStaysOptIn(t *testing.T) {
	api := newTestAPI(t)
	a, err := auth.BetterAuth(auth.Options{
		Secret:  f8Secret,
		Adapter: api.Adapter(),
		BaseURL: "https://app.example.com",
		DB:      newMemoryAdapter(),
	})
	if err != nil {
		t.Fatalf("BetterAuth: %v", err)
	}
	cc := a.Context.Options.Session.CookieCache
	if cc.Enabled {
		t.Fatal("stateful (DB) must stay opt-in: cookieCache.enabled must remain false")
	}
	if cc.Strategy != "" {
		t.Fatalf("stateful (DB) must not default strategy, got %q", cc.Strategy)
	}
	if cc.RefreshCache.Enabled {
		t.Fatal("stateful (DB) must not default refreshCache")
	}
	if a.Context.Options.Account.StoreAccountCookie {
		t.Fatal("stateful with database must not default storeAccountCookie")
	}
}

func TestStatelessDefaults_SecondaryOnlyStaysOptInCacheButStoresAccount(t *testing.T) {
	api := newTestAPI(t)
	a, err := auth.BetterAuth(auth.Options{
		Secret:           f8Secret,
		Adapter:          api.Adapter(),
		BaseURL:          "https://app.example.com",
		SecondaryStorage: newStubSecondaryStorage(),
	})
	if err != nil {
		t.Fatalf("BetterAuth: %v", err)
	}
	cc := a.Context.Options.Session.CookieCache
	if cc.Enabled {
		t.Fatal("secondary-only (stateful) must stay opt-in: cookieCache.enabled must remain false")
	}
	if !a.Context.Options.Account.StoreAccountCookie {
		t.Fatal("secondary-only (no primary database) must default storeAccountCookie=true")
	}
}

// Missing baseURL must warn (upstream create-context.ts:152-156).
func TestStatelessDefaults_MissingBaseURLWarn(t *testing.T) {
	api := newTestAPI(t)
	got, logger := f8CaptureLogger(types.LogLevelWarn)
	if _, err := auth.BetterAuth(auth.Options{
		Secret:  f8Secret,
		Adapter: api.Adapter(),
		Logger:  logger,
	}); err != nil {
		t.Fatalf("BetterAuth: %v", err)
	}
	joined := strings.Join(*got, "\n")
	if !strings.Contains(joined, "Base URL is not set") {
		t.Fatalf("missing baseURL must warn with upstream message, got %v", *got)
	}

	got2, logger2 := f8CaptureLogger(types.LogLevelWarn)
	if _, err := auth.BetterAuth(auth.Options{
		Secret:  f8Secret,
		Adapter: api.Adapter(),
		BaseURL: "https://app.example.com",
		Logger:  logger2,
	}); err != nil {
		t.Fatalf("BetterAuth: %v", err)
	}
	for _, l := range *got2 {
		if strings.Contains(l, "Base URL is not set") {
			t.Fatalf("explicit baseURL must not warn, got %v", *got2)
		}
	}
}
