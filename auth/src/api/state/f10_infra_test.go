package state

import "testing"

// F10 stateful refreshCache coverage (P05-GAP-3).
//
// Upstream: vendor/better-auth/packages/better-auth/src/context/create-context.ts:318-351
// (`refreshCache` is for stateless/DB-less setups; when a server-side store
// is configured it warns and disables refreshCache) with
// hasServerSessionStore = database || secondaryStorage
// (context/store-capabilities.ts:3-5).
func TestF10_ResolveCookieRefreshCache_StatefulWarnDisable(t *testing.T) {
	enabled, updateAge, warned := ResolveCookieRefreshCache(true, 0, 300, true)
	if enabled {
		t.Fatal("stateful store must disable refreshCache")
	}
	if updateAge != 0 {
		t.Fatalf("disabled refreshCache must carry no threshold, got %d", updateAge)
	}
	if !warned {
		t.Fatal("stateful disable must warn (upstream logger.warn)")
	}
}

func TestF10_ResolveCookieRefreshCache_StatelessHonored(t *testing.T) {
	enabled, updateAge, warned := ResolveCookieRefreshCache(true, 0, 300, false)
	if !enabled {
		t.Fatal("stateless refreshCache=true must stay enabled")
	}
	if updateAge != 60 {
		t.Fatalf("default threshold must be floor(maxAge*0.2)=60, got %d", updateAge)
	}
	if warned {
		t.Fatal("stateless honor must not warn")
	}
}

func TestF10_ResolveCookieRefreshCache_ExplicitUpdateAge(t *testing.T) {
	enabled, updateAge, warned := ResolveCookieRefreshCache(true, 45, 300, false)
	if !enabled || warned {
		t.Fatalf("explicit config must stay enabled without warning, got %v %v", enabled, warned)
	}
	if updateAge != 45 {
		t.Fatalf("explicit updateAge must win, got %d", updateAge)
	}
}

func TestF10_ResolveCookieRefreshCache_UnsetStaysOff(t *testing.T) {
	enabled, updateAge, warned := ResolveCookieRefreshCache(false, 0, 300, false)
	if enabled || warned || updateAge != 0 {
		t.Fatalf("unset refreshCache must stay off quietly, got %v %d %v", enabled, updateAge, warned)
	}
	// Unset with a stateful store is the normal v1 shape: no warning owed.
	enabled, _, warned = ResolveCookieRefreshCache(false, 0, 300, true)
	if enabled || warned {
		t.Fatalf("unset refreshCache on a stateful store must stay off quietly, got %v %v", enabled, warned)
	}
}
