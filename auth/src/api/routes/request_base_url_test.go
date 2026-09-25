package routes

import (
	"context"
	"sync"
	"testing"

	"github.com/brick-org/brick/auth/src/types"
)

// F6-01 request-context tests (upstream: utils/url.ts resolveDynamicBaseURL,
// context/helpers.ts resolveRequestContext, api/to-auth-endpoints.test.ts
// dynamic baseURL resolution, api/state/oauth.ts serverContext).
//
// These tests target the NEW request-scoped helpers owned by AUTH-F6-01.
// They fail before implementation (undefined symbols) and pass after.

func TestRequestContextEffectiveBaseURLStaticFallback(t *testing.T) {
	opts := types.Options{BaseURL: "https://app.example"}
	if got := EffectiveBaseURL(context.Background(), opts); got != "https://app.example" {
		t.Fatalf("static fallback = %q, want https://app.example", got)
	}
	if got := EffectiveFullBaseURL(context.Background(), opts); got != "https://app.example/api/auth" {
		t.Fatalf("static full = %q, want https://app.example/api/auth", got)
	}
}

func TestRequestContextEffectiveBaseURLDynamicPerRequest(t *testing.T) {
	opts := types.Options{DynamicBaseURL: &types.DynamicBaseURLConfig{AllowedHosts: []string{"tenant-a.example.com"}}}
	ctx := WithRequestFullBaseURLValue(context.Background(), "https://tenant-a.example.com/api/auth")
	if got := EffectiveBaseURL(ctx, opts); got != "https://tenant-a.example.com" {
		t.Fatalf("dynamic origin = %q", got)
	}
	if got := EffectiveFullBaseURL(ctx, opts); got != "https://tenant-a.example.com/api/auth" {
		t.Fatalf("dynamic full = %q", got)
	}
}

func TestRequestContextConcurrentTwoHostsIsolated(t *testing.T) {
	opts := types.Options{DynamicBaseURL: &types.DynamicBaseURLConfig{AllowedHosts: []string{"tenant-a.example.com", "tenant-b.example.com"}}}
	var wg sync.WaitGroup
	results := make([]string, 2)
	for i, host := range []string{"https://tenant-a.example.com/api/auth", "https://tenant-b.example.com/api/auth"} {
		wg.Add(1)
		go func(idx int, full string) {
			defer wg.Done()
			ctx := WithRequestFullBaseURLValue(context.Background(), full)
			results[idx] = EffectiveFullBaseURL(ctx, opts)
		}(i, host)
	}
	wg.Wait()
	if results[0] != "https://tenant-a.example.com/api/auth" || results[1] != "https://tenant-b.example.com/api/auth" {
		t.Fatalf("concurrent hosts leaked: %v", results)
	}
}

func TestRequestContextOAuthServerContextProducerReserved(t *testing.T) {
	// Trusted producer merges context-carried + explicit, explicit wins.
	base := AddOAuthServerContextValue(context.Background(), map[string]any{"tenant": "t1", "flow": "signin"})
	merged := ResolveOAuthServerContext(base, map[string]any{"flow": "link"})
	if merged["tenant"] != "t1" || merged["flow"] != "link" {
		t.Fatalf("serverContext merge = %v", merged)
	}
	// Empty layers resolve to nil (omitted on the wire like upstream undefined).
	if got := ResolveOAuthServerContext(context.Background(), nil); got != nil {
		t.Fatalf("empty serverContext = %v, want nil", got)
	}
}

func TestRequestContextCookieSecureUsesRequestScheme(t *testing.T) {
	httpsOpts := types.Options{DynamicBaseURL: &types.DynamicBaseURLConfig{AllowedHosts: []string{"tenant-a.example.com"}}}
	httpsCtx := WithRequestFullBaseURLValue(context.Background(), "https://tenant-a.example.com/api/auth")
	if !ResolveSecureCookiesWithContext(httpsCtx, httpsOpts, CookieRequestHeaders{}) {
		t.Fatal("https request host must resolve secure cookies")
	}
	loopOpts := types.Options{DynamicBaseURL: &types.DynamicBaseURLConfig{AllowedHosts: []string{"localhost"}}}
	loopCtx := WithRequestFullBaseURLValue(context.Background(), "http://localhost:3000/api/auth")
	if ResolveSecureCookiesWithContext(loopCtx, loopOpts, CookieRequestHeaders{}) {
		t.Fatal("http loopback must not resolve secure cookies")
	}
}
