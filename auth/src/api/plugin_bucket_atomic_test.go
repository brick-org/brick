package api

import (
	"strings"
	"sync"
	"testing"

	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2/humatest"
)

// countingStorage records every Consume call per key for plugin-bucket
// wiring tests.
type countingStorage struct {
	mu    sync.Mutex
	calls map[string]int
}

func (s *countingStorage) Consume(key string, rule types.RateLimitRule) (types.RateLimitConsumeResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.calls == nil {
		s.calls = map[string]int{}
	}
	s.calls[key]++
	if s.calls[key] > rule.Max {
		retry := rule.Window
		return types.RateLimitConsumeResult{Allowed: false, RetryAfter: &retry}, nil
	}
	return types.RateLimitConsumeResult{Allowed: true}, nil
}

func (s *countingStorage) countFor(sub string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	total := 0
	for k, n := range s.calls {
		if strings.Contains(k, sub) {
			total += n
		}
	}
	return total
}

// TestPluginBucket_AtomicSingleConsume wires the Wave 10 middleware change:
// plugin buckets consume once per request through the selected backend (no
// post-handler record). Max 2 → 200, 200, then 429 with X-Retry-After, and
// exactly 3 backend consumes.
func TestPluginBucket_AtomicSingleConsume(t *testing.T) {
	storage := &countingStorage{}
	enabled := true
	opts := testRateLimitOptions()
	opts.RateLimit.Enabled = &enabled
	opts.RateLimit.CustomStorage = storage
	opts.Plugins = []types.Plugin{
		&stubRateLimitPlugin{
			id: "test-plugin",
			rules: []types.PluginRateLimitRule{
				{Window: 60, Max: 2, PathMatcher: func(path string) bool { return path == "/ok" }},
			},
		},
	}
	api := Router(humatest.NewAdapter(), "/api/auth", opts)
	testAPI := humatest.Wrap(t, api)

	for i, want := range []int{200, 200, 429} {
		resp := testAPI.Get("/api/auth/ok")
		if resp.Code != want {
			t.Fatalf("request %d: expected %d, got %d: %s", i+1, want, resp.Code, resp.Body.String())
		}
	}
	// The plugin bucket ("|plugin|test-plugin|/ok") must be consumed exactly
	// once per request: the pre-handler atomic consume replaced the legacy
	// check-then-record pair, so no post-handler record follows.
	if got := storage.countFor("|plugin|test-plugin|/ok"); got != 3 {
		t.Fatalf("expected exactly 3 plugin-bucket consumes (one per request), got %d", got)
	}
}
