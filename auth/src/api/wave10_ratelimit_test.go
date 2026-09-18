package api

// AUTH-V10-02 — adversarial and cross-language conformance (tests only).
//
// This file owns the api package's Wave 10 adversarial coverage: rate-limit
// bursts against the memory backend (exactly-max admission under
// concurrency), ConsumeResolvedRateLimit burst parity, and rate-limit path
// normalization fuzzing.
//
// Upstream references (pinned Better Auth v1.7.5 at 5468e6bf):
//   - packages/better-auth/src/api/rate-limiter/index.ts
//     (BetterAuthRateLimitStorage.consume single-step consume,
//     onRequestRateLimit, getDefaultSpecialRules, longestObservedWindow)
//   - packages/better-auth/src/api/rate-limiter/index.test.ts (window
//     rollover, retry-after, failed-request counting, storage-error
//     semantics)
//
// Work limits pinned for this file: burst sizes are fixed (32 racers max)
// so the suite stays fast under -race; fuzz paths are capped at 1KiB. The
// memory backend is process-global, so every burst uses a unique key. No
// production code is changed here.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Memory-backend burst: 32 concurrent consumes against Max=8 admit exactly 8
// (single-step check-and-increment; no stale-read pass-through), and the
// limiter stays limited afterwards with a positive retry-after.
func TestWave10_MemoryBurstAllowsExactlyMax(t *testing.T) {
	storage := MemoryRateLimitStorage{}
	key := fmt.Sprintf("w10-burst-%d", time.Now().UnixNano())
	const max = 8
	const racers = 32

	var allowed atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, limited := storage.Consume(key, 10*time.Second, max); !limited {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()
	if allowed.Load() != max {
		t.Fatalf("memory burst allowed = %d, want exactly %d", allowed.Load(), max)
	}
	if retryAfter, limited := storage.Consume(key, 10*time.Second, max); !limited || retryAfter < 1 {
		t.Fatalf("post-burst consume must stay limited with retry-after, got %d %v", retryAfter, limited)
	}
}

// Resolved-burst parity through the production entry point: the same
// exactly-max admission holds via ConsumeResolvedRateLimit on the memory
// backend, and distinct keys do not share buckets.
func TestWave10_ConsumeResolvedBurstMemoryBackend(t *testing.T) {
	opts := enabledOptions()
	base := fmt.Sprintf("w10-resolved-%d", time.Now().UnixNano())
	const max = 5
	const racers = 20

	burst := func(key string) int64 {
		var allowed atomic.Int64
		var wg sync.WaitGroup
		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ok, _, err := ConsumeResolvedRateLimit(context.Background(), resolvedRateLimit{
					Key:    key,
					Window: 10 * time.Second,
					Max:    max,
				}, opts)
				if err != nil {
					t.Errorf("consume: %v", err)
					return
				}
				if ok {
					allowed.Add(1)
				}
			}()
		}
		wg.Wait()
		return allowed.Load()
	}

	if got := burst(base + "|a"); got != max {
		t.Fatalf("resolved burst allowed = %d, want exactly %d", got, max)
	}
	// A sibling key has an independent bucket (no cross-key leakage).
	if got := burst(base + "|b"); got != max {
		t.Fatalf("sibling bucket allowed = %d, want exactly %d", got, max)
	}
	// The first bucket is still exhausted.
	ok, _, err := ConsumeResolvedRateLimit(context.Background(), resolvedRateLimit{
		Key:    base + "|a",
		Window: 10 * time.Second,
		Max:    max,
	}, opts)
	if err != nil || ok {
		t.Fatalf("exhausted bucket must stay limited, got %v %v", ok, err)
	}
}

// Window rollover under burst: after the window elapses, the bucket reopens
// for exactly max again (no stuck-limited, no stuck-open).
func TestWave10_MemoryWindowRollover(t *testing.T) {
	storage := MemoryRateLimitStorage{}
	key := fmt.Sprintf("w10-rollover-%d", time.Now().UnixNano())
	window := 50 * time.Millisecond
	const max = 3
	for i := 0; i < max; i++ {
		if _, limited := storage.Consume(key, window, max); limited {
			t.Fatalf("consume %d must pass", i)
		}
	}
	if _, limited := storage.Consume(key, window, max); !limited {
		t.Fatal("bucket must be limited at max")
	}
	time.Sleep(3 * window)
	var allowed atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < max*2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, limited := storage.Consume(key, window, max); !limited {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()
	if allowed.Load() != max {
		t.Fatalf("post-rollover burst allowed = %d, want exactly %d", allowed.Load(), max)
	}
}

// FuzzWave10_NormalizeRateLimitPath fuzzes path normalization: it never
// panics, always returns a "/"-rooted path, and is deterministic.
func FuzzWave10_NormalizeRateLimitPath(f *testing.F) {
	f.Add("/api/auth/sign-in/email", "/api/auth")
	f.Add("/api/auth/", "/api/auth/")
	f.Add("", "")
	f.Add("/x", "/y")
	f.Fuzz(func(t *testing.T, requestPath, basePath string) {
		if len(requestPath) > 1024 || len(basePath) > 1024 {
			t.Skip("over wave10 1KiB cap")
		}
		got := normalizeRateLimitPath(requestPath, basePath)
		if !strings.HasPrefix(got, "/") {
			t.Fatalf("normalized path %q must be /-rooted", got)
		}
		if again := normalizeRateLimitPath(requestPath, basePath); again != got {
			t.Fatalf("nondeterministic normalize of %q %q", requestPath, basePath)
		}
	})
}
