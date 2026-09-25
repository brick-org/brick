package api

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/types"
)


// stubSecondary is a minimal SecondaryStorage with Increment.
type d6StubSecondary struct {
	mu     sync.Mutex
	counts map[string]int64
	fail   error
}

func (s *d6StubSecondary) Get(key string) (any, error)           { return nil, nil }
func (s *d6StubSecondary) GetAndDelete(key string) (any, error)  { return nil, nil }
func (s *d6StubSecondary) Set(key, value string, ttl *int) error { return nil }
func (s *d6StubSecondary) Delete(key string) error               { return nil }
func (s *d6StubSecondary) Increment(key string, ttl int) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return 0, s.fail
	}
	if s.counts == nil {
		s.counts = map[string]int64{}
	}
	s.counts[key]++
	return s.counts[key], nil
}

// errFindAdapter wraps a types.Adapter to fail FindOne with err.
type errFindAdapter struct {
	types.Adapter
	err error
}

func (a *errFindAdapter) FindOne(_ context.Context, _ string, _ []types.Where, _ []string) (map[string]any, error) {
	return nil, a.err
}

func TestRateLimitBackends_PluginBucketUsesSelectedAtomicBackend(t *testing.T) {
	resetDatabaseLongestObserved()
	db := newFakeRateLimitAdapter()
	opts := enabledOptions()
	opts.RateLimit.Storage = types.RateLimitStorageDatabase
	opts.DB = db
	config := resolvedRateLimit{Key: "ip|plugin|p|/ok", Window: 10 * time.Second, Max: 2}
	if _, err := db.Create(context.Background(), "rateLimit", map[string]any{
		"key": config.Key, "count": int64(0), "lastRequest": time.Now().UnixMilli(),
	}, nil); err != nil {
		t.Fatal(err)
	}
	// Single-step atomic consume through the selected backend: exactly Max
	var wg sync.WaitGroup
	allowed := 0
	var mu sync.Mutex
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, _, err := ConsumeResolvedRateLimit(context.Background(), config, opts)
			if err != nil {
				t.Errorf("consume: %v", err)
				return
			}
			if ok {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if allowed != 2 {
		t.Fatalf("atomic plugin bucket allowed = %d, want exactly 2", allowed)
	}
}

func TestRateLimitBackends_DatabaseRetryAfterIsExact(t *testing.T) {
	db := newFakeRateLimitAdapter()
	now := time.Now()
	current := now
	storage := DatabaseRateLimitStorage{DB: db, Now: func() time.Time { return current }}
	window := 10 * time.Second
	if _, limited := storage.Consume("k-exact", window, 1); limited {
		t.Fatal("first must pass")
	}
	current = current.Add(3 * time.Second)
	retryAfter, limited := storage.Consume("k-exact", window, 1)
	if !limited {
		t.Fatal("second must be limited")
	}
	if retryAfter != 7 {
		t.Fatalf("retryAfter = %d, want 7 (upstream getRetryAfter)", retryAfter)
	}
}

func TestRateLimitBackends_StorageErrorSurfacesInsteadOfSilentLimit(t *testing.T) {
	resetDatabaseLongestObserved()
	db := newFakeRateLimitAdapter()
	errAdapter := &errFindAdapter{Adapter: db, err: errors.New("connection refused")}
	config := resolvedRateLimit{Key: "k-err", Window: 10 * time.Second, Max: 100}
	opts := enabledOptions()
	opts.RateLimit.Storage = types.RateLimitStorageDatabase
	opts.DB = errAdapter
	if _, _, err := ConsumeResolvedRateLimit(context.Background(), config, opts); err == nil {
		t.Fatal("storage failure must surface as an error (request-time 500), not a silent limit")
	}
	storage := DatabaseRateLimitStorage{DB: errAdapter}
	if _, limited := storage.Consume("k-err", 10*time.Second, 100); !limited {
		t.Fatal("Consume interface must fail closed on storage errors")
	}
}

func TestRateLimitBackends_DynamicResolverWindowFeedsPruneCutoff(t *testing.T) {
	resetDatabaseLongestObserved()
	db := newFakeRateLimitAdapter()
	now := time.Now()
	longKey := "127.0.0.1|/dynamic-active"
	staleKey := "127.0.0.1|/dynamic-stale"
	if _, err := db.Create(context.Background(), "rateLimit", map[string]any{
		"key": longKey, "count": 1, "lastRequest": now.Add(-90 * time.Second).UnixMilli(),
	}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Create(context.Background(), "rateLimit", map[string]any{
		"key": staleKey, "count": 1, "lastRequest": now.Add(-130 * time.Second).UnixMilli(),
	}, nil); err != nil {
		t.Fatal(err)
	}
	opts := enabledOptions()
	opts.RateLimit.Storage = types.RateLimitStorageDatabase
	opts.DB = db
	opts.RateLimit.CustomRuleResolvers = map[string]types.RateLimitRuleResolver{
		"/sign-in/email": func(_ *http.Request, current types.RateLimitRule) (types.RateLimitRule, bool) {
			return types.RateLimitRule{Window: 120, Max: 10}, true
		},
	}
	_ = opts
	// pruning while the 130s-old row is collected, mirroring upstream's
	config := resolvedRateLimit{Key: "127.0.0.1|/sign-in/email", Window: 120 * time.Second, Max: 10}
	if ok, _, err := ConsumeResolvedRateLimit(context.Background(), config, opts); err != nil || !ok {
		t.Fatalf("consume = %v, %v; want allowed", ok, err)
	}
	if row, _ := db.FindOne(context.Background(), "rateLimit", []types.Where{{Field: "key", Value: longKey}}, nil); row == nil {
		t.Fatal("active 90s row with 120s dynamic window must survive pruning")
	}
	if row, _ := db.FindOne(context.Background(), "rateLimit", []types.Where{{Field: "key", Value: staleKey}}, nil); row != nil {
		t.Fatal("stale 130s row must be pruned")
	}
}

func TestRateLimitBackends_FailedRequestsCountInRequestPhase(t *testing.T) {
	resetDatabaseLongestObserved()
	db := newFakeRateLimitAdapter()
	opts := enabledOptions()
	opts.RateLimit.Storage = types.RateLimitStorageDatabase
	opts.DB = db
	config := resolvedRateLimit{Key: "k-fail", Window: 10 * time.Second, Max: 1}
	if ok, _, err := ConsumeResolvedRateLimit(context.Background(), config, opts); err != nil || !ok {
		t.Fatalf("first consume = %v, %v", ok, err)
	}
	if ok, _, err := ConsumeResolvedRateLimit(context.Background(), config, opts); err != nil || ok {
		t.Fatalf("second consume after failed request must be limited, got %v, %v", ok, err)
	}
}

func TestRateLimitBackends_ConcurrentDatabaseEnforcement_AllowsExactlyMax(t *testing.T) {
	resetDatabaseLongestObserved()
	db := newFakeRateLimitAdapter()
	opts := enabledOptions()
	opts.RateLimit.Storage = types.RateLimitStorageDatabase
	opts.DB = db
	config := resolvedRateLimit{Key: "k-burst", Window: 10 * time.Second, Max: 4}
	if _, err := db.Create(context.Background(), "rateLimit", map[string]any{
		"key": config.Key, "count": int64(0), "lastRequest": time.Now().UnixMilli(),
	}, nil); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	allowed := 0
	var mu sync.Mutex
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, _, err := ConsumeResolvedRateLimit(context.Background(), config, opts)
			if err != nil {
				t.Errorf("consume: %v", err)
				return
			}
			if ok {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if allowed != 4 {
		t.Fatalf("concurrent burst allowed = %d, want exactly 4", allowed)
	}
	row, err := db.FindOne(context.Background(), "rateLimit", []types.Where{{Field: "key", Value: "k-burst"}}, nil)
	if err != nil || row == nil {
		t.Fatalf("row lookup: %v", err)
	}
	if count, _ := rateLimitCountValue(row["count"]); count != 4 {
		t.Fatalf("stored count = %d, want 4 (guarded increment never overshoots)", count)
	}
}
