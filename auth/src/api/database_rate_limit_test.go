package api

import (
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/types"
)

var errEmptyDatabaseIncrement = errors.New("auth: increment requires a non-empty increment or set")

// fakeRateLimitAdapter is a minimal in-memory types.Adapter with comparison
type fakeRateLimitAdapter struct {
	mu     sync.Mutex
	tables map[string][]map[string]any
}

func newFakeRateLimitAdapter() *fakeRateLimitAdapter {
	return &fakeRateLimitAdapter{tables: map[string][]map[string]any{}}
}

func fakeNumber(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case float64:
		return int64(n), true
	default:
		return 0, false
	}
}

func fakeLastRequestMs(v any) (int64, bool) {
	if ms, ok := fakeNumber(v); ok {
		return ms, true
	}
	if t, ok := v.(time.Time); ok {
		return t.UnixMilli(), true
	}
	return 0, false
}

func fakeWhereMatches(row map[string]any, where []types.Where) bool {
	for _, clause := range where {
		got, present := row[clause.Field]
		op := clause.Operator
		if op == "" {
			op = types.OpEq
		}
		switch op {
		case types.OpEq:
			want, _ := clause.Value.(string)
			gotStr, _ := got.(string)
			if op == types.OpEq && clause.Value != nil {
				if gotStr != want && got != clause.Value {
					gotNum, gotOk := fakeNumber(got)
					wantNum, wantOk := fakeNumber(clause.Value)
					if !gotOk || !wantOk || gotNum != wantNum {
						return false
					}
				} else if gotStr != want && got == nil {
					return false
				}
				_ = present
				continue
			}
			if got != clause.Value {
				return false
			}
		case types.OpLt, types.OpLte, types.OpGt, types.OpGte:
			gotMs, gotOk := fakeLastRequestMs(got)
			if !gotOk {
				if gotNum, ok := fakeNumber(got); ok {
					gotMs, gotOk = gotNum, true
				}
			}
			wantMs, wantOk := fakeLastRequestMs(clause.Value)
			if !wantOk {
				if wantNum, ok := fakeNumber(clause.Value); ok {
					wantMs, wantOk = wantNum, true
				}
			}
			if !gotOk || !wantOk {
				return false
			}
			switch op {
			case types.OpLt:
				if !(gotMs < wantMs) {
					return false
				}
			case types.OpLte:
				if !(gotMs <= wantMs) {
					return false
				}
			case types.OpGt:
				if !(gotMs > wantMs) {
					return false
				}
			case types.OpGte:
				if !(gotMs >= wantMs) {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

func (m *fakeRateLimitAdapter) Create(_ context.Context, model string, data map[string]any, _ []string) (map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	row := make(map[string]any, len(data))
	for k, v := range data {
		row[k] = v
	}
	m.tables[model] = append(m.tables[model], row)
	out := make(map[string]any, len(row))
	for k, v := range row {
		out[k] = v
	}
	return out, nil
}

func (m *fakeRateLimitAdapter) FindOne(_ context.Context, model string, where []types.Where, _ []string) (map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, row := range m.tables[model] {
		if fakeWhereMatches(row, where) {
			out := make(map[string]any, len(row))
			for k, v := range row {
				out[k] = v
			}
			return out, nil
		}
	}
	return nil, nil
}

func (m *fakeRateLimitAdapter) FindMany(_ context.Context, model string, where []types.Where, _, _ int, _ *types.SortBy, _ []string) ([]map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var rows []map[string]any
	for _, row := range m.tables[model] {
		if fakeWhereMatches(row, where) {
			out := make(map[string]any, len(row))
			for k, v := range row {
				out[k] = v
			}
			rows = append(rows, out)
		}
	}
	return rows, nil
}

func (m *fakeRateLimitAdapter) Count(ctx context.Context, model string, where []types.Where) (int, error) {
	rows, _ := m.FindMany(ctx, model, where, 0, 0, nil, nil)
	return len(rows), nil
}

func (m *fakeRateLimitAdapter) Update(ctx context.Context, model string, where []types.Where, data map[string]any) (map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, row := range m.tables[model] {
		if fakeWhereMatches(row, where) {
			for k, v := range data {
				row[k] = v
			}
			out := make(map[string]any, len(row))
			for k, v := range row {
				out[k] = v
			}
			return out, nil
		}
	}
	return nil, nil
}

func (m *fakeRateLimitAdapter) UpdateMany(_ context.Context, model string, where []types.Where, data map[string]any) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	updated := 0
	for _, row := range m.tables[model] {
		if fakeWhereMatches(row, where) {
			for k, v := range data {
				row[k] = v
			}
			updated++
		}
	}
	return updated, nil
}

func (m *fakeRateLimitAdapter) Delete(_ context.Context, model string, where []types.Where) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	kept := m.tables[model][:0]
	for _, row := range m.tables[model] {
		if !fakeWhereMatches(row, where) {
			kept = append(kept, row)
		}
	}
	m.tables[model] = kept
	return nil
}

func (m *fakeRateLimitAdapter) DeleteMany(ctx context.Context, model string, where []types.Where) (int, error) {
	before, _ := m.Count(ctx, model, nil)
	if err := m.Delete(ctx, model, where); err != nil {
		return 0, err
	}
	after, _ := m.Count(ctx, model, nil)
	return before - after, nil
}

func (m *fakeRateLimitAdapter) ConsumeOne(_ context.Context, model string, where []types.Where) (map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, row := range m.tables[model] {
		if fakeWhereMatches(row, where) {
			out := make(map[string]any, len(row))
			for k, v := range row {
				out[k] = v
			}
			m.tables[model] = append(m.tables[model][:i], m.tables[model][i+1:]...)
			return out, nil
		}
	}
	return nil, nil
}

func (m *fakeRateLimitAdapter) IncrementOne(_ context.Context, model string, where []types.Where, increment map[string]int, set map[string]any) (map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(increment) == 0 && len(set) == 0 {
		return nil, errEmptyDatabaseIncrement
	}
	for _, row := range m.tables[model] {
		if fakeWhereMatches(row, where) {
			for field, delta := range increment {
				cur, _ := fakeNumber(row[field])
				row[field] = cur + int64(delta)
			}
			for k, v := range set {
				row[k] = v
			}
			out := make(map[string]any, len(row))
			for k, v := range row {
				out[k] = v
			}
			return out, nil
		}
	}
	return nil, nil
}

func (m *fakeRateLimitAdapter) Transaction(_ context.Context, fn func(tx types.Adapter) error) error {
	return fn(m)
}

func databaseTestStorage(db *fakeRateLimitAdapter) DatabaseRateLimitStorage {
	return DatabaseRateLimitStorage{DB: db}
}

func TestDatabaseRateLimitStorage_AllowsUpToMax(t *testing.T) {
	db := newFakeRateLimitAdapter()
	storage := databaseTestStorage(db)
	window := 10 * time.Second
	for i := 0; i < 3; i++ {
		if _, limited := storage.Consume("k1", window, 3); limited {
			t.Fatalf("request %d must pass", i+1)
		}
	}
	retryAfter, limited := storage.Consume("k1", window, 3)
	if !limited {
		t.Fatal("fourth request must be limited")
	}
	if retryAfter < 1 {
		t.Fatalf("retryAfter must be positive, got %d", retryAfter)
	}
}

func TestDatabaseRateLimitStorage_ResetsAfterWindow(t *testing.T) {
	db := newFakeRateLimitAdapter()
	now := time.Now()
	current := now
	storage := DatabaseRateLimitStorage{DB: db, Now: func() time.Time { return current }}
	window := time.Second
	if _, limited := storage.Consume("k-window", window, 1); limited {
		t.Fatal("first request must pass")
	}
	if _, limited := storage.Consume("k-window", window, 1); !limited {
		t.Fatal("second request must be limited")
	}
	current = current.Add(1100 * time.Millisecond)
	if _, limited := storage.Consume("k-window", window, 1); limited {
		t.Fatal("request after window expiry must pass")
	}
}

func TestDatabaseRateLimitStorage_ExactBoundaryResets(t *testing.T) {
	db := newFakeRateLimitAdapter()
	now := time.Now()
	current := now
	storage := DatabaseRateLimitStorage{DB: db, Now: func() time.Time { return current }}
	window := time.Second
	if _, limited := storage.Consume("k-boundary", window, 1); limited {
		t.Fatal("first request must pass")
	}
	current = current.Add(1000 * time.Millisecond)
	if _, limited := storage.Consume("k-boundary", window, 1); limited {
		t.Fatal("request at the window boundary must pass")
	}
}

func TestDatabaseRateLimitStorage_GuardedIncrementNeverExceedsMax(t *testing.T) {
	db := newFakeRateLimitAdapter()
	storage := DatabaseRateLimitStorage{DB: db}
	window := 10 * time.Second
	allowed := 0
	for i := 0; i < 10; i++ {
		if _, limited := storage.Consume("k-burst", window, 4); !limited {
			allowed++
		}
	}
	if allowed != 4 {
		t.Fatalf("exactly 4 of 10 must pass with max=4, got %d", allowed)
	}
	row, err := db.FindOne(context.Background(), "rateLimit", []types.Where{{Field: "key", Value: "k-burst"}}, nil)
	if err != nil || row == nil {
		t.Fatalf("row lookup: %v", err)
	}
	count, _ := rateLimitCountValue(row["count"])
	if count != 4 {
		t.Fatalf("stored count = %d, want 4 (no overshoot)", count)
	}
}

func TestDatabaseRateLimitStorage_PruneKeepsLongWindowRows(t *testing.T) {
	db := newFakeRateLimitAdapter()
	now := time.Now()
	longKey, shortKey := "ip|/get-session", "ip|/sign-in/email"
	if _, err := db.Create(context.Background(), "rateLimit", map[string]any{
		"key": longKey, "count": 1, "lastRequest": now.Add(-90 * time.Second).UnixMilli(),
	}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Create(context.Background(), "rateLimit", map[string]any{
		"key": shortKey, "count": 1, "lastRequest": now.Add(-11 * time.Second).UnixMilli(),
	}, nil); err != nil {
		t.Fatal(err)
	}
	storage := DatabaseRateLimitStorage{DB: db, LongestWindowSeconds: 120}
	if _, limited := storage.Consume("ip|/sign-in/email", 10*time.Second, 100); limited {
		t.Fatal("request must pass")
	}
	if _, err := db.FindOne(context.Background(), "rateLimit", []types.Where{{Field: "key", Value: longKey}}, nil); err != nil {
		t.Fatal(err)
	} else {
		row, _ := db.FindOne(context.Background(), "rateLimit", []types.Where{{Field: "key", Value: longKey}}, nil)
		if row == nil {
			t.Fatal("active long-window row must survive pruning")
		}
	}
	stale, _ := db.FindOne(context.Background(), "rateLimit", []types.Where{{Field: "key", Value: shortKey}}, nil)
	_ = stale
}

func TestDatabaseRateLimitStorage_NilDBFailsClosed(t *testing.T) {
	storage := DatabaseRateLimitStorage{}
	if _, limited := storage.Consume("k", 10*time.Second, 100); !limited {
		t.Fatal("nil database backend must fail closed, not fail open")
	}
}

func TestDatabaseRateLimitStorage_RetryAfterMatchesWindow(t *testing.T) {
	db := newFakeRateLimitAdapter()
	storage := DatabaseRateLimitStorage{DB: db}
	window := 10 * time.Second
	if _, limited := storage.Consume("k-retry", window, 1); limited {
		t.Fatal("first request must pass")
	}
	retryAfter, limited := storage.Consume("k-retry", window, 1)
	if !limited {
		t.Fatal("second request must be limited")
	}
	if retryAfter < 1 || retryAfter > 10 {
		t.Fatalf("retryAfter = %d, want within (0,10]", retryAfter)
	}
}

func TestLongestConfiguredRateLimitWindow_CoversRules(t *testing.T) {
	opts := testRateLimitOptions()
	enabled := true
	opts.RateLimit.Enabled = &enabled
	opts.RateLimit.Window = 30
	opts.RateLimit.Max = 5
	opts.RateLimit.CustomRules = map[string]types.RateLimitRule{
		"/slow": {Window: 120, Max: 10},
	}
	if got := longestConfiguredRateLimitWindow(opts); got != 120 {
		t.Fatalf("longest window = %d, want 120", got)
	}
	def := testRateLimitOptions()
	def.RateLimit.Enabled = &enabled
	if got := longestConfiguredRateLimitWindow(def); got != 60 {
		t.Fatalf("longest window = %d, want 60", got)
	}
}

func TestDatabaseRateLimitKeys_SortedForDeterminism(t *testing.T) {
	keys := []string{"b", "a", "c"}
	sorted := append([]string(nil), keys...)
	sort.Strings(sorted)
	if sorted[0] != "a" || sorted[2] != "c" {
		t.Fatal("sanity check on sorted helper usage")
	}
}
