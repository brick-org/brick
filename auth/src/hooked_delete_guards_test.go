package auth_test

// hooked_fix_test.go: upstream conformance (Better Auth v1.7.5).

import (
	"context"
	"errors"
	"reflect"
	"testing"

	auth "github.com/brick-org/brick/auth/src"
)

// hfixAdapter is a recording Adapter with injectable read behavior.
type hfixAdapter struct {
	findOneFn  func(ctx context.Context, model string, where []auth.Where, sel []string) (map[string]any, error)
	findManyFn func(ctx context.Context, model string, where []auth.Where) ([]map[string]any, error)

	createFn     func(model string, data map[string]any) (map[string]any, error)
	updateFn     func(model string, data map[string]any) (map[string]any, error)
	updateManyFn func(model string, data map[string]any) (int, error)

	deletes     int
	deleteManys int
	lastCreate  map[string]any
	lastUpdate  map[string]any
}

func newHfixAdapter() *hfixAdapter {
	return &hfixAdapter{
		findOneFn: func(context.Context, string, []auth.Where, []string) (map[string]any, error) {
			return nil, nil
		},
		findManyFn: func(context.Context, string, []auth.Where) ([]map[string]any, error) {
			return []map[string]any{}, nil
		},
		createFn: func(_ string, data map[string]any) (map[string]any, error) {
			return cloneMap(data), nil
		},
		updateFn: func(_ string, data map[string]any) (map[string]any, error) {
			return cloneMap(data), nil
		},
		updateManyFn: func(string, map[string]any) (int, error) { return 0, nil },
	}
}

func (a *hfixAdapter) Create(_ context.Context, model string, data map[string]any, _ []string) (map[string]any, error) {
	a.lastCreate = cloneMap(data)
	return a.createFn(model, data)
}

func (a *hfixAdapter) FindOne(ctx context.Context, model string, where []auth.Where, sel []string) (map[string]any, error) {
	return a.findOneFn(ctx, model, where, sel)
}

func (a *hfixAdapter) FindMany(ctx context.Context, model string, where []auth.Where, _ int, _ int, _ *auth.SortBy, _ []string) ([]map[string]any, error) {
	return a.findManyFn(ctx, model, where)
}

func (a *hfixAdapter) Count(context.Context, string, []auth.Where) (int, error) {
	return 0, nil
}

func (a *hfixAdapter) Update(_ context.Context, model string, where []auth.Where, data map[string]any) (map[string]any, error) {
	_ = where
	a.lastUpdate = cloneMap(data)
	return a.updateFn(model, data)
}

func (a *hfixAdapter) UpdateMany(_ context.Context, model string, _ []auth.Where, data map[string]any) (int, error) {
	return a.updateManyFn(model, data)
}

func (a *hfixAdapter) Delete(context.Context, string, []auth.Where) error {
	a.deletes++
	return nil
}

func (a *hfixAdapter) DeleteMany(context.Context, string, []auth.Where) (int, error) {
	a.deleteManys++
	return 0, nil
}

func (a *hfixAdapter) ConsumeOne(_ context.Context, _ string, _ []auth.Where) (map[string]any, error) {
	return nil, nil
}

func (a *hfixAdapter) IncrementOne(_ context.Context, _ string, _ []auth.Where, increment map[string]int, set map[string]any) (map[string]any, error) {
	if len(increment) == 0 && len(set) == 0 {
		return nil, errors.New("auth: incrementOne requires a non-empty increment or set")
	}
	return nil, nil
}

func (a *hfixAdapter) Transaction(ctx context.Context, fn func(tx auth.Adapter) error) error {
	return fn(a)
}

func hfixDeleteHooks(before, after *int) auth.OperationHooks {
	return auth.OperationHooks{
		Before: func(_ context.Context, _ map[string]any) (map[string]any, error) {
			*before++
			return nil, nil
		},
		After: func(_ context.Context, _ map[string]any) error {
			*after++
			return nil
		},
	}
}

func TestHookedDeleteMissingRowSkipsHooksAndWrite(t *testing.T) {
	ctx := context.Background()
	inner := newHfixAdapter() // FindOne returns (nil, nil): no match.
	var before, after int
	wrapped := auth.NewHookedAdapter(inner, nil, auth.DBHooks{
		"user": {Delete: hfixDeleteHooks(&before, &after)},
	})
	if err := wrapped.Delete(ctx, "user", []auth.Where{{Field: "id", Value: "missing"}}); err != nil {
		t.Fatalf("delete of missing row must succeed quietly: %v", err)
	}
	if before != 0 || after != 0 {
		t.Fatalf("no hooks may fire for a missing row: before=%d after=%d", before, after)
	}
	if inner.deletes != 0 {
		t.Fatalf("inner.Delete must be skipped for a missing row: %d calls", inner.deletes)
	}
}

func TestHookedDeletePreReadErrorFailsClosed(t *testing.T) {
	ctx := context.Background()
	preErr := errors.New("find exploded")
	inner := newHfixAdapter()
	inner.findOneFn = func(context.Context, string, []auth.Where, []string) (map[string]any, error) {
		return nil, preErr
	}
	var before, after int
	wrapped := auth.NewHookedAdapter(inner, nil, auth.DBHooks{
		"user": {Delete: hfixDeleteHooks(&before, &after)},
	})
	err := wrapped.Delete(ctx, "user", []auth.Where{{Field: "id", Value: "1"}})
	if !errors.Is(err, preErr) {
		t.Fatalf("pre-read failure must fail closed, got: %v", err)
	}
	if before != 0 || after != 0 {
		t.Fatalf("no hooks may fire when the pre-read fails: before=%d after=%d", before, after)
	}
	if inner.deletes != 0 {
		t.Fatalf("inner.Delete must be skipped when the pre-read fails: %d calls", inner.deletes)
	}
}

func TestHookedDeleteManyEmptySetFiresNoHooks(t *testing.T) {
	ctx := context.Background()
	inner := newHfixAdapter() // FindMany returns an empty set.
	var before, after int
	wrapped := auth.NewHookedAdapter(inner, nil, auth.DBHooks{
		"user": {Delete: hfixDeleteHooks(&before, &after)},
	})
	if _, err := wrapped.DeleteMany(ctx, "user", []auth.Where{{Field: "id", Value: "missing"}}); err != nil {
		t.Fatal(err)
	}
	if before != 0 || after != 0 {
		t.Fatalf("no hooks may fire for an empty match: before=%d after=%d", before, after)
	}
	if inner.deleteManys != 1 {
		t.Fatalf("inner.DeleteMany must still run on an empty match: %d calls", inner.deleteManys)
	}
}

func TestHookedDeleteManyPreReadErrorLogsAndProceeds(t *testing.T) {
	ctx := context.Background()
	preErr := errors.New("findmany exploded")
	inner := newHfixAdapter()
	inner.findManyFn = func(context.Context, string, []auth.Where) ([]map[string]any, error) {
		return nil, preErr
	}
	var logged []string
	logger := auth.HookLogFunc(func(msg string, args ...any) {
		logged = append(logged, msg)
	})
	var before, after int
	wrapped := auth.NewHookedAdapterWithLogger(inner, nil, auth.DBHooks{
		"user": {Delete: hfixDeleteHooks(&before, &after)},
	}, logger)
	if _, err := wrapped.DeleteMany(ctx, "user", nil); err != nil {
		t.Fatalf("delete-many must proceed after a pre-read failure: %v", err)
	}
	if before != 0 || after != 0 {
		t.Fatalf("no hooks may fire when the pre-read fails: before=%d after=%d", before, after)
	}
	if inner.deleteManys != 1 {
		t.Fatalf("inner.DeleteMany must still run after a pre-read failure: %d calls", inner.deleteManys)
	}
	if len(logged) != 1 {
		t.Fatalf("pre-read failure must be logged, got %v", logged)
	}
}

func TestHookedDeleteUpdateManyAfterReceivesNilPayload(t *testing.T) {
	ctx := context.Background()
	inner := newHfixAdapter()
	inner.updateManyFn = func(string, map[string]any) (int, error) { return 3, nil }
	var called bool
	var payload map[string]any
	wrapped := auth.NewHookedAdapter(inner, nil, auth.DBHooks{
		"user": {Update: auth.OperationHooks{
			After: func(_ context.Context, data map[string]any) error {
				called = true
				payload = data
				return nil
			},
		}},
	})
	n, err := wrapped.UpdateMany(ctx, "user", nil, map[string]any{"role": "x"})
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("bulk count must pass through: got %d", n)
	}
	if !called {
		t.Fatal("update after hook must fire for bulk writes")
	}
	if payload != nil {
		t.Fatalf("bulk after payload must be nil, got %#v", payload)
	}
}

func TestHookedDeleteBeforeHookPartialMapMerges(t *testing.T) {
	ctx := context.Background()
	inner := newHfixAdapter()
	partial := map[string]any{"role": "admin"}
	wrapped := auth.NewHookedAdapter(inner, nil, auth.DBHooks{
		"user": {
			Create: auth.OperationHooks{
				Before: func(_ context.Context, _ map[string]any) (map[string]any, error) {
					return cloneMap(partial), nil
				},
			},
			Update: auth.OperationHooks{
				Before: func(_ context.Context, _ map[string]any) (map[string]any, error) {
					return cloneMap(partial), nil
				},
			},
		},
	})
	input := map[string]any{"id": "1", "role": "member", "email": "a@example.com"}
	if _, err := wrapped.Create(ctx, "user", input, nil); err != nil {
		t.Fatal(err)
	}
	// Merge-not-replace (upstream {...actualData, ...result.data}): keys
	want := map[string]any{"id": "1", "role": "admin", "email": "a@example.com"}
	if !reflect.DeepEqual(inner.lastCreate, want) {
		t.Fatalf("create payload must be merged, got %#v", inner.lastCreate)
	}
	if _, err := wrapped.Update(ctx, "user", []auth.Where{{Field: "id", Value: "1"}}, input); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(inner.lastUpdate, want) {
		t.Fatalf("update payload must be merged, got %#v", inner.lastUpdate)
	}
}

func TestHookedDeleteAfterHooksDeferPostCommit(t *testing.T) {
	ctx := context.Background()
	inner := newMemoryAdapter()
	var creates int
	wrapped := auth.NewHookedAdapter(inner, nil, auth.DBHooks{
		"user": {Create: auth.OperationHooks{
			After: func(_ context.Context, _ map[string]any) error {
				creates++
				return nil
			},
		}},
	})
	// Rollback skips deferred afters (upstream queueAfterTransactionHook).
	boom := errors.New("rollback")
	err := wrapped.Transaction(ctx, func(tx auth.DBAdapter) error {
		if _, err := tx.Create(ctx, "user", map[string]any{"id": "1"}, nil); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("transaction must propagate the failure, got: %v", err)
	}
	if creates != 0 {
		t.Fatalf("after hook must be skipped on rollback: %d calls", creates)
	}
	if n, _ := inner.Count(ctx, "user", nil); n != 0 {
		t.Fatal("rolled-back write must not persist")
	}
	if err := wrapped.Transaction(ctx, func(tx auth.DBAdapter) error {
		_, err := tx.Create(ctx, "user", map[string]any{"id": "2"}, nil)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if creates != 1 {
		t.Fatalf("after hook must flush post-commit: %d calls", creates)
	}
}

func TestHookedDeleteSilentAbortSkipsWrite(t *testing.T) {
	ctx := context.Background()
	inner := newMemoryAdapter()
	wrapped := auth.NewHookedAdapter(inner, nil, auth.DBHooks{
		"user": {
			Create: auth.OperationHooks{
				Before: func(_ context.Context, _ map[string]any) (map[string]any, error) {
					return nil, auth.ErrHookAbort
				},
				After: func(_ context.Context, _ map[string]any) error {
					t.Error("after must not fire on silent abort")
					return nil
				},
			},
			Update: auth.OperationHooks{
				Before: func(_ context.Context, _ map[string]any) (map[string]any, error) {
					return nil, auth.ErrHookAbort
				},
			},
			Delete: auth.OperationHooks{
				Before: func(_ context.Context, _ map[string]any) (map[string]any, error) {
					return nil, auth.ErrHookAbort
				},
				After: func(_ context.Context, _ map[string]any) error {
					t.Error("delete after must not fire on silent abort")
					return nil
				},
			},
		},
	})
	if res, err := wrapped.Create(ctx, "user", map[string]any{"id": "1"}, nil); err != nil || res != nil {
		t.Fatalf("silent abort must return (nil,nil), got %#v, %v", res, err)
	}
	if n, _ := inner.Count(ctx, "user", nil); n != 0 {
		t.Fatal("aborted create must not write")
	}
	if _, err := inner.Create(ctx, "user", map[string]any{"id": "2"}, nil); err != nil {
		t.Fatal(err)
	}
	if res, err := wrapped.Update(ctx, "user", []auth.Where{{Field: "id", Value: "2"}}, map[string]any{"name": "x"}); err != nil || res != nil {
		t.Fatalf("silent abort must return (nil,nil), got %#v, %v", res, err)
	}
	if n, err := wrapped.UpdateMany(ctx, "user", []auth.Where{{Field: "id", Value: "2"}}, map[string]any{"name": "y"}); err != nil || n != 0 {
		t.Fatalf("silent abort UpdateMany must return (0,nil), got %d, %v", n, err)
	}
	if err := wrapped.Delete(ctx, "user", []auth.Where{{Field: "id", Value: "2"}}); err != nil {
		t.Fatalf("silent abort Delete must return nil, got %v", err)
	}
	if n, _ := inner.Count(ctx, "user", nil); n != 1 {
		t.Fatal("aborted delete must not remove the row")
	}
	if n, err := wrapped.DeleteMany(ctx, "user", []auth.Where{{Field: "id", Value: "2"}}); err != nil || n != 0 {
		t.Fatalf("silent abort DeleteMany must return (0,nil), got %d, %v", n, err)
	}
	if n, _ := inner.Count(ctx, "user", nil); n != 1 {
		t.Fatal("aborted deleteMany must not remove the row")
	}
}

// hfixPlugin is a minimal Plugin exposing DB hooks.
type hfixPlugin struct {
	id    string
	hooks auth.DBHooks
}

func (p *hfixPlugin) ID() string                        { return p.id }
func (p *hfixPlugin) Init(auth.AuthContext) error       { return nil }
func (p *hfixPlugin) Endpoints() []auth.Endpoint        { return nil }
func (p *hfixPlugin) Schema() auth.PluginSchema         { return nil }
func (p *hfixPlugin) Hooks() auth.DBHooks               { return p.hooks }
func (p *hfixPlugin) RouteHooks() auth.PluginRouteHooks { return auth.PluginRouteHooks{} }
func (p *hfixPlugin) ErrorCodes() map[string]string     { return nil }

func TestHookedDeletePluginSourceLabel(t *testing.T) {
	ctx := context.Background()
	hookErr := errors.New("after failed")
	inner := newHfixAdapter()
	var argSets [][]any
	logger := auth.HookLogFunc(func(_ string, args ...any) {
		argSets = append(argSets, args)
	})
	after := func(_ context.Context, _ map[string]any) error { return hookErr }
	wrapped := auth.NewHookedAdapterWithLogger(inner,
		[]auth.Plugin{&hfixPlugin{id: "test-plugin", hooks: auth.DBHooks{
			"user": {Create: auth.OperationHooks{After: after}},
		}}},
		auth.DBHooks{
			"user": {Create: auth.OperationHooks{After: after}},
		}, logger)
	if _, err := wrapped.Create(ctx, "user", map[string]any{"id": "1"}, nil); err == nil {
		t.Fatal("after-hook error must propagate (D05 throw)")
	}
	if len(argSets) != 1 {
		t.Fatalf("expected one logged after-hook error (first failure stops the loop), got %d", len(argSets))
	}
	// Upstream labels plugin hook sources "plugin:<id>" (context/helpers.ts).
	want := []string{"plugin:test-plugin"}
	for i, args := range argSets {
		var source string
		for j := 0; j+1 < len(args); j += 2 {
			if key, ok := args[j].(string); ok && key == "source" {
				source, _ = args[j+1].(string)
			}
		}
		if source != want[i] {
			t.Fatalf("hook %d source: got %q, want %q", i, source, want[i])
		}
	}
}

func TestAtomicConsumeOneSingleRow(t *testing.T) {
	ctx := context.Background()
	inner := newMemoryAdapter()
	if _, err := inner.Create(ctx, "verification", map[string]any{"id": "1", "identifier": "tok"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := inner.Create(ctx, "verification", map[string]any{"id": "2", "identifier": "tok"}, nil); err != nil {
		t.Fatal(err)
	}
	first, err := inner.ConsumeOne(ctx, "verification", []auth.Where{{Field: "identifier", Value: "tok"}})
	if err != nil || first == nil {
		t.Fatalf("expected first consume, got %#v, %v", first, err)
	}
	if n, _ := inner.Count(ctx, "verification", nil); n != 1 {
		t.Fatalf("consume must delete exactly one row, left %d", n)
	}
	second, err := inner.ConsumeOne(ctx, "verification", []auth.Where{{Field: "identifier", Value: "tok"}})
	if err != nil || second == nil {
		t.Fatalf("expected second consume of remaining row, got %#v, %v", second, err)
	}
	third, err := inner.ConsumeOne(ctx, "verification", []auth.Where{{Field: "identifier", Value: "tok"}})
	if err != nil || third != nil {
		t.Fatalf("expected nil when empty, got %#v, %v", third, err)
	}
}

func TestAtomicIncrementOneGuarded(t *testing.T) {
	ctx := context.Background()
	inner := newMemoryAdapter()
	if _, err := inner.Create(ctx, "rateLimit", map[string]any{"id": "1", "key": "k", "count": 1}, nil); err != nil {
		t.Fatal(err)
	}
	updated, err := inner.IncrementOne(ctx, "rateLimit", []auth.Where{{Field: "id", Value: "1"}}, map[string]int{"count": 2}, nil)
	if err != nil || updated == nil {
		t.Fatalf("expected increment, got %#v, %v", updated, err)
	}
	if updated["count"] != 3 {
		t.Fatalf("expected count 3, got %#v", updated["count"])
	}
	if _, err := inner.IncrementOne(ctx, "rateLimit", []auth.Where{{Field: "id", Value: "1"}}, nil, nil); err == nil {
		t.Fatal("empty increment+set must error")
	}
	missing, err := inner.IncrementOne(ctx, "rateLimit", []auth.Where{{Field: "id", Value: "missing"}}, map[string]int{"count": 1}, nil)
	if err != nil || missing != nil {
		t.Fatalf("expected nil on no match, got %#v, %v", missing, err)
	}
}

func TestHookedConsumeOneFiresDeleteHooks(t *testing.T) {
	ctx := context.Background()
	inner := newMemoryAdapter()
	if _, err := inner.Create(ctx, "verification", map[string]any{"id": "1", "identifier": "tok"}, nil); err != nil {
		t.Fatal(err)
	}
	var befores, afters int
	wrapped := auth.NewHookedAdapter(inner, nil, auth.DBHooks{
		"verification": {Delete: auth.OperationHooks{
			Before: func(_ context.Context, _ map[string]any) (map[string]any, error) {
				befores++
				return nil, nil
			},
			After: func(_ context.Context, _ map[string]any) error {
				afters++
				return nil
			},
		}},
	})
	consumed, err := wrapped.ConsumeOne(ctx, "verification", []auth.Where{{Field: "identifier", Value: "tok"}})
	if err != nil || consumed == nil {
		t.Fatalf("expected consume, got %#v, %v", consumed, err)
	}
	if befores != 1 || afters != 1 {
		t.Fatalf("delete hooks must fire for consume: before=%d after=%d", befores, afters)
	}
	aborting := auth.NewHookedAdapter(inner, nil, auth.DBHooks{
		"verification": {Delete: auth.OperationHooks{
			Before: func(_ context.Context, _ map[string]any) (map[string]any, error) {
				return nil, auth.ErrHookAbort
			},
		}},
	})
	if _, err := inner.Create(ctx, "verification", map[string]any{"id": "2", "identifier": "tok2"}, nil); err != nil {
		t.Fatal(err)
	}
	if res, err := aborting.ConsumeOne(ctx, "verification", []auth.Where{{Field: "identifier", Value: "tok2"}}); err != nil || res != nil {
		t.Fatalf("silent abort must return (nil,nil), got %#v, %v", res, err)
	}
	if n, _ := inner.Count(ctx, "verification", []auth.Where{{Field: "identifier", Value: "tok2"}}); n != 1 {
		t.Fatal("aborted consume must not delete")
	}
}
