package auth_test

import (
	"context"
	"errors"
	"testing"

	auth "github.com/brick-org/brick/auth/src"
)

type hookCall struct {
	op     string
	source string
}

func TestHookedCRUD_UpdateManyFiresUpdateHooks(t *testing.T) {
	ctx := context.Background()
	inner := newMemoryAdapter()
	if _, err := inner.Create(ctx, "user", map[string]any{"id": "1", "role": "member"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := inner.Create(ctx, "user", map[string]any{"id": "2", "role": "member"}, nil); err != nil {
		t.Fatal(err)
	}
	var calls []hookCall
	wrapped := auth.NewHookedAdapter(inner, nil, auth.DBHooks{
		"user": {
			Update: auth.OperationHooks{
				Before: func(_ context.Context, data map[string]any) (map[string]any, error) {
					calls = append(calls, hookCall{op: "before"})
					data["role"] = "admin"
					return data, nil
				},
				After: func(_ context.Context, _ map[string]any) error {
					calls = append(calls, hookCall{op: "after"})
					return nil
				},
			},
		},
	})
	n, err := wrapped.UpdateMany(ctx, "user", []auth.Where{{Field: "role", Value: "member"}}, map[string]any{"role": "member"})
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("UpdateMany count: got %d", n)
	}
	if len(calls) != 2 || calls[0].op != "before" || calls[1].op != "after" {
		t.Fatalf("UpdateMany must fire update before+after: %v", calls)
	}
	row, _ := inner.FindOne(ctx, "user", []auth.Where{{Field: "id", Value: "1"}}, nil)
	if row["role"] != "admin" {
		t.Fatalf("before-hook mutation must apply to bulk writes: %v", row)
	}
}

func TestHookedCRUD_UpdateManyBeforeAborts(t *testing.T) {
	ctx := context.Background()
	inner := newMemoryAdapter()
	if _, err := inner.Create(ctx, "user", map[string]any{"id": "1", "role": "member"}, nil); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("abort bulk write")
	afterFired := false
	wrapped := auth.NewHookedAdapter(inner, nil, auth.DBHooks{
		"user": {
			Update: auth.OperationHooks{
				Before: func(_ context.Context, _ map[string]any) (map[string]any, error) {
					return nil, boom
				},
				After: func(_ context.Context, _ map[string]any) error {
					afterFired = true
					return nil
				},
			},
		},
	})
	if _, err := wrapped.UpdateMany(ctx, "user", []auth.Where{{Field: "role", Value: "member"}}, map[string]any{"role": "x"}); !errors.Is(err, boom) {
		t.Fatalf("before error must abort UpdateMany: %v", err)
	}
	if afterFired {
		t.Fatal("after hooks must not fire when before aborts")
	}
	row, _ := inner.FindOne(ctx, "user", []auth.Where{{Field: "id", Value: "1"}}, nil)
	if row["role"] != "member" {
		t.Fatalf("aborted UpdateMany must not mutate: %v", row)
	}
}

func TestHookedCRUD_AfterHookErrorsAreLoggedAndPropagated(t *testing.T) {
	ctx := context.Background()
	hookErr := errors.New("after failed")
	var logged []string
	logger := auth.HookLogFunc(func(msg string, args ...any) {
		logged = append(logged, msg)
	})
	// AUTH-S6-01 D05 (aligned to upstream transaction.ts:170): the write
	quiet := auth.NewHookedAdapter(newMemoryAdapter(), nil, auth.DBHooks{
		"user": {Create: auth.OperationHooks{
			After: func(_ context.Context, _ map[string]any) error { return hookErr },
		}},
	})
	if _, err := quiet.Create(ctx, "user", map[string]any{"id": "1"}, nil); !errors.Is(err, hookErr) {
		t.Fatalf("after-hook error must propagate (D05 throw), got: %v", err)
	}
	// With a logger the failure is additionally reported (upstream
	inner := newMemoryAdapter()
	noisy := auth.NewHookedAdapterWithLogger(inner, nil, auth.DBHooks{
		"user": {Create: auth.OperationHooks{
			After: func(_ context.Context, _ map[string]any) error { return hookErr },
		}},
	}, logger)
	if _, err := noisy.Create(ctx, "user", map[string]any{"id": "1"}, nil); !errors.Is(err, hookErr) {
		t.Fatalf("after-hook error must propagate (D05 throw), got: %v", err)
	}
	if len(logged) != 1 {
		t.Fatalf("expected one logged after-hook error, got %v", logged)
	}
	if _, err := inner.FindOne(ctx, "user", []auth.Where{{Field: "id", Value: "1"}}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestHookedCRUD_TransactionPropagatesHooks(t *testing.T) {
	ctx := context.Background()
	inner := newMemoryAdapter()
	var creates, bulkUpdates int
	wrapped := auth.NewHookedAdapterWithLogger(inner, nil, auth.DBHooks{
		"user": {
			Create: auth.OperationHooks{
				After: func(_ context.Context, _ map[string]any) error {
					creates++
					return nil
				},
			},
			Update: auth.OperationHooks{
				After: func(_ context.Context, _ map[string]any) error {
					bulkUpdates++
					return nil
				},
			},
		},
	}, nil)
	err := wrapped.Transaction(ctx, func(tx auth.DBAdapter) error {
		if _, err := tx.Create(ctx, "user", map[string]any{"id": "1", "role": "m"}, nil); err != nil {
			return err
		}
		_, err := tx.UpdateMany(ctx, "user", []auth.Where{{Field: "id", Value: "1"}}, map[string]any{"role": "a"})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if creates != 1 {
		t.Fatalf("create hooks must fire inside transactions: %d", creates)
	}
	if bulkUpdates != 1 {
		t.Fatalf("update-many hooks must fire inside transactions: %d", bulkUpdates)
	}
}

func TestHookedCRUD_BeforeAbortSemantics(t *testing.T) {
	ctx := context.Background()
	inner := newMemoryAdapter()
	boom := errors.New("stop")
	wrapped := auth.NewHookedAdapter(inner, nil, auth.DBHooks{
		"user": {
			Create: auth.OperationHooks{
				Before: func(_ context.Context, _ map[string]any) (map[string]any, error) {
					return nil, boom
				},
			},
		},
	})
	if _, err := wrapped.Create(ctx, "user", map[string]any{"id": "1"}, nil); !errors.Is(err, boom) {
		t.Fatalf("create before error must abort: %v", err)
	}
	if n, _ := inner.Count(ctx, "user", nil); n != 0 {
		t.Fatal("aborted create must not write")
	}
}
