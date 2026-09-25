package auth_test

// hooked_wave1_test.go: upstream conformance (Better Auth v1.7.5).

import (
	"context"
	"errors"
	"testing"

	auth "github.com/brick-org/brick/auth/src"
	"github.com/brick-org/brick/auth/src/types"
)

func TestWave1BeforeHookPartialMapMerges(t *testing.T) {
	ctx := context.Background()
	inner := newHfixAdapter()
	wrapped := auth.NewHookedAdapter(inner, nil, auth.DBHooks{
		"user": {
			Create: auth.OperationHooks{
				Before: func(_ context.Context, _ map[string]any) (map[string]any, error) {
					return map[string]any{"role": "admin"}, nil
				},
			},
			Update: auth.OperationHooks{
				Before: func(_ context.Context, _ map[string]any) (map[string]any, error) {
					return map[string]any{"role": "admin"}, nil
				},
			},
		},
	})
	input := map[string]any{"id": "1", "role": "member", "email": "a@example.com"}
	if _, err := wrapped.Create(ctx, "user", input, nil); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"id": "1", "role": "admin", "email": "a@example.com"}
	for k, v := range want {
		if inner.lastCreate[k] != v {
			t.Fatalf("create payload[%q] = %#v, want %#v (full %#v)", k, inner.lastCreate[k], v, inner.lastCreate)
		}
	}
	if len(inner.lastCreate) != len(want) {
		t.Fatalf("create payload = %#v, want %#v", inner.lastCreate, want)
	}
	if _, err := wrapped.Update(ctx, "user", []auth.Where{{Field: "id", Value: "1"}}, input); err != nil {
		t.Fatal(err)
	}
	for k, v := range want {
		if inner.lastUpdate[k] != v {
			t.Fatalf("update payload[%q] = %#v, want %#v (full %#v)", k, inner.lastUpdate[k], v, inner.lastUpdate)
		}
	}
}

func TestWave1UpdateManyAfterBulkReceivesCount(t *testing.T) {
	ctx := context.Background()
	inner := newHfixAdapter()
	inner.updateManyFn = func(string, map[string]any) (int, error) { return 3, nil }
	var bulkCounts []int
	var rowPayloads []map[string]any
	wrapped := auth.NewHookedAdapter(inner, nil, auth.DBHooks{
		"user": {Update: auth.OperationHooks{
			After: func(_ context.Context, data map[string]any) error {
				rowPayloads = append(rowPayloads, data)
				return nil
			},
			AfterBulk: func(_ context.Context, count int) error {
				bulkCounts = append(bulkCounts, count)
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
	if len(rowPayloads) != 1 || rowPayloads[0] != nil {
		t.Fatalf("row after hook must fire once with nil, got %#v", rowPayloads)
	}
	if len(bulkCounts) != 1 || bulkCounts[0] != 3 {
		t.Fatalf("bulk after hook must observe count 3, got %v", bulkCounts)
	}
}

func TestWave1PostCommitAfterErrorPropagates(t *testing.T) {
	ctx := context.Background()
	inner := newMemoryAdapter()
	hookErr := errors.New("post-commit after failed")
	wrapped := auth.NewHookedAdapter(inner, nil, auth.DBHooks{
		"user": {Create: auth.OperationHooks{
			After: func(_ context.Context, _ map[string]any) error { return hookErr },
		}},
	})
	err := wrapped.Transaction(ctx, func(tx auth.Adapter) error {
		_, err := tx.Create(ctx, "user", map[string]any{"id": "1"}, nil)
		return err
	})
	if !errors.Is(err, hookErr) {
		t.Fatalf("post-commit after-hook error must propagate, got: %v", err)
	}
	if n, _ := inner.Count(ctx, "user", nil); n != 1 {
		t.Fatal("committed write must persist despite the after-hook failure")
	}
}

func TestWave1PostCommitErrorHandlerSwallows(t *testing.T) {
	ctx := context.Background()
	inner := newMemoryAdapter()
	hookErr := errors.New("post-commit after failed")
	var handled []error
	wrapped := auth.NewHookedAdapterWithOptions(inner, nil, auth.DBHooks{
		"user": {Create: auth.OperationHooks{
			After: func(_ context.Context, _ map[string]any) error { return hookErr },
		}},
	}, auth.HookedAdapterOptions{
		OnAfterCommitHookError: func(err error) { handled = append(handled, err) },
	})
	err := wrapped.Transaction(ctx, func(tx auth.Adapter) error {
		_, err := tx.Create(ctx, "user", map[string]any{"id": "1"}, nil)
		return err
	})
	if err != nil {
		t.Fatalf("handled post-commit error must not fail the call, got: %v", err)
	}
	if len(handled) != 1 || !errors.Is(handled[0], hookErr) {
		t.Fatalf("handler must observe the hook error, got %v", handled)
	}
}

func TestWave1PostCommitHandlerRunsLaterHooks(t *testing.T) {
	ctx := context.Background()
	inner := newMemoryAdapter()
	firstErr := errors.New("first after failed")
	var handled []error
	var secondRan bool
	wrapped := auth.NewHookedAdapterWithOptions(inner, nil, auth.DBHooks{
		"user": {Create: auth.OperationHooks{
			After: func(_ context.Context, data map[string]any) error {
				if data["id"] == "1" {
					return firstErr
				}
				secondRan = true
				return nil
			},
		}},
	}, auth.HookedAdapterOptions{
		OnAfterCommitHookError: func(err error) { handled = append(handled, err) },
	})
	err := wrapped.Transaction(ctx, func(tx auth.Adapter) error {
		if _, err := tx.Create(ctx, "user", map[string]any{"id": "1"}, nil); err != nil {
			return err
		}
		_, err := tx.Create(ctx, "user", map[string]any{"id": "2"}, nil)
		return err
	})
	if err != nil {
		t.Fatalf("handled errors must not fail the call, got: %v", err)
	}
	if len(handled) != 1 || !errors.Is(handled[0], firstErr) {
		t.Fatalf("handler must observe the first error, got %v", handled)
	}
	if !secondRan {
		t.Fatal("later post-commit hooks must still run when a handler is installed")
	}
}

func TestWave1PostCommitWithoutHandlerStopsAtFirstError(t *testing.T) {
	ctx := context.Background()
	inner := newMemoryAdapter()
	firstErr := errors.New("first after failed")
	var secondRan bool
	wrapped := auth.NewHookedAdapter(inner, nil, auth.DBHooks{
		"user": {Create: auth.OperationHooks{
			After: func(_ context.Context, data map[string]any) error {
				if data["id"] == "1" {
					return firstErr
				}
				secondRan = true
				return nil
			},
		}},
	})
	err := wrapped.Transaction(ctx, func(tx auth.Adapter) error {
		if _, err := tx.Create(ctx, "user", map[string]any{"id": "1"}, nil); err != nil {
			return err
		}
		_, err := tx.Create(ctx, "user", map[string]any{"id": "2"}, nil)
		return err
	})
	if !errors.Is(err, firstErr) {
		t.Fatalf("first post-commit error must propagate, got: %v", err)
	}
	if secondRan {
		t.Fatal("later hooks must be skipped once an unhandled post-commit error propagates")
	}
}

func TestWave1AdapterOverrideReplacesInnerCreate(t *testing.T) {
	ctx := context.Background()
	inner := newHfixAdapter()
	called := false
	wrapped := auth.NewHookedAdapterWithOptions(inner, nil, nil, auth.HookedAdapterOptions{
		Overrides: types.PluginAdapterOverrides{
			"create": func(ctx context.Context, args ...any) (any, error) {
				called = true
				return map[string]any{"id": "custom", "from": "override"}, nil
			},
		},
	})
	got, err := wrapped.Create(ctx, "user", map[string]any{"id": "1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("create override must be consulted")
	}
	if got["from"] != "override" {
		t.Fatalf("override result must pass through, got %#v", got)
	}
	if inner.lastCreate != nil {
		t.Fatalf("inner.Create must be skipped when an override handles create, got %#v", inner.lastCreate)
	}
}

func TestWave1AdapterOverrideTypeMismatchFailsClosed(t *testing.T) {
	ctx := context.Background()
	inner := newHfixAdapter()
	wrapped := auth.NewHookedAdapterWithOptions(inner, nil, nil, auth.HookedAdapterOptions{
		Overrides: types.PluginAdapterOverrides{
			"create": func(ctx context.Context, args ...any) (any, error) {
				return "not-a-row", nil
			},
		},
	})
	if _, err := wrapped.Create(ctx, "user", map[string]any{"id": "1"}, nil); err == nil {
		t.Fatal("override returning the wrong shape must fail closed")
	}
	if inner.lastCreate != nil {
		t.Fatalf("inner.Create must not run after an override shape error, got %#v", inner.lastCreate)
	}
}

func TestWave1FieldValidatorRejectsWrite(t *testing.T) {
	ctx := context.Background()
	inner := newMemoryAdapter()
	boom := errors.New("bad role")
	wrapped := auth.NewHookedAdapterWithOptions(inner, nil, nil, auth.HookedAdapterOptions{
		FieldSchemas: map[string]map[string]types.FieldAttribute{
			"user": {
				"role": {Type: types.FieldTypeString, Validator: types.NewFieldValidator(
					types.FieldValidatorFunc(func(v any) error {
						if v == "bad" {
							return boom
						}
						return nil
					}), nil,
				)},
			},
		},
	})
	if _, err := wrapped.Create(ctx, "user", map[string]any{"id": "1", "role": "bad"}, nil); !errors.Is(err, boom) {
		t.Fatalf("validator rejection must abort the write, got: %v", err)
	}
	if n, _ := inner.Count(ctx, "user", nil); n != 0 {
		t.Fatal("rejected write must not persist")
	}
	if _, err := wrapped.Create(ctx, "user", map[string]any{"id": "1", "role": "good"}, nil); err != nil {
		t.Fatalf("accepting value must write, got: %v", err)
	}
}

func TestWave1FieldTransformInputOutput(t *testing.T) {
	ctx := context.Background()
	inner := newMemoryAdapter()
	upper := types.NewFieldTransform(
		types.FieldTransformFunc(func(v any) (any, error) {
			s, _ := v.(string)
			out := ""
			for _, r := range s {
				if r >= 'a' && r <= 'z' {
					r -= 'a' - 'A'
				}
				out += string(r)
			}
			return out, nil
		}),
		types.FieldTransformFunc(func(v any) (any, error) {
			s, _ := v.(string)
			return "out:" + s, nil
		}),
	)
	wrapped := auth.NewHookedAdapterWithOptions(inner, nil, nil, auth.HookedAdapterOptions{
		FieldSchemas: map[string]map[string]types.FieldAttribute{
			"user": {"nick": {Type: types.FieldTypeString, Transform: upper}},
		},
	})
	if _, err := wrapped.Create(ctx, "user", map[string]any{"id": "1", "nick": "bob"}, nil); err != nil {
		t.Fatal(err)
	}
	raw, err := inner.FindOne(ctx, "user", []auth.Where{{Field: "id", Value: "1"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if raw["nick"] != "BOB" {
		t.Fatalf("input transform must apply before storage, got %#v", raw["nick"])
	}
	got, err := wrapped.FindOne(ctx, "user", []auth.Where{{Field: "id", Value: "1"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got["nick"] != "out:BOB" {
		t.Fatalf("output transform must apply on reads, got %#v", got["nick"])
	}
}
