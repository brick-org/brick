package bunadapter

import (
	"context"
	"errors"
	"testing"

	authdb "github.com/brick-org/brick/auth/src/db"
)

// AUTH-D6-01: generic transaction result, sequential fallback, nested
// transactions, and post-commit error propagation through the bun adapter.
//
// Upstream: transaction <R>(callback) => Promise<R> with sequential fallback
// when config.transaction is false (factory.ts:46-48, index.ts:506-509).
// HookedAdapter post-commit behavior is owned by the auth root; here we pin
// the bun side: result capture, error propagation, savepoint nesting, and
// sequential fallback for offline adapters.

func TestBun_TransactionResultCapturesValue(t *testing.T) {
	ctx := context.Background()
	a := sqliteAdapter(t, "sqlite", Options{})
	got, err := authdb.TransactionResult(ctx, a, func(tx authdb.Adapter) (string, error) {
		if _, err := tx.Create(ctx, "widget", map[string]any{"id": "txr1", "name": "x"}, nil); err != nil {
			return "", err
		}
		return "ok", nil
	})
	if err != nil || got != "ok" {
		t.Fatalf("TransactionResult = %q, %v; want ok, nil", got, err)
	}
	if row, _ := a.FindOne(ctx, "widget", []authdb.Where{{Field: "id", Value: "txr1"}}, nil); row == nil {
		t.Fatal("committed value must persist")
	}
}

func TestBun_TransactionResultPropagatesErrorAndRollsBack(t *testing.T) {
	ctx := context.Background()
	a := sqliteAdapter(t, "sqlite", Options{})
	boom := errors.New("boom")
	_, err := authdb.TransactionResult(ctx, a, func(tx authdb.Adapter) (int, error) {
		if _, err := tx.Create(ctx, "widget", map[string]any{"id": "txr2"}, nil); err != nil {
			return 0, err
		}
		return 0, boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want boom", err)
	}
	if row, _ := a.FindOne(ctx, "widget", []authdb.Where{{Field: "id", Value: "txr2"}}, nil); row != nil {
		t.Fatal("rolled-back row must not persist")
	}
}

func TestBun_SequentialFallbackReturnsValue(t *testing.T) {
	ctx := context.Background()
	// Offline adapter (nil DB): sequential fallback runs the callback
	// directly (upstream createAsIsTransaction) and still returns its value.
	a := NewWithDialect(nil, nil, authdb.Config{}, "pg")
	got, err := authdb.TransactionResult(ctx, a, func(tx authdb.Adapter) (int, error) {
		return 7, nil
	})
	if err != nil || got != 7 {
		t.Fatalf("sequential fallback = %d, %v; want 7, nil", got, err)
	}
}

func TestBun_NestedTransactionSavepointAndPostCommit(t *testing.T) {
	ctx := context.Background()
	a := sqliteAdapter(t, "sqlite", Options{})
	// Nested failure rolls back to the savepoint only; outer + successful
	// inner persist (savepoint semantics, no nested-transaction error).
	err := a.Transaction(ctx, func(tx authdb.Adapter) error {
		if _, err := tx.Create(ctx, "widget", map[string]any{"id": "n-outer"}, nil); err != nil {
			return err
		}
		if err := tx.Transaction(ctx, func(ntx authdb.Adapter) error {
			if _, err := ntx.Create(ctx, "widget", map[string]any{"id": "n-bad"}, nil); err != nil {
				return err
			}
			return context.DeadlineExceeded
		}); err == nil {
			t.Fatal("nested failure must propagate")
		}
		return tx.Transaction(ctx, func(ntx authdb.Adapter) error {
			_, err := ntx.Create(ctx, "widget", map[string]any{"id": "n-good"}, nil)
			return err
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]bool{"n-outer": true, "n-good": true, "n-bad": false} {
		got, err := a.FindOne(ctx, "widget", []authdb.Where{{Field: "id", Value: id}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if (got != nil) != want {
			t.Fatalf("row %q present=%v want %v", id, got != nil, want)
		}
	}
}
