package db

import "context"

// File boundary: auth/src/db/with-hooks.go, mirroring the upstream
// src/db/with-hooks.ts boundary.
//
// Content note: this file carries the generic transaction-result helper
// (upstream transaction callback return). The hooked write operations
// (upstream getWithHooks) live in the auth root hooked_adapter.go and stay
// with the coordinator's hooked_adapter.go split task;
// see SOURCE_LAYOUT_MOVE_LIST.md.
//
// TransactionResult runs fn inside adapter.Transaction and returns its value,
// porting upstream's generic transaction callback
// (vendor/.../core/src/db/adapter/index.ts:506-509,
// vendor/.../core/src/db/adapter/factory.ts:46-48:
// transaction: <R>(callback: (trx) => Promise<R>) => Promise<R>).
//
// When the store has no real transaction implementation the adapter runs the
// callback directly against itself (sequential fallback, mirroring upstream's
// createAsIsTransaction); this helper preserves that behavior while adding
// the return-value channel the error-only Adapter.Transaction lacks. It does
// not change HookedAdapter semantics: hooks propagate through the inner
// Transaction call, and post-commit flush errors propagate as the call error.
//
// Upstream TypeScript name: transaction (generic callback return).
func TransactionResult[R any](ctx context.Context, adapter Adapter, fn func(tx Adapter) (R, error)) (R, error) {
	var out R
	err := adapter.Transaction(ctx, func(tx Adapter) error {
		v, err := fn(tx)
		if err != nil {
			return err
		}
		out = v
		return nil
	})
	if err != nil {
		var zero R
		return zero, err
	}
	return out, nil
}
