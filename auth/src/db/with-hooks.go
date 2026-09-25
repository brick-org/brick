package db

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

// File boundary: auth/src/db/with-hooks.go (upstream src/db/with-hooks.ts).
//
// Content note: this file carries the generic transaction-result helper
// (upstream transaction callback return). The hooked write operations
// (upstream getWithHooks) live in the auth root hooked_adapter.go and stay
// with the coordinator's hooked_adapter.go split task.
//
// TransactionResult runs fn inside adapter.Transaction and returns its value,
// porting upstream's generic transaction callback
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

// VerificationReservationID returns the deterministic primary key for a
// verification reservation, mirroring upstream reserveVerificationValue
// (db/internal-adapter.ts): base64url without padding over the SHA-256 of
// "reserve:" + the RAW identifier (UTF-8 bytes).
//
// The verification.identifier column is non-unique, so uniqueness comes from
// this deterministic PK: the INSERT is the first-writer-wins gate and a
// duplicate is detected portably by re-reading the row (see
// ReserveVerificationValue).
func VerificationReservationID(identifier string) string {
	sum := sha256.Sum256([]byte("reserve:" + identifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ReserveVerificationValue races to create a verification reservation row
// exactly once, mirroring upstream reserveVerificationValue
// (db/internal-adapter.ts): the first caller wins (true), every later caller
// observes the taken marker (false). Use it for replay tombstones where the
// first caller must win.
//
//   - identifier is the RAW identifier: it feeds VerificationReservationID
//     (upstream hashes data.identifier, not the stored form).
//   - storedIdentifier is the row's identifier column (the caller's
//     processIdentifier result honoring the store-identifier option,
//     including the plain fallback for non-plain modes). Callers that store
//     identifiers as-is pass identifier twice.
//   - The create carries an explicit id, which is the forceAllowId:true path:
//     Go adapters always honor caller-supplied ids (there is no factory
//     warn-and-strip), so no extra flag is needed.
//   - Like upstream, duplicate detection is portable: on ANY create error the
//     row is re-read by PK, and a present row means the race was lost
//     (false, nil). A missed re-read returns the failure typed via
//     MapDuplicateKeyError when it is a constraint violation, so routes can
//     branch on IsDuplicateKeyError instead of driver strings.
//
// Secondary-storage-only verification cannot enforce the deterministic-PK
// gate (upstream throws there); callers keep that fail-closed check — this
// helper is the database path only.
func ReserveVerificationValue(ctx context.Context, adapter Adapter, identifier, storedIdentifier, value string, expiresAt time.Time) (bool, error) {
	reservationID := VerificationReservationID(identifier)
	now := time.Now().UTC()
	_, err := adapter.Create(ctx, "verification", map[string]any{
		"id":         reservationID,
		"identifier": storedIdentifier,
		"value":      value,
		"expiresAt":  expiresAt,
		"createdAt":  now,
		"updatedAt":  now,
	}, nil)
	if err == nil {
		return true, nil
	}
	row, findErr := adapter.FindOne(ctx, "verification", []Where{{Field: "id", Value: reservationID}}, nil)
	if findErr == nil && row != nil {
		return false, nil
	}
	return false, MapDuplicateKeyError("verification", err)
}

// ErrConsumeOneUnsupported is returned by adapters without an atomic
// single-row consume so ConsumeOneWithFallback can take the FindOne+Delete
// fallback inside a Transaction. Adapters with a real ConsumeOne (like bun
// on every dialect) never return it.
var ErrConsumeOneUnsupported = errors.New("db: adapter does not support atomic ConsumeOne")

// ConsumeOneWithFallback atomically consumes a single row matching where,
// preferring the adapter's ConsumeOne race gate (the primitive the
// reset/verify/delete-token consume paths must use so exactly one concurrent
// caller wins).
//
// Adapters that cannot consume atomically return (wrapping)
// ErrConsumeOneUnsupported from ConsumeOne, and the consume falls back to
// FindOne+Delete inside a Transaction, pinning the exact row by id for the
// delete (the id-only guard, matching the snapshot-guard fallback). Any
// other ConsumeOne error propagates without a fallback delete. A row without
// an id fails closed (no delete) since the fallback cannot pin it.
func ConsumeOneWithFallback(ctx context.Context, adapter Adapter, model string, where []Where) (map[string]any, error) {
	row, err := adapter.ConsumeOne(ctx, model, where)
	if err == nil {
		return row, nil
	}
	if !errors.Is(err, ErrConsumeOneUnsupported) {
		return nil, err
	}
	return TransactionResult(ctx, adapter, func(tx Adapter) (map[string]any, error) {
		found, err := tx.FindOne(ctx, model, where, nil)
		if err != nil || found == nil {
			return nil, err
		}
		id, ok := found["id"]
		if !ok || id == nil {
			return nil, fmt.Errorf("db: cannot fall back to FindOne+Delete for model %q without a row id", model)
		}
		if err := tx.Delete(ctx, model, []Where{{Field: "id", Value: id}}); err != nil {
			return nil, err
		}
		return found, nil
	})
}
