package routes

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/brick-org/brick/auth/src/crypto"
	"github.com/brick-org/brick/auth/src/types"
)

// mintModelID mints a model row ID honoring Advanced.Database.GenerateID via
// the shared context-generator service (types.MintModelID, mirroring upstream
// generateIdFunc in create-context.ts:248-263). Model mints pass no size
// hint, matching upstream's generateId({model}) call sites.
//
// ok=false means "omit the ID and let the database issue it" (upstream
// generateId:false / "serial", or a custom function returning false).
// Random tokens (session tokens, verification tokens, OAuth state) are NOT
// model IDs — upstream mints those with generateId(n) directly — and must
// never flow through here.
func mintModelID(opts types.Options, model string) (string, bool) {
	return types.MintModelID(opts, model, nil)
}

// setRowID sets the create-row ID from a mint result, omitting the key when
// the generator defers to the database. Callers must then consume the
// persisted-row return (see persistedRowID) so adapter/database-issued IDs
// win.
func setRowID(row map[string]any, id string, ok bool) {
	if ok {
		row["id"] = id
	}
}

// persistedRowID returns the persisted "id" from a created row, preferring
// the adapter/database-issued value over the pre-minted fallback (upstream
// create returns the persisted row; numeric serial IDs stringify like the
// factory output transform). A missing/unrecognized ID keeps the fallback so
// echo adapters behave identically to before.
func persistedRowID(row map[string]any, fallback string) string {
	if row == nil {
		return fallback
	}
	switch v := row["id"].(type) {
	case string:
		if v != "" {
			return v
		}
	case int:
		return fmt.Sprintf("%d", v)
	case int32:
		return fmt.Sprintf("%d", v)
	case int64:
		return fmt.Sprintf("%d", v)
	case uint:
		return fmt.Sprintf("%d", v)
	case uint64:
		return fmt.Sprintf("%d", v)
	case float64:
		return fmt.Sprintf("%.0f", v)
	}
	return fallback
}

// createIssuedSession creates the session row for credential/social/verified
// issuance, mirroring upstream createSession (db/internal-adapter.ts:466-603):
//
//   - secondary-only deployments (secondary storage without
//     Session.StoreSessionInDatabase) skip the primary DB entirely
//     (upstream createWithHooks executeMainFn: storeInDb); the session ID is
//     minted in memory via the context generator with a random fallback when
//     it defers to the database (`generatedId !== false ? generatedId :
//     generateId()` — there is no database to issue one);
//   - database deployments persist through opts.DB (hooks included, as with
//     every route-level create) and return the persisted row, so
//     adapter/database-issued IDs win.
//
// The token is caller-minted randomness (upstream token: generateId(32)
// direct, bypassing the context generator) and is never routed through
// mintModelID. A failing create surfaces an error; callers map it to
// ErrFailedToCreateSession.
//
// Upstream TypeScript name: createSession.
func createIssuedSession(ctx context.Context, opts types.Options, userID, token string, expiresAt, now time.Time) (types.Session, error) {
	id, ok := mintModelID(opts, "session")
	if opts.SecondaryStorage != nil && !opts.Session.StoreSessionInDatabase {
		if !ok || id == "" {
			id = crypto.GenerateID()
		}
		return types.Session{
			ID:        id,
			UserID:    userID,
			Token:     token,
			ExpiresAt: expiresAt,
			CreatedAt: now,
			UpdatedAt: now,
		}, nil
	}
	if opts.DB == nil {
		return types.Session{}, errors.New("auth: session persistence requires options.DB")
	}
	row := map[string]any{
		"userId":    userID,
		"token":     token,
		"expiresAt": expiresAt,
		"createdAt": now,
		"updatedAt": now,
	}
	setRowID(row, id, ok)
	created, err := opts.DB.Create(ctx, "session", row, nil)
	if err != nil {
		return types.Session{}, err
	}
	return rowToSession(created, opts), nil
}
