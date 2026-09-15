package brick

import (
	"context"

	"github.com/brick-org/brick/db"
)

// NoRecord is a sentinel type for operations where no record exists (List, Create).
type NoRecord struct{}

// AccessCtx carries contextual information for guard evaluation.
type AccessCtx[Row any] struct {
	Actor   any
	Session any
	Record  Row
	Context context.Context
	Filter  map[string]any
}

// Guard evaluates access for a typed resource.
//
//   - Check  — runs before any DB query; return an error to deny the operation.
//     Use for session-level checks (auth, roles, rate limits) that don't need
//     a fetched row.
//   - Filter — returns []db.Where appended to every CRUD query so access scoping
//     happens at the SQL level. Out-of-scope rows return 404, not 403.
type Guard[Row any] struct {
	Check  func(ctx AccessCtx[Row]) error
	Filter func(ctx AccessCtx[Row]) []db.Where
}

// CheckRowsAffected runs Check if rowsAffected is 0.
func (g Guard[Row]) CheckRowsAffected(ctx AccessCtx[Row], rowsAffected int64) error {
	if rowsAffected > 0 {
		return nil
	}
	if g.Check != nil {
		return g.Check(ctx)
	}
	return nil
}

// GuardChain chains multiple guards together.
type GuardChain[Row any] struct {
	guards []Guard[Row]
}

// Guards creates a guard chain from multiple guards.
func Guards[Row any](guards ...Guard[Row]) GuardChain[Row] {
	return GuardChain[Row]{guards: guards}
}

// CheckRowsAffected runs Check for each guard in order.
func (gc GuardChain[Row]) CheckRowsAffected(ctx AccessCtx[Row], rowsAffected int64) error {
	for _, g := range gc.guards {
		if err := g.CheckRowsAffected(ctx, rowsAffected); err != nil {
			return err
		}
	}
	return nil
}

// Access defines per-operation guards for a resource. Each slot is uniform
// `[]Guard[map[string]any]` because the runtime CRUD pipeline operates on
// dynamic maps. For List and Create the AccessCtx.Record will be nil.
//
// Apps compose guards from any source — brick ships no auth-aware helpers
// (IsAuthenticated, OwnsRecord, etc.) since brick is auth-agnostic.
type Access struct {
	List   []Guard[map[string]any]
	Get    []Guard[map[string]any]
	Create []Guard[map[string]any]
	Update []Guard[map[string]any]
	Delete []Guard[map[string]any]
}
