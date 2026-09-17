package brick

import (
	"context"

	"github.com/brick-org/brick/brick/db"
)

// NoInput is a sentinel type for hook operations that have no input body
// (e.g., BeforeDelete, AfterDelete).
type NoInput struct{}

// HookCtx carries contextual information for lifecycle hook evaluation.
// Input is the incoming request body (or NoInput). Row is the typed record
// (or NoRecord). AfterUpdate receives Previous (state before update).
// ResourceName is the brick resource name (e.g., "deals") — set by the
// runtime so generic hooks can identify which resource they are processing.
type HookCtx[Input any, Row any] struct {
	ResourceName string
	Input        *Input
	Record       Row
	Previous     Row
	Actor        any
	DB           *db.DB
	Context      context.Context
}

// HookFunc is the function signature for a lifecycle hook.
type HookFunc[Input any, Row any] func(ctx HookCtx[Input, Row]) error

// ValidateCtx carries validation context for the Validate hook.
// It runs on both create and update, after BeforeCreate/BeforeUpdate
// but before the database write.
type ValidateCtx struct {
	ResourceName string
	Input        map[string]any
	Previous     map[string]any // nil on create
	Actor        any
	Context      context.Context
	DB           *db.DB
	op           op // opCreate or opUpdate
}

// IsCreate returns true when the Validate hook fires during a create.
func (c ValidateCtx) IsCreate() bool { return c.op == opCreate }

// IsUpdate returns true when the Validate hook fires during an update.
func (c ValidateCtx) IsUpdate() bool { return c.op == opUpdate }

// Hooks holds the lifecycle hook slots for a resource.
// Each hook can return an error to abort the operation.
type Hooks[Input any, Row any] struct {
	BeforeCreate HookFunc[Input, Row]
	AfterCreate  HookFunc[Input, Row]
	BeforeUpdate HookFunc[Input, Row]
	AfterUpdate  HookFunc[Input, Row]
	BeforeDelete HookFunc[Input, Row]
	AfterDelete  HookFunc[Input, Row]
	// Validate runs after BeforeCreate/BeforeUpdate and before the DB write.
	// ctx.IsCreate() / ctx.IsUpdate() distinguishes the two paths.
	// ctx.Previous is nil on create, populated on update.
	Validate func(ctx ValidateCtx) error
}
