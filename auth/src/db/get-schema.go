package db

import (
	"fmt"
	"strings"
	"sync"
)

// File boundary: auth/src/db/get-schema.go, mirroring the upstream
// src/db/get-schema.ts boundary.
//
// Content note: this file ports the schema-check runtime
// (vendor/better-auth/packages/core/src/db/schema-check.ts: createSchemaCheck
// and friends). The table-shape getSchema parity (upstream get-schema.ts)
// lives in the auth root schema.go and stays with the coordinator's
// schema.go split task; see SOURCE_LAYOUT_MOVE_LIST.md.
//
// Runtime schema-check services, porting
// vendor/better-auth/packages/core/src/db/schema-check.ts (Better Auth
// v1.7.5, commit 5468e6bf).
//
// Upstream TypeScript names are noted per symbol; Go-only adaptations (channel
// promises instead of JS promises) are marked as such.

// SchemaSource names the store a schema comparison ran against.
type SchemaSource string

const (
	// SchemaSourceDatabase mirrors the "database" source passed to
	// createSchemaCheck in get-migration.ts.
	SchemaSourceDatabase SchemaSource = "database"
)

// SchemaFinding is the minimal finding shape the check consumes: a missing or
// unexpected column/table description. The full diff vocabulary lives in the
// schema owner (auth root); this package only needs kind/table/column to
// build the mismatch error.
type SchemaFinding struct {
	Kind   string
	Table  string
	Column string
}

// SchemaMismatchError mirrors upstream's SchemaMismatchError (schema-diff.ts):
// a cached mismatch rethrown on every later call without asking the store
// again, until a migration invalidates it.
type SchemaMismatchError struct {
	Findings []SchemaFinding
	Source   SchemaSource
}

func (e *SchemaMismatchError) Error() string {
	parts := make([]string, 0, len(e.Findings))
	for _, f := range e.Findings {
		if f.Column != "" {
			parts = append(parts, f.Table+"."+f.Column)
		} else {
			parts = append(parts, f.Table)
		}
	}
	return fmt.Sprintf("auth: database schema mismatch (%s): %s", string(e.Source), strings.Join(parts, ", "))
}

// SchemaCheck is the shared check for one adapter instance.
//
// A nil channel means the schema is known clean and the database revision is
// unchanged (upstream's synchronous `undefined` return). A non-nil channel
// yields nil on success or the mismatch/store error on failure. Concurrent
// first calls share one lookup; clean results are cached until invalidation;
// mismatches are cached and rethrown without re-asking; store failures are
// not kept. (Go-only adaptation of the JS promise return.)
type SchemaCheck func() <-chan error

var (
	schemaRevMu  sync.Mutex
	schemaRevs   = map[any]*int{}
	schemaRegMu  sync.Mutex
	schemaChecks = map[any]SchemaCheck{}
)

// ChecksSchema reports whether the adapter validates its schema, mirroring
// upstream checksSchema: enabled in every environment unless explicitly
// disabled.
//
// Upstream TypeScript name: checksSchema.
func ChecksSchema(validate *bool) bool {
	return validate == nil || *validate
}

// InvalidateSchemaChecks bumps the schema revision for database so its checks
// re-run, mirroring upstream invalidateSchemaChecks.
//
// Upstream TypeScript name: invalidateSchemaChecks.
func InvalidateSchemaChecks(database any) {
	if database == nil {
		return
	}
	schemaRevMu.Lock()
	defer schemaRevMu.Unlock()
	if rev, ok := schemaRevs[database]; ok {
		*rev++
	}
}

// RegisterSchemaCheck attaches a check to the adapter it verifies, mirroring
// upstream registerSchemaCheck (the adapter object itself is left untouched).
//
// Upstream TypeScript name: registerSchemaCheck.
func RegisterSchemaCheck(adapter any, check SchemaCheck) {
	if adapter == nil || check == nil {
		return
	}
	schemaRegMu.Lock()
	defer schemaRegMu.Unlock()
	schemaChecks[adapter] = check
}

// SchemaCheckFor returns the check registered for adapter, if its store is
// checked at all.
//
// Upstream TypeScript name: schemaCheckFor.
func SchemaCheckFor(adapter any) SchemaCheck {
	if adapter == nil {
		return nil
	}
	schemaRegMu.Lock()
	defer schemaRegMu.Unlock()
	return schemaChecks[adapter]
}

// CreateSchemaCheck turns a schema comparison into a check shared by one
// adapter instance, mirroring upstream createSchemaCheck: the first call runs
// find and every concurrent call shares that lookup; a clean result is cached
// until invalidation; a mismatch is kept as one SchemaMismatchError and
// rethrown on every later call without asking the store again; pending
// callers follow the new check if their revision is invalidated; a failure to
// reach the store (error or panic) is not kept, so the next call asks again.
//
// Upstream TypeScript name: createSchemaCheck.
func CreateSchemaCheck(find func() ([]SchemaFinding, error), source SchemaSource, database ...any) SchemaCheck {
	var rev *int
	if len(database) > 0 && database[0] != nil {
		db := database[0]
		schemaRevMu.Lock()
		r, ok := schemaRevs[db]
		if !ok {
			v := 0
			r = &v
			schemaRevs[db] = r
		}
		rev = r
		schemaRevMu.Unlock()
	}
	c := &schemaCheckState{
		find:   find,
		source: source,
		rev:    rev,
	}
	if rev != nil {
		c.checkedRev = *rev
	}
	return c.check
}

type schemaCheckState struct {
	mu         sync.Mutex
	find       func() ([]SchemaFinding, error)
	source     SchemaSource
	rev        *int
	checkedRev int
	clean      bool
	mismatch   error
	pending    *pendingLookup
}

type pendingLookup struct {
	done chan struct{}
	err  error
}

func completedCheck(err error) <-chan error {
	ch := make(chan error, 1)
	ch <- err
	return ch
}

func (c *schemaCheckState) currentRev() int {
	if c.rev == nil {
		return 0
	}
	schemaRevMu.Lock()
	defer schemaRevMu.Unlock()
	return *c.rev
}

func (c *schemaCheckState) check() <-chan error {
	c.mu.Lock()
	cur := c.currentRevLocked()
	if c.checkedRev != cur {
		c.checkedRev = cur
		c.clean = false
		c.mismatch = nil
		c.pending = nil
	}
	if c.clean {
		c.mu.Unlock()
		return nil
	}
	if c.mismatch != nil {
		err := c.mismatch
		c.mu.Unlock()
		return completedCheck(err)
	}
	if c.pending != nil {
		p := c.pending
		c.mu.Unlock()
		<-p.done
		return completedCheck(p.err)
	}
	p := &pendingLookup{done: make(chan struct{})}
	c.pending = p
	curSnap := cur
	c.mu.Unlock()

	go func() {
		findings, err := c.runFind()
		c.mu.Lock()
		// Revision moved while finding: discard and follow the new check
		// (upstream `if (revision?.value !== currentRevision) return
		// checkSchema()`), so old lookups never overwrite post-migration
		// verdicts and pending callers follow the new lookup.
		if c.rev != nil {
			schemaRevMu.Lock()
			latest := *c.rev
			schemaRevMu.Unlock()
			if latest != curSnap {
				c.pending = nil
				c.mu.Unlock()
				next := c.check()
				var nerr error
				if next != nil {
					nerr = <-next
				}
				p.err = nerr
				close(p.done)
				return
			}
		}
		if err != nil {
			// Store unreachable (or sync panic): not kept, next call asks
			// again (upstream clears verdict on rejection).
			c.pending = nil
			c.mu.Unlock()
			p.err = err
			close(p.done)
			return
		}
		if len(findings) > 0 {
			mismatch := &SchemaMismatchError{Findings: append([]SchemaFinding(nil), findings...), Source: c.source}
			c.mismatch = mismatch
			c.pending = nil
			c.mu.Unlock()
			p.err = mismatch
			close(p.done)
			return
		}
		if c.checkedRev == curSnap {
			c.clean = true
		}
		c.pending = nil
		c.mu.Unlock()
		p.err = nil
		close(p.done)
	}()
	<-p.done
	return completedCheck(p.err)
}

// currentRevLocked reads the revision; caller must hold c.mu (it takes the
// global revision lock, a separate mutex, so no deadlock).
func (c *schemaCheckState) currentRevLocked() int {
	if c.rev == nil {
		return 0
	}
	schemaRevMu.Lock()
	defer schemaRevMu.Unlock()
	return *c.rev
}

// runFind executes the lookup, converting a panic (upstream synchronous
// throw) into a retryable error.
func (c *schemaCheckState) runFind() (findings []SchemaFinding, err error) {
	defer func() {
		if r := recover(); r != nil {
			findings = nil
			if e, ok := r.(error); ok {
				err = e
			} else {
				err = fmt.Errorf("auth: schema check failed: %v", r)
			}
		}
	}()
	return c.find()
}
