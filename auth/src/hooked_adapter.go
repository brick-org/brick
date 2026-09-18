package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/brick-org/brick/auth/src/types"
)

// HookedAdapter wraps a DBAdapter and fires lifecycle hooks
// (BeforeCreate/AfterCreate, etc.) around each operation.
// Hooks are collected from all plugins during auth.BetterAuth.
//
// This mirrors vendor/better-auth/packages/better-auth/src/db/with-hooks.ts
// to the extent the Go hook surface allows. Intentional deviations from
// upstream are documented here (not on the shared BeforeHookFunc/AfterHookFunc
// types, which live outside this file):
//
// Hook contracts (Go):
//   - Before hooks abort error-only or silently: return (nil, err) to abort
//     with an error without touching the database; return
//     (nil, ErrHookAbort) to abort silently with null and no write (no error
//     surfaced), mirroring upstream's literal `false` return. Use errors.Is
//     to detect the sentinel (it may be wrapped).
//   - A non-nil map returned from a before hook is MERGED over the pending
//     payload (mutated keys win, omitted keys survive), mirroring upstream's
//     ({...actualData, ...result.data}).
//   - After hooks defer past successful Transaction commit (collected during
//     tx, flushed on success, skipped on rollback), mirroring upstream's
//     queueAfterTransactionHook. Outside transactions they run synchronously
//     and their failures PROPAGATE: the call fails without rolling back the
//     committed write, mirroring upstream's immediate-execution rejection
//     (core/src/context/transaction.ts:170 "does not retry an immediately
//     executed hook when it fails"). Failures are additionally reported to
//     the adapter logger when one is configured (log-and-report); when no
//     HookLogger is configured (the default), the error still propagates —
//     pass a logger via NewHookedAdapterWithLogger (wired automatically from
//     Options.Logger by BetterAuth) to hear them alongside the returned
//     error. Decision D05 (AUTH-S6-01): aligned to throw.
//   - Post-commit (Transaction flush) after-hook errors PROPAGATE: the
//     Transaction call fails without rolling back committed work, mirroring
//     upstream's post-commit rethrow. Install an OnAfterCommitHookError
//     handler (HookedAdapterOptions) to report each failure and keep the
//     call succeeding; a reporting handler never suppresses later hooks,
//     while an unhandled failure stops the flush at the first error — both
//     mirroring runWithTransaction.
//
// Delete/DeleteMany pre-reads:
//   - Delete fetches the row first so hooks receive the actual record. When no
//     row matches, before hooks, overrides, the inner Delete, and after hooks
//     are all skipped. A pre-read failure fails closed: the error is returned
//     without running hooks, overrides, or the write (upstream swallows the
//     error and skips the write, returning null).
//   - DeleteMany fetches all matching rows first. An empty match fires zero
//     hooks while the inner DeleteMany (or its override) still runs. A
//     pre-read failure is reported to the logger when one is configured and
//     deletion still proceeds with zero hooks (upstream also proceeds after
//     a failed pre-read); with no logger the failure is discarded quietly,
//     as with after-hook errors.
//
// UpdateMany reuses the Update before/after hooks, mirroring
// updateManyWithHooks. The shared row-typed after hook still fires with nil
// for backwards compatibility; the AfterBulk hook carries the bulk result
// count (upstream passes it to the shared update.after hook, which the
// row-typed AfterHookFunc cannot carry).
//
// Adapter overrides (PluginAdapterOverrides, collected from plugins via
// types.CollectAdapterOverrides plus explicit HookedAdapterOptions.Overrides
// with explicit entries winning) replace the inner write for the hooked
// operations, mirroring the custom*Fn parameters of with-hooks.ts: hooks
// still wrap the override (before runs on the merged payload, after runs on
// the override result). Supported keys: "create", "update", "updateMany",
// "delete", "deleteMany". Override argument/return conventions (fail closed
// on shape mismatch, inner skipped):
//   - create:     fn(ctx, model string, data map[string]any, sel []string)
//     returns (map[string]any, error); nil result means null.
//   - update:     fn(ctx, model string, where []Where, data map[string]any)
//     returns (map[string]any, error); nil result means null.
//   - updateMany: fn(ctx, model string, where []Where, data map[string]any)
//     returns (int, error).
//   - delete:     fn(ctx, model string, where []Where) returns (any, error);
//     the value is ignored.
//   - deleteMany: fn(ctx, model string, where []Where) returns (int, error).
//
// Reads (FindOne/FindMany/Count), ConsumeOne, and IncrementOne have no
// override surface: upstream defines custom fns only for the hooked writes,
// and ConsumeOne keeps its atomic race gate on the inner adapter.
//
// Field validators/transforms (FieldAttribute.Validator/Transform) execute
// when HookedAdapterOptions.FieldSchemas provides per-model attributes:
// Validator.Input then Transform.Input run on the pending write payload
// before before-hooks (a rejection aborts the operation with no write);
// Transform.Output runs on rows returned from Create/Update/FindOne/
// FindMany/IncrementOne/ConsumeOne. Validator.Output is never executed,
// mirroring upstream (parseInputData validates inputs only; outputs are
// filtered, never validated). With no schemas for a model the adapter
// leaves values untouched.
//
// ConsumeOne fires the Delete before/after hooks around the atomic consume,
// mirroring consumeOneWithHooks: the first concurrent caller wins,
// subsequent racers resolve to (nil, nil) without firing after hooks.
// A silent abort (ErrHookAbort) skips the consume with (nil, nil).
// IncrementOne has no hooks and delegates directly.
//
// Hook sources mirror the upstream context labels: "plugin:<id>" for plugin
// hooks (see vendor/.../src/context/helpers.ts) and "user" for user-supplied
// databaseHooks.
//
// Transaction propagates hooks into the tx adapter; after hooks defer to
// post-commit (see above).
type HookedAdapter struct {
	inner            Adapter
	hooks            mergedHooks
	logger           HookLogger
	onAfterCommitErr AfterCommitHookErrorHandler
	fields           map[string]map[string]types.FieldAttribute
	overrides        types.PluginAdapterOverrides
	inTx             bool
	pending          *[]pendingAfter
}

// pendingAfter is a deferred after-hook queued during a transaction.
type pendingAfter struct {
	op       string
	model    string
	source   string
	ctx      context.Context
	data     map[string]any
	hook     AfterHookFunc
	bulkHook types.AfterBulkHookFunc
	count    int
}

// AfterCommitHookErrorHandler reports a post-commit (Transaction flush)
// after-hook failure after the surrounding work has committed.
//
// It mirrors upstream runWithTransaction's onAfterCommitHookError option
// (core/src/context/transaction.ts): reporting cannot roll back committed
// work or suppress later hooks, and the Transaction call succeeds. Without
// a handler the first flush failure fails the call instead. The reported
// error wraps the operation, model, and hook source; use errors.Is/As to
// reach the hook's cause.
type AfterCommitHookErrorHandler func(err error)

// HookedAdapterOptions tunes HookedAdapter beyond hooks and logging.
//
// Zero value preserves historical behavior except for the upstream-faithful
// fixes that always apply (before-hook merge, post-commit propagation).
type HookedAdapterOptions struct {
	// Logger additionally reports synchronous after-hook failures and
	// DeleteMany pre-read failures. Nil (the default) skips the report;
	// after-hook failures still propagate to the caller (D05: aligned to
	// throw).
	Logger HookLogger
	// OnAfterCommitHookError reports post-commit after-hook failures. Nil
	// (the default) lets the first flush failure fail the Transaction
	// call; a set handler keeps the call succeeding and observes every
	// failure while later hooks still run.
	OnAfterCommitHookError AfterCommitHookErrorHandler
	// FieldSchemas provides per-model field attributes whose
	// Validator/Transform execute around hooked operations. Nil (the
	// default) leaves values untouched. See the HookedAdapter contract.
	FieldSchemas map[string]map[string]types.FieldAttribute
	// Overrides replaces the inner write per operation (see the
	// HookedAdapter contract for keys and conventions). Entries win over
	// plugin-collected overrides. Nil means plugin-collected only.
	Overrides types.PluginAdapterOverrides
}

// HookLogger receives After-hook failures for observability. It is
// deliberately tiny so BetterAuth can wire opts.Logger without changing
// default output: when nil (the default) failures are still propagated to
// the caller, just without the log report.
type HookLogger interface {
	Error(msg string, args ...any)
}

// HookLogFunc adapts a plain function to HookLogger.
type HookLogFunc func(msg string, args ...any)

func (f HookLogFunc) Error(msg string, args ...any) { f(msg, args...) }

type mergedHooks struct {
	// keyed by model name → list of hooks in declaration order
	models map[string][]modelHookEntry
}

type modelHookEntry struct {
	source string // "plugin:<id>" or "user"
	hooks  ModelHooks
}

// NewHookedAdapter wraps inner with plugin hooks followed by user hooks.
// Plugin adapter overrides are collected automatically (explicit options
// win; see NewHookedAdapterWithOptions).
func NewHookedAdapter(inner Adapter, plugins []Plugin, userHooks DBHooks) Adapter {
	return NewHookedAdapterWithOptions(inner, plugins, userHooks, HookedAdapterOptions{})
}

// NewHookedAdapterWithLogger wraps inner like NewHookedAdapter and
// additionally reports After-hook errors to logger (failures propagate to
// the caller regardless; a nil logger only skips the report). Upstream TS
// name: getWithHooks.
func NewHookedAdapterWithLogger(inner Adapter, plugins []Plugin, userHooks DBHooks, logger HookLogger) Adapter {
	return NewHookedAdapterWithOptions(inner, plugins, userHooks, HookedAdapterOptions{Logger: logger})
}

// NewHookedAdapterWithOptions wraps inner like NewHookedAdapter with full
// tuning: after-commit error handling, field validator/transform schemas,
// and explicit adapter overrides. Plugin hooks run before user hooks;
// plugin-collected adapter overrides apply unless an explicit Overrides
// entry wins for the same operation. When no hooks, schemas, or overrides
// apply, inner is returned unwrapped. Upstream TS name: getWithHooks.
func NewHookedAdapterWithOptions(inner Adapter, plugins []Plugin, userHooks DBHooks, opts HookedAdapterOptions) Adapter {
	mh := mergedHooks{models: make(map[string][]modelHookEntry)}
	for _, p := range plugins {
		if p == nil {
			continue
		}
		dbHooks := p.Hooks()
		for model, hooks := range dbHooks {
			mh.models[model] = append(mh.models[model], modelHookEntry{
				source: "plugin:" + p.ID(),
				hooks:  hooks,
			})
		}
	}
	for model, hooks := range userHooks {
		mh.models[model] = append(mh.models[model], modelHookEntry{
			source: "user",
			hooks:  hooks,
		})
	}
	overrides := types.CollectAdapterOverrides(plugins)
	for op, fn := range opts.Overrides {
		if fn == nil {
			continue
		}
		overrides[op] = fn
	}
	// If nothing applies, skip the wrapper entirely.
	if len(mh.models) == 0 && len(overrides) == 0 && len(opts.FieldSchemas) == 0 {
		return inner
	}
	return &HookedAdapter{
		inner:            inner,
		hooks:            mh,
		logger:           opts.Logger,
		onAfterCommitErr: opts.OnAfterCommitHookError,
		fields:           opts.FieldSchemas,
		overrides:        overrides,
	}
}

func isHookAbort(err error) bool {
	return errors.Is(err, types.ErrHookAbort)
}

// mergeHookData overlays mutated over base (mutated keys win, omitted keys
// survive), mirroring upstream's {...actualData, ...result.data}. The result
// is always a fresh map; neither input is mutated. A nil mutated map keeps
// the base unchanged.
func mergeHookData(base, mutated map[string]any) map[string]any {
	if len(mutated) == 0 {
		return base
	}
	out := make(map[string]any, len(base)+len(mutated))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range mutated {
		out[k] = v
	}
	return out
}

// applyFieldInput runs Validator.Input then Transform.Input over the pending
// write payload for model (validator wins per field, mirroring
// parseInputData's validator-first branches). A rejection aborts the
// operation with no write. The result is a fresh map; the input is never
// mutated. Models without schemas pass through untouched.
func (h *HookedAdapter) applyFieldInput(model string, data map[string]any) (map[string]any, error) {
	schema := h.fields[model]
	if len(schema) == 0 {
		return data, nil
	}
	out := make(map[string]any, len(data))
	for k, v := range data {
		out[k] = v
	}
	for key, value := range data {
		attr, ok := schema[key]
		if !ok {
			continue
		}
		if attr.Validator != nil && attr.Validator.Input != nil {
			if err := attr.Validator.Input.Validate(value); err != nil {
				return nil, fmt.Errorf("auth: field %q validation failed on model %q: %w", key, model, err)
			}
			continue
		}
		if attr.Transform != nil && attr.Transform.Input != nil {
			next, err := attr.Transform.Input(value)
			if err != nil {
				return nil, fmt.Errorf("auth: field %q transform failed on model %q: %w", key, model, err)
			}
			out[key] = next
		}
	}
	return out, nil
}

// applyFieldOutput runs Transform.Output over a returned row for model.
// Failures abort the read. Nil rows pass through; models without output
// transforms return the row untouched (no copy).
func (h *HookedAdapter) applyFieldOutput(model string, row map[string]any) (map[string]any, error) {
	if row == nil {
		return nil, nil
	}
	schema := h.fields[model]
	if len(schema) == 0 {
		return row, nil
	}
	var out map[string]any
	for key, value := range row {
		attr, ok := schema[key]
		if !ok || attr.Transform == nil || attr.Transform.Output == nil {
			continue
		}
		if out == nil {
			out = make(map[string]any, len(row))
			for k, v := range row {
				out[k] = v
			}
		}
		next, err := attr.Transform.Output(value)
		if err != nil {
			return nil, fmt.Errorf("auth: field %q output transform failed on model %q: %w", key, model, err)
		}
		out[key] = next
	}
	if out == nil {
		return row, nil
	}
	return out, nil
}

// Override operation keys consulted on HookedAdapter.overrides.
const (
	overrideCreate     = "create"
	overrideUpdate     = "update"
	overrideUpdateMany = "updateMany"
	overrideDelete     = "delete"
	overrideDeleteMany = "deleteMany"
)

// runCreateOverride runs the "create" adapter override when present.
// It reports (result, handled=true, err); unhandled operations return
// handled=false. Shape mismatches fail closed: the inner write is skipped.
func (h *HookedAdapter) runCreateOverride(ctx context.Context, model string, data map[string]any, sel []string) (map[string]any, bool, error) {
	fn := h.overrides[overrideCreate]
	if fn == nil {
		return nil, false, nil
	}
	res, err := fn(ctx, model, data, sel)
	if err != nil {
		return nil, true, err
	}
	if res == nil {
		return nil, true, nil
	}
	row, ok := res.(map[string]any)
	if !ok {
		return nil, true, fmt.Errorf("auth: adapter override %q returned %T, want map[string]any", overrideCreate, res)
	}
	return row, true, nil
}

// runUpdateOverride runs the "update" adapter override when present.
func (h *HookedAdapter) runUpdateOverride(ctx context.Context, model string, where []Where, data map[string]any) (map[string]any, bool, error) {
	fn := h.overrides[overrideUpdate]
	if fn == nil {
		return nil, false, nil
	}
	res, err := fn(ctx, model, where, data)
	if err != nil {
		return nil, true, err
	}
	if res == nil {
		return nil, true, nil
	}
	row, ok := res.(map[string]any)
	if !ok {
		return nil, true, fmt.Errorf("auth: adapter override %q returned %T, want map[string]any", overrideUpdate, res)
	}
	return row, true, nil
}

// runUpdateManyOverride runs the "updateMany" adapter override when present.
func (h *HookedAdapter) runUpdateManyOverride(ctx context.Context, model string, where []Where, data map[string]any) (int, bool, error) {
	fn := h.overrides[overrideUpdateMany]
	if fn == nil {
		return 0, false, nil
	}
	res, err := fn(ctx, model, where, data)
	if err != nil {
		return 0, true, err
	}
	count, ok := res.(int)
	if !ok {
		return 0, true, fmt.Errorf("auth: adapter override %q returned %T, want int", overrideUpdateMany, res)
	}
	return count, true, nil
}

// runDeleteOverride runs the "delete" adapter override when present.
func (h *HookedAdapter) runDeleteOverride(ctx context.Context, model string, where []Where) (bool, error) {
	fn := h.overrides[overrideDelete]
	if fn == nil {
		return false, nil
	}
	_, err := fn(ctx, model, where)
	if err != nil {
		return true, err
	}
	return true, nil
}

// runDeleteManyOverride runs the "deleteMany" adapter override when present.
func (h *HookedAdapter) runDeleteManyOverride(ctx context.Context, model string, where []Where) (int, bool, error) {
	fn := h.overrides[overrideDeleteMany]
	if fn == nil {
		return 0, false, nil
	}
	res, err := fn(ctx, model, where)
	if err != nil {
		return 0, true, err
	}
	count, ok := res.(int)
	if !ok {
		return 0, true, fmt.Errorf("auth: adapter override %q returned %T, want int", overrideDeleteMany, res)
	}
	return count, true, nil
}

// flushPending runs deferred after-hooks post-commit. A set
// OnAfterCommitHookError handler observes every failure and the flush
// succeeds; otherwise the first failure is logged (when a logger is
// configured) and returned, skipping the remaining hooks — mirroring
// upstream runWithTransaction, where reporting cannot roll back committed
// work and an unhandled failure throws.
func (h *HookedAdapter) flushPending(pending []pendingAfter) error {
	for _, p := range pending {
		var err error
		if p.bulkHook != nil {
			err = p.bulkHook(p.ctx, p.count)
		} else if p.hook != nil {
			err = p.hook(p.ctx, p.data)
		}
		if err == nil {
			continue
		}
		wrapped := fmt.Errorf("auth: db %s.after hook failed (model %s, source %s): %w", p.op, p.model, p.source, err)
		if h.onAfterCommitErr != nil {
			h.onAfterCommitErr(wrapped)
			continue
		}
		h.logAfterErr(p.op, p.model, p.source, err)
		return wrapped
	}
	return nil
}

func (h *HookedAdapter) logAfterErr(op, model, source string, err error) {
	if err == nil || h.logger == nil {
		return
	}
	h.logger.Error("auth: db "+op+".after hook failed", "model", model, "source", source, "error", err)
}

func (h *HookedAdapter) logPreReadErr(op, model string, err error) {
	if err == nil || h.logger == nil {
		return
	}
	h.logger.Error("auth: db "+op+" pre-read failed", "model", model, "error", err)
}

// runAfterOrDefer runs an after hook immediately outside transactions, or
// queues it for post-commit flush inside transactions. Outside transactions
// a failure is logged (when a logger is configured) and PROPAGATED: the
// call fails without rolling back the committed write, mirroring upstream's
// immediate-execution rejection. Decision D05 (AUTH-S6-01): aligned to throw.
func (h *HookedAdapter) runAfterOrDefer(ctx context.Context, op, model, source string, hook AfterHookFunc, data map[string]any) error {
	if hook == nil {
		return nil
	}
	if h.inTx && h.pending != nil {
		*h.pending = append(*h.pending, pendingAfter{
			op: op, model: model, source: source,
			ctx: ctx, data: data, hook: hook,
		})
		return nil
	}
	if err := hook(ctx, data); err != nil {
		h.logAfterErr(op, model, source, err)
		return fmt.Errorf("auth: db %s.after hook failed (model %s, source %s): %w", op, model, source, err)
	}
	return nil
}

// runAfterBulkOrDefer runs a bulk after hook immediately outside
// transactions, or queues it for post-commit flush inside transactions.
// Failures propagate like runAfterOrDefer (D05: aligned to throw).
func (h *HookedAdapter) runAfterBulkOrDefer(ctx context.Context, op, model, source string, hook types.AfterBulkHookFunc, count int) error {
	if hook == nil {
		return nil
	}
	if h.inTx && h.pending != nil {
		*h.pending = append(*h.pending, pendingAfter{
			op: op, model: model, source: source,
			ctx: ctx, bulkHook: hook, count: count,
		})
		return nil
	}
	if err := hook(ctx, count); err != nil {
		h.logAfterErr(op, model, source, err)
		return fmt.Errorf("auth: db %s.after hook failed (model %s, source %s): %w", op, model, source, err)
	}
	return nil
}

// Adapter forwarding methods — Create, Update, UpdateMany, Delete, DeleteMany, ConsumeOne have hooks.

func (h *HookedAdapter) Create(ctx context.Context, model string, data map[string]any, sel []string) (map[string]any, error) {
	payload, err := h.applyFieldInput(model, data)
	if err != nil {
		return nil, err
	}
	effective := payload
	for _, entry := range h.hooks.models[model] {
		if entry.hooks.Create.Before != nil {
			mutated, err := entry.hooks.Create.Before(ctx, effective)
			if err != nil {
				if isHookAbort(err) {
					return nil, nil
				}
				return nil, err
			}
			effective = mergeHookData(effective, mutated)
		}
	}
	var result map[string]any
	if row, handled, err := h.runCreateOverride(ctx, model, effective, sel); err != nil {
		return nil, err
	} else if handled {
		result = row
	} else {
		result, err = h.inner.Create(ctx, model, effective, sel)
		if err != nil {
			return nil, err
		}
	}
	result, err = h.applyFieldOutput(model, result)
	if err != nil {
		return nil, err
	}
	for _, entry := range h.hooks.models[model] {
		if entry.hooks.Create.After != nil {
			if err := h.runAfterOrDefer(ctx, "create", model, entry.source, entry.hooks.Create.After, result); err != nil {
				return result, err
			}
		}
	}
	return result, nil
}

func (h *HookedAdapter) runUpdateBefore(ctx context.Context, model string, data map[string]any) (map[string]any, error) {
	payload, err := h.applyFieldInput(model, data)
	if err != nil {
		return nil, err
	}
	effective := payload
	for _, entry := range h.hooks.models[model] {
		if entry.hooks.Update.Before != nil {
			mutated, err := entry.hooks.Update.Before(ctx, effective)
			if err != nil {
				return nil, err
			}
			effective = mergeHookData(effective, mutated)
		}
	}
	return effective, nil
}

func (h *HookedAdapter) runUpdateAfter(ctx context.Context, model string, result map[string]any) error {
	for _, entry := range h.hooks.models[model] {
		if entry.hooks.Update.After != nil {
			if err := h.runAfterOrDefer(ctx, "update", model, entry.source, entry.hooks.Update.After, result); err != nil {
				return err
			}
		}
	}
	return nil
}

func (h *HookedAdapter) runUpdateAfterBulk(ctx context.Context, model string, count int) error {
	for _, entry := range h.hooks.models[model] {
		if entry.hooks.Update.AfterBulk != nil {
			if err := h.runAfterBulkOrDefer(ctx, "update", model, entry.source, entry.hooks.Update.AfterBulk, count); err != nil {
				return err
			}
		}
	}
	return nil
}

func (h *HookedAdapter) Update(ctx context.Context, model string, where []Where, data map[string]any) (map[string]any, error) {
	effective, err := h.runUpdateBefore(ctx, model, data)
	if err != nil {
		if isHookAbort(err) {
			return nil, nil
		}
		return nil, err
	}
	var result map[string]any
	if row, handled, err := h.runUpdateOverride(ctx, model, where, effective); err != nil {
		return nil, err
	} else if handled {
		result = row
	} else {
		result, err = h.inner.Update(ctx, model, where, effective)
		if err != nil {
			return nil, err
		}
	}
	result, err = h.applyFieldOutput(model, result)
	if err != nil {
		return nil, err
	}
	if err := h.runUpdateAfter(ctx, model, result); err != nil {
		return result, err
	}
	return result, nil
}

// UpdateMany fires the Update before/after hooks around the bulk write,
// mirroring upstream updateManyWithHooks (which reuses the update hooks).
// Before-hook results merge over the update payload; abort with an error,
// or abort silently with ErrHookAbort (0, nil). The shared row-typed after
// hook still fires with nil for backwards compatibility while AfterBulk
// carries the bulk result count. After-hook errors propagate outside
// transactions (D05: aligned to throw) and post-commit inside them
// (see flushPending).
func (h *HookedAdapter) UpdateMany(ctx context.Context, model string, where []Where, data map[string]any) (int, error) {
	effective, err := h.runUpdateBefore(ctx, model, data)
	if err != nil {
		if isHookAbort(err) {
			return 0, nil
		}
		return 0, err
	}
	var count int
	if n, handled, err := h.runUpdateManyOverride(ctx, model, where, effective); err != nil {
		return 0, err
	} else if handled {
		count = n
	} else {
		count, err = h.inner.UpdateMany(ctx, model, where, effective)
		if err != nil {
			return 0, err
		}
	}
	if err := h.runUpdateAfter(ctx, model, nil); err != nil {
		return count, err
	}
	if err := h.runUpdateAfterBulk(ctx, model, count); err != nil {
		return count, err
	}
	return count, nil
}

func (h *HookedAdapter) Delete(ctx context.Context, model string, where []Where) error {
	// Fetch the row before deletion so hooks receive the actual record.
	row, err := h.inner.FindOne(ctx, model, where, nil)
	if err != nil {
		// Fail closed: without the pre-read there is no row for hooks and no
		// safe basis for the write, so skip hooks and the write and surface
		// the error. Upstream swallows this error and skips the write.
		return fmt.Errorf("auth: delete pre-read %s: %w", model, err)
	}
	if row == nil {
		// Nothing matches: skip before hooks, overrides, the write, and
		// after hooks, mirroring upstream (which gates all three on the
		// fetched entity).
		return nil
	}
	for _, entry := range h.hooks.models[model] {
		if entry.hooks.Delete.Before != nil {
			_, err := entry.hooks.Delete.Before(ctx, row)
			if err != nil {
				if isHookAbort(err) {
					return nil
				}
				return err
			}
		}
	}
	if handled, err := h.runDeleteOverride(ctx, model, where); err != nil {
		return err
	} else if !handled {
		if err := h.inner.Delete(ctx, model, where); err != nil {
			return err
		}
	}
	for _, entry := range h.hooks.models[model] {
		if entry.hooks.Delete.After != nil {
			if err := h.runAfterOrDefer(ctx, "delete", model, entry.source, entry.hooks.Delete.After, row); err != nil {
				return err
			}
		}
	}
	return nil
}

func (h *HookedAdapter) DeleteMany(ctx context.Context, model string, where []Where) (int, error) {
	// Fetch all matching rows before deletion so hooks receive the actual records.
	// An empty match fires zero hooks while the inner DeleteMany still runs,
	// mirroring upstream. A pre-read failure is reported to the logger when one
	// is configured and deletion still proceeds with zero hooks, mirroring
	// upstream (which proceeds with deletion after a failed pre-read).
	var rows []map[string]any
	// Negative limit requests an explicitly unbounded pre-read: hooks must
	// observe every matching row, not just the default page.
	if rs, err := h.inner.FindMany(ctx, model, where, -1, 0, nil, nil); err != nil {
		h.logPreReadErr("deletemany", model, err)
	} else {
		rows = rs
	}
	for _, row := range rows {
		for _, entry := range h.hooks.models[model] {
			if entry.hooks.Delete.Before != nil {
				_, err := entry.hooks.Delete.Before(ctx, row)
				if err != nil {
					if isHookAbort(err) {
						return 0, nil
					}
					return 0, err
				}
			}
		}
	}
	var count int
	if n, handled, err := h.runDeleteManyOverride(ctx, model, where); err != nil {
		return 0, err
	} else if handled {
		count = n
	} else {
		count, err = h.inner.DeleteMany(ctx, model, where)
		if err != nil {
			return 0, err
		}
	}
	for _, row := range rows {
		for _, entry := range h.hooks.models[model] {
			if entry.hooks.Delete.After != nil {
				if err := h.runAfterOrDefer(ctx, "delete", model, entry.source, entry.hooks.Delete.After, row); err != nil {
					return count, err
				}
			}
		}
	}
	return count, nil
}

// EndPreservedSessions ends (instead of deleting) the rows matched by
// where, mirroring upstream endPreservedSessions
// (internal-adapter.ts:91-106): the session-delete hooks still run (so
// OAuth token revocation and back-channel logout fire on session end) while
// the physical write is replaced by endUpdate applied through UpdateMany.
// Matching callers restrict where to still-live rows. Adapter overrides for
// DeleteMany still win when present; otherwise the inner adapter performs
// the end update with no hooks of its own (routes must not observe update
// hooks for an end-of-life transition).
func (h *HookedAdapter) EndPreservedSessions(ctx context.Context, model string, where []Where, endUpdate map[string]any) (int, error) {
	var rows []map[string]any
	if rs, err := h.inner.FindMany(ctx, model, where, -1, 0, nil, nil); err != nil {
		h.logPreReadErr("endpreserved", model, err)
	} else {
		rows = rs
	}
	for _, row := range rows {
		for _, entry := range h.hooks.models[model] {
			if entry.hooks.Delete.Before != nil {
				_, err := entry.hooks.Delete.Before(ctx, row)
				if err != nil {
					if isHookAbort(err) {
						return 0, nil
					}
					return 0, err
				}
			}
		}
	}
	var count int
	if n, handled, err := h.runDeleteManyOverride(ctx, model, where); err != nil {
		return 0, err
	} else if handled {
		count = n
	} else {
		n, err := h.inner.UpdateMany(ctx, model, where, endUpdate)
		if err != nil {
			return 0, err
		}
		count = n
	}
	for _, row := range rows {
		for _, entry := range h.hooks.models[model] {
			if entry.hooks.Delete.After != nil {
				if err := h.runAfterOrDefer(ctx, "delete", model, entry.source, entry.hooks.Delete.After, row); err != nil {
					return count, err
				}
			}
		}
	}
	return count, nil
}

// ConsumeOne fires the Delete before/after hooks around the atomic consume,
// mirroring consumeOneWithHooks. The first concurrent caller wins;
// subsequent racers resolve to (nil, nil) without firing after hooks.
// A silent abort (ErrHookAbort) skips the consume with (nil, nil).
func (h *HookedAdapter) ConsumeOne(ctx context.Context, model string, where []Where) (map[string]any, error) {
	entries := h.hooks.models[model]
	hasBefore := false
	for _, e := range entries {
		if e.hooks.Delete.Before != nil {
			hasBefore = true
			break
		}
	}
	var snapshot map[string]any
	if hasBefore {
		// Best-effort snapshot for before hooks; failures proceed without
		// hooks (upstream swallows pre-read errors here).
		if row, err := h.inner.FindOne(ctx, model, where, nil); err == nil {
			snapshot = row
		}
		if snapshot != nil {
			for _, entry := range entries {
				if entry.hooks.Delete.Before != nil {
					_, err := entry.hooks.Delete.Before(ctx, snapshot)
					if err != nil {
						if isHookAbort(err) {
							return nil, nil
						}
						return nil, err
					}
				}
			}
		}
	}
	consumed, err := h.inner.ConsumeOne(ctx, model, where)
	if err != nil {
		return nil, err
	}
	if consumed == nil {
		return nil, nil
	}
	consumed, err = h.applyFieldOutput(model, consumed)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.hooks.Delete.After != nil {
			if err := h.runAfterOrDefer(ctx, "delete", model, entry.source, entry.hooks.Delete.After, consumed); err != nil {
				return consumed, err
			}
		}
	}
	return consumed, nil
}

// IncrementOne has no hooks and delegates directly. Field output
// transforms still apply to the returned row when schemas are provided.
func (h *HookedAdapter) IncrementOne(ctx context.Context, model string, where []Where, increment map[string]int, set map[string]any) (map[string]any, error) {
	row, err := h.inner.IncrementOne(ctx, model, where, increment, set)
	if err != nil {
		return nil, err
	}
	return h.applyFieldOutput(model, row)
}

// FindOne/FindMany have no hooks. Field output transforms apply to
// returned rows when schemas are provided.

func (h *HookedAdapter) FindOne(ctx context.Context, model string, where []Where, sel []string) (map[string]any, error) {
	row, err := h.inner.FindOne(ctx, model, where, sel)
	if err != nil {
		return nil, err
	}
	return h.applyFieldOutput(model, row)
}

func (h *HookedAdapter) FindMany(ctx context.Context, model string, where []Where, limit, offset int, sortBy *SortBy, sel []string) ([]map[string]any, error) {
	rows, err := h.inner.FindMany(ctx, model, where, limit, offset, sortBy, sel)
	if err != nil {
		return nil, err
	}
	schema := h.fields[model]
	if len(schema) == 0 {
		return rows, nil
	}
	for i, row := range rows {
		out, err := h.applyFieldOutput(model, row)
		if err != nil {
			return nil, err
		}
		rows[i] = out
	}
	return rows, nil
}

func (h *HookedAdapter) Count(ctx context.Context, model string, where []Where) (int, error) {
	return h.inner.Count(ctx, model, where)
}

// Transaction propagates hooks into the tx adapter and defers after hooks
// past successful commit (collected during tx, flushed on success, skipped
// on rollback), mirroring upstream's queueAfterTransactionHook. Flush
// failures propagate (see flushPending): the call fails without rolling
// back committed work unless an after-commit handler is installed.
func (h *HookedAdapter) Transaction(ctx context.Context, fn func(tx Adapter) error) error {
	// Share the pending queue through nesting so inner-tx afters also defer
	// to the outermost commit.
	if h.inTx && h.pending != nil {
		return h.inner.Transaction(ctx, func(tx Adapter) error {
			return fn(h.txAdapter(tx, h.pending))
		})
	}
	var pending []pendingAfter
	err := h.inner.Transaction(ctx, func(tx Adapter) error {
		var txAdapter Adapter = tx
		if h.wraps() {
			txAdapter = h.txAdapter(tx, &pending)
		}
		return fn(txAdapter)
	})
	if err != nil {
		return err
	}
	return h.flushPending(pending)
}

// wraps reports whether any wrapper behavior applies (hooks, overrides, or
// field schemas). When false the inner adapter is returned unwrapped.
func (h *HookedAdapter) wraps() bool {
	return len(h.hooks.models) > 0 || len(h.overrides) > 0 || len(h.fields) > 0
}

// txAdapter builds the transaction-scoped wrapper sharing the parent's
// hooks, logger, handler, schemas, and overrides with the pending queue.
func (h *HookedAdapter) txAdapter(tx Adapter, pending *[]pendingAfter) Adapter {
	return &HookedAdapter{
		inner:            tx,
		hooks:            h.hooks,
		logger:           h.logger,
		onAfterCommitErr: h.onAfterCommitErr,
		fields:           h.fields,
		overrides:        h.overrides,
		inTx:             true,
		pending:          pending,
	}
}
