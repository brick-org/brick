package db

import (
	"context"

	"github.com/uptrace/bun"
)

// NextFrappeIntPK allocates the next integer PK for a Frappe shared table
// whose `name` column is an integer (e.g. tabCRM View Settings).
//
// It takes a transaction-scoped advisory lock keyed on table + ":name" (one
// arg — key and table cannot drift), then reads COALESCE(MAX(name),0)+1.
// The lock is held until the surrounding transaction commits or rolls back.
//
// MUST be called on the tx-bound *DB inside RunInTx:
// pg_advisory_xact_lock releases at transaction end, so calling this outside
// a tx would release the lock at statement end and MAX+1 would race. M5's
// autoname `autoincrement` strategy calls this helper; callers stamp the
// Frappe columns (creation/modified/owner/…) app-side as today.
//
// Table and column travel as bun.Ident — never interpolated.
func (d *DB) NextFrappeIntPK(ctx context.Context, table string) (int64, error) {
	var locked any
	if err := d.Raw(ctx, &locked, "SELECT pg_advisory_xact_lock(hashtext(?))", table+":name"); err != nil {
		return 0, err
	}
	var next int64
	if err := d.Raw(ctx, &next,
		"SELECT COALESCE(MAX(?), 0) + 1 FROM ?",
		bun.Ident("name"), bun.Ident(table),
	); err != nil {
		return 0, err
	}
	return next, nil
}
