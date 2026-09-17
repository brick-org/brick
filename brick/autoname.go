package brick

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"

	"github.com/brick-org/brick/brick/db"
	"github.com/brick-org/brick/dsl/schema"
)

// ─── PK constructors ───────────────────────────────────────────────────────
// Only the strategies with live DSL users are constructed. Series, format,
// and from-field were cut (no consumer; re-add on demand with tests).

// UUIDPK declares a UUID primary key (the Brick default, but with a
// configurable column name).
func UUIDPK(column string) *schema.PK {
	return &schema.PK{Column: column, Type: schema.FieldUUID, Autoname: schema.Autoname{Strategy: schema.AutonameUUID}}
}

// AutoincPK declares an integer primary key allocated via NextFrappeIntPK:
// advisory-lock + MAX+1 inside the create tx. Race-safe, gap-tolerant,
// matching Frappe semantics for int `name` columns.
func AutoincPK(column string) *schema.PK {
	return &schema.PK{Column: column, Type: schema.FieldInt, Autoname: schema.Autoname{Strategy: schema.AutonameAutoinc}}
}

// AutonameHash generates n random lowercase base-36 characters.
func AutonameHash(n int) schema.Autoname {
	return schema.Autoname{Strategy: schema.AutonameHash, HashLen: n}
}

// AutonamePrompt requires the client to send the PK value in the create body.
func AutonamePrompt() schema.Autoname {
	return schema.Autoname{Strategy: schema.AutonamePrompt}
}

// ─── Runtime generation ────────────────────────────────────────────────────

// applyAutoname populates body[pk.Column] according to the PK's strategy.
// Runs inside the create tx, AFTER guard checks and validation —
// unauthenticated or invalid creates must never burn counters or take
// advisory locks. txDB must be the tx-bound *db.DB (autoinc's advisory
// lock is transaction-scoped).
func applyAutoname(ctx context.Context, txDB *db.DB, table string, pk *schema.PK, body map[string]any) error {
	col := pk.Column
	switch pk.Autoname.Strategy {
	case schema.AutonamePrompt:
		v, _ := body[col].(string)
		if strings.TrimSpace(v) == "" {
			var v Validation
			v.Add(col, "required", col+" is required")
			return Unprocessable(v.Errs())
		}
		return nil
	case schema.AutonameAutoinc:
		next, err := txDB.NextFrappeIntPK(ctx, table)
		if err != nil {
			return err
		}
		body[col] = next
		return nil
	}

	// A BeforeCreate-style caller may have set the value deliberately
	// (client values are stripped earlier via the readonly PK field).
	if v, ok := body[col].(string); ok && v != "" {
		return nil
	}

	switch pk.Autoname.Strategy {
	case schema.AutonameUUID, "":
		body[col] = newUUID()
	case schema.AutonameHash:
		body[col] = randBase36(pk.Autoname.HashLen)
	}
	return nil
}

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	hexed := hex.EncodeToString(b[:])
	return hexed[0:8] + "-" + hexed[8:12] + "-" + hexed[12:16] + "-" + hexed[16:20] + "-" + hexed[20:32]
}

func randBase36(n int) string {
	if n <= 0 {
		n = 10
	}
	const charset = "0123456789abcdefghijklmnopqrstuvwxyz"
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	for i := range buf {
		buf[i] = charset[int(buf[i])%len(charset)]
	}
	return string(buf)
}
