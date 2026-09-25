package bunadapter

// F10 (PARITY_V3 gap 14 core subset), bun side: reserve round-trip, typed duplicate errors, consume-once.

import (
	"context"
	"testing"
	"time"

	authdb "github.com/brick-org/brick/auth/src/db"
)

const f10VerificationsSchema = `
CREATE TABLE IF NOT EXISTS "verifications" ("id" TEXT PRIMARY KEY, "identifier" TEXT NOT NULL, "value" TEXT NOT NULL, "expires_at" TEXT NOT NULL, "created_at" TEXT NOT NULL, "updated_at" TEXT NOT NULL);
`

func f10VerificationAdapter(t *testing.T) authdb.Adapter {
	t.Helper()
	db := openSQLiteDB(t)
	ctx := context.Background()
	for _, stmt := range splitSchema(f10VerificationsSchema) {
		if _, err := db.NewRaw(stmt).Exec(ctx); err != nil {
			t.Fatalf("verifications schema: %v", err)
		}
	}
	return NewWithOptions(db, authdb.Config{}, Options{Models: DefaultModelDefs()})
}

func TestF10_Bun_ReserveRoundTrip(t *testing.T) {
	ctx := context.Background()
	a := f10VerificationAdapter(t)
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second)

	first, err := authdb.ReserveVerificationValue(ctx, a, "reserve:once", "reserve:once", "jti-live", expires)
	if err != nil || !first {
		t.Fatalf("first reserve = %v, %v; want true, nil", first, err)
	}
	second, err := authdb.ReserveVerificationValue(ctx, a, "reserve:once", "reserve:once", "jti-replay", expires)
	if err != nil || second {
		t.Fatalf("replay reserve = %v, %v; want false, nil", second, err)
	}
	id := authdb.VerificationReservationID("reserve:once")
	row, err := a.FindOne(ctx, "verification", []authdb.Where{{Field: "id", Value: id}}, nil)
	if err != nil || row == nil {
		t.Fatalf("reserved row must be findable: %v %v", row, err)
	}
	if row["value"] != "jti-live" || row["identifier"] != "reserve:once" {
		t.Fatalf("first-writer-wins row: %v", row)
	}
}

func TestF10_Bun_DuplicateIsTyped(t *testing.T) {
	ctx := context.Background()
	a := f10VerificationAdapter(t)
	now := time.Now().UTC().Truncate(time.Second)

	base := map[string]any{
		"id": "dup-pk", "identifier": "tok", "value": "v",
		"expiresAt": now, "createdAt": now, "updatedAt": now,
	}
	if _, err := a.Create(ctx, "verification", base, nil); err != nil {
		t.Fatalf("seed create: %v", err)
	}
	_, err := a.Create(ctx, "verification", base, nil)
	t.Logf("raw duplicate error: %v", err)
	if err == nil {
		t.Fatal("duplicate PK insert must error")
	}
	if !authdb.IsDuplicateKeyError(err) {
		t.Fatalf("duplicate PK must be a typed DuplicateKey error: %v", err)
	}

	user := map[string]any{
		"id": "u-dup", "name": "Dup", "email": "dup@x.y",
		"createdAt": now, "updatedAt": now,
	}
	if _, err := a.Create(ctx, "user", user, nil); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	user["id"] = "u-dup-2"
	if _, err := a.Create(ctx, "user", user, nil); !authdb.IsDuplicateKeyError(err) {
		t.Fatalf("duplicate unique email must be typed: %v", err)
	}
}

func TestF10_Bun_ConsumeOnce(t *testing.T) {
	ctx := context.Background()
	a := f10VerificationAdapter(t)
	now := time.Now().UTC().Truncate(time.Second)

	if _, err := a.Create(ctx, "verification", map[string]any{
		"id": "consume-1", "identifier": "tok-once", "value": "user-7",
		"expiresAt": now.Add(time.Hour), "createdAt": now, "updatedAt": now,
	}, nil); err != nil {
		t.Fatalf("seed: %v", err)
	}
	where := []authdb.Where{{Field: "identifier", Value: "tok-once"}}
	first, err := authdb.ConsumeOneWithFallback(ctx, a, "verification", where)
	if err != nil || first == nil || first["value"] != "user-7" {
		t.Fatalf("first consume = %v, %v; want the row", first, err)
	}
	second, err := authdb.ConsumeOneWithFallback(ctx, a, "verification", where)
	if err != nil || second != nil {
		t.Fatalf("second consume = %v, %v; want (nil, nil)", second, err)
	}
	n, err := a.Count(ctx, "verification", where)
	if err != nil || n != 0 {
		t.Fatalf("consumed rows must be gone: n=%d err=%v", n, err)
	}
}
