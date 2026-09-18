package bunadapter

import (
	"testing"

	authdb "github.com/brick-org/brick/auth/src/db"
)

func testAdapter(cfg authdb.Config, dialect string) *Adapter {
	return &Adapter{cfg: cfg, dialect: dialect}
}

func TestParity_ColMapping(t *testing.T) {
	a := testAdapter(authdb.Config{
		FieldNames: map[string]string{"user.email": "email_address"},
	}, "pg")
	if got, err := a.colName("user", "email"); err != nil || got != "email_address" {
		t.Fatalf("custom FieldName: got %q err %v want email_address", got, err)
	}
	if got, err := a.colName("user", "userId"); err != nil || got != "user_id" {
		t.Fatalf("camelToSnake fallback: got %q err %v want user_id", got, err)
	}
	if got, err := a.colName("session", "email"); err != nil || got != "email" {
		t.Fatalf("unmapped model fallback: got %q err %v want email", got, err)
	}
	if _, err := a.colName("user", "a b"); err == nil {
		t.Fatal("unsafe column identifier must be rejected")
	}
}

func TestParity_TableMapping(t *testing.T) {
	a := testAdapter(authdb.Config{ModelNames: map[string]string{"user": "app_users"}}, "pg")
	if got, err := a.tableName("user"); err != nil || got != "app_users" {
		t.Fatalf("custom ModelName: got %q err %v", got, err)
	}
	if got, err := a.tableName("session"); err != nil || got != "sessions" {
		t.Fatalf("plural fallback: got %q err %v", got, err)
	}
	if _, err := a.tableName("user; DROP TABLE users"); err == nil {
		t.Fatal("unsafe table identifier must be rejected")
	}
}

func mustCol(t *testing.T, a *Adapter, model, field string) string {
	t.Helper()
	col, err := a.colName(model, field)
	if err != nil {
		t.Fatalf("colName(%q, %q): %v", model, field, err)
	}
	return col
}

func TestParity_EncodeRow(t *testing.T) {
	a := testAdapter(authdb.Config{
		FieldNames: map[string]string{"user.email": "email_address"},
	}, "pg")
	row, err := a.encodeRow("user", map[string]any{"email": "a@b.c", "userId": "u1"})
	if err != nil {
		t.Fatal(err)
	}
	if row["email_address"] != "a@b.c" {
		t.Fatalf("encode custom column: %v", row)
	}
	if row["user_id"] != "u1" {
		t.Fatalf("encode snake fallback: %v", row)
	}
}

func TestParity_DecodeRowReversesCustomFieldNames(t *testing.T) {
	a := testAdapter(authdb.Config{
		FieldNames: map[string]string{"user.email": "email_address"},
	}, "pg")
	// Physical custom column decodes to logical camelCase keys per contract
	// (transformOutput key part).
	decoded, err := a.decodeRow("user", map[string]any{"email_address": "a@b.c", "user_id": "u1"})
	if err != nil {
		t.Fatal(err)
	}
	if decoded["email"] != "a@b.c" {
		t.Fatalf("decode custom column: %v", decoded)
	}
	if decoded["userId"] != "u1" {
		t.Fatalf("decode passthrough: %v", decoded)
	}
	if _, ok := decoded["email_address"]; ok {
		t.Fatalf("custom physical key must not leak: %v", decoded)
	}
}

func TestParity_SelectProjection(t *testing.T) {
	a := testAdapter(authdb.Config{
		FieldNames: map[string]string{"user.email": "email_address"},
	}, "pg")
	row := map[string]any{"id": "1", "email": "a@b.c", "name": "n"}
	projected := a.projectRow("user", row, []string{"email"})
	if len(projected) != 1 || projected["email"] != "a@b.c" {
		t.Fatalf("project single logical field: %v", projected)
	}
	if got := a.projectRow("user", row, nil); len(got) != 3 {
		t.Fatalf("empty select returns full row: %v", got)
	}
	cols, err := a.selectColumns("user", []string{"email", "userId", "email"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cols) != 2 || cols[0] != "email_address" || cols[1] != "user_id" {
		t.Fatalf("selectColumns maps logical->physical deduped: %v", cols)
	}
}

func mustResolve(t *testing.T, a *Adapter, model string, w authdb.Where) (string, string, any) {
	t.Helper()
	op, col, val, err := a.resolveWhere(model, w)
	if err != nil {
		t.Fatalf("resolveWhere(%v): %v", w, err)
	}
	return op, col, val
}

func TestParity_ResolveWhereEqualityAndNull(t *testing.T) {
	a := testAdapter(authdb.Config{}, "pg")
	op, col, val := mustResolve(t, a, "user", authdb.Where{Field: "userId", Value: "u1"})
	if op != "= ?" || col != "user_id" || val != "u1" {
		t.Fatalf("eq: %q %q %v", op, col, val)
	}
	if op, _, _ := mustResolve(t, a, "user", authdb.Where{Field: "email", Value: nil}); op != "IS NULL" {
		t.Fatalf("eq nil must be IS NULL, got %q", op)
	}
	if op, _, _ := mustResolve(t, a, "user", authdb.Where{Field: "email", Operator: authdb.OpNe, Value: nil}); op != "IS NOT NULL" {
		t.Fatalf("ne nil must be IS NOT NULL, got %q", op)
	}
}

func TestParity_ResolveWhereLikePortability(t *testing.T) {
	pg := testAdapter(authdb.Config{}, "pg")
	lite := testAdapter(authdb.Config{}, "sqlite")

	// Upstream parity: LIKE on the default (sensitive) path on all dialects,
	// including Postgres; ILIKE is pg-insensitive only.
	if op, _, _ := mustResolve(t, pg, "user", authdb.Where{Field: "name", Operator: authdb.OpContains, Value: "ali"}); op != "LIKE ?" {
		t.Fatalf("pg contains must be LIKE, got %q", op)
	}
	// Non-Postgres dialects use portable LIKE on the default path.
	if op, _, val := mustResolve(t, lite, "user", authdb.Where{Field: "name", Operator: authdb.OpContains, Value: "ali"}); op != "LIKE ?" || val != "%ali%" {
		t.Fatalf("sqlite contains must be LIKE, got %q %v", op, val)
	}
	if _, _, val := mustResolve(t, lite, "user", authdb.Where{Field: "name", Operator: authdb.OpStartsWith, Value: "al"}); val != "al%" {
		t.Fatalf("starts_with pattern: %v", val)
	}
	if _, _, val := mustResolve(t, lite, "user", authdb.Where{Field: "name", Operator: authdb.OpEndsWith, Value: "ce"}); val != "%ce" {
		t.Fatalf("ends_with pattern: %v", val)
	}
	// Insensitive mode: ILIKE on pg, LOWER() LIKE elsewhere.
	if op, _, _ := mustResolve(t, pg, "user", authdb.Where{Field: "name", Operator: authdb.OpContains, Value: "ali", Mode: "insensitive"}); op != "ILIKE ?" {
		t.Fatalf("pg insensitive must be ILIKE, got %q", op)
	}
	if op, _, _ := mustResolve(t, lite, "user", authdb.Where{Field: "name", Operator: authdb.OpContains, Value: "ali", Mode: "insensitive"}); op != "LOWER_LIKE" {
		t.Fatalf("sqlite insensitive must be LOWER_LIKE, got %q", op)
	}
}

func TestParity_DialectHelpers(t *testing.T) {
	if got := (&Adapter{dialect: ""}).Dialect(); got != "pg" {
		t.Fatalf("empty dialect defaults to pg, got %q", got)
	}
	if !testAdapter(authdb.Config{}, "postgres").isPostgres() {
		t.Fatal("postgres alias must count as pg")
	}
	if testAdapter(authdb.Config{}, "mysql").isPostgres() {
		t.Fatal("mysql must not count as pg")
	}
	if !testAdapter(authdb.Config{}, "sqlite").supportsReturning() {
		t.Fatal("sqlite supports RETURNING")
	}
	if testAdapter(authdb.Config{}, "mysql").supportsReturning() {
		t.Fatal("mysql must not use RETURNING")
	}
	if got := NewWithDialect(nil, nil, authdb.Config{}, "sqlite"); got.(*Adapter).Dialect() != "sqlite" {
		t.Fatal("NewWithDialect must preserve the dialect label")
	}
}
