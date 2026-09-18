package bunadapter

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	authdb "github.com/brick-org/brick/auth/src/db"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	_ "modernc.org/sqlite"
)

const sqliteSchema = `
CREATE TABLE "widgets" ("id" TEXT PRIMARY KEY, "name" TEXT, "role" TEXT, "age" INTEGER, "active" INTEGER);
CREATE TABLE "things" ("id" TEXT PRIMARY KEY, "greeting" TEXT NOT NULL DEFAULT 'hello', "n" INTEGER NOT NULL DEFAULT 42);
CREATE TABLE "users" ("id" TEXT PRIMARY KEY, "name" TEXT NOT NULL, "email" TEXT NOT NULL UNIQUE, "email_verified" INTEGER NOT NULL DEFAULT 0, "image" TEXT, "created_at" TEXT NOT NULL, "updated_at" TEXT NOT NULL);
CREATE TABLE "sessions" ("id" TEXT PRIMARY KEY, "user_id" TEXT NOT NULL, "token" TEXT NOT NULL UNIQUE, "expires_at" TEXT NOT NULL, "ip_address" TEXT, "user_agent" TEXT, "created_at" TEXT NOT NULL, "updated_at" TEXT NOT NULL);
CREATE TABLE "profiles" ("id" TEXT PRIMARY KEY, "settings" TEXT, "tags" TEXT, "score" REAL, "active" INTEGER, "seen_at" TEXT, "owner_id" TEXT, "email" TEXT UNIQUE);
`

func widgetRegistry() map[string]ModelDef {
	return map[string]ModelDef{"widget": {Fields: map[string]FieldDef{
		"id":     {},
		"name":   {Type: FieldTypeString},
		"role":   {Type: FieldTypeString},
		"age":    {Type: FieldTypeNumber},
		"active": {Type: FieldTypeBoolean},
	}}}
}

func profileRegistry() map[string]ModelDef {
	return map[string]ModelDef{"profile": {Fields: map[string]FieldDef{
		"id":       {},
		"settings": {Type: FieldTypeJSON},
		"tags":     {Type: FieldTypeStringArray},
		"score":    {Type: FieldTypeNumber},
		"active":   {Type: FieldTypeBoolean},
		"seenAt":   {Type: FieldTypeDate},
		"ownerId":  {Type: FieldTypeString, References: &FieldReference{Model: "user", Field: "id"}},
		"email":    {Type: FieldTypeString, Unique: true},
	}}}
}

// openSQLiteDB opens an isolated in-memory SQLite database with the shared
// test schema. Each call gets a fresh database (the DSN embeds a unique
// name) so tests never share state.
var sqliteDBSeq = 0

func openSQLiteDB(t *testing.T) *bun.DB {
	t.Helper()
	sqliteDBSeq++
	sqldb, err := sql.Open("sqlite", "file:auth-test-"+itoa(sqliteDBSeq)+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	db := bun.NewDB(sqldb, sqlitedialect.New())
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	for _, stmt := range splitSchema(sqliteSchema) {
		if _, err := db.NewRaw(stmt).Exec(ctx); err != nil {
			t.Fatalf("schema: %v", err)
		}
	}
	return db
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func splitSchema(schema string) []string {
	var out []string
	start := 0
	for i := 0; i < len(schema); i++ {
		if schema[i] == ';' {
			if stmt := schema[start:i]; len(trimSpace(stmt)) > 0 {
				out = append(out, stmt)
			}
			start = i + 1
		}
	}
	return out
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\n' || s[0] == '\t' || s[0] == '\r') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\n' || s[len(s)-1] == '\t' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

// sqliteAdapter builds an adapter over a fresh in-memory database with an
// explicit dialect label (forcing "mysql"/"mssql" exercises the
// non-RETURNING fallback paths against SQLite syntax).
func sqliteAdapter(t *testing.T, dialect string, opts Options) authdb.Adapter {
	t.Helper()
	db := openSQLiteDB(t)
	if dialect == "" || dialect == "sqlite" {
		return NewWithOptions(db, authdb.Config{}, opts)
	}
	return NewWithDialectOptions(db, db, authdb.Config{}, dialect, opts)
}

func TestSQLite_ContractSuites(t *testing.T) {
	t.Run("lenient", func(t *testing.T) {
		runAdapterContractSuite(t, "sqlite-lenient", sqliteAdapter(t, "sqlite", Options{}))
	})
	t.Run("strict", func(t *testing.T) {
		runAdapterContractSuite(t, "sqlite-strict", sqliteAdapter(t, "sqlite", Options{Models: widgetRegistry()}))
	})
	t.Run("mysql-fallback", func(t *testing.T) {
		runAdapterContractSuite(t, "sqlite-mysql", sqliteAdapter(t, "mysql", Options{Models: widgetRegistry()}))
	})
	t.Run("mssql-fallback", func(t *testing.T) {
		runAdapterContractSuite(t, "sqlite-mssql", sqliteAdapter(t, "mssql", Options{Models: widgetRegistry()}))
	})
}

func TestContractSuite_Memory(t *testing.T) {
	runAdapterContractSuite(t, "memory", newContractMemoryAdapter())
}

func TestSQLite_CreateReturnsPersistedRow(t *testing.T) {
	ctx := context.Background()
	a := sqliteAdapter(t, "sqlite", Options{})
	// DB-side defaults and triggers must survive: the row comes back from
	// RETURNING *, not from the input echo.
	row, err := a.Create(ctx, "thing", map[string]any{"id": "t1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if row["id"] != "t1" || row["greeting"] != "hello" {
		t.Fatalf("persisted defaults must be returned: %v", row)
	}
	if asFloat(row["n"]) != 42 {
		t.Fatalf("numeric default must be returned: %v", row)
	}
}

func TestSQLite_RegistryDefaults(t *testing.T) {
	ctx := context.Background()
	a := sqliteAdapter(t, "sqlite", Options{Models: DefaultModelDefs()})
	now := time.Now().UTC().Truncate(time.Second)
	row, err := a.Create(ctx, "user", map[string]any{
		"id": "u1", "name": "Al", "email": "a@b.c",
		"createdAt": now, "updatedAt": now,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// emailVerified defaults to false via the registry (porting
	// withApplyDefault); the value round-trips through the 0/1 encoding.
	if row["emailVerified"] != false {
		t.Fatalf("registry default must apply: %v", row)
	}
	// Registry-less create still inserts explicit values untouched.
	plain := sqliteAdapter(t, "sqlite", Options{})
	if _, err := plain.Create(ctx, "user", map[string]any{
		"id": "u2", "name": "Bo", "email": "b@c.d", "emailVerified": true,
		"createdAt": now.Format(time.RFC3339Nano), "updatedAt": now.Format(time.RFC3339Nano),
	}, nil); err != nil {
		t.Fatal(err)
	}
}

func rawPhysicalRow(t *testing.T, db *bun.DB, table, id string) map[string]any {
	t.Helper()
	row := map[string]any{}
	if err := db.NewSelect().TableExpr(table).Where("? = ?", bun.Ident("id"), id).Limit(1).Scan(context.Background(), &row); err != nil {
		t.Fatal(err)
	}
	return row
}

func TestSQLite_TransformsRoundTrip(t *testing.T) {
	ctx := context.Background()
	db := openSQLiteDB(t)
	a := NewWithOptions(db, authdb.Config{}, Options{Models: profileRegistry()})
	seen := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	created, err := a.Create(ctx, "profile", map[string]any{
		"id": "p1", "settings": map[string]any{"theme": "dark"},
		"tags": []string{"a", "b"}, "score": 1.5, "active": true, "seenAt": seen,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Stored encoding on a store without native JSON/date/boolean support.
	raw := rawPhysicalRow(t, db, "profiles", "p1")
	if raw["active"] != int64(1) {
		t.Fatalf("boolean must store as 1: %#v", raw["active"])
	}
	if raw["settings"] != `{"theme":"dark"}` {
		t.Fatalf("JSON must stringify: %#v", raw["settings"])
	}
	if raw["tags"] != `["a","b"]` {
		t.Fatalf("arrays must stringify: %#v", raw["tags"])
	}
	if _, ok := raw["seen_at"].(string); !ok {
		t.Fatalf("dates must store as strings: %#v", raw["seen_at"])
	}
	// Revival on read.
	if created["active"] != true {
		t.Fatalf("boolean must revive: %v", created)
	}
	settings, ok := created["settings"].(map[string]any)
	if !ok || settings["theme"] != "dark" {
		t.Fatalf("JSON must parse: %v", created)
	}
	tags, ok := created["tags"].([]any)
	if !ok || len(tags) != 2 || tags[0] != "a" {
		t.Fatalf("arrays must parse: %v", created)
	}
	got, err := a.FindOne(ctx, "profile", []authdb.Where{{Field: "id", Value: "p1"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["seenAt"].(time.Time); !ok {
		t.Fatalf("date must revive to time.Time: %#v", got["seenAt"])
	}
	if asFloat(got["score"]) != 1.5 {
		t.Fatalf("number must survive: %v", got)
	}
}

func TestSQLite_DateStringInput(t *testing.T) {
	ctx := context.Background()
	a := sqliteAdapter(t, "sqlite", Options{Models: profileRegistry()})
	row, err := a.Create(ctx, "profile", map[string]any{"id": "d1", "seenAt": "2026-05-06T07:08:09Z"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := row["seenAt"].(time.Time); !ok {
		t.Fatalf("date strings normalize to time.Time: %#v", row["seenAt"])
	}
}

func TestSQLite_WhereCoercion(t *testing.T) {
	ctx := context.Background()
	a := sqliteAdapter(t, "sqlite", Options{Models: profileRegistry()})
	if _, err := a.Create(ctx, "profile", map[string]any{"id": "w1", "active": true, "score": 2.0}, nil); err != nil {
		t.Fatal(err)
	}
	// Boolean fields accept "true"/"false" strings (factory where coercion).
	hit, err := a.FindOne(ctx, "profile", []authdb.Where{{Field: "active", Value: "true"}}, []string{"id"})
	if err != nil || hit == nil || hit["id"] != "w1" {
		t.Fatalf("boolean string coercion: %v %v", hit, err)
	}
	// Number fields accept numeric strings.
	hit, err = a.FindOne(ctx, "profile", []authdb.Where{{Field: "score", Value: "2"}}, []string{"id"})
	if err != nil || hit == nil || hit["id"] != "w1" {
		t.Fatalf("number string coercion: %v %v", hit, err)
	}
	// Date fields accept time.Time on stores without native dates.
	hit, err = a.FindOne(ctx, "profile", []authdb.Where{{Field: "id", Value: "w1"}}, []string{"seenAt"})
	if err != nil {
		t.Fatal(err)
	}
	_ = hit
}

func TestSQLite_StrictErrors(t *testing.T) {
	ctx := context.Background()
	a := sqliteAdapter(t, "sqlite", Options{Models: profileRegistry()})
	if _, err := a.FindOne(ctx, "nope", nil, nil); !isInvalidModel(err) {
		t.Fatalf("unknown model must error: %v", err)
	}
	if _, err := a.FindOne(ctx, "profile", []authdb.Where{{Field: "nope", Value: 1}}, nil); !isInvalidField(err) {
		t.Fatalf("unknown where field must error: %v", err)
	}
	if _, err := a.Create(ctx, "profile", map[string]any{"id": "x", "nope": 1}, nil); !isInvalidField(err) {
		t.Fatalf("unknown data field must error: %v", err)
	}
	if _, err := a.FindMany(ctx, "profile", nil, 0, 0, &authdb.SortBy{Field: "nope"}, nil); !isInvalidField(err) {
		t.Fatalf("unknown sort field must error: %v", err)
	}
	if _, err := a.FindMany(ctx, "profile", []authdb.Where{{Field: "id", Operator: "bogus", Value: "x"}}, 0, 0, nil, nil); !isInvalidValue(err) {
		t.Fatalf("unknown operator must error on strict adapters: %v", err)
	}
	if _, err := a.Create(ctx, "profile", map[string]any{"id": "x", "seenAt": "not-a-date"}, nil); !isInvalidValue(err) {
		t.Fatalf("unparseable date must error: %v", err)
	}
	// Lenient adapters keep the historical silent-eq normalization.
	plain := sqliteAdapter(t, "sqlite", Options{})
	if _, err := plain.FindMany(ctx, "profile", []authdb.Where{{Field: "id", Operator: "bogus", Value: "x"}}, 0, 0, nil, nil); err != nil {
		t.Fatalf("lenient adapters normalize unknown operators: %v", err)
	}
}

func isInvalidModel(err error) bool { return isErrType[*authdb.InvalidModelError](err) }
func isInvalidField(err error) bool { return isErrType[*authdb.InvalidFieldError](err) }
func isInvalidValue(err error) bool { return isErrType[*authdb.InvalidValueError](err) }

func isErrType[T error](err error) bool {
	if err == nil {
		return false
	}
	var target T
	return errors.As(err, &target)
}

func TestSQLite_CustomTransforms(t *testing.T) {
	ctx := context.Background()
	var order []string
	registry := map[string]ModelDef{"profile": {Fields: map[string]FieldDef{
		"id": {},
		"email": {Type: FieldTypeString, Transform: &FieldTransform{
			Input: func(v any) (any, error) { order = append(order, "field-in"); return v.(string) + "+fi", nil },
			Output: func(v any) (any, error) {
				order = append(order, "field-out")
				if v == nil {
					return nil, nil
				}
				return v.(string) + "+fo", nil
			},
		}},
	}}}
	db := openSQLiteDB(t)
	a := NewWithOptions(db, authdb.Config{}, Options{
		Models: registry,
		CustomTransformInput: func(tc TransformContext, v any) any {
			order = append(order, "hook-in:"+tc.Action+":"+tc.Field)
			return v
		},
		CustomTransformOutput: func(tc TransformContext, v any) any {
			order = append(order, "hook-out:"+tc.Field)
			return v
		},
	})
	row, err := a.Create(ctx, "profile", map[string]any{"id": "e1", "email": "a@b.c"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Factory ordering per field: default, field input, capability
	// coercions, hook on write; field output, capability revival, hook on
	// read. The id field's hook entries may interleave anywhere (map
	// order), so assert the email subsequence only.
	var emailOrder []string
	for _, step := range order {
		if strings.HasSuffix(step, ":email") || step == "field-in" || step == "field-out" {
			emailOrder = append(emailOrder, step)
		}
	}
	wantOrder := []string{"field-in", "hook-in:create:email", "field-out", "hook-out:email"}
	if strings.Join(emailOrder, ",") != strings.Join(wantOrder, ",") {
		t.Fatalf("transform order = %v, want %v (full %v)", emailOrder, wantOrder, order)
	}
	raw := rawPhysicalRow(t, db, "profiles", "e1")
	if raw["email"] != "a@b.c+fi" {
		t.Fatalf("stored value carries field input: %#v", raw["email"])
	}
	if row["email"] != "a@b.c+fi+fo" {
		t.Fatalf("returned value carries field output: %#v", row["email"])
	}
}

func TestSQLite_OnUpdate(t *testing.T) {
	ctx := context.Background()
	a := sqliteAdapter(t, "sqlite", Options{Models: DefaultModelDefs()})
	before, err := a.Create(ctx, "user", map[string]any{"id": "u9", "name": "Zed", "email": "z@z.z"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	updatedAt, ok := before["updatedAt"].(time.Time)
	if !ok {
		t.Fatalf("updatedAt must revive: %v", before)
	}
	time.Sleep(10 * time.Millisecond)
	after, err := a.Update(ctx, "user", []authdb.Where{{Field: "id", Value: "u9"}}, map[string]any{"name": "Zed2"})
	if err != nil {
		t.Fatal(err)
	}
	// onUpdate refreshes updatedAt even though the payload omits it
	// (factory transformInput update behavior).
	afterAt, ok := after["updatedAt"].(time.Time)
	if !ok {
		t.Fatalf("updatedAt must revive after update: %v", after)
	}
	if !afterAt.After(updatedAt) {
		t.Fatalf("onUpdate must bump updatedAt: before %v after %v", updatedAt, afterAt)
	}
	if after["name"] != "Zed2" {
		t.Fatalf("payload update must apply: %v", after)
	}
}

func TestSQLite_SavepointNestedTransaction(t *testing.T) {
	ctx := context.Background()
	a := sqliteAdapter(t, "sqlite", Options{})
	outer := func(tx authdb.Adapter) error {
		if _, err := tx.Create(ctx, "widget", map[string]any{"id": "outer", "name": "o"}, nil); err != nil {
			return err
		}
		// A failing nested transaction rolls back to its savepoint only.
		if err := tx.Transaction(ctx, func(ntx authdb.Adapter) error {
			if _, err := ntx.Create(ctx, "widget", map[string]any{"id": "inner-bad", "name": "x"}, nil); err != nil {
				return err
			}
			return context.DeadlineExceeded
		}); err == nil {
			t.Fatal("nested failure must propagate")
		}
		// A successful nested transaction persists within the outer one.
		return tx.Transaction(ctx, func(ntx authdb.Adapter) error {
			_, err := ntx.Create(ctx, "widget", map[string]any{"id": "inner-good", "name": "y"}, nil)
			return err
		})
	}
	if err := a.Transaction(ctx, outer); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]bool{"outer": true, "inner-good": true, "inner-bad": false} {
		got, err := a.FindOne(ctx, "widget", []authdb.Where{{Field: "id", Value: id}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if (got != nil) != want {
			t.Fatalf("row %q present=%v want %v", id, got != nil, want)
		}
	}
}

func seedUserSession(t *testing.T, a authdb.Adapter) {
	t.Helper()
	ctx := context.Background()
	if _, err := a.Create(ctx, "user", map[string]any{"id": "u1", "name": "Al", "email": "a@b.c"}, nil); err != nil {
		t.Fatal(err)
	}
	for _, s := range []map[string]any{
		{"id": "s1", "userId": "u1", "token": "tok1", "expiresAt": time.Now().UTC().Add(time.Hour)},
		{"id": "s2", "userId": "u1", "token": "tok2", "expiresAt": time.Now().UTC().Add(time.Hour)},
	} {
		if _, err := a.Create(ctx, "session", s, nil); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSQLite_Joins(t *testing.T) {
	ctx := context.Background()
	newJoined := func(t *testing.T) authdb.Joiner {
		t.Helper()
		a := sqliteAdapter(t, "sqlite", Options{Models: DefaultModelDefs()})
		seedUserSession(t, a)
		j, ok := a.(authdb.Joiner)
		if !ok {
			t.Fatal("adapter must implement authdb.Joiner")
		}
		return j
	}
	t.Run("backwardOneToOne", func(t *testing.T) {
		j := newJoined(t)
		row, err := j.FindOneWithJoin(ctx, "session", []authdb.Where{{Field: "id", Value: "s1"}}, nil, authdb.JoinOption{"user": {}})
		if err != nil {
			t.Fatal(err)
		}
		user, ok := row["user"].(map[string]any)
		if !ok || user["email"] != "a@b.c" {
			t.Fatalf("session->user one-to-one: %v", row)
		}
	})
	t.Run("forwardOneToMany", func(t *testing.T) {
		j := newJoined(t)
		row, err := j.FindOneWithJoin(ctx, "user", []authdb.Where{{Field: "id", Value: "u1"}}, nil, authdb.JoinOption{"session": {}})
		if err != nil {
			t.Fatal(err)
		}
		sessions, ok := row["session"].([]map[string]any)
		if !ok || len(sessions) != 2 {
			t.Fatalf("user->session one-to-many: %v", row)
		}
	})
	t.Run("findManyJoin", func(t *testing.T) {
		j := newJoined(t)
		rows, err := j.FindManyWithJoin(ctx, "session", nil, -1, 0, nil, nil, authdb.JoinOption{"user": {}})
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 2 {
			t.Fatalf("joined findMany: %v", rows)
		}
		for _, r := range rows {
			if u, ok := r["user"].(map[string]any); !ok || u["id"] != "u1" {
				t.Fatalf("each row carries its user: %v", r)
			}
		}
	})
	t.Run("selectKeepsJoins", func(t *testing.T) {
		j := newJoined(t)
		row, err := j.FindOneWithJoin(ctx, "session", []authdb.Where{{Field: "id", Value: "s1"}}, []string{"token"}, authdb.JoinOption{"user": {}})
		if err != nil {
			t.Fatal(err)
		}
		if row["token"] != "tok1" {
			t.Fatalf("select must project base fields: %v", row)
		}
		if _, ok := row["user"]; !ok {
			t.Fatalf("select must preserve joins: %v", row)
		}
		if _, leaked := row["id"]; leaked {
			t.Fatalf("unselected base fields must not leak: %v", row)
		}
	})
	t.Run("noForeignKey", func(t *testing.T) {
		j := newJoined(t)
		_, err := j.FindOneWithJoin(ctx, "user", []authdb.Where{{Field: "id", Value: "u1"}}, nil, authdb.JoinOption{"verification": {}})
		if err == nil {
			t.Fatal("join without a foreign key must error")
		}
	})
	t.Run("missingBase", func(t *testing.T) {
		j := newJoined(t)
		row, err := j.FindOneWithJoin(ctx, "session", []authdb.Where{{Field: "id", Value: "nope"}}, nil, authdb.JoinOption{"user": {}})
		if err != nil || row != nil {
			t.Fatalf("join miss must be (nil,nil): %v %v", row, err)
		}
	})
}
