package bunadapter

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	authdb "github.com/brick-org/brick/auth/src/db"
)

// AUTH-V10-03 live PostgreSQL matrix (adapters/bun half; skips without DATABASE_URL).

func pgLiveUniqueTable(prefix string) string {
	n := pgTableSeq.Add(1)
	name := fmt.Sprintf("%s_%d", prefix, n)
	if len(name) > 55 {
		name = name[:55]
	}
	return name
}

// TestPostgres_PluginTablesCreateDropCycles: plugin-shaped tables round-trip on live PG.
func TestPostgres_PluginTablesCreateDropCycles(t *testing.T) {
	db := requirePostgres(t)
	ctx := context.Background()

	users := pgLiveUniqueTable("v10m_users")
	sessions := pgLiveUniqueTable("v10m_sessions")
	orgs := pgLiveUniqueTable("v10m_orgs")
	members := pgLiveUniqueTable("v10m_members")
	oauthClients := pgLiveUniqueTable("v10m_oauthclients")
	oauthRefresh := pgLiveUniqueTable("v10m_oauthrefresh")
	jwks := pgLiveUniqueTable("v10m_jwks")

	stmts := []string{
		fmt.Sprintf(`CREATE TABLE %s ("id" TEXT PRIMARY KEY, "name" TEXT NOT NULL, "email" TEXT NOT NULL UNIQUE, "email_verified" BOOLEAN NOT NULL DEFAULT FALSE, "image" TEXT, "role" TEXT NOT NULL DEFAULT 'user', "banned" BOOLEAN NOT NULL DEFAULT FALSE, "ban_reason" TEXT, "ban_expires" TIMESTAMPTZ, "created_at" TIMESTAMPTZ NOT NULL, "updated_at" TIMESTAMPTZ NOT NULL)`, quoteIdent(users)),
		fmt.Sprintf(`CREATE TABLE %s ("id" TEXT PRIMARY KEY, "user_id" TEXT NOT NULL REFERENCES %s ("id") ON DELETE CASCADE, "token" TEXT NOT NULL UNIQUE, "expires_at" TIMESTAMPTZ NOT NULL, "impersonated_by" TEXT, "ip_address" TEXT, "user_agent" TEXT, "created_at" TIMESTAMPTZ NOT NULL, "updated_at" TIMESTAMPTZ NOT NULL)`, quoteIdent(sessions), quoteIdent(users)),
		fmt.Sprintf(`CREATE TABLE %s ("id" TEXT PRIMARY KEY, "name" TEXT NOT NULL, "slug" TEXT NOT NULL UNIQUE, "created_at" TIMESTAMPTZ NOT NULL)`, quoteIdent(orgs)),
		fmt.Sprintf(`CREATE TABLE %s ("id" TEXT PRIMARY KEY, "organization_id" TEXT NOT NULL REFERENCES %s ("id") ON DELETE CASCADE, "user_id" TEXT NOT NULL REFERENCES %s ("id") ON DELETE CASCADE, "role" TEXT NOT NULL DEFAULT 'member', "created_at" TIMESTAMPTZ NOT NULL)`, quoteIdent(members), quoteIdent(orgs), quoteIdent(users)),
		fmt.Sprintf(`CREATE TABLE %s ("id" TEXT PRIMARY KEY, "client_id" TEXT NOT NULL UNIQUE, "user_id" TEXT REFERENCES %s ("id") ON DELETE CASCADE, "created_at" TIMESTAMPTZ NOT NULL)`, quoteIdent(oauthClients), quoteIdent(users)),
		fmt.Sprintf(`CREATE TABLE %s ("id" TEXT PRIMARY KEY, "token" TEXT NOT NULL UNIQUE, "client_id" TEXT NOT NULL REFERENCES %s ("client_id"), "user_id" TEXT NOT NULL REFERENCES %s ("id") ON DELETE CASCADE, "expires_at" TIMESTAMPTZ NOT NULL)`, quoteIdent(oauthRefresh), quoteIdent(oauthClients), quoteIdent(users)),
		fmt.Sprintf(`CREATE TABLE %s ("id" TEXT PRIMARY KEY, "public_key" TEXT NOT NULL, "private_key" TEXT NOT NULL, "alg" TEXT, "crv" TEXT, "created_at" TIMESTAMPTZ NOT NULL, "expires_at" TIMESTAMPTZ)`, quoteIdent(jwks)),
	}
	for _, s := range stmts {
		if _, err := db.NewRaw(s).Exec(ctx); err != nil {
			t.Fatalf("create plugin table: %v", err)
		}
	}
	t.Cleanup(func() {
		for _, tbl := range []string{oauthRefresh, oauthClients, members, orgs, sessions, jwks, users} {
			_, _ = db.NewRaw(fmt.Sprintf(`DROP TABLE IF EXISTS %s`, quoteIdent(tbl))).Exec(context.Background())
		}
	})

	adapter := NewWithOptions(db, authdb.Config{ModelNames: map[string]string{
		"adminUser": users, "adminSession": sessions,
		"org": orgs, "orgMember": members,
		"oauthClient": oauthClients, "oauthRefresh": oauthRefresh,
		"jwks": jwks,
	}}, Options{})

	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	future := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	adminRow, err := adapter.Create(ctx, "adminUser", map[string]any{
		"id": "au1", "name": "Admin", "email": "admin-live@example.com",
		"role": "admin", "banned": false,
		"createdAt": now, "updatedAt": now,
	}, nil)
	if err != nil {
		t.Fatalf("admin user create: %v", err)
	}
	if adminRow["role"] != "admin" {
		t.Fatalf("admin role must round-trip: %v", adminRow)
	}
	if _, err := adapter.Create(ctx, "adminSession", map[string]any{
		"id": "as1", "userId": "au1", "token": "tok-live-1",
		"expiresAt": future, "impersonatedBy": "root",
		"createdAt": now, "updatedAt": now,
	}, nil); err != nil {
		t.Fatalf("admin session create: %v", err)
	}

	if _, err := adapter.Create(ctx, "orgMember", map[string]any{
		"id": "m-bad", "organizationId": "nope", "userId": "au1", "role": "member",
		"createdAt": now,
	}, nil); err == nil {
		t.Fatal("dangling organization FK must be rejected by live PG")
	}
	if _, err := adapter.Create(ctx, "org", map[string]any{
		"id": "o1", "name": "Acme", "slug": "acme-live", "createdAt": now,
	}, nil); err != nil {
		t.Fatalf("org create: %v", err)
	}
	if _, err := adapter.Create(ctx, "orgMember", map[string]any{
		"id": "m1", "organizationId": "o1", "userId": "au1", "role": "owner",
		"createdAt": now,
	}, nil); err != nil {
		t.Fatalf("member create: %v", err)
	}
	got, err := adapter.FindOne(ctx, "orgMember", []authdb.Where{{Field: "id", Value: "m1"}}, nil)
	if err != nil || got == nil || got["role"] != "owner" {
		t.Fatalf("member round-trip: %v %v", got, err)
	}

	if _, err := adapter.Create(ctx, "oauthClient", map[string]any{
		"id": "c1", "clientId": "live-client-1", "userId": "au1", "createdAt": now,
	}, nil); err != nil {
		t.Fatalf("oauth client create: %v", err)
	}
	if _, err := adapter.Create(ctx, "oauthRefresh", map[string]any{
		"id": "r1", "token": "live-refresh-1", "clientId": "live-client-1",
		"userId": "au1", "expiresAt": future,
	}, nil); err != nil {
		t.Fatalf("oauth refresh create: %v", err)
	}
	n, err := adapter.Count(ctx, "oauthRefresh", []authdb.Where{{Field: "clientId", Value: "live-client-1"}})
	if err != nil || n != 1 {
		t.Fatalf("oauth refresh count = %d, %v; want 1", n, err)
	}

	jwksRow, err := adapter.Create(ctx, "jwks", map[string]any{
		"id": "k1", "publicKey": "pub", "privateKey": "priv", "createdAt": now,
	}, nil)
	if err != nil {
		t.Fatalf("jwks create: %v", err)
	}
	if jwksRow["publicKey"] != "pub" {
		t.Fatalf("jwks round-trip: %v", jwksRow)
	}

	if _, err := db.NewRaw(fmt.Sprintf(`DROP TABLE %s CASCADE`, quoteIdent(orgs))).Exec(ctx); err != nil {
		t.Fatalf("drop orgs cascade: %v", err)
	}
	if _, err := adapter.Create(ctx, "orgMember", map[string]any{
		"id": "m2", "organizationId": "gone", "userId": "au1", "role": "member",
		"createdAt": now,
	}, nil); err != nil {
		t.Fatalf("post-cascade member insert must succeed without the FK: %v", err)
	}
	if _, err := db.NewRaw(fmt.Sprintf(`DROP TABLE %s`, quoteIdent(members))).Exec(ctx); err != nil {
		t.Fatalf("drop members: %v", err)
	}
	if _, err := adapter.Count(ctx, "orgMember", nil); err == nil {
		t.Fatal("dropped members table must stop serving queries (expected error)")
	}
	still, err := adapter.FindOne(ctx, "adminUser", []authdb.Where{{Field: "id", Value: "au1"}}, []string{"role"})
	if err != nil || still == nil || still["role"] != "admin" {
		t.Fatalf("unrelated tables must keep serving after cascade drop: %v %v", still, err)
	}
}

// TestPostgres_RateLimitTableBehavior exercises the rate-limit storage shape against live PG.
func TestPostgres_RateLimitTableBehavior(t *testing.T) {
	db := requirePostgres(t)
	ctx := context.Background()
	table := pgLiveUniqueTable("v10m_ratelimit")
	create := fmt.Sprintf(`CREATE TABLE %s ("id" TEXT PRIMARY KEY, "key" TEXT NOT NULL UNIQUE, "count" INTEGER NOT NULL DEFAULT 0, "last_request" BIGINT NOT NULL)`, quoteIdent(table))
	if _, err := db.NewRaw(create).Exec(ctx); err != nil {
		t.Fatalf("create rate-limit table: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.NewRaw(fmt.Sprintf(`DROP TABLE IF EXISTS %s`, quoteIdent(table))).Exec(context.Background())
	})
	adapter := NewWithOptions(db, authdb.Config{ModelNames: map[string]string{"rateLimit": table}}, Options{})
	consume := func(key string, nowMillis int64, windowMillis int64, max int64) (allowed bool, count float64) {
		t.Helper()
		row, err := adapter.FindOne(ctx, "rateLimit", []authdb.Where{{Field: "key", Value: key}}, nil)
		if err != nil {
			t.Fatalf("find rate-limit row: %v", err)
		}
		if row == nil {
			created, err := adapter.Create(ctx, "rateLimit", map[string]any{
				"id": "rl-" + key, "key": key, "count": 1, "lastRequest": nowMillis,
			}, nil)
			if err != nil {
				t.Fatalf("create rate-limit row: %v", err)
			}
			return true, asFloat(created["count"])
		}
		last := int64(asFloat(row["lastRequest"]))
		if nowMillis-last > windowMillis {
			updated, err := adapter.Update(ctx, "rateLimit",
				[]authdb.Where{{Field: "key", Value: key}},
				map[string]any{"count": 1, "lastRequest": nowMillis})
			if err != nil || updated == nil {
				t.Fatalf("reset rate-limit row: %v %v", updated, err)
			}
			return true, 1
		}
		updated, err := adapter.IncrementOne(ctx, "rateLimit",
			[]authdb.Where{{Field: "key", Value: key}}, map[string]int{"count": 1}, nil)
		if err != nil || updated == nil {
			t.Fatalf("increment rate-limit row: %v %v", updated, err)
		}
		c := asFloat(updated["count"])
		return c <= float64(max), c
	}

	if ok, c := consume("k1", 1_000, 60_000, 3); !ok || c != 1 {
		t.Fatalf("first consume must create count=1, ok=%v c=%v", ok, c)
	}
	if ok, c := consume("k1", 2_000, 60_000, 3); !ok || c != 2 {
		t.Fatalf("second consume must increment to 2, ok=%v c=%v", ok, c)
	}
	if ok, c := consume("k1", 3_000, 60_000, 3); !ok || c != 3 {
		t.Fatalf("third consume must increment to 3, ok=%v c=%v", ok, c)
	}
	if ok, c := consume("k1", 4_000, 60_000, 3); ok || c != 4 {
		t.Fatalf("over-max consume must be denied at 4, ok=%v c=%v", ok, c)
	}
	if ok, c := consume("k1", 200_000, 60_000, 3); !ok || c != 1 {
		t.Fatalf("expired window must reset to 1, ok=%v c=%v", ok, c)
	}

	if _, err := adapter.Create(ctx, "rateLimit", map[string]any{
		"id": "rl-conc", "key": "conc", "count": 0, "lastRequest": 300_000,
	}, nil); err != nil {
		t.Fatalf("create concurrent row: %v", err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 160)
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				_, err := adapter.IncrementOne(ctx, "rateLimit",
					[]authdb.Where{{Field: "key", Value: "conc"}}, map[string]int{"count": 1}, nil)
				if err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent increment: %v", err)
	}
	final, err := adapter.FindOne(ctx, "rateLimit", []authdb.Where{{Field: "key", Value: "conc"}}, []string{"count"})
	if err != nil || final == nil || asFloat(final["count"]) != 160 {
		t.Fatalf("concurrent increments must converge to 160: %v %v", final, err)
	}
}

// TestPostgres_ConsumeOneConcurrentSingleWinner proves exactly one concurrent consumer wins a row on live PG.
func TestPostgres_ConsumeOneConcurrentSingleWinner(t *testing.T) {
	db := requirePostgres(t)
	ctx := context.Background()
	table := pgLiveUniqueTable("v10m_consume")
	if _, err := db.NewRaw(fmt.Sprintf(`CREATE TABLE %s ("id" TEXT PRIMARY KEY, "name" TEXT)`, quoteIdent(table))).Exec(ctx); err != nil {
		t.Fatalf("create consume table: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.NewRaw(fmt.Sprintf(`DROP TABLE IF EXISTS %s`, quoteIdent(table))).Exec(context.Background())
	})
	adapter := NewWithOptions(db, authdb.Config{ModelNames: map[string]string{"widget": table}}, Options{})
	if _, err := adapter.Create(ctx, "widget", map[string]any{"id": "once", "name": "single"}, nil); err != nil {
		t.Fatalf("seed consume row: %v", err)
	}
	const racers = 8
	var wg sync.WaitGroup
	wins := make(chan map[string]any, racers)
	errs := make(chan error, racers)
	for g := 0; g < racers; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			row, err := adapter.ConsumeOne(ctx, "widget", []authdb.Where{{Field: "id", Value: "once"}})
			if err != nil {
				errs <- err
				return
			}
			if row != nil {
				wins <- row
			}
		}()
	}
	wg.Wait()
	close(wins)
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent consume: %v", err)
	}
	got := 0
	for row := range wins {
		got++
		if row["name"] != "single" {
			t.Fatalf("winner must carry the row: %v", row)
		}
	}
	if got != 1 {
		t.Fatalf("exactly one consumer must win, got %d", got)
	}
	left, err := adapter.Count(ctx, "widget", nil)
	if err != nil || left != 0 {
		t.Fatalf("consumed table must be empty: %d %v", left, err)
	}
}

// TestPostgres_CoreMigrationApplyAndIntrospect applies core-table DDL to isolated tables on live PG.
func TestPostgres_CoreMigrationApplyAndIntrospect(t *testing.T) {
	db := requirePostgres(t)
	ctx := context.Background()
	users := pgLiveUniqueTable("v10m_cusers")
	sessions := pgLiveUniqueTable("v10m_csessions")
	accounts := pgLiveUniqueTable("v10m_caccounts")
	verifications := pgLiveUniqueTable("v10m_cverifs")

	for _, s := range []string{
		fmt.Sprintf(`CREATE TABLE %s ("id" TEXT PRIMARY KEY, "email" TEXT NOT NULL UNIQUE, "email_verified" BOOLEAN NOT NULL DEFAULT FALSE, "name" TEXT NOT NULL, "image" TEXT, "created_at" TIMESTAMPTZ NOT NULL, "updated_at" TIMESTAMPTZ NOT NULL)`, quoteIdent(users)),
		fmt.Sprintf(`CREATE TABLE %s ("id" TEXT PRIMARY KEY, "user_id" TEXT NOT NULL, "token" TEXT NOT NULL UNIQUE, "expires_at" TIMESTAMPTZ NOT NULL, "ip_address" TEXT, "user_agent" TEXT, "created_at" TIMESTAMPTZ NOT NULL, "updated_at" TIMESTAMPTZ NOT NULL)`, quoteIdent(sessions)),
		fmt.Sprintf(`CREATE TABLE %s ("id" TEXT PRIMARY KEY, "user_id" TEXT NOT NULL, "provider_id" TEXT NOT NULL, "account_id" TEXT NOT NULL, "access_token" TEXT, "refresh_token" TEXT, "id_token" TEXT, "access_token_expires_at" TIMESTAMPTZ, "refresh_token_expires_at" TIMESTAMPTZ, "scope" TEXT, "password" TEXT, "created_at" TIMESTAMPTZ NOT NULL, "updated_at" TIMESTAMPTZ NOT NULL)`, quoteIdent(accounts)),
		fmt.Sprintf(`CREATE TABLE %s ("id" TEXT PRIMARY KEY, "identifier" TEXT NOT NULL, "value" TEXT NOT NULL, "expires_at" TIMESTAMPTZ NOT NULL, "created_at" TIMESTAMPTZ NOT NULL, "updated_at" TIMESTAMPTZ NOT NULL)`, quoteIdent(verifications)),
	} {
		if _, err := db.NewRaw(s).Exec(ctx); err != nil {
			t.Fatalf("create core table: %v", err)
		}
	}
	t.Cleanup(func() {
		for _, tbl := range []string{verifications, accounts, sessions, users} {
			_, _ = db.NewRaw(fmt.Sprintf(`DROP TABLE IF EXISTS %s`, quoteIdent(tbl))).Exec(context.Background())
		}
	})

	for tbl, wantCols := range map[string][]string{
		users:         {"id", "email", "email_verified", "name", "created_at", "updated_at"},
		sessions:      {"id", "user_id", "token", "expires_at", "created_at", "updated_at"},
		accounts:      {"id", "user_id", "provider_id", "account_id", "created_at", "updated_at"},
		verifications: {"id", "identifier", "value", "expires_at", "created_at", "updated_at"},
	} {
		var cols []string
		if err := db.NewRaw(`SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name=? ORDER BY ordinal_position`, tbl).Scan(ctx, &cols); err != nil {
			t.Fatalf("introspect %s: %v", tbl, err)
		}
		have := map[string]bool{}
		for _, c := range cols {
			have[c] = true
		}
		for _, w := range wantCols {
			if !have[w] {
				t.Fatalf("table %s missing column %s (have %v)", tbl, w, cols)
			}
		}
		var pk string
		if err := db.NewRaw(`SELECT c.column_name FROM information_schema.table_constraints tc JOIN information_schema.key_column_usage c ON tc.constraint_name=c.constraint_name WHERE tc.table_name=? AND tc.constraint_type='PRIMARY KEY'`, tbl).Scan(ctx, &pk); err != nil {
			t.Fatalf("introspect pk %s: %v", tbl, err)
		}
		if pk != "id" {
			t.Fatalf("table %s pk = %q, want id", tbl, pk)
		}
	}
	for tbl, col := range map[string]string{users: "email", sessions: "token"} {
		var n int
		if err := db.NewRaw(`SELECT COUNT(*) FROM information_schema.table_constraints WHERE table_name=? AND constraint_type='UNIQUE'`, tbl).Scan(ctx, &n); err != nil {
			t.Fatalf("introspect unique %s: %v", tbl, err)
		}
		if n < 1 {
			t.Fatalf("table %s must carry a UNIQUE constraint (col %s)", tbl, col)
		}
	}

	adapter := NewWithOptions(db, authdb.Config{ModelNames: map[string]string{
		"user": users, "session": sessions, "account": accounts, "verification": verifications,
	}}, Options{})
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := adapter.Create(ctx, "user", map[string]any{
		"id": "cu1", "name": "Mig", "email": "mig-live@example.com",
		"emailVerified": false, "createdAt": now, "updatedAt": now,
	}, nil); err != nil {
		t.Fatalf("post-migration user create: %v", err)
	}
	got, err := adapter.FindOne(ctx, "user", []authdb.Where{{Field: "email", Value: "mig-live@example.com"}}, []string{"name"})
	if err != nil || got == nil || got["name"] != "Mig" {
		t.Fatalf("post-migration user read: %v %v", got, err)
	}
	if !strings.Contains(users, "v10m_") {
		t.Fatalf("isolation prefix lost: %s", users)
	}
}
