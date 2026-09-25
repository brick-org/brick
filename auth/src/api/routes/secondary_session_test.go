package routes

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/types"
)

// mapSecondaryStorage is a fake types.SecondaryStorage. stringMode mirrors a
// Redis-style backend returning JSON strings; object mode mirrors backends
// that return already-parsed values (upstream secondary-storage.test.ts
// covers both shapes).
type mapSecondaryStorage struct {
	mu         sync.Mutex
	values     map[string]any
	stringMode bool
	sets       int
}

func newMapSecondaryStorage(stringMode bool) *mapSecondaryStorage {
	return &mapSecondaryStorage{values: map[string]any{}, stringMode: stringMode}
}

func (m *mapSecondaryStorage) Get(key string) (any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.values[key]
	if !ok {
		return nil, nil
	}
	if m.stringMode {
		if s, ok := v.(string); ok {
			return s, nil
		}
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		return string(raw), nil
	}
	return v, nil
}

func (m *mapSecondaryStorage) GetAndDelete(key string) (any, error) {
	v, err := m.Get(key)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	delete(m.values, key)
	m.mu.Unlock()
	return v, nil
}

func (m *mapSecondaryStorage) Increment(key string, _ int) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var cur int64
	if raw, ok := m.values[key]; ok {
		switch n := raw.(type) {
		case int64:
			cur = n
		case int:
			cur = int64(n)
		case float64:
			cur = int64(n)
		}
	}
	cur++
	m.values[key] = cur
	return cur, nil
}

func (m *mapSecondaryStorage) Set(key, value string, _ *int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stringMode {
		m.values[key] = value
	} else {
		var parsed any
		if err := json.Unmarshal([]byte(value), &parsed); err != nil {
			return err
		}
		m.values[key] = parsed
	}
	m.sets++
	return nil
}

func (m *mapSecondaryStorage) Delete(key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.values, key)
	return nil
}

func (m *mapSecondaryStorage) has(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.values[key]
	return ok
}

func secondarySessionTestOptions(db *parityMemAdapter, store types.SecondaryStorage) types.Options {
	opts := sessionTestOptions(db)
	opts.SecondaryStorage = store
	return opts
}

// seedSecondarySession mirrors upstream createSession with secondary storage:
func seedSecondarySession(t *testing.T, ctx context.Context, opts types.Options, db *parityMemAdapter, email, token string, expiresAt time.Time) {
	t.Helper()
	parityCreateUser(t, db, email, true)
	userRow, err := db.FindOne(ctx, "user", []types.Where{{Field: "email", Value: email}}, nil)
	if err != nil || userRow == nil {
		t.Fatalf("seed user lookup: %v", err)
	}
	now := time.Now().UTC()
	session := types.Session{
		ID:        "sess-" + token,
		UserID:    stringField(userRow, "id"),
		Token:     token,
		ExpiresAt: expiresAt,
		CreatedAt: now,
		UpdatedAt: now,
	}
	user := rowToUser(userRow, opts)
	if opts.Session.StoreSessionInDatabase {
		if _, err := db.Create(ctx, "session", sessionToRow(session), nil); err != nil {
			t.Fatalf("seed db session: %v", err)
		}
	}
	if err := writeSecondarySession(opts, session, user); err != nil {
		t.Fatalf("seed secondary session: %v", err)
	}
}

func TestSecondarySession_GetServesFromCache(t *testing.T) {
	ctx := context.Background()
	for _, stringMode := range []bool{true, false} {
		db := newParityMemAdapter()
		store := newMapSecondaryStorage(stringMode)
		opts := secondarySessionTestOptions(db, store)
		seedSecondarySession(t, ctx, opts, db, "cache@example.com", "tok-cache", time.Now().UTC().Add(time.Hour))

		if row, _ := db.FindOne(ctx, "session", []types.Where{{Field: "token", Value: "tok-cache"}}, nil); row != nil {
			t.Fatal("secondary-only mode must not write a database row")
		}
		res, err := resolveGetSession(ctx, opts, getSessionRequest{token: "tok-cache", headers: CookieRequestHeaders{}})
		if err != nil {
			t.Fatalf("stringMode=%v: get-session: %v", stringMode, err)
		}
		if res.session.Token != "tok-cache" || res.user.Email != "cache@example.com" {
			t.Fatalf("stringMode=%v: wrong session %+v %+v", stringMode, res.session, res.user)
		}
	}
}

func TestSecondarySession_MissFallsBackToDatabase(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	store := newMapSecondaryStorage(true)
	opts := secondarySessionTestOptions(db, store)
	opts.Session.StoreSessionInDatabase = true
	seedSessionUser(t, db, "fallback@example.com", "tok-fallback", time.Now().UTC().Add(time.Hour))
	res, err := resolveGetSession(ctx, opts, getSessionRequest{token: "tok-fallback", headers: CookieRequestHeaders{}})
	if err != nil {
		t.Fatalf("database fallback: %v", err)
	}
	if res.session.Token != "tok-fallback" {
		t.Fatalf("wrong session: %+v", res.session)
	}
	if !store.has("tok-fallback") {
		t.Fatal("database fallback must backfill the secondary entry")
	}
}

func TestSecondarySession_MissWithoutPersistenceIsUnauthorized(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	store := newMapSecondaryStorage(true)
	opts := secondarySessionTestOptions(db, store)
	seedSessionUser(t, db, "revoked@example.com", "tok-revoked", time.Now().UTC().Add(time.Hour))
	if _, err := resolveGetSession(ctx, opts, getSessionRequest{token: "tok-revoked", headers: CookieRequestHeaders{}}); err == nil {
		t.Fatal("expected unauthorized for a session missing from secondary storage")
	} else if status, _ := statusOf(t, err); status != 401 {
		t.Fatalf("expected 401, got %d", status)
	}
}

func TestSecondarySession_ListAndRevoke(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	store := newMapSecondaryStorage(true)
	opts := secondarySessionTestOptions(db, store)
	seedSecondarySession(t, ctx, opts, db, "list@example.com", "tok-list-1", time.Now().UTC().Add(time.Hour))
	seedSecondarySession(t, ctx, opts, db, "list@example.com", "tok-list-2", time.Now().UTC().Add(-time.Hour))

	sessions, err := listSecondarySessions(opts, stringField(mustFindUser(t, ctx, db, "list@example.com"), "id"))
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].Token != "tok-list-1" {
		t.Fatalf("expected only the live session, got %+v", sessions)
	}

	if err := deleteSecondarySession(opts, "tok-list-1"); err != nil {
		t.Fatal(err)
	}
	if store.has("tok-list-1") {
		t.Fatal("revoked token must be removed from secondary storage")
	}
	if _, err := resolveGetSession(ctx, opts, getSessionRequest{token: "tok-list-1", headers: CookieRequestHeaders{}}); err == nil {
		t.Fatal("revoked session must not resolve")
	}
}

func TestSecondarySession_PreserveKeepsEndedRow(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	store := newMapSecondaryStorage(true)
	opts := secondarySessionTestOptions(db, store)
	opts.Session.StoreSessionInDatabase = true
	opts.Session.PreserveSessionInDatabase = true
	seedSecondarySession(t, ctx, opts, db, "preserve@example.com", "tok-preserve", time.Now().UTC().Add(time.Hour))

	if err := deleteSecondaryAwareSession(ctx, opts, "tok-preserve"); err != nil {
		t.Fatal(err)
	}
	if store.has("tok-preserve") {
		t.Fatal("revoked token must leave secondary storage")
	}
	row, err := db.FindOne(ctx, "session", []types.Where{{Field: "token", Value: "tok-preserve"}}, nil)
	if err != nil || row == nil {
		t.Fatalf("preserved row must remain in the database: %v", err)
	}
	if exp, ok := timeField(row, "expires_at", "expiresAt"); !ok || exp.After(time.Now().UTC()) {
		t.Fatalf("preserved row must be marked ended, got %v", exp)
	}
	if _, err := resolveGetSession(ctx, opts, getSessionRequest{token: "tok-preserve", headers: CookieRequestHeaders{}}); err == nil {
		t.Fatal("preserved (ended) session must not resolve")
	}
}

func TestSecondarySession_RefreshExtendsCache(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	store := newMapSecondaryStorage(true)
	opts := secondarySessionTestOptions(db, store)
	seedSecondarySession(t, ctx, opts, db, "refresh2@example.com", "tok-refresh2", time.Now().UTC().Add(30*time.Second))

	before, err := findSecondarySession(opts, "tok-refresh2")
	if err != nil || before == nil {
		t.Fatalf("seed lookup: %v %v", before, err)
	}
	_, _, refreshed, _, err := loadSessionWithRefresh(ctx, opts, "tok-refresh2", sessionRefreshConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !refreshed {
		t.Fatal("due secondary session must refresh")
	}
	after, err := findSecondarySession(opts, "tok-refresh2")
	if err != nil || after == nil {
		t.Fatalf("post-refresh lookup: %v %v", after, err)
	}
	if !after.Session.ExpiresAt.After(before.Session.ExpiresAt) {
		t.Fatalf("expiry not extended: %v -> %v", before.Session.ExpiresAt, after.Session.ExpiresAt)
	}
}

func TestSecondaryVerification_HashedIdentifier(t *testing.T) {
	store := newMapSecondaryStorage(true)
	opts := parityTestOptions(newParityMemAdapter())
	opts.SecondaryStorage = store
	opts.Verification.StoreIdentifier.Mode = types.StoreIdentifierHashed

	identifier := "change-email:tok-abc"
	stored, err := processVerificationIdentifier(identifier, resolveVerificationStoreOption(identifier, opts.Verification.StoreIdentifier))
	if err != nil {
		t.Fatal(err)
	}
	if stored == identifier {
		t.Fatal("hashed mode must not store the plain identifier")
	}
	row := map[string]any{
		"id": "v1", "identifier": stored, "value": "{}",
		"expiresAt": time.Now().UTC().Add(time.Hour),
		"createdAt": time.Now().UTC(), "updatedAt": time.Now().UTC(),
	}
	if err := writeSecondaryVerification(opts, identifier, row); err != nil {
		t.Fatal(err)
	}
	if store.has("verification:" + identifier) {
		t.Fatal("hashed mode must key secondary storage by the hash")
	}
	found, err := findSecondaryVerification(opts, identifier)
	if err != nil || found == nil {
		t.Fatalf("hashed lookup: %v %v", found, err)
	}
	if stringField(found, "id") != "v1" {
		t.Fatalf("wrong row: %+v", found)
	}
}

func TestSecondaryVerification_PlainIdentifier(t *testing.T) {
	store := newMapSecondaryStorage(false)
	opts := parityTestOptions(newParityMemAdapter())
	opts.SecondaryStorage = store

	identifier := "change-email:tok-plain"
	row := map[string]any{
		"id": "v2", "identifier": identifier, "value": "{}",
		"expiresAt": time.Now().UTC().Add(time.Hour),
		"createdAt": time.Now().UTC(), "updatedAt": time.Now().UTC(),
	}
	if err := writeSecondaryVerification(opts, identifier, row); err != nil {
		t.Fatal(err)
	}
	found, err := findSecondaryVerification(opts, identifier)
	if err != nil || found == nil {
		t.Fatalf("plain lookup: %v %v", found, err)
	}
	if err := deleteSecondaryVerification(opts, identifier); err != nil {
		t.Fatal(err)
	}
	if found, _ := findSecondaryVerification(opts, identifier); found != nil {
		t.Fatal("deleted verification must not resolve")
	}
}

func TestSecondaryVerification_ExpiredRowInvalid(t *testing.T) {
	store := newMapSecondaryStorage(true)
	opts := parityTestOptions(newParityMemAdapter())
	opts.SecondaryStorage = store

	identifier := "change-email:tok-old"
	row := map[string]any{
		"id": "v3", "identifier": identifier, "value": "{}",
		"expiresAt": time.Now().UTC().Add(-time.Hour),
		"createdAt": time.Now().UTC(), "updatedAt": time.Now().UTC(),
	}
	if err := writeSecondaryVerification(opts, identifier, row); err != nil {
		t.Fatal(err)
	}
	if found, err := findSecondaryVerification(opts, identifier); err != nil || found != nil {
		t.Fatalf("expired row must not resolve: %v %+v", err, found)
	}
}

func mustFindUser(t *testing.T, ctx context.Context, db *parityMemAdapter, email string) map[string]any {
	t.Helper()
	row, err := db.FindOne(ctx, "user", []types.Where{{Field: "email", Value: email}}, nil)
	if err != nil || row == nil {
		t.Fatalf("user lookup: %v", err)
	}
	return row
}
