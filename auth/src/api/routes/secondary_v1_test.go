package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

// countSecondaryStorage wraps mapSecondaryStorage counting Set calls per
// key, mirroring the writeLog in update-user.test.ts "should not write to
// secondary storage multiple times for the same session token during
// updateUser".
type countSecondaryStorage struct {
	*mapSecondaryStorage
	mu   sync.Mutex
	sets map[string]int
}

func newCountSecondaryStorage(stringMode bool) *countSecondaryStorage {
	return &countSecondaryStorage{
		mapSecondaryStorage: newMapSecondaryStorage(stringMode),
		sets:                map[string]int{},
	}
}

func (c *countSecondaryStorage) Set(key, value string, ttl *int) error {
	c.mu.Lock()
	c.sets[key]++
	c.mu.Unlock()
	return c.mapSecondaryStorage.Set(key, value, ttl)
}

func (c *countSecondaryStorage) setCount(key string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sets[key]
}

func (c *countSecondaryStorage) totalSets() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	total := 0
	for _, n := range c.sets {
		total += n
	}
	return total
}

func (c *countSecondaryStorage) resetCounts() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sets = map[string]int{}
}

// appendSecondaryRef injects one active-sessions list entry (e.g. an expired
// or dangling reference) without a backing token value.
func appendSecondaryRef(t *testing.T, store *mapSecondaryStorage, userID, token string, expiresAt time.Time) {
	t.Helper()
	raw, err := store.Get(activeSessionsKey(userID))
	if err != nil {
		t.Fatalf("read refs: %v", err)
	}
	refs := parseSecondarySessionRefs(raw)
	refs = append(refs, secondarySessionRef{Token: token, ExpiresAt: expiresAt.UnixMilli()})
	sortSecondarySessionRefs(refs)
	encoded, err := json.Marshal(refs)
	if err != nil {
		t.Fatal(err)
	}
	ttl := secondarySessionTTL(time.UnixMilli(refs[len(refs)-1].ExpiresAt).UTC(), time.Now().UTC())
	if err := store.Set(activeSessionsKey(userID), string(encoded), &ttl); err != nil {
		t.Fatal(err)
	}
}

func secondaryV1UserID(t *testing.T, ctx context.Context, db *parityMemAdapter, email string) string {
	t.Helper()
	return stringField(mustFindUser(t, ctx, db, email), "id")
}

// TestSecondaryV1_RefreshPropagatesAcrossSessions ports update-user.test.ts
// "should propagate updates across sessions when secondaryStorage is
// enabled" at the secondary-runtime level: after refreshSecondaryUserSessions
// every live token of the user serves the updated user while the session
// halves stay untouched.
func TestSecondaryV1_RefreshPropagatesAcrossSessions(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	store := newMapSecondaryStorage(true)
	opts := secondarySessionTestOptions(db, store)
	now := time.Now().UTC()
	seedSecondarySession(t, ctx, opts, db, "prop@example.com", "tok-prop-1", now.Add(time.Hour))
	seedSecondarySession(t, ctx, opts, db, "prop@example.com", "tok-prop-2", now.Add(time.Hour))

	updated := rowToUser(mustFindUser(t, ctx, db, "prop@example.com"), opts)
	updated.Name = "updatedName"
	if err := refreshSecondaryUserSessions(opts, updated); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	for _, token := range []string{"tok-prop-1", "tok-prop-2"} {
		cached, err := findSecondarySession(opts, token)
		if err != nil || cached == nil {
			t.Fatalf("token %s lookup: %v %v", token, cached, err)
		}
		if cached.User.Name != "updatedName" {
			t.Fatalf("token %s user name %q, want updatedName", token, cached.User.Name)
		}
		if cached.Session.Token != token {
			t.Fatalf("token %s session half rewritten: %+v", token, cached.Session)
		}
	}
	res, err := resolveGetSession(ctx, opts, getSessionRequest{token: "tok-prop-2", headers: CookieRequestHeaders{}})
	if err != nil {
		t.Fatalf("get-session: %v", err)
	}
	if res.user.Name != "updatedName" {
		t.Fatalf("served user name %q, want updatedName", res.user.Name)
	}
}

// TestSecondaryV1_RefreshWritesOncePerToken ports update-user.test.ts
// "should not write to secondary storage multiple times for the same session
// token during updateUser": the refresh costs exactly one Set per live token
// and never rewrites the active-sessions list.
func TestSecondaryV1_RefreshWritesOncePerToken(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	store := newCountSecondaryStorage(true)
	opts := secondarySessionTestOptions(db, store.mapSecondaryStorage)
	opts.SecondaryStorage = store
	seedSecondarySession(t, ctx, opts, db, "once@example.com", "tok-once", time.Now().UTC().Add(time.Hour))
	userID := secondaryV1UserID(t, ctx, db, "once@example.com")
	store.resetCounts()

	updated := rowToUser(mustFindUser(t, ctx, db, "once@example.com"), opts)
	updated.Name = "updatedName"
	if err := refreshSecondaryUserSessions(opts, updated); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if got := store.setCount("tok-once"); got != 1 {
		t.Fatalf("token writes = %d, want exactly 1", got)
	}
	if got := store.setCount(activeSessionsKey(userID)); got != 0 {
		t.Fatalf("active-sessions list writes = %d, want 0", got)
	}
	if total := store.totalSets(); total != 1 {
		t.Fatalf("total writes = %d, want 1", total)
	}
}

// TestSecondaryV1_RefreshSkipsStaleRefs pins the filter semantics of
// upstream refreshUserSessions: expired references and dangling tokens are
// skipped without error and without creating entries.
func TestSecondaryV1_RefreshSkipsStaleRefs(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	store := newMapSecondaryStorage(true)
	opts := secondarySessionTestOptions(db, store)
	seedSecondarySession(t, ctx, opts, db, "stale-ref@example.com", "tok-live", time.Now().UTC().Add(time.Hour))
	userID := secondaryV1UserID(t, ctx, db, "stale-ref@example.com")
	appendSecondaryRef(t, store, userID, "tok-expired", time.Now().UTC().Add(-time.Hour))
	appendSecondaryRef(t, store, userID, "tok-ghost", time.Now().UTC().Add(time.Hour))

	updated := rowToUser(mustFindUser(t, ctx, db, "stale-ref@example.com"), opts)
	updated.Name = "updatedName"
	if err := refreshSecondaryUserSessions(opts, updated); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if cached, _ := findSecondarySession(opts, "tok-live"); cached == nil || cached.User.Name != "updatedName" {
		t.Fatalf("live session must be refreshed: %+v", cached)
	}
	if store.has("tok-expired") {
		t.Fatal("expired reference must not create a token entry")
	}
	if store.has("tok-ghost") {
		t.Fatal("dangling reference must not create a token entry")
	}
}

// TestSecondaryV1_DeleteAllThenRecreateKeepsOnlyReplacement ports
// update-user.test.ts "should preserve the replacement session in secondary
// storage" at the secondary-runtime level: clearing all of a user's sessions
// then mirroring one fresh session leaves exactly the replacement behind
// (old tokens gone, list holding only the new token).
func TestSecondaryV1_DeleteAllThenRecreateKeepsOnlyReplacement(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	store := newMapSecondaryStorage(true)
	opts := secondarySessionTestOptions(db, store)
	now := time.Now().UTC()
	seedSecondarySession(t, ctx, opts, db, "replace@example.com", "tok-old-1", now.Add(time.Hour))
	seedSecondarySession(t, ctx, opts, db, "replace@example.com", "tok-old-2", now.Add(time.Hour))
	userID := secondaryV1UserID(t, ctx, db, "replace@example.com")

	if err := deleteSecondaryAwareUserSessions(ctx, opts, userID); err != nil {
		t.Fatalf("delete all: %v", err)
	}
	for _, token := range []string{"tok-old-1", "tok-old-2"} {
		if store.has(token) {
			t.Fatalf("revoked token %s must leave secondary storage", token)
		}
		if _, err := resolveGetSession(ctx, opts, getSessionRequest{token: token, headers: CookieRequestHeaders{}}); err == nil {
			t.Fatalf("revoked token %s must not resolve", token)
		}
	}
	if store.has(activeSessionsKey(userID)) {
		t.Fatal("list key must be removed once no live session remains")
	}

	replacement := types.Session{
		ID:        "sess-tok-new",
		UserID:    userID,
		Token:     "tok-new",
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
		UpdatedAt: now,
	}
	user := rowToUser(mustFindUser(t, ctx, db, "replace@example.com"), opts)
	if err := writeSecondarySession(opts, replacement, user); err != nil {
		t.Fatalf("mirror replacement: %v", err)
	}
	cached, err := findSecondarySession(opts, "tok-new")
	if err != nil || cached == nil {
		t.Fatalf("replacement lookup: %v %v", cached, err)
	}
	if cached.Session.UserID != userID || cached.User.ID != userID {
		t.Fatalf("wrong owner: %+v %+v", cached.Session, cached.User)
	}
	refs := getSecondarySessionRefs(opts, userID)
	if len(refs) != 1 || refs[0].Token != "tok-new" {
		t.Fatalf("list must hold only the replacement, got %+v", refs)
	}
}

// TestSecondaryV1_RouteListRevokeSecondary ports the session-api.test.ts
// "session storage" revoke+list legs through the HTTP routes: list serves
// live sessions only, revoke answers status true, the revoked session then
// 401s and the list is empty with no store residue.
func TestSecondaryV1_RouteListRevokeSecondary(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	store := newMapSecondaryStorage(true)
	opts := secondarySessionTestOptions(db, store)
	seedSecondarySession(t, ctx, opts, db, "routelist@example.com", "tok-rl-1", time.Now().UTC().Add(time.Hour))
	seedSecondarySession(t, ctx, opts, db, "routelist@example.com", "tok-rl-2", time.Now().UTC().Add(time.Hour))
	userID := secondaryV1UserID(t, ctx, db, "routelist@example.com")
	appendSecondaryRef(t, store, userID, "tok-rl-expired", time.Now().UTC().Add(-time.Hour))

	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	ListSessions(api, "/api/auth", opts)
	RevokeSession(api, "/api/auth", opts)
	GetSession(api, "/api/auth", opts)

	listTokens := func(cookie string) []string {
		t.Helper()
		resp := api.Get("/api/auth/list-sessions", "Cookie: "+cookie)
		if resp.Code != http.StatusOK {
			t.Fatalf("list-sessions: %d %s", resp.Code, resp.Body.String())
		}
		var sessions []struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(resp.Body.Bytes(), &sessions); err != nil {
			t.Fatalf("decode list: %v (%s)", err, resp.Body.String())
		}
		tokens := make([]string, 0, len(sessions))
		for _, s := range sessions {
			tokens = append(tokens, s.Token)
		}
		return tokens
	}

	cookie := signedSessionHeader(t, opts, "tok-rl-1")
	cookie2 := signedSessionHeader(t, opts, "tok-rl-2")
	if tokens := listTokens(cookie); len(tokens) != 2 || tokens[0] == tokens[1] {
		t.Fatalf("expected both live sessions, got %v", tokens)
	}
	for _, token := range listTokens(cookie) {
		if token == "tok-rl-expired" {
			t.Fatal("expired reference must not be listed")
		}
	}

	revoke := api.Post("/api/auth/revoke-session", "Cookie: "+cookie, map[string]any{"token": "tok-rl-1"})
	if revoke.Code != http.StatusOK {
		t.Fatalf("revoke-session: %d %s", revoke.Code, revoke.Body.String())
	}
	var revokeBody struct {
		Status bool `json:"status"`
	}
	if err := json.Unmarshal(revoke.Body.Bytes(), &revokeBody); err != nil || !revokeBody.Status {
		t.Fatalf("revoke status: %v (%s)", err, revoke.Body.String())
	}

	// The survivor still lists exactly itself; the revoked token authenticates
	// nothing anymore, so listing with it 401s (upstream's client surfaces
	// this leg as null data).
	if tokens := listTokens(cookie2); len(tokens) != 1 || tokens[0] != "tok-rl-2" {
		t.Fatalf("expected only the surviving session, got %v", tokens)
	}
	if resp := api.Get("/api/auth/list-sessions", "Cookie: "+cookie); resp.Code != http.StatusUnauthorized {
		t.Fatalf("list with revoked cookie: got %d, want 401: %s", resp.Code, resp.Body.String())
	}
	if resp := api.Get("/api/auth/get-session", "Cookie: "+cookie); resp.Code != http.StatusOK || !strings.Contains(resp.Body.String(), `"session":null`) {
		t.Fatalf("revoked get-session: got %d, want 200 null: %s", resp.Code, resp.Body.String())
	}
	if store.has("tok-rl-1") {
		t.Fatal("revoked token must leave secondary storage")
	}
	if refs := getSecondarySessionRefs(opts, userID); len(refs) != 1 || refs[0].Token != "tok-rl-2" {
		t.Fatalf("list key must hold only the survivor, got %+v", refs)
	}
}
