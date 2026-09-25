package routes

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/cookies"
	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

func wave2BoolPtr(v bool) *bool { return &v }

// emailAuthTestOptions enables the credential flows for sign-up/sign-in tests.
func emailAuthTestOptions(db *parityMemAdapter) types.Options {
	opts := sessionTestOptions(db)
	opts.EmailAndPassword.Enabled = true
	return opts
}

func registerEmailAuth(api humatest.TestAPI, base string, opts types.Options) {
	SignUpEmail(api, base, opts)
	SignInEmail(api, base, opts)
	SignOut(api, base, opts)
	GetSession(api, base, opts)
	UpdateSession(api, base, opts)
	ListSessions(api, base, opts)
}

// sessionExpiryOf reads the stored expiry of a session token from the fake DB.
func sessionExpiryOf(t *testing.T, ctx context.Context, db *parityMemAdapter, token string) time.Time {
	t.Helper()
	row, err := db.FindOne(ctx, "session", []types.Where{{Field: "token", Value: token}}, nil)
	if err != nil || row == nil {
		t.Fatalf("session lookup: %v", err)
	}
	exp, ok := timeField(row, "expires_at", "expiresAt")
	if !ok {
		t.Fatal("session row missing expiry")
	}
	return exp
}

// setCookiesOf collects Set-Cookie headers from a humatest response by name.
func setCookiesOf(t *testing.T, resp *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, raw := range resp.Header().Values("Set-Cookie") {
		name := strings.TrimSpace(strings.SplitN(raw, "=", 2)[0])
		out[name] = raw
	}
	return out
}

// TestSignUpRememberMe pins upstream createSession/session-cookie parity
func TestSignUpRememberMe(t *testing.T) {
	boot := func(t *testing.T) (humatest.TestAPI, *parityMemAdapter, types.Options) {
		db := newParityMemAdapter()
		opts := emailAuthTestOptions(db)
		_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
		registerEmailAuth(api, "/api/auth", opts)
		return api, db, opts
	}

	t.Run("false shortens expiry and mints the marker", func(t *testing.T) {
		api, db, opts := boot(t)
		before := time.Now().UTC()
		resp := api.Post("/api/auth/sign-up/email", map[string]any{
			"name": "Rem", "email": "rem@example.com", "password": "password123",
			"rememberMe": false,
		})
		if resp.Code != http.StatusOK {
			t.Fatalf("sign-up: %d %s", resp.Code, resp.Body.String())
		}
		var body struct {
			Token *string `json:"token"`
		}
		if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil || body.Token == nil {
			t.Fatalf("sign-up must return a session token: %s (%v)", resp.Body.String(), err)
		}
		if got := sessionExpiryOf(t, context.Background(), db, *body.Token); got.After(before.Add(25 * time.Hour)) {
			t.Fatalf("dontRememberMe session must expire in ~1 day, got %v", got)
		}
		jar := setCookiesOf(t, resp)
		if _, ok := jar[resolveDontRememberCookieName(opts, false)]; !ok {
			t.Fatalf("missing dont_remember marker in %v", jar)
		}
	})

	t.Run("default keeps the full lifetime without a marker", func(t *testing.T) {
		api, db, opts := boot(t)
		before := time.Now().UTC()
		resp := api.Post("/api/auth/sign-up/email", map[string]any{
			"name": "Rem", "email": "rem2@example.com", "password": "password123",
		})
		if resp.Code != http.StatusOK {
			t.Fatalf("sign-up: %d %s", resp.Code, resp.Body.String())
		}
		var body struct {
			Token *string `json:"token"`
		}
		if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil || body.Token == nil {
			t.Fatalf("sign-up must return a session token: %s (%v)", resp.Body.String(), err)
		}
		if got := sessionExpiryOf(t, context.Background(), db, *body.Token); got.Before(before.Add(30*time.Minute)) || got.After(before.Add(2*time.Hour)) {
			t.Fatalf("persistent session must keep the configured lifetime, got %v", got)
		}
		if _, ok := setCookiesOf(t, resp)[resolveDontRememberCookieName(opts, false)]; ok {
			t.Fatal("persistent sign-up must not mint dont_remember")
		}
	})
}

// redirect/url response pair (sign-in.ts:603-637).
func TestSignInRememberMeAndCallback(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	registerEmailAuth(api, "/api/auth", opts)

	signUp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "In", "email": "in@example.com", "password": "password123",
	})
	if signUp.Code != http.StatusOK {
		t.Fatalf("seed sign-up: %d %s", signUp.Code, signUp.Body.String())
	}

	resp := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": "in@example.com", "password": "password123",
		"rememberMe": false, "callbackURL": "/dashboard",
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("sign-in: %d %s", resp.Code, resp.Body.String())
	}
	var body struct {
		Token    string  `json:"token"`
		Redirect bool    `json:"redirect"`
		URL      *string `json:"url"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Redirect || body.URL == nil || *body.URL != "/dashboard" {
		t.Fatalf("callbackURL must drive redirect/url, got %+v", body)
	}
	before := time.Now().UTC()
	if got := sessionExpiryOf(t, context.Background(), db, body.Token); got.After(before.Add(25 * time.Hour)) {
		t.Fatalf("dontRememberMe session must expire in ~1 day, got %v", got)
	}
	if _, ok := setCookiesOf(t, resp)[resolveDontRememberCookieName(opts, false)]; !ok {
		t.Fatal("sign-in with rememberMe=false must mint dont_remember")
	}

	plain := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": "in@example.com", "password": "password123",
	})
	var plainBody struct {
		Redirect bool    `json:"redirect"`
		URL      *string `json:"url"`
	}
	if err := json.Unmarshal(plain.Body.Bytes(), &plainBody); err != nil {
		t.Fatal(err)
	}
	if plainBody.Redirect || plainBody.URL != nil {
		t.Fatalf("no callbackURL must mean redirect=false without url, got %+v", plainBody)
	}
}

// sign-in issuance mirror the pair into secondary storage (upstream
func TestCreationMirrorsSecondaryStorage(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	store := newMapSecondaryStorage(true)
	opts := emailAuthTestOptions(db)
	opts.SecondaryStorage = store
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	registerEmailAuth(api, "/api/auth", opts)

	signUp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "Mirror", "email": "mirror@example.com", "password": "password123",
	})
	if signUp.Code != http.StatusOK {
		t.Fatalf("sign-up: %d %s", signUp.Code, signUp.Body.String())
	}
	var upBody struct {
		Token *string `json:"token"`
	}
	if err := json.Unmarshal(signUp.Body.Bytes(), &upBody); err != nil || upBody.Token == nil {
		t.Fatalf("sign-up token: %s (%v)", signUp.Body.String(), err)
	}
	if !store.has(*upBody.Token) {
		t.Fatal("sign-up issuance must mirror the session into secondary storage")
	}
	if !store.has(activeSessionsKey(mustFindUserID(t, ctx, db, "mirror@example.com"))) {
		t.Fatal("sign-up issuance must maintain the active-sessions list")
	}

	signIn := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": "mirror@example.com", "password": "password123",
	})
	if signIn.Code != http.StatusOK {
		t.Fatalf("sign-in: %d %s", signIn.Code, signIn.Body.String())
	}
	var inBody struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(signIn.Body.Bytes(), &inBody); err != nil {
		t.Fatal(err)
	}
	if !store.has(inBody.Token) {
		t.Fatal("sign-in issuance must mirror the session into secondary storage")
	}
}

func mustFindUserID(t *testing.T, ctx context.Context, db *parityMemAdapter, email string) string {
	t.Helper()
	row, err := db.FindOne(ctx, "user", []types.Where{{Field: "email", Value: email}}, nil)
	if err != nil || row == nil {
		t.Fatalf("user lookup: %v", err)
	}
	return stringField(row, "id")
}

// TestSignOutSecondaryAware pins secondary-aware sign-out (upstream
func TestSignOutSecondaryAware(t *testing.T) {
	ctx := context.Background()

	t.Run("secondary entry is removed", func(t *testing.T) {
		db := newParityMemAdapter()
		store := newMapSecondaryStorage(true)
		opts := secondarySessionTestOptions(db, store)
		seedSecondarySession(t, ctx, opts, db, "out@example.com", "tok-out", time.Now().UTC().Add(time.Hour))
		_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
		SignOut(api, "/api/auth", opts)
		resp := api.Post("/api/auth/sign-out", "Cookie: "+signedSessionHeader(t, opts, "tok-out"))
		if resp.Code != http.StatusOK {
			t.Fatalf("sign-out: %d %s", resp.Code, resp.Body.String())
		}
		if store.has("tok-out") {
			t.Fatal("sign-out must delete the secondary entry")
		}
	})

	t.Run("preserve mode ends the database row", func(t *testing.T) {
		db := newParityMemAdapter()
		store := newMapSecondaryStorage(true)
		opts := secondarySessionTestOptions(db, store)
		opts.Session.StoreSessionInDatabase = true
		opts.Session.PreserveSessionInDatabase = true
		seedSecondarySession(t, ctx, opts, db, "keep@example.com", "tok-keep", time.Now().UTC().Add(time.Hour))
		_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
		SignOut(api, "/api/auth", opts)
		resp := api.Post("/api/auth/sign-out", "Cookie: "+signedSessionHeader(t, opts, "tok-keep"))
		if resp.Code != http.StatusOK {
			t.Fatalf("sign-out: %d %s", resp.Code, resp.Body.String())
		}
		if store.has("tok-keep") {
			t.Fatal("sign-out must delete the secondary entry")
		}
		row, err := db.FindOne(ctx, "session", []types.Where{{Field: "token", Value: "tok-keep"}}, nil)
		if err != nil || row == nil {
			t.Fatalf("preserved row must remain: %v", err)
		}
		if exp, ok := timeField(row, "expires_at", "expiresAt"); !ok || exp.After(time.Now().UTC()) {
			t.Fatalf("preserved row must be ended, got %v", exp)
		}
	})
}

// TestExpiredRowDeletion pins upstream expiry cleanup (session.ts:297-301):
func TestExpiredRowDeletion(t *testing.T) {
	ctx := context.Background()

	t.Run("authoritative read deletes the expired row", func(t *testing.T) {
		db := newParityMemAdapter()
		opts := sessionTestOptions(db)
		seedSessionUser(t, db, "exp@example.com", "tok-exp", time.Now().UTC().Add(-time.Hour))
		if _, err := resolveGetSession(ctx, opts, getSessionRequest{token: "tok-exp", headers: CookieRequestHeaders{}}); err == nil {
			t.Fatal("expired session must error")
		}
		if row, _ := db.FindOne(ctx, "session", []types.Where{{Field: "token", Value: "tok-exp"}}, nil); row != nil {
			t.Fatal("expired row must be deleted on an authoritative read")
		}
	})

	t.Run("deferred get never writes", func(t *testing.T) {
		db := newParityMemAdapter()
		opts := sessionTestOptions(db)
		seedSessionUser(t, db, "def@example.com", "tok-def", time.Now().UTC().Add(-time.Hour))
		if _, err := resolveGetSession(ctx, opts, getSessionRequest{token: "tok-def", headers: CookieRequestHeaders{}, readOnly: true}); err == nil {
			t.Fatal("expired session must error")
		}
		if row, _ := db.FindOne(ctx, "session", []types.Where{{Field: "token", Value: "tok-def"}}, nil); row == nil {
			t.Fatal("deferred GET must not delete the expired row")
		}
	})
}

// TestGetSessionNoStore pins the upstream no-store contract
func TestGetSessionNoStore(t *testing.T) {
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	seedSessionUser(t, db, "store@example.com", "tok-store", time.Now().UTC().Add(time.Hour))
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	GetSession(api, "/api/auth", opts)
	resp := api.Get("/api/auth/get-session", "Cookie: "+signedSessionHeader(t, opts, "tok-store"))
	if resp.Code != http.StatusOK {
		t.Fatalf("get-session: %d %s", resp.Code, resp.Body.String())
	}
	if got := resp.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if got := resp.Header().Get("Pragma"); got != "no-cache" {
		t.Fatalf("Pragma = %q, want no-cache", got)
	}
}

// TestListSessionsFreshness pins the upstream fresh-session gate on
func TestListSessionsFreshness(t *testing.T) {
	seedStale := func(t *testing.T, db *parityMemAdapter, email, token string) {
		t.Helper()
		parityCreateUser(t, db, email, true)
		userRow, err := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: email}}, nil)
		if err != nil || userRow == nil {
			t.Fatalf("seed user: %v", err)
		}
		now := time.Now().UTC()
		stale := now.Add(-49 * time.Hour)
		if _, err := db.Create(context.Background(), "session", map[string]any{
			"id": "sess-" + token, "userId": stringField(userRow, "id"), "token": token,
			"expiresAt": now.Add(time.Hour), "createdAt": stale, "updatedAt": stale,
		}, nil); err != nil {
			t.Fatalf("seed session: %v", err)
		}
	}

	t.Run("stale session is rejected", func(t *testing.T) {
		db := newParityMemAdapter()
		opts := sessionTestOptions(db)
		seedStale(t, db, "stale@example.com", "tok-stale")
		_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
		ListSessions(api, "/api/auth", opts)
		resp := api.Get("/api/auth/list-sessions", "Cookie: "+signedSessionHeader(t, opts, "tok-stale"))
		if resp.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d: %s", resp.Code, resp.Body.String())
		}
		if !strings.Contains(resp.Body.String(), types.ErrSessionNotFresh) {
			t.Fatalf("body missing SESSION_NOT_FRESH: %s", resp.Body.String())
		}
	})

	t.Run("explicit zero disables the check", func(t *testing.T) {
		db := newParityMemAdapter()
		opts := sessionTestOptions(db)
		opts.Session.FreshAge = new(int)
		seedStale(t, db, "fresh0@example.com", "tok-fresh0")
		_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
		ListSessions(api, "/api/auth", opts)
		resp := api.Get("/api/auth/list-sessions", "Cookie: "+signedSessionHeader(t, opts, "tok-fresh0"))
		if resp.Code != http.StatusOK {
			t.Fatalf("FreshAge=0 must disable freshness, got %d: %s", resp.Code, resp.Body.String())
		}
	})
}

// (upstream parseSessionInput semantics): validators/transforms execute,
func TestUpdateSessionFullSchema(t *testing.T) {
	ctx := context.Background()

	seedWithFields := func(t *testing.T, db *parityMemAdapter, opts types.Options) {
		t.Helper()
		seedSessionUser(t, db, "upd@example.com", "tok-upd", time.Now().UTC().Add(time.Hour))
	}

	t.Run("validator rejection surfaces VALIDATION_ERROR", func(t *testing.T) {
		db := newParityMemAdapter()
		opts := sessionTestOptions(db)
		opts.Session.Model.AdditionalFields = map[string]types.FieldAttribute{
			"role": {Validator: &types.FieldValidator{
				Input: types.FieldValidatorFunc(func(v any) error {
					if s, _ := v.(string); s == "admin" {
						return errors.New("reserved")
					}
					return nil
				}),
			}},
		}
		seedWithFields(t, db, opts)
		_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
		UpdateSession(api, "/api/auth", opts)
		resp := api.Post("/api/auth/update-session",
			"Cookie: "+signedSessionHeader(t, opts, "tok-upd"),
			map[string]any{"role": "admin"})
		if resp.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", resp.Code, resp.Body.String())
		}
		if !strings.Contains(resp.Body.String(), types.ErrValidationError) {
			t.Fatalf("body missing VALIDATION_ERROR: %s", resp.Body.String())
		}
		_ = ctx
	})

	t.Run("transform executes and unknown fields are dropped", func(t *testing.T) {
		db := newParityMemAdapter()
		opts := sessionTestOptions(db)
		opts.Session.Model.AdditionalFields = map[string]types.FieldAttribute{
			"nick": {Transform: &types.FieldTransform{
				Input: func(v any) (any, error) { return strings.ToUpper(v.(string)), nil },
			}},
		}
		seedWithFields(t, db, opts)
		_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
		UpdateSession(api, "/api/auth", opts)
		resp := api.Post("/api/auth/update-session",
			"Cookie: "+signedSessionHeader(t, opts, "tok-upd"),
			map[string]any{"nick": "bob", "brand_new_field": "kept"})
		if resp.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
		}
		row, err := db.FindOne(ctx, "session", []types.Where{{Field: "token", Value: "tok-upd"}}, nil)
		if err != nil || row == nil {
			t.Fatal(err)
		}
		if stringField(row, "nick") != "BOB" {
			t.Fatalf("transformed nick not stored: %+v", row)
		}
		if stringField(row, "brand_new_field", "brandNewField") == "kept" {
			t.Fatalf("unknown field must be dropped (upstream): %+v", row)
		}
	})

	t.Run("input:false truthy rejects with FIELD_NOT_ALLOWED", func(t *testing.T) {
		db := newParityMemAdapter()
		opts := sessionTestOptions(db)
		opts.Session.Model.AdditionalFields = map[string]types.FieldAttribute{
			"secret": {Input: wave2BoolPtr(false)},
		}
		seedWithFields(t, db, opts)
		_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
		UpdateSession(api, "/api/auth", opts)
		resp := api.Post("/api/auth/update-session",
			"Cookie: "+signedSessionHeader(t, opts, "tok-upd"),
			map[string]any{"secret": "x"})
		if resp.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", resp.Code, resp.Body.String())
		}
		if !strings.Contains(resp.Body.String(), types.ErrFieldNotAllowed) {
			t.Fatalf("body missing FIELD_NOT_ALLOWED: %s", resp.Body.String())
		}
	})

	t.Run("snake spelling normalizes to the logical name", func(t *testing.T) {
		db := newParityMemAdapter()
		opts := sessionTestOptions(db)
		opts.Session.Model.AdditionalFields = map[string]types.FieldAttribute{
			"displayName": {},
		}
		seedWithFields(t, db, opts)
		_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
		UpdateSession(api, "/api/auth", opts)
		resp := api.Post("/api/auth/update-session",
			"Cookie: "+signedSessionHeader(t, opts, "tok-upd"),
			map[string]any{"display_name": "Bo"})
		if resp.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
		}
		row, err := db.FindOne(ctx, "session", []types.Where{{Field: "token", Value: "tok-upd"}}, nil)
		if err != nil || row == nil {
			t.Fatal(err)
		}
		if stringField(row, "displayName") != "Bo" {
			t.Fatalf("snake key must normalize to logical name: %+v", row)
		}
	})
}

// TestRowToSessionFullSchema pins the output-side migration: option-declared
func TestRowToSessionFullSchema(t *testing.T) {
	opts := parityTestOptions(newParityMemAdapter())
	opts.Session.Model.AdditionalFields = map[string]types.FieldAttribute{
		"nick":   {},
		"hidden": {Returned: wave2BoolPtr(false)},
	}
	row := map[string]any{
		"id": "s1", "userId": "u1", "token": "tok",
		"nick": "bob", "hidden": "nope", "undeclared": "kept",
	}
	got := rowToSession(row, opts)
	if got.AdditionalFields["nick"] != "bob" {
		t.Fatalf("option field must surface: %+v", got.AdditionalFields)
	}
	if _, ok := got.AdditionalFields["hidden"]; ok {
		t.Fatalf("returned:false must stay stripped: %+v", got.AdditionalFields)
	}
	if got.AdditionalFields["undeclared"] != "kept" {
		t.Fatalf("unknown fields pass through (union): %+v", got.AdditionalFields)
	}
}

// TestStrategyCachesRoundTrip pins JWT/JWE cookie-cache issuance and reads
func TestStrategyCachesRoundTrip(t *testing.T) {
	ctx := context.Background()
	for _, strategy := range []types.SessionCookieCacheStrategy{
		types.SessionCookieCacheJWT, types.SessionCookieCacheJWE,
	} {
		db := newParityMemAdapter()
		opts := sessionTestOptions(db)
		opts.Session.CookieCache.Enabled = true
		opts.Session.CookieCache.Strategy = strategy
		seedSessionUser(t, db, "cache-"+string(strategy)+"@example.com", "tok-"+string(strategy), time.Now().UTC().Add(time.Hour))

		sessionRow, userRow, _, err := loadSessionAndUser(ctx, opts, "tok-"+string(strategy))
		if err != nil {
			t.Fatal(err)
		}
		session, user := rowToSession(sessionRow, opts), rowToUser(userRow, opts)
		now := time.Now().UTC()
		issued, err := newSessionCookies(opts, CookieRequestHeaders{}, "tok-"+string(strategy), session, user, opts.Session, now)
		if err != nil {
			t.Fatalf("%s: issuance: %v", strategy, err)
		}
		if len(issued) != 2 {
			t.Fatalf("%s: expected session+cache cookies, got %d", strategy, len(issued))
		}
		header := signedSessionHeader(t, opts, "tok-"+string(strategy)) + "; " + issued[1].Name + "=" + issued[1].Value
		cached, ok := cachedSessionFromRequest(header, opts.AllSecrets(), "tok-"+string(strategy), opts.Session)
		if !ok || cached == nil {
			t.Fatalf("%s: expected cache hit", strategy)
		}
		if cached.Session.Token != "tok-"+string(strategy) {
			t.Fatalf("%s: wrong session: %+v", strategy, cached.Session)
		}
		if _, ok := cachedSessionFromRequest(header, []string{"foreign-secret"}, "tok-"+string(strategy), opts.Session); ok {
			t.Fatalf("%s: foreign secret must miss", strategy)
		}
		rotated := opts.Session
		rotated.CookieCache.Version = "2"
		if _, ok := cachedSessionFromRequest(header, opts.AllSecrets(), "tok-"+string(strategy), rotated); ok {
			t.Fatalf("%s: rotated version must miss", strategy)
		}
	}
}

// TestRefreshDefaults pins the upstream session-config defaults
func TestRefreshDefaults(t *testing.T) {
	opts := parityTestOptions(newParityMemAdapter())
	if got := opts.Session.ExpiresInDuration(); got != 7*24*time.Hour {
		t.Fatalf("default lifetime = %v, want 7d", got)
	}
	row := map[string]any{"expiresAt": time.Now().UTC().Add(30 * time.Second)}
	if due := sessionRefreshDue(row, opts, false, time.Now().UTC()); !due {
		t.Fatal("a session expiring in 30s must be due under default 24h/7d settings")
	}
	threshold, ok := cookies.CookieCacheRefreshThreshold(true, 0, opts.Session.CookieCacheMaxAgeDuration())
	if !ok || threshold != time.Minute {
		t.Fatalf("default refresh threshold = %v,%v, want 1m,true", threshold, ok)
	}
}
