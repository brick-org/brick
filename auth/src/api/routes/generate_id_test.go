package routes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

// issuingMemAdapter wraps parityMemAdapter simulating a database-issued ID
// (upstream generateId:false / "serial"): creates that omit "id" get a
// synthetic issued ID back, and every omission is recorded per model. It
// pins the serial contract: routes must omit the ID and consume the
// persisted-row return instead of a pre-minted value.
type issuingMemAdapter struct {
	*parityMemAdapter
	mu      sync.Mutex
	issued  int
	omitted map[string]int
}

func newIssuingMemAdapter() *issuingMemAdapter {
	return &issuingMemAdapter{parityMemAdapter: newParityMemAdapter(), omitted: map[string]int{}}
}

func (a *issuingMemAdapter) Create(ctx context.Context, model string, data map[string]any, select_ []string) (map[string]any, error) {
	cp := make(map[string]any, len(data)+1)
	for k, v := range data {
		cp[k] = v
	}
	if _, ok := cp["id"]; !ok {
		a.mu.Lock()
		a.issued++
		n := a.issued
		a.omitted[model]++
		a.mu.Unlock()
		cp["id"] = fmt.Sprintf("db-issued-%d", n)
	}
	return a.parityMemAdapter.Create(ctx, model, cp, select_)
}

func (a *issuingMemAdapter) omittedCount(model string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.omitted[model]
}

// Transaction preserves database-issued-ID semantics inside transactions
// (upstream runWithTransaction, e.g. sign-up.ts:183): the tx clone issues
// IDs for omitted creates exactly like the outer adapter, and commits back
// on success. Without this, the inherited parityMemAdapter.Transaction
// would run the tx against a plain clone that never issues IDs, breaking
// serial-mode creation paths that transact (sign-up user+account).
func (a *issuingMemAdapter) Transaction(ctx context.Context, fn func(tx types.Adapter) error) error {
	inner := &issuingMemAdapter{parityMemAdapter: newParityMemAdapter(), omitted: map[string]int{}}
	// Seed the tx with a snapshot of current tables.
	a.parityMemAdapter.mu.Lock()
	for model, rows := range a.parityMemAdapter.tables {
		for _, row := range rows {
			inner.parityMemAdapter.tables[model] = append(inner.parityMemAdapter.tables[model], parityClone(row))
		}
	}
	a.parityMemAdapter.mu.Unlock()
	if err := fn(inner); err != nil {
		return err
	}
	a.parityMemAdapter.mu.Lock()
	a.parityMemAdapter.tables = inner.parityMemAdapter.tables
	a.parityMemAdapter.mu.Unlock()
	a.mu.Lock()
	for model, n := range inner.omitted {
		a.omitted[model] += n
	}
	issued := inner.issued
	a.mu.Unlock()
	_ = ctx
	_ = issued
	return nil
}

// generateIDCall records one custom-generateID invocation.
type generateIDCall struct {
	model string
	size  *int
}

// recordingGenerateID returns a custom GenerateID func that records every
// (model, size) pair and mints prefix+model IDs.
func recordingGenerateID(prefix string, calls *[]generateIDCall, mu *sync.Mutex) types.GenerateIDFunc {
	return func(model string, size *int) (string, bool) {
		mu.Lock()
		*calls = append(*calls, generateIDCall{model: model, size: size})
		mu.Unlock()
		return prefix + model, true
	}
}

func generateIDModels(calls []generateIDCall) []string {
	out := make([]string, 0, len(calls))
	for _, c := range calls {
		out = append(out, c.model)
	}
	return out
}

// signUpViaAPI performs a credential sign-up and returns the session token.
func signUpViaAPI(t *testing.T, api humatest.TestAPI, email string) string {
	t.Helper()
	resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "Gen", "email": email, "password": "password123",
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("sign-up: %d %s", resp.Code, resp.Body.String())
	}
	var body struct {
		Token *string `json:"token"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil || body.Token == nil || *body.Token == "" {
		t.Fatalf("sign-up must return a session token: %s (%v)", resp.Body.String(), err)
	}
	return *body.Token
}

// TestGenerateID_CustomFuncHonoredAtSignUp ports the upstream context-generator
// contract (create-context.ts generateIdFunc + internal-adapter createSession
// + sign-up synthetic/real creates): a custom generateId receives the model
// name (user/account/session) with a nil size hint, and every model-row ID it
// returns is persisted. Session/verification tokens are NOT model IDs
// (upstream generateId(32) direct) and must keep random values.
func TestGenerateID_CustomFuncHonoredAtSignUp(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	var mu sync.Mutex
	var calls []generateIDCall
	opts.Advanced.Database.GenerateID.Func = recordingGenerateID("t-", &calls, &mu)
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	registerEmailAuth(api, "/api/auth", opts)

	token := signUpViaAPI(t, api, "custom-id@example.com")
	if strings.HasPrefix(token, "t-") {
		t.Fatalf("session token must stay random, got %q", token)
	}
	if len(token) != 32 {
		t.Fatalf("session token must keep the 32-char random shape, got %q", token)
	}

	userRow, err := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: "custom-id@example.com"}}, nil)
	if err != nil || userRow == nil {
		t.Fatalf("user lookup: %v", err)
	}
	if got, _ := userRow["id"].(string); got != "t-user" {
		t.Fatalf("user id must honor the custom generator, got %q", got)
	}
	accountRow, err := db.FindOne(context.Background(), "account", []types.Where{{Field: "userId", Value: "t-user"}}, nil)
	if err != nil || accountRow == nil {
		t.Fatalf("account must link the generated user id: %v %+v", err, accountRow)
	}
	if got, _ := accountRow["id"].(string); got != "t-account" {
		t.Fatalf("account id must honor the custom generator, got %q", got)
	}
	sessionRow, err := db.FindOne(context.Background(), "session", []types.Where{{Field: "token", Value: token}}, nil)
	if err != nil || sessionRow == nil {
		t.Fatalf("session lookup: %v", err)
	}
	if got, _ := sessionRow["id"].(string); got != "t-session" {
		t.Fatalf("session id must honor the custom generator, got %q", got)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 3 {
		t.Fatalf("expected user/account/session mints, got %v", generateIDModels(calls))
	}
	for _, want := range []string{"user", "account", "session"} {
		found := false
		for _, c := range calls {
			if c.model == want {
				found = true
				if c.size != nil {
					t.Fatalf("model mint for %q must pass a nil size hint, got %d", want, *c.size)
				}
			}
		}
		if !found {
			t.Fatalf("custom generator must see model %q, got %v", want, generateIDModels(calls))
		}
	}
}

// TestGenerateID_UUIDModeAtSignUp ports the "uuid" shorthand to creation:
// model-row IDs come out as UUIDs while the session token keeps its random
// shape.
func TestGenerateID_UUIDModeAtSignUp(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.Advanced.Database.GenerateID.Mode = types.GenerateIDModeUUID
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	registerEmailAuth(api, "/api/auth", opts)

	token := signUpViaAPI(t, api, "uuid-id@example.com")
	if len(token) != 32 {
		t.Fatalf("session token must keep the 32-char random shape, got %q", token)
	}
	userRow, err := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: "uuid-id@example.com"}}, nil)
	if err != nil || userRow == nil {
		t.Fatalf("user lookup: %v", err)
	}
	userID, _ := userRow["id"].(string)
	if len(userID) != 36 || strings.Count(userID, "-") != 4 || userID[14] != '4' {
		t.Fatalf("user id must be a v4 UUID, got %q", userID)
	}
	sessionRow, err := db.FindOne(context.Background(), "session", []types.Where{{Field: "token", Value: token}}, nil)
	if err != nil || sessionRow == nil {
		t.Fatalf("session lookup: %v", err)
	}
	sessionID, _ := sessionRow["id"].(string)
	if len(sessionID) != 36 || strings.Count(sessionID, "-") != 4 {
		t.Fatalf("session id must be a UUID, got %q", sessionID)
	}
}

// TestGenerateID_SerialModeOmitsIDs ports the "serial" shorthand to creation
// (upstream generateId:false): routes omit the ID so the database issues it,
// and downstream rows consume the persisted return (the account links the
// issued user ID, not a pre-minted value).
func TestGenerateID_SerialModeOmitsIDs(t *testing.T) {
	db := newIssuingMemAdapter()
	opts := emailAuthTestOptions(db.parityMemAdapter)
	opts.DB = db
	opts.Advanced.Database.GenerateID.Mode = types.GenerateIDModeSerial
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	registerEmailAuth(api, "/api/auth", opts)

	token := signUpViaAPI(t, api, "serial-id@example.com")
	userRow, err := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: "serial-id@example.com"}}, nil)
	if err != nil || userRow == nil {
		t.Fatalf("user lookup: %v", err)
	}
	userID, _ := userRow["id"].(string)
	if !strings.HasPrefix(userID, "db-issued-") {
		t.Fatalf("user id must be database-issued, got %q", userID)
	}
	for _, model := range []string{"user", "account", "session"} {
		if n := db.omittedCount(model); n == 0 {
			t.Fatalf("serial mode must omit the %q id from the create, got no omission", model)
		}
	}
	accountRow, err := db.FindOne(context.Background(), "account", []types.Where{{Field: "userId", Value: userID}}, nil)
	if err != nil || accountRow == nil {
		t.Fatalf("account must link the issued user id %q: %v", userID, err)
	}
	sessionRow, err := db.FindOne(context.Background(), "session", []types.Where{{Field: "token", Value: token}}, nil)
	if err != nil || sessionRow == nil {
		t.Fatalf("session lookup: %v", err)
	}
	if sid, _ := sessionRow["id"].(string); !strings.HasPrefix(sid, "db-issued-") {
		t.Fatalf("session id must be database-issued, got %q", sid)
	}
	if len(token) != 32 {
		t.Fatalf("session token must stay random, got %q", token)
	}
}

// TestSecondaryOnlySignUpSkipsDB ports the secondary-only branch of upstream
// createSession (internal-adapter.ts:568-576, executeMainFn: storeInDb): with
// secondary storage and StoreSessionInDatabase unset, issuance writes no
// primary session row and serves entirely from the secondary pair. The
// session ID still honors the custom generator.
func TestSecondaryOnlySignUpSkipsDB(t *testing.T) {
	db := newParityMemAdapter()
	store := newMapSecondaryStorage(true)
	opts := emailAuthTestOptions(db)
	opts.SecondaryStorage = store
	var mu sync.Mutex
	var calls []generateIDCall
	opts.Advanced.Database.GenerateID.Func = recordingGenerateID("s-", &calls, &mu)
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	registerEmailAuth(api, "/api/auth", opts)

	token := signUpViaAPI(t, api, "secondary-only@example.com")

	rows, err := db.FindMany(context.Background(), "session", nil, 0, 0, nil, nil)
	if err != nil {
		t.Fatalf("session scan: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("secondary-only issuance must skip the primary DB, got %d session rows", len(rows))
	}
	pair, err := findSecondarySession(opts, token)
	if err != nil || pair == nil {
		t.Fatalf("secondary pair must be present: %v", err)
	}
	if pair.Session.ID != "s-session" {
		t.Fatalf("secondary-only session id must honor the custom generator, got %q", pair.Session.ID)
	}
	if pair.Session.Token != token || pair.User.Email != "secondary-only@example.com" {
		t.Fatalf("wrong secondary pair: %+v %+v", pair.Session, pair.User)
	}
}

// TestSecondaryOnlySignInSkipsDB covers the sign-in issuance leg of the same
// upstream branch: no primary session row is written in secondary-only mode.
func TestSecondaryOnlySignInSkipsDB(t *testing.T) {
	db := newParityMemAdapter()
	store := newMapSecondaryStorage(true)
	opts := emailAuthTestOptions(db)
	opts.SecondaryStorage = store
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	registerEmailAuth(api, "/api/auth", opts)

	signUpViaAPI(t, api, "signin-secondary@example.com")
	resp := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": "signin-secondary@example.com", "password": "password123",
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("sign-in: %d %s", resp.Code, resp.Body.String())
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil || body.Token == "" {
		t.Fatalf("sign-in must return a token: %s (%v)", resp.Body.String(), err)
	}
	rows, err := db.FindMany(context.Background(), "session", nil, 0, 0, nil, nil)
	if err != nil {
		t.Fatalf("session scan: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("secondary-only sign-in must skip the primary DB, got %d session rows", len(rows))
	}
	if pair, err := findSecondarySession(opts, body.Token); err != nil || pair == nil {
		t.Fatalf("secondary pair must be present: %v", err)
	}
}

// TestGenerateID_SerialSecondaryOnlySessionFallsBack ports the
// `generatedId !== false ? generatedId : generateId()` fallback in upstream
// createSession: a serial deployment with secondary-only sessions still mints
// an in-memory random session ID (there is no database to issue one).
func TestGenerateID_SerialSecondaryOnlySessionFallsBack(t *testing.T) {
	db := newParityMemAdapter()
	store := newMapSecondaryStorage(true)
	opts := emailAuthTestOptions(db)
	opts.SecondaryStorage = store
	opts.Advanced.Database.GenerateID.Mode = types.GenerateIDModeSerial
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	registerEmailAuth(api, "/api/auth", opts)

	token := signUpViaAPI(t, api, "serial-secondary@example.com")
	rows, err := db.FindMany(context.Background(), "session", nil, 0, 0, nil, nil)
	if err != nil {
		t.Fatalf("session scan: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("secondary-only issuance must skip the primary DB, got %d session rows", len(rows))
	}
	pair, err := findSecondarySession(opts, token)
	if err != nil || pair == nil {
		t.Fatalf("secondary pair must be present: %v", err)
	}
	if len(pair.Session.ID) != 32 {
		t.Fatalf("serial secondary-only session must fall back to a random ID, got %q", pair.Session.ID)
	}
}

// errSecondaryStorage fails every Set, pinning the issuance-failure matrix.
type errSecondaryStorage struct {
	*mapSecondaryStorage
}

func (e *errSecondaryStorage) Set(string, string, *int) error {
	return errors.New("secondary unavailable")
}

// failSessionAdapter fails session-row creates, pinning the DB-failure leg.
type failSessionAdapter struct {
	*parityMemAdapter
}

func (a *failSessionAdapter) Create(ctx context.Context, model string, data map[string]any, select_ []string) (map[string]any, error) {
	if model == "session" {
		return nil, errors.New("database unavailable")
	}
	return a.parityMemAdapter.Create(ctx, model, data, select_)
}

// TestSessionIssuanceFailureMatrix ports the failure legs around upstream
// createSession mirroring: a failing secondary mirror fails issuance loudly
// (like the database create), and a database failure surfaces instead of a
// half-issued session.
func TestSessionIssuanceFailureMatrix(t *testing.T) {
	t.Run("mirror failure fails sign-up", func(t *testing.T) {
		db := newParityMemAdapter()
		opts := emailAuthTestOptions(db)
		opts.SecondaryStorage = &errSecondaryStorage{newMapSecondaryStorage(true)}
		_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
		registerEmailAuth(api, "/api/auth", opts)
		resp := api.Post("/api/auth/sign-up/email", map[string]any{
			"name": "Fail", "email": "mirror-fail@example.com", "password": "password123",
		})
		if resp.Code == http.StatusOK {
			t.Fatalf("failing mirror must fail issuance, got %d %s", resp.Code, resp.Body.String())
		}
	})
	t.Run("database failure fails sign-up", func(t *testing.T) {
		db := newParityMemAdapter()
		failing := &failSessionAdapter{db}
		opts := emailAuthTestOptions(db)
		opts.DB = failing
		_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
		registerEmailAuth(api, "/api/auth", opts)
		resp := api.Post("/api/auth/sign-up/email", map[string]any{
			"name": "Fail", "email": "db-fail@example.com", "password": "password123",
		})
		if resp.Code == http.StatusOK {
			t.Fatalf("failing database create must fail issuance, got %d %s", resp.Code, resp.Body.String())
		}
	})
	t.Run("secondary-only mirror failure fails sign-up with no DB row", func(t *testing.T) {
		db := newParityMemAdapter()
		opts := emailAuthTestOptions(db)
		opts.SecondaryStorage = &errSecondaryStorage{newMapSecondaryStorage(true)}
		_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
		registerEmailAuth(api, "/api/auth", opts)
		resp := api.Post("/api/auth/sign-up/email", map[string]any{
			"name": "Fail", "email": "mirror-fail-2@example.com", "password": "password123",
		})
		if resp.Code == http.StatusOK {
			t.Fatalf("failing secondary-only mirror must fail issuance, got %d %s", resp.Code, resp.Body.String())
		}
		rows, err := db.FindMany(context.Background(), "session", nil, 0, 0, nil, nil)
		if err != nil {
			t.Fatalf("session scan: %v", err)
		}
		if len(rows) != 0 {
			t.Fatalf("failed secondary-only issuance must leave no DB row, got %d", len(rows))
		}
	})
}

// TestGenerateID_VerificationRowUsesCustomFunc pins the custom generator on
// verification-row creation (upstream createVerificationValue flows through
// the adapter defaultValue honoring generateId): the reset-password row ID
// carries the custom mint while the token itself stays random.
func TestGenerateID_VerificationRowUsesCustomFunc(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	opts.EmailAndPassword.Enabled = true
	opts.EmailAndPassword.SendResetPassword = func(types.ResetPasswordData) error { return nil }
	var mu sync.Mutex
	var calls []generateIDCall
	opts.Advanced.Database.GenerateID.Func = recordingGenerateID("v-", &calls, &mu)
	parityCreateUser(t, db, "reset-id@example.com", true)

	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	RequestPasswordReset(api, "/api/auth", opts)
	resp := api.Post("/api/auth/request-password-reset", map[string]any{
		"email": "reset-id@example.com",
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("request-password-reset: %d %s", resp.Code, resp.Body.String())
	}
	rows, err := db.FindMany(context.Background(), "verification", nil, 0, 0, nil, nil)
	if err != nil || len(rows) != 1 {
		t.Fatalf("expected one verification row, got %d (%v)", len(rows), err)
	}
	if got, _ := rows[0]["id"].(string); got != "v-verification" {
		t.Fatalf("verification id must honor the custom generator, got %q", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 1 || calls[0].model != "verification" {
		t.Fatalf("custom generator must see exactly the verification model, got %v", generateIDModels(calls))
	}
}

// TestGenerateID_EmailVerificationSessionHonorsCustomFunc pins the custom
// generator on the post-verification auto-sign-in session (the fourth
// issuance leg sharing createSession semantics).
func TestGenerateID_EmailVerificationSessionHonorsCustomFunc(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	store := newMapSecondaryStorage(true)
	opts := parityTestOptions(db)
	opts.SecondaryStorage = store
	var mu sync.Mutex
	var calls []generateIDCall
	opts.Advanced.Database.GenerateID.Func = recordingGenerateID("e-", &calls, &mu)
	parityCreateUser(t, db, "verify-session@example.com", false)
	userRow, err := db.FindOne(ctx, "user", []types.Where{{Field: "email", Value: "verify-session@example.com"}}, nil)
	if err != nil || userRow == nil {
		t.Fatalf("seed user lookup: %v", err)
	}
	user := rowToUser(userRow, opts)
	now := time.Now().UTC()
	cookiesOut, err := createVerificationSession(ctx, opts, CookieRequestHeaders{}, user, now)
	if err != nil {
		t.Fatalf("createVerificationSession: %v", err)
	}
	if len(cookiesOut) == 0 {
		t.Fatal("expected session cookies")
	}
	rows, err := db.FindMany(ctx, "session", nil, 0, 0, nil, nil)
	if err != nil {
		t.Fatalf("session scan: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("secondary-only verification session must skip the primary DB, got %d rows", len(rows))
	}
	mu.Lock()
	defer mu.Unlock()
	found := false
	for _, c := range calls {
		if c.model == "session" {
			found = true
		}
	}
	if !found {
		t.Fatalf("custom generator must mint the verification session, got %v", generateIDModels(calls))
	}
}
