package auth_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	auth "github.com/brick-org/brick/auth/src"
	authbun "github.com/brick-org/brick/auth/src/adapters/bun"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
)

type memoryAdapter struct {
	tables map[string][]map[string]any
}

// newTestAdapter returns a humatest adapter backed by a real httptest server.
func newTestAdapter(t *testing.T) (huma.Adapter, *httptest.Server) {
	t.Helper()
	_, testAPI := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	srv := httptest.NewServer(testAPI.Adapter())
	t.Cleanup(srv.Close)
	return testAPI.Adapter(), srv
}

func newTestAPI(t *testing.T) humatest.TestAPI {
	t.Helper()
	_, testAPI := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	return testAPI
}

// mustBetterAuth calls auth.BetterAuth and fails the test on error.
// BetterAuth returns (Auth, error) since the breaking error-handling pass;
// all in-repo callers must handle the error.
func mustBetterAuth(t *testing.T, opts auth.Options) auth.Auth {
	t.Helper()
	a, err := auth.BetterAuth(opts)
	if err != nil {
		t.Fatalf("BetterAuth: %v", err)
	}
	return a
}

// Cycle 1 — tracer bullet

func TestNew_SmokeOK(t *testing.T) {
	adapter, srv := newTestAdapter(t)
	mustBetterAuth(t, auth.Options{Secret: "test-secret", Adapter: adapter})

	resp, err := http.Get(srv.URL + "/api/auth/ok")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var body struct {
		OK bool `json:"ok"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !body.OK {
		t.Fatal("expected ok=true")
	}
}

// Cycle 2 — base path

func TestNew_DefaultBasePath(t *testing.T) {
	adapter, srv := newTestAdapter(t)
	mustBetterAuth(t, auth.Options{Secret: "s", Adapter: adapter})

	resp, _ := http.Get(srv.URL + "/api/auth/ok")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("default base path /api/auth unreachable, got %d", resp.StatusCode)
	}
}

func TestNew_CustomBasePath(t *testing.T) {
	adapter, srv := newTestAdapter(t)
	mustBetterAuth(t, auth.Options{Secret: "s", BasePath: "/v1/auth", Adapter: adapter})

	resp, _ := http.Get(srv.URL + "/v1/auth/ok")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/v1/auth/ok should return 200, got %d", resp.StatusCode)
	}
	resp2, _ := http.Get(srv.URL + "/api/auth/ok")
	if resp2.StatusCode == http.StatusOK {
		t.Fatal("/api/auth/ok must not exist when custom base path is set")
	}
}

// Cycle 3 — cookie signing

func TestCookieSignVerify(t *testing.T) {
	signed, err := auth.SignCookie("super-secret", "session-token-abc")
	if err != nil {
		t.Fatalf("SignCookie: %v", err)
	}
	value, ok := auth.VerifyCookie("super-secret", signed)
	if !ok {
		t.Fatal("VerifyCookie should return true for valid signature")
	}
	if value != "session-token-abc" {
		t.Fatalf("expected original value, got %q", value)
	}
}

func TestCookieVerify_Tampered(t *testing.T) {
	signed, _ := auth.SignCookie("secret", "token")
	_, ok := auth.VerifyCookie("secret", signed+"x")
	if ok {
		t.Fatal("tampered cookie must not verify")
	}
}

func TestCookieVerify_WrongSecret(t *testing.T) {
	signed, _ := auth.SignCookie("secret-a", "token")
	_, ok := auth.VerifyCookie("secret-b", signed)
	if ok {
		t.Fatal("wrong secret must not verify")
	}
}

func TestCookieVerify_RetainedSecretAfterRotation(t *testing.T) {
	signed, err := auth.SignCookie("secret-a", "token")
	if err != nil {
		t.Fatalf("SignCookie: %v", err)
	}

	value, ok := auth.VerifyCookieWithSecrets([]auth.Secret{
		{Version: 2, Value: "secret-b"},
		{Version: 1, Value: "secret-a"},
	}, signed)
	if !ok {
		t.Fatal("cookie signed with a retained secret must still verify after rotation")
	}
	if value != "token" {
		t.Fatalf("expected original value, got %q", value)
	}
}

// Cycle 4 — error codes

func TestErrorCodes_Exported(t *testing.T) {
	codes := []string{
		auth.ErrUserNotFound,
		auth.ErrInvalidPassword,
		auth.ErrUserAlreadyExists,
		auth.ErrSessionExpired,
		auth.ErrInvalidToken,
		auth.ErrEmailNotVerified,
	}
	for _, c := range codes {
		if c == "" {
			t.Fatal("all error code constants must be non-empty strings")
		}
	}
}
func TestNew_DisabledPathReturns404(t *testing.T) {
	api := newTestAPI(t)
	mustBetterAuth(t, auth.Options{
		Secret:        "test-secret",
		Adapter:       api.Adapter(),
		DisabledPaths: []string{"/sign-in/email"},
	})

	okResp := api.Get("/api/auth/ok")
	if okResp.Code != http.StatusOK {
		t.Fatalf("expected /ok to stay enabled, got %d", okResp.Code)
	}

	signInResp := api.Post("/api/auth/sign-in/email", map[string]any{
		"email":    "test@example.com",
		"password": "password123",
	})
	if signInResp.Code != http.StatusNotFound {
		t.Fatalf("expected disabled path to return 404, got %d", signInResp.Code)
	}
}

func TestNew_AppNameDefaultAndCustom(t *testing.T) {
	api := newTestAPI(t)
	defaultAuth := mustBetterAuth(t, auth.Options{
		Secret:  "test-secret",
		Adapter: api.Adapter(),
	})
	if defaultAuth.Context.AppName != "Better Auth" {
		t.Fatalf("expected default app name, got %q", defaultAuth.Context.AppName)
	}

	customAuth := mustBetterAuth(t, auth.Options{
		Secret:  "test-secret",
		Adapter: api.Adapter(),
		AppName: "Brick Auth",
	})
	if customAuth.Context.AppName != "Brick Auth" {
		t.Fatalf("expected custom app name, got %q", customAuth.Context.AppName)
	}
}

func TestNew_LoggerAndTelemetryOptionsExposed(t *testing.T) {
	api := newTestAPI(t)
	captured := []string{}
	instance := mustBetterAuth(t, auth.Options{
		Secret:  "test-secret",
		Adapter: api.Adapter(),
		Logger: auth.LoggerOptions{
			Disabled: true,
			Level:    "debug",
			Log: func(level, message string, args ...any) {
				captured = append(captured, level+":"+message)
			},
		},
		Telemetry: auth.TelemetryOptions{
			Enabled: true,
			Debug:   true,
		},
	})

	if !instance.Context.Options.Logger.Disabled {
		t.Fatal("expected logger disabled flag to be preserved")
	}
	if instance.Context.Options.Logger.Level != "debug" {
		t.Fatalf("expected logger level debug, got %q", instance.Context.Options.Logger.Level)
	}
	if !instance.Context.Options.Telemetry.Enabled || !instance.Context.Options.Telemetry.Debug {
		t.Fatal("expected telemetry options to be preserved")
	}
	if len(captured) != 0 {
		t.Fatal("expected no logger calls during construction in the no-op parity slice")
	}
}

func TestNew_RequestHooksRunAroundAuthRequests(t *testing.T) {
	type hookKey struct{}

	adapter, srv := newTestAdapter(t)
	observed := []string{}
	mustBetterAuth(t, auth.Options{
		Secret:  "test-secret",
		Adapter: adapter,
		Hooks: auth.HooksOptions{
			Before: func(ctx huma.Context) (huma.Context, error) {
				observed = append(observed, "before:"+ctx.Method()+":"+ctx.URL().Path)
				return huma.WithContext(ctx, context.WithValue(ctx.Context(), hookKey{}, "set-by-before")), nil
			},
			After: func(ctx huma.Context) {
				if got := ctx.Context().Value(hookKey{}); got != "set-by-before" {
					t.Fatalf("expected request context value from before hook, got %v", got)
				}
				observed = append(observed, fmt.Sprintf("after:%d", ctx.Status()))
			},
		},
	})

	resp, err := http.Get(srv.URL + "/api/auth/ok")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	expected := []string{"before:GET:/api/auth/ok", "after:200"}
	if len(observed) != len(expected) {
		t.Fatalf("expected %v hook calls, got %v", expected, observed)
	}
	for i := range expected {
		if observed[i] != expected[i] {
			t.Fatalf("expected hook call %q at index %d, got %q", expected[i], i, observed[i])
		}
	}
}

func TestNew_OnAPIErrorRunsForAuthRouteFailures(t *testing.T) {
	adapter, srv := newTestAdapter(t)
	captured := struct {
		status      int
		title       string
		detail      string
		path        string
		operationID string
	}{}

	mustBetterAuth(t, auth.Options{
		Secret:  "test-secret",
		Adapter: adapter,
		OnAPIError: auth.APIErrorOptions{
			OnError: func(err huma.StatusError, ctx huma.Context) {
				captured.status = err.GetStatus()
				var model *huma.ErrorModel
				if errors.As(err, &model) {
					captured.title = model.Title
					captured.detail = model.Detail
				}
				captured.path = ctx.URL().Path
				captured.operationID = ctx.Operation().OperationID
			},
		},
	})

	resp, err := http.Post(
		srv.URL+"/api/auth/sign-in/email",
		"application/json",
		strings.NewReader(`{"email":"hooked@example.com","password":"password123"}`),
	)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	if captured.status != http.StatusBadRequest {
		t.Fatalf("expected captured status 400, got %d", captured.status)
	}
	if captured.title != "Bad Request" {
		t.Fatalf("expected captured title %q, got %q", "Bad Request", captured.title)
	}
	if captured.detail != "EMAIL_PASSWORD_DISABLED: Email and password is not enabled" {
		t.Fatalf("expected captured detail %q, got %q", "EMAIL_PASSWORD_DISABLED: Email and password is not enabled", captured.detail)
	}
	if captured.path != "/api/auth/sign-in/email" {
		t.Fatalf("expected captured path %q, got %q", "/api/auth/sign-in/email", captured.path)
	}
	if captured.operationID != "signInEmail" {
		t.Fatalf("expected captured operation ID %q, got %q", "signInEmail", captured.operationID)
	}
}

func openDB(t *testing.T) *bun.DB {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set — skipping Postgres integration tests")
	}
	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn)))
	db := bun.NewDB(sqldb, pgdialect.New())
	t.Cleanup(func() { db.Close() })
	return db
}

func migrate(t *testing.T, db *bun.DB) {
	t.Helper()
	ctx := context.Background()
	tables := []any{
		(*authbun.User)(nil),
		(*authbun.Session)(nil),
		(*authbun.Account)(nil),
		(*authbun.Verification)(nil),
	}
	for _, table := range tables {
		if _, err := db.NewCreateTable().Model(table).IfNotExists().Exec(ctx); err != nil {
			t.Fatalf("create table: %v", err)
		}
	}
	t.Cleanup(func() {
		for i := len(tables) - 1; i >= 0; i-- {
			_, _ = db.NewDropTable().Model(tables[i]).IfExists().Exec(ctx)
		}
	})
}

func newIntegrationAuth(t *testing.T, session auth.SessionOptions) (*httptest.Server, auth.DBAdapter) {
	t.Helper()
	return newIntegrationAuthWithOptions(t, auth.Options{
		Session: session,
		EmailAndPassword: auth.EmailAndPasswordOptions{
			Enabled: true,
		},
	})
}

func newIntegrationAuthWithOptions(t *testing.T, opts auth.Options) (*httptest.Server, auth.DBAdapter) {
	t.Helper()
	db := openDB(t)
	migrate(t, db)
	adapter, srv := newTestAdapter(t)
	opts.Secret = "test-secret"
	opts.Adapter = adapter
	opts.DB = authbun.New(db, authbun.Config{})
	if !opts.EmailAndPassword.Enabled {
		opts.EmailAndPassword.Enabled = true
	}
	mustBetterAuth(t, opts)
	return srv, authbun.New(db, authbun.Config{})
}

func newMemoryAuthServer(t *testing.T, opts auth.Options) (*httptest.Server, auth.DBAdapter) {
	t.Helper()
	adapter, srv := newTestAdapter(t)
	db := newMemoryAdapter()
	mustBetterAuth(t, auth.Options{
		Secret:            "test-secret",
		Adapter:           adapter,
		DB:                db,
		Session:           opts.Session,
		EmailAndPassword:  opts.EmailAndPassword,
		EmailVerification: opts.EmailVerification,
		User:              opts.User,
		Plugins:           opts.Plugins,
		RateLimit:         opts.RateLimit,
	})
	return srv, db
}

func newMemoryAuthAPI(t *testing.T, opts auth.Options) (humatest.TestAPI, auth.DBAdapter) {
	t.Helper()
	api := newTestAPI(t)
	db := newMemoryAdapter()
	mustBetterAuth(t, auth.Options{
		Secret:            "test-secret",
		Adapter:           api.Adapter(),
		DB:                db,
		Session:           opts.Session,
		EmailAndPassword:  opts.EmailAndPassword,
		EmailVerification: opts.EmailVerification,
		User:              opts.User,
		Plugins:           opts.Plugins,
		RateLimit:         opts.RateLimit,
	})
	return api, db
}

func signUp(t *testing.T, baseURL string, email string) (*http.Response, string) {
	t.Helper()
	body := strings.NewReader(`{"name":"Test User","email":"` + email + `","password":"password123"}`)
	resp, err := http.Post(baseURL+"/api/auth/sign-up/email", "application/json", body)
	if err != nil {
		t.Fatalf("sign-up request failed: %v", err)
	}
	setCookies := resp.Header.Values("Set-Cookie")
	if len(setCookies) == 0 {
		t.Fatalf("expected session cookies")
	}
	return resp, cookieHeaderFromSetCookies(setCookies)
}

func getSession(t *testing.T, baseURL string, cookie string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, baseURL+"/api/auth/get-session", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Cookie", cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get-session request failed: %v", err)
	}
	return resp
}

func decodeJSON[T any](t *testing.T, resp *http.Response, out *T) {
	t.Helper()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatalf("decode json: %v", err)
	}
}

func findCredentialAccountByEmail(t *testing.T, db auth.DBAdapter, email string) map[string]any {
	t.Helper()
	userRow, err := db.FindOne(context.Background(), "user", []auth.Where{
		{Field: "email", Value: email},
	}, nil)
	if err != nil {
		t.Fatalf("find user by email: %v", err)
	}
	if userRow == nil {
		t.Fatalf("expected user row for %s", email)
	}
	userID, _ := userRow["id"].(string)
	accountRow, err := db.FindOne(context.Background(), "account", []auth.Where{
		{Field: "userId", Value: userID},
		{Field: "providerId", Value: "credential", Connector: "AND"},
	}, nil)
	if err != nil {
		t.Fatalf("find credential account: %v", err)
	}
	if accountRow == nil {
		t.Fatalf("expected credential account for %s", email)
	}
	return accountRow
}

func TestAuthSessionRefresh_UsesSignedCookie(t *testing.T) {
	srv, db := newIntegrationAuth(t, auth.SessionOptions{ExpiresIn: 5, UpdateAge: intPtr(1)})
	resp, cookie := signUp(t, srv.URL, "refresh@example.com")
	resp.Body.Close()

	time.Sleep(1100 * time.Millisecond)

	sessionResp := getSession(t, srv.URL, cookie)
	defer sessionResp.Body.Close()
	if sessionResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", sessionResp.StatusCode)
	}
	if sessionResp.Header.Get("Set-Cookie") == "" {
		t.Fatalf("expected refreshed session cookie header")
	}

	row, err := db.FindOne(context.Background(), "session", []auth.Where{
		{Field: "token", Value: strings.Split(strings.Split(cookie, ";")[0], "=")[1]},
	}, nil)
	if err == nil && row != nil {
		t.Fatalf("expected signed cookie token, not raw cookie token")
	}
}

func TestAuthSessionFlows_RetainedCookieWorksAfterSecretRotation(t *testing.T) {
	db := openDB(t)
	migrate(t, db)

	adapter, oldSrv := newTestAdapter(t)
	mustBetterAuth(t, auth.Options{
		Secret:  "test-secret-v1",
		Adapter: adapter,
		DB:      authbun.New(db, authbun.Config{}),
		Session: auth.SessionOptions{ExpiresIn: 3600, UpdateAge: intPtr(1)},
		EmailAndPassword: auth.EmailAndPasswordOptions{
			Enabled: true,
		},
	})

	resp, cookie := signUp(t, oldSrv.URL, "rotation@example.com")
	resp.Body.Close()

	rotatedAdapter, rotatedSrv := newTestAdapter(t)
	mustBetterAuth(t, auth.Options{
		Secret:  "test-secret-v2",
		Secrets: []auth.Secret{{Version: 2, Value: "test-secret-v2"}, {Version: 1, Value: "test-secret-v1"}},
		Adapter: rotatedAdapter,
		DB:      authbun.New(db, authbun.Config{}),
		Session: auth.SessionOptions{ExpiresIn: 3600, UpdateAge: intPtr(1)},
		EmailAndPassword: auth.EmailAndPasswordOptions{
			Enabled: true,
		},
	})

	sessionResp := getSession(t, rotatedSrv.URL, cookie)
	defer sessionResp.Body.Close()
	if sessionResp.StatusCode != http.StatusOK {
		t.Fatalf("expected retained session cookie to keep working after rotation, got %d", sessionResp.StatusCode)
	}
}

func TestAuthSessionFlows_NewCookieUsesCurrentSecretAfterRotation(t *testing.T) {
	db := openDB(t)
	migrate(t, db)

	adapter, srv := newTestAdapter(t)
	mustBetterAuth(t, auth.Options{
		Secret:  "test-secret-v2",
		Secrets: []auth.Secret{{Version: 2, Value: "test-secret-v2"}, {Version: 1, Value: "test-secret-v1"}},
		Adapter: adapter,
		DB:      authbun.New(db, authbun.Config{}),
		Session: auth.SessionOptions{ExpiresIn: 3600, UpdateAge: intPtr(1)},
		EmailAndPassword: auth.EmailAndPasswordOptions{
			Enabled: true,
		},
	})

	resp, cookie := signUp(t, srv.URL, "rotation-current@example.com")
	resp.Body.Close()

	signed := extractCookieHeaderValue(t, cookie)
	if _, ok := auth.VerifyCookie("test-secret-v2", signed); !ok {
		t.Fatal("newly issued cookie must verify with the current secret")
	}
	if _, ok := auth.VerifyCookie("test-secret-v1", signed); ok {
		t.Fatal("newly issued cookie must not verify with the retained old secret")
	}
}

func TestAuthPasswordResetToken_WorksAcrossSecretRotation(t *testing.T) {
	db := openDB(t)
	migrate(t, db)

	var resetToken string

	oldAdapter, oldSrv := newTestAdapter(t)
	mustBetterAuth(t, auth.Options{
		Secret:  "test-secret-v1",
		Adapter: oldAdapter,
		DB:      authbun.New(db, authbun.Config{}),
		Session: auth.SessionOptions{ExpiresIn: 3600, UpdateAge: intPtr(1)},
		EmailAndPassword: auth.EmailAndPasswordOptions{
			Enabled: true,
			SendResetPassword: func(data auth.ResetPasswordData) error {
				resetToken = data.Token
				return nil
			},
		},
	})

	resp, _ := signUp(t, oldSrv.URL, "rotation-reset@example.com")
	resp.Body.Close()

	resetReqBody := strings.NewReader(`{"email":"rotation-reset@example.com"}`)
	resetReqResp, err := http.Post(oldSrv.URL+"/api/auth/request-password-reset", "application/json", resetReqBody)
	if err != nil {
		t.Fatalf("request-password-reset failed: %v", err)
	}
	resetReqResp.Body.Close()
	if resetToken == "" {
		t.Fatal("expected password reset token to be issued")
	}

	rotatedAdapter, rotatedSrv := newTestAdapter(t)
	mustBetterAuth(t, auth.Options{
		Secret:  "test-secret-v2",
		Secrets: []auth.Secret{{Version: 2, Value: "test-secret-v2"}, {Version: 1, Value: "test-secret-v1"}},
		Adapter: rotatedAdapter,
		DB:      authbun.New(db, authbun.Config{}),
		Session: auth.SessionOptions{ExpiresIn: 3600, UpdateAge: intPtr(1)},
		EmailAndPassword: auth.EmailAndPasswordOptions{
			Enabled: true,
		},
	})

	resetBody := strings.NewReader(`{"token":"` + resetToken + `","newPassword":"password456"}`)
	resetResp, err := http.Post(rotatedSrv.URL+"/api/auth/reset-password", "application/json", resetBody)
	if err != nil {
		t.Fatalf("reset-password failed: %v", err)
	}
	defer resetResp.Body.Close()
	if resetResp.StatusCode != http.StatusOK {
		t.Fatalf("expected reset-password to succeed after rotation, got %d", resetResp.StatusCode)
	}

	signInBody := strings.NewReader(`{"email":"rotation-reset@example.com","password":"password456"}`)
	signInResp, err := http.Post(rotatedSrv.URL+"/api/auth/sign-in/email", "application/json", signInBody)
	if err != nil {
		t.Fatalf("sign-in after reset failed: %v", err)
	}
	defer signInResp.Body.Close()
	if signInResp.StatusCode != http.StatusOK {
		t.Fatalf("expected sign-in with reset password to succeed, got %d", signInResp.StatusCode)
	}
}

func TestAuthSessionFlows_ListRevokeUpdateDelete(t *testing.T) {
	srv, db := newIntegrationAuthWithOptions(t, auth.Options{
		Session:          auth.SessionOptions{ExpiresIn: 3600, UpdateAge: intPtr(1)},
		EmailAndPassword: auth.EmailAndPasswordOptions{Enabled: true},
		User:             auth.UserOptions{DeleteUser: auth.DeleteUserOptions{Enabled: true}},
	})
	resp, cookie := signUp(t, srv.URL, "account@example.com")
	resp.Body.Close()

	signInBody := strings.NewReader(`{"email":"account@example.com","password":"password123"}`)
	signInResp, err := http.Post(srv.URL+"/api/auth/sign-in/email", "application/json", signInBody)
	if err != nil {
		t.Fatalf("sign-in request failed: %v", err)
	}
	secondCookie := signInResp.Header.Get("Set-Cookie")
	signInResp.Body.Close()
	if secondCookie == "" {
		t.Fatalf("expected second session cookie")
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/auth/list-sessions", nil)
	req.Header.Set("Cookie", cookie)
	listResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("list-sessions failed: %v", err)
	}
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list-sessions expected 200, got %d", listResp.StatusCode)
	}
	listResp.Body.Close()

	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/api/auth/list-accounts", nil)
	req.Header.Set("Cookie", cookie)
	accountsResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("list-accounts failed: %v", err)
	}
	if accountsResp.StatusCode != http.StatusOK {
		t.Fatalf("list-accounts expected 200, got %d", accountsResp.StatusCode)
	}
	accountsResp.Body.Close()

	revokeReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/auth/revoke-session", strings.NewReader(`{"token":"`+extractSignedCookieValue(t, secondCookie)+`"}`))
	revokeReq.Header.Set("Content-Type", "application/json")
	revokeReq.Header.Set("Cookie", cookie)
	revokeResp, err := http.DefaultClient.Do(revokeReq)
	if err != nil {
		t.Fatalf("revoke-session failed: %v", err)
	}
	if revokeResp.StatusCode != http.StatusOK {
		t.Fatalf("revoke-session expected 200, got %d", revokeResp.StatusCode)
	}
	revokeResp.Body.Close()

	row, err := db.FindOne(context.Background(), "session", []auth.Where{{Field: "token", Value: extractSignedCookieValue(t, secondCookie)}}, nil)
	if err != nil {
		t.Fatalf("find revoked session: %v", err)
	}
	if row != nil {
		t.Fatalf("expected revoked session to be deleted")
	}

	updateReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/auth/update-user", strings.NewReader(`{"name":"Updated Name","image":"https://example.com/u.png"}`))
	updateReq.Header.Set("Content-Type", "application/json")
	updateReq.Header.Set("Cookie", cookie)
	updateResp, err := http.DefaultClient.Do(updateReq)
	if err != nil {
		t.Fatalf("update-user failed: %v", err)
	}
	if updateResp.StatusCode != http.StatusOK {
		t.Fatalf("update-user expected 200, got %d", updateResp.StatusCode)
	}
	updateResp.Body.Close()

	currentSessionResp := getSession(t, srv.URL, cookie)
	defer currentSessionResp.Body.Close()
	var sessionPayload struct {
		User struct {
			Name  string  `json:"name"`
			Image *string `json:"image"`
		} `json:"user"`
	}
	if err := json.NewDecoder(currentSessionResp.Body).Decode(&sessionPayload); err != nil {
		t.Fatalf("decode session payload: %v", err)
	}
	if sessionPayload.User.Name != "Updated Name" {
		t.Fatalf("expected updated name, got %q", sessionPayload.User.Name)
	}
	if sessionPayload.User.Image == nil || *sessionPayload.User.Image != "https://example.com/u.png" {
		t.Fatalf("expected updated image")
	}

	deleteReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/auth/delete-user", strings.NewReader(`{}`))
	deleteReq.Header.Set("Content-Type", "application/json")
	deleteReq.Header.Set("Cookie", cookie)
	deleteResp, err := http.DefaultClient.Do(deleteReq)
	if err != nil {
		t.Fatalf("delete-user failed: %v", err)
	}
	if deleteResp.StatusCode != http.StatusOK {
		t.Fatalf("delete-user expected 200, got %d", deleteResp.StatusCode)
	}
	deleteResp.Body.Close()

	users, _ := db.Count(context.Background(), "user", nil)
	sessions, _ := db.Count(context.Background(), "session", nil)
	accounts, _ := db.Count(context.Background(), "account", nil)
	if users != 0 || sessions != 0 || accounts != 0 {
		t.Fatalf("expected user/session/account rows deleted, got users=%d sessions=%d accounts=%d", users, sessions, accounts)
	}
}

func TestAuthRateLimit_SignInUsesSpecialRule(t *testing.T) {
	db := openDB(t)
	migrate(t, db)
	adapter, srv := newTestAdapter(t)
	mustBetterAuth(t, auth.Options{
		Secret:  "test-secret",
		Adapter: adapter,
		DB:      authbun.New(db, authbun.Config{}),
		Session: auth.SessionOptions{ExpiresIn: 3600, UpdateAge: intPtr(1)},
		EmailAndPassword: auth.EmailAndPasswordOptions{
			Enabled: true,
		},
		RateLimit: auth.RateLimitOptions{
			Enabled: boolPtr(true),
			Window:  60,
			Max:     20,
		},
	})

	resp, _ := signUp(t, srv.URL, "rate-limit-sign-in@example.com")
	resp.Body.Close()

	for i := 0; i < 4; i++ {
		body := strings.NewReader(`{"email":"rate-limit-sign-in@example.com","password":"password123"}`)
		resp, err := http.Post(srv.URL+"/api/auth/sign-in/email", "application/json", body)
		if err != nil {
			t.Fatalf("sign-in request failed: %v", err)
		}
		resp.Body.Close()

		if i < 3 && resp.StatusCode != http.StatusOK {
			t.Fatalf("attempt %d: expected 200, got %d", i+1, resp.StatusCode)
		}
		if i == 3 {
			if resp.StatusCode != http.StatusTooManyRequests {
				t.Fatalf("attempt %d: expected 429, got %d", i+1, resp.StatusCode)
			}
			if resp.Header.Get("X-Retry-After") == "" {
				t.Fatalf("attempt %d: expected X-Retry-After header", i+1)
			}
		}
	}
}

func TestAuthRateLimit_CustomRuleCanDisablePath(t *testing.T) {
	db := openDB(t)
	migrate(t, db)
	adapter, srv := newTestAdapter(t)
	mustBetterAuth(t, auth.Options{
		Secret:  "test-secret",
		Adapter: adapter,
		DB:      authbun.New(db, authbun.Config{}),
		Session: auth.SessionOptions{ExpiresIn: 3600, UpdateAge: intPtr(1)},
		EmailAndPassword: auth.EmailAndPasswordOptions{
			Enabled: true,
		},
		RateLimit: auth.RateLimitOptions{
			Enabled: boolPtr(true),
			Window:  60,
			Max:     1,
			CustomRules: map[string]auth.RateLimitRule{
				"/get-session": {Disabled: true},
			},
		},
	})

	resp, cookie := signUp(t, srv.URL, "rate-limit-session@example.com")
	resp.Body.Close()

	for i := 0; i < 5; i++ {
		sessionResp := getSession(t, srv.URL, cookie)
		sessionResp.Body.Close()
		if sessionResp.StatusCode != http.StatusOK {
			t.Fatalf("attempt %d: expected 200, got %d", i+1, sessionResp.StatusCode)
		}
	}
}

func TestDeleteUser_DisabledByUserOptions(t *testing.T) {
	srv, db := newIntegrationAuthWithOptions(t, auth.Options{
		Session: auth.SessionOptions{ExpiresIn: 3600, UpdateAge: intPtr(1)},
		User: auth.UserOptions{
			DeleteUser: auth.DeleteUserOptions{
				Enabled: false,
			},
		},
	})

	resp, cookie := signUp(t, srv.URL, "delete-disabled@example.com")
	resp.Body.Close()

	deleteReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/auth/delete-user", strings.NewReader(`{}`))
	deleteReq.Header.Set("Content-Type", "application/json")
	deleteReq.Header.Set("Cookie", cookie)
	deleteResp, err := http.DefaultClient.Do(deleteReq)
	if err != nil {
		t.Fatalf("delete-user failed: %v", err)
	}
	defer deleteResp.Body.Close()
	if deleteResp.StatusCode != http.StatusNotFound {
		t.Fatalf("delete-user expected 404 when disabled, got %d", deleteResp.StatusCode)
	}

	users, _ := db.Count(context.Background(), "user", nil)
	if users != 1 {
		t.Fatalf("expected user to remain when delete-user disabled, got users=%d", users)
	}
}

func TestDeleteUser_VerificationFlow(t *testing.T) {
	var sent auth.DeleteAccountVerificationData
	srv, db := newIntegrationAuthWithOptions(t, auth.Options{
		Session: auth.SessionOptions{ExpiresIn: 3600, UpdateAge: intPtr(1)},
		User: auth.UserOptions{
			DeleteUser: auth.DeleteUserOptions{
				Enabled: true,
				SendDeleteAccountVerification: func(data auth.DeleteAccountVerificationData) error {
					sent = data
					return nil
				},
			},
		},
	})

	resp, cookie := signUp(t, srv.URL, "delete-verify@example.com")
	resp.Body.Close()

	deleteReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/auth/delete-user", strings.NewReader(`{}`))
	deleteReq.Header.Set("Content-Type", "application/json")
	deleteReq.Header.Set("Cookie", cookie)
	deleteResp, err := http.DefaultClient.Do(deleteReq)
	if err != nil {
		t.Fatalf("delete-user failed: %v", err)
	}
	defer deleteResp.Body.Close()
	if deleteResp.StatusCode != http.StatusOK {
		t.Fatalf("delete-user expected 200, got %d", deleteResp.StatusCode)
	}
	if sent.Token == "" {
		t.Fatal("expected delete verification token to be sent")
	}

	users, _ := db.Count(context.Background(), "user", nil)
	if users != 1 {
		t.Fatalf("expected user to remain until verification, got users=%d", users)
	}

	verifyReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/auth/delete-user", strings.NewReader(`{"token":"`+sent.Token+`"}`))
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyReq.Header.Set("Cookie", cookie)
	verifyResp, err := http.DefaultClient.Do(verifyReq)
	if err != nil {
		t.Fatalf("delete-user token confirmation failed: %v", err)
	}
	defer verifyResp.Body.Close()
	if verifyResp.StatusCode != http.StatusOK {
		t.Fatalf("delete-user token confirmation expected 200, got %d", verifyResp.StatusCode)
	}

	users, _ = db.Count(context.Background(), "user", nil)
	sessions, _ := db.Count(context.Background(), "session", nil)
	accounts, _ := db.Count(context.Background(), "account", nil)
	verifications, _ := db.Count(context.Background(), "verification", nil)
	if users != 0 || sessions != 0 || accounts != 0 || verifications != 0 {
		t.Fatalf("expected all user data deleted after confirmation, got users=%d sessions=%d accounts=%d verifications=%d", users, sessions, accounts, verifications)
	}
}

func TestDeleteUser_RequiresFreshSessionWithoutPassword(t *testing.T) {
	srv, db := newIntegrationAuthWithOptions(t, auth.Options{
		Session: auth.SessionOptions{ExpiresIn: 3600, UpdateAge: intPtr(1), FreshAge: intPtr(1)},
		User: auth.UserOptions{
			DeleteUser: auth.DeleteUserOptions{
				Enabled: true,
			},
		},
	})

	resp, cookie := signUp(t, srv.URL, "delete-stale@example.com")
	resp.Body.Close()

	sessionRow, err := db.FindOne(context.Background(), "session", []auth.Where{
		{Field: "token", Value: extractSignedCookieValue(t, cookie)},
	}, nil)
	if err != nil || sessionRow == nil {
		t.Fatalf("expected session row, got err=%v", err)
	}
	sessionID, _ := sessionRow["id"].(string)
	if _, err := db.Update(context.Background(), "session", []auth.Where{
		{Field: "id", Value: sessionID},
	}, map[string]any{
		"createdAt": time.Now().UTC().Add(-5 * time.Second),
	}); err != nil {
		t.Fatalf("update session createdAt: %v", err)
	}

	deleteReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/auth/delete-user", strings.NewReader(`{}`))
	deleteReq.Header.Set("Content-Type", "application/json")
	deleteReq.Header.Set("Cookie", cookie)
	deleteResp, err := http.DefaultClient.Do(deleteReq)
	if err != nil {
		t.Fatalf("delete-user failed: %v", err)
	}
	defer deleteResp.Body.Close()
	if deleteResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("delete-user expected 400 for stale session, got %d", deleteResp.StatusCode)
	}
}

func TestChangeEmail_UpdateWithoutVerification(t *testing.T) {
	var sent auth.VerificationEmailData
	srv, _ := newIntegrationAuthWithOptions(t, auth.Options{
		Session: auth.SessionOptions{ExpiresIn: 3600, UpdateAge: intPtr(1)},
		EmailVerification: auth.EmailVerificationOptions{
			SendVerificationEmail: func(data auth.VerificationEmailData) error {
				sent = data
				return nil
			},
		},
		User: auth.UserOptions{
			ChangeEmail: auth.ChangeEmailOptions{
				Enabled:                        true,
				UpdateEmailWithoutVerification: true,
			},
		},
	})

	resp, cookie := signUp(t, srv.URL, "change-email@example.com")
	resp.Body.Close()

	changeReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/auth/change-email", strings.NewReader(`{"newEmail":"new-change-email@example.com"}`))
	changeReq.Header.Set("Content-Type", "application/json")
	changeReq.Header.Set("Cookie", cookie)
	changeResp, err := http.DefaultClient.Do(changeReq)
	if err != nil {
		t.Fatalf("change-email failed: %v", err)
	}
	defer changeResp.Body.Close()
	if changeResp.StatusCode != http.StatusOK {
		t.Fatalf("change-email expected 200, got %d", changeResp.StatusCode)
	}
	if sent.Token == "" {
		t.Fatal("expected verification email to be sent to new email")
	}
	if sent.User == nil || sent.User.Email != "new-change-email@example.com" {
		t.Fatalf("expected verification email to target updated email, got %+v", sent.User)
	}

	sessionResp := getSession(t, srv.URL, cookie)
	defer sessionResp.Body.Close()
	if sessionResp.StatusCode != http.StatusOK {
		t.Fatalf("get-session expected 200, got %d", sessionResp.StatusCode)
	}
	var payload struct {
		User struct {
			Email         string `json:"email"`
			EmailVerified bool   `json:"emailVerified"`
		} `json:"user"`
	}
	if err := json.NewDecoder(sessionResp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode session payload: %v", err)
	}
	if payload.User.Email != "new-change-email@example.com" {
		t.Fatalf("expected session email to update immediately, got %q", payload.User.Email)
	}
	if payload.User.EmailVerified {
		t.Fatal("expected user to remain unverified until verification")
	}
}

func TestEmailPassword_AutoSignInDisabledReturnsNullTokenWithoutCookie(t *testing.T) {
	srv, _ := newMemoryAuthServer(t, auth.Options{
		Session: auth.SessionOptions{ExpiresIn: 3600, UpdateAge: intPtr(1)},
		EmailAndPassword: auth.EmailAndPasswordOptions{
			Enabled:    true,
			AutoSignIn: boolPtr(false),
		},
	})

	resp, err := http.Post(srv.URL+"/api/auth/sign-up/email", "application/json", strings.NewReader(`{"name":"No Session","email":"nosession@example.com","password":"password123"}`))
	if err != nil {
		t.Fatalf("sign-up request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Set-Cookie"); got != "" {
		t.Fatalf("expected no session cookie, got %q", got)
	}

	var body struct {
		Token *string `json:"token"`
		User  struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	decodeJSON(t, resp, &body)
	if body.Token != nil {
		t.Fatalf("expected null token, got %q", *body.Token)
	}
	if body.User.Email != "nosession@example.com" {
		t.Fatalf("unexpected user email %q", body.User.Email)
	}
}

func TestEmailPassword_DuplicateSignUpReturnsSyntheticUserAndCallsOnExistingUserSignUp(t *testing.T) {
	var callbackEmails []string
	srv, _ := newMemoryAuthServer(t, auth.Options{
		Session: auth.SessionOptions{ExpiresIn: 3600, UpdateAge: intPtr(1)},
		EmailAndPassword: auth.EmailAndPasswordOptions{
			Enabled:                  true,
			RequireEmailVerification: true,
			OnExistingUserSignUp: func(data auth.ExistingUserSignUpData) error {
				callbackEmails = append(callbackEmails, data.User.Email)
				return nil
			},
			CustomSyntheticUser: func(data auth.SyntheticUserData) map[string]any {
				return map[string]any{
					"id":            data.ID,
					"email":         data.CoreFields.Email,
					"emailVerified": false,
					"name":          "Synthetic " + data.CoreFields.Name,
					"createdAt":     data.CoreFields.CreatedAt,
					"updatedAt":     data.CoreFields.UpdatedAt,
				}
			},
		},
	})

	firstResp, err := http.Post(srv.URL+"/api/auth/sign-up/email", "application/json", strings.NewReader(`{"name":"Original","email":"duplicate@example.com","password":"password123"}`))
	if err != nil {
		t.Fatalf("first sign-up failed: %v", err)
	}
	firstResp.Body.Close()

	secondResp, err := http.Post(srv.URL+"/api/auth/sign-up/email", "application/json", strings.NewReader(`{"name":"Duplicate","email":"duplicate@example.com","password":"password456"}`))
	if err != nil {
		t.Fatalf("second sign-up failed: %v", err)
	}
	defer secondResp.Body.Close()

	if secondResp.StatusCode != http.StatusOK {
		t.Fatalf("expected synthetic success response, got %d", secondResp.StatusCode)
	}

	var body struct {
		Token *string `json:"token"`
		User  struct {
			Email string `json:"email"`
			Name  string `json:"name"`
		} `json:"user"`
	}
	decodeJSON(t, secondResp, &body)
	if body.Token != nil {
		t.Fatalf("expected null token, got %q", *body.Token)
	}
	if body.User.Email != "duplicate@example.com" {
		t.Fatalf("unexpected synthetic email %q", body.User.Email)
	}
	if body.User.Name != "Synthetic Duplicate" {
		t.Fatalf("unexpected synthetic user name %q", body.User.Name)
	}
	if len(callbackEmails) != 1 || callbackEmails[0] != "duplicate@example.com" {
		t.Fatalf("expected callback with existing user email once, got %#v", callbackEmails)
	}
}

func TestEmailPassword_ResetPasswordHonorsCallbackAndSessionRevocationOptions(t *testing.T) {
	var resetToken string
	var resetEmails []string
	srv, _ := newMemoryAuthServer(t, auth.Options{
		Session: auth.SessionOptions{ExpiresIn: 3600, UpdateAge: intPtr(1)},
		EmailAndPassword: auth.EmailAndPasswordOptions{
			Enabled: true,
			SendResetPassword: func(data auth.ResetPasswordData) error {
				resetToken = data.Token
				return nil
			},
			OnPasswordReset: func(data auth.PasswordResetData) error {
				resetEmails = append(resetEmails, data.User.Email)
				return nil
			},
		},
	})

	signUpResp, cookie := signUp(t, srv.URL, "reset-default@example.com")
	signUpResp.Body.Close()

	requestResp, err := http.Post(srv.URL+"/api/auth/request-password-reset", "application/json", strings.NewReader(`{"email":"reset-default@example.com"}`))
	if err != nil {
		t.Fatalf("request-password-reset failed: %v", err)
	}
	requestResp.Body.Close()

	resetResp, err := http.Post(srv.URL+"/api/auth/reset-password", "application/json", strings.NewReader(`{"token":"`+resetToken+`","newPassword":"new-password123"}`))
	if err != nil {
		t.Fatalf("reset-password failed: %v", err)
	}
	resetResp.Body.Close()

	if len(resetEmails) != 1 || resetEmails[0] != "reset-default@example.com" {
		t.Fatalf("expected onPasswordReset callback once, got %#v", resetEmails)
	}

	sessionResp := getSession(t, srv.URL, cookie)
	defer sessionResp.Body.Close()
	if sessionResp.StatusCode != http.StatusOK {
		t.Fatalf("expected existing session to survive by default, got %d", sessionResp.StatusCode)
	}
}

func TestEmailPassword_RevokeSessionsOnPasswordResetDeletesExistingSessions(t *testing.T) {
	var resetToken string
	srv, _ := newMemoryAuthServer(t, auth.Options{
		Session: auth.SessionOptions{ExpiresIn: 3600, UpdateAge: intPtr(1)},
		EmailAndPassword: auth.EmailAndPasswordOptions{
			Enabled:                       true,
			RevokeSessionsOnPasswordReset: true,
			SendResetPassword: func(data auth.ResetPasswordData) error {
				resetToken = data.Token
				return nil
			},
		},
	})

	signUpResp, cookie := signUp(t, srv.URL, "reset-revoke@example.com")
	signUpResp.Body.Close()

	requestResp, err := http.Post(srv.URL+"/api/auth/request-password-reset", "application/json", strings.NewReader(`{"email":"reset-revoke@example.com"}`))
	if err != nil {
		t.Fatalf("request-password-reset failed: %v", err)
	}
	requestResp.Body.Close()

	resetResp, err := http.Post(srv.URL+"/api/auth/reset-password", "application/json", strings.NewReader(`{"token":"`+resetToken+`","newPassword":"new-password123"}`))
	if err != nil {
		t.Fatalf("reset-password failed: %v", err)
	}
	resetResp.Body.Close()

	sessionResp := getSession(t, srv.URL, cookie)
	var revokedBody map[string]any
	decodeJSON(t, sessionResp, &revokedBody)
	defer sessionResp.Body.Close()
	if sessionResp.StatusCode != http.StatusOK {
		t.Fatalf("expected revoked session to read 200 null, got %d", sessionResp.StatusCode)
	}
	if revokedBody["session"] != nil || revokedBody["user"] != nil {
		t.Fatalf("expected revoked session to be null, got %v", revokedBody)
	}
}

func TestEmailPassword_PasswordOverridesAreUsedAcrossSignUpSignInAndReset(t *testing.T) {
	var resetToken string
	srv, db := newMemoryAuthServer(t, auth.Options{
		Session: auth.SessionOptions{ExpiresIn: 3600, UpdateAge: intPtr(1)},
		EmailAndPassword: auth.EmailAndPasswordOptions{
			Enabled: true,
			Password: auth.PasswordOptions{
				Hash: func(password string) (string, error) {
					return "custom:" + password, nil
				},
				Verify: func(data auth.PasswordVerifyData) (bool, error) {
					return data.Hash == "custom:"+data.Password, nil
				},
			},
			SendResetPassword: func(data auth.ResetPasswordData) error {
				resetToken = data.Token
				return nil
			},
		},
	})

	signUpResp, _ := signUp(t, srv.URL, "override@example.com")
	signUpResp.Body.Close()

	accountRow := findCredentialAccountByEmail(t, db, "override@example.com")
	if got, _ := accountRow["password"].(string); got != "custom:password123" {
		t.Fatalf("expected custom hashed password, got %q", got)
	}

	signInResp, err := http.Post(srv.URL+"/api/auth/sign-in/email", "application/json", strings.NewReader(`{"email":"override@example.com","password":"password123"}`))
	if err != nil {
		t.Fatalf("sign-in request failed: %v", err)
	}
	signInResp.Body.Close()
	if signInResp.StatusCode != http.StatusOK {
		t.Fatalf("expected sign-in success with custom verifier, got %d", signInResp.StatusCode)
	}

	requestResp, err := http.Post(srv.URL+"/api/auth/request-password-reset", "application/json", strings.NewReader(`{"email":"override@example.com"}`))
	if err != nil {
		t.Fatalf("request-password-reset failed: %v", err)
	}
	requestResp.Body.Close()

	resetResp, err := http.Post(srv.URL+"/api/auth/reset-password", "application/json", strings.NewReader(`{"token":"`+resetToken+`","newPassword":"new-password123"}`))
	if err != nil {
		t.Fatalf("reset-password failed: %v", err)
	}
	resetResp.Body.Close()

	updatedAccountRow := findCredentialAccountByEmail(t, db, "override@example.com")
	if got, _ := updatedAccountRow["password"].(string); got != "custom:new-password123" {
		t.Fatalf("expected custom hashed reset password, got %q", got)
	}
}

func TestEmailPassword_CustomVerifierIsUsedForChangePasswordAndDeleteUser(t *testing.T) {
	verifyCalls := 0
	srv, _ := newMemoryAuthServer(t, auth.Options{
		Session: auth.SessionOptions{ExpiresIn: 3600, UpdateAge: intPtr(1)},
		EmailAndPassword: auth.EmailAndPasswordOptions{
			Enabled: true,
			Password: auth.PasswordOptions{
				Hash: func(password string) (string, error) {
					return "custom:" + password, nil
				},
				Verify: func(data auth.PasswordVerifyData) (bool, error) {
					verifyCalls++
					return data.Hash == "custom:"+data.Password, nil
				},
			},
		},
		User: auth.UserOptions{DeleteUser: auth.DeleteUserOptions{Enabled: true}},
	})

	signUpResp, cookie := signUp(t, srv.URL, "override-sensitive@example.com")
	signUpResp.Body.Close()

	changeReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/auth/change-password", strings.NewReader(`{"currentPassword":"password123","newPassword":"new-password123"}`))
	changeReq.Header.Set("Content-Type", "application/json")
	changeReq.Header.Set("Cookie", cookie)
	changeResp, err := http.DefaultClient.Do(changeReq)
	if err != nil {
		t.Fatalf("change-password request failed: %v", err)
	}
	changeResp.Body.Close()
	if changeResp.StatusCode != http.StatusOK {
		t.Fatalf("change-password expected 200, got %d", changeResp.StatusCode)
	}

	deleteReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/auth/delete-user", strings.NewReader(`{"password":"new-password123"}`))
	deleteReq.Header.Set("Content-Type", "application/json")
	deleteReq.Header.Set("Cookie", cookie)
	deleteResp, err := http.DefaultClient.Do(deleteReq)
	if err != nil {
		t.Fatalf("delete-user request failed: %v", err)
	}
	deleteResp.Body.Close()
	if deleteResp.StatusCode != http.StatusOK {
		t.Fatalf("delete-user expected 200, got %d", deleteResp.StatusCode)
	}
	if verifyCalls != 2 {
		t.Fatalf("custom verifier called %d times, want 2", verifyCalls)
	}
}

func TestSignOut_AdvancedCookieOptionsApplied(t *testing.T) {
	adapter, srv := newTestAdapter(t)
	mustBetterAuth(t, auth.Options{
		Secret:  "test-secret",
		Adapter: adapter,
		BaseURL: "https://example.com",
		Advanced: auth.AdvancedOptions{
			UseSecureCookies: boolPtr(true),
			CookiePrefix:     "test-prefix",
			CrossSubDomainCookies: auth.CrossSubDomainCookiesOptions{
				Enabled: true,
			},
			DefaultCookieAttributes: auth.CookieAttributes{
				SameSite: http.SameSiteStrictMode,
			},
		},
	})

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/auth/sign-out", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "better-auth.session_token=garbage-token")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("sign-out request failed: %v", err)
	}
	resp.Body.Close()

	setCookie := resp.Header.Get("Set-Cookie")
	if !strings.Contains(setCookie, "__Secure-test-prefix.session_token=") {
		t.Fatalf("expected secure prefixed cookie name, got %q", setCookie)
	}
	if !strings.Contains(setCookie, "Domain=example.com") {
		t.Fatalf("expected cross-subdomain domain from baseURL, got %q", setCookie)
	}
	if !strings.Contains(setCookie, "SameSite=Strict") {
		t.Fatalf("expected default cookie attributes to override SameSite, got %q", setCookie)
	}
	if !strings.Contains(setCookie, "Secure") {
		t.Fatalf("expected secure cookies, got %q", setCookie)
	}
}

func TestSignOut_CrossSubDomainCookieUsesTrustedProxyHost(t *testing.T) {
	adapter, srv := newTestAdapter(t)
	mustBetterAuth(t, auth.Options{
		Secret:  "test-secret",
		Adapter: adapter,
		BaseURL: "https://fallback.example.com",
		Advanced: auth.AdvancedOptions{
			TrustedProxyHeaders: boolPtr(true),
			CrossSubDomainCookies: auth.CrossSubDomainCookiesOptions{
				Enabled: true,
			},
		},
	})

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/auth/sign-out", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-Host", "auth.proxy.example.com")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Cookie", "better-auth.session_token=garbage-token")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("sign-out request failed: %v", err)
	}
	defer resp.Body.Close()

	setCookie := resp.Header.Get("Set-Cookie")
	if !strings.Contains(setCookie, "Domain=auth.proxy.example.com") {
		t.Fatalf("expected cookie domain to use trusted proxy host, got %q", setCookie)
	}
}

func extractSignedCookieValue(t *testing.T, setCookie string) string {
	t.Helper()
	signed := extractCookieHeaderValue(t, setCookie)
	value, ok := auth.VerifyCookie("test-secret", signed)
	if !ok {
		t.Fatalf("invalid signed cookie")
	}
	return value
}

func extractCookieHeaderValue(t *testing.T, setCookie string) string {
	t.Helper()
	parts := strings.Split(setCookie, ";")
	if len(parts) == 0 {
		t.Fatalf("invalid set-cookie header")
	}
	nameValue := strings.SplitN(parts[0], "=", 2)
	if len(nameValue) != 2 {
		t.Fatalf("invalid cookie pair")
	}
	return nameValue[1]
}

func verifySignedCookieValue(t *testing.T, cookieValue string) string {
	t.Helper()
	value, ok := auth.VerifyCookie("test-secret", cookieValue)
	if !ok {
		t.Fatalf("invalid signed cookie")
	}
	return value
}

func cookieHeaderFromSetCookies(setCookies []string) string {
	pairs := make([]string, 0, len(setCookies))
	for _, setCookie := range setCookies {
		part := strings.SplitN(setCookie, ";", 2)[0]
		if part != "" {
			pairs = append(pairs, part)
		}
	}
	return strings.Join(pairs, "; ")
}

func extractCookieValue(t *testing.T, cookieHeader, name string) string {
	t.Helper()
	req := &http.Request{Header: http.Header{"Cookie": []string{cookieHeader}}}
	cookie, err := req.Cookie(name)
	if err != nil {
		t.Fatalf("cookie %q not found: %v", name, err)
	}
	return cookie.Value
}

func TestDeleteUser_RequiresFreshSessionWhenPasswordOmitted(t *testing.T) {
	srv, db := newMemoryAuthServer(t, auth.Options{Session: auth.SessionOptions{ExpiresIn: 3600, UpdateAge: intPtr(1), FreshAge: intPtr(1)}, EmailAndPassword: auth.EmailAndPasswordOptions{Enabled: true}, User: auth.UserOptions{DeleteUser: auth.DeleteUserOptions{Enabled: true}}})
	resp, cookieHeader := signUp(t, srv.URL, "stale-delete@example.com")
	resp.Body.Close()

	token := verifySignedCookieValue(t, extractCookieValue(t, cookieHeader, "better-auth.session_token"))
	updated, err := db.Update(context.Background(), "session", []auth.Where{
		{Field: "token", Value: token},
	}, map[string]any{
		"createdAt": time.Now().UTC().Add(-5 * time.Second),
		"updatedAt": time.Now().UTC(),
	})
	if err != nil || updated == nil {
		t.Fatalf("aging session: %v", err)
	}

	deleteReq, err := http.NewRequest(http.MethodPost, srv.URL+"/api/auth/delete-user", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("new delete-user request: %v", err)
	}
	deleteReq.Header.Set("Content-Type", "application/json")
	deleteReq.Header.Set("Cookie", cookieHeader)
	deleteResp, err := http.DefaultClient.Do(deleteReq)
	if err != nil {
		t.Fatalf("delete-user failed: %v", err)
	}
	defer deleteResp.Body.Close()
	if deleteResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", deleteResp.StatusCode)
	}

	var body map[string]any
	if err := json.NewDecoder(deleteResp.Body).Decode(&body); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if detail, _ := body["detail"].(string); detail != auth.ErrSessionExpired {
		t.Fatalf("expected detail %q, got %#v", auth.ErrSessionExpired, body)
	}
}

func TestSessionCookieCache_AllowsGetSessionWithoutDatabaseRow(t *testing.T) {
	srv, db := newMemoryAuthServer(t, auth.Options{
		Session: auth.SessionOptions{
			ExpiresIn: 3600,
			UpdateAge: intPtr(1),
			CookieCache: auth.SessionCookieCacheOptions{
				Enabled: true,
				MaxAge:  300,
			},
		},
		EmailAndPassword: auth.EmailAndPasswordOptions{Enabled: true},
	})
	resp, cookieHeader := signUp(t, srv.URL, "cookie-cache@example.com")
	resp.Body.Close()

	if got := extractCookieValue(t, cookieHeader, "auth_session_data"); got == "" {
		t.Fatal("expected auth_session_data cookie")
	}

	token := verifySignedCookieValue(t, extractCookieValue(t, cookieHeader, "better-auth.session_token"))
	if err := db.Delete(context.Background(), "session", []auth.Where{
		{Field: "token", Value: token},
	}); err != nil {
		t.Fatalf("delete session row: %v", err)
	}

	sessionResp := getSession(t, srv.URL, cookieHeader)
	defer sessionResp.Body.Close()
	if sessionResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", sessionResp.StatusCode)
	}

	var payload struct {
		User struct {
			Email string `json:"email"`
		} `json:"user"`
		Session struct {
			Token string `json:"token"`
		} `json:"session"`
	}
	if err := json.NewDecoder(sessionResp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode session payload: %v", err)
	}
	if payload.User.Email != "cookie-cache@example.com" {
		t.Fatalf("expected cached user email, got %q", payload.User.Email)
	}
	if payload.Session.Token != token {
		t.Fatalf("expected cached session token %q, got %q", token, payload.Session.Token)
	}
}

func TestNew_RejectsUnsupportedSecondaryStorageSessionFlags(t *testing.T) {
	api := newTestAPI(t)

	assertErr := func(name string, session auth.SessionOptions) {
		t.Helper()
		_, err := auth.BetterAuth(auth.Options{
			Secret:  "test-secret",
			Adapter: api.Adapter(),
			Session: session,
		})
		if err == nil {
			t.Fatalf("%s: expected error", name)
		}
		if !strings.Contains(err.Error(), "secondary storage") {
			t.Fatalf("%s: unexpected error %q", name, err.Error())
		}
	}

	assertErr("storeSessionInDatabase", auth.SessionOptions{StoreSessionInDatabase: true})
	assertErr("preserveSessionInDatabase", auth.SessionOptions{PreserveSessionInDatabase: true})
}


// testPlugin implements auth.Plugin for testing the plugin contract.
type testPlugin struct {
	initCalled bool
	hooks      auth.DBHooks
}

func (p *testPlugin) ID() string { return "test-plugin" }

func (p *testPlugin) Init(_ auth.AuthContext) error {
	p.initCalled = true
	return nil
}

func (p *testPlugin) Endpoints() []auth.Endpoint {
	return []auth.Endpoint{
		{
			Method:      http.MethodGet,
			Path:        "/test-plugin-ping",
			OperationID: "testPluginPing",
			Summary:     "Test plugin ping endpoint",
			Register: func(api any, basePath string, _ auth.Options) {
				humaAPI := api.(huma.API)
				type pingOutput struct {
					Body struct {
						Pong bool `json:"pong"`
					}
				}
				huma.Register(humaAPI, huma.Operation{
					Method:      http.MethodGet,
					Path:        basePath + "/test-plugin-ping",
					OperationID: "testPluginPing",
					Summary:     "Test plugin ping endpoint",
				}, func(_ context.Context, _ *struct{}) (*pingOutput, error) {
					out := &pingOutput{}
					out.Body.Pong = true
					return out, nil
				})
			},
		},
	}
}

func (p *testPlugin) Schema() auth.PluginSchema {
	return auth.PluginSchema{
		"user": auth.TableSchema{
			Fields: map[string]auth.FieldAttribute{
				"role": {Type: auth.FieldTypeString, Required: boolPtr(false), DefaultValue: "member"},
			},
		},
	}
}

func (p *testPlugin) Hooks() auth.DBHooks {
	if p.hooks != nil {
		return p.hooks
	}
	return auth.DBHooks{
		"user": auth.ModelHooks{
			Create: auth.OperationHooks{
				Before: func(_ context.Context, data map[string]any) (map[string]any, error) {
					if _, ok := data["role"]; !ok {
						data["role"] = "member"
					}
					return data, nil
				},
			},
		},
	}
}

func (p *testPlugin) RouteHooks() auth.PluginRouteHooks {
	return auth.PluginRouteHooks{}
}

func (p *testPlugin) ErrorCodes() map[string]string {
	return map[string]string{
		"TEST_ERROR": "This is a test error",
	}
}

// failPlugin fails Init to exercise BetterAuth error returns.
type failPlugin struct{ id string }

func (p *failPlugin) ID() string                        { return p.id }
func (p *failPlugin) Init(auth.AuthContext) error       { return errors.New("init boom") }
func (p *failPlugin) Endpoints() []auth.Endpoint        { return nil }
func (p *failPlugin) Schema() auth.PluginSchema         { return nil }
func (p *failPlugin) Hooks() auth.DBHooks               { return nil }
func (p *failPlugin) RouteHooks() auth.PluginRouteHooks { return auth.PluginRouteHooks{} }
func (p *failPlugin) ErrorCodes() map[string]string     { return nil }

func boolPtr(b bool) *bool { return &b }

func intPtr(v int) *int { return &v }

func newMemoryAdapter() *memoryAdapter {
	return &memoryAdapter{
		tables: map[string][]map[string]any{
			"user":         {},
			"session":      {},
			"account":      {},
			"verification": {},
		},
	}
}

func (m *memoryAdapter) Create(_ context.Context, model string, data map[string]any, _ []string) (map[string]any, error) {
	row := memoryNormalizeRow(data)
	m.tables[model] = append(m.tables[model], row)
	return memoryCloneRow(row), nil
}

func (m *memoryAdapter) FindOne(_ context.Context, model string, where []auth.Where, _ []string) (map[string]any, error) {
	for _, row := range m.tables[model] {
		if memoryMatches(row, where) {
			return memoryCloneRow(row), nil
		}
	}
	return nil, nil
}

func (m *memoryAdapter) FindMany(_ context.Context, model string, where []auth.Where, limit, offset int, _ *auth.SortBy, _ []string) ([]map[string]any, error) {
	rows := make([]map[string]any, 0)
	for _, row := range m.tables[model] {
		if memoryMatches(row, where) {
			rows = append(rows, memoryCloneRow(row))
		}
	}
	if offset > 0 && offset < len(rows) {
		rows = rows[offset:]
	} else if offset >= len(rows) {
		return []map[string]any{}, nil
	}
	if limit > 0 && limit < len(rows) {
		rows = rows[:limit]
	}
	return rows, nil
}

func (m *memoryAdapter) Update(_ context.Context, model string, where []auth.Where, data map[string]any) (map[string]any, error) {
	update := memoryNormalizeRow(data)
	for _, row := range m.tables[model] {
		if memoryMatches(row, where) {
			for key, value := range update {
				row[key] = value
			}
			return memoryCloneRow(row), nil
		}
	}
	return nil, nil
}

func (m *memoryAdapter) UpdateMany(_ context.Context, model string, where []auth.Where, data map[string]any) (int, error) {
	update := memoryNormalizeRow(data)
	updated := 0
	for _, row := range m.tables[model] {
		if memoryMatches(row, where) {
			for key, value := range update {
				row[key] = value
			}
			updated++
		}
	}
	return updated, nil
}

func (m *memoryAdapter) Delete(_ context.Context, model string, where []auth.Where) error {
	filtered := m.tables[model][:0]
	for _, row := range m.tables[model] {
		if !memoryMatches(row, where) {
			filtered = append(filtered, row)
		}
	}
	m.tables[model] = filtered
	return nil
}

func (m *memoryAdapter) DeleteMany(ctx context.Context, model string, where []auth.Where) (int, error) {
	before := len(m.tables[model])
	if err := m.Delete(ctx, model, where); err != nil {
		return 0, err
	}
	return before - len(m.tables[model]), nil
}

func (m *memoryAdapter) ConsumeOne(_ context.Context, model string, where []auth.Where) (map[string]any, error) {
	for i, row := range m.tables[model] {
		if memoryMatches(row, where) {
			consumed := memoryCloneRow(row)
			m.tables[model] = append(m.tables[model][:i], m.tables[model][i+1:]...)
			return consumed, nil
		}
	}
	return nil, nil
}

func (m *memoryAdapter) IncrementOne(_ context.Context, model string, where []auth.Where, increment map[string]int, set map[string]any) (map[string]any, error) {
	if len(increment) == 0 && len(set) == 0 {
		return nil, errors.New("auth: incrementOne requires a non-empty increment or set")
	}
	for _, row := range m.tables[model] {
		if memoryMatches(row, where) {
			for logical, delta := range increment {
				cur, _ := memoryToNumber(row[memoryToLogical(logical)])
				row[memoryToLogical(logical)] = cur + delta
			}
			for k, v := range memoryNormalizeRow(set) {
				row[k] = v
			}
			return memoryCloneRow(row), nil
		}
	}
	return nil, nil
}

func memoryToNumber(v any) (int, bool) {
	switch n := v.(type) {
	case nil:
		return 0, true
	case int:
		return n, true
	case int8:
		return int(n), true
	case int16:
		return int(n), true
	case int32:
		return int(n), true
	case int64:
		return int(n), true
	case uint:
		return int(n), true
	case uint32:
		return int(n), true
	case uint64:
		return int(n), true
	case float32:
		return int(n), true
	case float64:
		return int(n), true
	default:
		return 0, false
	}
}

func (m *memoryAdapter) Count(_ context.Context, model string, where []auth.Where) (int, error) {
	if len(where) == 0 {
		return len(m.tables[model]), nil
	}
	count := 0
	for _, row := range m.tables[model] {
		if memoryMatches(row, where) {
			count++
		}
	}
	return count, nil
}

func (m *memoryAdapter) Transaction(ctx context.Context, fn func(tx auth.DBAdapter) error) error {
	clone := newMemoryAdapter()
	for model, rows := range m.tables {
		clone.tables[model] = make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			clone.tables[model] = append(clone.tables[model], memoryCloneRow(row))
		}
	}
	if err := fn(clone); err != nil {
		return err
	}
	m.tables = clone.tables
	return nil
}

func memoryNormalizeRow(data map[string]any) map[string]any {
	row := make(map[string]any, len(data))
	for key, value := range data {
		row[memoryToLogical(key)] = value
	}
	return row
}

func memoryCloneRow(row map[string]any) map[string]any {
	cloned := make(map[string]any, len(row))
	for key, value := range row {
		cloned[key] = value
	}
	return cloned
}

func memoryMatches(row map[string]any, where []auth.Where) bool {
	if len(where) == 0 {
		return true
	}
	result := true
	for i, clause := range where {
		field := memoryToLogical(clause.Field)
		matches := row[field] == clause.Value
		if i == 0 {
			result = matches
			continue
		}
		if strings.EqualFold(clause.Connector, "OR") {
			result = result || matches
		} else {
			result = result && matches
		}
	}
	return result
}

// memoryToLogical maps physical-or-logical input to logical camelCase keys
// (transformOutput key part): snake_case folds to camelCase, camelCase
// passes through. Memory adapters have no Config overrides.
func memoryToLogical(key string) string {
	if !strings.Contains(key, "_") {
		return key
	}
	var b strings.Builder
	upperNext := false
	for i, r := range key {
		if r == '_' {
			upperNext = i > 0
			continue
		}
		if upperNext && r >= 'a' && r <= 'z' {
			b.WriteRune(r - ('a' - 'A'))
			upperNext = false
			continue
		}
		upperNext = false
		b.WriteRune(r)
	}
	return b.String()
}

func memoryCamelToSnake(s string) string {
	var b strings.Builder
	for i, r := range s {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(r + 32)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func TestPluginSystem_InitCalled(t *testing.T) {
	adapter, _ := newTestAdapter(t)
	plugin := &testPlugin{}
	mustBetterAuth(t, auth.Options{
		Secret:  "test-secret",
		Adapter: adapter,
		Plugins: []auth.Plugin{plugin},
	})
	if !plugin.initCalled {
		t.Fatal("expected plugin Init to be called")
	}
}

func TestPluginSystem_EndpointReachable(t *testing.T) {
	adapter, srv := newTestAdapter(t)
	plugin := &testPlugin{}
	mustBetterAuth(t, auth.Options{
		Secret:  "test-secret",
		Adapter: adapter,
		Plugins: []auth.Plugin{plugin},
	})

	resp, err := http.Get(srv.URL + "/api/auth/test-plugin-ping")
	if err != nil {
		t.Fatalf("ping request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var body struct {
		Pong bool `json:"pong"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !body.Pong {
		t.Fatal("expected pong=true")
	}
}

func TestPluginSystem_ErrorCodesMerged(t *testing.T) {
	adapter, _ := newTestAdapter(t)
	plugin := &testPlugin{}
	a := mustBetterAuth(t, auth.Options{
		Secret:  "test-secret",
		Adapter: adapter,
		Plugins: []auth.Plugin{plugin},
	})

	msg, ok := auth.PluginErrorCodes["TEST_ERROR"]
	if !ok {
		t.Fatal("expected TEST_ERROR in PluginErrorCodes")
	}
	if msg != "This is a test error" {
		t.Fatalf("unexpected error message: %q", msg)
	}
	// Per-Auth codes merge plugin + BASE in upstream order with messages.
	raw, ok := a.ErrorCodes["TEST_ERROR"]
	if !ok || raw.Code != "TEST_ERROR" || raw.Message != "This is a test error" {
		t.Fatalf("expected per-Auth TEST_ERROR RawError, got %#v", raw)
	}
	base, ok := a.ErrorCodes[auth.ErrUserNotFound]
	if !ok || base.Code != "USER_NOT_FOUND" || base.Message != "User not found" {
		t.Fatalf("expected per-Auth BASE USER_NOT_FOUND, got %#v", base)
	}
	for _, code := range []string{auth.ErrChangeEmailDisabled, auth.ErrMethodNotAllowedDeferSessionRequired} {
		if _, ok := a.ErrorCodes[code]; !ok {
			t.Fatalf("expected per-Auth code %q", code)
		}
		if _, ok := auth.PluginErrorCodes[code]; !ok {
			t.Fatalf("expected deprecated global code %q", code)
		}
	}
}

func TestBetterAuth_PluginInitError(t *testing.T) {
	adapter, _ := newTestAdapter(t)
	plugin := &failPlugin{id: "boom"}
	if _, err := auth.BetterAuth(auth.Options{Secret: "s", Adapter: adapter, Plugins: []auth.Plugin{plugin}}); err == nil {
		t.Fatal("expected plugin init error")
	} else if got := err.Error(); !strings.Contains(got, `"boom"`) {
		t.Fatalf("expected plugin id in error, got %q", got)
	}
}

// patchPlugin exercises the OPTIONAL PluginInitPatches interface: it returns
type patchPlugin struct {
	id string
}

func (p *patchPlugin) ID() string                  { return p.id }
func (p *patchPlugin) Init(auth.AuthContext) error { return nil }
func (p *patchPlugin) Endpoints() []auth.Endpoint  { return nil }
func (p *patchPlugin) Schema() auth.PluginSchema   { return nil }
func (p *patchPlugin) Hooks() auth.DBHooks         { return nil }
func (p *patchPlugin) RouteHooks() auth.PluginRouteHooks {
	return auth.PluginRouteHooks{}
}
func (p *patchPlugin) ErrorCodes() map[string]string { return nil }
func (p *patchPlugin) InitPatches(auth.AuthContext) (auth.PluginInitPatch, error) {
	return auth.PluginInitPatch{
		Options: &auth.Options{
			TrustedOrigins: []string{"https://patch.example.com"},
			DatabaseHooks: auth.DBHooks{
				"user": {Create: auth.OperationHooks{
					After: func(_ context.Context, _ map[string]any) error { return nil },
				}},
			},
		},
		Context: &auth.AuthContext{AppName: "Patched App"},
	}, nil
}

func TestBetterAuth_InitPatchesMerged(t *testing.T) {
	adapter, _ := newTestAdapter(t)
	a, err := auth.BetterAuth(auth.Options{
		Secret:  "test-secret-patch-0123456789abcdef",
		Adapter: adapter,
		Plugins: []auth.Plugin{&patchPlugin{id: "patcher"}},
	})
	if err != nil {
		t.Fatalf("BetterAuth: %v", err)
	}
	if a.Context.AppName != "Patched App" {
		t.Fatalf("expected patched AppName, got %q", a.Context.AppName)
	}
	found := false
	for _, o := range a.Context.Options.TrustedOrigins {
		if o == "https://patch.example.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected patched trusted origin, got %#v", a.Context.Options.TrustedOrigins)
	}
}

func TestBetterAuth_EnvSecrets(t *testing.T) {
	adapter, _ := newTestAdapter(t)
	t.Setenv("BETTER_AUTH_SECRET", "env-secret-0123456789abcdef01234567")
	t.Setenv("AUTH_SECRET", "")
	t.Setenv("BETTER_AUTH_SECRETS", "")
	a, err := auth.BetterAuth(auth.Options{Adapter: adapter})
	if err != nil {
		t.Fatalf("BetterAuth with env secret: %v", err)
	}
	if a.Context.Secret != "env-secret-0123456789abcdef01234567" {
		t.Fatalf("expected env secret, got %q", a.Context.Secret)
	}
}

func TestBetterAuth_EnvSecretsVersioned(t *testing.T) {
	adapter, _ := newTestAdapter(t)
	t.Setenv("BETTER_AUTH_SECRET", "")
	t.Setenv("AUTH_SECRET", "")
	t.Setenv("BETTER_AUTH_SECRETS", "2:second-secret-0123456789abcdef12,1:first-secret-0123456789abcdef01")
	a, err := auth.BetterAuth(auth.Options{Adapter: adapter})
	if err != nil {
		t.Fatalf("BetterAuth with versioned env: %v", err)
	}
	if a.Context.Secret != "second-secret-0123456789abcdef12" {
		t.Fatalf("expected first entry as current, got %q", a.Context.Secret)
	}
	if a.Context.SecretConfig.CurrentVersion != 2 {
		t.Fatalf("expected current version 2, got %d", a.Context.SecretConfig.CurrentVersion)
	}
	if a.Context.SecretConfig.Keys[1] != "first-secret-0123456789abcdef01" {
		t.Fatalf("expected versioned keys, got %#v", a.Context.SecretConfig.Keys)
	}
}

func TestBetterAuth_MissingSecretErrors(t *testing.T) {
	adapter, _ := newTestAdapter(t)
	t.Setenv("BETTER_AUTH_SECRET", "")
	t.Setenv("AUTH_SECRET", "")
	t.Setenv("BETTER_AUTH_SECRETS", "")
	if _, err := auth.BetterAuth(auth.Options{Adapter: adapter}); err == nil {
		t.Fatal("expected missing-secret error")
	}
}

func TestPluginSystem_HookMutatesData(t *testing.T) {
	db := openDB(t)
	migrate(t, db)

	ctx := context.Background()
	_, err := db.ExecContext(ctx, "ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'member'")
	if err != nil {
		t.Fatalf("add role column: %v", err)
	}

	plugin := &testPlugin{}
	adapter, srv := newTestAdapter(t)
	mustBetterAuth(t, auth.Options{
		Secret:  "test-secret",
		Adapter: adapter,
		DB:      authbun.New(db, authbun.Config{}),
		Session: auth.SessionOptions{ExpiresIn: 3600, UpdateAge: intPtr(1)},
		EmailAndPassword: auth.EmailAndPasswordOptions{
			Enabled: true,
		},
		Plugins: []auth.Plugin{plugin},
	})

	resp, _ := signUp(t, srv.URL, "plugin-hook@example.com")
	resp.Body.Close()

	bunDB := authbun.New(db, authbun.Config{})
	row, err := bunDB.FindOne(ctx, "user", []auth.Where{
		{Field: "email", Value: "plugin-hook@example.com"},
	}, nil)
	if err != nil {
		t.Fatalf("find user: %v", err)
	}
	if row == nil {
		t.Fatal("expected user row")
	}
	role, _ := row["role"].(string)
	if role != "member" {
		t.Fatalf("expected role='member', got %q", role)
	}
}

func TestNew_DatabaseHooksRunAfterPluginHooks(t *testing.T) {
	db := openDB(t)
	migrate(t, db)

	ctx := context.Background()
	_, err := db.ExecContext(ctx, "ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'member'")
	if err != nil {
		t.Fatalf("add role column: %v", err)
	}

	order := []string{}
	plugin := &testPlugin{
		hooks: auth.DBHooks{
			"user": auth.ModelHooks{
				Create: auth.OperationHooks{
					Before: func(_ context.Context, data map[string]any) (map[string]any, error) {
						order = append(order, "plugin-before")
						data["role"] = "member"
						return data, nil
					},
					After: func(_ context.Context, data map[string]any) error {
						order = append(order, "plugin-after")
						return nil
					},
				},
			},
		},
	}

	adapter, srv := newTestAdapter(t)
	mustBetterAuth(t, auth.Options{
		Secret:  "test-secret",
		Adapter: adapter,
		DB:      authbun.New(db, authbun.Config{}),
		Session: auth.SessionOptions{ExpiresIn: 3600, UpdateAge: intPtr(1)},
		EmailAndPassword: auth.EmailAndPasswordOptions{
			Enabled: true,
		},
		Plugins: []auth.Plugin{plugin},
		DatabaseHooks: auth.DBHooks{
			"user": auth.ModelHooks{
				Create: auth.OperationHooks{
					Before: func(_ context.Context, data map[string]any) (map[string]any, error) {
						order = append(order, "global-before")
						data["role"] = "admin"
						return data, nil
					},
					After: func(_ context.Context, data map[string]any) error {
						order = append(order, "global-after")
						return nil
					},
				},
			},
		},
	})

	resp, _ := signUp(t, srv.URL, "global-hooks@example.com")
	resp.Body.Close()

	row, err := authbun.New(db, authbun.Config{}).FindOne(ctx, "user", []auth.Where{
		{Field: "email", Value: "global-hooks@example.com"},
	}, nil)
	if err != nil {
		t.Fatalf("find user: %v", err)
	}
	if row == nil {
		t.Fatal("expected user row")
	}
	role, _ := row["role"].(string)
	if role != "admin" {
		t.Fatalf("expected global hook to run after plugin hook and set role='admin', got %q", role)
	}
	expectedOrder := []string{"plugin-before", "global-before", "plugin-after", "global-after"}
	if len(order) != len(expectedOrder) {
		t.Fatalf("expected hook order %v, got %v", expectedOrder, order)
	}
	for i := range expectedOrder {
		if order[i] != expectedOrder[i] {
			t.Fatalf("expected hook order %v, got %v", expectedOrder, order)
		}
	}
}

func TestNew_DatabaseHooksWorkWithoutPlugins(t *testing.T) {
	db := openDB(t)
	migrate(t, db)

	ctx := context.Background()
	_, err := db.ExecContext(ctx, "ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'member'")
	if err != nil {
		t.Fatalf("add role column: %v", err)
	}

	adapter, srv := newTestAdapter(t)
	mustBetterAuth(t, auth.Options{
		Secret:  "test-secret",
		Adapter: adapter,
		DB:      authbun.New(db, authbun.Config{}),
		Session: auth.SessionOptions{ExpiresIn: 3600, UpdateAge: intPtr(1)},
		EmailAndPassword: auth.EmailAndPasswordOptions{
			Enabled: true,
		},
		DatabaseHooks: auth.DBHooks{
			"user": auth.ModelHooks{
				Create: auth.OperationHooks{
					Before: func(_ context.Context, data map[string]any) (map[string]any, error) {
						data["role"] = "owner"
						return data, nil
					},
				},
			},
		},
	})

	resp, _ := signUp(t, srv.URL, "global-only-hooks@example.com")
	resp.Body.Close()

	row, err := authbun.New(db, authbun.Config{}).FindOne(ctx, "user", []auth.Where{
		{Field: "email", Value: "global-only-hooks@example.com"},
	}, nil)
	if err != nil {
		t.Fatalf("find user: %v", err)
	}
	if row == nil {
		t.Fatal("expected user row")
	}
	role, _ := row["role"].(string)
	if role != "owner" {
		t.Fatalf("expected global hook to run without plugins and set role='owner', got %q", role)
	}
}

func TestNew_DatabaseHooksDeleteUserExposeDeletedRows(t *testing.T) {
	db := openDB(t)
	migrate(t, db)

	var deletedSessions []map[string]any
	var deletedAccounts []map[string]any
	var deletedUsers []map[string]any

	adapter, srv := newTestAdapter(t)
	mustBetterAuth(t, auth.Options{
		Secret:  "test-secret",
		Adapter: adapter,
		DB:      authbun.New(db, authbun.Config{}),
		Session: auth.SessionOptions{ExpiresIn: 3600, UpdateAge: intPtr(1)},
		EmailAndPassword: auth.EmailAndPasswordOptions{
			Enabled: true,
		},
		User: auth.UserOptions{
			DeleteUser: auth.DeleteUserOptions{Enabled: true},
		},
		DatabaseHooks: auth.DBHooks{
			"session": auth.ModelHooks{
				Delete: auth.OperationHooks{
					After: func(_ context.Context, data map[string]any) error {
						deletedSessions = append(deletedSessions, cloneMap(data))
						return nil
					},
				},
			},
			"account": auth.ModelHooks{
				Delete: auth.OperationHooks{
					After: func(_ context.Context, data map[string]any) error {
						deletedAccounts = append(deletedAccounts, cloneMap(data))
						return nil
					},
				},
			},
			"user": auth.ModelHooks{
				Delete: auth.OperationHooks{
					After: func(_ context.Context, data map[string]any) error {
						deletedUsers = append(deletedUsers, cloneMap(data))
						return nil
					},
				},
			},
		},
	})

	resp, cookie := signUp(t, srv.URL, "delete-hooks@example.com")
	resp.Body.Close()

	deleteReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/auth/delete-user", strings.NewReader(`{}`))
	deleteReq.Header.Set("Content-Type", "application/json")
	deleteReq.Header.Set("Cookie", cookie)
	deleteResp, err := http.DefaultClient.Do(deleteReq)
	if err != nil {
		t.Fatalf("delete-user failed: %v", err)
	}
	defer deleteResp.Body.Close()
	if deleteResp.StatusCode != http.StatusOK {
		t.Fatalf("delete-user expected 200, got %d", deleteResp.StatusCode)
	}

	if len(deletedSessions) != 1 {
		t.Fatalf("expected 1 deleted session hook payload, got %d", len(deletedSessions))
	}
	if deletedSessions[0]["userId"] == nil || deletedSessions[0]["token"] == nil {
		t.Fatalf("expected deleted session hook payload to include persisted row data, got %#v", deletedSessions[0])
	}

	if len(deletedAccounts) != 1 {
		t.Fatalf("expected 1 deleted account hook payload, got %d", len(deletedAccounts))
	}
	if deletedAccounts[0]["userId"] == nil || deletedAccounts[0]["providerId"] != "credential" {
		t.Fatalf("expected deleted account hook payload to include persisted row data, got %#v", deletedAccounts[0])
	}

	if len(deletedUsers) != 1 {
		t.Fatalf("expected 1 deleted user hook payload, got %d", len(deletedUsers))
	}
	if deletedUsers[0]["email"] != "delete-hooks@example.com" || deletedUsers[0]["id"] == nil {
		t.Fatalf("expected deleted user hook payload to include persisted row data, got %#v", deletedUsers[0])
	}
}

type recordingAdapter struct {
	createFn func(model string, data map[string]any) (map[string]any, error)
}

func (a *recordingAdapter) Create(_ context.Context, model string, data map[string]any, _ []string) (map[string]any, error) {
	if a.createFn != nil {
		return a.createFn(model, data)
	}
	return cloneMap(data), nil
}

func (a *recordingAdapter) FindOne(context.Context, string, []auth.Where, []string) (map[string]any, error) {
	return nil, errors.New("not implemented")
}

func (a *recordingAdapter) FindMany(context.Context, string, []auth.Where, int, int, *auth.SortBy, []string) ([]map[string]any, error) {
	return nil, errors.New("not implemented")
}

func (a *recordingAdapter) Update(context.Context, string, []auth.Where, map[string]any) (map[string]any, error) {
	return nil, errors.New("not implemented")
}

func (a *recordingAdapter) UpdateMany(context.Context, string, []auth.Where, map[string]any) (int, error) {
	return 0, errors.New("not implemented")
}

func (a *recordingAdapter) Delete(context.Context, string, []auth.Where) error {
	return errors.New("not implemented")
}

func (a *recordingAdapter) DeleteMany(context.Context, string, []auth.Where) (int, error) {
	return 0, errors.New("not implemented")
}

func (a *recordingAdapter) ConsumeOne(context.Context, string, []auth.Where) (map[string]any, error) {
	return nil, errors.New("not implemented")
}

func (a *recordingAdapter) IncrementOne(context.Context, string, []auth.Where, map[string]int, map[string]any) (map[string]any, error) {
	return nil, errors.New("not implemented")
}

func (a *recordingAdapter) Count(context.Context, string, []auth.Where) (int, error) {
	return 0, errors.New("not implemented")
}

func (a *recordingAdapter) Transaction(ctx context.Context, fn func(tx auth.Adapter) error) error {
	return fn(a)
}

func cloneMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func TestHookedAdapter_DatabaseHooksSupportCoreModels(t *testing.T) {
	afterOrder := []string{}
	inner := &recordingAdapter{
		createFn: func(model string, data map[string]any) (map[string]any, error) {
			created := cloneMap(data)
			created["model"] = model
			return created, nil
		},
	}

	wrapped := auth.NewHookedAdapter(inner, nil, auth.DBHooks{
		"user": auth.ModelHooks{
			Create: auth.OperationHooks{
				Before: func(_ context.Context, data map[string]any) (map[string]any, error) {
					data["hooked"] = "user"
					return data, nil
				},
				After: func(_ context.Context, data map[string]any) error {
					afterOrder = append(afterOrder, data["model"].(string))
					return nil
				},
			},
		},
		"session": auth.ModelHooks{
			Create: auth.OperationHooks{
				Before: func(_ context.Context, data map[string]any) (map[string]any, error) {
					data["hooked"] = "session"
					return data, nil
				},
				After: func(_ context.Context, data map[string]any) error {
					afterOrder = append(afterOrder, data["model"].(string))
					return nil
				},
			},
		},
		"account": auth.ModelHooks{
			Create: auth.OperationHooks{
				Before: func(_ context.Context, data map[string]any) (map[string]any, error) {
					data["hooked"] = "account"
					return data, nil
				},
				After: func(_ context.Context, data map[string]any) error {
					afterOrder = append(afterOrder, data["model"].(string))
					return nil
				},
			},
		},
		"verification": auth.ModelHooks{
			Create: auth.OperationHooks{
				Before: func(_ context.Context, data map[string]any) (map[string]any, error) {
					data["hooked"] = "verification"
					return data, nil
				},
				After: func(_ context.Context, data map[string]any) error {
					afterOrder = append(afterOrder, data["model"].(string))
					return nil
				},
			},
		},
	})

	models := []string{"user", "session", "account", "verification"}
	for _, model := range models {
		result, err := wrapped.Create(context.Background(), model, map[string]any{"id": model}, nil)
		if err != nil {
			t.Fatalf("create %s: %v", model, err)
		}
		if got, _ := result["hooked"].(string); got != model {
			t.Fatalf("expected %s hook to mutate create data, got %q", model, got)
		}
	}

	if len(afterOrder) != len(models) {
		t.Fatalf("expected after hooks for %v, got %v", models, afterOrder)
	}
	for i := range models {
		if afterOrder[i] != models[i] {
			t.Fatalf("expected after hooks for %v, got %v", models, afterOrder)
		}
	}
}

func TestHookedAdapter_TransactionPreservesHooks(t *testing.T) {
	inner := &recordingAdapter{
		createFn: func(_ string, data map[string]any) (map[string]any, error) {
			return cloneMap(data), nil
		},
	}

	wrapped := auth.NewHookedAdapter(inner, nil, auth.DBHooks{
		"user": auth.ModelHooks{
			Create: auth.OperationHooks{
				Before: func(_ context.Context, data map[string]any) (map[string]any, error) {
					data["fromHook"] = true
					return data, nil
				},
			},
		},
	})

	err := wrapped.Transaction(context.Background(), func(tx auth.Adapter) error {
		row, err := tx.Create(context.Background(), "user", map[string]any{"id": "tx-user"}, nil)
		if err != nil {
			return err
		}
		if row["fromHook"] != true {
			t.Fatalf("expected transaction-scoped adapter to preserve hooks, got %#v", row)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("transaction: %v", err)
	}
}


// routeHookPlugin is a minimal Plugin for testing route-level hooks.
type routeHookPlugin struct {
	id     string
	before []auth.PluginRouteBeforeHook
	after  []auth.PluginRouteAfterHook
}

func (p *routeHookPlugin) ID() string {
	if p.id != "" {
		return p.id
	}
	return "route-hook-plugin"
}
func (p *routeHookPlugin) Init(_ auth.AuthContext) error { return nil }
func (p *routeHookPlugin) Endpoints() []auth.Endpoint    { return nil }
func (p *routeHookPlugin) Schema() auth.PluginSchema     { return nil }
func (p *routeHookPlugin) Hooks() auth.DBHooks           { return nil }
func (p *routeHookPlugin) ErrorCodes() map[string]string { return nil }
func (p *routeHookPlugin) RouteHooks() auth.PluginRouteHooks {
	return auth.PluginRouteHooks{Before: p.before, After: p.after}
}

type requestLifecyclePlugin struct {
	id          string
	onRequest   auth.PluginOnRequestHandler
	onResponse  auth.PluginOnResponseHandler
	middlewares []auth.PluginMiddleware
	rateLimits  []auth.PluginRateLimitRule
}

func (p *requestLifecyclePlugin) ID() string {
	if p.id != "" {
		return p.id
	}
	return "request-lifecycle-plugin"
}

func (p *requestLifecyclePlugin) Init(_ auth.AuthContext) error            { return nil }
func (p *requestLifecyclePlugin) Endpoints() []auth.Endpoint               { return nil }
func (p *requestLifecyclePlugin) Schema() auth.PluginSchema                { return nil }
func (p *requestLifecyclePlugin) Hooks() auth.DBHooks                      { return nil }
func (p *requestLifecyclePlugin) ErrorCodes() map[string]string            { return nil }
func (p *requestLifecyclePlugin) RouteHooks() auth.PluginRouteHooks        { return auth.PluginRouteHooks{} }
func (p *requestLifecyclePlugin) OnRequest() auth.PluginOnRequestHandler   { return p.onRequest }
func (p *requestLifecyclePlugin) OnResponse() auth.PluginOnResponseHandler { return p.onResponse }
func (p *requestLifecyclePlugin) Middlewares() []auth.PluginMiddleware     { return p.middlewares }
func (p *requestLifecyclePlugin) RateLimitRules() []auth.PluginRateLimitRule {
	return p.rateLimits
}

func TestPluginRouteHooks_BeforeHookFiresOnMatchingPath(t *testing.T) {
	fired := false
	plugin := &routeHookPlugin{
		before: []auth.PluginRouteBeforeHook{
			{
				Matcher: func(ctx huma.Context) bool {
					return strings.HasSuffix(ctx.Operation().Path, "/ok")
				},
				Handler: func(ctx huma.Context) (huma.Context, error) {
					fired = true
					return nil, nil
				},
			},
		},
	}
	srv, _ := newIntegrationAuthWithOptions(t, auth.Options{
		Plugins: []auth.Plugin{plugin},
	})
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/auth/ok")
	if err != nil {
		t.Fatalf("GET /ok: %v", err)
	}
	resp.Body.Close()

	if !fired {
		t.Error("expected plugin before hook to fire for matching path /ok")
	}
}

func TestPluginRouteHooks_BeforeHookSkipsNonMatchingPath(t *testing.T) {
	fired := false
	plugin := &routeHookPlugin{
		before: []auth.PluginRouteBeforeHook{
			{
				Matcher: func(ctx huma.Context) bool {
					return strings.HasSuffix(ctx.Operation().Path, "/sign-in/email")
				},
				Handler: func(ctx huma.Context) (huma.Context, error) {
					fired = true
					return nil, nil
				},
			},
		},
	}
	srv, _ := newIntegrationAuthWithOptions(t, auth.Options{
		Plugins: []auth.Plugin{plugin},
	})
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/auth/ok")
	if err != nil {
		t.Fatalf("GET /ok: %v", err)
	}
	resp.Body.Close()

	if fired {
		t.Error("expected plugin before hook NOT to fire for non-matching path")
	}
}

func TestPluginRouteHooks_BeforeHookErrorShortCircuits(t *testing.T) {
	plugin := &routeHookPlugin{
		before: []auth.PluginRouteBeforeHook{
			{
				Matcher: func(ctx huma.Context) bool { return true },
				Handler: func(ctx huma.Context) (huma.Context, error) {
					return nil, huma.Error403Forbidden("hook blocked this request")
				},
			},
		},
	}
	srv, _ := newIntegrationAuthWithOptions(t, auth.Options{
		Plugins: []auth.Plugin{plugin},
	})
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/auth/ok")
	if err != nil {
		t.Fatalf("GET /ok: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 from before hook error, got %d", resp.StatusCode)
	}
}

func TestPluginRouteHooks_AfterHookFiresOnMatchingPath(t *testing.T) {
	fired := false
	plugin := &routeHookPlugin{
		after: []auth.PluginRouteAfterHook{
			{
				Matcher: func(ctx huma.Context) bool {
					return strings.HasSuffix(ctx.Operation().Path, "/ok")
				},
				Handler: func(ctx huma.Context) {
					fired = true
				},
			},
		},
	}
	srv, _ := newIntegrationAuthWithOptions(t, auth.Options{
		Plugins: []auth.Plugin{plugin},
	})
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/auth/ok")
	if err != nil {
		t.Fatalf("GET /ok: %v", err)
	}
	resp.Body.Close()

	if !fired {
		t.Error("expected plugin after hook to fire for matching path /ok")
	}
}

func TestPluginRouteHooks_BeforeHooksFireInPluginDeclarationOrder(t *testing.T) {
	var order []string
	p1 := &routeHookPlugin{
		id: "p1",
		before: []auth.PluginRouteBeforeHook{
			{
				Matcher: func(ctx huma.Context) bool { return true },
				Handler: func(ctx huma.Context) (huma.Context, error) {
					order = append(order, "p1")
					return nil, nil
				},
			},
		},
	}
	p2 := &routeHookPlugin{
		id: "p2",
		before: []auth.PluginRouteBeforeHook{
			{
				Matcher: func(ctx huma.Context) bool { return true },
				Handler: func(ctx huma.Context) (huma.Context, error) {
					order = append(order, "p2")
					return nil, nil
				},
			},
		},
	}
	srv, _ := newIntegrationAuthWithOptions(t, auth.Options{
		Plugins: []auth.Plugin{p1, p2},
	})
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/auth/ok")
	if err != nil {
		t.Fatalf("GET /ok: %v", err)
	}
	resp.Body.Close()

	if len(order) != 2 || order[0] != "p1" || order[1] != "p2" {
		t.Errorf("expected before hooks to fire as [p1 p2], got %v", order)
	}
}

func TestPluginRouteHooks_AfterHooksFireInPluginDeclarationOrder(t *testing.T) {
	var order []string
	p1 := &routeHookPlugin{
		id: "p1",
		after: []auth.PluginRouteAfterHook{
			{
				Matcher: func(ctx huma.Context) bool { return true },
				Handler: func(ctx huma.Context) {
					order = append(order, "p1")
				},
			},
		},
	}
	p2 := &routeHookPlugin{
		id: "p2",
		after: []auth.PluginRouteAfterHook{
			{
				Matcher: func(ctx huma.Context) bool { return true },
				Handler: func(ctx huma.Context) {
					order = append(order, "p2")
				},
			},
		},
	}
	srv, _ := newIntegrationAuthWithOptions(t, auth.Options{
		Plugins: []auth.Plugin{p1, p2},
	})
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/auth/ok")
	if err != nil {
		t.Fatalf("GET /ok: %v", err)
	}
	resp.Body.Close()

	if len(order) != 2 || order[0] != "p1" || order[1] != "p2" {
		t.Errorf("expected after hooks to fire as [p1 p2], got %v", order)
	}
}

func TestPluginOnRequest_RunsInDeclarationOrderAndPassesModifiedRequest(t *testing.T) {
	var order []string
	var received string
	p1 := &requestLifecyclePlugin{
		id: "p1",
		onRequest: func(req *http.Request, _ auth.AuthContext) (*auth.PluginOnRequestResult, error) {
			order = append(order, "p1")
			next := req.Clone(req.Context())
			next.Header.Set("X-From-P1", "hello")
			return &auth.PluginOnRequestResult{Request: next}, nil
		},
	}
	p2 := &requestLifecyclePlugin{
		id: "p2",
		onRequest: func(req *http.Request, _ auth.AuthContext) (*auth.PluginOnRequestResult, error) {
			order = append(order, "p2")
			received = req.Header.Get("X-From-P1")
			return nil, nil
		},
	}

	api, _ := newMemoryAuthAPI(t, auth.Options{
		Plugins: []auth.Plugin{p1, p2},
	})
	resp := api.Get("/api/auth/ok")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}

	if want := []string{"p1", "p2"}; len(order) != len(want) || order[0] != want[0] || order[1] != want[1] {
		t.Fatalf("expected onRequest order %v, got %v", want, order)
	}
	if received != "hello" {
		t.Fatalf("expected second plugin to observe modified request header, got %q", received)
	}
}

func TestPluginOnRequest_CanShortCircuitChain(t *testing.T) {
	var order []string
	p1 := &requestLifecyclePlugin{
		id: "p1",
		onRequest: func(req *http.Request, _ auth.AuthContext) (*auth.PluginOnRequestResult, error) {
			order = append(order, "p1")
			return &auth.PluginOnRequestResult{
				Response: &http.Response{
					StatusCode: http.StatusForbidden,
					Header:     http.Header{"Content-Type": []string{"text/plain"}},
					Body:       io.NopCloser(strings.NewReader("blocked")),
				},
			}, nil
		},
	}
	p2 := &requestLifecyclePlugin{
		id: "p2",
		onRequest: func(req *http.Request, _ auth.AuthContext) (*auth.PluginOnRequestResult, error) {
			order = append(order, "p2")
			return nil, nil
		},
	}

	api, _ := newMemoryAuthAPI(t, auth.Options{
		Plugins: []auth.Plugin{p1, p2},
	})
	resp := api.Get("/api/auth/ok")
	body := resp.Body.String()

	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected 403 short-circuit response, got %d", resp.Code)
	}
	if body != "blocked" {
		t.Fatalf("expected short-circuit body, got %q", body)
	}
	if want := []string{"p1"}; len(order) != len(want) || order[0] != want[0] {
		t.Fatalf("expected onRequest order %v, got %v", want, order)
	}
}

func TestPluginMiddlewares_RunInDeclarationOrderForMatchingPath(t *testing.T) {
	var order []string
	p1 := &requestLifecyclePlugin{
		id: "p1",
		middlewares: []auth.PluginMiddleware{
			{
				Path: "/ok",
				Handler: func(ctx huma.Context) (huma.Context, error) {
					order = append(order, "p1")
					return nil, nil
				},
			},
		},
	}
	p2 := &requestLifecyclePlugin{
		id: "p2",
		middlewares: []auth.PluginMiddleware{
			{
				Path: "/ok",
				Handler: func(ctx huma.Context) (huma.Context, error) {
					order = append(order, "p2")
					return nil, nil
				},
			},
		},
	}

	api, _ := newMemoryAuthAPI(t, auth.Options{
		Plugins: []auth.Plugin{p1, p2},
	})
	resp := api.Get("/api/auth/ok")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}

	if want := []string{"p1", "p2"}; len(order) != len(want) || order[0] != want[0] || order[1] != want[1] {
		t.Fatalf("expected middleware order %v, got %v", want, order)
	}
}

func TestPluginOnResponse_CanReplaceResponseBeforeSend(t *testing.T) {
	p := &requestLifecyclePlugin{
		onResponse: func(resp *http.Response, _ auth.AuthContext) (*auth.PluginOnResponseResult, error) {
			return &auth.PluginOnResponseResult{
				Response: &http.Response{
					StatusCode: http.StatusAccepted,
					Header: http.Header{
						"Content-Type":      []string{"application/json"},
						"X-Plugin-Response": []string{"yes"},
					},
					Body: io.NopCloser(strings.NewReader(`{"ok":"plugin"}`)),
				},
			}, nil
		},
	}

	api, _ := newMemoryAuthAPI(t, auth.Options{
		Plugins: []auth.Plugin{p},
	})
	resp := api.Get("/api/auth/ok")
	body := resp.Body.String()

	if resp.Code != http.StatusAccepted {
		t.Fatalf("expected replaced response status, got %d", resp.Code)
	}
	if resp.Header().Get("X-Plugin-Response") != "yes" {
		t.Fatalf("expected plugin response header")
	}
	if body != `{"ok":"plugin"}` {
		t.Fatalf("expected replaced response body, got %q", body)
	}
}

func TestPluginRateLimitRule_LimitsMatchingPath(t *testing.T) {
	p := &requestLifecyclePlugin{
		rateLimits: []auth.PluginRateLimitRule{
			{
				Window: 60,
				Max:    1,
				PathMatcher: func(path string) bool {
					return path == "/ok"
				},
			},
		},
	}

	api, _ := newMemoryAuthAPI(t, auth.Options{
		Plugins: []auth.Plugin{p},
		// Plugin rules honor the upstream enabled gate (resolveRateLimitConfig
		RateLimit: auth.RateLimitOptions{Enabled: boolPtr(true)},
	})
	first := api.Get("/api/auth/ok", "X-Forwarded-For: 198.51.100.28")
	if first.Code != http.StatusOK {
		t.Fatalf("expected first request to pass, got %d", first.Code)
	}

	second := api.Get("/api/auth/ok", "X-Forwarded-For: 198.51.100.28")
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("expected second request to be rate-limited, got %d", second.Code)
	}
}
