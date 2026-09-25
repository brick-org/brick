package routes

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

// Wiring v1: secondary-storage route fan-out (Task A) and hook-thrown
// APIError propagation (Task B). Every test below FAILS on the pre-fix tree
// (stale secondary copies survive; hook statuses collapse to 500) and PASSES
// once the route wiring mirrors upstream.

func wiringSecondaryAPI(t *testing.T, opts types.Options) humatest.TestAPI {
	t.Helper()
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	SignUpEmail(api, "/api/auth", opts)
	SignInEmail(api, "/api/auth", opts)
	UpdateUser(api, "/api/auth", opts)
	ChangePassword(api, "/api/auth", opts)
	ChangeEmail(api, "/api/auth", opts)
	DeleteUser(api, "/api/auth", opts)
	SendVerificationEmail(api, "/api/auth", opts)
	VerifyEmail(api, "/api/auth", opts)
	return api
}

func wiringTokenOf(t *testing.T, resp *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Token *string `json:"token"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode token: %v (%s)", err, resp.Body.String())
	}
	if body.Token == nil || *body.Token == "" {
		t.Fatalf("response carries no token: %s", resp.Body.String())
	}
	return *body.Token
}

// wiringSignUpIn: two sessions mirrored (upstream createSession).
func wiringSignUpIn(t *testing.T, api humatest.TestAPI, email, password string) (string, string) {
	t.Helper()
	signUp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "Wiring", "email": email, "password": password,
	})
	if signUp.Code != 200 {
		t.Fatalf("seed sign-up = %d: %s", signUp.Code, signUp.Body.String())
	}
	first := wiringTokenOf(t, signUp)
	signIn := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": email, "password": password,
	})
	if signIn.Code != 200 {
		t.Fatalf("seed sign-in = %d: %s", signIn.Code, signIn.Body.String())
	}
	return first, wiringTokenOf(t, signIn)
}

// (upstream refreshUserSessions, internal-adapter.ts:108-137). Pre-fix the
func TestWiringV1_UpdateUserPropagatesToSecondarySessions(t *testing.T) {
	db := newParityMemAdapter()
	store := newMapSecondaryStorage(true)
	opts := emailAuthTestOptions(db)
	opts.SecondaryStorage = store
	api := wiringSecondaryAPI(t, opts)
	first, second := wiringSignUpIn(t, api, "wire-update@test.com", "password123")

	resp := api.Post("/api/auth/update-user", map[string]any{"name": "Wired"},
		"Cookie: "+signedSessionHeader(t, opts, first))
	if resp.Code != 200 || !strings.Contains(resp.Body.String(), `"status":true`) {
		t.Fatalf("update-user = %d, want 200 status:true: %s", resp.Code, resp.Body.String())
	}
	for _, token := range []string{first, second} {
		cached, err := findSecondarySession(opts, token)
		if err != nil || cached == nil {
			t.Fatalf("token %s lookup: %v %v", token, cached, err)
		}
		if cached.User.Name != "Wired" {
			t.Fatalf("token %s cached user name %q, want Wired (stale copy survived)", token, cached.User.Name)
		}
		if cached.Session.Token != token {
			t.Fatalf("token %s session half rewritten: %+v", token, cached.Session)
		}
	}
}

type wiringToggleStorage struct {
	*mapSecondaryStorage
	fail bool
}

func (w *wiringToggleStorage) Set(key, value string, ttl *int) error {
	if w.fail {
		return errors.New("secondary unavailable")
	}
	return w.mapSecondaryStorage.Set(key, value, ttl)
}

func TestWiringV1_UpdateUserSecondaryFailureIsLoud(t *testing.T) {
	db := newParityMemAdapter()
	store := &wiringToggleStorage{mapSecondaryStorage: newMapSecondaryStorage(true)}
	opts := emailAuthTestOptions(db)
	opts.SecondaryStorage = store
	api := wiringSecondaryAPI(t, opts)
	first, _ := wiringSignUpIn(t, api, "wire-update-loud@test.com", "password123")

	store.fail = true
	resp := api.Post("/api/auth/update-user", map[string]any{"name": "Wired"},
		"Cookie: "+signedSessionHeader(t, opts, first))
	if resp.Code != 500 || !strings.Contains(resp.Body.String(), types.ErrFailedToUpdateUser) {
		t.Fatalf("update-user with failing secondary = %d, want 500 FAILED_TO_UPDATE_USER: %s", resp.Code, resp.Body.String())
	}
}

// (upstream deleteUserSessions fan-out) while preserving the replacement
func TestWiringV1_ChangePasswordClearsSecondarySessions(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	store := newMapSecondaryStorage(true)
	opts := emailAuthTestOptions(db)
	opts.SecondaryStorage = store
	opts.Session.StoreSessionInDatabase = true
	api := wiringSecondaryAPI(t, opts)
	first, second := wiringSignUpIn(t, api, "wire-change-pw@test.com", "password123")

	resp := api.Post("/api/auth/change-password", map[string]any{
		"currentPassword": "password123", "newPassword": "newpassword123",
		"revokeOtherSessions": true,
	}, "Cookie: "+signedSessionHeader(t, opts, first))
	if resp.Code != 200 {
		t.Fatalf("change-password = %d: %s", resp.Code, resp.Body.String())
	}
	replacement := wiringTokenOf(t, resp)

	for _, token := range []string{first, second} {
		if store.has(token) {
			t.Fatalf("revoked token %s must leave secondary storage", token)
		}
		if _, err := resolveGetSession(ctx, opts, getSessionRequest{token: token, headers: CookieRequestHeaders{}}); err == nil {
			t.Fatalf("revoked token %s must not resolve", token)
		}
		if row, _ := db.FindOne(ctx, "session", []types.Where{{Field: "token", Value: token}}, nil); row != nil {
			t.Fatalf("revoked token %s must leave the database", token)
		}
	}
	cached, err := findSecondarySession(opts, replacement)
	if err != nil || cached == nil {
		t.Fatalf("replacement lookup: %v %v", cached, err)
	}
	if _, err := resolveGetSession(ctx, opts, getSessionRequest{token: replacement, headers: CookieRequestHeaders{}}); err != nil {
		t.Fatalf("replacement must resolve: %v", err)
	}
}

// Task A.3: verify-email flips emailVerified across secondary sessions.
func TestWiringV1_VerifyEmailFlipsSecondarySessions(t *testing.T) {
	db := newParityMemAdapter()
	store := newMapSecondaryStorage(true)
	opts := emailAuthTestOptions(db)
	opts.SecondaryStorage = store
	var token string
	opts.EmailVerification.SendVerificationEmail = func(data types.VerificationEmailData) error {
		token = data.Token
		return nil
	}
	api := wiringSecondaryAPI(t, opts)
	first, second := wiringSignUpIn(t, api, "wire-verify@test.com", "password123")

	if resp := api.Post("/api/auth/send-verification-email", map[string]any{
		"email": "wire-verify@test.com",
	}, "Cookie: "+signedSessionHeader(t, opts, first)); resp.Code != 200 {
		t.Fatalf("send = %d: %s", resp.Code, resp.Body.String())
	}
	if token == "" {
		t.Fatal("expected a verification token")
	}
	if resp := api.Post("/api/auth/verify-email", map[string]any{"token": token}); resp.Code != 200 {
		t.Fatalf("verify = %d: %s", resp.Code, resp.Body.String())
	}
	for _, sessionToken := range []string{first, second} {
		cached, err := findSecondarySession(opts, sessionToken)
		if err != nil || cached == nil {
			t.Fatalf("token %s lookup: %v %v", sessionToken, cached, err)
		}
		if !cached.User.EmailVerified {
			t.Fatalf("token %s cached user still unverified (stale copy survived)", sessionToken)
		}
	}
}

// email-verification.go sendVerificationEmailForUser, upstream #8757).
func TestWiringV1_VerifyEmailHookAPIErrorPropagates(t *testing.T) {
	boot := func(t *testing.T, mutate func(*types.Options)) (humatest.TestAPI, string) {
		t.Helper()
		db := newParityMemAdapter()
		store := newMapSecondaryStorage(true)
		opts := emailAuthTestOptions(db)
		opts.SecondaryStorage = store
		var token string
		opts.EmailVerification.SendVerificationEmail = func(data types.VerificationEmailData) error {
			token = data.Token
			return nil
		}
		mutate(&opts)
		api := wiringSecondaryAPI(t, opts)
		first, _ := wiringSignUpIn(t, api, "wire-hook@test.com", "password123")
		if resp := api.Post("/api/auth/send-verification-email", map[string]any{
			"email": "wire-hook@test.com",
		}, "Cookie: "+signedSessionHeader(t, opts, first)); resp.Code != 200 {
			t.Fatalf("send = %d: %s", resp.Code, resp.Body.String())
		}
		return api, token
	}

	t.Run("before hook keeps 403", func(t *testing.T) {
		api, token := boot(t, func(opts *types.Options) {
			opts.EmailVerification.BeforeEmailVerification = func(*types.User) error {
				return types.HttpError{Code: "WIRING_VERIFY_BLOCKED", Message: "blocked", Status: 403}
			}
		})
		resp := api.Post("/api/auth/verify-email", map[string]any{"token": token})
		if resp.Code != 403 || !strings.Contains(resp.Body.String(), "WIRING_VERIFY_BLOCKED") {
			t.Fatalf("verify with throwing before-hook = %d, want 403 WIRING_VERIFY_BLOCKED: %s", resp.Code, resp.Body.String())
		}
	})

	t.Run("after hook keeps 429", func(t *testing.T) {
		api, token := boot(t, func(opts *types.Options) {
			opts.EmailVerification.AfterEmailVerification = func(*types.User) error {
				return types.HttpError{Code: "WIRING_AFTER_LIMITED", Message: "limited", Status: 429}
			}
		})
		resp := api.Post("/api/auth/verify-email", map[string]any{"token": token})
		if resp.Code != 429 || !strings.Contains(resp.Body.String(), "WIRING_AFTER_LIMITED") {
			t.Fatalf("verify with throwing after-hook = %d, want 429 WIRING_AFTER_LIMITED: %s", resp.Code, resp.Body.String())
		}
	})
}

// Task B: a hook-thrown APIError keeps its status on the delete-user path
func TestWiringV1_DeleteUserHookAPIErrorPropagates(t *testing.T) {
	boot := func(t *testing.T, mutate func(*types.Options)) (humatest.TestAPI, string) {
		t.Helper()
		db := newParityMemAdapter()
		opts := emailAuthTestOptions(db)
		opts.User.DeleteUser.Enabled = true
		mutate(&opts)
		api := wiringSecondaryAPI(t, opts)
		credsSignInSeed(t, api, "wire-del-hook@test.com", "password123")
		return api, credsAuthCookie(t, api, "wire-del-hook@test.com", "password123")
	}

	t.Run("before hook keeps 403", func(t *testing.T) {
		api, cookie := boot(t, func(opts *types.Options) {
			opts.User.DeleteUser.BeforeDelete = func(*types.User) error {
				return types.HttpError{Code: "WIRING_DELETE_BLOCKED", Message: "blocked", Status: 403}
			}
		})
		resp := api.Post("/api/auth/delete-user", map[string]any{}, "Cookie: "+cookie)
		if resp.Code != 403 || !strings.Contains(resp.Body.String(), "WIRING_DELETE_BLOCKED") {
			t.Fatalf("delete with throwing before-hook = %d, want 403 WIRING_DELETE_BLOCKED: %s", resp.Code, resp.Body.String())
		}
	})

	t.Run("after hook keeps 429", func(t *testing.T) {
		db := newParityMemAdapter()
		opts := emailAuthTestOptions(db)
		opts.User.DeleteUser.Enabled = true
		opts.User.DeleteUser.AfterDelete = func(*types.User) error {
			return types.HttpError{Code: "WIRING_DELETE_AFTER_LIMITED", Message: "limited", Status: 429}
		}
		api := wiringSecondaryAPI(t, opts)
		credsSignInSeed(t, api, "wire-del-after@test.com", "password123")
		cookie := credsAuthCookie(t, api, "wire-del-after@test.com", "password123")
		resp := api.Post("/api/auth/delete-user", map[string]any{}, "Cookie: "+cookie)
		if resp.Code != 429 || !strings.Contains(resp.Body.String(), "WIRING_DELETE_AFTER_LIMITED") {
			t.Fatalf("delete with throwing after-hook = %d, want 429 WIRING_DELETE_AFTER_LIMITED: %s", resp.Code, resp.Body.String())
		}
		if row, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: "wire-del-after@test.com"}}, nil); row != nil {
			t.Fatal("after-hook failure must still bracket the committed delete (upstream direct await)")
		}
	})
}
