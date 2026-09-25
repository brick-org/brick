package routes

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2/humatest"
)

// Pinned upstream: sign-in.test.ts — core (non-social, non-CSRF,
// non-origin-middleware) legs.

func credsSignInSeed(t *testing.T, api humatest.TestAPI, email, password string) {
	t.Helper()
	if resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "Seed", "email": email, "password": password,
	}); resp.Code != 200 {
		t.Fatalf("seed sign-up = %d: %s", resp.Code, resp.Body.String())
	}
}

// sessionCookieOf extracts a forwardable "name=value" Cookie header from a
func sessionCookieOf(t *testing.T, resp *httptest.ResponseRecorder) string {
	t.Helper()
	for _, raw := range resp.Header().Values("Set-Cookie") {
		if seg, _, _ := strings.Cut(raw, ";"); strings.Contains(seg, "=") {
			return seg
		}
	}
	t.Fatal("no Set-Cookie with session cookie")
	return ""
}

// sign-in.test.ts "logs expected auth validation failures below error
func TestSignIn_SignInWarnLogs(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	var calls [][2]string
	opts.Logger.Log = func(level, message string, _ ...any) {
		calls = append(calls, [2]string{level, message})
	}
	api := credsSignUpAPI(t, opts)
	credsSignInSeed(t, api, "warn-target@test.com", "password123")

	calls = nil
	resp := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": "warn-target@test.com", "password": "wrong-password",
	})
	if resp.Code != 401 {
		t.Fatalf("wrong-password status = %d, want 401: %s", resp.Code, resp.Body.String())
	}
	if !credsLogged(calls, "warn", "Invalid password") {
		t.Fatalf("expected warn 'Invalid password', got %#v", calls)
	}

	calls = nil
	resp = api.Post("/api/auth/sign-in/email", map[string]any{
		"email": "missing-sign-in@test.com", "password": "password123",
	})
	if resp.Code != 401 {
		t.Fatalf("unknown-user status = %d, want 401: %s", resp.Code, resp.Body.String())
	}
	if !credsLogged(calls, "warn", "User not found") {
		t.Fatalf("expected warn 'User not found', got %#v", calls)
	}
	for _, c := range calls {
		if c[0] == "error" {
			t.Fatalf("no error-level logs expected, got %#v", calls)
		}
	}
}

func credsLogged(calls [][2]string, level, substr string) bool {
	for _, c := range calls {
		if c[0] == level && strings.Contains(c[1], substr) {
			return true
		}
	}
	return false
}

// sign-in.test.ts "should return additionalFields in signInEmail response".
func TestSignIn_SignInAdditionalFields(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.User.Model.AdditionalFields = map[string]types.FieldAttribute{
		"newField": {Type: "string", Required: credsFalsePtr()},
		"isAdmin":  {Type: "boolean", DefaultValue: true, Input: credsFalsePtr()},
	}
	api := credsSignUpAPI(t, opts)
	if resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "SignIn Test", "email": "signin-additional@test.com",
		"password": "password123", "newField": "signin-value",
	}); resp.Code != 200 {
		t.Fatalf("seed sign-up = %d: %s", resp.Code, resp.Body.String())
	}
	resp := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": "signin-additional@test.com", "password": "password123",
	})
	if resp.Code != 200 {
		t.Fatalf("sign-in = %d: %s", resp.Code, resp.Body.String())
	}
	var body struct {
		User map[string]any `json:"user"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.User["newField"] != "signin-value" {
		t.Fatalf("newField = %#v", body.User["newField"])
	}
	if body.User["isAdmin"] != true {
		t.Fatalf("isAdmin default must surface, got %#v", body.User["isAdmin"])
	}
}

// sign-in.test.ts "email case insensitivity" legs.
func TestSignIn_SignInCaseInsensitive(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	api := credsSignUpAPI(t, opts)
	mixed, password := "Test.User@Example.COM", "securePassword123"
	if resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "Test User", "email": mixed, "password": password,
	}); resp.Code != 200 {
		t.Fatalf("seed sign-up = %d: %s", resp.Code, resp.Body.String())
	}
	for _, variant := range []string{
		"test.user@example.com",
		"TEST.USER@EXAMPLE.COM",
		mixed,
	} {
		resp := api.Post("/api/auth/sign-in/email", map[string]any{
			"email": variant, "password": password,
		})
		if resp.Code != 200 {
			t.Fatalf("sign-in with %q = %d: %s", variant, resp.Code, resp.Body.String())
		}
		var body struct {
			User struct {
				Email string `json:"email"`
			} `json:"user"`
		}
		if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body.User.Email != "test.user@example.com" {
			t.Fatalf("email = %q, want lowercase", body.User.Email)
		}
	}
}

// sign-in.test.ts-adjacent (sign-in.ts:551 "Password not found"): a
func TestSignIn_SignInPasswordlessCredentialAccount(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	now := time.Now().UTC()
	if _, err := db.Create(context.Background(), "user", map[string]any{
		"id": "user-pwless", "email": "pwless@test.com", "emailVerified": false,
		"name": "Pwless", "createdAt": now, "updatedAt": now,
	}, nil); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.Create(context.Background(), "account", map[string]any{
		"id": "acct-pwless", "userId": "user-pwless", "providerId": "credential",
		"accountId": "user-pwless", "createdAt": now, "updatedAt": now,
	}, nil); err != nil {
		t.Fatalf("seed account: %v", err)
	}
	var calls [][2]string
	opts.Logger.Log = func(level, message string, _ ...any) {
		calls = append(calls, [2]string{level, message})
	}
	api := credsSignUpAPI(t, opts)
	resp := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": "pwless@test.com", "password": "password123",
	})
	if resp.Code != 401 {
		t.Fatalf("status = %d, want 401: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), types.ErrInvalidEmailOrPassword) {
		t.Fatalf("code must stay generic: %s", resp.Body.String())
	}
	if !credsLogged(calls, "warn", "Password not found") {
		t.Fatalf("expected warn 'Password not found', got %#v", calls)
	}
}
