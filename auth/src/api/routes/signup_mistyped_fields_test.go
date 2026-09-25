package routes

// G1 lane: P01 second-pass — JSON mistyped known fields must 4xx.
// Upstream refs (vendor/better-auth @ 5468e6bf):
//   - sign-up.ts:17-26 zod object (name/email/password strings,
//     image/callbackURL optional strings, rememberMe optional bool).
//   - Form path pins 422 on banana (signup_form_bodies_test.go:134-143).

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

func g1SignUpAPI(t *testing.T, opts types.Options) humatest.TestAPI {
	t.Helper()
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	SignUpEmail(api, "/api/auth", opts)
	return api
}

func TestSignUpMistyped_SignUpJSONMistypedRememberMeIsClientError(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	api := g1SignUpAPI(t, opts)
	resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "G1 User", "email": "g1-rememberme@test.com",
		"password": "password123", "rememberMe": "banana",
	})
	if resp.Code < 400 || resp.Code >= 500 {
		t.Fatalf("JSON mistyped rememberMe status = %d, want 4xx: %s", resp.Code, resp.Body.String())
	}
	if row, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: "g1-rememberme@test.com"}}, nil); row != nil {
		t.Fatal("mistyped sign-up must not persist a user")
	}
}

func TestSignUpMistyped_SignUpJSONMistypedNameIsClientError(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	api := g1SignUpAPI(t, opts)
	resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": 123, "email": "g1-name@test.com",
		"password": "password123",
	})
	if resp.Code < 400 || resp.Code >= 500 {
		t.Fatalf("JSON mistyped name status = %d, want 4xx: %s", resp.Code, resp.Body.String())
	}
	if row, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: "g1-name@test.com"}}, nil); row != nil {
		t.Fatal("mistyped sign-up must not persist a user")
	}
}

func TestSignUpMistyped_SignUpJSONValidStillSucceeds(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	api := g1SignUpAPI(t, opts)
	resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "G1 Valid", "email": "g1-valid@test.com",
		"password": "password123",
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("valid JSON sign-up status = %d, want 200: %s", resp.Code, resp.Body.String())
	}
}

// Unmarshal-level pins: mistyped KNOWN keys must be a decode error (not
func TestSignUpMistyped_SignUpUnmarshalMistypedKnownKeysError(t *testing.T) {
	t.Run("rememberMe banana errors", func(t *testing.T) {
		var b signUpBody
		err := json.Unmarshal([]byte(`{"name":"G1","email":"g1@test.com","password":"password123","rememberMe":"banana"}`), &b)
		if err == nil {
			t.Fatalf("rememberMe banana must be a type error, got absent (RememberMe=%v Extra=%v)", b.RememberMe, b.Extra)
		}
	})
	t.Run("name number errors", func(t *testing.T) {
		var b signUpBody
		err := json.Unmarshal([]byte(`{"name":123,"email":"g1@test.com","password":"password123"}`), &b)
		if err == nil {
			t.Fatalf("numeric name must be a type error, got absent (Name=%q Extra=%v)", b.Name, b.Extra)
		}
	})
	t.Run("unknown keys still passthrough", func(t *testing.T) {
		var b signUpBody
		if err := json.Unmarshal([]byte(`{"name":"G1","email":"g1@test.com","password":"password123","newField":"custom"}`), &b); err != nil {
			t.Fatalf("unknown key must not error: %v", err)
		}
		if b.Extra["newField"] != "custom" {
			t.Fatalf("unknown key must land in Extra, got %#v", b.Extra)
		}
	})
}
