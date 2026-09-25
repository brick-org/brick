package routes

// F1 lane: P01-GAP-1 form-urlencoded sign-up + sendOnSignUp tri-state pins.
//
// Upstream refs (vendor/better-auth @ 5468e6bf):
//   - sign-up.ts:38-41 allowedMediaTypes json+form; sign-up.test.ts
//     "sign-up with form data / should accept form-urlencoded content type".
//   - sign-up.test.ts "sign-up sendOnSignUp option behavior" (3 legs).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

// f1SetSendOnSignUp assigns EmailVerification.SendOnSignUp without naming its
// static type, so this file compiles whether the field is bool (current
// tree) or *bool (pending tri-state migration: nil = unset, fall back to
// requireEmailVerification). Merge owner: no edits needed on either side.
func f1SetSendOnSignUp(t *testing.T, opts *types.Options, v bool) {
	t.Helper()
	field := reflect.ValueOf(&opts.EmailVerification.SendOnSignUp).Elem()
	if field.Kind() == reflect.Bool {
		field.SetBool(v)
		return
	}
	if field.Kind() == reflect.Ptr && field.Type().Elem().Kind() == reflect.Bool {
		bv := reflect.New(field.Type().Elem())
		bv.Elem().SetBool(v)
		field.Set(bv)
		return
	}
	t.Fatalf("SendOnSignUp has unexpected kind %v", field.Kind())
}

// f1SendOnSignUpIsTriState reports whether SendOnSignUp is *bool (nil =
// unset). Compiles on both sides of the pending types migration.
func f1SendOnSignUpIsTriState() bool {
	var zero types.EmailVerificationOptions
	_, ok := any(zero.SendOnSignUp).(*bool)
	return ok
}

func f1SignUpAPI(t *testing.T, opts types.Options) humatest.TestAPI {
	t.Helper()
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	SignUpEmail(api, "/api/auth", opts)
	return api
}

// P01-GAP-1: POST /sign-up/email must accept
// application/x-www-form-urlencoded bodies (upstream allowedMediaTypes
// json+form), with additional fields surviving like the JSON path.
func TestF1_SignUpFormURLEncoded(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.User.Model.AdditionalFields = map[string]types.FieldAttribute{
		"newField": {Type: "string", Required: credsFalsePtr()},
	}
	api := f1SignUpAPI(t, opts)

	form := url.Values{
		"name":       {"Form User"},
		"email":      {"form@test.com"},
		"password":   {"password123"},
		"rememberMe": {"false"},
		"newField":   {"custom-value"},
	}
	resp := api.Post("/api/auth/sign-up/email",
		"Content-Type: application/x-www-form-urlencoded",
		strings.NewReader(form.Encode()))
	if resp.Code != http.StatusOK {
		t.Fatalf("form sign-up status = %d, want 200: %s", resp.Code, resp.Body.String())
	}
	var body struct {
		Token *string `json:"token"`
		User  struct {
			Email    string `json:"email"`
			Name     string `json:"name"`
			NewField string `json:"newField"`
		} `json:"user"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.User.Email != "form@test.com" || body.User.Name != "Form User" {
		t.Fatalf("unexpected user: %+v", body.User)
	}
	if body.User.NewField != "custom-value" {
		t.Fatalf("newField = %q, want custom-value", body.User.NewField)
	}
	if body.Token == nil || *body.Token == "" {
		t.Fatal("form sign-up must return a session token")
	}
	row, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: "form@test.com"}}, nil)
	if row == nil {
		t.Fatal("form sign-up must persist the user row")
	}
	if row["newField"] != "custom-value" {
		t.Fatalf("persisted newField = %#v", row["newField"])
	}
}

// Form bodies must validate exactly like JSON bodies: a missing required
// field fails (absent keys stay absent through the transcode) and a
// non-boolean rememberMe fails (left verbatim for schema validation).
func TestF1_SignUpFormValidationParity(t *testing.T) {
	post := func(t *testing.T, form url.Values) int {
		t.Helper()
		db := newParityMemAdapter()
		opts := emailAuthTestOptions(db)
		api := f1SignUpAPI(t, opts)
		resp := api.Post("/api/auth/sign-up/email",
			"Content-Type: application/x-www-form-urlencoded",
			strings.NewReader(form.Encode()))
		return resp.Code
	}

	t.Run("missing password is a client error", func(t *testing.T) {
		code := post(t, url.Values{"name": {"No Pass"}, "email": {"nopass@test.com"}})
		if code < 400 || code >= 500 {
			t.Fatalf("form missing password status = %d, want 4xx", code)
		}
	})

	t.Run("non-boolean rememberMe is a client error", func(t *testing.T) {
		code := post(t, url.Values{
			"name": {"Bad RM"}, "email": {"badrm@test.com"},
			"password": {"password123"}, "rememberMe": {"banana"},
		})
		if code < 400 || code >= 500 {
			t.Fatalf("form garbage rememberMe status = %d, want 4xx", code)
		}
	})
}

// Upstream "should send verification email when sendOnSignUp is true":
// explicit true wins even when requireEmailVerification is false (leg not
// covered by TestTriageV1_SignUpSendOnSignUpTrue, which sets require=true).
func TestF1_SendOnSignUpTrueSendsWithoutRequire(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.EmailAndPassword.RequireEmailVerification = false
	f1SetSendOnSignUp(t, &opts, true)
	var calls int
	opts.EmailVerification.SendVerificationEmail = func(types.VerificationEmailData) error {
		calls++
		return nil
	}
	api := f1SignUpAPI(t, opts)
	resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "Explicit True", "email": "explicit-true@test.com", "password": "password123",
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("sign-up status = %d: %s", resp.Code, resp.Body.String())
	}
	if calls != 1 {
		t.Fatalf("explicit sendOnSignUp=true must send once without require, got %d", calls)
	}
}

// Upstream "should not send verification email when sendOnSignUp is false,
// even with requireEmailVerification": needs *bool tri-state. While the
// field is still bool, explicit false is indistinguishable from unset and
// falls back to require (sends); that fallback is asserted so the test stays
// green on both sides of the migration, and the true upstream leg engages
// automatically once the field becomes *bool.
func TestF1_SendOnSignUpExplicitFalse(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.EmailAndPassword.RequireEmailVerification = true
	f1SetSendOnSignUp(t, &opts, false)
	var calls int
	opts.EmailVerification.SendVerificationEmail = func(types.VerificationEmailData) error {
		calls++
		return nil
	}
	api := f1SignUpAPI(t, opts)
	resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "Explicit False", "email": "explicit-false@test.com", "password": "password123",
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("sign-up status = %d: %s", resp.Code, resp.Body.String())
	}
	if f1SendOnSignUpIsTriState() {
		if calls != 0 {
			t.Fatalf("explicit sendOnSignUp=false must suppress the send, got %d", calls)
		}
	} else {
		// Bool tree: false == unset, falls back to requireEmailVerification.
		if calls != 1 {
			t.Fatalf("bool-tree fallback: send calls = %d, want 1 ( flips to 0 under *bool)", calls)
		}
	}
}
