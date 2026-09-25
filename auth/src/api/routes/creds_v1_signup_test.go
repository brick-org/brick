package routes

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

func credsFalsePtr() *bool { v := false; return &v }

// Pinned upstream: sign-up.test.ts — core (non-social, non-CSRF) legs.

func credsSignUpAPI(t *testing.T, opts types.Options) humatest.TestAPI {
	t.Helper()
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	SignUpEmail(api, "/api/auth", opts)
	SignInEmail(api, "/api/auth", opts)
	return api
}

// sign-up.test.ts "should return additionalFields in signUpEmail response":
// declared additional fields persist and echo with defaults applied.
func TestCredsV1_SignUpAdditionalFields(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.User.Model.AdditionalFields = map[string]types.FieldAttribute{
		"newField": {Type: "string", Required: credsFalsePtr()},
		"isAdmin":  {Type: "boolean", DefaultValue: true, Input: credsFalsePtr()},
	}
	api := credsSignUpAPI(t, opts)
	resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "Additional Fields Test", "email": "additional-fields@test.com",
		"password": "password123", "newField": "custom-value",
	})
	if resp.Code != 200 {
		t.Fatalf("sign-up status = %d, want 200: %s", resp.Code, resp.Body.String())
	}
	var body struct {
		Token *string `json:"token"`
		User  struct {
			Email    string `json:"email"`
			NewField string `json:"newField"`
			IsAdmin  bool   `json:"isAdmin"`
		} `json:"user"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.User.NewField != "custom-value" {
		t.Fatalf("newField = %q, want custom-value", body.User.NewField)
	}
	if !body.User.IsAdmin {
		t.Fatal("defaultValue isAdmin=true must be applied and returned")
	}
	row, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: "additional-fields@test.com"}}, nil)
	if row == nil {
		t.Fatal("user row must persist")
	}
	if row["newField"] != "custom-value" {
		t.Fatalf("persisted newField = %#v", row["newField"])
	}
}

// sign-up.test.ts "should not allow user to set the field that is set to
// input: false": a truthy input:false value fails with the upstream message.
func TestCredsV1_SignUpInputFalseRejected(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.User.Model.AdditionalFields = map[string]types.FieldAttribute{
		"role": {Type: "string", Required: credsFalsePtr(), Input: credsFalsePtr()},
	}
	api := credsSignUpAPI(t, opts)
	resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "Input False Test", "email": "input-false@test.com",
		"password": "password123", "role": "admin",
	})
	if resp.Code != 400 {
		t.Fatalf("sign-up status = %d, want 400: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "role is not allowed to be set") {
		t.Fatalf("body must carry the upstream message: %s", resp.Body.String())
	}
	if row, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: "input-false@test.com"}}, nil); row != nil {
		t.Fatal("rejected sign-up must not persist a user")
	}
}

// sign-up.test.ts "should succeed when passing empty name".
func TestCredsV1_SignUpEmptyName(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	api := credsSignUpAPI(t, opts)
	resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "", "email": "noname@test.com", "password": "password123",
	})
	if resp.Code != 200 {
		t.Fatalf("sign-up status = %d, want 200: %s", resp.Code, resp.Body.String())
	}
	var body struct {
		Token string `json:"token"`
		User  struct {
			Name string `json:"name"`
		} `json:"user"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Token == "" {
		t.Fatal("expected a session token")
	}
	if row, _ := db.FindOne(context.Background(), "session", []types.Where{{Field: "token", Value: body.Token}}, nil); row == nil {
		t.Fatal("session row must exist for the returned token")
	}
}

// sign-up.test.ts "should throw status code 400 when passing invalid body"
// (missing password surfaces a client error, never a user row).
func TestCredsV1_SignUpMissingPasswordIsClientError(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	api := credsSignUpAPI(t, opts)
	resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "Test", "email": "body-validation@test.com",
	})
	if resp.Code < 400 || resp.Code >= 500 {
		t.Fatalf("sign-up status = %d, want 4xx: %s", resp.Code, resp.Body.String())
	}
	if row, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: "body-validation@test.com"}}, nil); row != nil {
		t.Fatal("invalid sign-up must not persist a user")
	}
}

// sign-up.test.ts sendOnSignUp legs: the verification URL must carry the
// callbackURL encoded so it round-trips verbatim.
func TestCredsV1_SignUpVerificationURLEncoding(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.EmailVerification.SendOnSignUp = boolPtr(true)
	var capturedURL, capturedToken string
	opts.EmailVerification.SendVerificationEmail = func(data types.VerificationEmailData) error {
		capturedURL, capturedToken = data.URL, data.Token
		return nil
	}
	api := credsSignUpAPI(t, opts)
	resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "CB", "email": "cb@test.com", "password": "password123",
		"callbackURL": "/dashboard?tab=settings&from=email",
	})
	if resp.Code != 200 {
		t.Fatalf("sign-up status = %d: %s", resp.Code, resp.Body.String())
	}
	if capturedToken == "" {
		t.Fatal("verification email must be sent on sign-up")
	}
	parsed, err := url.Parse(capturedURL)
	if err != nil {
		t.Fatalf("parse sent URL: %v", err)
	}
	if got := parsed.Query().Get("callbackURL"); got != "/dashboard?tab=settings&from=email" {
		t.Fatalf("callbackURL round-trip = %q", got)
	}
	if parsed.Query().Get("from") != "" {
		t.Fatalf("query segments must not leak into the outer URL: %q", capturedURL)
	}
}

// sign-in.test.ts "should not allow duplicate sign-ups with different email
// casing": sign-up stores lowercase and dedupes case-insensitively.
func TestCredsV1_SignUpDuplicateCaseInsensitive(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	api := credsSignUpAPI(t, opts)
	if resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "First", "email": "duplicate.test@example.com", "password": "password123",
	}); resp.Code != 200 {
		t.Fatalf("first sign-up = %d: %s", resp.Code, resp.Body.String())
	}
	resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "Second", "email": "DUPLICATE.TEST@EXAMPLE.COM", "password": "password123",
	})
	if resp.Code == 200 {
		t.Fatalf("case-variant duplicate must fail, got 200: %s", resp.Body.String())
	}
	row, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: "duplicate.test@example.com"}}, nil)
	if row == nil || row["email"] != "duplicate.test@example.com" {
		t.Fatalf("email must be stored lowercase, got %#v", row)
	}
}

// sign-in.test.ts "logs expected auth validation failures below error
// level": short passwords warn without error-level logs.
func TestCredsV1_SignUpShortPasswordWarns(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	var calls [][2]string
	opts.Logger.Log = func(level, message string, _ ...any) {
		calls = append(calls, [2]string{level, message})
	}
	api := credsSignUpAPI(t, opts)
	resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "Short", "email": "short-password@test.com", "password": "short",
	})
	if resp.Code != 400 {
		t.Fatalf("sign-up status = %d, want 400: %s", resp.Code, resp.Body.String())
	}
	warned, errored := false, false
	for _, c := range calls {
		if c[0] == "warn" && strings.Contains(c[1], "Password is too short") {
			warned = true
		}
		if c[0] == "error" {
			errored = true
		}
	}
	if !warned {
		t.Fatalf("expected warn 'Password is too short', got %#v", calls)
	}
	if errored {
		t.Fatalf("no error-level logs expected, got %#v", calls)
	}
}

// sign-up.test.ts enumeration-protection indistinguishability legs
// (#9346): real and synthetic users share image key presence/values, key
// sets, and token:null; the synthetic echoes the request body with a fresh
// id while defaults apply to both.
func TestCredsV1_SyntheticResponseParity(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.EmailAndPassword.RequireEmailVerification = true
	opts.User.Model.AdditionalFields = map[string]types.FieldAttribute{
		"displayName": {Type: "string", Required: credsFalsePtr()},
		"isAdmin":     {Type: "boolean", DefaultValue: false, Input: credsFalsePtr()},
	}
	api := credsSignUpAPI(t, opts)

	firstResp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "First User", "email": "indistinguishable@test.com",
		"password": "password123", "displayName": "FirstDisplay",
	})
	if firstResp.Code != 200 {
		t.Fatalf("first = %d: %s", firstResp.Code, firstResp.Body.String())
	}
	secondResp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "Second Attempt", "email": "indistinguishable@test.com",
		"password": "password456", "displayName": "SecondDisplay",
	})
	if secondResp.Code != 200 {
		t.Fatalf("second = %d: %s", secondResp.Code, secondResp.Body.String())
	}
	var first, second struct {
		Token *string        `json:"token"`
		User  map[string]any `json:"user"`
	}
	if err := json.Unmarshal(firstResp.Body.Bytes(), &first); err != nil {
		t.Fatalf("decode first: %v", err)
	}
	if err := json.Unmarshal(secondResp.Body.Bytes(), &second); err != nil {
		t.Fatalf("decode second: %v", err)
	}
	// Same key sets (order-insensitive here; the Go serializer emits
	// sorted keys deterministically for both sides).
	if len(first.User) != len(second.User) {
		t.Fatalf("key count %d vs %d: %#v vs %#v", len(first.User), len(second.User), first.User, second.User)
	}
	for k := range first.User {
		if _, ok := second.User[k]; !ok {
			t.Fatalf("synthetic user missing key %q: %#v", k, second.User)
		}
	}
	_, firstHasImage := first.User["image"]
	_, secondHasImage := second.User["image"]
	if firstHasImage != secondHasImage || first.User["image"] != second.User["image"] {
		t.Fatalf("image presence/values must match: %#v vs %#v", first.User, second.User)
	}
	if second.Token != nil {
		t.Fatalf("synthetic token must be null, got %v", second.Token)
	}
	if second.User["name"] != "Second Attempt" {
		t.Fatalf("synthetic echoes the request, got %#v", second.User["name"])
	}
	if second.User["id"] == first.User["id"] {
		t.Fatal("synthetic id must be fresh")
	}
	if second.User["isAdmin"] != false || second.User["displayName"] != "SecondDisplay" {
		t.Fatalf("synthetic carries defaults+request fields: %#v", second.User)
	}
}
