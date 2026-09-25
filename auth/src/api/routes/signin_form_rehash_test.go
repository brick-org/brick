package routes

// G2/G3/G7 lane (PARITY_V2.md P02 second-pass gaps; upstream sign-in.ts @
// 5468e6bf): form-urlencoded accept (G2, sign-in.ts:406-407,446-449),
// EMAIL_PASSWORD_DISABLED typed code (G3, sign-in.ts:512-520), and
// UpgradeHashIfNeeded rotation wiring (G7).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/crypto"
	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
	"golang.org/x/crypto/bcrypt"
)

func g2SignInAPI(t *testing.T, opts types.Options) humatest.TestAPI {
	t.Helper()
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	SignUpEmail(api, "/api/auth", opts)
	SignInEmail(api, "/api/auth", opts)
	return api
}

// bodies (upstream allowedMediaTypes json+form), mirroring the sign-up
func TestSignInForm_SignInFormURLEncoded(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	api := g2SignInAPI(t, opts)
	credsSignInSeed(t, api, "g2-form@test.com", "password123")

	form := url.Values{
		"email":      {"g2-form@test.com"},
		"password":   {"password123"},
		"rememberMe": {"false"},
	}
	resp := api.Post("/api/auth/sign-in/email",
		"Content-Type: application/x-www-form-urlencoded",
		strings.NewReader(form.Encode()))
	if resp.Code != http.StatusOK {
		t.Fatalf("form sign-in status = %d, want 200: %s", resp.Code, resp.Body.String())
	}
	var body struct {
		Token string `json:"token"`
		User  struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Token == "" {
		t.Fatal("form sign-in must return a session token")
	}
	if body.User.Email != "g2-form@test.com" {
		t.Fatalf("user email = %q, want g2-form@test.com", body.User.Email)
	}
}

// G2: form bodies must validate exactly like JSON bodies: a missing required
func TestSignInForm_SignInFormValidationParity(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	api := g2SignInAPI(t, opts)
	credsSignInSeed(t, api, "g2-formval@test.com", "password123")

	post := func(form url.Values) int {
		resp := api.Post("/api/auth/sign-in/email",
			"Content-Type: application/x-www-form-urlencoded",
			strings.NewReader(form.Encode()))
		return resp.Code
	}

	t.Run("missing password is a client error", func(t *testing.T) {
		code := post(url.Values{"email": {"g2-formval@test.com"}})
		if code < 400 || code >= 500 {
			t.Fatalf("form missing password status = %d, want 4xx", code)
		}
	})

	t.Run("non-boolean rememberMe is a client error", func(t *testing.T) {
		code := post(url.Values{
			"email": {"g2-formval@test.com"}, "password": {"password123"},
			"rememberMe": {"banana"},
		})
		if code < 400 || code >= 500 {
			t.Fatalf("form garbage rememberMe status = %d, want 4xx", code)
		}
	})
}

// EMAIL_PASSWORD_DISABLED code (upstream sign-in.ts:512-520), not a plain
func TestSignInForm_SignInEmailPasswordDisabledCode(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.EmailAndPassword.Enabled = false
	api := g2SignInAPI(t, opts)

	resp := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": "g2-disabled@test.com", "password": "password123",
	})
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("disabled status = %d, want 400: %s", resp.Code, resp.Body.String())
	}
	body := resp.Body.String()
	if !strings.Contains(body, "EMAIL_PASSWORD_DISABLED") {
		t.Fatalf("disabled body must carry EMAIL_PASSWORD_DISABLED, got %s", body)
	}
	if !strings.Contains(body, "Email and password is not enabled") {
		t.Fatalf("disabled body must carry the upstream message, got %s", body)
	}
}

// G7: a legacy bcrypt credential hash rotates to the scrypt format on a
func TestSignInForm_SignInBcryptHashRotatedToScrypt(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	ctx := context.Background()
	now := time.Now().UTC()

	legacy, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt seed: %v", err)
	}
	if _, err := db.Create(ctx, "user", map[string]any{
		"id": "user-g2-rehash", "email": "g2-rehash@test.com", "emailVerified": false,
		"name": "Rehash", "createdAt": now, "updatedAt": now,
	}, nil); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.Create(ctx, "account", map[string]any{
		"id": "acct-g2-rehash", "userId": "user-g2-rehash", "providerId": "credential",
		"accountId": "user-g2-rehash", "password": string(legacy),
		"createdAt": now, "updatedAt": now,
	}, nil); err != nil {
		t.Fatalf("seed account: %v", err)
	}

	api := g2SignInAPI(t, opts)
	resp := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": "g2-rehash@test.com", "password": "password123",
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("sign-in = %d: %s", resp.Code, resp.Body.String())
	}

	accountWhere := []types.Where{
		{Field: "userId", Value: "user-g2-rehash"},
		{Field: "providerId", Value: "credential", Connector: "AND"},
	}
	row, err := db.FindOne(ctx, "account", accountWhere, nil)
	if err != nil || row == nil {
		t.Fatalf("account lookup: %v", err)
	}
	stored, _ := row["password"].(string)
	if stored == string(legacy) {
		t.Fatal("credential hash was not rotated after sign-in")
	}
	if strings.HasPrefix(stored, "$2a$") || strings.HasPrefix(stored, "$2b$") || strings.HasPrefix(stored, "$2y$") {
		t.Fatalf("rotated hash is still bcrypt: %q", stored)
	}
	if !strings.Contains(stored, ":") {
		t.Fatalf("rotated hash is not scrypt format: %q", stored)
	}
	if !crypto.VerifyPassword(stored, "password123") {
		t.Fatal("rotated hash must verify the password")
	}

	again := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": "g2-rehash@test.com", "password": "password123",
	})
	if again.Code != http.StatusOK {
		t.Fatalf("second sign-in = %d: %s", again.Code, again.Body.String())
	}
}

// G7: custom Password.Verify hooks opt out of automatic rotation — the
func TestSignInForm_SignInCustomVerifySkipsRotation(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.EmailAndPassword.Password.Verify = func(data types.PasswordVerifyData) (bool, error) {
		return crypto.VerifyPassword(data.Hash, data.Password), nil
	}
	ctx := context.Background()
	now := time.Now().UTC()

	legacy, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt seed: %v", err)
	}
	if _, err := db.Create(ctx, "user", map[string]any{
		"id": "user-g2-custom", "email": "g2-custom@test.com", "emailVerified": false,
		"name": "Custom", "createdAt": now, "updatedAt": now,
	}, nil); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.Create(ctx, "account", map[string]any{
		"id": "acct-g2-custom", "userId": "user-g2-custom", "providerId": "credential",
		"accountId": "user-g2-custom", "password": string(legacy),
		"createdAt": now, "updatedAt": now,
	}, nil); err != nil {
		t.Fatalf("seed account: %v", err)
	}

	api := g2SignInAPI(t, opts)
	resp := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": "g2-custom@test.com", "password": "password123",
	})
	if resp.Code != http.StatusOK {
		t.Fatalf("sign-in = %d: %s", resp.Code, resp.Body.String())
	}
	row, err := db.FindOne(ctx, "account", []types.Where{
		{Field: "userId", Value: "user-g2-custom"},
		{Field: "providerId", Value: "credential", Connector: "AND"},
	}, nil)
	if err != nil || row == nil {
		t.Fatalf("account lookup: %v", err)
	}
	if stored, _ := row["password"].(string); stored != string(legacy) {
		t.Fatalf("custom-verify sign-in must not rotate the hash, got %q", stored)
	}
}
