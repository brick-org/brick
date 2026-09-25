package routes

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/brick-org/brick/auth/src/types"
)

// P02 sign-in gaps (PARITY_V2.md P02): malformed-email 400 (GAP-1),
// Location header on trusted callbackURL (GAP-2), sendOnSignIn resend
// coverage (GAP-3). Pinned upstream: Better Auth v1.7.5 @ 5468e6bf
// (sign-in.ts:522-525, 625-627, 569-601).

// (upstream sign-in.ts:522-525) instead of falling through to 401.
func TestSignIn_MalformedEmailIs400(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	api := credsSignUpAPI(t, opts)
	credsSignInSeed(t, api, "f2-format@test.com", "password123")

	for _, malformed := range []string{
		"not-an-email",
		"missing-at-sign.com",
		"missing@",
		"@missing-local.com",
		"no-tld@domain",
		"two@@signs.com",
		"space in@email.com",
	} {
		resp := api.Post("/api/auth/sign-in/email", map[string]any{
			"email": malformed, "password": "password123",
		})
		if resp.Code != 400 {
			t.Fatalf("malformed %q status = %d, want 400: %s", malformed, resp.Code, resp.Body.String())
		}
		if !strings.Contains(resp.Body.String(), types.ErrInvalidEmail) {
			t.Fatalf("malformed %q body must carry INVALID_EMAIL, got %s", malformed, resp.Body.String())
		}
		if strings.Contains(resp.Body.String(), types.ErrInvalidEmailOrPassword) {
			t.Fatalf("malformed %q must not leak the 401 credential code, got %s", malformed, resp.Body.String())
		}
	}

	resp := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": "f2-unknown@test.com", "password": "password123",
	})
	if resp.Code != 401 {
		t.Fatalf("unknown-user status = %d, want 401: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), types.ErrInvalidEmailOrPassword) {
		t.Fatalf("unknown user must stay generic, got %s", resp.Body.String())
	}
}

// header (upstream sign-in.ts:625-627) alongside the existing body
func TestSignIn_CallbackURLSetsLocationHeader(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	api := credsSignUpAPI(t, opts)
	credsSignInSeed(t, api, "f2-location@test.com", "password123")

	resp := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": "f2-location@test.com", "password": "password123",
		"callbackURL": "/dashboard",
	})
	if resp.Code != 200 {
		t.Fatalf("sign-in = %d: %s", resp.Code, resp.Body.String())
	}
	var body struct {
		Redirect bool    `json:"redirect"`
		URL      *string `json:"url"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !body.Redirect || body.URL == nil || *body.URL != "/dashboard" {
		t.Fatalf("body redirect/url pair must survive, got %+v", body)
	}
	if loc := resp.Header().Get("Location"); loc != "/dashboard" {
		t.Fatalf("Location = %q, want /dashboard", loc)
	}

	bogus := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": "f2-location@test.com", "password": "password123",
		"callbackURL": "https://evil.example.com/cb",
	})
	if bogus.Code != 403 {
		t.Fatalf("untrusted sign-in = %d, want 403: %s", bogus.Code, bogus.Body.String())
	}
	if !strings.Contains(bogus.Body.String(), types.ErrInvalidCallbackURL) {
		t.Fatalf("untrusted body must carry INVALID_CALLBACK_URL, got %s", bogus.Body.String())
	}
}

// upstream sign-in.ts:588-597) — an unverified sign-in still 403s
func TestSignIn_SendOnSignInResends(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.EmailAndPassword.RequireEmailVerification = true
	opts.EmailVerification.SendOnSignIn = true
	var calls int
	var captured types.VerificationEmailData
	opts.EmailVerification.SendVerificationEmail = func(data types.VerificationEmailData) error {
		calls++
		captured = data
		return nil
	}
	api := credsSignUpAPI(t, opts)
	credsSignInSeed(t, api, "f2-resend@test.com", "password123")
	calls = 0
	captured = types.VerificationEmailData{}

	resp := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": "f2-resend@test.com", "password": "password123",
	})
	if resp.Code != 403 {
		t.Fatalf("status = %d, want 403 EMAIL_NOT_VERIFIED: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), types.ErrEmailNotVerified) {
		t.Fatalf("want EMAIL_NOT_VERIFIED, got %s", resp.Body.String())
	}
	if calls != 1 {
		t.Fatalf("resend calls = %d, want 1", calls)
	}
	if captured.Token == "" || captured.URL == "" {
		t.Fatalf("resend must carry token+URL, got %+v", captured)
	}
	if captured.User == nil || captured.User.Email != "f2-resend@test.com" {
		t.Fatalf("resend user = %#v, want f2-resend@test.com", captured.User)
	}
}
