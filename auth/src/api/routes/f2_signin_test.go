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

// P02-GAP-1: a malformed email format answers 400 INVALID_EMAIL
// (upstream sign-in.ts:522-525) instead of falling through to 401.
// The format gate runs before any user lookup, so existence never leaks:
// malformed input is 400 for unknown and seeded addresses alike, while a
// well-formed unknown address stays 401 INVALID_EMAIL_OR_PASSWORD.
func TestF2_SignInMalformedEmailIs400(t *testing.T) {
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

	// Well-formed unknown address keeps the generic 401 (no existence leak
	// in the other direction).
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

// P02-GAP-2: a present, trusted callbackURL sets the Location response
// header (upstream sign-in.ts:625-627) alongside the existing body
// redirect/url pair. An untrusted callbackURL keeps the body pair but
// sets no Location header (no open redirect).
func TestF2_SignInCallbackURLSetsLocationHeader(t *testing.T) {
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

	// Untrusted absolute URL: 403 INVALID_CALLBACK_URL (upstream global
	// middleware; realigned from embed-and-continue by F7a for 100% parity).
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

// P02-GAP-3 (coverage): the sendOnSignIn:true resend leg (sign-in.go:104-117,
// upstream sign-in.ts:588-597) — an unverified sign-in still 403s
// EMAIL_NOT_VERIFIED but resends the verification email once, carrying a
// token and URL.
func TestF2_SignInSendOnSignInResends(t *testing.T) {
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
	calls = 0 // isolate the sign-in resend (sign-up itself sends once)
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
