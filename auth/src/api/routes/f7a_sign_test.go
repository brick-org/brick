package routes

// F7A lane (PARITY_V3 gap 9 + gap 16 sign-up minors; upstream
// origin-check.ts:89-151 + sign-up.ts @ 5468e6bf):
//   - untrusted callbackURL on sign-in/sign-up must 403 INVALID_CALLBACK_URL
//     (global middleware) instead of embed-and-continue.
//   - sign-up disabled must carry EMAIL_PASSWORD_SIGN_UP_DISABLED code.
//   - customSyntheticUser forwards only user.additionalFields keys.
//   - verification token/URL minted even when no sender configured.

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/types"
)

func TestF7A_SignInUntrustedCallback403(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	api := credsSignUpAPI(t, opts)
	credsSignInSeed(t, api, "f7a-signin@test.com", "password123")

	resp := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": "f7a-signin@test.com", "password": "password123",
		"callbackURL": "https://evil.example.com/cb",
	})
	if resp.Code != http.StatusForbidden {
		t.Fatalf("untrusted sign-in callback status = %d, want 403: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), types.ErrInvalidCallbackURL) {
		t.Fatalf("body must carry INVALID_CALLBACK_URL, got %s", resp.Body.String())
	}
}

func TestF7A_SignUpUntrustedCallback403(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	api := credsSignUpAPI(t, opts)

	resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "F7A", "email": "f7a-signup@test.com", "password": "password123",
		"callbackURL": "https://evil.example.com/cb",
	})
	if resp.Code != http.StatusForbidden {
		t.Fatalf("untrusted sign-up callback status = %d, want 403: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), types.ErrInvalidCallbackURL) {
		t.Fatalf("body must carry INVALID_CALLBACK_URL, got %s", resp.Body.String())
	}
}

func TestF7A_SignUpDisabledCode(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.EmailAndPassword.DisableSignUp = true
	api := credsSignUpAPI(t, opts)

	resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "F7A", "email": "f7a-disabled@test.com", "password": "password123",
	})
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("disabled status = %d, want 400: %s", resp.Code, resp.Body.String())
	}
	body := resp.Body.String()
	if !strings.Contains(body, "EMAIL_PASSWORD_SIGN_UP_DISABLED") {
		t.Fatalf("disabled body must carry EMAIL_PASSWORD_SIGN_UP_DISABLED, got %s", body)
	}
	if !strings.Contains(body, "Email and password sign up is not enabled") {
		t.Fatalf("disabled body must carry upstream message, got %s", body)
	}
}

func TestF7A_SyntheticScopeOnlyUserAdditionalFields(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.EmailAndPassword.RequireEmailVerification = true
	opts.User.Model.AdditionalFields = map[string]types.FieldAttribute{
		"allowed": {Type: "string", Required: credsFalsePtr()},
	}
	opts.Schema = types.PluginSchema{
		"user": types.TableSchema{Fields: map[string]types.FieldAttribute{
			"pluginField": {Type: "string"},
		}},
	}
	var gotAdditional map[string]any
	opts.EmailAndPassword.CustomSyntheticUser = func(data types.SyntheticUserData) map[string]any {
		gotAdditional = map[string]any{}
		for k, v := range data.AdditionalFields {
			gotAdditional[k] = v
		}
		now := time.Now().UTC()
		return map[string]any{
			"id": data.ID, "email": data.CoreFields.Email, "emailVerified": false,
			"name": data.CoreFields.Name, "image": data.CoreFields.Image,
			"createdAt": now, "updatedAt": now,
		}
	}
	api := credsSignUpAPI(t, opts)

	first := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "First", "email": "f7a-synth@test.com", "password": "password123",
		"allowed": "yes", "pluginField": "plug",
	})
	if first.Code != http.StatusOK {
		t.Fatalf("first sign-up = %d: %s", first.Code, first.Body.String())
	}
	second := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "Second", "email": "f7a-synth@test.com", "password": "password456",
		"allowed": "yes2", "pluginField": "plug2",
	})
	if second.Code != http.StatusOK {
		t.Fatalf("duplicate sign-up = %d: %s", second.Code, second.Body.String())
	}
	if gotAdditional == nil {
		t.Fatal("CustomSyntheticUser must be invoked on the duplicate leg")
	}
	if _, ok := gotAdditional["allowed"]; !ok {
		t.Fatalf("user additionalFields key must be forwarded, got %#v", gotAdditional)
	}
	if _, ok := gotAdditional["pluginField"]; ok {
		t.Fatalf("plugin field must NOT be forwarded to customSyntheticUser, got %#v", gotAdditional)
	}
}

func TestF7A_SignUpMintEvenWithoutSender(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.Secret = ""
	opts.Secrets = nil
	opts.EmailVerification.SendOnSignUp = boolPtr(true)
	opts.EmailAndPassword.AutoSignIn = boolPtr(false)
	// No sender configured.
	opts.EmailVerification.SendVerificationEmail = nil
	opts.EmailVerification.SendVerificationEmailRequest = nil
	api := credsSignUpAPI(t, opts)

	resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "F7A", "email": "f7a-mint@test.com", "password": "password123",
	})
	// Upstream mints the token before checking the sender (sign-up.ts:395-407):
	// with an empty secret the mint fails 500 even when no sender is set.
	// Pre-fix skips the mint entirely and answers 200.
	if resp.Code != http.StatusInternalServerError {
		t.Fatalf("mint-skip status = %d, want 500: %s", resp.Code, resp.Body.String())
	}
}
