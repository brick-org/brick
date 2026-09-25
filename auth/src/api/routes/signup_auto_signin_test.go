package routes

import (
	"strings"
	"testing"

	"github.com/brick-org/brick/auth/src/types"
)

// G1: upstream sign-up.ts:236-238 returns the generic duplicate response
// when requireEmailVerification OR autoSignIn === false. Go previously only
// checked RequireEmailVerification, answering 422 for duplicates under
// explicit autoSignIn=false.

// should return synthetic user for existing email when autoSignIn is
func TestSignUpAutoSignIn_AutoSignInFalseDuplicateIsSynthetic(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.EmailAndPassword.AutoSignIn = boolPtr(false)
	api := credsSignUpAPI(t, opts)
	credsSignInSeed(t, api, "g1dupe@test.com", "password123")
	resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "G1", "email": "g1dupe@test.com", "password": "password123",
	})
	if resp.Code != 200 {
		t.Fatalf("duplicate sign-up = %d, want opaque 200: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), `"token":null`) {
		t.Fatalf("synthetic token:null required, got %s", resp.Body.String())
	}
	if strings.Contains(resp.Body.String(), "USER_ALREADY_EXISTS") {
		t.Fatalf("must not leak existence, got %s", resp.Body.String())
	}
}

// should call onExistingUserSignUp when autoSignIn is false without
func TestSignUpAutoSignIn_AutoSignInFalseDuplicateFiresHook(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	opts.EmailAndPassword.AutoSignIn = boolPtr(false)
	fired := false
	opts.EmailAndPassword.OnExistingUserSignUp = func(types.ExistingUserSignUpData) error {
		fired = true
		return nil
	}
	api := credsSignUpAPI(t, opts)
	credsSignInSeed(t, api, "g1hook@test.com", "password123")
	resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "G1", "email": "g1hook@test.com", "password": "password123",
	})
	if resp.Code != 200 {
		t.Fatalf("duplicate sign-up = %d, want opaque 200: %s", resp.Code, resp.Body.String())
	}
	if !fired {
		t.Fatal("OnExistingUserSignUp must fire on the autoSignIn=false duplicate leg")
	}
}

