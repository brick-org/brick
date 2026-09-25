package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/brick-org/brick/auth/src/crypto"
	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

// B3: already-verified GET/POST without callbackURL must return
// {status:true,user:null} instead of the user object (upstream
// email-verification.ts:480-488,540-543 @ 5468e6bf). Redirect-with-callbackURL
// path stays as-is.

func b3VerifyAPI(t *testing.T, opts types.Options) humatest.TestAPI {
	t.Helper()
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	VerifyEmail(api, "/api/auth", opts)
	return api
}

func b3IssuePlainToken(t *testing.T, opts types.Options, email string) string {
	t.Helper()
	token, err := crypto.CreateEmailVerificationToken(opts.CurrentSecret(), email, "", 3600, nil)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	return token
}

// Process level: already-verified must return nil user with success.
func TestB3_AlreadyVerifiedProcessReturnsNullUser(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	parityCreateUser(t, db, "b3-verified@example.com", true)

	token := b3IssuePlainToken(t, opts, "b3-verified@example.com")
	user, _, errCode, status := processVerifyEmail(context.Background(), opts, token, CookieRequestHeaders{})
	if errCode != "" {
		t.Fatalf("expected success, got %s (%d)", errCode, status)
	}
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if user != nil {
		t.Fatalf("already-verified must return null user, got %#v", user)
	}
}

// POST /verify-email without callbackURL must return {status:true,user:null}.
func TestB3_AlreadyVerifiedPostReturnsNullUser(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	parityCreateUser(t, db, "b3-post@example.com", true)
	token := b3IssuePlainToken(t, opts, "b3-post@example.com")
	api := b3VerifyAPI(t, opts)

	resp := api.Post("/api/auth/verify-email", map[string]any{"token": token})
	if resp.Code != http.StatusOK {
		t.Fatalf("POST status = %d, want 200: %s", resp.Code, resp.Body.String())
	}
	raw := resp.Body.String()
	if !strings.Contains(raw, `"status":true`) {
		t.Fatalf("POST must contain status:true, got %s", raw)
	}
	if !strings.Contains(raw, `"user":null`) {
		t.Fatalf("POST already-verified must return user:null, got %s", raw)
	}
	var body struct {
		Status bool         `json:"status"`
		User   *types.User  `json:"user"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !body.Status {
		t.Fatalf("status must be true, got %#v", body)
	}
	if body.User != nil {
		t.Fatalf("POST already-verified user must be null, got %#v", body.User)
	}
}

// GET /verify-email without callbackURL must return {status:true,user:null}.
func TestB3_AlreadyVerifiedGetReturnsNullUser(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	parityCreateUser(t, db, "b3-get@example.com", true)
	token := b3IssuePlainToken(t, opts, "b3-get@example.com")
	api := b3VerifyAPI(t, opts)

	resp := api.Get("/api/auth/verify-email?token=" + url.QueryEscape(token))
	if resp.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200: %s", resp.Code, resp.Body.String())
	}
	raw := resp.Body.String()
	if !strings.Contains(raw, `"status":true`) {
		t.Fatalf("GET must contain status:true, got %s", raw)
	}
	if !strings.Contains(raw, `"user":null`) {
		t.Fatalf("GET already-verified must return user:null, got %s", raw)
	}
	var body struct {
		Status bool        `json:"status"`
		User   *types.User `json:"user"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !body.Status {
		t.Fatalf("status must be true, got %#v", body)
	}
	if body.User != nil {
		t.Fatalf("GET already-verified user must be null, got %#v", body.User)
	}
}

// Redirect-with-callbackURL path stays as-is: already-verified with
// callbackURL still 302s to the callback (not JSON).
func TestB3_AlreadyVerifiedGetRedirectUnchanged(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	parityCreateUser(t, db, "b3-redirect@example.com", true)
	token := b3IssuePlainToken(t, opts, "b3-redirect@example.com")
	api := b3VerifyAPI(t, opts)

	callback := "/callback"
	resp := api.Get("/api/auth/verify-email?token=" + url.QueryEscape(token) + "&callbackURL=" + url.QueryEscape(callback))
	if resp.Code != http.StatusFound {
		t.Fatalf("redirect status = %d, want 302: %s", resp.Code, resp.Body.String())
	}
	if loc := resp.Header().Get("Location"); loc != callback {
		t.Fatalf("Location = %q, want %q", loc, callback)
	}
}

// Fresh (unverified) verify must still return the user object.
func TestB3_FreshVerifyStillReturnsUser(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	parityCreateUser(t, db, "b3-fresh@example.com", false)

	token := b3IssuePlainToken(t, opts, "b3-fresh@example.com")
	user, _, errCode, _ := processVerifyEmail(context.Background(), opts, token, CookieRequestHeaders{})
	if errCode != "" {
		t.Fatalf("expected success, got %s", errCode)
	}
	// Upstream fresh plain verify answers {status:true,user:null}
	// (email-verification.ts:540-543; realigned by F2 for 100% parity).
	if user != nil {
		t.Fatalf("fresh verify must return null user, got %#v", user)
	}
	row, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: "b3-fresh@example.com"}}, nil)
	if verified, _ := row["emailVerified"].(bool); !verified {
		t.Fatal("user row must still be marked verified")
	}
}
