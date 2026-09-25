package cookies

// v1 ports: cookies.test.ts getCookieCache expiry + secret-rotation.test.ts JWE leg (session codec, rotated secrets).

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/brick-org/brick/auth/src/crypto"
)

func v1CachePayload(expiresAt time.Time) map[string]any {
	now := time.Now().UTC()
	return map[string]any{
		"session": map[string]any{
			"id":        "s1",
			"token":     "session-token",
			"userId":    "u1",
			"expiresAt": expiresAt.UTC().Format(time.RFC3339),
			"createdAt": now.Format(time.RFC3339),
			"updatedAt": now.Format(time.RFC3339),
		},
		"user": map[string]any{
			"id":            "u1",
			"email":         "cache@test.com",
			"emailVerified": true,
			"name":          "Cache User",
			"createdAt":     now.Format(time.RFC3339),
			"updatedAt":     now.Format(time.RFC3339),
		},
	}
}

func TestCacheExpiry_CompactCacheFreshSnapshot(t *testing.T) {
	value, err := CreateCompactCookieCache("better-auth.secret", v1CachePayload(time.Now().Add(time.Hour)), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	session, _, err := VerifyCompactCookieCache([]string{"better-auth.secret"}, value)
	if err != nil {
		t.Fatalf("fresh cache rejected: %v", err)
	}
	user, _ := session["user"].(map[string]any)
	if user["email"] != "cache@test.com" {
		t.Fatalf("payload = %v", session)
	}
}

func TestCacheExpiry_CompactCacheEmbeddedSessionExpired(t *testing.T) {
	value, err := CreateCompactCookieCache("better-auth.secret", v1CachePayload(time.Now().Add(-time.Minute)), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyCompactCookieCache([]string{"better-auth.secret"}, value); err == nil {
		t.Fatal("embedded-expired cache accepted")
	} else if !strings.Contains(err.Error(), "embedded") {
		t.Fatalf("error = %v, want embedded-session-expiry", err)
	}
}

func TestCacheExpiry_CompactCacheWindowElapsed(t *testing.T) {
	value, err := CreateCompactCookieCache("better-auth.secret", v1CachePayload(time.Now().Add(time.Hour)), -time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyCompactCookieCache([]string{"better-auth.secret"}, value); err == nil {
		t.Fatal("elapsed-window cache accepted")
	}
}

func TestCacheExpiry_CompactCacheInvalidAndMissingSecret(t *testing.T) {
	value, err := CreateCompactCookieCache("better-auth.secret", v1CachePayload(time.Now().Add(time.Hour)), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// Upstream "should return null if the cookie is invalid".
	if _, _, err := VerifyCompactCookieCache([]string{"wrong-secret"}, value); err == nil {
		t.Error("wrong secret accepted")
	}
	// Upstream "should throw an error if the secret is not provided".
	if _, _, err := VerifyCompactCookieCache(nil, value); err == nil {
		t.Error("missing secret accepted")
	}
}

func TestCacheExpiry_JWTCacheInvalidToken(t *testing.T) {
	// Upstream "should return null for invalid JWT token".
	if _, _, err := VerifySessionCacheJWT([]string{"better-auth.secret"}, "invalid.jwt.token"); err == nil {
		t.Error("invalid JWT accepted")
	}
	if _, _, err := VerifySessionCacheJWT(nil, "invalid.jwt.token"); err == nil {
		t.Error("invalid JWT accepted without secrets")
	}
}

func TestCacheExpiry_JWECacheMismatchedKidNoFallback(t *testing.T) {
	// Upstream "rejects token with mismatched kid (no fallback)".
	session, user := jwtTestData()
	token, err := CreateSessionCacheJWE("secret-a-at-least-32-chars-long!!", session, user, "1", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifySessionCacheJWE([]string{"secret-b-at-least-32-chars-long!!"}, token); err == nil {
		t.Error("mismatched kid decrypted")
	}
}

func TestCacheExpiry_JWECacheKidLessFallbackTriesAllSecrets(t *testing.T) {
	// Upstream "decode kid-less JWT tries all secrets (fallback)".
	secretA := "secret-a-at-least-32-chars-long!!"
	secretB := "secret-b-at-least-32-chars-long!!"
	now := time.Now().Unix()
	plaintext, err := json.Marshal(map[string]any{
		"session":   map[string]any{"id": "s1", "token": "tok"},
		"user":      map[string]any{"id": "u1"},
		"updatedAt": time.Now().UnixMilli(),
		"iat":       now,
		"exp":       now + 3600,
		"jti":       "kid-less",
	})
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.DeriveEncryptionSecret(secretB, crypto.SessionCookieEncryptionSalt)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := jose.NewEncrypter(
		jose.A256CBC_HS512,
		jose.Recipient{Algorithm: jose.DIRECT, Key: key},
		(&jose.EncrypterOptions{}).WithType("JWT").WithContentType("JWT"),
	)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	token, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := VerifySessionCacheJWE([]string{secretA, secretB}, token)
	if err != nil {
		t.Fatalf("kid-less fallback failed: %v", err)
	}
	if got.Session["token"] != "tok" {
		t.Fatalf("payload = %+v", got)
	}
	if _, _, err := VerifySessionCacheJWE([]string{secretA}, token); err == nil {
		t.Error("kid-less token decrypted without its secret")
	}
}

func TestCacheExpiry_JWECacheAcceptsA256GCM(t *testing.T) {
	// Upstream jwtDecryptOpts accepts A256GCM alongside A256CBC-HS512 (32-byte truncation).
	secret := "gcm-compat-secret-at-least-32-chars!"
	now := time.Now().Unix()
	plaintext, err := json.Marshal(map[string]any{
		"session":   map[string]any{"id": "s1", "token": "tok"},
		"user":      map[string]any{"id": "u1"},
		"updatedAt": time.Now().UnixMilli(),
		"iat":       now,
		"exp":       now + 3600,
		"jti":       "gcm",
	})
	if err != nil {
		t.Fatal(err)
	}
	full, err := crypto.DeriveEncryptionSecret(secret, crypto.SessionCookieEncryptionSalt)
	if err != nil {
		t.Fatal(err)
	}
	kid, err := crypto.OctThumbprint(full)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{Algorithm: jose.DIRECT, Key: full[:32]},
		(&jose.EncrypterOptions{}).WithType("JWT").WithContentType("JWT").WithHeader(jose.HeaderKey("kid"), kid),
	)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	token, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifySessionCacheJWE([]string{secret}, token); err != nil {
		t.Fatalf("A256GCM payload rejected: %v", err)
	}
}
