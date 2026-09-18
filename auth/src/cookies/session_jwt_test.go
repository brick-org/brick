package cookies

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/crypto"
)

func jwtTestData() (session, user map[string]any) {
	return map[string]any{
		"id":        "sess-1",
		"userId":    "user-1",
		"token":     "tok-1",
		"expiresAt": time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		"createdAt": time.Now().UTC().Format(time.RFC3339),
		"updatedAt": time.Now().UTC().Format(time.RFC3339),
	}, map[string]any{
		"id":            "user-1",
		"email":         "jwt@example.com",
		"emailVerified": true,
		"name":          "JWT",
		"createdAt":     time.Now().UTC().Format(time.RFC3339),
		"updatedAt":     time.Now().UTC().Format(time.RFC3339),
	}
}

// TestCreateVerifySessionCacheJWT_RoundTrip pins the upstream default JWT
// cache shape (cookies/index.ts setCookieCache/decodeCookieCache, HS256 with
// the auth secret): issue with the current secret, verify with rotation, and
// recover session/user/version plus the outer expiry.
func TestCreateVerifySessionCacheJWT_RoundTrip(t *testing.T) {
	session, user := jwtTestData()
	token, err := CreateSessionCacheJWT("secret-one", session, user, "1", 5*time.Minute)
	if err != nil {
		t.Fatalf("issue jwt cache: %v", err)
	}
	// Wrong-only secrets must fail closed.
	if _, _, err := VerifySessionCacheJWT([]string{"wrong"}, token); err == nil {
		t.Fatal("wrong secret must not verify")
	}
	// Rotation: a retained (non-first) secret still verifies.
	got, expMillis, err := VerifySessionCacheJWT([]string{"secret-two", "secret-one"}, token)
	if err != nil {
		t.Fatalf("rotation verify: %v", err)
	}
	if got.Version != "1" {
		t.Fatalf("version = %q, want %q", got.Version, "1")
	}
	if time.Until(time.UnixMilli(expMillis)) < 4*time.Minute {
		t.Fatalf("outer expiry too short: %d", expMillis)
	}
	if got.Session["token"] != "tok-1" || got.User["id"] != "user-1" {
		t.Fatalf("wrong payload: %+v", got)
	}
}

// TestVerifySessionCacheJWT_Rejects pins the fail-closed matrix for the JWT
// cache: tampered payloads, wrong algorithms, and expired tokens never verify.
func TestVerifySessionCacheJWT_Rejects(t *testing.T) {
	session, user := jwtTestData()
	token, err := CreateSessionCacheJWT("secret-one", session, user, "", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	tampered := token[:len(token)-2] + "xx"
	for name, value := range map[string]string{
		"tampered": tampered,
		"garbage":  "not.a.jwt",
		"empty":    "",
	} {
		if _, _, err := VerifySessionCacheJWT([]string{"secret-one"}, value); err == nil {
			t.Fatalf("%s token must not verify", name)
		}
	}

	expired, err := CreateSessionCacheJWT("secret-one", session, user, "", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if _, _, err := VerifySessionCacheJWT([]string{"secret-one"}, expired); err == nil {
		t.Fatal("expired jwt cache must not verify")
	}
}

// TestCreateSessionCacheJWT_DefaultWindow pins the upstream caller default
// (cookies/index.ts passes `maxAge || 60 * 5`): a non-positive window issues
// with the 5-minute default instead of an already-expired token.
func TestCreateSessionCacheJWT_DefaultWindow(t *testing.T) {
	session, user := jwtTestData()
	token, err := CreateSessionCacheJWT("secret-one", session, user, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	_, expMillis, err := VerifySessionCacheJWT([]string{"secret-one"}, token)
	if err != nil {
		t.Fatalf("default-window token must verify: %v", err)
	}
	if remaining := time.Until(time.UnixMilli(expMillis)); remaining < 4*time.Minute {
		t.Fatalf("default window too short: %v", remaining)
	}
}

// TestCreateVerifySessionCacheJWE_RoundTrip pins the upstream JWE cache shape
// (cookies/index.ts jwe branch, crypto/jwt.ts symmetricEncodeJWT): dir /
// A256CBC-HS512 with an HKDF-derived key whose thumbprint is the kid. The kid
// must select the right secret under rotation, and unknown kids fail closed.
func TestCreateVerifySessionCacheJWE_RoundTrip(t *testing.T) {
	session, user := jwtTestData()
	token, err := CreateSessionCacheJWE("secret-one", session, user, "7", 5*time.Minute)
	if err != nil {
		t.Fatalf("issue jwe cache: %v", err)
	}
	got, _, err := VerifySessionCacheJWE([]string{"secret-two", "secret-one"}, token)
	if err != nil {
		t.Fatalf("rotation verify: %v", err)
	}
	if got.Version != "7" {
		t.Fatalf("version = %q, want %q", got.Version, "7")
	}
	if got.Session["token"] != "tok-1" || got.User["email"] != "jwt@example.com" {
		t.Fatalf("wrong payload: %+v", got)
	}
	// No published secret matches: fail closed.
	if _, _, err := VerifySessionCacheJWE([]string{"other-a", "other-b"}, token); err == nil {
		t.Fatal("unknown kid must not decrypt")
	}
	// Tampered ciphertext fails closed.
	tampered := token[:len(token)-4] + "xxxx"
	if _, _, err := VerifySessionCacheJWE([]string{"secret-one"}, tampered); err == nil {
		t.Fatal("tampered jwe must not decrypt")
	}
	if _, _, err := VerifySessionCacheJWE([]string{"secret-one"}, "garbage"); err == nil {
		t.Fatal("garbage jwe must not decrypt")
	}
}

// TestSessionCacheJWEPayloadShape pins the protected-header contract upstream
// relies on for kid-selected rotation (dir / A256CBC-HS512 / thumbprint kid).
func TestSessionCacheJWEPayloadShape(t *testing.T) {
	session, user := jwtTestData()
	token, err := CreateSessionCacheJWE("header-secret", session, user, "", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	header := decodeJOSEHeader(t, token)
	if header["alg"] != "dir" {
		t.Fatalf("alg = %v, want dir", header["alg"])
	}
	if header["enc"] != "A256CBC-HS512" {
		t.Fatalf("enc = %v, want A256CBC-HS512", header["enc"])
	}
	kid, _ := header["kid"].(string)
	if kid == "" {
		t.Fatal("jwe cache must carry a kid thumbprint")
	}
	key, err := crypto.DeriveEncryptionSecret("header-secret", crypto.SessionCookieEncryptionSalt)
	if err != nil {
		t.Fatal(err)
	}
	wantKid, err := crypto.OctThumbprint(key)
	if err != nil {
		t.Fatal(err)
	}
	if kid != wantKid {
		t.Fatalf("kid = %q, want derived thumbprint %q", kid, wantKid)
	}
}

func decodeJOSEHeader(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		t.Fatalf("malformed token: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(raw, &header); err != nil {
		t.Fatalf("parse header: %v", err)
	}
	return header
}
