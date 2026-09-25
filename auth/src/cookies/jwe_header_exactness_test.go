package cookies

// F3 gap 11: CreateSessionCacheJWE emits exactly {alg,enc,kid} (upstream index.ts:209-214 @5468e6bf).

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/crypto"
)

const f3Secret = "f3-secret-at-least-32-chars-long!!"

func f3SessionUser() (session, user map[string]any) {
	now := time.Now().UTC().Format(time.RFC3339)
	return map[string]any{
			"id":        "sess-f3",
			"userId":    "user-f3",
			"token":     "tok-f3",
			"expiresAt": time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
			"createdAt": now,
			"updatedAt": now,
		}, map[string]any{
			"id":            "user-f3",
			"email":         "f3@example.com",
			"emailVerified": true,
			"name":          "F3",
			"createdAt":     now,
			"updatedAt":     now,
		}
}

func f3ProtectedHeader(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 5 {
		t.Fatalf("token is not a compact JWE: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode protected header: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(raw, &header); err != nil {
		t.Fatalf("parse protected header: %v", err)
	}
	return header
}

// Header exactly {alg,enc,kid}.
func TestJWEHeader_JWEHeaderExactlyThreeKeys(t *testing.T) {
	session, user := f3SessionUser()
	token, err := CreateSessionCacheJWE(f3Secret, session, user, "1", 5*time.Minute)
	if err != nil {
		t.Fatalf("issue jwe cache: %v", err)
	}
	header := f3ProtectedHeader(t, token)
	if len(header) != 3 {
		t.Fatalf("protected header keys = %v, want exactly {alg,enc,kid}", header)
	}
	if header["alg"] != "dir" {
		t.Fatalf("alg = %v, want dir", header["alg"])
	}
	if header["enc"] != "A256CBC-HS512" {
		t.Fatalf("enc = %v, want A256CBC-HS512", header["enc"])
	}
	key, err := crypto.DeriveEncryptionSecret(f3Secret, crypto.SessionCookieEncryptionSalt)
	if err != nil {
		t.Fatal(err)
	}
	wantKid, err := crypto.OctThumbprint(key)
	if err != nil {
		t.Fatal(err)
	}
	if header["kid"] != wantKid {
		t.Fatalf("kid = %v, want %q", header["kid"], wantKid)
	}
	if _, ok := header["typ"]; ok {
		t.Fatalf("protected header must not carry typ: %v", header)
	}
	if _, ok := header["cty"]; ok {
		t.Fatalf("protected header must not carry cty: %v", header)
	}
}

// cookies-stack-minted token decodes via the crypto stack.
func TestJWEHeader_JWECrossStackCookiesToCrypto(t *testing.T) {
	session, user := f3SessionUser()
	token, err := CreateSessionCacheJWE(f3Secret, session, user, "1", 5*time.Minute)
	if err != nil {
		t.Fatalf("cookies mint: %v", err)
	}
	claims, err := crypto.SymmetricDecodeJWT(token, f3Secret, crypto.SessionCookieEncryptionSalt)
	if err != nil {
		t.Fatalf("crypto-stack decode of cookies-minted token: %v", err)
	}
	sess, ok := claims["session"].(map[string]any)
	if !ok || sess["token"] != "tok-f3" {
		t.Fatalf("session claim mismatch: %v", claims["session"])
	}
	u, ok := claims["user"].(map[string]any)
	if !ok || u["id"] != "user-f3" {
		t.Fatalf("user claim mismatch: %v", claims["user"])
	}
}

// crypto-stack-minted token verifies via the cookies stack.
func TestJWEHeader_JWECrossStackCryptoToCookies(t *testing.T) {
	session, user := f3SessionUser()
	payload := map[string]any{"session": session, "user": user, "marker": "f3-cross"}
	token, err := crypto.SymmetricEncodeJWT(payload, f3Secret, crypto.SessionCookieEncryptionSalt, 3600)
	if err != nil {
		t.Fatalf("crypto mint: %v", err)
	}
	got, _, err := VerifySessionCacheJWE([]string{f3Secret}, token)
	if err != nil {
		t.Fatalf("cookies-stack verify of crypto-minted token: %v", err)
	}
	if got.Session["token"] != "tok-f3" {
		t.Fatalf("session.token = %v, want tok-f3", got.Session["token"])
	}
	if got.User["id"] != "user-f3" || got.User["email"] != "f3@example.com" {
		t.Fatalf("user mismatch: %v", got.User)
	}
}
