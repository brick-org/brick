package crypto_test

// C2 coverage for PARITY_V2.md P11 caveat (upstream crypto/jwt.ts @ 5468e6bf):
// existing JWE tests are Go-round-trips only (IV randomized, never pinned vs
// a jose-minted fixture).
//
// VERDICT: property-pinned (NOT fixture-pinned).
//
// Why: vendor/better-auth upstream contains NO fixed (deterministic) JWE
// compact-token vector. Every JWE leg in
// packages/better-auth/src/crypto/secret-rotation.test.ts (JWE
// multi-secret describe, lines 186-320) mints its token live via
// symmetricEncodeJWT -> jose EncryptJWT (random CEK IV per encryption) with
// .setJti(crypto.randomUUID()) (jwt.ts:104-109), then decodes it in the same
// test. A grep for fixed compact tokens (eyJ... literals) across the crypto
// and cookies upstream test files finds nothing mintable-deterministic to
// pin a Go decode against: any hardcoded token would embed one random IV.
// The only fixed vectors upstream are key-level (HKDF output, kid
// thumbprint), already pinned by TestDeriveEncryptionSecretVectors and
// TestOctThumbprintVector in jwe_test.go.
//
// So instead this file pins DETERMINISTIC properties across 50 iterations:
//   - protected header is exactly {alg,enc,kid} (upstream EncryptJWT sets
//     only those, jwt.ts:105), with alg=dir, enc=A256CBC-HS512, and
//     kid == OctThumbprint(DeriveEncryptionSecret(secret, salt));
//   - round-trip payload equality on every iteration;
//   - distinct full tokens / ciphertext segments (randomness alive — the
//     reason a fixed fixture cannot exist);
//   - cross-stack decode: a crypto-stack-minted token verifies via the
//     cookies stack (VerifySessionCacheJWE) and a cookies-stack-minted
//     token decodes via the crypto stack (SymmetricDecodeJWT), proving the
//     two JWE stacks agree on keys despite separate issue paths
//     (P11 two-stacks note). All C2 tests use the session salt so the kid
//     pin doubles as the cross-stack binding proof.

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/cookies"
	"github.com/brick-org/brick/auth/src/crypto"
)

const (
	c2Secret = "secret-a-at-least-32-chars-long!!"
	c2Salt   = crypto.SessionCookieEncryptionSalt
)

func c2ProtectedHeader(t *testing.T, token string) map[string]any {
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

func c2WantKid(t *testing.T) string {
	t.Helper()
	derived, err := crypto.DeriveEncryptionSecret(c2Secret, c2Salt)
	if err != nil {
		t.Fatal(err)
	}
	kid, err := crypto.OctThumbprint(derived)
	if err != nil {
		t.Fatal(err)
	}
	return kid
}

// Header is exactly {alg,enc,kid} with the thumbprint kid, on all 50 mints.
func TestJWEDeterminism_JWEHeaderExactAndKidPinned(t *testing.T) {
	wantKid := c2WantKid(t)
	for i := 0; i < 50; i++ {
		token, err := crypto.SymmetricEncodeJWT(map[string]any{"foo": "bar"}, c2Secret, c2Salt, 3600)
		if err != nil {
			t.Fatalf("iteration %d: encode: %v", i, err)
		}
		header := c2ProtectedHeader(t, token)
		if len(header) != 3 {
			t.Fatalf("iteration %d: header keys = %v, want exactly {alg,enc,kid}", i, header)
		}
		if header["alg"] != crypto.JWEKeyManagementAlg {
			t.Fatalf("iteration %d: alg = %v, want %q", i, header["alg"], crypto.JWEKeyManagementAlg)
		}
		if header["enc"] != crypto.JWEContentEncryption {
			t.Fatalf("iteration %d: enc = %v, want %q", i, header["enc"], crypto.JWEContentEncryption)
		}
		if header["kid"] != wantKid {
			t.Fatalf("iteration %d: kid = %v, want %q", i, header["kid"], wantKid)
		}
	}
}

// Every mint round-trips its payload, and all 50 tokens differ (IV/jti
// randomness alive — the reason no fixed upstream fixture exists).
func TestJWEDeterminism_JWERoundTripPayloadEqualityAndRandomness(t *testing.T) {
	seenTokens := make(map[string]struct{}, 50)
	seenCiphertext := make(map[string]struct{}, 50)
	for i := 0; i < 50; i++ {
		payload := map[string]any{"foo": "bar", "scope": "c2"}
		token, err := crypto.SymmetricEncodeJWT(payload, c2Secret, c2Salt, 3600)
		if err != nil {
			t.Fatalf("iteration %d: encode: %v", i, err)
		}
		if _, dup := seenTokens[token]; dup {
			t.Fatalf("iteration %d: duplicate compact token, randomness dead", i)
		}
		seenTokens[token] = struct{}{}
		if ct := strings.Split(token, ".")[3]; true {
			if _, dup := seenCiphertext[ct]; dup {
				t.Fatalf("iteration %d: duplicate ciphertext segment, IV randomness dead", i)
			}
			seenCiphertext[ct] = struct{}{}
		}
		decoded, err := crypto.SymmetricDecodeJWT(token, c2Secret, c2Salt)
		if err != nil {
			t.Fatalf("iteration %d: decode: %v", i, err)
		}
		if decoded["foo"] != "bar" || decoded["scope"] != "c2" {
			t.Fatalf("iteration %d: payload mismatch: %v", i, decoded)
		}
	}
}

func c2SessionUser() (session, user map[string]any) {
	now := time.Now().UTC().Format(time.RFC3339)
	return map[string]any{
			"id":        "sess-c2",
			"userId":    "user-c2",
			"token":     "tok-c2",
			"expiresAt": time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
			"createdAt": now,
			"updatedAt": now,
		}, map[string]any{
			"id":            "user-c2",
			"email":         "c2@example.com",
			"emailVerified": true,
			"name":          "C2",
			"createdAt":     now,
			"updatedAt":     now,
		}
}

// crypto-stack-minted token verifies via the cookies stack.
func TestJWEDeterminism_JWECrossStackCryptoToCookies(t *testing.T) {
	session, user := c2SessionUser()
	payload := map[string]any{"session": session, "user": user, "marker": "c2-cross"}
	token, err := crypto.SymmetricEncodeJWT(payload, c2Secret, c2Salt, 3600)
	if err != nil {
		t.Fatalf("crypto mint: %v", err)
	}
	got, _, err := cookies.VerifySessionCacheJWE([]string{c2Secret}, token)
	if err != nil {
		t.Fatalf("cookies-stack verify of crypto-minted token: %v", err)
	}
	if got.Session["token"] != "tok-c2" {
		t.Fatalf("session.token = %v, want tok-c2", got.Session["token"])
	}
	if got.User["id"] != "user-c2" || got.User["email"] != "c2@example.com" {
		t.Fatalf("user mismatch: %v", got.User)
	}
}

// cookies-stack-minted token decodes via the crypto stack (which tolerates
// the cookies issuer's typ/cty header params).
func TestJWEDeterminism_JWECrossStackCookiesToCrypto(t *testing.T) {
	session, user := c2SessionUser()
	token, err := cookies.CreateSessionCacheJWE(c2Secret, session, user, "1", 5*time.Minute)
	if err != nil {
		t.Fatalf("cookies mint: %v", err)
	}
	claims, err := crypto.SymmetricDecodeJWT(token, c2Secret, c2Salt)
	if err != nil {
		t.Fatalf("crypto-stack decode of cookies-minted token: %v", err)
	}
	sess, ok := claims["session"].(map[string]any)
	if !ok || sess["token"] != "tok-c2" {
		t.Fatalf("session claim mismatch: %v", claims["session"])
	}
	u, ok := claims["user"].(map[string]any)
	if !ok || u["id"] != "user-c2" {
		t.Fatalf("user claim mismatch: %v", claims["user"])
	}
}
