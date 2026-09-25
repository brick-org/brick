package crypto

// G11 coverage for PARITY_V2.md second-pass P11 R6 + G8 (upstream
// crypto/jwt.ts @ 5468e6bf):
//   - R6: SymmetricDecodeJWT must gate A256GCM key truncation on the token's
//     enc (the cookies/jwt.go decryptionKeys policy), not try both key widths
//     unconditionally.
//   - G8: SymmetricEncodeJWT must emit exactly {alg,enc,kid} (upstream
//     EncryptJWT sets only those, jwt.ts:104-109) — no typ/cty — while
//     SymmetricDecodeJWT stays tolerant of legacy typ/cty-bearing tokens.

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

const (
	g11SecretA = "secret-a-at-least-32-chars-long!!"
	g11SecretB = "secret-b-at-least-32-chars-long!!"
	g11Salt    = "test-salt"
)

func g11ProtectedHeader(t *testing.T, token string) map[string]any {
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

func g11MintManual(t *testing.T, enc jose.ContentEncryption, secret, salt string, payload map[string]any, withKid, withTypCty bool) string {
	t.Helper()
	full, err := DeriveEncryptionSecret(secret, salt)
	if err != nil {
		t.Fatal(err)
	}
	key := full
	if enc == jose.A256GCM {
		key = full[:32]
	}
	opts := &jose.EncrypterOptions{}
	if withTypCty {
		opts = opts.WithType("JWT").WithContentType("JWT")
	}
	if withKid {
		kid, err := OctThumbprint(full)
		if err != nil {
			t.Fatal(err)
		}
		opts = opts.WithHeader(jose.HeaderKey("kid"), kid)
	}
	encrypter, err := jose.NewEncrypter(
		enc,
		jose.Recipient{Algorithm: jose.DIRECT, Key: key},
		opts,
	)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := encrypter.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	token, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func g11Payload() map[string]any {
	now := time.Now().Unix()
	return map[string]any{
		"foo": "bar",
		"iat": now,
		"exp": now + 3600,
	}
}

// G8: issuance must set exactly {alg,enc,kid} — no typ/cty.
func TestG11_JWEHeaderExactness(t *testing.T) {
	token, err := SymmetricEncodeJWT(map[string]any{"foo": "bar"}, g11SecretA, g11Salt, 3600)
	if err != nil {
		t.Fatal(err)
	}
	header := g11ProtectedHeader(t, token)
	if len(header) != 3 {
		t.Fatalf("protected header keys = %v, want exactly {alg,enc,kid}", header)
	}
	if header["alg"] != JWEKeyManagementAlg {
		t.Fatalf("alg = %v, want %q", header["alg"], JWEKeyManagementAlg)
	}
	if header["enc"] != JWEContentEncryption {
		t.Fatalf("enc = %v, want %q", header["enc"], JWEContentEncryption)
	}
	full, err := DeriveEncryptionSecret(g11SecretA, g11Salt)
	if err != nil {
		t.Fatal(err)
	}
	wantKid, err := OctThumbprint(full)
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

// G8 interop: decode stays tolerant of legacy typ/cty-bearing tokens.
func TestG11_JWEDecodeTolerantOfLegacyTypCty(t *testing.T) {
	token := g11MintManual(t, jose.A256CBC_HS512, g11SecretA, g11Salt, g11Payload(), true, true)
	if got := g11ProtectedHeader(t, token); got["typ"] == nil || got["cty"] == nil {
		t.Fatalf("fixture must carry legacy typ/cty, got %v", got)
	}
	decoded, err := SymmetricDecodeJWT(token, g11SecretA, g11Salt)
	if err != nil {
		t.Fatalf("legacy typ/cty token rejected: %v", err)
	}
	if decoded["foo"] != "bar" {
		t.Fatalf("decoded = %v, want foo=bar", decoded)
	}
}

// R6: A256GCM-wrapped tokens (truncated 32-byte key, thumbprint kid) decode;
// the issued A256CBC-HS512 shape still round-trips.
func TestG11_JWEA256GCMCompat(t *testing.T) {
	gcm := g11MintManual(t, jose.A256GCM, g11SecretA, g11Salt, g11Payload(), true, false)
	if got := g11ProtectedHeader(t, gcm); got["enc"] != string(jose.A256GCM) {
		t.Fatalf("fixture enc = %v, want A256GCM", got["enc"])
	}
	decoded, err := SymmetricDecodeJWT(gcm, g11SecretA, g11Salt)
	if err != nil {
		t.Fatalf("A256GCM token rejected: %v", err)
	}
	if decoded["foo"] != "bar" {
		t.Fatalf("decoded = %v, want foo=bar", decoded)
	}
	// Kid-less A256GCM token falls back across rotated secrets.
	kidLess := g11MintManual(t, jose.A256GCM, g11SecretB, g11Salt, g11Payload(), false, false)
	cfg := SecretConfig{
		Keys:           map[int]string{2: g11SecretA, 1: g11SecretB},
		CurrentVersion: 2,
	}
	decoded, err = SymmetricDecodeJWT(kidLess, cfg, g11Salt)
	if err != nil {
		t.Fatalf("kid-less A256GCM fallback failed: %v", err)
	}
	if decoded["foo"] != "bar" {
		t.Fatalf("decoded = %v, want foo=bar", decoded)
	}
	// Issued shape still round-trips alongside.
	issued, err := SymmetricEncodeJWT(map[string]any{"foo": "bar"}, g11SecretA, g11Salt, 3600)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err = SymmetricDecodeJWT(issued, g11SecretA, g11Salt)
	if err != nil {
		t.Fatalf("issued token rejected: %v", err)
	}
	if decoded["foo"] != "bar" {
		t.Fatalf("decoded = %v, want foo=bar", decoded)
	}
}

// R6: key-width selection is gated on enc — full 64-byte key except for
// A256GCM payloads, which use the 32-byte truncation.
func TestG11_JWEDecryptionKeysEncGated(t *testing.T) {
	full, err := DeriveEncryptionSecret(g11SecretA, g11Salt)
	if err != nil {
		t.Fatal(err)
	}
	cbc := jweDecryptionKeys(full, string(jose.A256CBC_HS512))
	if len(cbc) != 1 || len(cbc[0]) != 64 || string(cbc[0]) != string(full) {
		t.Fatalf("A256CBC-HS512 must use the full key only, got %d entries", len(cbc))
	}
	gcm := jweDecryptionKeys(full, string(jose.A256GCM))
	if len(gcm) != 1 || len(gcm[0]) != 32 || string(gcm[0]) != string(full[:32]) {
		t.Fatalf("A256GCM must use the truncated key only, got %d entries", len(gcm))
	}
	unknown := jweDecryptionKeys(full, "A128CBC-HS256")
	if len(unknown) != 1 || len(unknown[0]) != 64 {
		t.Fatalf("unknown enc must fall back to the full key, got %d entries", len(unknown))
	}
}
