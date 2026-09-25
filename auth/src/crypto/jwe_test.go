package crypto

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestDeriveEncryptionSecretVectors(t *testing.T) {
	// HKDF-SHA256 vectors (RFC 5869 via Python stdlib, L=64, upstream params).
	for _, tc := range []struct{ secret, salt, wantHex string }{
		{
			"secret-a-at-least-32-chars-long!!", "better-auth-session",
			"5c627bc7f797a61f50f3f248da457b686487563d7c5de865d5a503644424bcf9bd9b31a2f91d584caaadbdabd5763fc38842bb0831cf0db5e81345de6ce1c95a",
		},
		{
			"secret-a-at-least-32-chars-long!!", "better-auth-account",
			"631ed5bbfde5623e6735845367e5abd68ed15e903a45d9102ebe5f96a64a894269af07cb77a805b614501b32fa71f2f02dfcc6bda1d508d360afecb4efbc8cf0",
		},
		{
			"secret", "better-auth-session",
			"55395ead878196aae4b9e3ee64bf8843fff0201c21c7baec664acb1008b671be4fc4f22a4e324f4e5ff70d2bab689dd5d5e7542b2f9e1ba39904bf9adde0842d",
		},
	} {
		key, err := DeriveEncryptionSecret(tc.secret, tc.salt)
		if err != nil {
			t.Fatalf("derive: %v", err)
		}
		if len(key) != DerivedEncryptionKeyLen {
			t.Fatalf("key len = %d, want %d", len(key), DerivedEncryptionKeyLen)
		}
		if got := hex.EncodeToString(key); got != tc.wantHex {
			t.Errorf("derive(%q, %q) = %s, want %s", tc.secret, tc.salt, got, tc.wantHex)
		}
	}
	// Salts isolate keys; deterministic.
	a, _ := DeriveEncryptionSecret("s", SessionCookieEncryptionSalt)
	b, _ := DeriveEncryptionSecret("s", AccountCookieEncryptionSalt)
	c, _ := DeriveEncryptionSecret("s", SessionCookieEncryptionSalt)
	if hex.EncodeToString(a) == hex.EncodeToString(b) {
		t.Error("session and account salts derived the same key")
	}
	if hex.EncodeToString(a) != hex.EncodeToString(c) {
		t.Error("derivation is not deterministic")
	}
	if _, err := DeriveEncryptionSecret("", "better-auth-session"); err == nil {
		t.Error("empty secret must be rejected")
	}
}

func TestOctThumbprintVector(t *testing.T) {
	// The JWE "kid" for the session key derived above.
	key, err := DeriveEncryptionSecret("secret-a-at-least-32-chars-long!!", "better-auth-session")
	if err != nil {
		t.Fatal(err)
	}
	got, err := OctThumbprint(key)
	if err != nil {
		t.Fatal(err)
	}
	const want = "j1rhto4vRQhKa1GhOM13Hs2XUzeuZHSHF9kAoNDL7Mw"
	if got != want {
		t.Fatalf("thumbprint = %q, want %q", got, want)
	}
	// RFC 7638 canonical '{"k":"...","kty":"oct"}'.
	canonical := `{"k":"` + base64.RawURLEncoding.EncodeToString(key) + `","kty":"oct"}`
	sum := sha256.Sum256([]byte(canonical))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != got {
		t.Fatal("thumbprint does not match the RFC 7638 canonical encoding")
	}
	// Deterministic, 43 chars, key-sensitive.
	again, _ := OctThumbprint(key)
	flipped := append(append([]byte{}, key...), 0)
	flipped[0] ^= 1
	other, _ := OctThumbprint(flipped)
	if again != got || len(got) != 43 || other == got {
		t.Fatalf("thumbprint properties: %q %q", again, other)
	}
	if _, err := OctThumbprint(nil); err == nil {
		t.Error("empty key must be rejected")
	}
}

func TestJWEConstants(t *testing.T) {
	if JWEKeyManagementAlg != "dir" || JWEContentEncryption != "A256CBC-HS512" {
		t.Errorf("jwe alg/enc = %q/%q", JWEKeyManagementAlg, JWEContentEncryption)
	}
	if JWEClockToleranceSeconds != 15 {
		t.Errorf("jwe clock tolerance = %d, want 15", JWEClockToleranceSeconds)
	}
	if EncryptionKeyInfo != "BetterAuth.js Generated Encryption Key" {
		t.Errorf("hkdf info = %q", EncryptionKeyInfo)
	}
	if SessionCookieEncryptionSalt != "better-auth-session" || AccountCookieEncryptionSalt != "better-auth-account" {
		t.Error("encryption salts changed")
	}
	if DerivedEncryptionKeyLen != 64 {
		t.Errorf("derived key len = %d, want 64", DerivedEncryptionKeyLen)
	}
	if strings.Contains(EncryptionKeyInfo, "\n") {
		t.Error("hkdf info must be the exact upstream byte string")
	}
}
