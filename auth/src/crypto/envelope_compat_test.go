package crypto

import (
	"strings"
	"testing"
)

func TestSymmetricEncryptDecryptStringKey(t *testing.T) {
	a, err := SymmetricEncrypt("secret", "plaintext")
	if err != nil {
		t.Fatal(err)
	}
	b, err := SymmetricEncrypt("secret", "plaintext")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("encryption must use random nonces")
	}
	// Bare-hex payload for string keys (upstream rawEncrypt).
	for _, c := range a {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("string-key payload must be bare hex, got %q", a)
		}
	}
	plain, err := SymmetricDecrypt("secret", a)
	if err != nil || plain != "plaintext" {
		t.Fatalf("decrypt = %q, %v", plain, err)
	}
	if _, err := SymmetricDecrypt("wrong", a); err == nil {
		t.Fatal("wrong secret decrypted ciphertext")
	}
}

func TestSymmetricEnvelopeRoundTrip(t *testing.T) {
	cfg := SecretConfig{
		Keys:           map[int]string{1: "old-secret", 2: "current-secret"},
		CurrentVersion: 2,
		LegacySecret:   "legacy-secret",
	}
	env, err := SymmetricEncrypt(cfg, "hello")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(env, "$ba$2$") {
		t.Fatalf("envelope = %q, want $ba$2$ prefix", env)
	}
	plain, err := SymmetricDecrypt(cfg, env)
	if err != nil || plain != "hello" {
		t.Fatalf("decrypt = %q, %v", plain, err)
	}
	// Retired version decrypts via retained keys.
	old := cfg
	old.CurrentVersion = 1
	oldEnv, err := SymmetricEncrypt(old, "old-data")
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := SymmetricDecrypt(cfg, oldEnv); err != nil || plain != "old-data" {
		t.Fatalf("rotated decrypt = %q, %v", plain, err)
	}
	// Legacy bare-hex decrypts via legacy secret.
	legacyHex, err := SymmetricEncrypt("legacy-secret", "legacy")
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := SymmetricDecrypt(cfg, legacyHex); err != nil || plain != "legacy" {
		t.Fatalf("legacy decrypt = %q, %v", plain, err)
	}
	// Unknown versions / missing legacy fail closed.
	bad, err := SymmetricEncrypt(SecretConfig{Keys: map[int]string{9: "s"}, CurrentVersion: 9}, "x")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SymmetricDecrypt(cfg, bad); err == nil {
		t.Fatal("unknown version decrypted")
	}
	noLegacy := SecretConfig{Keys: map[int]string{2: "current-secret"}, CurrentVersion: 2}
	if _, err := SymmetricDecrypt(noLegacy, legacyHex); err == nil {
		t.Fatal("legacy payload decrypted without legacy secret")
	}
	if _, err := SymmetricEncrypt(SecretConfig{}, "x"); err == nil {
		t.Fatal("missing version must error")
	}
}

func TestEncryptFormatsDifferAndDecryptFallsBack(t *testing.T) {
	// Legacy $brick$ (AES-GCM) vs upstream (XChaCha20) differ.
	brick, err := EncryptString("secret", "plaintext")
	if err != nil {
		t.Fatal(err)
	}
	upstream, err := SymmetricEncrypt("secret", "plaintext")
	if err != nil {
		t.Fatal(err)
	}
	if brick == upstream {
		t.Fatal("formats must differ")
	}
	// DecryptString keeps reading $brick$...
	if plain, err := DecryptString("secret", brick); err != nil || plain != "plaintext" {
		t.Fatalf("brick decrypt = %q, %v", plain, err)
	}
	// ...and upstream format (fallback).
	if plain, err := DecryptString("secret", upstream); err != nil || plain != "plaintext" {
		t.Fatalf("upstream fallback decrypt = %q, %v", plain, err)
	}
	// Wrong secrets fail on both formats.
	if _, err := DecryptString("wrong", brick); err == nil {
		t.Fatal("wrong secret decrypted $brick$ payload")
	}
	if _, err := DecryptString("wrong", upstream); err == nil {
		t.Fatal("wrong secret decrypted upstream payload")
	}
	// DecryptStringCompatible spans rotation on both formats.
	if plain, err := DecryptStringCompatible([]string{"old", "secret"}, upstream); err != nil || plain != "plaintext" {
		t.Fatalf("compatible decrypt = %q, %v", plain, err)
	}
	if plain, err := DecryptStringCompatible([]string{"old", "secret"}, brick); err != nil || plain != "plaintext" {
		t.Fatalf("compatible brick decrypt = %q, %v", plain, err)
	}
}

func TestParseEnvelope(t *testing.T) {
	v, ct, ok := ParseEnvelope("$ba$2$abcd")
	if !ok || v != 2 || ct != "abcd" {
		t.Fatalf("parse = %d %q %v", v, ct, ok)
	}
	if FormatEnvelope(2, "abcd") != "$ba$2$abcd" {
		t.Fatal("format mismatch")
	}
	for _, bad := range []string{"", "bare-hex", "$brick$xx", "$ba$nope", "$ba$-1$x"} {
		if _, _, ok := ParseEnvelope(bad); ok {
			t.Errorf("parsed non-envelope %q", bad)
		}
	}
}
