package crypto

// v1 ports of the crypto-owned cases in
// vendor/better-auth/packages/better-auth/src/crypto/secret-rotation.test.ts
// (envelope format + symmetricEncrypt/symmetricDecrypt rotation). The
// context secret helpers (parseSecretsEnv/validateSecretsArray/
// buildSecretConfig) live in src/context and belong to the sibling agent.

import (
	"strings"
	"testing"
)

const (
	v1SecretA = "secret-a-at-least-32-chars-long!!"
	v1SecretB = "secret-b-at-least-32-chars-long!!"
)

func TestV1_ParseEnvelopeVectors(t *testing.T) {
	if _, _, ok := ParseEnvelope("abcdef1234567890"); ok {
		t.Error("bare hex must not parse as envelope")
	}
	v, ct, ok := ParseEnvelope("$ba$2$abcdef1234567890")
	if !ok || v != 2 || ct != "abcdef1234567890" {
		t.Fatalf("parse = %d %q %v", v, ct, ok)
	}
	if _, _, ok := ParseEnvelope("$ba$-1$abcdef"); ok {
		t.Error("negative version must be rejected")
	}
	if _, _, ok := ParseEnvelope("$ba$abc$abcdef"); ok {
		t.Error("non-integer version must be rejected")
	}
	if got := FormatEnvelope(3, "deadbeef"); got != "$ba$3$deadbeef" {
		t.Fatalf("format = %q", got)
	}
}

func TestV1_SymmetricSingleStringBareHex(t *testing.T) {
	encrypted, err := SymmetricEncrypt(v1SecretA, "hello world")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(encrypted, "$ba$") {
		t.Fatalf("string-key payload must be bare hex, got %q", encrypted)
	}
	decrypted, err := SymmetricDecrypt(v1SecretA, encrypted)
	if err != nil || decrypted != "hello world" {
		t.Fatalf("decrypt = %q, %v", decrypted, err)
	}
}

func TestV1_SymmetricOneKeyEnvelope(t *testing.T) {
	cfg := SecretConfig{Keys: map[int]string{1: v1SecretA}, CurrentVersion: 1}
	encrypted, err := SymmetricEncrypt(cfg, "hello world")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encrypted, "$ba$1$") {
		t.Fatalf("envelope = %q, want $ba$1$ prefix", encrypted)
	}
	decrypted, err := SymmetricDecrypt(cfg, encrypted)
	if err != nil || decrypted != "hello world" {
		t.Fatalf("decrypt = %q, %v", decrypted, err)
	}
}

func TestV1_SymmetricRotation(t *testing.T) {
	cfg := SecretConfig{Keys: map[int]string{2: v1SecretB, 1: v1SecretA}, CurrentVersion: 2}
	encrypted, err := SymmetricEncrypt(cfg, "rotated data")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encrypted, "$ba$2$") {
		t.Fatalf("envelope = %q, want $ba$2$ prefix", encrypted)
	}
	if decrypted, err := SymmetricDecrypt(cfg, encrypted); err != nil || decrypted != "rotated data" {
		t.Fatalf("decrypt = %q, %v", decrypted, err)
	}
}

func TestV1_SymmetricDecryptOldKeyAfterRotation(t *testing.T) {
	oldCfg := SecretConfig{Keys: map[int]string{1: v1SecretA}, CurrentVersion: 1}
	encrypted, err := SymmetricEncrypt(oldCfg, "old data")
	if err != nil {
		t.Fatal(err)
	}
	newCfg := SecretConfig{Keys: map[int]string{2: v1SecretB, 1: v1SecretA}, CurrentVersion: 2}
	decrypted, err := SymmetricDecrypt(newCfg, encrypted)
	if err != nil || decrypted != "old data" {
		t.Fatalf("decrypt = %q, %v", decrypted, err)
	}
}

func TestV1_SymmetricLegacyBareHex(t *testing.T) {
	bareHex, err := SymmetricEncrypt(v1SecretA, "legacy data")
	if err != nil {
		t.Fatal(err)
	}
	cfg := SecretConfig{Keys: map[int]string{2: v1SecretB}, CurrentVersion: 2, LegacySecret: v1SecretA}
	decrypted, err := SymmetricDecrypt(cfg, bareHex)
	if err != nil || decrypted != "legacy data" {
		t.Fatalf("legacy decrypt = %q, %v", decrypted, err)
	}
	// Without the legacy secret the bare-hex payload fails closed.
	noLegacy := SecretConfig{Keys: map[int]string{2: v1SecretB}, CurrentVersion: 2}
	_, err = SymmetricDecrypt(noLegacy, bareHex)
	if err == nil || !strings.Contains(err.Error(), "no legacy secret available") {
		t.Fatalf("error = %v, want no-legacy-secret", err)
	}
}

func TestV1_SymmetricUnknownVersion(t *testing.T) {
	cfg := SecretConfig{Keys: map[int]string{1: v1SecretA}, CurrentVersion: 1}
	encrypted, err := SymmetricEncrypt(cfg, "test")
	if err != nil {
		t.Fatal(err)
	}
	retired := SecretConfig{Keys: map[int]string{2: v1SecretB}, CurrentVersion: 2}
	_, err = SymmetricDecrypt(retired, encrypted)
	if err == nil || !strings.Contains(err.Error(), "key may have been retired") {
		t.Fatalf("error = %v, want retired-key", err)
	}
}

func TestV1_SymmetricVersionGaps(t *testing.T) {
	cfg := SecretConfig{Keys: map[int]string{3: v1SecretB, 1: v1SecretA}, CurrentVersion: 3}
	encrypted, err := SymmetricEncrypt(cfg, "gapped")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encrypted, "$ba$3$") {
		t.Fatalf("envelope = %q, want $ba$3$ prefix", encrypted)
	}
	if decrypted, err := SymmetricDecrypt(cfg, encrypted); err != nil || decrypted != "gapped" {
		t.Fatalf("decrypt = %q, %v", decrypted, err)
	}
}
