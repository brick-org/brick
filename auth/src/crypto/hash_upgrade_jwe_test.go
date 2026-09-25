package crypto

// F11: bcrypt->scrypt rehash + JWE multi-secret legs (secret-rotation.test.ts:187-293); stricter deviations kept.

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

const (
	f11SecretA = "secret-a-at-least-32-chars-long!!"
	f11SecretB = "secret-b-at-least-32-chars-long!!"
	f11Salt    = "test-salt"
)

// bcrypt->scrypt rehash helper.

func TestHashUpgrade__BcryptToScrypt(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("legacy-password"), 4)
	if err != nil {
		t.Fatal(err)
	}
	stored := string(hash)
	newHash, upgraded := UpgradeHashIfNeeded(stored, "legacy-password")
	if !upgraded {
		t.Fatal("legacy bcrypt hash with correct password must upgrade")
	}
	if newHash == "" || newHash == stored {
		t.Fatalf("newHash must be a fresh non-empty hash, got %q", newHash)
	}
	if strings.HasPrefix(newHash, "$2a$") || strings.HasPrefix(newHash, "$2b$") || strings.HasPrefix(newHash, "$2y$") {
		t.Fatalf("newHash must be scrypt format, got %q", newHash)
	}
	if !VerifyPassword(newHash, "legacy-password") {
		t.Fatal("fresh scrypt hash did not verify")
	}
	if VerifyPassword(newHash, "wrong-password") {
		t.Fatal("fresh scrypt hash verified wrong password")
	}
}

func TestHashUpgrade__WrongPasswordNoUpgrade(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("legacy-password"), 4)
	if err != nil {
		t.Fatal(err)
	}
	if newHash, upgraded := UpgradeHashIfNeeded(string(hash), "wrong-password"); upgraded || newHash != "" {
		t.Fatalf("wrong password must not upgrade, got %q %v", newHash, upgraded)
	}
}

func TestHashUpgrade__ScryptNoUpgrade(t *testing.T) {
	hash, err := HashPassword("scrypt-password")
	if err != nil {
		t.Fatal(err)
	}
	if newHash, upgraded := UpgradeHashIfNeeded(hash, "scrypt-password"); upgraded || newHash != "" {
		t.Fatalf("valid scrypt hash must not upgrade, got %q %v", newHash, upgraded)
	}
	if newHash, upgraded := UpgradeHashIfNeeded(hash, "wrong"); upgraded || newHash != "" {
		t.Fatalf("scrypt hash with wrong password must not upgrade, got %q %v", newHash, upgraded)
	}
}

func TestHashUpgrade__MalformedNoUpgrade(t *testing.T) {
	for _, bad := range []string{"", "no-colon", "00:00", "zz:zz", "$2b$bad"} {
		if newHash, upgraded := UpgradeHashIfNeeded(bad, "password"); upgraded || newHash != "" {
			t.Errorf("malformed hash %q must not upgrade, got %q %v", bad, newHash, upgraded)
		}
	}
}

// JWE multi-secret legs (secret-rotation.test.ts:187-293).

func TestJWE__SingleSecretString(t *testing.T) {
	token, err := SymmetricEncodeJWT(map[string]any{"foo": "bar"}, f11SecretA, f11Salt, 3600)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := SymmetricDecodeJWT(token, f11SecretA, f11Salt)
	if err != nil {
		t.Fatal(err)
	}
	if decoded["foo"] != "bar" {
		t.Fatalf("decoded = %v, want foo=bar", decoded)
	}
}

func TestJWE__SameConfig(t *testing.T) {
	cfg := SecretConfig{Keys: map[int]string{1: f11SecretA}, CurrentVersion: 1}
	token, err := SymmetricEncodeJWT(map[string]any{"foo": "bar"}, cfg, f11Salt, 3600)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := SymmetricDecodeJWT(token, cfg, f11Salt)
	if err != nil {
		t.Fatal(err)
	}
	if decoded["foo"] != "bar" {
		t.Fatalf("decoded = %v, want foo=bar", decoded)
	}
}

func TestJWE__RotatedContainingOldKey(t *testing.T) {
	oldCfg := SecretConfig{Keys: map[int]string{1: f11SecretA}, CurrentVersion: 1}
	token, err := SymmetricEncodeJWT(map[string]any{"foo": "bar"}, oldCfg, f11Salt, 3600)
	if err != nil {
		t.Fatal(err)
	}
	newCfg := SecretConfig{Keys: map[int]string{2: f11SecretB, 1: f11SecretA}, CurrentVersion: 2}
	decoded, err := SymmetricDecodeJWT(token, newCfg, f11Salt)
	if err != nil {
		t.Fatal(err)
	}
	if decoded["foo"] != "bar" {
		t.Fatalf("decoded = %v, want foo=bar", decoded)
	}
}

func TestJWE__KidLessFallbackTriesAllSecrets(t *testing.T) {
	// Upstream secret-rotation.test.ts:248-272 (kid selects retained key).
	token, err := SymmetricEncodeJWT(map[string]any{"foo": "bar"}, f11SecretA, f11Salt, 3600)
	if err != nil {
		t.Fatal(err)
	}
	cfg := SecretConfig{
		Keys:           map[int]string{2: f11SecretB, 1: f11SecretA},
		CurrentVersion: 2,
		LegacySecret:   f11SecretA,
	}
	decoded, err := SymmetricDecodeJWT(token, cfg, f11Salt)
	if err != nil {
		t.Fatal(err)
	}
	if decoded["foo"] != "bar" {
		t.Fatalf("decoded = %v, want foo=bar", decoded)
	}
}

func TestJWE__LegacyStringConfig(t *testing.T) {
	// Upstream secret-rotation.test.ts:274-293 (legacySecret verifies).
	token, err := SymmetricEncodeJWT(map[string]any{"foo": "bar"}, f11SecretA, f11Salt, 3600)
	if err != nil {
		t.Fatal(err)
	}
	cfg := SecretConfig{
		Keys:           map[int]string{2: f11SecretB},
		CurrentVersion: 2,
		LegacySecret:   f11SecretA,
	}
	decoded, err := SymmetricDecodeJWT(token, cfg, f11Salt)
	if err != nil {
		t.Fatal(err)
	}
	if decoded["foo"] != "bar" {
		t.Fatalf("decoded = %v, want foo=bar", decoded)
	}
}

func TestJWE__MismatchedKidNoFallback(t *testing.T) {
	// Upstream secret-rotation.test.ts:295-319 (no fallback, Go: error).
	cfgA := SecretConfig{Keys: map[int]string{1: f11SecretA}, CurrentVersion: 1}
	token, err := SymmetricEncodeJWT(map[string]any{"foo": "bar"}, cfgA, f11Salt, 3600)
	if err != nil {
		t.Fatal(err)
	}
	cfgB := SecretConfig{Keys: map[int]string{2: f11SecretB}, CurrentVersion: 2}
	if _, err := SymmetricDecodeJWT(token, cfgB, f11Salt); err == nil {
		t.Fatal("mismatched kid must fail closed")
	}
}

// Deviation pins (fail-closed stricter, kept).

func TestConstantTimeEqual_LengthMismatchFails(t *testing.T) {
	if !ConstantTimeEqual([]byte("abc"), []byte("abc")) {
		t.Error("equal inputs must compare equal")
	}
	if ConstantTimeEqual([]byte("abc"), []byte("abcd")) {
		t.Error("length-mismatched inputs must fail (fail-closed stricter than upstream max-len loop)")
	}
	if ConstantTimeEqualString("abc", "abcd") {
		t.Error("string length-mismatched inputs must fail")
	}
}

func TestParseEnvelope_StrictRejectsPrefix(t *testing.T) {
	// Upstream parseInt accepts "1abc"; Go Atoi rejects (stricter).
	if _, _, ok := ParseEnvelope("$ba$1abc$deadbeef"); ok {
		t.Error("prefix version must be rejected (stricter than upstream parseInt)")
	}
	if _, _, ok := ParseEnvelope("$ba$2$abcdef"); !ok {
		t.Error("valid envelope must parse")
	}
}
