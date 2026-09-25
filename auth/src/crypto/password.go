package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/text/unicode/norm"
)

// Upstream crypto/password.ts; scrypt N=16384 r=16 p=1 keyLen=64 saltLen=16.
const (
	scryptN       = 16384
	scryptR       = 16
	scryptP       = 1
	scryptKeyLen  = 64
	scryptSaltLen = 16
)

// HashPassword returns Better Auth's `hex(salt):hex(scrypt-key)` format.
func HashPassword(password string) (string, error) {
	salt := make([]byte, scryptSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	saltHex := hex.EncodeToString(salt)
	// Hex-encoded (not raw) salt feeds scrypt for cross-language hashes.
	key, err := scrypt.Key([]byte(norm.NFKC.String(password)), []byte(saltHex), scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return "", err
	}
	return saltHex + ":" + hex.EncodeToString(key), nil
}

// UpgradeHashIfNeeded mints a fresh scrypt hash when a legacy bcrypt hash verifies.
// Scrypt hashes never rehash here; failures yield ("", false) so callers keep the verified hash.
func UpgradeHashIfNeeded(storedHash, password string) (newHash string, upgraded bool) {
	if !strings.HasPrefix(storedHash, "$2a$") && !strings.HasPrefix(storedHash, "$2b$") && !strings.HasPrefix(storedHash, "$2y$") {
		return "", false
	}
	if !VerifyPassword(storedHash, password) {
		return "", false
	}
	fresh, err := HashPassword(password)
	if err != nil || fresh == "" {
		return "", false
	}
	return fresh, true
}

// VerifyPassword verifies scrypt hashes; bcrypt remains only as a migration bridge.
func VerifyPassword(hash, password string) bool {
	if strings.HasPrefix(hash, "$2a$") || strings.HasPrefix(hash, "$2b$") || strings.HasPrefix(hash, "$2y$") {
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
	}
	parts := strings.Split(hash, ":")
	if len(parts) != 2 {
		return false
	}
	salt, err := hex.DecodeString(parts[0])
	if err != nil || len(salt) != scryptSaltLen {
		return false
	}
	want, err := hex.DecodeString(parts[1])
	if err != nil || len(want) != scryptKeyLen {
		return false
	}
	got, err := scrypt.Key([]byte(norm.NFKC.String(password)), []byte(parts[0]), scryptN, scryptR, scryptP, len(want))
	return err == nil && subtle.ConstantTimeCompare(got, want) == 1
}
