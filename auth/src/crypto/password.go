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

// These parameters match @better-auth/utils/password in Better Auth v1.7.5.
const (
	scryptN       = 16384
	scryptR       = 16
	scryptP       = 1
	scryptKeyLen  = 64
	scryptSaltLen = 16
)

// HashPassword returns Better Auth's `hex(salt):hex(scrypt-key)` format.
// Passwords are NFKC-normalized to match the upstream implementation.
func HashPassword(password string) (string, error) {
	salt := make([]byte, scryptSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	saltHex := hex.EncodeToString(salt)
	// Better Auth passes the hex-encoded salt string to scrypt rather than the
	// decoded random bytes. Preserve that detail for cross-language hashes.
	key, err := scrypt.Key([]byte(norm.NFKC.String(password)), []byte(saltHex), scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return "", err
	}
	return saltHex + ":" + hex.EncodeToString(key), nil
}

// UpgradeHashIfNeeded verifies password against storedHash and, when the
// hash is a legacy bcrypt bridge entry ($2a$/$2b$/$2y$) that verifies, mints
// a fresh upstream scrypt hash for rotation (P11-GAP-1).
//
// Returns ("", false) when no upgrade applies: verification failed,
// malformed hash, or the hash is already the upstream scrypt format.
// Scrypt hashes never rehash here (upstream verify-only; no rehash-on-verify
// cost change). A hashing failure also yields ("", false) so callers keep
// the verified legacy hash rather than persisting an empty one.
//
// Merge owner (sign-in.go, NOT wired here — another agent owns that file):
//
//	if newHash, upgraded := crypto.UpgradeHashIfNeeded(storedHash, password); upgraded {
//	    // persist newHash to the credential account (UPDATE account SET password=newHash)
//	}
//
// Removal policy: keep the bcrypt bridge until no stored credential hash
// carries a $2* prefix; then delete the bridge and this helper together.
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

// VerifyPassword verifies Better Auth scrypt hashes. Bcrypt verification is
// retained as a migration bridge for hashes created by the pre-parity Go port;
// all newly generated hashes use the upstream scrypt format.
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
