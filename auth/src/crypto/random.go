package crypto

import (
	"crypto/rand"
	"math/big"
)

// Better Auth's generateRandomString alphabet (a-z, 0-9, A-Z, -_).
// Note: upstream generateId uses alphanumeric only; GenerateID here uses the
// generateRandomString alphabet and serves both IDs and tokens. The conflation
// is documented in PARITY.md; use GenerateRandomString for token-oriented call
// sites when porting upstream behavior.
const idAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_"

// DefaultIDSize is the default Better Auth identifier length: generateId
// uses `size || 32` upstream (packages/core/src/utils/id.ts).
const DefaultIDSize = 32

// GenerateID returns a 32-character Better Auth random identifier.
func GenerateID() string {
	return GenerateIDWithSize(DefaultIDSize)
}

// GenerateIDWithSize returns an n-character Better Auth random identifier,
// mirroring upstream generateId(size?): non-positive sizes fall back to the
// 32-character default (JS `size || 32`). The alphabet is the same
// generateRandomString set used by GenerateID (see the documented deviation
// on idAlphabet).
func GenerateIDWithSize(n int) string {
	if n <= 0 {
		n = DefaultIDSize
	}
	return GenerateRandomString(n)
}

// GenerateRandomString returns an n-character random string using Better Auth's
// generateRandomString alphabet. It mirrors upstream `generateRandomString`
// for the default alphabet; custom alphabets are not yet supported.
// Non-positive lengths return an empty string (never panics).
func GenerateRandomString(n int) string {
	if n <= 0 {
		return ""
	}
	b := make([]byte, n)
	max := big.NewInt(int64(len(idAlphabet)))
	for i := range b {
		num, _ := rand.Int(rand.Reader, max)
		b[i] = idAlphabet[num.Int64()]
	}
	return string(b)
}
