package crypto

import (
	"crypto/rand"
	"math/big"
)

// Upstream crypto/random.ts
// Note: upstream generateId is alphanumeric-only; this alphabet adds -_ for tokens.
const idAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_"

// DefaultIDSize is the default identifier length (32).
const DefaultIDSize = 32

// GenerateID returns a 32-character random identifier.
func GenerateID() string {
	return GenerateIDWithSize(DefaultIDSize)
}

// GenerateIDWithSize returns an n-character identifier; non-positive sizes fall back to 32.
func GenerateIDWithSize(n int) string {
	if n <= 0 {
		n = DefaultIDSize
	}
	return GenerateRandomString(n)
}

// GenerateRandomString returns an n-character random string; non-positive lengths return empty.
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
