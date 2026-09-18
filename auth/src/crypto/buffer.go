package crypto

import (
	"crypto/subtle"
)

// Constant-time buffer comparison, mirroring
// vendor/better-auth/packages/better-auth/src/crypto/buffer.ts
// (constantTimeEqual).
//
// Inputs accept strings or byte slices; strings encode as UTF-8, matching the
// upstream TextEncoder path. Lengths mix into the comparison so unequal
// lengths fail, and the comparison runs over the full maximum length to avoid
// early-exit timing.
// ConstantTimeEqual reports whether a and b hold equal bytes without
// early-exit timing, mirroring upstream constantTimeEqual.
func ConstantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(normalizeConstantTimeInput(a), normalizeConstantTimeInput(b)) == 1
}

// ConstantTimeEqualString reports whether the UTF-8 encodings of a and b are
// equal in constant time. It is the string-input form of upstream
// constantTimeEqual (which TextEncoder-encodes string inputs).
func ConstantTimeEqualString(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func normalizeConstantTimeInput(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}
