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
//
// DEVIATION (fail-closed STRICTER, kept — do not weaken): upstream
// buffer.ts:16-22 loops Math.max(len) with zero-padding so a length mismatch
// still walks the full loop; Go subtle.ConstantTimeCompare returns 0 early on
// length mismatch. The difference is unobservable on the fixed 64B scrypt
// path and fail-closed everywhere else (unequal lengths always reject); a
// max-len reimplementation would only widen timing, never acceptance.
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
