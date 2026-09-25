package crypto

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// Upstream oauth2/utils.ts
// S256Challenge computes base64url(sha256(verifier)) with no padding.
// Plain mode is NOT implemented: upstream never negotiates it and accepting it lets observers replay; call sites must reject "plain".
func S256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// GenerateCodeChallenge mirrors upstream `generateCodeChallenge`.
func GenerateCodeChallenge(verifier string) string {
	return S256Challenge(verifier)
}

// VerifyPKCE reports whether verifier hashes (S256) to challenge; no "plain" fallback.
func VerifyPKCE(verifier, challenge string) bool {
	return subtle.ConstantTimeCompare([]byte(S256Challenge(verifier)), []byte(challenge)) == 1
}
