package crypto

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// PKCE S256 helpers (canonical implementation).
//
// Upstream threads PKCE through the OAuth2 flow (src/oauth2/state.ts carries
// the codeVerifier; the provider layer challenges/verifies); there is no
// standalone crypto/pkce.ts boundary. The Go port keeps the transform here
// and references it from oauth2/utils.go without duplicating behavior —
// callers in either package use S256Challenge/GenerateCodeChallenge/VerifyPKCE
// from this package.
//
// S256Challenge computes the PKCE S256 code challenge for a verifier:
// base64url(sha256(verifier)) with no padding. Matches better-auth's
// generateCodeChallenge (packages/core/src/oauth2/utils.ts) and is the only
// challenge method the Go port emits: upstream create-authorization-url
// always sets code_challenge_method=S256.
//
// The plain challenge mode (challenge == verifier, RFC 7636 §4.2) is
// intentionally NOT implemented: upstream never negotiates it, accepting it
// would let a network observer replay the challenge as the verifier, and
// VerifyPKCE therefore only ever checks the S256 transform. Call sites must
// reject "plain" explicitly rather than falling back to string equality.
func S256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// GenerateCodeChallenge mirrors upstream `generateCodeChallenge` (TS is async
// due to WebCrypto; Go's SHA-256 is synchronous).
func GenerateCodeChallenge(verifier string) string {
	return S256Challenge(verifier)
}

// VerifyPKCE reports whether verifier hashes (S256) to the given challenge.
// There is deliberately no "plain" fallback: a challenge that equals the
// verifier verbatim never verifies (see S256Challenge).
func VerifyPKCE(verifier, challenge string) bool {
	return subtle.ConstantTimeCompare([]byte(S256Challenge(verifier)), []byte(challenge)) == 1
}
