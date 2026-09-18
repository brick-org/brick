package crypto

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// GO-ONLY EXTENSION (auth/SOURCE_LAYOUT_MOVE_LIST.md Cryptography): no
// standalone upstream file boundary in packages/better-auth/src/crypto/; the
// API-route email flows consume it via Create/VerifyEmailVerificationToken.
//
// Portable pieces of the upstream JWE session/account-cookie strategy,
// mirroring vendor/better-auth/packages/better-auth/src/crypto/jwt.ts
// (symmetricEncodeJWT/symmetricDecodeJWT).
//
// Upstream derives a 64-byte content-encryption key with HKDF-SHA256 over the
// auth secret (salted per cookie purpose: "better-auth-session" /
// "better-auth-account"), wraps payloads in an A256CBC-HS512 JWE
// (key-management "dir") whose "kid" is the JWK SHA-256 thumbprint of the
// derived key, and enforces a 15s clock tolerance on decrypt.
//
// The helpers below expose exactly the portable, JOSE-independent parts —
// key derivation and kid computation — so key lifecycle and test vectors can
// be validated without a JOSE stack. Full JWE issue/verify lives in
// cookies/jwt.go (Create/VerifySessionCacheJWE) and is wired at the
// route layer; never decode jwt/jwe cache payloads without it.
const (
	// JWEKeyManagementAlg is the upstream JWE key-management algorithm
	// ("dir": the derived key is used directly).
	JWEKeyManagementAlg = "dir"
	// JWEContentEncryption is the upstream JWE content-encryption algorithm
	// (64-byte key).
	JWEContentEncryption = "A256CBC-HS512"
	// JWEClockToleranceSeconds mirrors jwtDecryptOpts clockTolerance.
	JWEClockToleranceSeconds = 15
	// EncryptionKeyInfo is the HKDF info string, the UTF-8 bytes of
	// "BetterAuth.js Generated Encryption Key".
	EncryptionKeyInfo = "BetterAuth.js Generated Encryption Key"
	// SessionCookieEncryptionSalt is the HKDF salt for session-data cookies.
	SessionCookieEncryptionSalt = "better-auth-session"
	// AccountCookieEncryptionSalt is the HKDF salt for account-data cookies.
	AccountCookieEncryptionSalt = "better-auth-account"
)

// DerivedEncryptionKeyLen is the HKDF output length in bytes (A256CBC-HS512
// needs a 64-byte key).
const DerivedEncryptionKeyLen = 64

// DeriveEncryptionSecret derives the 64-byte JWE content-encryption key for
// salt from secret, mirroring upstream deriveEncryptionSecret:
//
//	hkdf(SHA-256, ikm=secret, salt=salt, info="BetterAuth.js Generated
//	Encryption Key", L=64)
//
// secret and salt are raw UTF-8 bytes. Different salts (session vs account)
// derive unrelated keys from the same secret.
func DeriveEncryptionSecret(secret, salt string) ([]byte, error) {
	if secret == "" {
		return nil, fmt.Errorf("crypto: secret is required")
	}
	saltBytes := []byte(salt)
	if len(saltBytes) == 0 {
		// RFC 5869 §2.2: a missing salt is the HashLen-zero string.
		saltBytes = make([]byte, sha256.Size)
	}
	r := hkdf.New(sha256.New, []byte(secret), saltBytes, []byte(EncryptionKeyInfo))
	key := make([]byte, DerivedEncryptionKeyLen)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("crypto: derive encryption secret: %w", err)
	}
	return key, nil
}

// OctThumbprint computes the RFC 7638 JWK SHA-256 thumbprint of a symmetric
// (oct) key, mirroring jose's calculateJwkThumbprint for the derived
// encryption key: base64url(SHA-256('{"k":"<base64url(key)>","kty":"oct"}')).
// Upstream stores this thumbprint as the JWE "kid" so decoders can select
// the secret whose derived key matches without trial-decrypting every
// rotated secret.
func OctThumbprint(key []byte) (string, error) {
	if len(key) == 0 {
		return "", fmt.Errorf("crypto: key is required")
	}
	// Struct (not map) keeps the RFC 7638 lexicographic member order
	// ("k" before "kty") deterministic.
	canonical, err := json.Marshal(struct {
		K   string `json:"k"`
		Kty string `json:"kty"`
	}{
		K:   base64.RawURLEncoding.EncodeToString(key),
		Kty: "oct",
	})
	if err != nil {
		return "", fmt.Errorf("crypto: thumbprint jwk: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}
