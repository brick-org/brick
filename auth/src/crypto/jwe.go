package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	jose "github.com/go-jose/go-jose/v4"
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
// be validated without a JOSE stack. The generic JWE issue/verify port
// (SymmetricEncodeJWT/SymmetricDecodeJWT below, mirroring jwt.ts) lives here
// for crypto-owned rotation vectors; the typed session/account-cookie
// wrappers live in cookies/jwt.go (Create/VerifySessionCacheJWE) and are
// wired at the route layer; never decode jwt/jwe cache payloads without it.
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

// SymmetricEncodeJWT encrypts payload into a compact JWE, mirroring upstream
// symmetricEncodeJWT (jwt.ts:90-110): HKDF-derived dir/A256CBC-HS512 key for
// salt, kid set to the derived-key thumbprint, iat/exp/jti claims. key is a
// string (single secret) or SecretConfig (versioned envelope selection via
// the current version). expiresInSeconds defaults to 3600 when zero, matching
// the upstream default parameter.
func SymmetricEncodeJWT(payload map[string]any, key any, salt string, expiresInSeconds int) (string, error) {
	current, err := jweCurrentSecret(key)
	if err != nil {
		return "", err
	}
	derived, err := DeriveEncryptionSecret(current, salt)
	if err != nil {
		return "", err
	}
	kid, err := OctThumbprint(derived)
	if err != nil {
		return "", err
	}
	if expiresInSeconds == 0 {
		expiresInSeconds = 3600
	}
	now := time.Now().Unix()
	claims := make(map[string]any, len(payload)+3)
	for k, v := range payload {
		claims[k] = v
	}
	claims["iat"] = now
	claims["exp"] = now + int64(expiresInSeconds)
	claims["jti"] = newJWEJTI()
	plaintext, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("crypto: jwe encode payload: %w", err)
	}
	encrypter, err := jose.NewEncrypter(
		jose.A256CBC_HS512,
		jose.Recipient{Algorithm: jose.DIRECT, Key: derived},
		(&jose.EncrypterOptions{}).
			WithType("JWT").
			WithContentType("JWT").
			WithHeader(jose.HeaderKey("kid"), kid),
	)
	if err != nil {
		return "", fmt.Errorf("crypto: jwe encrypter: %w", err)
	}
	object, err := encrypter.Encrypt(plaintext)
	if err != nil {
		return "", fmt.Errorf("crypto: jwe encrypt: %w", err)
	}
	return object.CompactSerialize()
}

// SymmetricDecodeJWT decrypts a compact JWE issued by SymmetricEncodeJWT,
// mirroring upstream symmetricDecodeJWT (jwt.ts:118-185): kid selects the
// secret whose derived-key thumbprint matches (unknown kids fail closed with
// no fallback); kid-less tokens are tried against every candidate in order.
// Expiry enforces the upstream 15s clock tolerance; A256GCM payloads are
// accepted like jwtDecryptOpts (derived key truncated to 32 bytes). Empty
// tokens and undecryptable/tampered/expired payloads fail closed with an
// error (upstream returns null).
func SymmetricDecodeJWT(token string, key any, salt string) (map[string]any, error) {
	if token == "" {
		return nil, fmt.Errorf("crypto: invalid jwe encoding")
	}
	object, err := jose.ParseEncrypted(token,
		[]jose.KeyAlgorithm{jose.DIRECT},
		[]jose.ContentEncryption{jose.A256CBC_HS512, jose.A256GCM})
	if err != nil {
		return nil, fmt.Errorf("crypto: invalid jwe encoding")
	}
	type candidate struct {
		key []byte
		kid string
	}
	var candidates []candidate
	for _, secret := range jweAllSecrets(key) {
		if secret == "" {
			continue
		}
		derived, err := DeriveEncryptionSecret(secret, salt)
		if err != nil {
			continue
		}
		kid, err := OctThumbprint(derived)
		if err != nil {
			continue
		}
		candidates = append(candidates, candidate{key: derived, kid: kid})
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("crypto: no jwe secret available")
	}
	tryKeys := func(c candidate) [][]byte {
		if len(c.key) >= 32 {
			return [][]byte{c.key, c.key[:32]}
		}
		return [][]byte{c.key}
	}
	decryptWith := func(c candidate) (map[string]any, error) {
		var plaintext []byte
		var decErr error
		for _, k := range tryKeys(c) {
			plaintext, decErr = object.Decrypt(k)
			if decErr == nil {
				break
			}
		}
		if decErr != nil {
			return nil, decErr
		}
		var claims map[string]any
		if err := json.Unmarshal(plaintext, &claims); err != nil {
			return nil, fmt.Errorf("crypto: invalid jwe payload")
		}
		if exp, ok := numericClaim(claims["exp"]); ok && time.Now().Unix() > exp+JWEClockToleranceSeconds {
			return nil, fmt.Errorf("crypto: jwe expired")
		}
		return claims, nil
	}
	if kid := object.Header.KeyID; kid != "" {
		for _, c := range candidates {
			if c.kid == kid {
				claims, err := decryptWith(c)
				if err != nil {
					return nil, err
				}
				return claims, nil
			}
		}
		return nil, fmt.Errorf("crypto: no matching decryption secret")
	}
	// Kid-less: try the current (first) secret, then every remaining secret
	// (upstream symmetricDecodeJWT fallback).
	var lastErr error = fmt.Errorf("crypto: jwe decryption failed")
	for _, c := range candidates {
		claims, err := decryptWith(c)
		if err == nil {
			return claims, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// jweCurrentSecret selects the encryption secret for issuance, mirroring
// upstream getCurrentSecret (jwt.ts:62-71).
func jweCurrentSecret(key any) (string, error) {
	switch k := key.(type) {
	case string:
		if k == "" {
			return "", fmt.Errorf("crypto: secret is required")
		}
		return k, nil
	case SecretConfig:
		secret, ok := k.Keys[k.CurrentVersion]
		if !ok || secret == "" {
			return "", fmt.Errorf("crypto: secret version %d not found in keys", k.CurrentVersion)
		}
		return secret, nil
	case *SecretConfig:
		if k == nil {
			return "", fmt.Errorf("crypto: secret is required")
		}
		return jweCurrentSecret(*k)
	default:
		return "", fmt.Errorf("crypto: key must be a string or SecretConfig")
	}
}

// jweAllSecrets lists every candidate decryption secret, mirroring upstream
// getAllSecrets (jwt.ts:73-88): the versioned keys plus the legacy secret
// when its value is not already present. Order is deterministic (current
// first, then remaining versions ascending) so kid-less fallback tries the
// current secret before retained ones.
func jweAllSecrets(key any) []string {
	switch k := key.(type) {
	case string:
		return []string{k}
	case *SecretConfig:
		if k == nil {
			return nil
		}
		return jweAllSecrets(*k)
	case SecretConfig:
		seen := map[string]struct{}{}
		var out []string
		if cur, ok := k.Keys[k.CurrentVersion]; ok && cur != "" {
			out = append(out, cur)
			seen[cur] = struct{}{}
		}
		versions := make([]int, 0, len(k.Keys))
		for v := range k.Keys {
			if v == k.CurrentVersion {
				continue
			}
			versions = append(versions, v)
		}
		sort.Ints(versions)
		for _, v := range versions {
			if s := k.Keys[v]; s != "" {
				if _, dup := seen[s]; !dup {
					out = append(out, s)
					seen[s] = struct{}{}
				}
			}
		}
		if k.LegacySecret != "" {
			if _, dup := seen[k.LegacySecret]; !dup {
				out = append(out, k.LegacySecret)
			}
		}
		return out
	default:
		return nil
	}
}

// newJWEJTI mints the random jti claim EncryptJWT sets on every payload.
// Uniqueness is transport-only: neither upstream nor this runtime tracks jtis
// for replay.
func newJWEJTI() string {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(nonce[:])
}
