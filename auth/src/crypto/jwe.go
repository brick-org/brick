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
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/crypto/hkdf"
)

// Upstream crypto/jwt.ts
const (
	// JWEKeyManagementAlg is the upstream JWE key-management algorithm ("dir").
	JWEKeyManagementAlg = "dir"
	// JWEContentEncryption is the upstream content-encryption algorithm (64-byte key).
	JWEContentEncryption = "A256CBC-HS512"
	// JWEClockToleranceSeconds mirrors jwtDecryptOpts clockTolerance.
	JWEClockToleranceSeconds = 15
	// EncryptionKeyInfo is the HKDF info string "BetterAuth.js Generated Encryption Key".
	EncryptionKeyInfo = "BetterAuth.js Generated Encryption Key"
	// SessionCookieEncryptionSalt is the HKDF salt for session-data cookies.
	SessionCookieEncryptionSalt = "better-auth-session"
	// AccountCookieEncryptionSalt is the HKDF salt for account-data cookies.
	AccountCookieEncryptionSalt = "better-auth-account"
)

// DerivedEncryptionKeyLen is the HKDF output length in bytes (64 for A256CBC-HS512).
const DerivedEncryptionKeyLen = 64

// DeriveEncryptionSecret derives the 64-byte JWE key via HKDF-SHA256(secret, salt, info, L=64).
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

// OctThumbprint computes the RFC 7638 JWK SHA-256 thumbprint of a symmetric key.
// Upstream stores this as JWE "kid" so decoders select keys without trial-decrypting.
func OctThumbprint(key []byte) (string, error) {
	if len(key) == 0 {
		return "", fmt.Errorf("crypto: key is required")
	}
	// Struct (not map) keeps RFC 7638 lexicographic order deterministic.
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

// SymmetricEncodeJWT encrypts payload into a compact JWE with HKDF-derived dir/A256CBC-HS512 key.
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

// SymmetricDecodeJWT decrypts a compact JWE issued by SymmetricEncodeJWT.
// secret whose derived-key thumbprint matches (unknown kids fail closed with
// no fallback); kid-less tokens are tried against every candidate in order.
// Empty tokens and undecryptable/tampered/expired payloads fail
// closed with an error.
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
	enc, err := jweContentEncryption(token)
	if err != nil {
		return nil, err
	}
	decryptWith := func(c candidate) (map[string]any, error) {
		var plaintext []byte
		var decErr error
		for _, k := range jweDecryptionKeys(c.key, enc) {
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
	// Kid-less tries current secret first, then retained ones.
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

// jweDecryptionKeys uses full 64-byte key, truncated to 32 bytes for A256GCM payloads.
func jweDecryptionKeys(key []byte, enc string) [][]byte {
	if jose.ContentEncryption(enc) == jose.A256GCM && len(key) >= 32 {
		return [][]byte{key[:32]}
	}
	return [][]byte{key}
}

// jweContentEncryption reads "enc" without a JOSE round-trip.
func jweContentEncryption(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 5 {
		return "", fmt.Errorf("crypto: invalid jwe encoding")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("crypto: invalid jwe encoding")
	}
	var header struct {
		Enc string `json:"enc"`
	}
	if err := json.Unmarshal(raw, &header); err != nil || header.Enc == "" {
		return "", fmt.Errorf("crypto: invalid jwe encoding")
	}
	return header.Enc, nil
}

// jweCurrentSecret selects the issuance secret.
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

// jweAllSecrets lists candidates current-first for kid-less fallback.
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

// newJWEJTI mints the random jti claim.
func newJWEJTI() string {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(nonce[:])
}
