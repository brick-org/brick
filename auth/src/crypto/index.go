// Package crypto implements the Better Auth cryptography surface.
//
// Upstream: vendor/better-auth/packages/better-auth/src/crypto/
// (buffer.ts, index.ts, jwt.ts, password.ts, random.ts).
//
// File map:
//   - index.go mirrors crypto/index.ts (XChaCha20 symmetricEncrypt /
//     symmetricDecrypt with "$ba$" version envelopes).
//   - buffer.go mirrors crypto/buffer.ts (constant-time comparison).
//   - jwt.go mirrors the JWT-plugin surface (EdDSA/ES*/RS*/PS* + JWKS,
//     kid-selected fail-closed); the crypto/jwt.ts HS256 sign/verify used by
//     core lives in email-verification.go (short-secret-safe stdlib HMAC)
//     and cookies/jwt.go (session-cache JWT codec), not here.
//   - jwe.go carries the JWE key derivation and thumbprint helpers used by
//     the session/account cookie codecs.
//   - password.go mirrors crypto/password.ts (scrypt hash/verify).
//   - random.go mirrors crypto/random.ts (identifier and token randomness).

// GO-ONLY EXTENSIONS (no upstream counterpart in
// packages/better-auth/src/crypto/): email-verification.go (email-token JWT
// helpers consumed by the API routes), jwe.go (portable HKDF/thumbprint
// helpers factored out of jwt.go), pkce.go (S256 challenge/verify; upstream
// threads PKCE through the OAuth2 flow in src/oauth2/state.ts and the
// provider layer — see ../../oauth2/utils.go), and token.go (legacy HMAC and
// AES-GCM token helpers kept as a migration bridge).
package crypto

// --- implementation (upstream crypto/index.ts; moved from symmetric.go,
// same package, no behavior change) ---

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

// GO-ONLY EXTENSION (auth/SOURCE_LAYOUT_MOVE_LIST.md Cryptography): upstream
// exposes this wire format through crypto/index.ts (symmetricEncrypt /
// symmetricDecrypt); it is kept as a separate Go file boundary.
//
// Upstream encryption wire format
// (vendor/better-auth/packages/better-auth/src/crypto/index.ts):
//
//   - Key derivation: SHA-256(secret) bytes.
//   - Cipher: XChaCha20-Poly1305 with a managed (random, prepended) 24-byte
//     nonce. Ciphertext is hex-encoded as nonce || ciphertext+tag.
//   - String keys produce a bare-hex payload (rawEncrypt).
//   - SecretConfig keys produce an envelope: "$ba$<version>$<hex>"
//     (formatEnvelope), with legacy bare-hex payloads decryptable via the
//     legacy secret (symmetricDecrypt).
//
// The pre-existing EncryptString/DecryptString pair in token.go instead uses
// AES-256-GCM with a base64url nonce||ciphertext payload under a "$brick$"
// prefix. The formats DIFFER: neither side reads the other's ciphertext.
// The helpers below implement the upstream format; DecryptString keeps reading
// "$brick$" payloads and now falls back to the upstream format so both old
// and new ciphertexts verify (never break existing reads).
const (
	// EnvelopePrefix is the upstream "$ba$" envelope marker.
	EnvelopePrefix = "$ba$"
)

// SecretConfig mirrors the upstream SecretConfig (secret rotation): versioned
// keys with a current version plus an optional legacy secret for bare-hex
// payloads issued before rotation.
type SecretConfig struct {
	Keys           map[int]string
	CurrentVersion int
	LegacySecret   string
}

// ParseEnvelope splits a "$ba$<version>$<ciphertext>" envelope, mirroring
// upstream parseEnvelope. It returns ok=false for non-envelope payloads.
//
// DEVIATION (fail-closed STRICTER, kept — do not weaken): upstream uses
// parseInt(slice, 10), which accepts a numeric prefix (parseInt("1abc",10)
// === 1, so "$ba$1abc$..." parses as version 1); Go strconv.Atoi rejects the
// same input, so "$ba$1abc$..." fails closed here. Pinned by
// TestF6ParseSecretsEnvStrictVersion; accepting prefixes would only widen
// acceptance, never fix a ported leg.
func ParseEnvelope(data string) (version int, ciphertext string, ok bool) {
	if !strings.HasPrefix(data, EnvelopePrefix) {
		return 0, "", false
	}
	rest := data[len(EnvelopePrefix):]
	sep := strings.Index(rest, "$")
	if sep < 0 {
		return 0, "", false
	}
	version, err := strconv.Atoi(rest[:sep])
	if err != nil || version < 0 {
		return 0, "", false
	}
	return version, rest[sep+1:], true
}

// FormatEnvelope builds a "$ba$<version>$<ciphertext>" envelope, mirroring
// upstream formatEnvelope.
func FormatEnvelope(version int, ciphertext string) string {
	return EnvelopePrefix + strconv.Itoa(version) + "$" + ciphertext
}

// SymmetricEncrypt encrypts data with key, mirroring upstream
// symmetricEncrypt. key is either a string (bare-hex payload) or a
// SecretConfig (versioned "$ba$" envelope using the current version).
func SymmetricEncrypt(key any, data string) (string, error) {
	switch k := key.(type) {
	case string:
		if k == "" {
			return "", fmt.Errorf("crypto: secret is required")
		}
		return rawEncrypt(k, data)
	case SecretConfig:
		secret, ok := k.Keys[k.CurrentVersion]
		if !ok || secret == "" {
			return "", fmt.Errorf("crypto: secret version %d not found in keys", k.CurrentVersion)
		}
		ciphertext, err := rawEncrypt(secret, data)
		if err != nil {
			return "", err
		}
		return FormatEnvelope(k.CurrentVersion, ciphertext), nil
	case *SecretConfig:
		if k == nil {
			return "", fmt.Errorf("crypto: secret is required")
		}
		return SymmetricEncrypt(*k, data)
	default:
		return "", fmt.Errorf("crypto: key must be a string or SecretConfig")
	}
}

// SymmetricDecrypt decrypts data with key, mirroring upstream
// symmetricDecrypt. String keys decrypt bare-hex payloads; SecretConfig keys
// decrypt "$ba$" envelopes via the matching version and legacy bare-hex
// payloads via the legacy secret.
func SymmetricDecrypt(key any, data string) (string, error) {
	switch k := key.(type) {
	case string:
		if k == "" {
			return "", fmt.Errorf("crypto: secret is required")
		}
		return rawDecrypt(k, data)
	case SecretConfig:
		if version, ciphertext, ok := ParseEnvelope(data); ok {
			secret, found := k.Keys[version]
			if !found || secret == "" {
				return "", fmt.Errorf("crypto: secret version %d not found in keys (key may have been retired)", version)
			}
			return rawDecrypt(secret, ciphertext)
		}
		if k.LegacySecret == "" {
			return "", fmt.Errorf("crypto: cannot decrypt legacy bare-hex payload: no legacy secret available")
		}
		return rawDecrypt(k.LegacySecret, data)
	case *SecretConfig:
		if k == nil {
			return "", fmt.Errorf("crypto: secret is required")
		}
		return SymmetricDecrypt(*k, data)
	default:
		return "", fmt.Errorf("crypto: key must be a string or SecretConfig")
	}
}

// SymmetricDecryptAny tries each secret in order against the upstream
// (XChaCha20) format, supporting rotation for versioned and bare-hex
// payloads. Envelope payloads select their version directly; bare-hex
// payloads are tried against every secret.
func SymmetricDecryptAny(secrets []string, data string) (string, error) {
	if version, ciphertext, ok := ParseEnvelope(data); ok {
		for _, secret := range secrets {
			_ = version
			if secret == "" {
				continue
			}
			// Envelope versions index into SecretConfig, not a bare list; for
			// a bare secret list every entry is a candidate for the payload.
			if plain, err := rawDecrypt(secret, ciphertext); err == nil {
				return plain, nil
			}
		}
		return "", fmt.Errorf("crypto: cannot decrypt envelope payload with the provided secrets")
	}
	var lastErr error
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		plain, err := rawDecrypt(secret, data)
		if err == nil {
			return plain, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no auth secret configured")
	}
	return "", lastErr
}

// DecryptStringCompatible decrypts ciphertext in EITHER the legacy "$brick$"
// AES-GCM format or the upstream XChaCha20 format, trying "$brick$" first so
// existing reads never break. secrets[0] is the current secret; retained
// secrets support rotation.
func DecryptStringCompatible(secrets []string, ciphertext string) (string, error) {
	if strings.HasPrefix(ciphertext, "$brick$") {
		for _, secret := range secrets {
			if secret == "" {
				continue
			}
			if plain, err := DecryptString(secret, ciphertext); err == nil {
				return plain, nil
			}
		}
	}
	return SymmetricDecryptAny(secrets, ciphertext)
}

func chachaAEAD(secret string) (cipher.AEAD, error) {
	key := sha256.Sum256([]byte(secret))
	return chacha20poly1305.NewX(key[:])
}

func rawEncrypt(secret, data string) (string, error) {
	aead, err := chachaAEAD(secret)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nil, nonce, []byte(data), nil)
	payload := append(nonce, sealed...)
	return hex.EncodeToString(payload), nil
}

func rawDecrypt(secret, hexPayload string) (string, error) {
	aead, err := chachaAEAD(secret)
	if err != nil {
		return "", err
	}
	payload, err := hex.DecodeString(strings.TrimSpace(hexPayload))
	if err != nil {
		return "", fmt.Errorf("crypto: invalid ciphertext encoding")
	}
	if len(payload) < aead.NonceSize() {
		return "", fmt.Errorf("crypto: ciphertext too short")
	}
	nonce := payload[:aead.NonceSize()]
	data := payload[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, data, nil)
	if err != nil {
		return "", fmt.Errorf("crypto: decryption failed")
	}
	return string(plain), nil
}
