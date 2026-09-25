// Package crypto implements the Better Auth cryptography surface.
// Upstream crypto/
package crypto

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

// XChaCha20 with SHA-256(secret) key, random 24-byte nonce, "$ba$" envelopes; "$brick$" AES-GCM differs and reads via DecryptStringCompatible so old ciphertexts verify.
const (
	// EnvelopePrefix is the upstream "$ba$" envelope marker.
	EnvelopePrefix = "$ba$"
)

// SecretConfig mirrors upstream rotation: versioned keys plus optional legacy secret.
type SecretConfig struct {
	Keys           map[int]string
	CurrentVersion int
	LegacySecret   string
}

// ParseEnvelope splits a "$ba$<version>$<ciphertext>" envelope; returns ok=false for non-envelopes.
//
// DEVIATION (fail-closed STRICTER, kept — do not weaken): upstream uses
// parseInt(slice, 10), which accepts a numeric prefix (parseInt("1abc",10)
// === 1, so "$ba$1abc$..." parses as version 1); Go strconv.Atoi rejects the
// same input, so "$ba$1abc$..." fails closed here. Pinned by
// TestInitParseSecretsEnvStrictVersion; accepting prefixes would only widen
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

// FormatEnvelope builds a "$ba$<version>$<ciphertext>" envelope.
func FormatEnvelope(version int, ciphertext string) string {
	return EnvelopePrefix + strconv.Itoa(version) + "$" + ciphertext
}

// SymmetricEncrypt encrypts data with a string (bare-hex) or SecretConfig (versioned envelope).
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

// SymmetricDecrypt decrypts bare-hex (string) or envelope/legacy (SecretConfig) payloads.
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

// SymmetricDecryptAny tries each secret in order for rotation.
func SymmetricDecryptAny(secrets []string, data string) (string, error) {
	if version, ciphertext, ok := ParseEnvelope(data); ok {
		for _, secret := range secrets {
			_ = version
			if secret == "" {
				continue
			}
			// Bare-list entries cannot index versions, so every entry is a candidate.
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

// DecryptStringCompatible decrypts "$brick$" or upstream formats, trying "$brick$" first so existing reads never break.
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
