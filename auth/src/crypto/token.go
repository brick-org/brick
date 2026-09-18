package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// GO-ONLY EXTENSION (auth/SOURCE_LAYOUT_MOVE_LIST.md Cryptography): legacy
// HMAC/AES-GCM token helpers with no upstream file boundary; retained as a
// migration bridge (see DecryptStringCompatible).
//
// tokenPayload is the JSON body embedded in a signed token.
type tokenPayload struct {
	Email     string `json:"email"`
	ExpiresAt int64  `json:"exp"`
	Nonce     string `json:"nonce"`
}

// GenerateToken creates an HMAC-signed token encoding email + expiry.
// Format: base64url(json(payload)).base64url(hmac-sha256(payload, secret))
func GenerateToken(secret, email string, expiresIn time.Duration) (string, error) {
	return GenerateTokenWithExpiry(secret, email, time.Now().Add(expiresIn))
}

// GenerateTokenWithExpiry creates an HMAC-signed token like GenerateToken
// but with an explicit expiry instant instead of a TTL. The wire format is
// identical; the explicit form exists for deterministic issuance (fixed test
// vectors) and for callers that already resolved the expiry. Emails are
// lowercased at issuance, matching upstream verification-token behavior.
func GenerateTokenWithExpiry(secret, email string, expiresAt time.Time) (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	p := tokenPayload{
		Email:     strings.ToLower(email),
		ExpiresAt: expiresAt.Unix(),
		Nonce:     base64.RawURLEncoding.EncodeToString(nonce),
	}
	payload, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	sig := signHMAC(secret, encoded)
	return encoded + "." + sig, nil
}

// VerifyToken validates the signature and expiry, returning the email on success.
func VerifyToken(secret, token string) (email string, err error) {
	return VerifyTokenAny([]string{secret}, token)
}

// VerifyTokenAny validates the signature against each secret and returns the
// embedded email on success.
func VerifyTokenAny(secrets []string, token string) (email string, err error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid token format")
	}
	encoded, sig := parts[0], parts[1]

	valid := false
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		if hmac.Equal([]byte(signHMAC(secret, encoded)), []byte(sig)) {
			valid = true
			break
		}
	}
	if !valid {
		return "", fmt.Errorf("invalid token signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("invalid token encoding")
	}
	var p tokenPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return "", fmt.Errorf("invalid token payload")
	}
	if time.Now().Unix() > p.ExpiresAt {
		return "", fmt.Errorf("token expired")
	}
	return p.Email, nil
}

func signHMAC(secret, data string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// MakeSignature returns the standard base64 HMAC-SHA256 of value, matching
// better-auth's makeSignature (used for signing OAuth authorization queries).
func MakeSignature(value, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(value))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// VerifySignature reports whether sig is a valid MakeSignature of value for any
// of the provided secrets, using a constant-time comparison.
func VerifySignature(value, sig string, secrets []string) bool {
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		if hmac.Equal([]byte(MakeSignature(value, secret)), []byte(sig)) {
			return true
		}
	}
	return false
}

// GenerateEncryptedToken creates an upstream-format encrypted token encoding
// email + expiry. Unlike GenerateToken (HMAC, payload visible on the wire),
// the payload is encrypted with SymmetricEncrypt (XChaCha20, string-key
// bare-hex wire format), so only secret holders can read the email or
// expiry. The HMAC token format is untouched; this is a separate wire format
// for callers that need confidentiality. Emails are lowercased at issuance.
func GenerateEncryptedToken(secret, email string, expiresIn time.Duration) (string, error) {
	if secret == "" {
		return "", fmt.Errorf("crypto: secret is required")
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	payload, err := json.Marshal(tokenPayload{
		Email:     strings.ToLower(email),
		ExpiresAt: time.Now().Add(expiresIn).Unix(),
		Nonce:     base64.RawURLEncoding.EncodeToString(nonce),
	})
	if err != nil {
		return "", err
	}
	return SymmetricEncrypt(secret, string(payload))
}

// VerifyEncryptedToken validates an encrypted token from
// GenerateEncryptedToken against a single secret, returning the email.
func VerifyEncryptedToken(secret, token string) (string, error) {
	return VerifyEncryptedTokenAny([]string{secret}, token)
}

// VerifyEncryptedTokenAny validates an encrypted token against each secret
// (rotation: retained secrets still verify) and returns the embedded email.
func VerifyEncryptedTokenAny(secrets []string, token string) (string, error) {
	plain, err := SymmetricDecryptAny(secrets, token)
	if err != nil {
		return "", fmt.Errorf("crypto: invalid encrypted token: %w", err)
	}
	var p tokenPayload
	if err := json.Unmarshal([]byte(plain), &p); err != nil || p.Email == "" {
		return "", fmt.Errorf("crypto: invalid encrypted token payload")
	}
	if time.Now().Unix() > p.ExpiresAt {
		return "", fmt.Errorf("crypto: token expired")
	}
	return p.Email, nil
}

// EncryptString encrypts plaintext with AES-256-GCM using a key derived from secret.
func EncryptString(secret, plaintext string) (string, error) {
	key := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := aead.Seal(nil, nonce, []byte(plaintext), nil)
	payload := append(nonce, ciphertext...)
	return "$brick$" + base64.RawURLEncoding.EncodeToString(payload), nil
}

// DecryptString decrypts ciphertext previously produced by EncryptString
// ("$brick$" AES-256-GCM). When the payload is not in the "$brick$" format it
// falls back to the upstream XChaCha20 format (SymmetricDecrypt) so both old
// and migrated ciphertexts read; existing "$brick$" reads never break. The
// formats differ — see symmetric.go — and new writes should prefer
// SymmetricEncrypt for upstream interoperability.
func DecryptString(secret, ciphertext string) (string, error) {
	if strings.HasPrefix(ciphertext, "$brick$") {
		if plain, err := decryptBrick(secret, ciphertext); err == nil {
			return plain, nil
		} else {
			// A "$brick$"-prefixed payload that fails AES-GCM is corrupt;
			// still try the upstream fallback before giving up so rotated
			// writers never hard-break reads, but prefer the original error
			// when both fail.
			if plain, fallbackErr := SymmetricDecrypt(secret, ciphertext); fallbackErr == nil {
				return plain, nil
			} else {
				return "", err
			}
		}
	}
	if plain, err := SymmetricDecrypt(secret, ciphertext); err == nil {
		return plain, nil
	}
	return decryptBrick(secret, ciphertext)
}

func decryptBrick(secret, ciphertext string) (string, error) {
	ciphertext = strings.TrimPrefix(ciphertext, "$brick$")
	payload, err := base64.RawURLEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	key := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(payload) < aead.NonceSize() {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce := payload[:aead.NonceSize()]
	data := payload[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, data, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
