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

// Upstream: legacy HMAC/AES-GCM bridge (no upstream file boundary).
type tokenPayload struct {
	Email     string `json:"email"`
	ExpiresAt int64  `json:"exp"`
	Nonce     string `json:"nonce"`
}

// GenerateToken creates an HMAC-signed token encoding email + expiry.
func GenerateToken(secret, email string, expiresIn time.Duration) (string, error) {
	return GenerateTokenWithExpiry(secret, email, time.Now().Add(expiresIn))
}

// GenerateTokenWithExpiry creates an HMAC-signed token with explicit expiry; emails lowercased at issuance.
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

// VerifyToken validates signature and expiry, returning email.
func VerifyToken(secret, token string) (email string, err error) {
	return VerifyTokenAny([]string{secret}, token)
}

// VerifyTokenAny validates against each secret for rotation.
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

// MakeSignature returns base64 HMAC-SHA256 of value.
func MakeSignature(value, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(value))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// VerifySignature reports whether sig is valid for any secret (constant-time).
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

// GenerateEncryptedToken creates an encrypted token; payload hidden so only secret holders read it.
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

// VerifyEncryptedToken validates an encrypted token, returning email.
func VerifyEncryptedToken(secret, token string) (string, error) {
	return VerifyEncryptedTokenAny([]string{secret}, token)
}

// VerifyEncryptedTokenAny validates against each secret for rotation.
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

// EncryptString encrypts plaintext with AES-256-GCM ("$brick$" format).
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

// DecryptString decrypts "$brick$" AES-GCM or upstream XChaCha20 so old and migrated ciphertexts read; existing "$brick$" reads never break.
func DecryptString(secret, ciphertext string) (string, error) {
	if strings.HasPrefix(ciphertext, "$brick$") {
		if plain, err := decryptBrick(secret, ciphertext); err == nil {
			return plain, nil
		} else {
			// Corrupt "$brick$" still tries upstream fallback so rotated writers never hard-break reads.
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
