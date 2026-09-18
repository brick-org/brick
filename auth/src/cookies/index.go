package cookies

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

// Sign returns "value.hmac" where hmac is HMAC-SHA256 of value keyed with secret,
// base64url-encoded without padding — same algorithm as better-auth.
func Sign(secret, value string) (string, error) {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(value))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return value + "." + sig, nil
}

// Verify checks the signature and returns the original value and true on success.
func Verify(secret, signed string) (string, bool) {
	idx := strings.LastIndex(signed, ".")
	if idx < 0 {
		return "", false
	}
	value := signed[:idx]
	gotSig := signed[idx+1:]

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(value))
	wantSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(gotSig), []byte(wantSig)) {
		return "", false
	}
	return value, true
}

// VerifyAny checks the signature against each candidate secret in order.
func VerifyAny(secrets []string, signed string) (string, bool) {
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		if value, ok := Verify(secret, signed); ok {
			return value, true
		}
	}
	return "", false
}
