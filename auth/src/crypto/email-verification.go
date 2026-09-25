package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Upstream api/routes/email-verification.ts
// EmailVerificationPayload is the verified claim set of an upstream-compatible email verification JWT.
type EmailVerificationPayload struct {
	Email       string
	UpdateTo    string
	RequestType string
	Extra       map[string]any
	IssuedAt    time.Time
	ExpiresAt   time.Time
}

// DefaultEmailVerificationExpirySeconds is the upstream default expiresIn (3600 seconds).
const DefaultEmailVerificationExpirySeconds = 3600

// CreateEmailVerificationToken issues an upstream-compatible HS256 JWT for email verification.
// expiresInSeconds == 0 selects the upstream default; negative values produce already-expired tokens.
//
// The JWT is built with the standard library rather than go-jose because
// upstream accepts secrets of any length (raw UTF-8 bytes) while go-jose
// enforces RFC 7518 minimum key sizes (HS256 >= 32 bytes). Short secrets
// must keep verifying for parity.
func CreateEmailVerificationToken(secret, email string, updateTo string, expiresInSeconds int, extraPayload map[string]any) (string, error) {
	if secret == "" {
		return "", fmt.Errorf("crypto: secret is required")
	}
	if expiresInSeconds == 0 {
		expiresInSeconds = DefaultEmailVerificationExpirySeconds
	}
	claims := map[string]any{}
	for k, v := range extraPayload {
		claims[k] = v
	}
	claims["email"] = strings.ToLower(email)
	if updateTo != "" {
		claims["updateTo"] = strings.ToLower(updateTo)
	}
	now := time.Now()
	std := map[string]any{
		"iat": now.Unix(),
		"exp": now.Add(time.Duration(expiresInSeconds) * time.Second).Unix(),
	}
	for k, v := range std {
		claims[k] = v
	}
	return signHS256(secret, claims)
}

// signHS256 builds HS256 JWT with stdlib so short secrets verify (no key-size floor).
func signHS256(secret string, claims map[string]any) (string, error) {
	header, err := json.Marshal(map[string]any{"alg": "HS256", "typ": "JWT"})
	if err != nil {
		return "", fmt.Errorf("crypto: sign email verification token: %w", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("crypto: sign email verification token: %w", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// VerifyEmailVerificationToken verifies an email verification JWT against a single secret.
func VerifyEmailVerificationToken(secret, token string) (*EmailVerificationPayload, error) {
	return VerifyEmailVerificationTokenAny([]string{secret}, token)
}

// VerifyEmailVerificationTokenAny verifies against each candidate secret in order for rotation.
func VerifyEmailVerificationTokenAny(secrets []string, token string) (*EmailVerificationPayload, error) {
	var lastErr error
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		payload, err := verifyEmailVerificationJWT(secret, token)
		if err == nil {
			return payload, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no auth secret configured")
	}
	return nil, lastErr
}

// VerifyEmailTokenWithFallback accepts both JWT (new) and legacy HMAC formats so migration never breaks outstanding tokens.
func VerifyEmailTokenWithFallback(secrets []string, token string) (email string, err error) {
	if payload, jwtErr := VerifyEmailVerificationTokenAny(secrets, token); jwtErr == nil {
		return payload.Email, nil
	}
	return VerifyTokenAny(secrets, token)
}

func verifyEmailVerificationJWT(secret, token string) (*EmailVerificationPayload, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("crypto: invalid email verification token")
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("crypto: invalid email verification token")
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerRaw, &header); err != nil || header.Alg != "HS256" {
		return nil, fmt.Errorf("crypto: invalid email verification token algorithm")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	wantSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(wantSig), []byte(parts[2])) {
		return nil, fmt.Errorf("crypto: invalid email verification token signature")
	}
	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("crypto: invalid email verification token payload")
	}
	claims := map[string]any{}
	if err := json.Unmarshal(payloadRaw, &claims); err != nil {
		return nil, fmt.Errorf("crypto: invalid email verification token payload")
	}
	exp, ok := numericClaim(claims["exp"])
	if !ok {
		return nil, fmt.Errorf("crypto: invalid email verification token payload")
	}
	if time.Now().Unix() > exp {
		return nil, fmt.Errorf("crypto: token expired")
	}
	email, _ := claims["email"].(string)
	if email == "" {
		return nil, fmt.Errorf("crypto: invalid email verification token payload")
	}
	payload := &EmailVerificationPayload{Email: email}
	if updateTo, _ := claims["updateTo"].(string); updateTo != "" {
		payload.UpdateTo = updateTo
	}
	if requestType, _ := claims["requestType"].(string); requestType != "" {
		payload.RequestType = requestType
	}
	if iat, ok := numericClaim(claims["iat"]); ok {
		payload.IssuedAt = time.Unix(iat, 0)
	}
	payload.ExpiresAt = time.Unix(exp, 0)
	extra := make(map[string]any)
	for k, v := range claims {
		switch k {
		case "email", "updateTo", "requestType", "exp", "iat", "nbf":
			continue
		default:
			extra[k] = v
		}
	}
	if len(extra) > 0 {
		payload.Extra = extra
	}
	return payload, nil
}
