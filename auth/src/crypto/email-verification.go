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

// GO-ONLY EXTENSION (auth/SOURCE_LAYOUT_MOVE_LIST.md Cryptography): upstream
// issues email tokens from src/api/routes/email-verification.ts; the Go port
// factors issuance/verification here for the API routes to share.
//
// EmailVerificationPayload is the verified claim set of an upstream-compatible
// email verification JWT. It mirrors the payload written by upstream
// createEmailVerificationToken
// (vendor/better-auth/packages/better-auth/src/api/routes/email-verification.ts):
// lowercased email, optional lowercased updateTo, and any extra payload keys.
// RequestType carries the well-known "requestType" extra key used by the
// change-email flows ("change-email-confirmation" /
// "change-email-verification"); all other extra keys are preserved in Extra.
type EmailVerificationPayload struct {
	Email       string
	UpdateTo    string
	RequestType string
	Extra       map[string]any
	IssuedAt    time.Time
	ExpiresAt   time.Time
}

// DefaultEmailVerificationExpirySeconds mirrors the upstream default
// expiresIn (3600 seconds) of createEmailVerificationToken.
const DefaultEmailVerificationExpirySeconds = 3600

// CreateEmailVerificationToken issues an upstream-compatible HS256 JWT for
// email verification, mirroring createEmailVerificationToken: SignJWT with
// {alg: HS256}, iat, and exp = now + expiresIn over
// {email (lowercased), updateTo (lowercased, when set), ...extraPayload}.
// expiresInSeconds == 0 selects the upstream default (3600s); negative values
// produce already-expired tokens. extraPayload keys are spread last so they
// can extend (or, as upstream, override) the standard claims.
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

// signHS256 serializes claims as a compact HS256 JWT
// (base64url(header).base64url(payload).base64url(HMAC-SHA256)), mirroring
// upstream SignJWT with {alg: HS256} and no key-size floor.
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

// VerifyEmailVerificationToken verifies an email verification JWT against a
// single secret, mirroring the upstream verify-email endpoint (jwtVerify with
// algorithms ["HS256"] plus schema parsing of {email, updateTo?,
// requestType?}).
func VerifyEmailVerificationToken(secret, token string) (*EmailVerificationPayload, error) {
	return VerifyEmailVerificationTokenAny([]string{secret}, token)
}

// VerifyEmailVerificationTokenAny verifies an email verification JWT against
// each candidate secret in order, supporting secret rotation: new tokens are
// issued with the current secret while retained secrets still verify.
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

// VerifyEmailTokenWithFallback accepts BOTH the upstream HS256 JWT format
// (new) and the legacy two-part custom-HMAC format (GenerateToken) so email
// flows can be migrated without breaking outstanding tokens. JWT is tried
// first; the legacy path is a fallback for tokens issued before migration.
//
// NOTE for the api worker (auth/api/... is owned by another worker and is not
// touched here): wire email verification/reset call sites to this helper (or
// to VerifyEmailVerificationTokenAny + VerifyTokenAny) instead of calling
// VerifyTokenAny alone. Outstanding legacy tokens keep working until they
// expire; newly issued tokens should use CreateEmailVerificationToken.
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
