package jwt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"time"

	"github.com/brick-org/brick/auth/src/cookies"
	authcrypto "github.com/brick-org/brick/auth/src/crypto"
	authtypes "github.com/brick-org/brick/auth/src/types"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const defaultCookieCacheMaxAge = 5 * time.Minute

var errCookieCacheSignerDisabled = errors.New("jwt: session cookie-cache signing is disabled")

type cookieCachePayload struct {
	Session   map[string]any
	User      map[string]any
	UpdatedAt int64
	Version   string
}

type cookieCacheVerified struct {
	Payload   cookieCachePayload
	ExpiresAt int64
}

// cookieCacheSigner is embedded by the JWT plugin when its JWKS store is ready.
type cookieCacheSigner struct {
	signer   Signer
	verifier Verifier
	enabled  bool
}

func newCookieCacheSigner(signer Signer, verifier Verifier, enabled bool) cookieCacheSigner {
	return cookieCacheSigner{signer: signer, verifier: verifier, enabled: enabled}
}

// SignCookieCache signs the upstream session-cache claim set using the plugin's active JWKS key.
func (s *cookieCacheSigner) SignCookieCache(ctx context.Context, opts authtypes.Options, payload cookieCachePayload, maxAge time.Duration) (string, error) {
	if !s.enabled {
		return "", errCookieCacheSignerDisabled
	}
	if s.signer == nil {
		return "", errors.New("jwt: session cookie-cache signer is unavailable")
	}
	if err := validateCookieCachePayload(payload); err != nil {
		return "", err
	}
	if maxAge <= 0 {
		maxAge = defaultCookieCacheMaxAge
	}

	now := time.Now()
	expiresAt := now.Add(maxAge).Unix()
	if expiresAt <= now.Unix() {
		return "", errors.New("jwt: session cookie-cache expiration must be in the future")
	}
	userID := payload.User["id"].(string)
	sessionToken := payload.Session["token"].(string)
	issuer := cookieCacheIssuer(opts)

	resolved, err := s.signer.ResolveSigningKey(ctx, SigningKeyOverrides{Typ: authcrypto.SessionCookieJWTType})
	if err != nil {
		return "", fmt.Errorf("jwt: resolve session cookie-cache signing key: %w", err)
	}
	if resolved.KeyID == "" || resolved.Algorithm == "" {
		return "", errors.New("jwt: session cookie-cache signing key is missing kid or algorithm")
	}
	claims := Payload{
		"iss":       issuer,
		"aud":       authcrypto.SessionCookieJWTAudience,
		"sub":       userID,
		"sid":       sessionToken,
		"iat":       now.Unix(),
		"exp":       expiresAt,
		"session":   payload.Session,
		"user":      payload.User,
		"updatedAt": payload.UpdatedAt,
		"version":   payload.Version,
	}
	token, err := s.signer.SignJWT(ctx, claims, SigningKeyOverrides{
		SigningKeyID:     resolved.KeyID,
		SigningAlgorithm: resolved.Algorithm,
		Typ:              authcrypto.SessionCookieJWTType,
	})
	if err != nil {
		return "", fmt.Errorf("jwt: sign session cookie-cache JWT: %w", err)
	}
	parsed, err := parseCookieCacheJWT(token)
	if err != nil {
		return "", err
	}
	header := parsed.Headers[0]
	if cookieCacheJWTType(header) != authcrypto.SessionCookieJWTType || header.KeyID != resolved.KeyID || header.Algorithm != string(resolved.Algorithm) {
		return "", errors.New("jwt: session cookie-cache signer returned an unexpected protected header")
	}
	return token, nil
}

// VerifyCookieCache accepts only the private session-cache JWT type and treats every failure as a cache miss.
func (s *cookieCacheSigner) VerifyCookieCache(ctx context.Context, opts authtypes.Options, token string) (cookieCacheVerified, error) {
	if !s.enabled {
		return cookieCacheVerified{}, errCookieCacheSignerDisabled
	}
	if s.verifier == nil {
		return cookieCacheVerified{}, errors.New("jwt: session cookie-cache verifier is unavailable")
	}
	parsed, err := parseCookieCacheJWT(token)
	if err != nil {
		return cookieCacheVerified{}, err
	}
	header := parsed.Headers[0]
	if cookieCacheJWTType(header) != authcrypto.SessionCookieJWTType || header.KeyID == "" {
		return cookieCacheVerified{}, errors.New("jwt: invalid session cookie-cache JWT type or kid")
	}

	issuer := cookieCacheIssuer(opts)
	claims, err := s.verifier.VerifyJWT(ctx, token, VerifyOptions{
		Issuer:            issuer,
		Audience:          []string{authcrypto.SessionCookieJWTAudience},
		AllowedAlgorithms: SupportedAlgorithms(),
		RequireExpiration: true,
	})
	if err != nil {
		return cookieCacheVerified{}, fmt.Errorf("jwt: verify session cookie-cache JWT: %w", err)
	}
	if claims.Issuer != issuer || !slices.Contains(claims.Audience, authcrypto.SessionCookieJWTAudience) {
		return cookieCacheVerified{}, errors.New("jwt: session cookie-cache issuer or audience mismatch")
	}
	if claims.ExpiresAt == nil || *claims.ExpiresAt <= time.Now().Unix() || *claims.ExpiresAt > math.MaxInt64/1000 {
		return cookieCacheVerified{}, errors.New("jwt: session cookie-cache JWT is expired or has an invalid expiration")
	}

	custom := claims.CustomClaims
	session, ok := custom["session"].(map[string]any)
	if !ok || session == nil {
		return cookieCacheVerified{}, errors.New("jwt: invalid session cookie-cache session shape")
	}
	user, ok := custom["user"].(map[string]any)
	if !ok || user == nil {
		return cookieCacheVerified{}, errors.New("jwt: invalid session cookie-cache user shape")
	}
	updatedAt, ok := cookieCacheInt64(custom["updatedAt"])
	if !ok || updatedAt <= 0 {
		return cookieCacheVerified{}, errors.New("jwt: invalid session cookie-cache updatedAt")
	}
	version, ok := custom["version"].(string)
	if !ok {
		return cookieCacheVerified{}, errors.New("jwt: invalid session cookie-cache version")
	}
	userID, ok := user["id"].(string)
	if !ok || userID == "" || claims.Subject != userID {
		return cookieCacheVerified{}, errors.New("jwt: session cookie-cache subject mismatch")
	}
	sessionToken, ok := session["token"].(string)
	if !ok || sessionToken == "" {
		return cookieCacheVerified{}, errors.New("jwt: invalid session cookie-cache token")
	}
	sid, ok := custom["sid"].(string)
	if !ok || sid != sessionToken {
		return cookieCacheVerified{}, errors.New("jwt: session cookie-cache session id mismatch")
	}
	if err := cookies.ValidateCachePayloadSchema(session, user); err != nil {
		return cookieCacheVerified{}, fmt.Errorf("jwt: invalid session cookie-cache payload: %w", err)
	}

	return cookieCacheVerified{
		Payload: cookieCachePayload{
			Session:   session,
			User:      user,
			UpdatedAt: updatedAt,
			Version:   version,
		},
		ExpiresAt: *claims.ExpiresAt * 1000,
	}, nil
}

func validateCookieCachePayload(payload cookieCachePayload) error {
	if err := cookies.ValidateCachePayloadSchema(payload.Session, payload.User); err != nil {
		return fmt.Errorf("jwt: invalid session cookie-cache payload: %w", err)
	}
	if payload.UpdatedAt <= 0 {
		return errors.New("jwt: session cookie-cache updatedAt must be positive")
	}
	if userID, ok := payload.User["id"].(string); !ok || userID == "" {
		return errors.New("jwt: session cookie-cache user id is required")
	}
	if sessionToken, ok := payload.Session["token"].(string); !ok || sessionToken == "" {
		return errors.New("jwt: session cookie-cache session token is required")
	}
	return nil
}

func cookieCacheIssuer(opts authtypes.Options) string {
	if opts.BaseURL != "" {
		return opts.BaseURL
	}
	return authcrypto.SessionCookieJWTIssuer
}

func parseCookieCacheJWT(token string) (*jwt.JSONWebToken, error) {
	algorithms := make([]jose.SignatureAlgorithm, 0, len(SupportedAlgorithms()))
	for _, algorithm := range SupportedAlgorithms() {
		algorithms = append(algorithms, jose.SignatureAlgorithm(algorithm))
	}
	parsed, err := jwt.ParseSigned(token, algorithms)
	if err != nil || parsed == nil || len(parsed.Headers) != 1 {
		return nil, errors.New("jwt: invalid session cookie-cache JWT")
	}
	return parsed, nil
}

func cookieCacheJWTType(header jose.Header) string {
	typ, _ := header.ExtraHeaders[jose.HeaderKey("typ")].(string)
	return typ
}

func cookieCacheInt64(value any) (int64, bool) {
	switch number := value.(type) {
	case int:
		return int64(number), true
	case int64:
		return number, true
	case json.Number:
		integer, err := strconv.ParseInt(string(number), 10, 64)
		return integer, err == nil
	case float64:
		if number != math.Trunc(number) || number >= math.MaxInt64 || number < math.MinInt64 {
			return 0, false
		}
		return int64(number), true
	default:
		return 0, false
	}
}
