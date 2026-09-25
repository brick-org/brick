package jwt

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	authcrypto "github.com/brick-org/brick/auth/src/crypto"
	authtypes "github.com/brick-org/brick/auth/src/types"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func TestCookieCacheSignerRoundTrip(t *testing.T) {
	store := newCookieCacheTestStore(t)
	signer := newCookieCacheSigner(store, store, true)
	opts := authtypes.Options{BaseURL: "https://auth.example.test"}
	payload := cookieCachePayload{
		Session:   map[string]any{"token": "session-token", "userId": "user-1"},
		User:      map[string]any{"id": "user-1", "email": "user@example.test"},
		UpdatedAt: time.Now().UnixMilli(),
		Version:   "cache-v1",
	}

	token, err := signer.SignCookieCache(context.Background(), opts, payload, 2*time.Minute)
	if err != nil {
		t.Fatalf("SignCookieCache() error = %v", err)
	}
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		t.Fatalf("jwt.ParseSigned() error = %v", err)
	}
	if got := cookieCacheJWTType(parsed.Headers[0]); got != authcrypto.SessionCookieJWTType {
		t.Fatalf("JWT typ = %q, want %q", got, authcrypto.SessionCookieJWTType)
	}
	if got := parsed.Headers[0].KeyID; got != store.keyID {
		t.Fatalf("JWT kid = %q, want %q", got, store.keyID)
	}

	verified, err := signer.VerifyCookieCache(context.Background(), opts, token)
	if err != nil {
		t.Fatalf("VerifyCookieCache() error = %v", err)
	}
	if verified.Payload.Session["token"] != payload.Session["token"] || verified.Payload.User["id"] != payload.User["id"] || verified.Payload.UpdatedAt != payload.UpdatedAt || verified.Payload.Version != payload.Version {
		t.Fatalf("verified payload = %#v, want %#v", verified.Payload, payload)
	}
	if verified.ExpiresAt <= time.Now().UnixMilli() {
		t.Fatalf("ExpiresAt = %d, want future timestamp in milliseconds", verified.ExpiresAt)
	}
}

func TestCookieCacheSignerRejectsAccessJWTType(t *testing.T) {
	store := newCookieCacheTestStore(t)
	signer := newCookieCacheSigner(store, store, true)
	opts := authtypes.Options{BaseURL: "https://auth.example.test"}
	claims := validCookieCacheClaims(opts, time.Now().Add(time.Minute).Unix())
	token, err := store.sign(claims, "JWT")
	if err != nil {
		t.Fatalf("sign access JWT: %v", err)
	}
	if _, err := signer.VerifyCookieCache(context.Background(), opts, token); err == nil {
		t.Fatal("VerifyCookieCache() accepted a normal access JWT")
	}
}

func TestCookieCacheSignerRejectsExpiredJWT(t *testing.T) {
	store := newCookieCacheTestStore(t)
	signer := newCookieCacheSigner(store, store, true)
	opts := authtypes.Options{BaseURL: "https://auth.example.test"}
	claims := validCookieCacheClaims(opts, time.Now().Add(-time.Minute).Unix())
	token, err := store.sign(claims, authcrypto.SessionCookieJWTType)
	if err != nil {
		t.Fatalf("sign expired cache JWT: %v", err)
	}
	if _, err := signer.VerifyCookieCache(context.Background(), opts, token); err == nil {
		t.Fatal("VerifyCookieCache() accepted an expired JWT")
	}
}

func TestCookieCacheSignerRejectsInvalidSignature(t *testing.T) {
	store := newCookieCacheTestStore(t)
	signer := newCookieCacheSigner(store, store, true)
	opts := authtypes.Options{BaseURL: "https://auth.example.test"}
	token, err := signer.SignCookieCache(context.Background(), opts, validCookieCachePayload(), time.Minute)
	if err != nil {
		t.Fatalf("SignCookieCache() error = %v", err)
	}
	parts := strings.Split(token, ".")
	if parts[2][0] == 'A' {
		parts[2] = "B" + parts[2][1:]
	} else {
		parts[2] = "A" + parts[2][1:]
	}
	token = strings.Join(parts, ".")
	if _, err := signer.VerifyCookieCache(context.Background(), opts, token); err == nil {
		t.Fatal("VerifyCookieCache() accepted a JWT with a modified signature")
	}
}

func TestCookieCacheSignerDisabled(t *testing.T) {
	signer := newCookieCacheSigner(nil, nil, false)
	opts := authtypes.Options{BaseURL: "https://auth.example.test"}
	if _, err := signer.SignCookieCache(context.Background(), opts, validCookieCachePayload(), time.Minute); !errors.Is(err, errCookieCacheSignerDisabled) {
		t.Fatalf("SignCookieCache() error = %v, want disabled error", err)
	}
	if _, err := signer.VerifyCookieCache(context.Background(), opts, "token"); !errors.Is(err, errCookieCacheSignerDisabled) {
		t.Fatalf("VerifyCookieCache() error = %v, want disabled error", err)
	}
}

func validCookieCachePayload() cookieCachePayload {
	return cookieCachePayload{
		Session:   map[string]any{"token": "session-token"},
		User:      map[string]any{"id": "user-1", "email": "user@example.test"},
		UpdatedAt: time.Now().UnixMilli(),
		Version:   "cache-v1",
	}
}

func validCookieCacheClaims(opts authtypes.Options, expiresAt int64) Payload {
	payload := validCookieCachePayload()
	issuer := cookieCacheIssuer(opts)
	return Payload{
		"iss":       issuer,
		"aud":       authcrypto.SessionCookieJWTAudience,
		"sub":       payload.User["id"],
		"sid":       payload.Session["token"],
		"iat":       time.Now().Unix(),
		"exp":       expiresAt,
		"session":   payload.Session,
		"user":      payload.User,
		"updatedAt": payload.UpdatedAt,
		"version":   payload.Version,
	}
}

type cookieCacheTestStore struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
	keyID   string
}

func newCookieCacheTestStore(t *testing.T) *cookieCacheTestStore {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	return &cookieCacheTestStore{private: private, public: public, keyID: "cookie-cache-key"}
}

func (s *cookieCacheTestStore) ResolveSigningKey(context.Context, SigningKeyOverrides) (ResolvedSigningKey, error) {
	return ResolvedSigningKey{Algorithm: AlgEdDSA, KeyID: s.keyID}, nil
}

func (s *cookieCacheTestStore) SignJWT(_ context.Context, claims Payload, overrides SigningKeyOverrides) (string, error) {
	return s.sign(claims, overrides.Typ)
}

func (s *cookieCacheTestStore) sign(claims Payload, typ string) (string, error) {
	key := jose.JSONWebKey{Key: s.private, Algorithm: string(AlgEdDSA), KeyID: s.keyID, Use: "sig"}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.EdDSA, Key: key},
		(&jose.SignerOptions{}).WithType(jose.ContentType(typ)),
	)
	if err != nil {
		return "", err
	}
	return jwt.Signed(signer).Claims(map[string]any(claims)).Serialize()
}

func (s *cookieCacheTestStore) VerifyJWT(_ context.Context, token string, _ VerifyOptions) (JWTClaims, error) {
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		return JWTClaims{}, err
	}
	if len(parsed.Headers) != 1 || parsed.Headers[0].KeyID != s.keyID {
		return JWTClaims{}, errors.New("unexpected test key")
	}
	key := jose.JSONWebKey{Key: s.public, Algorithm: string(AlgEdDSA), KeyID: s.keyID, Use: "sig"}
	var raw map[string]any
	if err := parsed.Claims(key, &raw); err != nil {
		return JWTClaims{}, err
	}
	expiresAt, _ := cookieCacheInt64(raw["exp"])
	claims := JWTClaims{
		Issuer:   cookieCacheTestStringClaim(raw["iss"]),
		Subject:  cookieCacheTestStringClaim(raw["sub"]),
		Audience: cookieCacheTestAudienceClaim(raw["aud"]),
	}
	if expiresAt != 0 {
		claims.ExpiresAt = &expiresAt
	}
	claims.CustomClaims = make(Payload, len(raw))
	for name, value := range raw {
		switch name {
		case "iss", "sub", "aud", "exp", "iat", "nbf", "jti":
		default:
			claims.CustomClaims[name] = value
		}
	}
	return claims, nil
}

func (s *cookieCacheTestStore) VerifyAccessToken(ctx context.Context, token string, options VerifyOptions) (JWTClaims, error) {
	return s.VerifyJWT(ctx, token, options)
}

func cookieCacheTestStringClaim(value any) string {
	text, _ := value.(string)
	return text
}

func cookieCacheTestAudienceClaim(value any) []string {
	switch audience := value.(type) {
	case string:
		return []string{audience}
	case []any:
		out := make([]string, 0, len(audience))
		for _, value := range audience {
			if text, ok := value.(string); ok {
				out = append(out, text)
			}
		}
		return out
	default:
		return nil
	}
}
