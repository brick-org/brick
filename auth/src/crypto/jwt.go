package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// DefaultJWTAlg is the default signing algorithm, matching better-auth
// (EdDSA with an Ed25519 key).
const DefaultJWTAlg = "EdDSA"

// Session-cookie-cache JWT constants mirroring
// vendor/better-auth/packages/better-auth/src/cookies/jwt.ts. The compact,
// JWT, and JWE cache strategies are wired (compact in cookies/cache.go,
// JWT/JWE in cookies/jwt.go, custom JWKS signer at the route layer
// via the JWT plugin); these constants pin the exact upstream type,
// audience, issuer, and clock tolerance for the custom-signer path instead
// of re-deriving them.
const (
	// SessionCookieJWTType is the JWS "typ" header required of
	// session-cache JWTs (SESSION_COOKIE_JWT_TYPE).
	SessionCookieJWTType = "better-auth.session-cache+jwt"
	// SessionCookieJWTAudience is the required "aud" claim
	// (SESSION_COOKIE_JWT_AUDIENCE).
	SessionCookieJWTAudience = "better-auth:session-cache"
	// SessionCookieJWTIssuer is the fallback "iss" claim when no baseURL is
	// configured (SESSION_COOKIE_JWT_ISSUER).
	SessionCookieJWTIssuer = "better-auth:session-cache"
	// SessionCookieJWTClockToleranceSeconds is the clock-skew tolerance
	// applied when verifying session-cache JWTs and JWE payloads
	// (clockTolerance: 15 in getSessionCookieJwtVerifyOptions/jwtDecryptOpts).
	SessionCookieJWTClockToleranceSeconds = 15
)

// supportedJWTAlgs lists the algorithms accepted when parsing a token. Mirrors
// better-auth's JWKOptions union (jwt/types.ts).
var supportedJWTAlgs = []jose.SignatureAlgorithm{
	jose.EdDSA,
	jose.ES256,
	jose.ES512,
	jose.PS256,
	jose.RS256,
}

// PublicKey holds a stored JWKS public key plus the metadata needed to expose
// and verify it. PublicJWKJSON is the serialised public JSON Web Key without a
// kid; the kid is the database row id (matching better-auth, which spreads the
// stored publicKey and overrides kid with the row id).
type PublicKey struct {
	Kid           string
	Alg           string
	PublicJWKJSON string
}

// GenerateKeyPair creates a new signing key pair for alg and returns the public
// and private keys serialised as JWK JSON, plus the curve name where applicable.
// An empty alg defaults to EdDSA.
func GenerateKeyPair(alg string) (publicJWK, privateJWK, crv string, err error) {
	if alg == "" {
		alg = DefaultJWTAlg
	}

	var priv, pub any
	switch alg {
	case "EdDSA":
		pubKey, privKey, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return "", "", "", e
		}
		priv, pub, crv = privKey, pubKey, "Ed25519"
	case "ES256":
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return "", "", "", e
		}
		priv, pub, crv = k, &k.PublicKey, "P-256"
	case "ES512":
		k, e := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if e != nil {
			return "", "", "", e
		}
		priv, pub, crv = k, &k.PublicKey, "P-521"
	case "RS256", "PS256":
		k, e := rsa.GenerateKey(rand.Reader, 2048)
		if e != nil {
			return "", "", "", e
		}
		priv, pub = k, &k.PublicKey
	default:
		return "", "", "", fmt.Errorf("crypto: unsupported jwt alg %q", alg)
	}

	pubBytes, err := (&jose.JSONWebKey{Key: pub, Algorithm: alg, Use: "sig"}).MarshalJSON()
	if err != nil {
		return "", "", "", err
	}
	privBytes, err := (&jose.JSONWebKey{Key: priv, Algorithm: alg, Use: "sig"}).MarshalJSON()
	if err != nil {
		return "", "", "", err
	}
	return string(pubBytes), string(privBytes), crv, nil
}

// SignJWT signs claims into a compact JWS using the private JWK JSON. The kid is
// written into the protected header so verifiers can select the matching public
// key. An empty alg defaults to EdDSA.
func SignJWT(privateJWKJSON, alg, kid string, claims map[string]any) (string, error) {
	if alg == "" {
		alg = DefaultJWTAlg
	}
	var jwk jose.JSONWebKey
	if err := jwk.UnmarshalJSON([]byte(privateJWKJSON)); err != nil {
		return "", fmt.Errorf("crypto: parse private jwk: %w", err)
	}
	jwk.KeyID = kid
	jwk.Algorithm = alg

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(alg), Key: jwk},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		return "", fmt.Errorf("crypto: new signer: %w", err)
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("crypto: sign jwt: %w", err)
	}
	return token, nil
}

// BuildJWKS assembles a JSON Web Key Set ({"keys": [...]}) from stored public
// keys, injecting each key's kid. The result is ready to JSON-encode at /jwks.
func BuildJWKS(keys []PublicKey) (map[string]any, error) {
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		var m map[string]any
		if err := json.Unmarshal([]byte(k.PublicJWKJSON), &m); err != nil {
			return nil, fmt.Errorf("crypto: parse public jwk: %w", err)
		}
		if k.Alg != "" {
			m["alg"] = k.Alg
		}
		m["kid"] = k.Kid
		out = append(out, m)
	}
	return map[string]any{"keys": out}, nil
}

// VerifyOptions configures claim validation during VerifyJWT.
type VerifyOptions struct {
	Issuer   string
	Audience []string
	// LeewaySeconds tolerates clock skew when checking exp/nbf claims: a
	// token is expired only when now is past exp+leeway, and not-yet-valid
	// only when now is before nbf-leeway. It mirrors the clockTolerance
	// option of jose's jwtVerify (upstream session-cache/JWE paths use 15;
	// see SessionCookieJWTClockToleranceSeconds). Zero preserves strict
	// validation; negative values are treated as zero.
	LeewaySeconds int64
}

// ErrJWTVerification is returned when a token fails signature or claim validation.
var ErrJWTVerification = errors.New("crypto: jwt verification failed")

// SelectKey returns the public key whose Kid matches kid, implementing the
// upstream kid-selected verification contract (plugins/jwt/verify.ts,
// cookies/jwt.ts verifySessionCookieJwtWithJwks): exact kid match, no
// fallback. Rotation works by publishing the full key set — retired kids
// fail closed here so callers must keep grace-period keys published (the
// plugins/jwt JWKS endpoint already filters with a 30-day default grace).
func SelectKey(keys []PublicKey, kid string) (*PublicKey, error) {
	if kid == "" {
		return nil, fmt.Errorf("%w: missing kid", ErrJWTVerification)
	}
	for i := range keys {
		if keys[i].Kid == kid {
			return &keys[i], nil
		}
	}
	return nil, fmt.Errorf("%w: no key for kid %q", ErrJWTVerification, kid)
}

// VerifyJWT verifies a compact JWS against the provided public keys (selected by
// the token's kid header) and validates issuer/audience/expiry. It returns the
// decoded claims on success.
func VerifyJWT(token string, keys []PublicKey, opts VerifyOptions) (map[string]any, error) {
	parsed, err := jwt.ParseSigned(token, supportedJWTAlgs)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJWTVerification, err)
	}
	if len(parsed.Headers) == 0 {
		return nil, ErrJWTVerification
	}
	match, err := SelectKey(keys, parsed.Headers[0].KeyID)
	if err != nil {
		return nil, err
	}

	var pubJWK jose.JSONWebKey
	if err := pubJWK.UnmarshalJSON([]byte(match.PublicJWKJSON)); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJWTVerification, err)
	}
	pubJWK.KeyID = match.Kid

	claims := map[string]any{}
	if err := parsed.Claims(pubJWK, &claims); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJWTVerification, err)
	}

	if err := validateClaims(claims, opts); err != nil {
		return nil, err
	}
	return claims, nil
}

func validateClaims(claims map[string]any, opts VerifyOptions) error {
	now := time.Now()
	leeway := time.Duration(opts.LeewaySeconds) * time.Second
	if leeway < 0 {
		leeway = 0
	}
	if exp, ok := numericClaim(claims["exp"]); ok && now.After(time.Unix(exp, 0).Add(leeway)) {
		return fmt.Errorf("%w: token expired", ErrJWTVerification)
	}
	if nbf, ok := numericClaim(claims["nbf"]); ok && now.Before(time.Unix(nbf, 0).Add(-leeway)) {
		return fmt.Errorf("%w: token not yet valid", ErrJWTVerification)
	}
	if opts.Issuer != "" {
		if iss, _ := claims["iss"].(string); iss != opts.Issuer {
			return fmt.Errorf("%w: issuer mismatch", ErrJWTVerification)
		}
	}
	if len(opts.Audience) > 0 && !audienceMatches(claims["aud"], opts.Audience) {
		return fmt.Errorf("%w: audience mismatch", ErrJWTVerification)
	}
	return nil
}

func audienceMatches(claim any, allowed []string) bool {
	got := map[string]struct{}{}
	switch v := claim.(type) {
	case string:
		got[v] = struct{}{}
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				got[s] = struct{}{}
			}
		}
	case []string:
		for _, s := range v {
			got[s] = struct{}{}
		}
	}
	for _, want := range allowed {
		if _, ok := got[want]; ok {
			return true
		}
	}
	return false
}

func numericClaim(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	}
	return 0, false
}
