package cookies

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/brick-org/brick/auth/src/crypto"
)

// JWT/JWE session-data cookie strategies, mirroring
// vendor/better-auth/packages/better-auth/src/cookies/index.ts
// (setCookieCache/decodeCookieCache) with crypto/jwt.ts:
//
//   - StrategyJWT ("jwt", the default-secret path): the cache payload is a
//     compact HS256 JWT signed with the auth secret
//     (signSecretJWT/verifySecretJWT: header {alg HS256}, claims
//     {session, user, updatedAt, version?, iat, exp}). No typ/aud/iss binding
//     on this path — claim binding (typ/sub/sid/aud/iss) only applies to the
//     custom-JWKS signer path owned by the JWT plugin
//     (cookies/jwt.ts verifySessionCookieJwtWithJwks).
//   - StrategyJWE ("jwe"): the cache payload is an EncryptJWT JWE
//     (symmetricEncodeJWT/symmetricDecodeJWT): direct key management ("dir"),
//     A256CBC-HS512 content encryption over the HKDF-derived session key
//     (crypto.DeriveEncryptionSecret with the session salt), the key's JWK
//     SHA-256 thumbprint as kid for rotation-aware selection, iat/exp/jti
//     claims, and a 15s clock tolerance on decrypt. Decrypt also accepts
//     A256GCM payloads, matching jwtDecryptOpts.
//
// Secret rotation: verify tries every candidate secret in order (JWT) or
// selects by kid thumbprint across candidates (JWE, with a kid-less fallback
// across candidates). Unknown kids, wrong keys, tampered values, and expired
// tokens fail closed — callers fall through to the authoritative store.
//
// The functions below implement the default-secret paths. Tokens minted by a
// custom cookieCacheSigner (JWT plugin) are verified by that signer at the
// route layer (cachedSessionFromRequestFull); they are never accepted here,
// so a custom-signer deployment cannot be downgraded to secret verification.

// SessionCacheData is the decoded JWT/JWE session-cache payload: the cached
// session/user pair plus the stamped version. ExpiresAt is the outer cache
// window in milliseconds since the epoch (the JWT exp claim or the JWE exp
// claim), mirroring decodeCookieCache's {session, expiresAt} pair.
type SessionCacheData struct {
	Session   map[string]any
	User      map[string]any
	Version   string
	ExpiresAt int64
}

// defaultSessionCacheMaxAge mirrors the upstream caller default
// (cookies/index.ts passes `maxAge || 60 * 5` into both JWT and JWE issuance).
const defaultSessionCacheMaxAge = 5 * time.Minute

// sessionCacheMaxAgeSecs normalizes the issuance window, applying the
// upstream default for non-positive inputs.
func sessionCacheMaxAgeSecs(maxAge time.Duration) int64 {
	if maxAge <= 0 {
		maxAge = defaultSessionCacheMaxAge
	}
	return int64(maxAge / time.Second)
}

// jwtCacheClaims is the JWT claim set: the CookieCachePayload fields merged
// with iat/exp, exactly as jose's SignJWT(payload) serializes them.
type jwtCacheClaims struct {
	Session   map[string]any `json:"session"`
	User      map[string]any `json:"user"`
	UpdatedAt int64          `json:"updatedAt"`
	Version   string         `json:"version,omitempty"`
	IssuedAt  int64          `json:"iat"`
	Expires   int64          `json:"exp"`
}

// jweCacheClaims extends the claim set with the jti EncryptJWT always sets
// (symmetricEncodeJWT sets issued-at, expiry, and a random jti).
type jweCacheClaims struct {
	jwtCacheClaims
	JTI string `json:"jti"`
}

// CreateSessionCacheJWT issues a StrategyJWT session-data cookie value for
// session/user, mirroring the jwt branch of upstream setCookieCache with the
// default secret signer: HS256 over the auth secret, outer window maxAge.
// version stamps the resolved cookie-cache version ("" stays unstamped and
// reads back as the default at the route layer).
func CreateSessionCacheJWT(secret string, session, user map[string]any, version string, maxAge time.Duration) (string, error) {
	if secret == "" {
		return "", fmt.Errorf("cookies: secret is required for the jwt cookie cache")
	}
	nowSec := time.Now().Unix()
	payload, err := json.Marshal(jwtCacheClaims{
		Session:   session,
		User:      user,
		UpdatedAt: time.Now().UnixMilli(),
		Version:   version,
		IssuedAt:  nowSec,
		Expires:   nowSec + sessionCacheMaxAgeSecs(maxAge),
	})
	if err != nil {
		return "", err
	}
	// jose SignJWT serializes the header as {"alg":"HS256"} with typ JWT;
	// byte order inside the JSON object is irrelevant because verification
	// recomputes over the received segments.
	header, err := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(unsigned))
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// VerifySessionCacheJWT validates a StrategyJWT value against each candidate
// secret (rotation) and returns the payload plus the outer expiry in
// milliseconds. The header algorithm is pinned to HS256 — anything else
// (including "none") fails closed. Expiry is strict (upstream jwtVerify runs
// without a clock tolerance on this path); missing or non-numeric exp, and
// payloads without session/user objects, fail closed.
func VerifySessionCacheJWT(secrets []string, value string) (SessionCacheData, int64, error) {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return SessionCacheData{}, 0, fmt.Errorf("cookies: invalid jwt cache encoding")
	}
	var header struct {
		Alg string `json:"alg"`
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return SessionCacheData{}, 0, fmt.Errorf("cookies: invalid jwt cache encoding")
	}
	if err := json.Unmarshal(rawHeader, &header); err != nil {
		return SessionCacheData{}, 0, fmt.Errorf("cookies: invalid jwt cache encoding")
	}
	if header.Alg != "HS256" {
		return SessionCacheData{}, 0, fmt.Errorf("cookies: unexpected jwt cache alg %q", header.Alg)
	}
	unsigned := parts[0] + "." + parts[1]
	want, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return SessionCacheData{}, 0, fmt.Errorf("cookies: invalid jwt cache encoding")
	}
	valid := false
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(unsigned))
		if hmac.Equal(mac.Sum(nil), want) {
			valid = true
			break
		}
	}
	if !valid {
		return SessionCacheData{}, 0, fmt.Errorf("cookies: invalid jwt cache signature")
	}
	rawPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return SessionCacheData{}, 0, fmt.Errorf("cookies: invalid jwt cache payload")
	}
	var claims jwtCacheClaims
	if err := json.Unmarshal(rawPayload, &claims); err != nil {
		return SessionCacheData{}, 0, fmt.Errorf("cookies: invalid jwt cache payload")
	}
	if claims.Session == nil || claims.User == nil {
		return SessionCacheData{}, 0, fmt.Errorf("cookies: invalid jwt cache payload")
	}
	// Schema validation runs AFTER signature verification (upstream
	// parseCookieCachePayload order): a correctly-signed but
	// schema-invalid payload is a miss, reported with the sentinel so
	// callers can Logf-warn + fall through to the database instead of
	// throwing. Wrong-typed core fields (including explicit JSON nulls,
	// which decode to nil) fail here; unknown keys stay allowed.
	if err := ValidateCachePayloadSchema(claims.Session, claims.User); err != nil {
		return SessionCacheData{}, 0, fmt.Errorf("cookies: invalid jwt cache payload schema: %w", err)
	}
	if claims.Expires == 0 {
		return SessionCacheData{}, 0, fmt.Errorf("cookies: jwt cache has no expiry")
	}
	// Strict like jose's jwtVerify on this path (no clock tolerance): the
	// token is expired once now reaches exp.
	if time.Now().Unix() >= claims.Expires {
		return SessionCacheData{}, 0, fmt.Errorf("cookies: jwt cache expired")
	}
	return SessionCacheData{
		Session:   claims.Session,
		User:      claims.User,
		Version:   claims.Version,
		ExpiresAt: claims.Expires * 1000,
	}, claims.Expires * 1000, nil
}

// CreateSessionCacheJWE issues a StrategyJWE session-data cookie value,
// mirroring the jwe branch of upstream setCookieCache
// (symmetricEncodeJWT with the "better-auth-session" salt): dir/A256CBC-HS512
// over the HKDF-derived key, kid set to the key thumbprint, iat/exp/jti
// claims, outer window maxAge.
func CreateSessionCacheJWE(secret string, session, user map[string]any, version string, maxAge time.Duration) (string, error) {
	if secret == "" {
		return "", fmt.Errorf("cookies: secret is required for the jwe cookie cache")
	}
	key, err := crypto.DeriveEncryptionSecret(secret, crypto.SessionCookieEncryptionSalt)
	if err != nil {
		return "", err
	}
	kid, err := crypto.OctThumbprint(key)
	if err != nil {
		return "", err
	}
	nowSec := time.Now().Unix()
	claims := jweCacheClaims{
		jwtCacheClaims: jwtCacheClaims{
			Session:   session,
			User:      user,
			UpdatedAt: time.Now().UnixMilli(),
			Version:   version,
			IssuedAt:  nowSec,
			Expires:   nowSec + sessionCacheMaxAgeSecs(maxAge),
		},
		JTI: newCacheJTI(),
	}
	plaintext, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encrypter, err := jose.NewEncrypter(
		jose.A256CBC_HS512,
		jose.Recipient{Algorithm: jose.DIRECT, Key: key},
		(&jose.EncrypterOptions{}).
			WithType("JWT").
			WithContentType("JWT").
			WithHeader(jose.HeaderKey("kid"), kid),
	)
	if err != nil {
		return "", fmt.Errorf("cookies: jwe encrypter: %w", err)
	}
	object, err := encrypter.Encrypt(plaintext)
	if err != nil {
		return "", fmt.Errorf("cookies: jwe encrypt: %w", err)
	}
	return object.CompactSerialize()
}

// VerifySessionCacheJWE decrypts a StrategyJWE value and returns the payload
// plus the outer expiry in milliseconds, mirroring symmetricDecodeJWT: the
// kid selects the secret whose derived key thumbprint matches (unknown kids
// fail closed with no fallback); kid-less tokens are tried against every
// candidate. Expiry enforces the upstream 15s clock tolerance; A256GCM
// payloads are accepted like jwtDecryptOpts (with the derived key truncated
// to 32 bytes). Payloads without session/user objects fail closed.
func VerifySessionCacheJWE(secrets []string, value string) (SessionCacheData, int64, error) {
	// jwtDecryptOpts accepts dir key management with A256CBC-HS512 (issued)
	// or A256GCM (legacy compat) content encryption; anything else fails at
	// parse time.
	object, err := jose.ParseEncrypted(value,
		[]jose.KeyAlgorithm{jose.DIRECT},
		[]jose.ContentEncryption{jose.A256CBC_HS512, jose.A256GCM})
	if err != nil {
		return SessionCacheData{}, 0, fmt.Errorf("cookies: invalid jwe cache encoding")
	}
	keys := make([]derivedCacheKey, 0, len(secrets))
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		key, err := crypto.DeriveEncryptionSecret(secret, crypto.SessionCookieEncryptionSalt)
		if err != nil {
			continue
		}
		kid, err := crypto.OctThumbprint(key)
		if err != nil {
			continue
		}
		keys = append(keys, derivedCacheKey{key: key, kid: kid})
	}
	if len(keys) == 0 {
		return SessionCacheData{}, 0, fmt.Errorf("cookies: no jwe cache secret available")
	}
	candidates := keys
	if kid := object.Header.KeyID; kid != "" {
		candidates = nil
		for _, k := range keys {
			if k.kid == kid {
				candidates = []derivedCacheKey{k}
				break
			}
		}
		if candidates == nil {
			return SessionCacheData{}, 0, fmt.Errorf("cookies: no jwe cache key for kid")
		}
	}
	enc, err := jweContentEncryption(value)
	if err != nil {
		return SessionCacheData{}, 0, err
	}
	var plaintext []byte
	decrypted := false
	for _, k := range candidates {
		for _, key := range decryptionKeys(k.key, enc) {
			plaintext, err = object.Decrypt(key)
			if err == nil {
				decrypted = true
				break
			}
		}
		if decrypted {
			break
		}
	}
	if !decrypted {
		return SessionCacheData{}, 0, fmt.Errorf("cookies: jwe cache decryption failed")
	}
	var claims jweCacheClaims
	if err := json.Unmarshal(plaintext, &claims); err != nil {
		return SessionCacheData{}, 0, fmt.Errorf("cookies: invalid jwe cache payload")
	}
	if claims.Session == nil || claims.User == nil {
		return SessionCacheData{}, 0, fmt.Errorf("cookies: invalid jwe cache payload")
	}
	// Schema validation runs AFTER decryption (upstream
	// parseCookieCachePayload order): a correctly-decrypted but
	// schema-invalid payload is a miss, reported with the sentinel so
	// callers can Logf-warn + fall through to the database instead of
	// throwing. Wrong-typed core fields (including explicit JSON nulls,
	// which decode to nil) fail here; unknown keys stay allowed.
	if err := ValidateCachePayloadSchema(claims.Session, claims.User); err != nil {
		return SessionCacheData{}, 0, fmt.Errorf("cookies: invalid jwe cache payload schema: %w", err)
	}
	if claims.Expires == 0 {
		return SessionCacheData{}, 0, fmt.Errorf("cookies: jwe cache has no expiry")
	}
	// Upstream jwtDecryptOpts clockTolerance: 15.
	if time.Now().Unix() > claims.Expires+crypto.JWEClockToleranceSeconds {
		return SessionCacheData{}, 0, fmt.Errorf("cookies: jwe cache expired")
	}
	return SessionCacheData{
		Session:   claims.Session,
		User:      claims.User,
		Version:   claims.Version,
		ExpiresAt: claims.Expires * 1000,
	}, claims.Expires * 1000, nil
}

// derivedCacheKey pairs an HKDF-derived session key with its kid thumbprint.
type derivedCacheKey struct {
	key []byte
	kid string
}

// decryptionKeys selects the decryption key bytes for a content-encryption
// algorithm: the full 64-byte derived key, truncated to 32 bytes for the
// A256GCM payloads jwtDecryptOpts still accepts.
func decryptionKeys(key []byte, enc string) [][]byte {
	if jose.ContentEncryption(enc) == jose.A256GCM && len(key) >= 32 {
		return [][]byte{key[:32]}
	}
	return [][]byte{key}
}

// jweContentEncryption reads the "enc" protected-header parameter from a
// compact JWE without a JOSE round-trip (go-jose surfaces only merged
// signature headers, not the content-encryption selector).
func jweContentEncryption(value string) (string, error) {
	parts := strings.Split(value, ".")
	if len(parts) != 5 {
		return "", fmt.Errorf("cookies: invalid jwe cache encoding")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("cookies: invalid jwe cache encoding")
	}
	var header struct {
		Enc string `json:"enc"`
	}
	if err := json.Unmarshal(raw, &header); err != nil || header.Enc == "" {
		return "", fmt.Errorf("cookies: invalid jwe cache encoding")
	}
	return header.Enc, nil
}

// newCacheJTI mints the random jti claim EncryptJWT sets on every payload.
// Uniqueness is transport-only: neither upstream nor this runtime tracks jtis
// for replay.
func newCacheJTI() string {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(nonce[:])
}
