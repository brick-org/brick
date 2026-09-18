package cookies

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// Session-data cookie strategies mirroring
// vendor/better-auth/packages/better-auth/src/cookies/index.ts
// (setCookieCache/decodeCookieCache):
//
//   - StrategyCompact ("compact", the default, also accepting the legacy
//     "base64-hmac" payloads): base64url(JSON{session, expiresAt, signature})
//     where signature = HMAC-SHA256(secret, JSON{...session, expiresAt}).
//     No JWT overhead; the outer expiresAt window and the embedded session
//     expiry must both be checked explicitly.
//   - StrategyJWT ("jwt"): the cache payload is a compact HS256 JWT over the
//     auth secret (see jwt.go Create/VerifySessionCacheJWT,
//     mirroring the default-secret path of upstream setCookieCache/
//     decodeCookieCache via crypto/jwt.ts signJWT/verifyJWT).
//   - StrategyJWE ("jwe"): the cache payload is an A256CBC-HS512 EncryptJWT
//     JWE with the HKDF-derived session key and thumbprint kid (see
//     jwt.go Create/VerifySessionCacheJWE, mirroring
//     symmetricEncodeJWT/symmetricDecodeJWT).
//
// Tokens minted by a custom cookieCacheSigner (JWT plugin) are verified by
// that signer at the route layer (cachedSessionFromRequestFull via
// findCookieCacheSigner, with rotation and typ/kid/aud/iss/sub/sid binding);
// the default-secret codecs below remain for deployments without the custom
// signer. Every decode failure falls through to the database (fail closed,
// never trust).
//
// The compact helpers below implement the StrategyCompact wire format over
// net/http so route code can read/write the default upstream cache without a
// JS runtime. Wire behavior of the existing session cookies is unchanged.
const (
	StrategyCompact = "compact"
	StrategyJWT     = "jwt"
	StrategyJWE     = "jwe"
)

// CompactCacheEnvelope is the JSON envelope of the StrategyCompact cookie
// value before base64url encoding.
type CompactCacheEnvelope struct {
	Session   map[string]any `json:"session"`
	ExpiresAt int64          `json:"expiresAt"`
	Signature string         `json:"signature"`
}

// DefaultCookieCacheVersion mirrors upstream's default cookie-cache version
// ("1", applied in setCookieCache and the get-session read path when no
// version is configured). Payloads predating version stamping carry no
// version and must compare as this default (upstream
// `session.version || "1"`).
const DefaultCookieCacheVersion = "1"

// CookieCacheRefreshThreshold converts the cookie-cache refresh knob into an
// effective refresh threshold: when the cache's remaining lifetime drops
// below the threshold, the get-session read path re-issues it without a
// database write (upstream session.ts:199-259, driven by
// ctx.sessionConfig.cookieRefreshCache).
//
// A positive updateAgeSec is used verbatim; otherwise the upstream default
// applies: 20% of the cache maxAge (create-context.ts:336-349). maxAge is
// the resolved CookieCache.MaxAge duration (5 minutes when unset). The
// second return is false when refresh is disabled (Enabled unset), in which
// case the threshold is meaningless and the cache is served as-is until it
// expires.
func CookieCacheRefreshThreshold(enabled bool, updateAgeSec int, maxAge time.Duration) (time.Duration, bool) {
	if !enabled {
		return 0, false
	}
	if maxAge <= 0 {
		maxAge = 5 * time.Minute
	}
	if updateAgeSec > 0 {
		return time.Duration(updateAgeSec) * time.Second, true
	}
	return maxAge / 5, true
}

// CreateCompactCookieCache builds a StrategyCompact session-data cookie value
// for session payload sessionData valid for maxAge, mirroring the compact
// branch of upstream setCookieCache. expiresAt is milliseconds since epoch,
// matching upstream getDate(maxAge, "sec").getTime().
func CreateCompactCookieCache(secret string, sessionData map[string]any, maxAge time.Duration) (string, error) {
	if secret == "" {
		return "", fmt.Errorf("cookies: secret is required for the compact cookie cache")
	}
	if maxAge == 0 {
		maxAge = 5 * time.Minute
	}
	expiresAt := time.Now().Add(maxAge).UnixMilli()
	unsigned, err := json.Marshal(compactUnsignedPayload(sessionData, expiresAt))
	if err != nil {
		return "", err
	}
	sig := compactSign(secret, string(unsigned))
	envelope, err := json.Marshal(CompactCacheEnvelope{
		Session:   sessionData,
		ExpiresAt: expiresAt,
		Signature: sig,
	})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(envelope), nil
}

// VerifyCompactCookieCache validates a StrategyCompact session-data cookie
// value against each candidate secret (secret rotation) and returns the
// session payload and expiry. It mirrors the compact branch of upstream
// decodeCookieCache/getCookieCache: HMAC verification, outer expiresAt window
// check, and embedded session expiry check.
func VerifyCompactCookieCache(secrets []string, value string) (session map[string]any, expiresAt int64, err error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, 0, fmt.Errorf("cookies: invalid compact cache encoding")
	}
	var envelope CompactCacheEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, 0, fmt.Errorf("cookies: invalid compact cache payload")
	}
	if envelope.Session == nil || envelope.Signature == "" {
		return nil, 0, fmt.Errorf("cookies: invalid compact cache payload")
	}
	unsigned, err := json.Marshal(compactUnsignedPayload(envelope.Session, envelope.ExpiresAt))
	if err != nil {
		return nil, 0, fmt.Errorf("cookies: invalid compact cache payload")
	}
	valid := false
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		if hmac.Equal([]byte(compactSign(secret, string(unsigned))), []byte(envelope.Signature)) {
			valid = true
			break
		}
	}
	if !valid {
		return nil, 0, fmt.Errorf("cookies: invalid compact cache signature")
	}
	now := time.Now().UnixMilli()
	if envelope.ExpiresAt != 0 && envelope.ExpiresAt < now {
		return nil, 0, fmt.Errorf("cookies: compact cache expired")
	}
	if embeddedExpiry, ok := embeddedSessionExpiry(envelope.Session); ok && embeddedExpiry < now {
		return nil, 0, fmt.Errorf("cookies: embedded session expired")
	}
	return envelope.Session, envelope.ExpiresAt, nil
}

func compactUnsignedPayload(session map[string]any, expiresAt int64) map[string]any {
	out := make(map[string]any, len(session)+1)
	for k, v := range session {
		out[k] = v
	}
	out["expiresAt"] = expiresAt
	return out
}

func compactSign(secret, unsignedJSON string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(unsignedJSON))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// embeddedSessionExpiry reads session.session.expiresAt (the upstream
// CookieCachePayload shape {session, user, updatedAt}) as milliseconds since
// epoch, mirroring upstream isEmbeddedSessionExpired. It returns ok=false
// when no parseable expiry is present, in which case the cache is treated as
// non-expired (matching upstream behavior for payloads without expiresAt).
// Falsy values (numeric 0, empty strings, zero times) also compare as absent:
// upstream bails on `!session?.expiresAt` before constructing a Date, so an
// explicit epoch-zero expiry must not invalidate the cache.
func embeddedSessionExpiry(session map[string]any) (millis int64, ok bool) {
	inner, _ := session["session"].(map[string]any)
	if inner == nil {
		return 0, false
	}
	raw, present := inner["expiresAt"]
	if !present {
		return 0, false
	}
	switch v := raw.(type) {
	case float64:
		if v == 0 {
			return 0, false
		}
		return normalizeExpiry(v), true
	case float32:
		if v == 0 {
			return 0, false
		}
		return normalizeExpiry(float64(v)), true
	case int64:
		if v == 0 {
			return 0, false
		}
		return normalizeExpiry(float64(v)), true
	case int:
		if v == 0 {
			return 0, false
		}
		return normalizeExpiry(float64(v)), true
	case string:
		if v == "" {
			return 0, false
		}
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t.UnixMilli(), true
		}
		var f float64
		if _, err := json.Marshal(v); err == nil {
			_ = f
		}
		return 0, false
	case time.Time:
		if v.IsZero() {
			return 0, false
		}
		return v.UnixMilli(), true
	case json.Number:
		if f, err := v.Float64(); err == nil {
			if f == 0 {
				return 0, false
			}
			return normalizeExpiry(f), true
		}
		return 0, false
	}
	return 0, false
}

// normalizeExpiry converts a numeric expiresAt to milliseconds. Values below
// 1e12 are interpreted as seconds (upstream stores ms, but numeric JSON
// payloads from other writers may carry seconds).
func normalizeExpiry(v float64) int64 {
	if v < 1e12 {
		return int64(v * 1000)
	}
	return int64(v)
}
