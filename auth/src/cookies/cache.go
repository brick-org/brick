package cookies

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Upstream cookies/index.ts
// Compact=base64url HMAC, jwt=HS256, jwe=A256CBC-HS512 with HKDF key; custom-signer tokens verify at route layer.
// Every decode failure falls through to the database (fail closed,
// never trust).
const (
	StrategyCompact = "compact"
	StrategyJWT     = "jwt"
	StrategyJWE     = "jwe"
)

// CompactCacheEnvelope is the JSON envelope before base64url encoding.
type CompactCacheEnvelope struct {
	Session   map[string]any `json:"session"`
	ExpiresAt int64          `json:"expiresAt"`
	Signature string         `json:"signature"`
}

// DefaultCookieCacheVersion is the upstream default ("1"); unstamped payloads must compare as this default.
const DefaultCookieCacheVersion = "1"

// CookieCacheRefreshThreshold converts the refresh knob into a threshold; false when disabled.
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

// CreateCompactCookieCache builds a compact cache value; expiresAt is millis since epoch.
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

// ErrCachePayloadSchema reports a correctly-signed payload failing the core contract.
// Callers must treat it as a cache MISS: warn through the configured logger
// and fall through to the database, never throw.
var ErrCachePayloadSchema = errors.New("cookies: invalid cookie cache payload schema")

// ValidateCachePayloadSchema type-checks session/user core fields; unknown keys allowed, explicit nulls fail.
func ValidateCachePayloadSchema(session, user map[string]any) error {
	if session == nil || user == nil {
		return ErrCachePayloadSchema
	}
	if v, ok := session["token"]; ok {
		if _, ok := v.(string); !ok {
			return ErrCachePayloadSchema
		}
	}
	if v, ok := user["id"]; ok {
		if _, ok := v.(string); !ok {
			return ErrCachePayloadSchema
		}
	}
	if v, ok := user["email"]; ok {
		if _, ok := v.(string); !ok {
			return ErrCachePayloadSchema
		}
	}
	if v, ok := user["emailVerified"]; ok {
		if _, ok := v.(bool); !ok {
			return ErrCachePayloadSchema
		}
	}
	return nil
}

// VerifyCompactCookieCache validates HMAC, outer window, and embedded expiry; rotation via candidates.
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
	// Schema runs AFTER signature: correctly-signed but invalid payloads report the sentinel for warn+miss.
	innerSession, _ := envelope.Session["session"].(map[string]any)
	innerUser, _ := envelope.Session["user"].(map[string]any)
	if err := ValidateCachePayloadSchema(innerSession, innerUser); err != nil {
		return nil, 0, fmt.Errorf("cookies: invalid compact cache payload schema: %w", err)
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

// embeddedSessionExpiry reads session.session.expiresAt as millis; absent/falsy compares as non-expired.
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

// normalizeExpiry converts numeric expiresAt to millis; values below 1e12 read as seconds.
func normalizeExpiry(v float64) int64 {
	if v < 1e12 {
		return int64(v * 1000)
	}
	return int64(v)
}
