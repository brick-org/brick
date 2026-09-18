package crypto

import (
	"strings"
	"testing"
	"time"
)

func signTestToken(t *testing.T, claims map[string]any) (string, []PublicKey) {
	t.Helper()
	pub, priv, _, err := GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatal(err)
	}
	token, err := SignJWT(priv, "EdDSA", "k1", claims)
	if err != nil {
		t.Fatal(err)
	}
	return token, []PublicKey{{Kid: "k1", Alg: "EdDSA", PublicJWKJSON: pub}}
}

func TestVerifyJWTLeewayBoundaries(t *testing.T) {
	now := time.Now().Unix()
	// exp 10s in the past: strict rejects, 15s leeway accepts.
	token, keys := signTestToken(t, map[string]any{"sub": "u", "exp": now - 10})
	if _, err := VerifyJWT(token, keys, VerifyOptions{}); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("strict expired error = %v", err)
	}
	if _, err := VerifyJWT(token, keys, VerifyOptions{LeewaySeconds: SessionCookieJWTClockToleranceSeconds}); err != nil {
		t.Fatalf("leeway should accept recently expired token: %v", err)
	}
	// exp 60s in the past: even the 15s tolerance rejects.
	token, keys = signTestToken(t, map[string]any{"sub": "u", "exp": now - 60})
	if _, err := VerifyJWT(token, keys, VerifyOptions{LeewaySeconds: SessionCookieJWTClockToleranceSeconds}); err == nil {
		t.Fatal("long-expired token accepted under leeway")
	}
	// nbf 10s in the future: strict rejects, 15s leeway accepts.
	token, keys = signTestToken(t, map[string]any{"sub": "u", "nbf": now + 10, "exp": now + 3600})
	if _, err := VerifyJWT(token, keys, VerifyOptions{}); err == nil || !strings.Contains(err.Error(), "not yet valid") {
		t.Fatalf("strict nbf error = %v", err)
	}
	if _, err := VerifyJWT(token, keys, VerifyOptions{LeewaySeconds: SessionCookieJWTClockToleranceSeconds}); err != nil {
		t.Fatalf("leeway should accept imminent nbf token: %v", err)
	}
	// Negative leeway behaves as zero.
	if _, err := VerifyJWT(token, keys, VerifyOptions{LeewaySeconds: -30}); err == nil {
		t.Fatal("negative leeway must behave as strict")
	}
}

func TestVerifyJWTIssuerAudienceStillEnforced(t *testing.T) {
	token, keys := signTestToken(t, map[string]any{
		"sub": "u", "iss": "https://auth.example.com", "aud": "app",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := VerifyJWT(token, keys, VerifyOptions{
		Issuer:        "https://auth.example.com",
		Audience:      []string{"app"},
		LeewaySeconds: SessionCookieJWTClockToleranceSeconds,
	}); err != nil {
		t.Fatalf("valid claims rejected: %v", err)
	}
	if _, err := VerifyJWT(token, keys, VerifyOptions{Issuer: "https://other.example.com"}); err == nil {
		t.Error("issuer mismatch accepted")
	}
	if _, err := VerifyJWT(token, keys, VerifyOptions{Audience: []string{"other"}}); err == nil {
		t.Error("audience mismatch accepted")
	}
}

func TestSelectKeyRotation(t *testing.T) {
	keys := []PublicKey{
		{Kid: "old", Alg: "EdDSA", PublicJWKJSON: "{}"},
		{Kid: "current", Alg: "EdDSA", PublicJWKJSON: "{}"},
	}
	got, err := SelectKey(keys, "old")
	if err != nil || got.Kid != "old" {
		t.Fatalf("retained key not selectable: %v %+v", got, err)
	}
	if _, err := SelectKey(keys, ""); err == nil || !strings.Contains(err.Error(), "missing kid") {
		t.Fatalf("empty kid error = %v", err)
	}
	if _, err := SelectKey(keys, "retired"); err == nil || !strings.Contains(err.Error(), `kid "retired"`) {
		t.Fatalf("unknown kid error = %v", err)
	}
	// Tokens signed before rotation verify against the retained set.
	pub, priv, _, err := GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatal(err)
	}
	oldToken, err := SignJWT(priv, "EdDSA", "old", map[string]any{"sub": "u"})
	if err != nil {
		t.Fatal(err)
	}
	set := []PublicKey{{Kid: "old", Alg: "EdDSA", PublicJWKJSON: pub}}
	if _, err := VerifyJWT(oldToken, append(set, PublicKey{Kid: "current", Alg: "EdDSA", PublicJWKJSON: pub}), VerifyOptions{}); err != nil {
		t.Fatalf("pre-rotation token rejected: %v", err)
	}
}

func TestSessionCookieJWTConstants(t *testing.T) {
	// Pinned to vendor/better-auth/packages/better-auth/src/cookies/jwt.ts.
	if SessionCookieJWTType != "better-auth.session-cache+jwt" {
		t.Errorf("typ = %q", SessionCookieJWTType)
	}
	if SessionCookieJWTAudience != "better-auth:session-cache" {
		t.Errorf("aud = %q", SessionCookieJWTAudience)
	}
	if SessionCookieJWTIssuer != "better-auth:session-cache" {
		t.Errorf("iss = %q", SessionCookieJWTIssuer)
	}
	if SessionCookieJWTClockToleranceSeconds != 15 {
		t.Errorf("clock tolerance = %d, want 15", SessionCookieJWTClockToleranceSeconds)
	}
}
