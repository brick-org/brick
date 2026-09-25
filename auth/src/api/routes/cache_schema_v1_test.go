package routes

// G1 route-layer schema-validation ports (pinned upstream Better Auth v1.7.5
// @ 5468e6bf).
// Upstream case: `decodeCookieCache` verifies the signature and THEN
// zod-validates the payload (`parseCookieCachePayload`,
// vendor/.../src/cookies/cache.ts:20-39, wired in

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/cookies"
)

func schemaV1RouteSession() map[string]any {
	now := time.Now().UTC()
	return map[string]any{
		"id":        "sess-route-1",
		"userId":    "user-route-1",
		"token":     "tok-route-1",
		"expiresAt": now.Add(time.Hour).Format(time.RFC3339),
		"createdAt": now.Format(time.RFC3339),
		"updatedAt": now.Format(time.RFC3339),
	}
}

func schemaV1RouteUser() map[string]any {
	now := time.Now().UTC()
	return map[string]any{
		"id":            "user-route-1",
		"email":         "route@example.com",
		"emailVerified": true,
		"name":          "Route",
		"createdAt":     now.Format(time.RFC3339),
		"updatedAt":     now.Format(time.RFC3339),
	}
}

// schemaV1RouteCompactValue signs a route-compact session_data value
func schemaV1RouteCompactValue(t *testing.T, secret string, session, user map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"session":   session,
		"user":      user,
		"expiresAt": time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339),
		"version":   "1",
	})
	if err != nil {
		t.Fatalf("marshal compact payload: %v", err)
	}
	signed, err := cookies.Sign(secret, base64.RawURLEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatalf("sign compact payload: %v", err)
	}
	return signed
}

// The resurrected probe at the route layer: a correctly-signed compact cache
func TestSchemaV1_CompactCachePayloadRejectsNullEmailVerified(t *testing.T) {
	session := schemaV1RouteSession()
	user := schemaV1RouteUser()
	user["emailVerified"] = nil
	value := schemaV1RouteCompactValue(t, "route-secret", session, user)
	payload, err := compactCachePayload(value, []string{"route-secret"})
	if err == nil {
		t.Fatalf("signed compact cache with emailVerified:null decoded: %+v", payload)
	}
	if !errors.Is(err, cookies.ErrCachePayloadSchema) {
		t.Fatalf("error = %v, want ErrCachePayloadSchema sentinel", err)
	}
}

// Valid compact payloads still decode with fields intact.
func TestSchemaV1_CompactCachePayloadAcceptsValid(t *testing.T) {
	value := schemaV1RouteCompactValue(t, "route-secret", schemaV1RouteSession(), schemaV1RouteUser())
	payload, err := compactCachePayload(value, []string{"route-secret"})
	if err != nil {
		t.Fatalf("valid compact cache rejected: %v", err)
	}
	if payload.Session.Token != "tok-route-1" {
		t.Fatalf("session token = %q, want tok-route-1", payload.Session.Token)
	}
	if payload.User.Email != "route@example.com" || !payload.User.EmailVerified {
		t.Fatalf("user = %+v", payload.User)
	}
}

// Signature failures stay signature failures (never the schema sentinel).
func TestSchemaV1_CompactCachePayloadSignatureIdentity(t *testing.T) {
	value := schemaV1RouteCompactValue(t, "route-secret", schemaV1RouteSession(), schemaV1RouteUser())
	if _, err := compactCachePayload("x"+value[1:], []string{"route-secret"}); err == nil {
		t.Fatal("tampered compact cache decoded")
	} else if errors.Is(err, cookies.ErrCachePayloadSchema) {
		t.Fatalf("tampered cache returned the schema sentinel: %v", err)
	}
	if _, err := compactCachePayload(value, []string{"wrong-secret"}); err == nil {
		t.Fatal("wrong-secret compact cache decoded")
	} else if errors.Is(err, cookies.ErrCachePayloadSchema) {
		t.Fatalf("wrong-secret cache returned the schema sentinel: %v", err)
	}
}

// Route-visible JWT analog: a correctly-signed JWT cache with
func TestSchemaV1_JWTCachePayloadSchemaVerdict(t *testing.T) {
	badUser := schemaV1RouteUser()
	badUser["emailVerified"] = nil
	bad, err := cookies.CreateSessionCacheJWT("route-secret", schemaV1RouteSession(), badUser, "1", 5*time.Minute)
	if err != nil {
		t.Fatalf("issue jwt cache: %v", err)
	}
	if _, err := jwtCachePayload(bad, []string{"route-secret"}); err == nil {
		t.Fatal("signed jwt cache with emailVerified:null decoded")
	} else if !errors.Is(err, cookies.ErrCachePayloadSchema) {
		t.Fatalf("error = %v, want ErrCachePayloadSchema sentinel", err)
	}
	good, err := cookies.CreateSessionCacheJWT("route-secret", schemaV1RouteSession(), schemaV1RouteUser(), "1", 5*time.Minute)
	if err != nil {
		t.Fatalf("issue jwt cache: %v", err)
	}
	payload, err := jwtCachePayload(good, []string{"route-secret"})
	if err != nil {
		t.Fatalf("valid jwt cache rejected: %v", err)
	}
	if payload.Session.Token != "tok-route-1" || !payload.User.EmailVerified {
		t.Fatalf("payload = %+v", payload)
	}
}

// Route-visible JWE analog.
func TestSchemaV1_JWECachePayloadSchemaVerdict(t *testing.T) {
	const secret = "route-v1-jwe-secret-at-least-32-chars!"
	badUser := schemaV1RouteUser()
	badUser["emailVerified"] = nil
	bad, err := cookies.CreateSessionCacheJWE(secret, schemaV1RouteSession(), badUser, "1", 5*time.Minute)
	if err != nil {
		t.Fatalf("issue jwe cache: %v", err)
	}
	if _, err := jweCachePayload(bad, []string{secret}); err == nil {
		t.Fatal("signed jwe cache with emailVerified:null decoded")
	} else if !errors.Is(err, cookies.ErrCachePayloadSchema) {
		t.Fatalf("error = %v, want ErrCachePayloadSchema sentinel", err)
	}
	good, err := cookies.CreateSessionCacheJWE(secret, schemaV1RouteSession(), schemaV1RouteUser(), "1", 5*time.Minute)
	if err != nil {
		t.Fatalf("issue jwe cache: %v", err)
	}
	payload, err := jweCachePayload(good, []string{secret})
	if err != nil {
		t.Fatalf("valid jwe cache rejected: %v", err)
	}
	if payload.Session.Token != "tok-route-1" || !payload.User.EmailVerified {
		t.Fatalf("payload = %+v", payload)
	}
}
