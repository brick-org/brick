package cookies

// G1 schema-validation ports (pinned upstream Better Auth v1.7.5 @ 5468e6bf).
//
// Upstream case: `decodeCookieCache` verifies the signature and THEN
// zod-validates the payload (`parseCookieCachePayload`,
// vendor/.../src/cookies/cache.ts:20-39 over `cookieCachePayloadSchema`,
// wired in vendor/.../src/cookies/index.ts:328-353 for the compact branch
// and the jwt/jwe branches). A correctly-signed but schema-invalid payload
// returns null with a configured-logger warn
// ("should use the configured logger for an invalid signed compact cookie"
// plus the JWT/JWE analogs).
//
// Go gap: VerifyCompactCookieCache checked envelope/HMAC/window/expiry
// only, and VerifySessionCacheJWT/VerifySessionCacheJWE checked session/user
// non-nil only, so a correctly-signed schema-invalid cache (e.g.
// user.emailVerified: null, which zod rejects but Go's typed unmarshal
// silently coerces to false) was ACCEPTED as a hit.
//
// These tests pin the fixed contract: correctly-signed schema-invalid
// payloads fail with the ErrCachePayloadSchema sentinel (identity checked
// with errors.Is), valid payloads still verify on all strategies, and
// tampered-signature failures keep their signature-step error (never the
// schema sentinel).

import (
	"errors"
	"testing"
	"time"
)

func schemaV1Session() map[string]any {
	now := time.Now().UTC()
	return map[string]any{
		"id":        "sess-schema-1",
		"userId":    "user-schema-1",
		"token":     "tok-schema-1",
		"expiresAt": now.Add(time.Hour).Format(time.RFC3339),
		"createdAt": now.Format(time.RFC3339),
		"updatedAt": now.Format(time.RFC3339),
	}
}

func schemaV1User() map[string]any {
	now := time.Now().UTC()
	return map[string]any{
		"id":            "user-schema-1",
		"email":         "schema@example.com",
		"emailVerified": true,
		"name":          "Schema",
		"createdAt":     now.Format(time.RFC3339),
		"updatedAt":     now.Format(time.RFC3339),
	}
}

func schemaV1Pair(mutUser func(map[string]any)) map[string]any {
	user := schemaV1User()
	if mutUser != nil {
		mutUser(user)
	}
	return map[string]any{
		"session": schemaV1Session(),
		"user":    user,
	}
}

// The deleted probe, resurrected: a correctly-signed compact cache carrying
// user.emailVerified: null (JSON null) must NOT verify. Upstream
// parseCookieCachePayload rejects it (z.boolean() rejects null); Go must
// return the schema sentinel, not a hit.
func TestSchemaV1_CompactRejectsNullEmailVerified(t *testing.T) {
	pair := schemaV1Pair(func(user map[string]any) {
		user["emailVerified"] = nil
	})
	value, err := CreateCompactCookieCache("schema-secret", pair, 5*time.Minute)
	if err != nil {
		t.Fatalf("issue compact cache: %v", err)
	}
	_, _, err = VerifyCompactCookieCache([]string{"schema-secret"}, value)
	if err == nil {
		t.Fatal("signed compact cache with emailVerified:null verified; want schema rejection")
	}
	if !errors.Is(err, ErrCachePayloadSchema) {
		t.Fatalf("error = %v, want ErrCachePayloadSchema sentinel", err)
	}
}

// JWT analog of the probe.
func TestSchemaV1_JWTRejectsNullEmailVerified(t *testing.T) {
	session := schemaV1Session()
	user := schemaV1User()
	user["emailVerified"] = nil
	token, err := CreateSessionCacheJWT("schema-secret", session, user, "1", 5*time.Minute)
	if err != nil {
		t.Fatalf("issue jwt cache: %v", err)
	}
	_, _, err = VerifySessionCacheJWT([]string{"schema-secret"}, token)
	if err == nil {
		t.Fatal("signed jwt cache with emailVerified:null verified; want schema rejection")
	}
	if !errors.Is(err, ErrCachePayloadSchema) {
		t.Fatalf("error = %v, want ErrCachePayloadSchema sentinel", err)
	}
}

// JWE analog of the probe.
func TestSchemaV1_JWERejectsNullEmailVerified(t *testing.T) {
	const secret = "schema-v1-jwe-secret-at-least-32-chars!"
	session := schemaV1Session()
	user := schemaV1User()
	user["emailVerified"] = nil
	token, err := CreateSessionCacheJWE(secret, session, user, "1", 5*time.Minute)
	if err != nil {
		t.Fatalf("issue jwe cache: %v", err)
	}
	_, _, err = VerifySessionCacheJWE([]string{secret}, token)
	if err == nil {
		t.Fatal("signed jwe cache with emailVerified:null verified; want schema rejection")
	}
	if !errors.Is(err, ErrCachePayloadSchema) {
		t.Fatalf("error = %v, want ErrCachePayloadSchema sentinel", err)
	}
}

// Wrong-typed core fields (not just null) are schema-invalid too.
func TestSchemaV1_CompactRejectsWrongTypedToken(t *testing.T) {
	pair := schemaV1Pair(nil)
	pair["session"].(map[string]any)["token"] = float64(123)
	value, err := CreateCompactCookieCache("schema-secret", pair, 5*time.Minute)
	if err != nil {
		t.Fatalf("issue compact cache: %v", err)
	}
	_, _, err = VerifyCompactCookieCache([]string{"schema-secret"}, value)
	if err == nil {
		t.Fatal("signed compact cache with numeric token verified; want schema rejection")
	}
	if !errors.Is(err, ErrCachePayloadSchema) {
		t.Fatalf("error = %v, want ErrCachePayloadSchema sentinel", err)
	}
}

// Valid payloads still verify on all three strategies.
func TestSchemaV1_ValidPayloadsVerify(t *testing.T) {
	const jweSecret = "schema-v1-jwe-secret-at-least-32-chars!"
	compact, err := CreateCompactCookieCache("schema-secret", schemaV1Pair(nil), 5*time.Minute)
	if err != nil {
		t.Fatalf("issue compact cache: %v", err)
	}
	if _, _, err := VerifyCompactCookieCache([]string{"schema-secret"}, compact); err != nil {
		t.Fatalf("valid compact cache rejected: %v", err)
	}
	jwt, err := CreateSessionCacheJWT("schema-secret", schemaV1Session(), schemaV1User(), "1", 5*time.Minute)
	if err != nil {
		t.Fatalf("issue jwt cache: %v", err)
	}
	gotJWT, _, err := VerifySessionCacheJWT([]string{"schema-secret"}, jwt)
	if err != nil {
		t.Fatalf("valid jwt cache rejected: %v", err)
	}
	if gotJWT.Session["token"] != "tok-schema-1" || gotJWT.User["email"] != "schema@example.com" {
		t.Fatalf("jwt payload = %+v", gotJWT)
	}
	jwe, err := CreateSessionCacheJWE(jweSecret, schemaV1Session(), schemaV1User(), "1", 5*time.Minute)
	if err != nil {
		t.Fatalf("issue jwe cache: %v", err)
	}
	gotJWE, _, err := VerifySessionCacheJWE([]string{jweSecret}, jwe)
	if err != nil {
		t.Fatalf("valid jwe cache rejected: %v", err)
	}
	if gotJWE.Session["token"] != "tok-schema-1" || gotJWE.User["email"] != "schema@example.com" {
		t.Fatalf("jwe payload = %+v", gotJWE)
	}
}

// Tampered-signature cases still fail at the signature step, never with the
// schema sentinel: the error identity must differ.
func TestSchemaV1_TamperedSignatureIsNotSchemaError(t *testing.T) {
	const jweSecret = "schema-v1-jwe-secret-at-least-32-chars!"
	compact, err := CreateCompactCookieCache("schema-secret", schemaV1Pair(nil), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	jwt, err := CreateSessionCacheJWT("schema-secret", schemaV1Session(), schemaV1User(), "1", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	jwe, err := CreateSessionCacheJWE(jweSecret, schemaV1Session(), schemaV1User(), "1", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func() error{
		"compact tampered": func() error {
			_, _, err := VerifyCompactCookieCache([]string{"schema-secret"}, "x"+compact[1:])
			return err
		},
		"compact wrong secret": func() error {
			_, _, err := VerifyCompactCookieCache([]string{"wrong-secret"}, compact)
			return err
		},
		"jwt tampered": func() error {
			_, _, err := VerifySessionCacheJWT([]string{"schema-secret"}, jwt[:len(jwt)-2]+"xx")
			return err
		},
		"jwt wrong secret": func() error {
			_, _, err := VerifySessionCacheJWT([]string{"wrong-secret"}, jwt)
			return err
		},
		"jwe tampered": func() error {
			_, _, err := VerifySessionCacheJWE([]string{jweSecret}, jwe[:len(jwe)-4]+"xxxx")
			return err
		},
		"jwe wrong secret": func() error {
			_, _, err := VerifySessionCacheJWE([]string{"other-a-at-least-32-chars-long!!!", "other-b-at-least-32-chars-long!!!"}, jwe)
			return err
		},
	}
	for name, fn := range cases {
		err := fn()
		if err == nil {
			t.Fatalf("%s: tampered cache verified", name)
		}
		if errors.Is(err, ErrCachePayloadSchema) {
			t.Fatalf("%s: signature failure returned the schema sentinel: %v", name, err)
		}
	}
}
