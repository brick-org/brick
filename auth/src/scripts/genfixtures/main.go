// Command genfixtures regenerates the checked-in golden vectors under
// auth/testdata using only the in-repo Go helpers (no network).
//
// It is wrapped by auth/scripts/gen-fixtures.sh; see auth/testdata/README.md
// for the repeatable fixture path and provenance policy.
//
// Time-sensitive fixtures (email JWT, session JWT/JWE, JWK-signed JWT) are
// minted with a ~10-year window so hermetic CI stays green without
// re-generation. Every secret and private key here is a fixture-only value
// (auth-r5-04-…) and must never be used outside tests.
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/brick-org/brick/auth/src/cookies"
	"github.com/brick-org/brick/auth/src/crypto"
)

const (
	pinnedCommit  = "5468e6bfcdff799848537cf5ad06ebab15aad9dd"
	pinnedVersion = "v1.7.5"
	// tenYears keeps exp-bearing fixtures valid for hermetic CI without
	// frequent re-generation. 10*365 days in seconds.
	tenYearSeconds = 10 * 365 * 24 * 3600
	tenYearWindow  = 10 * 365 * 24 * time.Hour
)

func main() {
	if err := run("testdata"); err != nil {
		fmt.Fprintln(os.Stderr, "genfixtures:", err)
		os.Exit(1)
	}
}

func run(dir string) error {
	generatedAt := time.Now().UTC().Format(time.RFC3339)

	if err := writeEmailJWT(dir); err != nil {
		return fmt.Errorf("email jwt: %w", err)
	}
	if err := writeXChaCha(dir); err != nil {
		return fmt.Errorf("xchacha: %w", err)
	}
	if err := writeSessionJWT(dir); err != nil {
		return fmt.Errorf("session jwt: %w", err)
	}
	if err := writeSessionJWE(dir); err != nil {
		return fmt.Errorf("session jwe: %w", err)
	}
	if err := writeJWK(dir, generatedAt); err != nil {
		return fmt.Errorf("jwk: %w", err)
	}
	if err := writeStaticJSON(dir, "cookies.json", cookiesFixture()); err != nil {
		return err
	}
	return writeProvenance(dir, generatedAt)
}

// ---------------------------------------------------------------------------
// Email HS256 JWT.
// ---------------------------------------------------------------------------

func writeEmailJWT(dir string) error {
	const secret = "auth-r5-04-email-fixture-secret-0123456789"
	token, err := crypto.CreateEmailVerificationToken(secret, "Fixture@Example.com", "", tenYearSeconds, map[string]any{"fixture": "auth-r5-04"})
	if err != nil {
		return err
	}
	// Go-write/TS-read check: header must be {alg HS256} and the payload must
	// carry the lowercased email plus iat/exp; then verify the round trip
	// (TS-write/Go-read direction uses the same shape).
	header, payload, err := splitJWT(token)
	if err != nil {
		return err
	}
	payloadBack, err := crypto.VerifyEmailVerificationToken(secret, token)
	if err != nil {
		return fmt.Errorf("self-verify: %w", err)
	}
	if payloadBack.Email != "fixture@example.com" {
		return fmt.Errorf("email not lowercased: %q", payloadBack.Email)
	}
	doc := map[string]any{
		"secret":  secret,
		"token":   token,
		"header":  header,
		"payload": payload,
		"expected": map[string]any{
			"alg":   "HS256",
			"email": "fixture@example.com",
			"extra": map[string]any{"fixture": "auth-r5-04"},
		},
		"note": "Upstream: createEmailVerificationToken (SignJWT {alg HS256}, lowercased email, iat/exp).",
	}
	return writeStaticJSON(dir, "email_jwt.json", doc)
}

// ---------------------------------------------------------------------------
// XChaCha20-Poly1305 envelope.
// ---------------------------------------------------------------------------

func writeXChaCha(dir string) error {
	const secret = "auth-r5-04-xchacha-fixture-secret"
	const plaintext = `{"callbackURL":"/dashboard","codeVerifier":"ts-verifier-0123456789abcdef","theme":"dark"}`
	bare, err := crypto.SymmetricEncrypt(secret, plaintext)
	if err != nil {
		return err
	}
	cfg := crypto.SecretConfig{
		Keys:           map[int]string{1: "auth-r5-04-xchacha-old", 2: secret},
		CurrentVersion: 2,
		LegacySecret:   "auth-r5-04-xchacha-legacy",
	}
	env, err := crypto.SymmetricEncrypt(cfg, plaintext)
	if err != nil {
		return err
	}
	// Verify both directions before persisting.
	if back, err := crypto.SymmetricDecrypt(secret, bare); err != nil || back != plaintext {
		return fmt.Errorf("bare round trip: %q %v", back, err)
	}
	if back, err := crypto.SymmetricDecrypt(cfg, env); err != nil || back != plaintext {
		return fmt.Errorf("envelope round trip: %q %v", back, err)
	}
	legacyHex, err := crypto.SymmetricEncrypt("auth-r5-04-xchacha-legacy", "legacy")
	if err != nil {
		return err
	}
	if back, err := crypto.SymmetricDecrypt(cfg, legacyHex); err != nil || back != "legacy" {
		return fmt.Errorf("legacy round trip: %q %v", back, err)
	}
	doc := map[string]any{
		"secret":    secret,
		"plaintext": plaintext,
		"bare_hex":  bare,
		"envelope":  env,
		"envelope_secret_config": map[string]any{
			"keys":            map[string]any{"1": "auth-r5-04-xchacha-old", "2": secret},
			"current_version": 2,
			"legacy_secret":   "auth-r5-04-xchacha-legacy",
		},
		"legacy_bare_hex": legacyHex,
		"expected": map[string]any{
			"envelope_prefix":   "$ba$2$",
			"bare_hex_alphabet": "0123456789abcdef",
		},
		"note": "Upstream: symmetricEncrypt/symmetricDecrypt/formatEnvelope/parseEnvelope (key = SHA-256(secret), XChaCha20-Poly1305, random 24-byte nonce prepended, hex).",
	}
	return writeStaticJSON(dir, "xchacha.json", doc)
}

// ---------------------------------------------------------------------------
// Session JWT/JWE cache.
// ---------------------------------------------------------------------------

func fixtureSession() map[string]any {
	return map[string]any{
		"id":        "sess-fixture-1",
		"userId":    "user-fixture-1",
		"token":     "tok-fixture-1",
		"expiresAt": "2036-01-01T00:00:00Z",
		"createdAt": "2026-01-01T00:00:00Z",
		"updatedAt": "2026-01-01T00:00:00Z",
	}
}

func fixtureUser() map[string]any {
	return map[string]any{
		"id":            "user-fixture-1",
		"email":         "fixture@example.com",
		"emailVerified": true,
		"name":          "Fixture",
		"createdAt":     "2026-01-01T00:00:00Z",
		"updatedAt":     "2026-01-01T00:00:00Z",
	}
}

func writeSessionJWT(dir string) error {
	const secret = "auth-r5-04-session-cache-secret-at-least-32-chars!!"
	session, user := fixtureSession(), fixtureUser()
	token, err := cookies.CreateSessionCacheJWT(secret, session, user, "1", tenYearWindow)
	if err != nil {
		return err
	}
	header, payload, err := splitJWT(token)
	if err != nil {
		return err
	}
	got, expMillis, err := cookies.VerifySessionCacheJWT([]string{"rotated-secret", secret}, token)
	if err != nil {
		return fmt.Errorf("self-verify: %w", err)
	}
	if got.Version != "1" || got.Session["token"] != "tok-fixture-1" || got.User["id"] != "user-fixture-1" {
		return fmt.Errorf("payload mismatch: %+v", got)
	}
	doc := map[string]any{
		"secret":  secret,
		"token":   token,
		"header":  header,
		"payload": payload,
		"session": session,
		"user":    user,
		"version": "1",
		"expected": map[string]any{
			"alg":           "HS256",
			"expiresMillis": expMillis,
		},
		"note": "Upstream: setCookieCache jwt branch (signSecretJWT HS256 over the auth secret).",
	}
	return writeStaticJSON(dir, "session_jwt.json", doc)
}

func writeSessionJWE(dir string) error {
	const secret = "auth-r5-04-session-cache-secret-at-least-32-chars!!"
	session, user := fixtureSession(), fixtureUser()
	token, err := cookies.CreateSessionCacheJWE(secret, session, user, "7", tenYearWindow)
	if err != nil {
		return err
	}
	header, err := splitJWEHeader(token)
	if err != nil {
		return err
	}
	key, err := crypto.DeriveEncryptionSecret(secret, crypto.SessionCookieEncryptionSalt)
	if err != nil {
		return err
	}
	wantKid, err := crypto.OctThumbprint(key)
	if err != nil {
		return err
	}
	if header["kid"] != wantKid {
		return fmt.Errorf("kid = %v, want %v", header["kid"], wantKid)
	}
	got, expMillis, err := cookies.VerifySessionCacheJWE([]string{"rotated-secret", secret}, token)
	if err != nil {
		return fmt.Errorf("self-verify: %w", err)
	}
	if got.Version != "7" {
		return fmt.Errorf("version = %q", got.Version)
	}
	doc := map[string]any{
		"secret":  secret,
		"token":   token,
		"header":  header,
		"session": session,
		"user":    user,
		"version": "7",
		"expected": map[string]any{
			"alg":           "dir",
			"enc":           "A256CBC-HS512",
			"kid":           wantKid,
			"expiresMillis": expMillis,
		},
		"note": "Upstream: setCookieCache jwe branch (symmetricEncodeJWT, HKDF salt better-auth-session, thumbprint kid, 15s tolerance).",
	}
	return writeStaticJSON(dir, "session_jwe.json", doc)
}

// ---------------------------------------------------------------------------
// JWK/JWKS (EdDSA; private half is TEST-ONLY fixture material).
// ---------------------------------------------------------------------------

func writeJWK(dir string, generatedAt string) error {
	const kid = "auth-r5-04-fixture-key-1"
	pub, priv, crv, err := crypto.GenerateKeyPair("EdDSA")
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	claims := map[string]any{
		"sub": "fixture-user-1",
		"iss": "https://auth.example.com",
		"aud": "https://api.example.com",
		"iat": now,
		"exp": now + tenYearSeconds,
	}
	token, err := crypto.SignJWT(priv, "EdDSA", kid, claims)
	if err != nil {
		return err
	}
	jwks, err := crypto.BuildJWKS([]crypto.PublicKey{{Kid: kid, Alg: "EdDSA", PublicJWKJSON: pub}})
	if err != nil {
		return err
	}
	// Verify before persisting (TS-write/Go-read direction uses this shape).
	back, err := crypto.VerifyJWT(token, []crypto.PublicKey{{Kid: kid, Alg: "EdDSA", PublicJWKJSON: pub}}, crypto.VerifyOptions{
		Issuer:   "https://auth.example.com",
		Audience: []string{"https://api.example.com"},
	})
	if err != nil {
		return fmt.Errorf("self-verify: %w", err)
	}
	if back["sub"] != "fixture-user-1" {
		return fmt.Errorf("sub mismatch: %v", back["sub"])
	}
	var pubMap map[string]any
	if err := json.Unmarshal([]byte(pub), &pubMap); err != nil {
		return err
	}
	jwkDoc := map[string]any{
		"alg":                   "EdDSA",
		"kid":                   kid,
		"crv":                   crv,
		"public_jwk":            pubMap,
		"private_jwk_test_only": json.RawMessage(priv),
		"token":                 token,
		"claims":                claims,
		"generated_at":          generatedAt,
		"note":                  "TEST-ONLY keypair. Upstream: crypto/jwt.ts JWKOptions + plugins/jwt rotation.",
	}
	if err := writeStaticJSON(dir, "jwk.json", jwkDoc); err != nil {
		return err
	}
	return writeStaticJSON(dir, "jwks.json", jwks)
}

// ---------------------------------------------------------------------------
// Static fixtures (deterministic; idempotent across regens).
// ---------------------------------------------------------------------------

func cookiesFixture() map[string]any {
	return map[string]any{
		"sign_vectors": []map[string]any{
			{"secret": "secret", "value": "value", "signed": "value.UOA-vmW-mLuL8RuiyJLVTAeayisNOwFidpxtdXolQ08"},
			{"secret": "key", "value": "The quick brown fox jumps over the lazy dog", "signed": "The quick brown fox jumps over the lazy dog.97yD9DBThCSxMpjmqm-xQ-9NWaFJRhdZl0edvC0aPNg"},
			{"secret": "Jefe", "value": "what do ya want for nothing?", "signed": "what do ya want for nothing?.W9zBRr9gdU5qBCQmCJV1x1oAPwidJzmDnexYuWTsOEM"},
		},
		"chunk_fixture": map[string]any{
			"name": "better-auth.session_data",
			"cookies": map[string]any{
				"better-auth.session_data.0": "FIRST",
				"better-auth.session_data.1": "SECOND",
				"better-auth.session_data.2": "THIRD",
			},
			"want": "FIRSTSECONDTHIRD",
		},
		"note": "Wire: value.hmac with HMAC-SHA256 base64url-nopad; chunk names <name>.<index> reassembled in index order.",
	}
}

// ---------------------------------------------------------------------------
// Provenance.
// ---------------------------------------------------------------------------

type fixtureProvenance struct {
	File              string `json:"file"`
	UpstreamFile      string `json:"upstream_file"`
	UpstreamTest      string `json:"upstream_test"`
	GenerationCommand string `json:"generation_command"`
}

func writeProvenance(dir, generatedAt string) error {
	goGen := "GOWORK=off go run ./scripts/genfixtures (from auth/; wrapped by ./scripts/gen-fixtures.sh)"
	tsRef := "opt-in: pnpm --dir vendor/better-auth vitest run <test> -t '<pattern>' (see gen-fixtures.sh --ts)"
	fixtures := []fixtureProvenance{
		{"email_jwt.json", "packages/better-auth/src/api/routes/email-verification.ts; packages/better-auth/src/crypto/jwt.ts", "email-verification route tests; " + tsRef + " crypto", goGen},
		{"xchacha.json", "packages/better-auth/src/crypto/index.ts", "packages/better-auth/src/crypto secret-rotation tests; " + tsRef, goGen},
		{"session_jwt.json", "packages/better-auth/src/cookies/index.ts; packages/better-auth/src/crypto/jwt.ts", "cookies tests; " + tsRef + " cookies", goGen},
		{"session_jwe.json", "packages/better-auth/src/cookies/index.ts; packages/better-auth/src/crypto/jwt.ts", "cookies tests; " + tsRef + " cookies", goGen},
		{"jwk.json", "packages/better-auth/src/crypto/jwt.ts", "packages/plugins/jwt tests; " + tsRef + " jwt", goGen},
		{"jwks.json", "packages/better-auth/src/crypto/jwt.ts", "jwks endpoint tests; " + tsRef + " jwt", goGen},
		{"cookies.json", "packages/better-auth/src/cookies/index.ts; packages/better-auth/src/crypto", "cookie tests; auth/cookies/edge_parity_test.go (TestSignFixedVectors); auth/cookies/wave4_conformance_test.go", "static HMAC/chunk vectors; verified by TestFixture_Cookies in auth/testutil"},
	}
	doc := map[string]any{
		"pinned_commit":  pinnedCommit,
		"pinned_version": pinnedVersion,
		"generated_at":   generatedAt,
		"generator":      "auth/scripts/genfixtures/main.go via auth/scripts/gen-fixtures.sh",
		"fixtures":       fixtures,
	}
	return writeStaticJSON(dir, "provenance.json", doc)
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

func writeStaticJSON(dir, name string, doc any) error {
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return os.WriteFile(filepath.Join(dir, name), raw, 0o644)
}

func splitJWT(token string) (header, payload map[string]any, err error) {
	var parts []string
	start := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	parts = append(parts, token[start:])
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("not a compact JWT")
	}
	if header, err = decodeSegment(parts[0]); err != nil {
		return nil, nil, fmt.Errorf("header: %w", err)
	}
	if payload, err = decodeSegment(parts[1]); err != nil {
		return nil, nil, fmt.Errorf("payload: %w", err)
	}
	return header, payload, nil
}

func decodeSegment(seg string) (map[string]any, error) {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func splitJWEHeader(token string) (map[string]any, error) {
	end := -1
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			end = i
			break
		}
	}
	if end < 0 {
		return nil, fmt.Errorf("not a compact JWE")
	}
	raw, err := base64.RawURLEncoding.DecodeString(token[:end])
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}
