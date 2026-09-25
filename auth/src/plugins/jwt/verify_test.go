package jwt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	authcrypto "github.com/brick-org/brick/auth/src/crypto"
	authtypes "github.com/brick-org/brick/auth/src/types"
	jose "github.com/go-jose/go-jose/v4"
)

func TestVerifyJWTValidatesSignatureAndRegisteredClaims(t *testing.T) {
	keys, privateKey := verificationKeyPair(t)
	valid := map[string]any{
		"iss":  "https://issuer.example",
		"sub":  "user-123",
		"aud":  []string{"api", "other"},
		"exp":  time.Now().Add(time.Hour).Unix(),
		"nbf":  time.Now().Add(-time.Minute).Unix(),
		"iat":  time.Now().Unix(),
		"jti":  "token-123",
		"role": "reader",
	}
	options := VerifyOptions{
		Issuer:   "https://issuer.example",
		Audience: []string{"api"},
		Leeway:   time.Second,
	}
	token := signVerificationJWT(t, privateKey, "verification-key", "JWT", valid)
	claims, err := verifyJWT(token, keys, options)
	if err != nil {
		t.Fatalf("verifyJWT(valid) error = %v", err)
	}
	if claims.Subject != "user-123" || claims.Issuer != options.Issuer || claims.JWTID != "token-123" {
		t.Fatalf("verifyJWT(valid) claims = %#v", claims)
	}
	if len(claims.Audience) != 2 || claims.CustomClaims["role"] != "reader" {
		t.Fatalf("verifyJWT(valid) audience/custom claims = %#v / %#v", claims.Audience, claims.CustomClaims)
	}

	for _, test := range []struct {
		name    string
		claims  map[string]any
		options VerifyOptions
	}{
		{name: "issuer mismatch", claims: valid, options: VerifyOptions{Issuer: "wrong", Audience: []string{"api"}}},
		{name: "audience mismatch", claims: valid, options: VerifyOptions{Issuer: options.Issuer, Audience: []string{"different"}}},
		{name: "missing subject", claims: map[string]any{"iss": options.Issuer, "aud": "api"}, options: options},
		{name: "malformed audience", claims: map[string]any{"iss": options.Issuer, "sub": "user", "aud": []any{"api", 4}}, options: options},
		{name: "expired", claims: map[string]any{"iss": options.Issuer, "sub": "user", "aud": "api", "exp": time.Now().Add(-time.Minute).Unix()}, options: options},
		{name: "not yet valid", claims: map[string]any{"iss": options.Issuer, "sub": "user", "aud": "api", "nbf": time.Now().Add(time.Minute).Unix()}, options: options},
		{name: "required expiration", claims: map[string]any{"iss": options.Issuer, "sub": "user", "aud": "api"}, options: VerifyOptions{Issuer: options.Issuer, Audience: options.Audience, RequireExpiration: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			token := signVerificationJWT(t, privateKey, "verification-key", "JWT", test.claims)
			if _, err := verifyJWT(token, keys, test.options); err == nil {
				t.Fatal("verifyJWT() succeeded for invalid claims")
			}
		})
	}

	noExpiration := map[string]any{"iss": options.Issuer, "sub": "user", "aud": "api"}
	if _, err := verifyJWT(signVerificationJWT(t, privateKey, "verification-key", "JWT", noExpiration), keys, VerifyOptions{}); err != nil {
		t.Fatalf("verifyJWT() without required expiration error = %v", err)
	}

	withinLeeway := map[string]any{
		"sub": "user",
		"aud": "api",
		"exp": time.Now().Add(-time.Second).Unix(),
		"nbf": time.Now().Add(time.Second).Unix(),
	}
	if _, err := verifyJWT(signVerificationJWT(t, privateKey, "verification-key", "JWT", withinLeeway), keys, VerifyOptions{Leeway: 3 * time.Second}); err != nil {
		t.Fatalf("verifyJWT() within leeway error = %v", err)
	}
}

func TestVerifyJWTRejectsTamperingAmbiguityAndKeyMismatch(t *testing.T) {
	keys, privateKey := verificationKeyPair(t)
	claims := map[string]any{
		"iss": "issuer",
		"sub": "subject",
		"aud": "audience",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	token := signVerificationJWT(t, privateKey, "verification-key", "JWT", claims)
	parts := strings.Split(token, ".")
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"issuer","sub":"attacker","aud":"audience"}`))
	tampered := strings.Join(parts, ".")
	if _, err := verifyJWT(tampered, keys, VerifyOptions{}); err == nil {
		t.Fatal("verifyJWT() accepted a tampered payload")
	}

	duplicateClaims := []byte(`{"iss":"issuer","sub":"first","sub":"second","aud":"audience"}`)
	if _, err := verifyJWT(signVerificationPayload(t, privateKey, "verification-key", "JWT", duplicateClaims), keys, VerifyOptions{}); err == nil {
		t.Fatal("verifyJWT() accepted duplicate claim names")
	}

	withoutKID := signVerificationJWT(t, privateKey, "", "JWT", claims)
	if _, err := verifyJWT(withoutKID, keys, VerifyOptions{}); err == nil {
		t.Fatal("verifyJWT() accepted a token without kid")
	}

	mismatchedKey := append([]JWK(nil), keys...)
	mismatchedKey[0].Alg = algorithmPtr(AlgRS256)
	if _, err := verifyJWT(token, mismatchedKey, VerifyOptions{}); err == nil {
		t.Fatal("verifyJWT() accepted an algorithm/key mismatch")
	}
	if _, err := verifyJWT(token, keys, VerifyOptions{AllowedAlgorithms: []JWSAlgorithm{AlgRS256}}); err == nil {
		t.Fatal("verifyJWT() accepted an algorithm outside the configured allowlist")
	}
	ambiguousKeys := append(append([]JWK(nil), keys...), keys[0])
	if _, err := verifyJWT(token, ambiguousKeys, VerifyOptions{}); err == nil {
		t.Fatal("verifyJWT() accepted duplicate key ids")
	}
}

func TestVerifyAccessTokenRequiresOAuthAccessTokenProfile(t *testing.T) {
	keys, privateKey := verificationKeyPair(t)
	options := VerifyOptions{Issuer: "https://issuer.example", Audience: []string{"api"}}
	valid := map[string]any{
		"iss":       options.Issuer,
		"sub":       "user-123",
		"aud":       "api",
		"exp":       time.Now().Add(time.Hour).Unix(),
		"iat":       time.Now().Unix(),
		"jti":       "token-789",
		"client_id": "client-456",
		"scope":     "profile email",
	}
	token := signVerificationJWT(t, privateKey, "verification-key", "at+jwt", valid)
	claims, err := verifyAccessToken(token, keys, options)
	if err != nil {
		t.Fatalf("verifyAccessToken(valid) error = %v", err)
	}
	if claims.CustomClaims["client_id"] != "client-456" || claims.CustomClaims["scope"] != "profile email" {
		t.Fatalf("verifyAccessToken(valid) custom claims = %#v", claims.CustomClaims)
	}

	for _, test := range []struct {
		name   string
		typ    string
		mutate func(map[string]any)
	}{
		{name: "session JWT type", typ: "JWT"},
		{name: "missing client id", typ: "at+jwt", mutate: func(claims map[string]any) { delete(claims, "client_id") }},
		{name: "missing scope", typ: "at+jwt", mutate: func(claims map[string]any) { delete(claims, "scope") }},
		{name: "empty scope", typ: "at+jwt", mutate: func(claims map[string]any) { claims["scope"] = "" }},
		{name: "missing expiration", typ: "at+jwt", mutate: func(claims map[string]any) { delete(claims, "exp") }},
		{name: "missing issuer", typ: "at+jwt", mutate: func(claims map[string]any) { delete(claims, "iss") }},
		{name: "missing audience", typ: "at+jwt", mutate: func(claims map[string]any) { delete(claims, "aud") }},
		{name: "missing issued-at", typ: "at+jwt", mutate: func(claims map[string]any) { delete(claims, "iat") }},
		{name: "missing JWT ID", typ: "at+jwt", mutate: func(claims map[string]any) { delete(claims, "jti") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			invalid := make(map[string]any, len(valid))
			for name, value := range valid {
				invalid[name] = value
			}
			if test.mutate != nil {
				test.mutate(invalid)
			}
			if _, err := verifyAccessToken(signVerificationJWT(t, privateKey, "verification-key", test.typ, invalid), keys, options); err == nil {
				t.Fatal("verifyAccessToken() succeeded for invalid access token")
			}
		})
	}
}

func TestPluginVerifyJWTUsesConfiguredIssuerAndAudienceDefaults(t *testing.T) {
	keys, privateKey := verificationKeyPair(t)
	options := Options{JWT: &JWTOptions{
		Issuer:   "https://issuer.example",
		Audience: []string{"api"},
	}}
	plugin := New(options)
	plugin.authCtx = authtypes.AuthContext{BaseURL: "https://auth.example"}
	plugin.store = &signingTestStore{keys: keys}
	plugin.initialized = true

	valid := map[string]any{
		"iss": options.JWT.Issuer,
		"sub": "user-123",
		"aud": options.JWT.Audience,
	}
	if _, err := plugin.VerifyJWT(context.Background(), signVerificationJWT(t, privateKey, "verification-key", "JWT", valid), VerifyOptions{}); err != nil {
		t.Fatalf("VerifyJWT() with configured defaults error = %v", err)
	}

	for name, mutate := range map[string]func(map[string]any){
		"wrong issuer":   func(claims map[string]any) { claims["iss"] = "https://attacker.example" },
		"wrong audience": func(claims map[string]any) { claims["aud"] = []string{"other-resource"} },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := map[string]any{"iss": options.JWT.Issuer, "sub": "user-123", "aud": options.JWT.Audience}
			mutate(invalid)
			if _, err := plugin.VerifyJWT(context.Background(), signVerificationJWT(t, privateKey, "verification-key", "JWT", invalid), VerifyOptions{}); err == nil {
				t.Fatal("VerifyJWT() accepted a token outside its configured issuer/audience policy")
			}
		})
	}
}

func TestPluginVerifyAccessTokenRequiresAndEnforcesExpectedResource(t *testing.T) {
	keys, privateKey := verificationKeyPair(t)
	plugin := New(Options{})
	plugin.store = &signingTestStore{keys: keys}
	plugin.initialized = true
	claims := map[string]any{
		"iss": "https://issuer.example", "sub": "user-123", "aud": "resource-a",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		"jti": "token-123", "client_id": "client-456", "scope": "read",
	}
	token := signVerificationJWT(t, privateKey, "verification-key", "at+jwt", claims)
	if _, err := plugin.VerifyAccessToken(context.Background(), token, VerifyOptions{}); err == nil {
		t.Fatal("VerifyAccessToken() accepted zero-value expected issuer/audience")
	}
	if _, err := plugin.VerifyAccessToken(context.Background(), token, VerifyOptions{
		Issuer: "https://issuer.example", Audience: []string{"resource-b"},
	}); err == nil {
		t.Fatal("VerifyAccessToken() accepted a token for a different resource")
	}
	if _, err := plugin.VerifyAccessToken(context.Background(), token, VerifyOptions{
		Issuer: "https://issuer.example", Audience: []string{"resource-a"},
	}); err != nil {
		t.Fatalf("VerifyAccessToken() with matching issuer/resource error = %v", err)
	}
}

func verificationKeyPair(t *testing.T) ([]JWK, string) {
	t.Helper()
	publicKey, privateKey, _, err := authcrypto.GenerateKeyPair(string(AlgEdDSA))
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	return []JWK{{ID: "verification-key", PublicKeyJSON: publicKey, Alg: algorithmPtr(AlgEdDSA)}}, privateKey
}

func signVerificationJWT(t *testing.T, privateKey, kid, typ string, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal JWT claims: %v", err)
	}
	return signVerificationPayload(t, privateKey, kid, typ, payload)
}

func signVerificationPayload(t *testing.T, privateKey, kid, typ string, payload []byte) string {
	t.Helper()
	var key jose.JSONWebKey
	if err := json.Unmarshal([]byte(privateKey), &key); err != nil {
		t.Fatalf("parse private JWK: %v", err)
	}
	key.KeyID = kid
	key.Algorithm = string(AlgEdDSA)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: key}, (&jose.SignerOptions{}).WithType(jose.ContentType(typ)))
	if err != nil {
		t.Fatalf("create JWS signer: %v", err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign JWT payload: %v", err)
	}
	token, err := signed.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize JWS: %v", err)
	}
	return token
}
