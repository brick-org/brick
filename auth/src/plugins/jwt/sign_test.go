package jwt

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	authcrypto "github.com/brick-org/brick/auth/src/crypto"
	authtypes "github.com/brick-org/brick/auth/src/types"
	"github.com/go-jose/go-jose/v4/jwt"
)

func TestSignJWTInteropAndProtectedHeaders(t *testing.T) {
	key := signingTestKey(t, "local-kid", AlgEdDSA, time.Now())
	store := &signingTestStore{keys: []JWK{key}}
	token, err := signJWT(context.Background(), store, Options{}, Payload{"custom": "value"}, SigningKeyOverrides{
		SigningKeyID:     key.ID,
		SigningAlgorithm: AlgEdDSA,
		Typ:              "at+jwt",
	})
	if err != nil {
		t.Fatalf("signJWT() error = %v", err)
	}
	claims, err := authcrypto.VerifyJWT(token, []authcrypto.PublicKey{{
		Kid: key.ID, Alg: string(AlgEdDSA), PublicJWKJSON: key.PublicKeyJSON,
	}}, authcrypto.VerifyOptions{})
	if err != nil {
		t.Fatalf("auth/src/crypto.VerifyJWT() error = %v", err)
	}
	if claims["custom"] != "value" {
		t.Fatalf("verified custom claim = %#v, want %q", claims["custom"], "value")
	}
	parsed, err := jwt.ParseSigned(token, signingAlgorithms)
	if err != nil {
		t.Fatalf("parse signed JWT: %v", err)
	}
	if len(parsed.Headers) != 1 {
		t.Fatalf("signature header count = %d, want 1", len(parsed.Headers))
	}
	header := parsed.Headers[0]
	if header.Algorithm != string(AlgEdDSA) || header.KeyID != key.ID {
		t.Fatalf("protected alg/kid = %q/%q, want %q/%q", header.Algorithm, header.KeyID, AlgEdDSA, key.ID)
	}
	if got := header.ExtraHeaders["typ"]; got != "at+jwt" {
		t.Fatalf("protected typ = %#v, want at+jwt", got)
	}
}

func TestSessionJWTClaimsDefaultsAndReservedClaims(t *testing.T) {
	key := signingTestKey(t, "session-kid", AlgEdDSA, time.Now())
	store := &signingTestStore{keys: []JWK{key}}
	start := time.Now().Unix()
	options := Options{JWT: &JWTOptions{
		Issuer:         "configured-issuer",
		Audience:       []string{"configured-audience"},
		ExpirationTime: &ExpirationTime{After: 5 * time.Minute},
		DefinePayload: func(SessionData) (Payload, error) {
			return Payload{
				"custom": "kept",
				"iss":    "callback-issuer",
				"sub":    "callback-subject",
				"aud":    []string{"callback-audience"},
				"iat":    int64(1),
				"exp":    int64(2),
				"jti":    "callback-id",
			}, nil
		},
		GetSubject: func(data SessionData) (string, error) {
			if data.User.ID != "user-1" || data.Session.ID != "session-1" {
				t.Fatalf("subject callback received session data: %#v", data)
			}
			return "configured-subject", nil
		},
	}}
	token, err := sessionJWT(context.Background(), store, options, "https://auth.example", authtypes.Session{ID: "session-1", UserID: "user-1"}, authtypes.User{ID: "user-1"})
	if err != nil {
		t.Fatalf("sessionJWT() error = %v", err)
	}
	claims, err := authcrypto.VerifyJWT(token, []authcrypto.PublicKey{{
		Kid: key.ID, Alg: string(AlgEdDSA), PublicJWKJSON: key.PublicKeyJSON,
	}}, authcrypto.VerifyOptions{Issuer: "configured-issuer", Audience: []string{"configured-audience"}})
	if err != nil {
		t.Fatalf("verify session JWT: %v", err)
	}
	if claims["iss"] != "configured-issuer" || claims["sub"] != "configured-subject" {
		t.Fatalf("registered issuer/subject claims = %#v/%#v", claims["iss"], claims["sub"])
	}
	if claims["custom"] != "kept" {
		t.Fatalf("custom claim = %#v, want kept", claims["custom"])
	}
	issuedAt, ok := claims["iat"].(float64)
	if !ok || int64(issuedAt) < start || int64(issuedAt) > time.Now().Unix() {
		t.Fatalf("iat = %#v, want current Unix timestamp", claims["iat"])
	}
	expiresAt, ok := claims["exp"].(float64)
	if !ok || int64(expiresAt) < start+5*60 || int64(expiresAt) > time.Now().Unix()+5*60 {
		t.Fatalf("exp = %#v, want issued-at plus configured five minutes", claims["exp"])
	}
	if claims["jti"] != nil {
		t.Fatalf("reserved callback jti was retained: %#v", claims["jti"])
	}
}

func TestSessionJWTRequiresSubjectAndIssuerAudience(t *testing.T) {
	key := signingTestKey(t, "required-claims", AlgEdDSA, time.Now())
	store := &signingTestStore{keys: []JWK{key}}
	for _, test := range []struct {
		name    string
		options Options
		user    authtypes.User
	}{
		{name: "missing subject", options: Options{JWT: &JWTOptions{Issuer: "issuer", Audience: []string{"aud"}}}, user: authtypes.User{}},
		{name: "missing issuer and audience", user: authtypes.User{ID: "user"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := sessionJWT(context.Background(), store, test.options, "", authtypes.Session{}, test.user); err == nil {
				t.Fatal("sessionJWT() succeeded without required issuer/audience/subject")
			}
		})
	}
}

func TestPluginSignJWTUsesResolvedBaseURLDefaults(t *testing.T) {
	key := signingTestKey(t, "plugin-defaults", AlgEdDSA, time.Now())
	plugin := New(Options{})
	plugin.authCtx.BaseURL = "https://auth.example.test"
	plugin.store = &signingTestStore{keys: []JWK{key}}
	plugin.initialized = true
	token, err := plugin.SignJWT(context.Background(), Payload{"sub": "user"}, SigningKeyOverrides{})
	if err != nil {
		t.Fatalf("SignJWT() error = %v", err)
	}
	claims, err := authcrypto.VerifyJWT(token, []authcrypto.PublicKey{{
		Kid: key.ID, Alg: string(AlgEdDSA), PublicJWKJSON: key.PublicKeyJSON,
	}}, authcrypto.VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyJWT() error = %v", err)
	}
	if claims["iss"] != "https://auth.example.test" {
		t.Errorf("issuer = %#v, want plugin base URL", claims["iss"])
	}
	if got, ok := claims["aud"].([]any); !ok || len(got) != 1 || got[0] != "https://auth.example.test" {
		t.Errorf("audience = %#v, want plugin base URL", claims["aud"])
	}
}

func TestSessionJWTUsesBaseURLAndDefaultLifetime(t *testing.T) {
	key := signingTestKey(t, "fallback-kid", AlgEdDSA, time.Now())
	store := &signingTestStore{keys: []JWK{key}}
	before := time.Now().Unix()
	token, err := sessionJWT(context.Background(), store, Options{}, "https://fallback.example", authtypes.Session{ID: "s", UserID: "u"}, authtypes.User{ID: "u"})
	if err != nil {
		t.Fatalf("sessionJWT() error = %v", err)
	}
	claims, err := authcrypto.VerifyJWT(token, []authcrypto.PublicKey{{
		Kid: key.ID, Alg: string(AlgEdDSA), PublicJWKJSON: key.PublicKeyJSON,
	}}, authcrypto.VerifyOptions{Issuer: "https://fallback.example", Audience: []string{"https://fallback.example"}})
	if err != nil {
		t.Fatalf("verify default session JWT: %v", err)
	}
	if claims["sub"] != "u" || claims["id"] != "u" {
		t.Fatalf("default subject/user claims = %#v/%#v", claims["sub"], claims["id"])
	}
	issuedAt, _ := claims["iat"].(float64)
	expiresAt, _ := claims["exp"].(float64)
	if int64(issuedAt) < before || int64(expiresAt)-int64(issuedAt) != 15*60 {
		t.Fatalf("default iat/exp = %#v/%#v, want current iat and 15-minute lifetime", claims["iat"], claims["exp"])
	}
}

func TestResolveSigningKeySelectsExactKidAndLatestLiveAlgorithm(t *testing.T) {
	oldEd := signingTestKey(t, "old-ed", AlgEdDSA, time.Now().Add(-time.Hour))
	newEd := signingTestKey(t, "new-ed", AlgEdDSA, time.Now())
	oldES := signingTestKey(t, "old-es", AlgES256, time.Now().Add(-time.Hour))
	newES := signingTestKey(t, "new-es", AlgES256, time.Now())
	expiredAt := time.Now().Add(-time.Minute)
	expiredES := signingTestKey(t, "expired-es", AlgES256, time.Now())
	expiredES.ExpiresAt = &expiredAt
	store := &signingTestStore{keys: []JWK{oldEd, newEd, oldES, newES, expiredES}}
	options := Options{JWKS: &JWKSOptions{KeyPairConfig: KeyPairConfig{Alg: AlgEdDSA}, KeyPairConfigs: []KeyPairConfig{{Alg: AlgES256}}}}

	byID, err := resolveSigningKey(context.Background(), store, options, SigningKeyOverrides{SigningKeyID: oldEd.ID})
	if err != nil {
		t.Fatalf("resolve exact old kid: %v", err)
	}
	if byID.KeyID != oldEd.ID || byID.Algorithm != AlgEdDSA {
		t.Fatalf("exact kid resolution = %#v, want %q/%q", byID, oldEd.ID, AlgEdDSA)
	}
	byAlgorithm, err := resolveSigningKey(context.Background(), store, options, SigningKeyOverrides{SigningAlgorithm: AlgES256})
	if err != nil {
		t.Fatalf("resolve latest ES256 key: %v", err)
	}
	if byAlgorithm.KeyID != newES.ID || byAlgorithm.Algorithm != AlgES256 {
		t.Fatalf("algorithm resolution = %#v, want %q/%q", byAlgorithm, newES.ID, AlgES256)
	}
}

func TestResolveSigningKeyRejectsBadOverridesWithoutFallback(t *testing.T) {
	expired := time.Now().Add(-time.Second)
	expiredKey := signingTestKey(t, "expired", AlgEdDSA, time.Now())
	expiredKey.ExpiresAt = &expired
	store := &signingTestStore{keys: []JWK{signingTestKey(t, "ed", AlgEdDSA, time.Now()), signingTestKey(t, "es", AlgES256, time.Now()), expiredKey}}
	options := Options{JWKS: &JWKSOptions{KeyPairConfig: KeyPairConfig{Alg: AlgEdDSA}}}
	tests := []struct {
		name      string
		overrides SigningKeyOverrides
		wantError string
	}{
		{name: "unknown kid", overrides: SigningKeyOverrides{SigningKeyID: "missing"}, wantError: "not found"},
		{name: "expired kid", overrides: SigningKeyOverrides{SigningKeyID: "expired"}, wantError: "expired"},
		{name: "kid algorithm mismatch", overrides: SigningKeyOverrides{SigningKeyID: "ed", SigningAlgorithm: AlgES256}, wantError: "not requested algorithm"},
		{name: "unconfigured algorithm", overrides: SigningKeyOverrides{SigningAlgorithm: AlgPS256}, wantError: "no live key"},
		{name: "unsupported algorithm", overrides: SigningKeyOverrides{SigningAlgorithm: "HS256"}, wantError: "unsupported JWS algorithm"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := resolveSigningKey(context.Background(), store, options, test.overrides)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("resolveSigningKey() error = %v, want containing %q", err, test.wantError)
			}
		})
	}
	if len(store.created) != 0 {
		t.Fatalf("bad overrides lazily created keys: %d", len(store.created))
	}
}

func TestResolveSigningKeyLazilyCreatesOnlyConfiguredAlgorithm(t *testing.T) {
	store := &signingTestStore{}
	options := Options{JWKS: &JWKSOptions{
		KeyPairConfig:  KeyPairConfig{Alg: AlgEdDSA},
		KeyPairConfigs: []KeyPairConfig{{Alg: AlgES256}},
	}}
	key, err := resolveSigningKey(context.Background(), store, options, SigningKeyOverrides{SigningAlgorithm: AlgES256})
	if err != nil {
		t.Fatalf("resolve configured additional algorithm: %v", err)
	}
	if key.Algorithm != AlgES256 || key.KeyID == "" || len(store.created) != 1 {
		t.Fatalf("resolved key = %#v, created keys = %d", key, len(store.created))
	}
}

func TestResolveSigningKeyKeepsPrimaryAlgorithmAfterExpiry(t *testing.T) {
	expiredAt := time.Now().Add(-time.Minute)
	expiredPrimary := signingTestKey(t, "expired-ed", AlgEdDSA, time.Now().Add(-time.Hour))
	expiredPrimary.ExpiresAt = &expiredAt
	liveSecondary := signingTestKey(t, "live-es", AlgES256, time.Now())
	store := &signingTestStore{keys: []JWK{expiredPrimary, liveSecondary}}
	options := Options{JWKS: &JWKSOptions{
		KeyPairConfig:  KeyPairConfig{Alg: AlgEdDSA},
		KeyPairConfigs: []KeyPairConfig{{Alg: AlgES256}},
	}}

	resolved, err := resolveSigningKey(context.Background(), store, options, SigningKeyOverrides{})
	if err != nil {
		t.Fatalf("resolveSigningKey() error = %v", err)
	}
	if resolved.Algorithm != AlgEdDSA || resolved.KeyID == liveSecondary.ID {
		t.Fatalf("resolved key = %#v, want a newly rotated EdDSA primary, not live ES256 key %q", resolved, liveSecondary.ID)
	}
	if len(store.created) != 1 || store.created[0].Alg == nil || *store.created[0].Alg != AlgEdDSA {
		t.Fatalf("created keys = %#v, want exactly one EdDSA rotation", store.created)
	}
}

func TestResolveSigningKeyRequiresRemoteIdentityAndNeverFallsBackLocally(t *testing.T) {
	local := signingTestKey(t, "local", AlgEdDSA, time.Now())
	store := &signingTestStore{keys: []JWK{local}}
	options := Options{JWT: &JWTOptions{Sign: func(context.Context, Payload, SigningKeyOverrides) (string, error) {
		return "", nil
	}}}
	if _, err := resolveSigningKey(context.Background(), store, options, SigningKeyOverrides{SigningKeyID: "remote", SigningAlgorithm: AlgEdDSA}); err == nil || !strings.Contains(err.Error(), "requires JWKS.RemoteURL") {
		t.Fatalf("remote signer without remote URL error = %v", err)
	}
	options.JWKS = &JWKSOptions{RemoteURL: "https://keys.example", KeyPairConfig: KeyPairConfig{Alg: AlgEdDSA}}
	if _, err := resolveSigningKey(context.Background(), store, options, SigningKeyOverrides{SigningAlgorithm: AlgEdDSA}); err == nil || !strings.Contains(err.Error(), "requires a signing key id") {
		t.Fatalf("remote signer without kid error = %v", err)
	}
	key, err := resolveSigningKey(context.Background(), store, options, SigningKeyOverrides{SigningKeyID: "remote-kid"})
	if err != nil {
		t.Fatalf("remote identity resolution: %v", err)
	}
	if key.KeyID != "remote-kid" || key.Algorithm != AlgEdDSA || key.PrivateKeyJSON != "" {
		t.Fatalf("remote resolved identity = %#v", key)
	}
	if len(store.created) != 0 {
		t.Fatalf("remote resolution touched local key creation: %d", len(store.created))
	}
}

func TestSignJWTUsesRemoteSignerAndValidatesItsIdentity(t *testing.T) {
	local := signingTestKey(t, "local", AlgEdDSA, time.Now())
	remotePublic, remotePrivate, _, err := authcrypto.GenerateKeyPair(string(AlgEdDSA))
	if err != nil {
		t.Fatal(err)
	}
	store := &signingTestStore{keys: []JWK{local}}
	var called bool
	options := Options{
		JWKS: &JWKSOptions{RemoteURL: "https://keys.example", KeyPairConfig: KeyPairConfig{Alg: AlgEdDSA}},
		JWT: &JWTOptions{Sign: func(_ context.Context, payload Payload, overrides SigningKeyOverrides) (string, error) {
			called = true
			if overrides.SigningKeyID != "remote-kid" || overrides.SigningAlgorithm != AlgEdDSA {
				t.Fatalf("remote signer overrides = %#v", overrides)
			}
			if payload["exp"] == nil {
				t.Fatal("remote signer payload is missing default expiration")
			}
			return authcrypto.SignJWT(remotePrivate, string(AlgEdDSA), overrides.SigningKeyID, map[string]any(payload))
		}},
	}
	token, err := signJWT(context.Background(), store, options, Payload{"sub": "remote-user"}, SigningKeyOverrides{
		SigningKeyID:     "remote-kid",
		SigningAlgorithm: AlgEdDSA,
	})
	if err != nil {
		t.Fatalf("signJWT() remote error = %v", err)
	}
	if !called || len(store.created) != 0 {
		t.Fatalf("remote signer called = %v, local keys created = %d", called, len(store.created))
	}
	claims, err := authcrypto.VerifyJWT(token, []authcrypto.PublicKey{{
		Kid: "remote-kid", Alg: string(AlgEdDSA), PublicJWKJSON: remotePublic,
	}}, authcrypto.VerifyOptions{})
	if err != nil || claims["sub"] != "remote-user" {
		t.Fatalf("remote JWT claims = %#v, error = %v", claims, err)
	}

	options.JWT.Sign = func(context.Context, Payload, SigningKeyOverrides) (string, error) {
		return authcrypto.SignJWT(remotePrivate, string(AlgEdDSA), "wrong-kid", map[string]any{})
	}
	if _, err := signJWT(context.Background(), store, options, Payload{}, SigningKeyOverrides{
		SigningKeyID: "remote-kid", SigningAlgorithm: AlgEdDSA,
	}); err == nil || !strings.Contains(err.Error(), "mismatched protected alg/kid") {
		t.Fatalf("mismatched remote identity error = %v", err)
	}
}

func TestSessionJWTCanUseRemoteSignerWithoutPinnedKeyID(t *testing.T) {
	_, remotePrivate, _, err := authcrypto.GenerateKeyPair(string(AlgEdDSA))
	if err != nil {
		t.Fatal(err)
	}
	options := Options{
		JWKS: &JWKSOptions{
			RemoteURL:     "https://keys.example.test/jwks",
			KeyPairConfig: KeyPairConfig{Alg: AlgEdDSA},
		},
		JWT: &JWTOptions{Sign: func(_ context.Context, payload Payload, overrides SigningKeyOverrides) (string, error) {
			if overrides.SigningKeyID != "" || overrides.SigningAlgorithm != AlgEdDSA {
				return "", fmt.Errorf("unexpected remote signer identity overrides: %#v", overrides)
			}
			return authcrypto.SignJWT(remotePrivate, string(AlgEdDSA), "remote-session-key", map[string]any(payload))
		}},
	}
	token, err := sessionJWT(context.Background(), nil, options, "https://auth.example.test", authtypes.Session{ID: "s"}, authtypes.User{ID: "u"})
	if err != nil {
		t.Fatalf("sessionJWT(remote) error = %v", err)
	}
	parsed, err := jwt.ParseSigned(token, signingAlgorithms)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Headers) != 1 || parsed.Headers[0].KeyID != "remote-session-key" {
		t.Fatalf("remote session JWT protected headers = %#v", parsed.Headers)
	}
}

func signingTestKey(t *testing.T, id string, algorithm JWSAlgorithm, createdAt time.Time) JWK {
	t.Helper()
	publicJSON, privateJSON, _, err := authcrypto.GenerateKeyPair(string(algorithm))
	if err != nil {
		t.Fatal(err)
	}
	return JWK{
		ID: id, PublicKeyJSON: publicJSON, PrivateKeyJSON: privateJSON,
		CreatedAt: createdAt, Alg: algorithmPtr(algorithm),
	}
}

type signingTestStore struct {
	keys    []JWK
	created []JWK
}

func (s *signingTestStore) getAll(context.Context) ([]JWK, error) {
	keys := slices.Clone(s.keys)
	slices.SortFunc(keys, compareJWKNewestFirst)
	return keys, nil
}

func (s *signingTestStore) getPublicAll(ctx context.Context) ([]JWK, error) {
	return s.getAll(ctx)
}

func (s *signingTestStore) getByID(_ context.Context, id string) (*JWK, error) {
	index := slices.IndexFunc(s.keys, func(key JWK) bool { return key.ID == id })
	if index < 0 {
		return nil, nil
	}
	key := s.keys[index]
	return &key, nil
}

func (s *signingTestStore) getLatest(ctx context.Context) (*JWK, error) {
	keys, err := s.getAll(ctx)
	if err != nil {
		return nil, err
	}
	for i := range keys {
		if !expiredJWK(&keys[i], time.Now()) {
			return &keys[i], nil
		}
	}
	return nil, nil
}

func (s *signingTestStore) getLatestByAlg(ctx context.Context, algorithm JWSAlgorithm) (*JWK, error) {
	keys, err := s.getAll(ctx)
	if err != nil {
		return nil, err
	}
	for i := range keys {
		if keys[i].Alg != nil && *keys[i].Alg == algorithm && !expiredJWK(&keys[i], time.Now()) {
			return &keys[i], nil
		}
	}
	return nil, nil
}

func (s *signingTestStore) create(_ context.Context, key JWK) (JWK, error) {
	s.keys = append(s.keys, key)
	s.created = append(s.created, key)
	return key, nil
}

func (s *signingTestStore) createJWK(ctx context.Context, key JWK) (JWK, error) {
	return s.create(ctx, key)
}

func TestWithDefaultJWTClaimsRejectsInvalidExpirationConfiguration(t *testing.T) {
	_, err := withDefaultJWTClaims(Options{JWT: &JWTOptions{ExpirationTime: &ExpirationTime{}}}, Payload{})
	if err == nil {
		t.Fatal("empty expiration config succeeded")
	}
	if !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("expiration config error = %v, want exactly-one validation", err)
	}
}

func TestSessionJWTPayloadIsJSONSerializable(t *testing.T) {
	key := signingTestKey(t, "json-kid", AlgEdDSA, time.Now())
	options := Options{JWT: &JWTOptions{DefinePayload: func(SessionData) (Payload, error) {
		return Payload{"structured": map[string]any{"ok": true}}, nil
	}}}
	token, err := sessionJWT(context.Background(), &signingTestStore{keys: []JWK{key}}, options, "https://auth.example", authtypes.Session{ID: "s"}, authtypes.User{ID: "u"})
	if err != nil {
		t.Fatalf("sessionJWT() error = %v", err)
	}
	parsed, err := jwt.ParseSigned(token, signingAlgorithms)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := parsed.UnsafeClaimsWithoutVerification(&payload); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(payload)
	if err != nil || !strings.Contains(string(encoded), `"structured":{"ok":true}`) {
		t.Fatalf("payload JSON = %s, error = %v", encoded, err)
	}
}
