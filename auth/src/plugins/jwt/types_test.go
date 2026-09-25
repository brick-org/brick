package jwt

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestSupportedAlgorithms(t *testing.T) {
	want := []JWSAlgorithm{AlgEdDSA, AlgES256, AlgES512, AlgPS256, AlgRS256}
	if got := SupportedAlgorithms(); !reflect.DeepEqual(got, want) {
		t.Fatalf("SupportedAlgorithms() = %v, want %v", got, want)
	}
	got := SupportedAlgorithms()
	got[0] = "none"
	if reflect.DeepEqual(SupportedAlgorithms(), got) {
		t.Fatal("SupportedAlgorithms() returned shared mutable storage")
	}
}

func TestResolveKeyPairConfigDefaultsAndValidation(t *testing.T) {
	if got, want := DefaultKeyPairConfig(), (KeyPairConfig{Alg: AlgEdDSA, Crv: CurveEd25519}); got != want {
		t.Fatalf("DefaultKeyPairConfig() = %#v, want %#v", got, want)
	}

	got, err := ResolveKeyPairConfig(KeyPairConfig{})
	if err != nil {
		t.Fatalf("ResolveKeyPairConfig(zero) error = %v", err)
	}
	if want := DefaultKeyPairConfig(); got != want {
		t.Fatalf("ResolveKeyPairConfig(zero) = %#v, want %#v", got, want)
	}

	got, err = ResolveKeyPairConfig(KeyPairConfig{Alg: AlgRS256})
	if err != nil {
		t.Fatalf("ResolveKeyPairConfig(RS256) error = %v", err)
	}
	if got.ModulusLength != 2048 {
		t.Fatalf("RSA modulus default = %d, want 2048", got.ModulusLength)
	}

	for _, config := range []KeyPairConfig{
		{Alg: "none"},
		{Alg: AlgEdDSA, Crv: CurveP256},
		{Alg: AlgES256, ModulusLength: 2048},
		{Alg: AlgPS256, ModulusLength: 1024},
		{Alg: AlgRS256, ModulusLength: 4096},
	} {
		if _, err := ResolveKeyPairConfig(config); err == nil {
			t.Errorf("ResolveKeyPairConfig(%#v) succeeded, want validation error", config)
		}
	}
}

func TestSessionCookieCacheOptionContract(t *testing.T) {
	if (Options{}).SessionCookieCache {
		t.Fatal("SessionCookieCache zero value = true, want upstream default false")
	}
	if got := (Options{SessionCookieCache: true}).SessionCookieCache; !got {
		t.Fatal("SessionCookieCache did not preserve explicit true")
	}
}

func TestJWTTypeContracts(t *testing.T) {
	var signer Signer = contractSigner{}
	var verifier Verifier = contractVerifier{}
	var _ DefinePayloadFunc = func(SessionData) (Payload, error) { return nil, nil }
	var _ GetSubjectFunc = func(SessionData) (string, error) { return "subject", nil }
	var _ RemoteSignFunc = func(context.Context, Payload, SigningKeyOverrides) (string, error) {
		return "compact-jws", nil
	}
	var _ = Options{
		JWKS: &JWKSOptions{
			KeyPairConfig:  KeyPairConfig{Alg: AlgES256},
			KeyPairConfigs: []KeyPairConfig{{Alg: AlgRS256}},
			GracePeriod:    30 * 24 * time.Hour,
		},
		JWT: &JWTOptions{
			Issuer:   "issuer",
			Audience: []string{"resource"},
			ExpirationTime: &ExpirationTime{
				After: 15 * time.Minute,
			},
			DefinePayload: func(data SessionData) (Payload, error) {
				return Payload{"user": data.User.ID}, nil
			},
			GetSubject: func(data SessionData) (string, error) { return data.User.ID, nil },
		},
		DisableSettingJWTHeader: true,
	}
	var _ = JWK{
		ID: "key-id", PublicKeyJSON: "{}", PrivateKeyJSON: "{}",
		CreatedAt: time.Unix(1, 0), Alg: algorithmPtr(AlgEdDSA), Crv: curvePtr(CurveEd25519),
	}
	var _ = ResolvedSigningKey{Algorithm: AlgES256, KeyID: "key-id", PrivateKeyJSON: "{}"}
	var _ = SigningKeyOverrides{SigningKeyID: "key-id", SigningAlgorithm: AlgES256, Typ: "at+jwt"}
	var _ = JWTClaims{Issuer: "issuer", Subject: "subject", Audience: []string{"resource"}}
	var _ = VerifyOptions{Issuer: "issuer", RequireExpiration: true}
	_ = signer
	_ = verifier
}

type contractSigner struct{}

func (contractSigner) ResolveSigningKey(context.Context, SigningKeyOverrides) (ResolvedSigningKey, error) {
	return ResolvedSigningKey{}, nil
}

func (contractSigner) SignJWT(context.Context, Payload, SigningKeyOverrides) (string, error) {
	return "", nil
}

type contractVerifier struct{}

func (contractVerifier) VerifyJWT(context.Context, string, VerifyOptions) (JWTClaims, error) {
	return JWTClaims{}, nil
}

func (contractVerifier) VerifyAccessToken(context.Context, string, VerifyOptions) (JWTClaims, error) {
	return JWTClaims{}, nil
}

func algorithmPtr(value JWSAlgorithm) *JWSAlgorithm { return &value }

func curvePtr(value Curve) *Curve { return &value }
