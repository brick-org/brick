package jwt

import (
	"context"
	"fmt"
	"time"

	authtypes "github.com/brick-org/brick/auth/src/types"
)

// JWSAlgorithm identifies an asymmetric JWS signing algorithm.
// Upstream vendor/better-auth/packages/better-auth/src/plugins/jwt/types.ts:225-254.
type JWSAlgorithm string

const (
	AlgEdDSA JWSAlgorithm = "EdDSA"
	AlgES256 JWSAlgorithm = "ES256"
	AlgES512 JWSAlgorithm = "ES512"
	AlgPS256 JWSAlgorithm = "PS256"
	AlgRS256 JWSAlgorithm = "RS256"
)

// SupportedAlgorithms returns the algorithms accepted by the JWT plugin.
func SupportedAlgorithms() []JWSAlgorithm {
	return []JWSAlgorithm{AlgEdDSA, AlgES256, AlgES512, AlgPS256, AlgRS256}
}

// Curve identifies a JWK elliptic-curve value.
type Curve string

const (
	CurveEd25519 Curve = "Ed25519"
	CurveP256    Curve = "P-256"
	CurveP521    Curve = "P-521"
)

// KeyPairConfig selects parameters for a locally managed signing key.
// Upstream vendor/better-auth/packages/better-auth/src/plugins/jwt/types.ts:232-252.
type KeyPairConfig struct {
	// Alg defaults to EdDSA when empty.
	Alg JWSAlgorithm
	// Crv is supported only for EdDSA; its default is Ed25519.
	Crv Curve
	// ModulusLength applies only to PS256 and RS256; zero defaults to 2048.
	// The current key generator supports exactly 2048 bits.
	ModulusLength int
}

// DefaultKeyPairConfig returns the upstream default EdDSA/Ed25519 config.
func DefaultKeyPairConfig() KeyPairConfig {
	return KeyPairConfig{Alg: AlgEdDSA, Crv: CurveEd25519}
}

// ResolveKeyPairConfig fills defaults and rejects algorithm-incompatible parameters.
func ResolveKeyPairConfig(config KeyPairConfig) (KeyPairConfig, error) {
	if config.Alg == "" {
		config.Alg = AlgEdDSA
	}
	switch config.Alg {
	case AlgEdDSA:
		if config.Crv == "" {
			config.Crv = CurveEd25519
		}
		if config.Crv != CurveEd25519 || config.ModulusLength != 0 {
			return KeyPairConfig{}, fmt.Errorf("jwt: invalid key-pair parameters for %q", config.Alg)
		}
	case AlgES256, AlgES512:
		if config.Crv != "" || config.ModulusLength != 0 {
			return KeyPairConfig{}, fmt.Errorf("jwt: invalid key-pair parameters for %q", config.Alg)
		}
	case AlgPS256, AlgRS256:
		if config.Crv != "" {
			return KeyPairConfig{}, fmt.Errorf("jwt: invalid curve %q for %q", config.Crv, config.Alg)
		}
		if config.ModulusLength == 0 {
			config.ModulusLength = 2048
		}
		if config.ModulusLength != 2048 {
			return KeyPairConfig{}, fmt.Errorf("jwt: RSA modulus length must be 2048 bits with the current key generator")
		}
	default:
		return KeyPairConfig{}, fmt.Errorf("jwt: unsupported JWS algorithm %q", config.Alg)
	}
	return config, nil
}

// Options configures the JWT plugin. Schema override and custom adapter
// options are deliberately deferred until their Go integration contracts
// have parity tests; they are not accepted as no-ops.
// Upstream vendor/better-auth/packages/better-auth/src/plugins/jwt/types.ts:6-223.
type Options struct {
	// JWKS configures local keys and the JWKS endpoint. Nil uses plugin defaults.
	JWKS *JWKSOptions
	// JWT configures claims and optional remote signing. Nil uses plugin defaults.
	JWT *JWTOptions
	// DisableSettingJWTHeader disables the session JWT response-header hook.
	DisableSettingJWTHeader bool
	// SessionCookieCache enables JWT session-cookie-cache signing; default false.
	// It requires the core session cookie-cache strategy to be "jwt".
	SessionCookieCache bool
}

// JWKSOptions configures local JWKS management and key publication.
// Upstream vendor/better-auth/packages/better-auth/src/plugins/jwt/types.ts:16-89.
type JWKSOptions struct {
	// RemoteURL disables the local JWKS endpoint and supplies the remote JWKS URL.
	RemoteURL string
	// KeyPairConfig configures the primary local key; its zero value defaults to EdDSA/Ed25519.
	KeyPairConfig KeyPairConfig
	// KeyPairConfigs declares additional algorithms whose keys may be created lazily.
	KeyPairConfigs []KeyPairConfig
	// DisablePrivateKeyEncryption opts out of encryption at rest; default behavior encrypts keys.
	DisablePrivateKeyEncryption bool
	// RotationInterval disables rotation when zero; positive values are durations.
	RotationInterval time.Duration
	// GracePeriod defaults to 30 days when zero.
	GracePeriod time.Duration
	// JWKSPath replaces /jwks; empty uses the default. A configured path must
	// start with / and exclude ..
	JWKSPath string
}

// JWTOptions configures claims and optional remote signing.
// Upstream vendor/better-auth/packages/better-auth/src/plugins/jwt/types.ts:92-174.
type JWTOptions struct {
	Issuer   string
	Audience []string
	// ExpirationTime nil defaults to 15 minutes. Go durations are used for
	// relative lifetimes; the upstream human-readable time-span string grammar is deferred.
	ExpirationTime *ExpirationTime
	DefinePayload  DefinePayloadFunc
	GetSubject     GetSubjectFunc
	// Sign is a server-side remote signer. It requires JWKS.RemoteURL and is
	// not an HTTP signing endpoint; it owns the protected alg/kid headers.
	Sign RemoteSignFunc
}

// ExpirationTime represents an absolute expiration or a relative lifetime.
// Exactly one of At, UnixSeconds, and After should be supplied when non-nil.
type ExpirationTime struct {
	At          *time.Time
	UnixSeconds *int64
	After       time.Duration
}

// SessionData is passed to JWT payload and subject customizers.
type SessionData struct {
	User    authtypes.User
	Session authtypes.Session
}

// Payload is a JWT payload with standard and application-specific claims.
type Payload map[string]any

// DefinePayloadFunc may return nil to add no custom claims.
type DefinePayloadFunc func(SessionData) (Payload, error)

// GetSubjectFunc returns the JWT subject for a session.
type GetSubjectFunc func(SessionData) (string, error)

// SigningKeyOverrides selects a key or algorithm for one signing operation.
// Empty fields leave selection to the plugin; Typ, when set, is protected.
type SigningKeyOverrides struct {
	SigningKeyID     string
	SigningAlgorithm JWSAlgorithm
	Typ              string
}

// RemoteSignFunc signs a payload outside the local JWK store.
// Implementations must set alg and kid in the protected header and honor Typ
// when provided. The caller validates that a remote URL is configured.
type RemoteSignFunc func(context.Context, Payload, SigningKeyOverrides) (string, error)

// JWK is a persisted JWKS row. PrivateKeyJSON is plaintext only after loading
// and decryption; adapters must encrypt it at rest unless explicitly disabled.
// Nil Alg and Crv preserve legacy rows whose values inherit key configuration.
// Upstream vendor/better-auth/packages/better-auth/src/plugins/jwt/types.ts:256-264.
type JWK struct {
	ID             string        `json:"id"`
	PublicKeyJSON  string        `json:"publicKey"`
	PrivateKeyJSON string        `json:"-"`
	CreatedAt      time.Time     `json:"createdAt"`
	ExpiresAt      *time.Time    `json:"expiresAt,omitempty"`
	Alg            *JWSAlgorithm `json:"alg"`
	Crv            *Curve        `json:"crv"`
}

// ResolvedSigningKey is the selected key material and JOSE identity for signing.
// A remote signer may return only Algorithm and KeyID; never expose this value over HTTP.
// Upstream vendor/better-auth/packages/better-auth/src/plugins/jwt/types.ts:266-277.
type ResolvedSigningKey struct {
	Algorithm      JWSAlgorithm
	KeyID          string
	PrivateKeyJSON string `json:"-"`
}

// JWTClaims contains registered claims and separately collected application claims.
type JWTClaims struct {
	Issuer    string   `json:"iss,omitempty"`
	Subject   string   `json:"sub,omitempty"`
	Audience  []string `json:"aud,omitempty"`
	ExpiresAt *int64   `json:"exp,omitempty"`
	NotBefore *int64   `json:"nbf,omitempty"`
	IssuedAt  *int64   `json:"iat,omitempty"`
	JWTID     string   `json:"jti,omitempty"`
	// CustomClaims carries non-registered claims; conversion to/from Payload is explicit.
	CustomClaims Payload `json:"-"`
}

// VerifyOptions controls signature and registered-claim validation.
type VerifyOptions struct {
	Issuer            string
	Audience          []string
	AllowedAlgorithms []JWSAlgorithm
	Leeway            time.Duration
	RequireExpiration bool
}

// Signer provides server-side signing and signing-key resolution without an HTTP signing surface.
type Signer interface {
	// ResolveSigningKey returns the exact key identity selected by the overrides.
	ResolveSigningKey(context.Context, SigningKeyOverrides) (ResolvedSigningKey, error)
	// SignJWT signs server-side; reuse the resolved key's ID and algorithm in overrides to pin it.
	SignJWT(context.Context, Payload, SigningKeyOverrides) (string, error)
}

// Verifier provides server-side JWT verification.
type Verifier interface {
	// VerifyJWT verifies a signed JWT against the configured verification policy.
	VerifyJWT(context.Context, string, VerifyOptions) (JWTClaims, error)
	// VerifyAccessToken accepts only the strict OAuth access-token profile.
	VerifyAccessToken(context.Context, string, VerifyOptions) (JWTClaims, error)
}
