package jwt

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"slices"
	"time"

	"github.com/brick-org/brick/auth/src/types"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

var signingAlgorithms = []jose.SignatureAlgorithm{
	jose.EdDSA,
	jose.ES256,
	jose.ES512,
	jose.PS256,
	jose.RS256,
}

var reservedSessionClaims = map[string]struct{}{
	"iss": {}, "sub": {}, "aud": {}, "exp": {}, "nbf": {}, "iat": {}, "jti": {},
}

// Upstream vendor/better-auth/packages/better-auth/src/plugins/jwt/sign.ts:93-253.
func resolveSigningKey(ctx context.Context, store jwksStore, options Options, overrides SigningKeyOverrides) (ResolvedSigningKey, error) {
	if ctx == nil {
		return ResolvedSigningKey{}, fmt.Errorf("jwt: signing context is required")
	}
	if err := ctx.Err(); err != nil {
		return ResolvedSigningKey{}, err
	}

	if options.JWT != nil && options.JWT.Sign != nil {
		if options.JWKS == nil || options.JWKS.RemoteURL == "" {
			return ResolvedSigningKey{}, fmt.Errorf("jwt: JWT.Sign requires JWKS.RemoteURL")
		}
		if overrides.SigningKeyID == "" {
			return ResolvedSigningKey{}, fmt.Errorf("jwt: remote signing requires a signing key id override")
		}
		algorithm := overrides.SigningAlgorithm
		if algorithm == "" {
			if options.JWKS.KeyPairConfig.Alg == "" {
				return ResolvedSigningKey{}, fmt.Errorf("jwt: remote signing requires a signing algorithm override or configured primary algorithm")
			}
			algorithm = options.JWKS.KeyPairConfig.Alg
		}
		if !isSupportedAlgorithm(algorithm) {
			return ResolvedSigningKey{}, fmt.Errorf("jwt: unsupported JWS algorithm %q", algorithm)
		}
		return ResolvedSigningKey{Algorithm: algorithm, KeyID: overrides.SigningKeyID}, nil
	}
	if store == nil {
		return ResolvedSigningKey{}, fmt.Errorf("jwt: local signing requires a JWKS store")
	}

	primaryConfig := KeyPairConfig{}
	if options.JWKS != nil {
		primaryConfig = options.JWKS.KeyPairConfig
	}
	primaryConfig, err := ResolveKeyPairConfig(primaryConfig)
	if err != nil {
		return ResolvedSigningKey{}, fmt.Errorf("jwt: invalid primary key-pair config: %w", err)
	}
	primaryAlg := primaryConfig.Alg

	var key *JWK
	switch {
	case overrides.SigningKeyID != "":
		key, err = store.getByID(ctx, overrides.SigningKeyID)
		if err != nil {
			return ResolvedSigningKey{}, fmt.Errorf("jwt: resolve signing key %q: %w", overrides.SigningKeyID, err)
		}
		if key == nil {
			return ResolvedSigningKey{}, fmt.Errorf("jwt: signing key id %q not found; provision the key before referencing it", overrides.SigningKeyID)
		}
		if expiredJWK(key, time.Now()) {
			return ResolvedSigningKey{}, fmt.Errorf("jwt: signing key id %q is expired", overrides.SigningKeyID)
		}
		algorithm := effectiveJWKAlgorithm(key, primaryAlg)
		if overrides.SigningAlgorithm != "" && algorithm != overrides.SigningAlgorithm {
			return ResolvedSigningKey{}, fmt.Errorf("jwt: signing key id %q uses algorithm %q, not requested algorithm %q", key.ID, algorithm, overrides.SigningAlgorithm)
		}
	case overrides.SigningAlgorithm != "":
		if !isSupportedAlgorithm(overrides.SigningAlgorithm) {
			return ResolvedSigningKey{}, fmt.Errorf("jwt: unsupported JWS algorithm %q", overrides.SigningAlgorithm)
		}
		key, err = latestKeyByAlgorithm(ctx, store, overrides.SigningAlgorithm, primaryAlg)
		if err != nil {
			return ResolvedSigningKey{}, err
		}
		if key == nil {
			config, ok, configErr := configuredKeyPair(options, overrides.SigningAlgorithm, primaryConfig)
			if configErr != nil {
				return ResolvedSigningKey{}, configErr
			}
			if !ok {
				return ResolvedSigningKey{}, fmt.Errorf("jwt: no live key with algorithm %q; only primary algorithm %q and configured additional algorithms may be created lazily", overrides.SigningAlgorithm, primaryAlg)
			}
			created, createErr := createJWK(ctx, store, config, rotationInterval(options))
			if createErr != nil {
				return ResolvedSigningKey{}, fmt.Errorf("jwt: create signing key for algorithm %q: %w", overrides.SigningAlgorithm, createErr)
			}
			key = &created
		}
	default:
		key, err = latestKeyByAlgorithm(ctx, store, primaryAlg, primaryAlg)
		if err != nil {
			return ResolvedSigningKey{}, err
		}
		if key == nil || expiredJWK(key, time.Now()) {
			created, createErr := createJWK(ctx, store, primaryConfig, rotationInterval(options))
			if createErr != nil {
				return ResolvedSigningKey{}, fmt.Errorf("jwt: create primary signing key: %w", createErr)
			}
			key = &created
		}
	}

	if key == nil {
		return ResolvedSigningKey{}, fmt.Errorf("jwt: no signing key resolved")
	}
	if expiredJWK(key, time.Now()) {
		return ResolvedSigningKey{}, fmt.Errorf("jwt: signing key id %q is expired", key.ID)
	}
	algorithm := effectiveJWKAlgorithm(key, primaryAlg)
	if !isSupportedAlgorithm(algorithm) {
		return ResolvedSigningKey{}, fmt.Errorf("jwt: signing key id %q has unsupported algorithm %q", key.ID, algorithm)
	}
	if overrides.SigningAlgorithm != "" && algorithm != overrides.SigningAlgorithm {
		return ResolvedSigningKey{}, fmt.Errorf("jwt: resolved signing key id %q uses algorithm %q, not requested algorithm %q", key.ID, algorithm, overrides.SigningAlgorithm)
	}
	if key.ID == "" {
		return ResolvedSigningKey{}, fmt.Errorf("jwt: resolved signing key has an empty id")
	}
	if key.PrivateKeyJSON == "" {
		return ResolvedSigningKey{}, fmt.Errorf("jwt: signing key id %q has no private key material", key.ID)
	}
	return ResolvedSigningKey{Algorithm: algorithm, KeyID: key.ID, PrivateKeyJSON: key.PrivateKeyJSON}, nil
}

// Upstream vendor/better-auth/packages/better-auth/src/plugins/jwt/sign.ts:255-341.
func signJWT(ctx context.Context, store jwksStore, options Options, payload Payload, overrides SigningKeyOverrides) (string, error) {
	claims, err := withDefaultJWTClaims(options, payload)
	if err != nil {
		return "", err
	}
	if options.JWT != nil && options.JWT.Sign != nil {
		if options.JWKS == nil || options.JWKS.RemoteURL == "" {
			return "", fmt.Errorf("jwt: JWT.Sign requires JWKS.RemoteURL")
		}
		remoteOverrides := overrides
		if remoteOverrides.SigningAlgorithm == "" {
			remoteOverrides.SigningAlgorithm = options.JWKS.KeyPairConfig.Alg
		}
		if !isSupportedAlgorithm(remoteOverrides.SigningAlgorithm) {
			return "", fmt.Errorf("jwt: remote signing requires a supported configured or overridden algorithm")
		}
		token, err := options.JWT.Sign(ctx, claims, remoteOverrides)
		if err != nil {
			return "", fmt.Errorf("jwt: remote signing: %w", err)
		}
		if err := validateRemoteSignedJWT(token, ResolvedSigningKey{
			Algorithm: remoteOverrides.SigningAlgorithm,
			KeyID:     remoteOverrides.SigningKeyID,
		}, overrides.Typ); err != nil {
			return "", err
		}
		return token, nil
	}
	resolved, err := resolveSigningKey(ctx, store, options, overrides)
	if err != nil {
		return "", err
	}
	return signWithResolvedKey(resolved, claims, overrides.Typ)
}

// Upstream vendor/better-auth/packages/better-auth/src/plugins/jwt/sign.ts:343-365.
func sessionJWT(ctx context.Context, store jwksStore, options Options, baseURL string, session types.Session, user types.User) (string, error) {
	var custom Payload
	if options.JWT != nil && options.JWT.DefinePayload != nil {
		var err error
		custom, err = options.JWT.DefinePayload(SessionData{Session: session, User: user})
		if err != nil {
			return "", fmt.Errorf("jwt: define session payload: %w", err)
		}
	} else {
		encodedUser, err := json.Marshal(user)
		if err != nil {
			return "", fmt.Errorf("jwt: encode default session payload: %w", err)
		}
		if err := json.Unmarshal(encodedUser, &custom); err != nil {
			return "", fmt.Errorf("jwt: decode default session payload: %w", err)
		}
	}

	claims := make(Payload, len(custom)+6)
	for name, value := range custom {
		if _, reserved := reservedSessionClaims[name]; !reserved {
			claims[name] = value
		}
	}
	data := SessionData{Session: session, User: user}
	subject := user.ID
	if options.JWT != nil && options.JWT.GetSubject != nil {
		var err error
		subject, err = options.JWT.GetSubject(data)
		if err != nil {
			return "", fmt.Errorf("jwt: get session subject: %w", err)
		}
	}
	if subject == "" {
		return "", fmt.Errorf("jwt: session JWT subject must not be empty")
	}

	now := time.Now().Unix()
	expiration := ExpirationTime{After: 15 * time.Minute}
	if options.JWT != nil && options.JWT.ExpirationTime != nil {
		expiration = *options.JWT.ExpirationTime
	}
	expiresAt, err := toExpJWT(expiration, now)
	if err != nil {
		return "", err
	}
	issuer := baseURL
	var audience []string
	if options.JWT != nil {
		if options.JWT.Issuer != "" {
			issuer = options.JWT.Issuer
		}
		if len(options.JWT.Audience) > 0 {
			audience = slices.Clone(options.JWT.Audience)
		}
	}
	if len(audience) == 0 && baseURL != "" {
		audience = []string{baseURL}
	}
	if issuer == "" || len(audience) == 0 {
		return "", fmt.Errorf("jwt: session JWT requires an issuer and audience or a request base URL")
	}

	claims["iat"] = now
	claims["exp"] = expiresAt
	claims["sub"] = subject
	claims["iss"] = issuer
	claims["aud"] = audience
	return signJWT(ctx, store, options, claims, SigningKeyOverrides{})
}

func withDefaultJWTClaims(options Options, payload Payload) (Payload, error) {
	claims := maps.Clone(payload)
	if claims == nil {
		claims = Payload{}
	}
	issuedAt := time.Now().Unix()
	if rawIssuedAt, ok := claims["iat"]; ok {
		parsed, valid := jwtNumericDate(rawIssuedAt)
		if !valid {
			return nil, fmt.Errorf("jwt: iat claim must be an integer Unix timestamp")
		}
		issuedAt = parsed
	}
	if _, hasExpiration := claims["exp"]; !hasExpiration {
		expiration := ExpirationTime{After: 15 * time.Minute}
		if options.JWT != nil && options.JWT.ExpirationTime != nil {
			expiration = *options.JWT.ExpirationTime
		}
		expiresAt, err := toExpJWT(expiration, issuedAt)
		if err != nil {
			return nil, err
		}
		claims["exp"] = expiresAt
	}
	if _, exists := claims["iss"]; !exists && options.JWT != nil && options.JWT.Issuer != "" {
		claims["iss"] = options.JWT.Issuer
	}
	if _, exists := claims["aud"]; !exists && options.JWT != nil && len(options.JWT.Audience) > 0 {
		claims["aud"] = slices.Clone(options.JWT.Audience)
	}
	return claims, nil
}

func latestKeyByAlgorithm(ctx context.Context, store jwksStore, algorithm, primary JWSAlgorithm) (*JWK, error) {
	key, err := store.getLatestByAlg(ctx, algorithm)
	if err != nil || key != nil {
		return key, err
	}
	if algorithm != primary {
		return nil, nil
	}
	keys, err := store.getPublicAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("jwt: list keys for legacy algorithm %q: %w", algorithm, err)
	}
	slices.SortFunc(keys, compareJWKNewestFirst)
	now := time.Now()
	for i := range keys {
		if keys[i].Alg == nil && !expiredJWK(&keys[i], now) {
			return store.getByID(ctx, keys[i].ID)
		}
	}
	return nil, nil
}

func configuredKeyPair(options Options, algorithm JWSAlgorithm, primary KeyPairConfig) (KeyPairConfig, bool, error) {
	if primary.Alg == algorithm {
		return primary, true, nil
	}
	if options.JWKS == nil {
		return KeyPairConfig{}, false, nil
	}
	for _, candidate := range options.JWKS.KeyPairConfigs {
		resolved, err := ResolveKeyPairConfig(candidate)
		if err != nil {
			return KeyPairConfig{}, false, fmt.Errorf("jwt: invalid additional key-pair config: %w", err)
		}
		if resolved.Alg == algorithm {
			return resolved, true, nil
		}
	}
	return KeyPairConfig{}, false, nil
}

func rotationInterval(options Options) time.Duration {
	if options.JWKS == nil {
		return 0
	}
	return options.JWKS.RotationInterval
}

func effectiveJWKAlgorithm(key *JWK, fallback JWSAlgorithm) JWSAlgorithm {
	if key.Alg != nil && *key.Alg != "" {
		return *key.Alg
	}
	return fallback
}

func expiredJWK(key *JWK, now time.Time) bool {
	return key != nil && key.ExpiresAt != nil && !key.ExpiresAt.After(now)
}

func isSupportedAlgorithm(algorithm JWSAlgorithm) bool {
	return slices.Contains(SupportedAlgorithms(), algorithm)
}

func signWithResolvedKey(key ResolvedSigningKey, claims Payload, typ string) (string, error) {
	if !isSupportedAlgorithm(key.Algorithm) {
		return "", fmt.Errorf("jwt: unsupported JWS algorithm %q", key.Algorithm)
	}
	if key.KeyID == "" {
		return "", fmt.Errorf("jwt: signing key id is required")
	}
	if key.PrivateKeyJSON == "" {
		return "", fmt.Errorf("jwt: signing key %q has no private key material", key.KeyID)
	}
	var privateKey jose.JSONWebKey
	if err := privateKey.UnmarshalJSON([]byte(key.PrivateKeyJSON)); err != nil {
		return "", fmt.Errorf("jwt: parse private JWK for key %q: %w", key.KeyID, err)
	}
	privateKey.KeyID = key.KeyID
	privateKey.Algorithm = string(key.Algorithm)
	options := &jose.SignerOptions{}
	if typ != "" {
		options = options.WithType(jose.ContentType(typ))
	}
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(key.Algorithm),
		Key:       privateKey,
	}, options)
	if err != nil {
		return "", fmt.Errorf("jwt: create signer: %w", err)
	}
	token, err := jwt.Signed(signer).Claims(map[string]any(claims)).Serialize()
	if err != nil {
		return "", fmt.Errorf("jwt: sign token: %w", err)
	}
	return token, nil
}

func validateRemoteSignedJWT(token string, key ResolvedSigningKey, typ string) error {
	parsed, err := jwt.ParseSigned(token, signingAlgorithms)
	if err != nil {
		return fmt.Errorf("jwt: remote signer returned an invalid compact JWS: %w", err)
	}
	if len(parsed.Headers) != 1 {
		return fmt.Errorf("jwt: remote signer must return a single-signature compact JWS")
	}
	header := parsed.Headers[0]
	if !slices.Contains(signingAlgorithms, jose.SignatureAlgorithm(header.Algorithm)) ||
		(key.Algorithm != "" && header.Algorithm != string(key.Algorithm)) ||
		(key.KeyID != "" && header.KeyID != key.KeyID) || header.KeyID == "" {
		return fmt.Errorf("jwt: remote signer returned mismatched protected alg/kid headers")
	}
	if typ != "" {
		got, ok := header.ExtraHeaders[jose.HeaderKey("typ")].(string)
		if !ok || got != typ {
			return fmt.Errorf("jwt: remote signer did not honor protected typ %q", typ)
		}
	}
	return nil
}

func jwtNumericDate(value any) (int64, bool) {
	switch number := value.(type) {
	case int:
		return int64(number), true
	case int32:
		return int64(number), true
	case int64:
		return number, true
	case uint:
		return int64(number), uint64(number) <= uint64(1<<63-1)
	case uint32:
		return int64(number), true
	case uint64:
		return int64(number), number <= uint64(1<<63-1)
	case float64:
		if math.IsNaN(number) || math.IsInf(number, 0) || math.Trunc(number) != number || number < -0x1p63 || number >= 0x1p63 {
			return 0, false
		}
		return int64(number), true
	case json.Number:
		parsed, err := number.Int64()
		return parsed, err == nil
	default:
		return 0, false
	}
}
