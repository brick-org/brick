package jwt

import (
	"context"
	"fmt"
	"slices"
	"time"

	cryptoutil "github.com/brick-org/brick/auth/src/crypto"
	"github.com/google/uuid"
)

// Upstream vendor/better-auth/packages/better-auth/src/plugins/jwt/utils.ts:29-46.
func generateExportedKeyPair(config KeyPairConfig) (publicJSON, privateJSON string, alg JWSAlgorithm, curve *Curve, err error) {
	resolved, err := ResolveKeyPairConfig(config)
	if err != nil {
		return "", "", "", nil, fmt.Errorf("jwt: resolve key-pair config: %w", err)
	}
	if !slices.Contains(SupportedAlgorithms(), resolved.Alg) {
		return "", "", "", nil, fmt.Errorf("jwt: unsupported JWS algorithm %q", resolved.Alg)
	}
	publicJSON, privateJSON, generatedCurve, err := cryptoutil.GenerateKeyPair(string(resolved.Alg))
	if err != nil {
		return "", "", "", nil, fmt.Errorf("jwt: generate %s key pair: %w", resolved.Alg, err)
	}
	alg = resolved.Alg
	if generatedCurve != "" {
		curve = new(Curve)
		*curve = Curve(generatedCurve)
	}
	return publicJSON, privateJSON, alg, curve, nil
}

// Upstream vendor/better-auth/packages/better-auth/src/plugins/jwt/utils.ts:65-115.
func createJWK(ctx context.Context, store jwksStore, config KeyPairConfig, rotationInterval time.Duration) (JWK, error) {
	if ctx == nil {
		return JWK{}, fmt.Errorf("jwt: create JWK: context is required")
	}
	if store == nil {
		return JWK{}, fmt.Errorf("jwt: create JWK: store is required")
	}
	if rotationInterval < 0 {
		return JWK{}, fmt.Errorf("jwt: create JWK: rotation interval must not be negative")
	}

	publicJSON, privateJSON, alg, curve, err := generateExportedKeyPair(config)
	if err != nil {
		return JWK{}, fmt.Errorf("jwt: create JWK key pair: %w", err)
	}

	createdAt := time.Now().UTC()
	key := JWK{
		ID:             uuid.NewString(),
		PublicKeyJSON:  publicJSON,
		PrivateKeyJSON: privateJSON,
		CreatedAt:      createdAt,
		Alg:            &alg,
		Crv:            curve,
	}
	if rotationInterval > 0 {
		expiresAt := createdAt.Add(rotationInterval)
		key.ExpiresAt = &expiresAt
	}

	created, err := store.create(ctx, key)
	if err != nil {
		return JWK{}, fmt.Errorf("jwt: persist JWK: %w", err)
	}
	return created, nil
}

// Upstream vendor/better-auth/packages/better-auth/src/plugins/jwt/utils.ts:14-27.
func toExpJWT(expiration ExpirationTime, issuedAt int64) (int64, error) {
	provided := 0
	if expiration.At != nil {
		provided++
	}
	if expiration.UnixSeconds != nil {
		provided++
	}
	if expiration.After != 0 {
		provided++
	}
	if provided != 1 {
		return 0, fmt.Errorf("jwt: expiration time must specify exactly one of At, UnixSeconds, or After")
	}
	if expiration.At != nil {
		return expiration.At.Unix(), nil
	}
	if expiration.UnixSeconds != nil {
		return *expiration.UnixSeconds, nil
	}
	if expiration.After < 0 {
		return 0, fmt.Errorf("jwt: relative expiration must not be negative")
	}

	seconds := int64(expiration.After / time.Second)
	const maxInt64 = int64(1<<63 - 1)
	if seconds > 0 && issuedAt > maxInt64-seconds {
		return 0, fmt.Errorf("jwt: relative expiration overflows Unix seconds")
	}
	return issuedAt + seconds, nil
}
