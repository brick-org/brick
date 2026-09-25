package jwt

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	authcrypto "github.com/brick-org/brick/auth/src/crypto"
	"github.com/brick-org/brick/auth/src/types"
)

const jwksModel = "jwks"

type jwksStore interface {
	getPublicAll(context.Context) ([]JWK, error)
	getByID(context.Context, string) (*JWK, error)
	getLatest(context.Context) (*JWK, error)
	getLatestByAlg(context.Context, JWSAlgorithm) (*JWK, error)
	create(context.Context, JWK) (JWK, error)
}

type databaseJWKSStore struct {
	adapter           types.Adapter
	secrets           authcrypto.SecretConfig
	disableEncryption bool
}

var _ jwksStore = (*databaseJWKSStore)(nil)

func newDatabaseJWKSStore(adapter types.Adapter, secrets types.SecretConfig, disableEncryption bool) (*databaseJWKSStore, error) {
	if adapter == nil {
		return nil, fmt.Errorf("jwt: database JWKS store requires an adapter")
	}
	return &databaseJWKSStore{
		adapter: adapter,
		secrets: authcrypto.SecretConfig{
			Keys:           maps.Clone(secrets.Keys),
			CurrentVersion: secrets.CurrentVersion,
			LegacySecret:   secrets.LegacySecret,
		},
		disableEncryption: disableEncryption,
	}, nil
}

func (s *databaseJWKSStore) getPublicAll(ctx context.Context) ([]JWK, error) {
	rows, err := s.adapter.FindMany(ctx, jwksModel, nil, -1, 0, nil, []string{
		"id", "publicKey", "createdAt", "expiresAt", "alg", "crv",
	})
	if err != nil {
		return nil, fmt.Errorf("jwt: find JWKS: %w", err)
	}

	keys := make([]JWK, 0, len(rows))
	for i, row := range rows {
		key, err := jwkMetadataFromRow(row)
		if err != nil {
			return nil, fmt.Errorf("jwt: decode JWKS row %d: %w", i, err)
		}
		keys = append(keys, key)
	}
	slices.SortFunc(keys, compareJWKNewestFirst)
	return keys, nil
}

func (s *databaseJWKSStore) getByID(ctx context.Context, id string) (*JWK, error) {
	row, err := s.adapter.FindOne(ctx, jwksModel, []types.Where{{Field: "id", Value: id}}, nil)
	if err != nil {
		return nil, fmt.Errorf("jwt: find JWKS key %q: %w", id, err)
	}
	if row == nil {
		return nil, nil
	}
	key, err := s.jwkFromRow(row)
	if err != nil {
		return nil, fmt.Errorf("jwt: decode JWKS key %q: %w", id, err)
	}
	return key, nil
}

func (s *databaseJWKSStore) getLatest(ctx context.Context) (*JWK, error) {
	keys, err := s.getPublicAll(ctx)
	if err != nil {
		return nil, err
	}
	latest := latestLiveJWK(keys, time.Now(), nil)
	if latest == nil {
		return nil, nil
	}
	return s.getByID(ctx, latest.ID)
}

func (s *databaseJWKSStore) getLatestByAlg(ctx context.Context, alg JWSAlgorithm) (*JWK, error) {
	keys, err := s.getPublicAll(ctx)
	if err != nil {
		return nil, err
	}
	latest := latestLiveJWK(keys, time.Now(), &alg)
	if latest == nil {
		return nil, nil
	}
	return s.getByID(ctx, latest.ID)
}

func (s *databaseJWKSStore) create(ctx context.Context, key JWK) (JWK, error) {
	privateKey := key.PrivateKeyJSON
	if !s.disableEncryption {
		var err error
		privateKey, err = authcrypto.SymmetricEncrypt(s.secrets, privateKey)
		if err != nil {
			return JWK{}, fmt.Errorf("jwt: encrypt private JWKS key %q: %w", key.ID, err)
		}
	}

	var expiresAt any
	if key.ExpiresAt != nil {
		expiresAt = *key.ExpiresAt
	}
	var alg any
	if key.Alg != nil {
		alg = string(*key.Alg)
	}
	var crv any
	if key.Crv != nil {
		crv = string(*key.Crv)
	}
	row, err := s.adapter.Create(ctx, jwksModel, map[string]any{
		"id":         key.ID,
		"publicKey":  key.PublicKeyJSON,
		"privateKey": privateKey,
		"createdAt":  key.CreatedAt,
		"expiresAt":  expiresAt,
		"alg":        alg,
		"crv":        crv,
	}, nil)
	if err != nil {
		return JWK{}, fmt.Errorf("jwt: create JWKS key %q: %w", key.ID, err)
	}
	created, err := s.jwkFromRow(row)
	if err != nil {
		return JWK{}, fmt.Errorf("jwt: decode created JWKS key %q: %w", key.ID, err)
	}
	return *created, nil
}

func (s *databaseJWKSStore) jwkFromRow(row map[string]any) (*JWK, error) {
	key, err := jwkMetadataFromRow(row)
	if err != nil {
		return nil, err
	}
	privateKey, err := requiredString(row, "privateKey")
	if err != nil {
		return nil, err
	}
	if !s.disableEncryption {
		privateKey, err = authcrypto.SymmetricDecrypt(s.secrets, privateKey)
		if err != nil {
			return nil, fmt.Errorf("decrypt private key: %w", err)
		}
	}
	key.PrivateKeyJSON = privateKey
	return &key, nil
}

func jwkMetadataFromRow(row map[string]any) (JWK, error) {
	id, err := requiredString(row, "id")
	if err != nil {
		return JWK{}, err
	}
	publicKey, err := requiredString(row, "publicKey")
	if err != nil {
		return JWK{}, err
	}
	createdAt, err := requiredTime(row, "createdAt")
	if err != nil {
		return JWK{}, err
	}
	expiresAt, err := optionalTime(row, "expiresAt")
	if err != nil {
		return JWK{}, err
	}
	alg, err := optionalAlgorithm(row, "alg")
	if err != nil {
		return JWK{}, err
	}
	crv, err := optionalCurve(row, "crv")
	if err != nil {
		return JWK{}, err
	}
	return JWK{
		ID: id, PublicKeyJSON: publicKey, CreatedAt: createdAt,
		ExpiresAt: expiresAt, Alg: alg, Crv: crv,
	}, nil
}

func requiredString(row map[string]any, field string) (string, error) {
	value, ok := row[field]
	if !ok {
		return "", fmt.Errorf("missing %q", field)
	}
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%q has type %T, want string", field, value)
	}
	return text, nil
}

func requiredTime(row map[string]any, field string) (time.Time, error) {
	value, ok := row[field]
	if !ok || value == nil {
		return time.Time{}, fmt.Errorf("missing %q", field)
	}
	parsed, err := parseJWKSDate(value)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid %q: %w", field, err)
	}
	return parsed, nil
}

func optionalTime(row map[string]any, field string) (*time.Time, error) {
	value, ok := row[field]
	if !ok || value == nil {
		return nil, nil
	}
	parsed, err := parseJWKSDate(value)
	if err != nil {
		return nil, fmt.Errorf("invalid %q: %w", field, err)
	}
	return &parsed, nil
}

func parseJWKSDate(value any) (time.Time, error) {
	switch date := value.(type) {
	case time.Time:
		return date, nil
	case *time.Time:
		if date == nil {
			return time.Time{}, fmt.Errorf("date is nil")
		}
		return *date, nil
	case string:
		parsed, err := time.Parse(time.RFC3339Nano, date)
		if err != nil {
			return time.Time{}, err
		}
		return parsed, nil
	default:
		return time.Time{}, fmt.Errorf("date has type %T, want time.Time or RFC3339 string", value)
	}
}

func optionalAlgorithm(row map[string]any, field string) (*JWSAlgorithm, error) {
	value, ok := row[field]
	if !ok || value == nil {
		return nil, nil
	}
	text, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("%q has type %T, want string or nil", field, value)
	}
	algorithm := JWSAlgorithm(text)
	return &algorithm, nil
}

func optionalCurve(row map[string]any, field string) (*Curve, error) {
	value, ok := row[field]
	if !ok || value == nil {
		return nil, nil
	}
	text, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("%q has type %T, want string or nil", field, value)
	}
	curve := Curve(text)
	return &curve, nil
}

func latestLiveJWK(keys []JWK, now time.Time, alg *JWSAlgorithm) *JWK {
	for i := range keys {
		key := &keys[i]
		if key.ExpiresAt != nil && !key.ExpiresAt.After(now) {
			continue
		}
		if alg != nil && (key.Alg == nil || *key.Alg != *alg) {
			continue
		}
		return key
	}
	return nil
}

func compareJWKNewestFirst(a, b JWK) int {
	if comparison := b.CreatedAt.Compare(a.CreatedAt); comparison != 0 {
		return comparison
	}
	return strings.Compare(a.ID, b.ID)
}
