package jwt

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"
)

func TestGenerateExportedKeyPairDefaults(t *testing.T) {
	publicJSON, privateJSON, alg, curve, err := generateExportedKeyPair(KeyPairConfig{})
	if err != nil {
		t.Fatalf("generateExportedKeyPair(zero) error = %v", err)
	}
	if alg != AlgEdDSA {
		t.Errorf("algorithm = %q, want %q", alg, AlgEdDSA)
	}
	if curve == nil || *curve != CurveEd25519 {
		t.Errorf("curve = %v, want %q", curve, CurveEd25519)
	}
	assertJWKJSON(t, publicJSON)
	assertJWKJSON(t, privateJSON)
	if publicJSON == privateJSON {
		t.Fatal("public and private key JSON are identical")
	}
}

func TestGenerateExportedKeyPairAlgorithmsAndCurveMetadata(t *testing.T) {
	tests := []struct {
		config KeyPairConfig
		alg    JWSAlgorithm
		curve  *Curve
	}{
		{config: KeyPairConfig{Alg: AlgEdDSA}, alg: AlgEdDSA, curve: curvePtr(CurveEd25519)},
		{config: KeyPairConfig{Alg: AlgES256}, alg: AlgES256, curve: curvePtr(CurveP256)},
		{config: KeyPairConfig{Alg: AlgES512}, alg: AlgES512, curve: curvePtr(CurveP521)},
		{config: KeyPairConfig{Alg: AlgPS256}, alg: AlgPS256},
		{config: KeyPairConfig{Alg: AlgRS256}, alg: AlgRS256},
	}
	for _, test := range tests {
		t.Run(string(test.alg), func(t *testing.T) {
			publicJSON, privateJSON, alg, curve, err := generateExportedKeyPair(test.config)
			if err != nil {
				t.Fatalf("generateExportedKeyPair(%#v) error = %v", test.config, err)
			}
			if alg != test.alg {
				t.Errorf("algorithm = %q, want %q", alg, test.alg)
			}
			if test.curve == nil {
				if curve != nil {
					t.Errorf("curve = %q, want nil", *curve)
				}
			} else if curve == nil || *curve != *test.curve {
				t.Errorf("curve = %v, want %q", curve, *test.curve)
			}
			assertJWKJSON(t, publicJSON)
			assertJWKJSON(t, privateJSON)
		})
	}
}

func TestGenerateExportedKeyPairRejectsUnsupportedConfig(t *testing.T) {
	for _, config := range []KeyPairConfig{
		{Alg: "none"},
		{Alg: AlgRS256, ModulusLength: 4096},
		{Alg: AlgPS256, ModulusLength: 1024},
		{Alg: AlgES256, Crv: CurveP256},
	} {
		if _, _, _, _, err := generateExportedKeyPair(config); err == nil {
			t.Errorf("generateExportedKeyPair(%#v) succeeded, want error", config)
		}
	}
}

func TestCreateJWKPersistsRotationMetadata(t *testing.T) {
	store := &utilsTestJWKSStore{}
	interval := 5 * time.Minute
	startedAt := time.Now().UTC()
	key, err := createJWK(context.Background(), store, KeyPairConfig{Alg: AlgES256}, interval)
	if err != nil {
		t.Fatalf("createJWK() error = %v", err)
	}
	finishedAt := time.Now().UTC()
	if len(store.keys) != 1 {
		t.Fatalf("persisted %d keys, want 1", len(store.keys))
	}
	if key.ID == "" {
		t.Fatal("key ID is empty")
	}
	if key.CreatedAt.Location() != time.UTC {
		t.Errorf("CreatedAt location = %v, want UTC", key.CreatedAt.Location())
	}
	if key.CreatedAt.Before(startedAt) || key.CreatedAt.After(finishedAt) {
		t.Errorf("CreatedAt = %v, want a current time between %v and %v", key.CreatedAt, startedAt, finishedAt)
	}
	if key.ExpiresAt == nil {
		t.Fatal("ExpiresAt is nil with a rotation interval")
	}
	if want := key.CreatedAt.Add(interval); !key.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want CreatedAt + interval = %v", *key.ExpiresAt, want)
	}
	if key.Alg == nil || *key.Alg != AlgES256 {
		t.Errorf("Alg = %v, want %q", key.Alg, AlgES256)
	}
	if key.Crv == nil || *key.Crv != CurveP256 {
		t.Errorf("Crv = %v, want %q", key.Crv, CurveP256)
	}
	if got := store.keys[0].ID; got != key.ID {
		t.Errorf("persisted ID = %q, returned ID = %q", got, key.ID)
	}
}

func TestCreateJWKWithoutRotationAndUniqueIDs(t *testing.T) {
	store := &utilsTestJWKSStore{}
	first, err := createJWK(context.Background(), store, KeyPairConfig{}, 0)
	if err != nil {
		t.Fatalf("first createJWK() error = %v", err)
	}
	second, err := createJWK(context.Background(), store, KeyPairConfig{}, 0)
	if err != nil {
		t.Fatalf("second createJWK() error = %v", err)
	}
	if first.ExpiresAt != nil || second.ExpiresAt != nil {
		t.Errorf("zero rotation interval should omit expiry, got %v and %v", first.ExpiresAt, second.ExpiresAt)
	}
	if first.ID == second.ID {
		t.Fatalf("generated duplicate key IDs %q", first.ID)
	}
}

func TestCreateJWKRejectsNegativeRotation(t *testing.T) {
	if _, err := createJWK(context.Background(), &utilsTestJWKSStore{}, KeyPairConfig{}, -time.Second); err == nil {
		t.Fatal("createJWK() with negative rotation interval succeeded, want error")
	}
}

func TestToExpJWTConvertsAbsoluteAndRelativeExpiration(t *testing.T) {
	at := time.Unix(1_700_000_000, 900_000_000)
	unixSeconds := int64(1_800_000_000)
	tests := []struct {
		name       string
		expiration ExpirationTime
		issuedAt   int64
		want       int64
	}{
		{name: "date", expiration: ExpirationTime{At: &at}, issuedAt: 100, want: 1_700_000_000},
		{name: "unix seconds", expiration: ExpirationTime{UnixSeconds: &unixSeconds}, issuedAt: 100, want: unixSeconds},
		{name: "relative duration", expiration: ExpirationTime{After: 90 * time.Second}, issuedAt: 100, want: 190},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := toExpJWT(test.expiration, test.issuedAt)
			if err != nil {
				t.Fatalf("toExpJWT() error = %v", err)
			}
			if got != test.want {
				t.Errorf("toExpJWT() = %d, want %d", got, test.want)
			}
		})
	}
}

func TestToExpJWTRejectsInvalidExpiration(t *testing.T) {
	at := time.Unix(100, 0)
	unixSeconds := int64(200)
	for _, expiration := range []ExpirationTime{
		{},
		{At: &at, UnixSeconds: &unixSeconds},
		{At: &at, After: time.Second},
		{After: -time.Second},
	} {
		if _, err := toExpJWT(expiration, 0); err == nil {
			t.Errorf("toExpJWT(%#v) succeeded, want error", expiration)
		}
	}

	if _, err := toExpJWT(ExpirationTime{After: 2 * time.Second}, 1<<63-2); err == nil {
		t.Fatal("toExpJWT() overflow succeeded, want error")
	}
}

func assertJWKJSON(t *testing.T, value string) {
	t.Helper()
	var jwk map[string]any
	if err := json.Unmarshal([]byte(value), &jwk); err != nil {
		t.Fatalf("generated JWK is invalid JSON: %v", err)
	}
}

type utilsTestJWKSStore struct {
	keys []JWK
}

func (s *utilsTestJWKSStore) getAll(context.Context) ([]JWK, error) {
	return append([]JWK(nil), s.keys...), nil
}

func (s *utilsTestJWKSStore) getPublicAll(ctx context.Context) ([]JWK, error) {
	return s.getAll(ctx)
}

func (s *utilsTestJWKSStore) getByID(_ context.Context, id string) (*JWK, error) {
	index := slices.IndexFunc(s.keys, func(key JWK) bool { return key.ID == id })
	if index < 0 {
		return nil, nil
	}
	key := s.keys[index]
	return &key, nil
}

func (s *utilsTestJWKSStore) getLatest(ctx context.Context) (*JWK, error) {
	return s.latest(ctx, nil)
}

func (s *utilsTestJWKSStore) getLatestByAlg(ctx context.Context, alg JWSAlgorithm) (*JWK, error) {
	return s.latest(ctx, &alg)
}

func (s *utilsTestJWKSStore) latest(ctx context.Context, alg *JWSAlgorithm) (*JWK, error) {
	keys, err := s.getAll(ctx)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(keys, compareJWKNewestFirst)
	return latestLiveJWK(keys, time.Now(), alg), nil
}

func (s *utilsTestJWKSStore) create(_ context.Context, key JWK) (JWK, error) {
	s.keys = append(s.keys, key)
	return key, nil
}
