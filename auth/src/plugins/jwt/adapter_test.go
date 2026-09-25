package jwt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	authcrypto "github.com/brick-org/brick/auth/src/crypto"
	"github.com/brick-org/brick/auth/src/types"
)

func TestDatabaseJWKSStoreCreateReadRoundTrip(t *testing.T) {
	ctx := context.Background()
	adapter := &jwksFakeAdapter{}
	store, err := newDatabaseJWKSStore(adapter, testSecretConfig(), false)
	if err != nil {
		t.Fatal(err)
	}

	createdAt := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	expiresAt := createdAt.Add(24 * time.Hour)
	want := JWK{
		ID:             "key-1",
		PublicKeyJSON:  `{"kty":"OKP","crv":"Ed25519"}`,
		PrivateKeyJSON: `{"kty":"OKP","d":"private-material"}`,
		CreatedAt:      createdAt,
		ExpiresAt:      &expiresAt,
		Alg:            algorithmPtr(AlgEdDSA),
		Crv:            curvePtr(CurveEd25519),
	}
	got, err := store.create(ctx, want)
	if err != nil {
		t.Fatalf("create() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("create() = %#v, want %#v", got, want)
	}
	if len(adapter.rows) != 1 || adapter.rows[0]["publicKey"] != want.PublicKeyJSON {
		t.Fatalf("persisted rows = %#v", adapter.rows)
	}
	if got, err := store.getByID(ctx, want.ID); err != nil {
		t.Fatalf("getByID() error = %v", err)
	} else if !reflect.DeepEqual(got, &want) {
		t.Fatalf("getByID() = %#v, want %#v", got, &want)
	}
	if adapter.lastModel != jwksModel {
		t.Fatalf("model = %q, want %q", adapter.lastModel, jwksModel)
	}
}

func TestDatabaseJWKSStoreEncryptsPrivateKeyAtRest(t *testing.T) {
	adapter := &jwksFakeAdapter{}
	store, err := newDatabaseJWKSStore(adapter, testSecretConfig(), false)
	if err != nil {
		t.Fatal(err)
	}
	key := JWK{ID: "encrypted", PublicKeyJSON: "public", PrivateKeyJSON: "private", CreatedAt: time.Now()}
	if _, err := store.create(context.Background(), key); err != nil {
		t.Fatalf("create() error = %v", err)
	}
	persisted, ok := adapter.rows[0]["privateKey"].(string)
	if !ok || !strings.HasPrefix(persisted, "$ba$") || persisted == key.PrivateKeyJSON {
		t.Fatalf("persisted private key = %#v, want encrypted envelope", adapter.rows[0]["privateKey"])
	}

	publicJSON, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(publicJSON), "privateKey") || strings.Contains(string(publicJSON), key.PrivateKeyJSON) {
		t.Fatalf("public JWK JSON exposed private key: %s", publicJSON)
	}
}

func TestDatabaseJWKSStoreCanDisablePrivateKeyEncryption(t *testing.T) {
	adapter := &jwksFakeAdapter{}
	store, err := newDatabaseJWKSStore(adapter, types.SecretConfig{}, true)
	if err != nil {
		t.Fatal(err)
	}
	key := JWK{ID: "plaintext", PublicKeyJSON: "public", PrivateKeyJSON: "private", CreatedAt: time.Now()}
	if _, err := store.create(context.Background(), key); err != nil {
		t.Fatalf("create() error = %v", err)
	}
	if got := adapter.rows[0]["privateKey"]; got != key.PrivateKeyJSON {
		t.Fatalf("persisted private key = %#v, want plaintext %q", got, key.PrivateKeyJSON)
	}
	if got, err := store.getByID(context.Background(), key.ID); err != nil || got == nil || got.PrivateKeyJSON != key.PrivateKeyJSON {
		t.Fatalf("getByID() = %#v, %v; want private key %q", got, err, key.PrivateKeyJSON)
	}
}

func TestDatabaseJWKSStoreFiltersAndSortsLiveKeys(t *testing.T) {
	created := time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC)
	expiredAt := created.Add(-time.Hour)
	rows := []map[string]any{
		jwksRow("new-live", created.Add(2*time.Hour), nil, string(AlgES256), string(CurveP256)),
		jwksRow("expired-newest", created.Add(3*time.Hour), &expiredAt, string(AlgES256), string(CurveP256)),
		jwksRow("old-live", created, nil, string(AlgEdDSA), string(CurveEd25519)),
		jwksRow("tie-a", created.Add(2*time.Hour), nil, "", ""),
		{
			"id": "legacy", "publicKey": "public-legacy", "privateKey": "private-legacy",
			"createdAt": created.Add(time.Hour), "expiresAt": nil,
		},
	}
	// Empty optional legacy fields are represented as SQL NULL, not empty strings.
	rows[3]["alg"] = nil
	rows[3]["crv"] = nil
	store, err := newDatabaseJWKSStore(&jwksFakeAdapter{rows: rows}, types.SecretConfig{}, true)
	if err != nil {
		t.Fatal(err)
	}

	keys, err := store.getPublicAll(context.Background())
	if err != nil {
		t.Fatalf("getPublicAll() error = %v", err)
	}
	var gotIDs []string
	for _, key := range keys {
		gotIDs = append(gotIDs, key.ID)
	}
	if want := []string{"expired-newest", "new-live", "tie-a", "legacy", "old-live"}; !reflect.DeepEqual(gotIDs, want) {
		t.Fatalf("getPublicAll() order = %v, want %v", gotIDs, want)
	}
	if keys[2].Alg != nil || keys[2].Crv != nil {
		t.Fatalf("legacy key optional fields = alg %v, crv %v; want nil", keys[2].Alg, keys[2].Crv)
	}
	if keys[3].Alg != nil || keys[3].Crv != nil {
		t.Fatalf("row with absent optional fields = alg %v, crv %v; want nil", keys[3].Alg, keys[3].Crv)
	}

	latest, err := store.getLatest(context.Background())
	if err != nil {
		t.Fatalf("getLatest() error = %v", err)
	}
	if latest == nil || latest.ID != "new-live" {
		t.Fatalf("getLatest() = %#v, want key new-live", latest)
	}
	latestES256, err := store.getLatestByAlg(context.Background(), AlgES256)
	if err != nil {
		t.Fatalf("getLatestByAlg() error = %v", err)
	}
	if latestES256 == nil || latestES256.ID != "new-live" {
		t.Fatalf("getLatestByAlg(ES256) = %#v, want key new-live", latestES256)
	}
	if latest, err := store.getLatestByAlg(context.Background(), AlgPS256); err != nil || latest != nil {
		t.Fatalf("getLatestByAlg(PS256) = %#v, %v; want nil, nil", latest, err)
	}
}

func TestDatabaseJWKSStorePropagatesErrors(t *testing.T) {
	ctx := context.Background()
	if _, err := newDatabaseJWKSStore(nil, types.SecretConfig{}, true); err == nil {
		t.Fatal("newDatabaseJWKSStore(nil) succeeded, want error")
	}

	store, err := newDatabaseJWKSStore(&jwksFakeAdapter{}, types.SecretConfig{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.create(ctx, JWK{ID: "no-secret", PrivateKeyJSON: "private"}); err == nil {
		t.Fatal("create() without an encryption secret succeeded, want error")
	}

	adapterErr := errors.New("database unavailable")
	adapter := &jwksFakeAdapter{findManyErr: adapterErr, findOneErr: adapterErr, createErr: adapterErr}
	store, err = newDatabaseJWKSStore(adapter, types.SecretConfig{}, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.getPublicAll(ctx); !errors.Is(err, adapterErr) {
		t.Fatalf("getPublicAll() error = %v, want wrapped adapter error", err)
	}
	if _, err := store.getByID(ctx, "missing"); !errors.Is(err, adapterErr) {
		t.Fatalf("getByID() error = %v, want wrapped adapter error", err)
	}
	if _, err := store.create(ctx, JWK{ID: "write-error"}); !errors.Is(err, adapterErr) {
		t.Fatalf("create() error = %v, want wrapped adapter error", err)
	}

	badRowAdapter := &jwksFakeAdapter{rows: []map[string]any{{
		"id": "bad-ciphertext", "publicKey": "public", "privateKey": "not ciphertext",
		"createdAt": time.Now(),
	}}}
	store, err = newDatabaseJWKSStore(badRowAdapter, testSecretConfig(), false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.getByID(ctx, "bad-ciphertext"); err == nil {
		t.Fatal("getByID() with invalid ciphertext succeeded, want error")
	}
}

func TestDatabaseJWKSStorePublicReadDoesNotDecryptPrivateKeys(t *testing.T) {
	publicJSON, _, _, err := authcrypto.GenerateKeyPair(string(AlgEdDSA))
	if err != nil {
		t.Fatal(err)
	}
	store, err := newDatabaseJWKSStore(&jwksFakeAdapter{rows: []map[string]any{{
		"id": "public-only", "publicKey": publicJSON, "privateKey": "corrupt ciphertext",
		"createdAt": time.Now(), "expiresAt": nil, "alg": string(AlgEdDSA), "crv": string(CurveEd25519),
	}}}, testSecretConfig(), false)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := store.getPublicAll(context.Background())
	if err != nil {
		t.Fatalf("getPublicAll() error = %v", err)
	}
	if len(keys) != 1 || keys[0].ID != "public-only" || keys[0].PrivateKeyJSON != "" {
		t.Fatalf("public key result = %#v, want metadata only", keys)
	}
	if _, err := store.getByID(context.Background(), "public-only"); err == nil {
		t.Fatal("getByID() accepted corrupt private-key ciphertext")
	}
}

func testSecretConfig() types.SecretConfig {
	return types.SecretConfig{Keys: map[int]string{1: "jwks-test-secret"}, CurrentVersion: 1}
}

func jwksRow(id string, createdAt time.Time, expiresAt *time.Time, alg, crv string) map[string]any {
	var expiry any
	if expiresAt != nil {
		expiry = *expiresAt
	}
	return map[string]any{
		"id": id, "publicKey": "public-" + id, "privateKey": "private-" + id,
		"createdAt": createdAt, "expiresAt": expiry, "alg": alg, "crv": crv,
	}
}

type jwksFakeAdapter struct {
	types.Adapter
	rows        []map[string]any
	createErr   error
	findOneErr  error
	findManyErr error
	lastModel   string
}

func (a *jwksFakeAdapter) Create(_ context.Context, model string, data map[string]any, _ []string) (map[string]any, error) {
	a.lastModel = model
	if model != jwksModel {
		return nil, fmt.Errorf("unexpected model %q", model)
	}
	if a.createErr != nil {
		return nil, a.createErr
	}
	row := cloneJWKSRow(data)
	a.rows = append(a.rows, row)
	return cloneJWKSRow(row), nil
}

func (a *jwksFakeAdapter) FindOne(_ context.Context, model string, where []types.Where, _ []string) (map[string]any, error) {
	a.lastModel = model
	if model != jwksModel {
		return nil, fmt.Errorf("unexpected model %q", model)
	}
	if a.findOneErr != nil {
		return nil, a.findOneErr
	}
	if len(where) != 1 || where[0].Field != "id" {
		return nil, fmt.Errorf("unexpected predicate %#v", where)
	}
	for _, row := range a.rows {
		if row["id"] == where[0].Value {
			return cloneJWKSRow(row), nil
		}
	}
	return nil, nil
}

func (a *jwksFakeAdapter) FindMany(_ context.Context, model string, where []types.Where, limit, offset int, sortBy *types.SortBy, _ []string) ([]map[string]any, error) {
	a.lastModel = model
	if model != jwksModel {
		return nil, fmt.Errorf("unexpected model %q", model)
	}
	if a.findManyErr != nil {
		return nil, a.findManyErr
	}
	if len(where) != 0 || limit >= 0 || offset != 0 || sortBy != nil {
		return nil, fmt.Errorf("unexpected FindMany options: where=%#v limit=%d offset=%d sort=%#v", where, limit, offset, sortBy)
	}
	rows := make([]map[string]any, len(a.rows))
	for i, row := range a.rows {
		rows[i] = cloneJWKSRow(row)
	}
	return rows, nil
}

func cloneJWKSRow(row map[string]any) map[string]any {
	copy := make(map[string]any, len(row))
	for key, value := range row {
		copy[key] = value
	}
	return copy
}
