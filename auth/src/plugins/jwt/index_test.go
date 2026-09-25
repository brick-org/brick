package jwt

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/api/routes"
	authtypes "github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
)

func TestPluginContractAndEndpointInventory(t *testing.T) {
	plugin := New(Options{})
	if plugin.ID() != "jwt" {
		t.Fatalf("ID() = %q, want jwt", plugin.ID())
	}
	var _ authtypes.Plugin = plugin
	var _ Signer = plugin
	var _ Verifier = plugin
	if !reflect.DeepEqual(plugin.Schema(), Schema()) {
		t.Fatal("Schema() did not forward to the package schema")
	}
	if len(plugin.Hooks()) != 0 || len(plugin.ErrorCodes()) != 0 {
		t.Fatalf("unexpected DB hooks or error codes: hooks=%#v codes=%#v", plugin.Hooks(), plugin.ErrorCodes())
	}

	endpoints := plugin.Endpoints()
	if len(endpoints) != 2 {
		t.Fatalf("Endpoints() returned %d endpoints, want only JWKS and token", len(endpoints))
	}
	want := []struct {
		method string
		path   string
	}{{http.MethodGet, "/jwks"}, {http.MethodGet, "/token"}}
	for i, endpoint := range endpoints {
		if endpoint.Method != want[i].method || endpoint.Path != want[i].path || endpoint.Register == nil {
			t.Errorf("Endpoints()[%d] = (%q, %q, Register=%t), want (%q, %q, true)", i,
				endpoint.Method, endpoint.Path, endpoint.Register != nil, want[i].method, want[i].path)
		}
	}
	for _, endpoint := range endpoints {
		if endpoint.Path == "/sign" || endpoint.Path == "/verify" {
			t.Errorf("unexpected HTTP signing or verification route %q", endpoint.Path)
		}
	}

	custom := New(Options{JWKS: &JWKSOptions{JWKSPath: "/keys/jwks"}})
	if got := custom.Endpoints()[0].Path; got != "/keys/jwks" {
		t.Fatalf("configured JWKS endpoint path = %q, want /keys/jwks", got)
	}
}

func TestJWTPluginOptionValidation(t *testing.T) {
	remoteSigner := RemoteSignFunc(func(context.Context, Payload, SigningKeyOverrides) (string, error) {
		return "signed", nil
	})
	for _, test := range []struct {
		name        string
		options     Options
		authOptions authtypes.Options
	}{
		{name: "relative JWKS path", options: Options{JWKS: &JWKSOptions{JWKSPath: "keys"}}},
		{name: "traversal JWKS path", options: Options{JWKS: &JWKSOptions{JWKSPath: "/keys/../private"}}},
		{name: "token path conflict", options: Options{JWKS: &JWKSOptions{JWKSPath: "/token"}}},
		{name: "custom signer needs remote URL", options: Options{JWT: &JWTOptions{Sign: remoteSigner}}},
		{
			name:    "remote JWKS needs explicit algorithm",
			options: Options{JWKS: &JWKSOptions{RemoteURL: "https://keys.example.test/jwks"}},
		},
		{
			name: "remote JWKS needs remote signer",
			options: Options{JWKS: &JWKSOptions{
				RemoteURL: "https://keys.example.test/jwks", KeyPairConfig: KeyPairConfig{Alg: AlgEdDSA},
			}},
		},
		{
			name:    "invalid remote URL",
			options: Options{JWKS: &JWKSOptions{RemoteURL: "/keys", KeyPairConfig: KeyPairConfig{Alg: AlgEdDSA}}},
		},
		{
			name:    "unsupported primary algorithm",
			options: Options{JWKS: &JWKSOptions{KeyPairConfig: KeyPairConfig{Alg: "none"}}},
		},
		{
			name:    "negative rotation interval",
			options: Options{JWKS: &JWKSOptions{RotationInterval: -time.Second}},
		},
		{
			name:    "invalid expiration",
			options: Options{JWT: &JWTOptions{ExpirationTime: &ExpirationTime{After: time.Minute, UnixSeconds: int64Ptr(123)}}},
		},
		{
			name:    "session cache strategy mismatch",
			options: Options{SessionCookieCache: true},
			authOptions: authtypes.Options{Session: authtypes.SessionOptions{
				CookieCache: authtypes.SessionCookieCacheOptions{Strategy: authtypes.SessionCookieCacheCompact},
			}},
		},
		{
			name: "JWT cache strategy requires plugin signing",
			authOptions: authtypes.Options{Session: authtypes.SessionOptions{
				CookieCache: authtypes.SessionCookieCacheOptions{Strategy: authtypes.SessionCookieCacheJWT},
			}},
		},
		{
			name: "session cache requires local keys",
			options: Options{
				JWKS:               &JWKSOptions{RemoteURL: "https://keys.example.test/jwks", KeyPairConfig: KeyPairConfig{Alg: AlgEdDSA}},
				JWT:                &JWTOptions{Sign: remoteSigner},
				SessionCookieCache: true,
			},
			authOptions: authtypes.Options{Session: authtypes.SessionOptions{
				CookieCache: authtypes.SessionCookieCacheOptions{Strategy: authtypes.SessionCookieCacheJWT},
			}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateOptions(test.options, test.authOptions); err == nil {
				t.Fatal("validateOptions() succeeded, want an error")
			}
		})
	}

	validRemote := Options{
		JWKS: &JWKSOptions{RemoteURL: "https://keys.example.test/jwks", KeyPairConfig: KeyPairConfig{Alg: AlgEdDSA}},
		JWT:  &JWTOptions{Sign: remoteSigner},
	}
	if err := validateOptions(validRemote, authtypes.Options{}); err != nil {
		t.Fatalf("validateOptions(valid remote signer) error = %v", err)
	}

	cacheOptions := Options{SessionCookieCache: true}
	coreOptions := authtypes.Options{Session: authtypes.SessionOptions{
		CookieCache: authtypes.SessionCookieCacheOptions{Strategy: authtypes.SessionCookieCacheJWT},
	}}
	if err := validateOptions(cacheOptions, coreOptions); err != nil {
		t.Fatalf("validateOptions(valid session-cookie-cache strategy) error = %v", err)
	}
}

func TestInitRejectsLocalSigningWithoutDatabase(t *testing.T) {
	plugin := New(Options{})
	if err := plugin.Init(authtypes.AuthContext{}); err == nil {
		t.Fatal("Init() without a database succeeded, want fail-closed error")
	}
	if plugin.store != nil || plugin.initialized {
		t.Fatalf("failed Init left usable key state: store=%T initialized=%t", plugin.store, plugin.initialized)
	}
}

func TestRemoteJWKSIsNotServed(t *testing.T) {
	options := Options{
		JWKS: &JWKSOptions{RemoteURL: "https://keys.example.test/jwks", KeyPairConfig: KeyPairConfig{Alg: AlgEdDSA}},
		JWT: &JWTOptions{Sign: func(context.Context, Payload, SigningKeyOverrides) (string, error) {
			return "", errors.New("unused remote signer")
		}},
	}
	plugin := New(options)
	if err := plugin.Init(authtypes.AuthContext{}); err != nil {
		t.Fatalf("Init(remote signer) error = %v", err)
	}
	out, err := plugin.getJWKS(context.Background())
	if out != nil {
		t.Fatalf("remote getJWKS output = %#v, want nil", out)
	}
	var statusErr huma.StatusError
	if !errors.As(err, &statusErr) || statusErr.GetStatus() != http.StatusNotFound {
		t.Fatalf("remote getJWKS error = %v, want HTTP 404", err)
	}
}

func TestJWKSResponseFiltersPrivateFields(t *testing.T) {
	public, err := publicJWK(JWK{
		ID:             "persisted-key-id",
		PublicKeyJSON:  `{"kty":"OKP","crv":"Ed25519","x":"public","kid":"untrusted-kid","d":"private","p":"private"}`,
		PrivateKeyJSON: `{"d":"must-not-leak"}`,
	}, DefaultKeyPairConfig())
	if err != nil {
		t.Fatalf("publicJWK() error = %v", err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(public, &got); err != nil {
		t.Fatalf("decode public JWK: %v", err)
	}
	for _, privateField := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
		if _, exists := got[privateField]; exists {
			t.Errorf("public JWK leaked private field %q", privateField)
		}
	}
	var kid string
	if err := json.Unmarshal(got["kid"], &kid); err != nil || kid != "persisted-key-id" {
		t.Errorf("public JWK kid = %q, error = %v; want persisted key id", kid, err)
	}
	for _, field := range []string{"kty", "crv", "x", "kid"} {
		if _, exists := got[field]; !exists {
			t.Errorf("public JWK missing field %q", field)
		}
	}
}

func TestJWKSPublicationBootstrapsAndFiltersExpiredKeys(t *testing.T) {
	now := time.Now()
	insideGrace := now.Add(-29 * 24 * time.Hour)
	outsideGrace := now.Add(-31 * 24 * time.Hour)
	keys := []JWK{
		{ID: "live", PublicKeyJSON: `{"kty":"OKP","x":"live"}`},
		{ID: "grace", PublicKeyJSON: `{"kty":"OKP","x":"grace"}`, ExpiresAt: &insideGrace},
		{ID: "retired", PublicKeyJSON: `{"kty":"OKP","x":"retired"}`, ExpiresAt: &outsideGrace},
	}
	got := publishedJWKs(keys, now, defaultGracePeriod)
	if len(got) != 2 || got[0].ID != "live" || got[1].ID != "grace" {
		t.Fatalf("published key IDs = %#v, want live + grace", got)
	}

	legacy, err := publicJWK(JWK{
		ID:            "legacy",
		PublicKeyJSON: `{"kty":"OKP","x":"legacy"}`,
	}, DefaultKeyPairConfig())
	if err != nil {
		t.Fatalf("publicJWK(legacy) error = %v", err)
	}
	var legacyFields map[string]json.RawMessage
	if err := json.Unmarshal(legacy, &legacyFields); err != nil {
		t.Fatal(err)
	}
	var algorithm, curve string
	if err := json.Unmarshal(legacyFields["alg"], &algorithm); err != nil || algorithm != string(AlgEdDSA) {
		t.Fatalf("legacy JWKS algorithm = %q, error = %v", algorithm, err)
	}
	if err := json.Unmarshal(legacyFields["crv"], &curve); err != nil || curve != string(CurveEd25519) {
		t.Fatalf("legacy JWKS curve = %q, error = %v", curve, err)
	}
}

func TestJWKSRequestCreatesInitialKey(t *testing.T) {
	adapter := &jwksFakeAdapter{}
	store, err := newDatabaseJWKSStore(adapter, authtypes.SecretConfig{}, true)
	if err != nil {
		t.Fatal(err)
	}
	plugin := New(Options{JWKS: &JWKSOptions{DisablePrivateKeyEncryption: true}})
	plugin.store = store
	plugin.initialized = true

	output, err := plugin.getJWKS(context.Background())
	if err != nil {
		t.Fatalf("getJWKS() error = %v", err)
	}
	if len(output.Body.Keys) != 1 || len(adapter.rows) != 1 {
		t.Fatalf("getJWKS() keys=%d persisted rows=%d, want one initial key", len(output.Body.Keys), len(adapter.rows))
	}
	var public map[string]json.RawMessage
	if err := json.Unmarshal(output.Body.Keys[0], &public); err != nil {
		t.Fatal(err)
	}
	if _, exists := public["kid"]; !exists {
		t.Fatal("bootstrapped public key is missing kid")
	}
}

func TestDisableSettingJWTHeaderDisablesRouteHook(t *testing.T) {
	options := Options{
		JWKS:                    &JWKSOptions{RemoteURL: "https://keys.example.test/jwks", KeyPairConfig: KeyPairConfig{Alg: AlgEdDSA}},
		JWT:                     &JWTOptions{Sign: func(context.Context, Payload, SigningKeyOverrides) (string, error) { return "", nil }},
		DisableSettingJWTHeader: true,
	}
	plugin := New(options)
	if err := plugin.Init(authtypes.AuthContext{}); err != nil {
		t.Fatalf("Init(remote signer) error = %v", err)
	}
	if got := plugin.RouteHooks(); !reflect.DeepEqual(got, authtypes.PluginRouteHooks{}) {
		t.Fatalf("RouteHooks() = %#v, want no hooks when header setting is disabled", got)
	}
}

func TestRequestBaseURLUsesResolvedRequestOrigin(t *testing.T) {
	ctx := routes.WithRequestFullBaseURLValue(context.Background(), "https://proxy.example.test:8443/api/auth")
	if got, want := requestBaseURL(ctx, "https://configured.example.test"), "https://proxy.example.test:8443"; got != want {
		t.Fatalf("requestBaseURL() = %q, want %q", got, want)
	}
	if got, want := requestBaseURL(context.Background(), "https://configured.example.test"), "https://configured.example.test"; got != want {
		t.Fatalf("requestBaseURL(fallback) = %q, want %q", got, want)
	}
}

func int64Ptr(value int64) *int64 { return &value }
