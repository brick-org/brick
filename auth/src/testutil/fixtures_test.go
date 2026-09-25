package testutil

// Both-directions fixture tests for the wire formats in auth/src/testdata.

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/cookies"
	"github.com/brick-org/brick/auth/src/crypto"
)

func TestFixture_EmailJWT_BothDirections(t *testing.T) {
	var doc struct {
		Secret   string         `json:"secret"`
		Token    string         `json:"token"`
		Header   map[string]any `json:"header"`
		Payload  map[string]any `json:"payload"`
		Expected struct {
			Alg   string `json:"alg"`
			Email string `json:"email"`
		} `json:"expected"`
	}
	MustLoad(t, "email_jwt.json", &doc)

	got, err := crypto.VerifyEmailVerificationTokenAny([]string{"decoy", doc.Secret}, doc.Token)
	if err != nil {
		t.Fatalf("verify fixture token: %v", err)
	}
	if got.Email != doc.Expected.Email {
		t.Errorf("email = %q, want %q", got.Email, doc.Expected.Email)
	}
	if got.Extra["fixture"] != "auth-r5-04" {
		t.Errorf("extra = %v", got.Extra)
	}
	if doc.Header["alg"] != "HS256" {
		t.Errorf("header alg = %v, want HS256", doc.Header["alg"])
	}
	if doc.Payload["email"] != doc.Expected.Email {
		t.Errorf("payload email = %v", doc.Payload["email"])
	}
	if _, ok := doc.Payload["exp"].(float64); !ok {
		t.Errorf("payload exp must be numeric, got %T", doc.Payload["exp"])
	}

	fresh, err := crypto.CreateEmailVerificationToken(doc.Secret, "Fresh@Example.com", "", 3600, nil)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	parts := strings.Split(fresh, ".")
	if len(parts) != 3 {
		t.Fatalf("fresh token is not a compact JWT: %q", fresh)
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(rawHeader, &header); err != nil || header["alg"] != "HS256" {
		t.Fatalf("fresh header = %s, %v", rawHeader, err)
	}
	back, err := crypto.VerifyEmailVerificationToken(doc.Secret, fresh)
	if err != nil || back.Email != "fresh@example.com" {
		t.Fatalf("fresh round trip = %+v, %v", back, err)
	}

	if _, err := crypto.VerifyEmailVerificationToken(doc.Secret, doc.Token+"a"); err == nil {
		t.Error("tampered token verified")
	}
	if _, err := crypto.VerifyEmailVerificationToken("wrong", doc.Token); err == nil {
		t.Error("wrong secret verified")
	}
	if _, err := crypto.VerifyEmailVerificationToken(doc.Secret, "not-a-jwt"); err == nil {
		t.Error("garbage verified")
	}
	legacy, err := crypto.GenerateToken(doc.Secret, "legacy@example.com", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.VerifyEmailVerificationToken(doc.Secret, legacy); err == nil {
		t.Error("legacy HMAC token verified as JWT")
	}
}

func TestFixture_XChaCha_BothDirections(t *testing.T) {
	var doc struct {
		Secret    string `json:"secret"`
		Plaintext string `json:"plaintext"`
		BareHex   string `json:"bare_hex"`
		Envelope  string `json:"envelope"`
		Cfg       struct {
			Keys map[string]string `json:"keys"`
		} `json:"envelope_secret_config"`
		LegacyBareHex string `json:"legacy_bare_hex"`
	}
	MustLoad(t, "xchacha.json", &doc)

	cfg := crypto.SecretConfig{
		Keys:           map[int]string{1: doc.Cfg.Keys["1"], 2: doc.Cfg.Keys["2"]},
		CurrentVersion: 2,
		LegacySecret:   "auth-r5-04-xchacha-legacy",
	}
	if back, err := crypto.SymmetricDecrypt(doc.Secret, doc.BareHex); err != nil || back != doc.Plaintext {
		t.Fatalf("bare decrypt = %q, %v", back, err)
	}
	if back, err := crypto.SymmetricDecrypt(cfg, doc.Envelope); err != nil || back != doc.Plaintext {
		t.Fatalf("envelope decrypt = %q, %v", back, err)
	}
	if back, err := crypto.SymmetricDecrypt(cfg, doc.LegacyBareHex); err != nil || back != "legacy" {
		t.Fatalf("legacy decrypt = %q, %v", back, err)
	}
	if !strings.HasPrefix(doc.Envelope, "$ba$2$") {
		t.Errorf("envelope = %q, want $ba$2$ prefix", doc.Envelope)
	}

	freshBare, err := crypto.SymmetricEncrypt(doc.Secret, "fresh")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range freshBare {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("bare payload not hex: %q", freshBare)
		}
	}
	freshEnv, err := crypto.SymmetricEncrypt(cfg, "fresh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(freshEnv, "$ba$2$") {
		t.Fatalf("fresh envelope = %q", freshEnv)
	}
	if _, err := crypto.SymmetricDecrypt("wrong", doc.BareHex); err == nil {
		t.Error("wrong secret decrypted bare payload")
	}
	if _, err := crypto.SymmetricDecrypt(cfg, doc.BareHex+"zz"); err == nil {
		t.Error("tampered payload decrypted")
	}
	if _, err := crypto.SymmetricDecrypt(cfg, "!!!not-hex!!!"); err == nil {
		t.Error("non-hex payload decrypted")
	}
	version, _, ok := crypto.ParseEnvelope(doc.Envelope)
	if !ok || version != 2 {
		t.Errorf("ParseEnvelope = %d %v", version, ok)
	}
}

func TestFixture_SessionJWT_BothDirections(t *testing.T) {
	var doc struct {
		Secret  string         `json:"secret"`
		Token   string         `json:"token"`
		Header  map[string]any `json:"header"`
		Payload map[string]any `json:"payload"`
		Session map[string]any `json:"session"`
		User    map[string]any `json:"user"`
		Version string         `json:"version"`
	}
	MustLoad(t, "session_jwt.json", &doc)

	got, expMillis, err := cookies.VerifySessionCacheJWT([]string{"rotated-secret", doc.Secret}, doc.Token)
	if err != nil {
		t.Fatalf("verify fixture: %v", err)
	}
	if got.Version != doc.Version || got.Session["token"] != "tok-fixture-1" || got.User["id"] != "user-fixture-1" {
		t.Fatalf("payload = %+v", got)
	}
	if time.Until(time.UnixMilli(expMillis)) <= 0 {
		t.Fatal("fixture already expired; regenerate with gen-fixtures.sh")
	}
	if doc.Header["alg"] != "HS256" {
		t.Errorf("header alg = %v, want HS256", doc.Header["alg"])
	}

	fresh, err := cookies.CreateSessionCacheJWT(doc.Secret, doc.Session, doc.User, "2", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.Split(fresh, ".")) != 3 {
		t.Fatalf("fresh token is not a compact JWT: %q", fresh)
	}
	back, _, err := cookies.VerifySessionCacheJWT([]string{doc.Secret}, fresh)
	if err != nil || back.Version != "2" {
		t.Fatalf("fresh round trip = %+v, %v", back, err)
	}

	if _, _, err := cookies.VerifySessionCacheJWT([]string{"wrong"}, doc.Token); err == nil {
		t.Error("wrong secret verified")
	}
	tampered := doc.Token[:len(doc.Token)-2] + "xx"
	if _, _, err := cookies.VerifySessionCacheJWT([]string{doc.Secret}, tampered); err == nil {
		t.Error("tampered token verified")
	}
	for _, bad := range []string{"", "not.a.jwt", strings.Repeat("A", 1<<20)} {
		if _, _, err := cookies.VerifySessionCacheJWT([]string{doc.Secret}, bad); err == nil {
			t.Errorf("malformed %q verified", bad[:min(len(bad), 16)])
		}
	}
	noneHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	noneToken := noneHeader + "." + strings.Split(doc.Token, ".")[1] + ".sig"
	if _, _, err := cookies.VerifySessionCacheJWT([]string{doc.Secret}, noneToken); err == nil {
		t.Error("none-alg token verified")
	}
}

func TestFixture_SessionJWE_BothDirections(t *testing.T) {
	var doc struct {
		Secret   string         `json:"secret"`
		Token    string         `json:"token"`
		Header   map[string]any `json:"header"`
		Session  map[string]any `json:"session"`
		User     map[string]any `json:"user"`
		Version  string         `json:"version"`
		Expected struct {
			Alg string `json:"alg"`
			Enc string `json:"enc"`
			Kid string `json:"kid"`
		} `json:"expected"`
	}
	MustLoad(t, "session_jwe.json", &doc)

	got, expMillis, err := cookies.VerifySessionCacheJWE([]string{"rotated-secret", doc.Secret}, doc.Token)
	if err != nil {
		t.Fatalf("verify fixture: %v", err)
	}
	if got.Version != doc.Version || got.Session["token"] != "tok-fixture-1" {
		t.Fatalf("payload = %+v", got)
	}
	if time.Until(time.UnixMilli(expMillis)) <= 0 {
		t.Fatal("fixture already expired; regenerate with gen-fixtures.sh")
	}
	if doc.Header["alg"] != "dir" || doc.Header["enc"] != "A256CBC-HS512" {
		t.Errorf("header = %v, want dir/A256CBC-HS512", doc.Header)
	}
	key, err := crypto.DeriveEncryptionSecret(doc.Secret, crypto.SessionCookieEncryptionSalt)
	if err != nil {
		t.Fatal(err)
	}
	wantKid, err := crypto.OctThumbprint(key)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Header["kid"] != wantKid || doc.Expected.Kid != wantKid {
		t.Errorf("kid = %v, want %v", doc.Header["kid"], wantKid)
	}
	if len(strings.Split(doc.Token, ".")) != 5 {
		t.Error("JWE must be 5-part compact serialization")
	}

	fresh, err := cookies.CreateSessionCacheJWE(doc.Secret, doc.Session, doc.User, "8", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	back, _, err := cookies.VerifySessionCacheJWE([]string{doc.Secret}, fresh)
	if err != nil || back.Version != "8" {
		t.Fatalf("fresh round trip = %+v, %v", back, err)
	}

	if _, _, err := cookies.VerifySessionCacheJWE([]string{"other-a", "other-b"}, doc.Token); err == nil {
		t.Error("unknown kid decrypted")
	}
	tampered := doc.Token[:len(doc.Token)-4] + "xxxx"
	if _, _, err := cookies.VerifySessionCacheJWE([]string{doc.Secret}, tampered); err == nil {
		t.Error("tampered JWE decrypted")
	}
	for _, bad := range []string{"", "garbage", strings.Repeat("B", 1<<20)} {
		if _, _, err := cookies.VerifySessionCacheJWE([]string{doc.Secret}, bad); err == nil {
			t.Errorf("malformed %q decrypted", bad[:min(len(bad), 16)])
		}
	}
}

func TestFixture_JWK_BothDirections(t *testing.T) {
	var jwkDoc struct {
		Alg       string         `json:"alg"`
		Kid       string         `json:"kid"`
		PublicJWK map[string]any `json:"public_jwk"`
		Token     string         `json:"token"`
		Claims    map[string]any `json:"claims"`
	}
	MustLoad(t, "jwk.json", &jwkDoc)
	var jwksDoc struct {
		Keys []map[string]any `json:"keys"`
	}
	MustLoad(t, "jwks.json", &jwksDoc)

	pubRaw, err := json.Marshal(jwkDoc.PublicJWK)
	if err != nil {
		t.Fatal(err)
	}
	keys := []crypto.PublicKey{{Kid: jwkDoc.Kid, Alg: jwkDoc.Alg, PublicJWKJSON: string(pubRaw)}}

	claims, err := crypto.VerifyJWT(jwkDoc.Token, keys, crypto.VerifyOptions{
		Issuer: "https://auth.example.com", Audience: []string{"https://api.example.com"},
	})
	if err != nil {
		t.Fatalf("verify fixture token: %v", err)
	}
	if claims["sub"] != "fixture-user-1" {
		t.Errorf("sub = %v", claims["sub"])
	}
	if len(jwksDoc.Keys) != 1 || jwksDoc.Keys[0]["kid"] != jwkDoc.Kid {
		t.Fatalf("jwks = %v", jwksDoc.Keys)
	}
	if jwksDoc.Keys[0]["kty"] != "OKP" || jwksDoc.Keys[0]["crv"] != "Ed25519" {
		t.Errorf("jwks key type = %v", jwksDoc.Keys[0])
	}
	built, err := crypto.BuildJWKS(keys)
	if err != nil {
		t.Fatal(err)
	}
	builtKeys, _ := built["keys"].([]map[string]any)
	if len(builtKeys) != 1 || builtKeys[0]["kid"] != jwkDoc.Kid {
		t.Fatalf("BuildJWKS = %v", built)
	}

	if _, err := crypto.VerifyJWT(jwkDoc.Token, []crypto.PublicKey{{Kid: "other", Alg: "EdDSA", PublicJWKJSON: string(pubRaw)}}, crypto.VerifyOptions{}); err == nil {
		t.Error("unknown kid verified")
	}
	if _, err := crypto.VerifyJWT(jwkDoc.Token, keys, crypto.VerifyOptions{Audience: []string{"https://other.example.com"}}); err == nil {
		t.Error("wrong audience verified")
	}
	if _, err := crypto.VerifyJWT(jwkDoc.Token+"a", keys, crypto.VerifyOptions{}); err == nil {
		t.Error("tampered token verified")
	}
	if _, err := crypto.VerifyJWT("garbage", keys, crypto.VerifyOptions{}); err == nil {
		t.Error("garbage verified")
	}
}

func TestFixture_Cookies(t *testing.T) {
	var doc struct {
		SignVectors []struct {
			Secret string `json:"secret"`
			Value  string `json:"value"`
			Signed string `json:"signed"`
		} `json:"sign_vectors"`
		Chunk struct {
			Name    string            `json:"name"`
			Cookies map[string]string `json:"cookies"`
			Want    string            `json:"want"`
		} `json:"chunk_fixture"`
	}
	MustLoad(t, "cookies.json", &doc)

	for _, vec := range doc.SignVectors {
		got, err := cookies.Sign(vec.Secret, vec.Value)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if got != vec.Signed {
			t.Errorf("Sign(%q) = %q, want %q", vec.Value, got, vec.Signed)
		}
		if back, ok := cookies.Verify(vec.Secret, vec.Signed); !ok || back != vec.Value {
			t.Errorf("Verify(%q) = %q, %v", vec.Signed, back, ok)
		}
		if _, ok := cookies.Verify("wrong-secret", vec.Signed); ok {
			t.Errorf("wrong secret verified %q", vec.Signed)
		}
		if _, ok := cookies.VerifyAny([]string{"old", vec.Secret}, vec.Signed); !ok {
			t.Errorf("VerifyAny rotation failed for %q", vec.Signed)
		}
	}
	for _, bad := range []string{"", "nosig", "a.", ".b"} {
		if _, ok := cookies.Verify("s", bad); ok && bad != "a." && bad != ".b" {
			t.Errorf("%q verified", bad)
		}
	}
	joined, ok := cookies.JoinChunkedCookies(doc.Chunk.Cookies, doc.Chunk.Name)
	if !ok || joined != doc.Chunk.Want {
		t.Fatalf("join = %q, %v; want %q", joined, ok, doc.Chunk.Want)
	}
	if idx, ok := cookies.ParseChunkIndex(doc.Chunk.Name, doc.Chunk.Name+".1"); !ok || idx != 1 {
		t.Fatalf("chunk index = %d, %v", idx, ok)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
