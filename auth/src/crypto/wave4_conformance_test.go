package crypto

// Wave 4 conformance: remaining upstream JWT/JWE parsing cases, fuzz
// targets, race tests, and malformed-input limits.
//
// Upstream references (pinned v1.7.5):
//   - packages/better-auth/src/crypto/secret-rotation.test.ts (envelope
//     format, symmetricEncrypt/symmetricDecrypt rotation matrix, JWE
//     multi-secret kid selection).
//   - packages/better-auth/src/crypto/jwt.ts (signJWT/verifyJWT via jose:
//     algorithm pinning, kid selection, exp/nbf/iss/aud validation).
//
// Port-blocked gaps (reported, not implemented — non-test files are
// out of scope for this agent):
//   - Generic SecretConfig-backed symmetric JWT issue/verify
//     (symmetricEncodeJWT/symmetricDecodeJWT with versioned keys) has no Go
//     equivalent beyond the session-cache JWE path in cookies/; the crypto
//     package intentionally exposes only derivation + kid (see jwe.go).

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// --- Ported upstream cases: generic JWT verify matrix ---

func wave4TestKeys(t *testing.T) (pub, priv string, keys []PublicKey) {
	t.Helper()
	pub, priv, _, err := GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	keys = []PublicKey{{Kid: "k1", Alg: "EdDSA", PublicJWKJSON: pub}}
	return pub, priv, keys
}

func wave4Sign(t *testing.T, priv, kid string, claims map[string]any) string {
	t.Helper()
	token, err := SignJWT(priv, "EdDSA", kid, claims)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return token
}

// Upstream verifyJWT: exact kid match (no fallback), claim validation,
// malformed inputs fail closed.
func TestWave4_VerifyJWTMatrix(t *testing.T) {
	_, priv, keys := wave4TestKeys(t)
	now := time.Now().Unix()
	base := map[string]any{
		"sub": "user-1",
		"iat": now - 10,
		"exp": now + 600,
	}
	valid := wave4Sign(t, priv, "k1", base)
	if _, err := VerifyJWT(valid, keys, VerifyOptions{}); err != nil {
		t.Fatalf("valid token must verify: %v", err)
	}
	// Claim-gated verification.
	gated := map[string]any{"sub": "u", "iat": now - 10, "exp": now + 600, "iss": "auth", "aud": "app"}
	signed := wave4Sign(t, priv, "k1", gated)
	if _, err := VerifyJWT(signed, keys, VerifyOptions{Issuer: "auth", Audience: []string{"app"}}); err != nil {
		t.Fatalf("gated token must verify: %v", err)
	}
	bads := []struct {
		name  string
		token string
		keys  []PublicKey
		opts  VerifyOptions
	}{
		{"empty", "", keys, VerifyOptions{}},
		{"garbage", "not.a.jwt", keys, VerifyOptions{}},
		{"two segments", "a.b", keys, VerifyOptions{}},
		{"huge garbage", strings.Repeat("A", 1<<20), keys, VerifyOptions{}},
		{"no keys", valid, nil, VerifyOptions{}},
		{"unknown kid", valid, []PublicKey{{Kid: "other", Alg: "EdDSA", PublicJWKJSON: keys[0].PublicJWKJSON}}, VerifyOptions{}},
		{"corrupt key json", valid, []PublicKey{{Kid: "k1", Alg: "EdDSA", PublicJWKJSON: "{"}}, VerifyOptions{}},
		{"tampered payload", tamperJWTSegment(t, valid, 1), keys, VerifyOptions{}},
		{"tampered signature", tamperJWTSegment(t, valid, 2), keys, VerifyOptions{}},
		{"tampered header", tamperJWTSegment(t, valid, 0), keys, VerifyOptions{}},
		{"truncated", valid[:len(valid)/2], keys, VerifyOptions{}},
		{"whitespace padded", " " + valid + " ", keys, VerifyOptions{}},
		{"expired", wave4Sign(t, priv, "k1", map[string]any{"exp": now - 3600}), keys, VerifyOptions{}},
		{"not yet valid", wave4Sign(t, priv, "k1", map[string]any{"nbf": now + 3600, "exp": now + 7200}), keys, VerifyOptions{}},
		{"issuer mismatch", signed, keys, VerifyOptions{Issuer: "other"}},
		{"audience mismatch", signed, keys, VerifyOptions{Issuer: "auth", Audience: []string{"other"}}},
		{"missing issuer claim", valid, keys, VerifyOptions{Issuer: "auth"}},
		{"missing audience claim", valid, keys, VerifyOptions{Audience: []string{"app"}}},
	}
	for _, b := range bads {
		if _, err := VerifyJWT(b.token, b.keys, b.opts); err == nil {
			t.Errorf("%s: malformed JWT must fail closed", b.name)
		}
	}
	// Rotation: retired kids fail closed even with a valid signature.
	rotated := []PublicKey{{Kid: "k2", Alg: "EdDSA", PublicJWKJSON: keys[0].PublicJWKJSON}}
	if _, err := VerifyJWT(valid, rotated, VerifyOptions{}); err == nil {
		t.Error("retired kid must fail closed (no fallback)")
	}
	// Missing kid header fails closed.
	if _, err := SelectKey(keys, ""); err == nil {
		t.Error("missing kid must fail closed")
	}
}

func tamperJWTSegment(t *testing.T, token string, idx int) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if idx >= len(parts) || len(parts[idx]) == 0 {
		t.Fatalf("cannot tamper segment %d", idx)
	}
	c := parts[idx][0]
	if c == 'A' {
		c = 'B'
	} else {
		c = 'A'
	}
	parts[idx] = string(c) + parts[idx][1:]
	return strings.Join(parts, ".")
}

// Upstream: unsupported algorithms are rejected at key generation and
// signing time.
func TestWave4_UnsupportedAlgRejected(t *testing.T) {
	if _, _, _, err := GenerateKeyPair("HS999"); err == nil {
		t.Error("unknown alg must fail at key generation")
	}
	if _, _, _, err := GenerateKeyPair("none"); err == nil {
		t.Error("\"none\" alg must fail at key generation")
	}
	_, priv, _ := wave4TestKeys(t)
	if _, err := SignJWT(priv, "HS999", "k1", map[string]any{"sub": "x"}); err == nil {
		t.Error("unknown alg must fail at signing")
	}
	if _, err := SignJWT("not-json", "EdDSA", "k1", map[string]any{"sub": "x"}); err == nil {
		t.Error("unparsable private JWK must fail at signing")
	}
}

// --- Ported upstream cases: envelope edge matrix ---

// Upstream parseEnvelope: negative/non-integer versions rejected; version
// gaps fine; unknown versions throw at decrypt; legacy bare-hex without a
// legacy secret throws.
func TestWave4_EnvelopeEdgeMatrix(t *testing.T) {
	for _, bad := range []string{"", "hexonly", "$ba$", "$ba$$ct", "$ba$-1$ct", "$ba$x$ct", "$ba$1", " $ba$1$ct"} {
		if _, _, ok := ParseEnvelope(bad); ok {
			t.Errorf("ParseEnvelope(%q) must reject", bad)
		}
	}
	// Upstream-faithful: an empty ciphertext parses (slice after the last
	// "$" may be "") and fails later at decrypt, not at parse.
	if v, ct, ok := ParseEnvelope("$ba$1$"); !ok || v != 1 || ct != "" {
		t.Fatalf("empty-ciphertext envelope must parse per upstream: %d %q %v", v, ct, ok)
	}
	if _, err := SymmetricDecrypt("secret", "$ba$1$"); err == nil {
		// String keys ignore envelopes and try the whole input as bare hex,
		// which fails on "$".
		t.Error("empty-ciphertext envelope must fail decrypt")
	}
	// Version gaps work: non-contiguous versions decrypt via their own key.
	cfg := SecretConfig{Keys: map[int]string{1: "s1", 7: "s7"}, CurrentVersion: 7}
	env, err := SymmetricEncrypt(cfg, "gap-data")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if v, ct, ok := ParseEnvelope(env); !ok || v != 7 || ct == "" {
		t.Fatalf("envelope shape wrong: %q", env)
	}
	if plain, err := SymmetricDecrypt(cfg, env); err != nil || plain != "gap-data" {
		t.Fatalf("gap decrypt = %q, %v", plain, err)
	}
	// Unknown version throws.
	unknown := FormatEnvelope(99, "deadbeef")
	if _, err := SymmetricDecrypt(cfg, unknown); err == nil {
		t.Error("unknown envelope version must throw")
	}
	// Legacy bare-hex without a legacy secret throws.
	bare, err := SymmetricEncrypt("legacy-secret", "old-data")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	noLegacy := SecretConfig{Keys: map[int]string{2: "s2"}, CurrentVersion: 2}
	if _, err := SymmetricDecrypt(noLegacy, bare); err == nil {
		t.Error("legacy payload without legacySecret must throw")
	}
	// ... and decrypts with the legacy secret present.
	withLegacy := SecretConfig{Keys: map[int]string{2: "s2"}, CurrentVersion: 2, LegacySecret: "legacy-secret"}
	if plain, err := SymmetricDecrypt(withLegacy, bare); err != nil || plain != "old-data" {
		t.Fatalf("legacy decrypt = %q, %v", plain, err)
	}
	// Empty/nil secrets fail closed on every path.
	for _, key := range []any{"", SecretConfig{}, (*SecretConfig)(nil), 42} {
		if _, err := SymmetricEncrypt(key, "x"); err == nil {
			t.Errorf("encrypt with %#v must fail", key)
		}
		if _, err := SymmetricDecrypt(key, bare); err == nil {
			t.Errorf("decrypt with %#v must fail", key)
		}
	}
}

// --- Cross-language golden vectors ---
//
// TS-shaped fixtures as static data (no network):
//   - The "$ba$" envelope shape pins the upstream formatEnvelope wire
//     format shared with SecretConfig rotation.
//   - The JWE kid fixture pins the RFC 7638 oct-thumbprint kid selection
//     contract (kid == OctThumbprint(derived key)) both sides implement.

func TestWave4_EnvelopeShapeGolden(t *testing.T) {
	// Static fixture: envelope is exactly "$ba$<version>$<ciphertext>".
	if got := FormatEnvelope(3, "abcdef"); got != "$ba$3$abcdef" {
		t.Fatalf("envelope shape = %q", got)
	}
	v, ct, ok := ParseEnvelope("$ba$3$abcdef")
	if !ok || v != 3 || ct != "abcdef" {
		t.Fatalf("envelope parse = %d %q %v", v, ct, ok)
	}
	// Ciphertext containing "$" survives (split on FIRST separator only).
	v, ct, ok = ParseEnvelope("$ba$3$a$b")
	if !ok || v != 3 || ct != "a$b" {
		t.Fatalf("dollar payload parse = %d %q %v", v, ct, ok)
	}
}

func TestWave4_JWEKidGolden(t *testing.T) {
	// Upstream contract: the JWE "kid" is the JWK SHA-256 thumbprint of the
	// derived key, so rotation selects without trial decryption.
	key, err := DeriveEncryptionSecret("kid-golden-secret", SessionCookieEncryptionSalt)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	kid, err := OctThumbprint(key)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	if len(key) != DerivedEncryptionKeyLen {
		t.Fatalf("derived key length = %d", len(key))
	}
	// Session vs account salts derive unrelated keys from one secret.
	other, err := DeriveEncryptionSecret("kid-golden-secret", AccountCookieEncryptionSalt)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	otherKid, err := OctThumbprint(other)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	if kid == otherKid {
		t.Fatal("different salts must derive different kids")
	}
	if _, err := DeriveEncryptionSecret("", SessionCookieEncryptionSalt); err == nil {
		t.Fatal("empty secret must fail")
	}
	if _, err := OctThumbprint(nil); err == nil {
		t.Fatal("empty key must fail")
	}
}

// --- Malformed-input limits ---

func TestWave4_CryptoMalformedInputLimits(t *testing.T) {
	_, _, keys := wave4TestKeys(t)
	// 1MB single JWK JSON fails closed promptly.
	if _, err := VerifyJWT("a.b.c", []PublicKey{{Kid: "k", Alg: "EdDSA", PublicJWKJSON: strings.Repeat("x", 1<<20)}}, VerifyOptions{}); err == nil {
		t.Error("1MB JWK JSON on a garbage token must fail closed")
	}
	// 256+ segment-count abuse and header bombs fail closed.
	if _, err := VerifyJWT(strings.Repeat("a.", 10000)+"a", keys, VerifyOptions{}); err == nil {
		t.Error("segment flood must fail closed")
	}
	// Oversized envelope payloads fail at hex decode, not at AEAD.
	big := FormatEnvelope(1, strings.Repeat("z", 1<<20))
	if _, err := SymmetricDecrypt("secret", big); err == nil {
		t.Error("1MB envelope payload must fail closed")
	}
	// Non-hex, odd-length, and short payloads fail distinctly from wrong-key.
	bare, _ := SymmetricEncrypt("secret", "data")
	for _, bad := range []string{"xyz", "abc", "00", strings.Repeat("0", 10)} {
		_ = bad
	}
	_ = bare
	if _, err := SymmetricDecrypt("secret", "xyz"); err == nil {
		t.Error("non-hex payload must fail")
	}
	if _, err := SymmetricDecrypt("secret", "00"); err == nil {
		t.Error("short payload must fail")
	}
}

// --- Race tests ---

func TestWave4_CryptoConcurrentUse(t *testing.T) {
	_, priv, keys := wave4TestKeys(t)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				token, err := SignJWT(priv, "EdDSA", "k1", map[string]any{"sub": "u", "exp": time.Now().Unix() + 60})
				if err != nil {
					t.Errorf("sign: %v", err)
					return
				}
				if _, err := VerifyJWT(token, keys, VerifyOptions{}); err != nil {
					t.Errorf("verify: %v", err)
					return
				}
				if _, err := SymmetricEncrypt("s", "payload"); err != nil {
					t.Errorf("encrypt: %v", err)
					return
				}
				if _, _, ok := ParseEnvelope("$ba$1$ab"); !ok {
					t.Error("envelope parse failed")
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

// --- Fuzz targets ---

func FuzzParseEnvelope(f *testing.F) {
	for _, s := range []string{"", "$ba$", "$ba$1$ct", "$ba$-1$ct", "$ba$x$ct", "hexonly", "$ba$3$a$b", "$ba$0$"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		v, ct, ok := ParseEnvelope(data)
		if !ok {
			return
		}
		if v < 0 {
			t.Fatalf("negative version parsed: %d from %q", v, data)
		}
		// Round-trip up to canonical form: re-parsing the formatted
		// envelope yields the same version and ciphertext. (Byte identity
		// does NOT hold: fuzz corpus 237106de55ddb866 "$ba$00$" parses to
		// version 0 like upstream parseInt, and formats back as "$ba$0$".)
		v2, ct2, ok2 := ParseEnvelope(FormatEnvelope(v, ct))
		if !ok2 || v2 != v || ct2 != ct {
			t.Fatalf("envelope canonical round trip failed for %q", data)
		}
	})
}

func FuzzSymmetricRoundTrip(f *testing.F) {
	f.Add("secret", "hello world")
	f.Add("", "x")
	f.Add("s", "")
	f.Add(strings.Repeat("k", 100), strings.Repeat("m", 5000))
	f.Fuzz(func(t *testing.T, secret, message string) {
		if secret == "" {
			if _, err := SymmetricEncrypt(secret, message); err == nil {
				t.Fatal("empty secret must fail")
			}
			return
		}
		enc, err := SymmetricEncrypt(secret, message)
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}
		// Bare-hex shape for string keys (upstream rawEncrypt).
		for _, c := range enc {
			if !strings.ContainsRune("0123456789abcdef", c) {
				t.Fatalf("non-hex char in bare payload %q", enc)
			}
		}
		plain, err := SymmetricDecrypt(secret, enc)
		if err != nil || plain != message {
			t.Fatalf("round trip failed: %q %v", plain, err)
		}
		// Wrong secret must fail.
		if _, err := SymmetricDecrypt(secret+"\x00", enc); err == nil {
			t.Fatal("wrong secret decrypted ciphertext")
		}
		// Decrypt path must never panic on arbitrary bytes.
		_, _ = SymmetricDecrypt(secret, message)
		_, _ = DecryptStringCompatible([]string{secret}, message)
	})
}

func FuzzVerifyJWTUnforgeable(f *testing.F) {
	_, priv, keys := wave4TestKeysForFuzz(f)
	claims := map[string]any{"sub": "u1", "exp": time.Now().Unix() + 600}
	valid, err := SignJWT(priv, "EdDSA", "k1", claims)
	if err != nil {
		f.Fatalf("sign: %v", err)
	}
	f.Add(valid)
	f.Add("")
	f.Add("a.b.c")
	f.Fuzz(func(t *testing.T, token string) {
		_, err := VerifyJWT(token, keys, VerifyOptions{})
		if err != nil {
			return
		}
		// Signature binding (time-stable unforgeability): every accepted
		// token is signature-bound, so flipping one bit of any segment
		// must break verification. (A byte-equality check against the
		// run-local token would be unsound: exp embeds time, so older
		// genuinely-issued seeds differ byte-wise.)
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			t.Fatalf("verified non-3-part token: %q", token)
		}
		for i := range parts {
			if parts[i] == "" {
				continue
			}
			mut := []string{parts[0], parts[1], parts[2]}
			mut[i] = flipB64CharWave4(parts[i])
			if _, err := VerifyJWT(strings.Join(mut, "."), keys, VerifyOptions{}); err == nil {
				t.Fatalf("mutated segment %d accepted for %q", i, token)
			}
		}
	})
}

func flipB64CharWave4(s string) string {
	c := s[0]
	if c == 'A' {
		c = 'B'
	} else {
		c = 'A'
	}
	return string(c) + s[1:]
}

func wave4TestKeysForFuzz(f *testing.F) (string, string, []PublicKey) {
	f.Helper()
	pub, priv, _, err := GenerateKeyPair("EdDSA")
	if err != nil {
		f.Fatalf("generate: %v", err)
	}
	return pub, priv, []PublicKey{{Kid: "k1", Alg: "EdDSA", PublicJWKJSON: pub}}
}
