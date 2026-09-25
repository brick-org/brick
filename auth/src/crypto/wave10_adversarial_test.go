package crypto

// AUTH-V10-02 adversarial conformance (tests only; upstream v1.7.5 @5468e6bf; fuzz caps: passwords ≤1KiB, hashes ≤4KiB, tokens ≤64KiB).

import (
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Scrypt cost (N=16384, r=16) is upstream parity; fuzzer exercises parser only.
const wave10MaxFuzzPasswordLen = 1024
const wave10MaxFuzzHashLen = 4096

// Fail closed on every malformed shape, any size, no panic.
func TestWave10_PasswordSizeCaps(t *testing.T) {
	hash, err := HashPassword("correct horse")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if !VerifyPassword(hash, "correct horse") {
		t.Fatal("valid password must verify")
	}
	if VerifyPassword(hash, "wrong") {
		t.Fatal("wrong password must not verify")
	}

	bads := map[string]string{
		"empty":            "",
		"no separator":     "abc123",
		"three parts":      "a:b:c",
		"non-hex salt":     "zzzz:abcd",
		"short salt":       "00:00",
		"short key":        strings.Repeat("aa", 16) + ":" + "bb",
		"1MB hash":         strings.Repeat("x", 1<<20),
		"1MB password key": strings.Repeat("y", 1<<20),
		"null bytes":       "a\x00b:c\x00d",
		"bcrypt garbage":   "$2a$10$" + strings.Repeat("0", 53),
	}
	for name, bad := range bads {
		if VerifyPassword(bad, "anything") {
			t.Errorf("%s: malformed hash must fail closed", name)
		}
		if VerifyPassword(hash, bad) && name == "1MB password key" {
			t.Errorf("%s: megabyte password must not verify against an unrelated hash", name)
		}
	}
	// 16KiB password must terminate (fail closed, once; scrypt dominates).
	if VerifyPassword(hash, strings.Repeat("p", 1<<14)) {
		t.Error("16KiB password must not verify against an unrelated hash")
	}

	// Bcrypt bridge: real bcrypt verifies; bcrypt-shaped garbage does not.
	bcryptHash, err := bcrypt.GenerateFromPassword([]byte("legacy-pass"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt hash: %v", err)
	}
	if !VerifyPassword(string(bcryptHash), "legacy-pass") {
		t.Error("bcrypt migration hash must verify")
	}
	if VerifyPassword(string(bcryptHash), "other-pass") {
		t.Error("bcrypt migration hash must reject the wrong password")
	}
}

// Rotation: retained kids verify, dropped fail closed, race-clean, no foreign-kid accept.
func TestWave10_KeyRotationDuringVerifyRace(t *testing.T) {
	pub1, priv1, _, err := GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatalf("generate k1: %v", err)
	}
	pub2, priv2, _, err := GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatalf("generate k2: %v", err)
	}
	oldSet := []PublicKey{{Kid: "k1", Alg: "EdDSA", PublicJWKJSON: pub1}}
	bothSets := [][]PublicKey{
		{{Kid: "k1", Alg: "EdDSA", PublicJWKJSON: pub1}, {Kid: "k2", Alg: "EdDSA", PublicJWKJSON: pub2}},
		{{Kid: "k2", Alg: "EdDSA", PublicJWKJSON: pub2}, {Kid: "k1", Alg: "EdDSA", PublicJWKJSON: pub1}},
	}
	newSet := []PublicKey{{Kid: "k2", Alg: "EdDSA", PublicJWKJSON: pub2}}

	preRotation, err := SignJWT(priv1, "EdDSA", "k1", map[string]any{"sub": "u", "exp": time.Now().Unix() + 600})
	if err != nil {
		t.Fatalf("sign pre-rotation: %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan string, 512)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				// Old token verifies under both retained orderings.
				for _, set := range bothSets {
					if _, err := VerifyJWT(preRotation, set, VerifyOptions{}); err != nil {
						errs <- "pre-rotation token rejected during rotation"
						return
					}
				}
				// New token verifies; old-only set rejects (exact kid, no fallback).
				fresh, err := SignJWT(priv2, "EdDSA", "k2", map[string]any{"sub": "u", "exp": time.Now().Unix() + 60})
				if err != nil {
					errs <- "sign during rotation failed"
					return
				}
				if _, err := VerifyJWT(fresh, newSet, VerifyOptions{}); err != nil {
					errs <- "post-rotation token rejected"
					return
				}
				if _, err := VerifyJWT(fresh, oldSet, VerifyOptions{}); err == nil {
					errs <- "new-kid token verified against retired set"
					return
				}
				// Foreign key with colliding kid never verifies.
				if _, err := VerifyJWT(preRotation, []PublicKey{{Kid: "k1", Alg: "EdDSA", PublicJWKJSON: pub2}}, VerifyOptions{}); err == nil {
					errs <- "cross-key kid collision verified"
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
}

// Oversized XChaCha fails at hex decode; rotation race-clean.
func TestWave10_XChaChaSizeAndRotationRace(t *testing.T) {
	cfg := SecretConfig{Keys: map[int]string{1: "s1", 2: "s2"}, CurrentVersion: 2}
	for _, big := range []string{strings.Repeat("z", 1<<20), strings.Repeat("0", 1<<20), "$ba$1$" + strings.Repeat("z", 1<<20)} {
		if _, err := SymmetricDecrypt("secret", big); err == nil {
			t.Errorf("1MB payload %q... must fail closed", big[:8])
		}
		if _, err := SymmetricDecrypt(cfg, big); err == nil {
			t.Errorf("1MB payload %q... must fail closed under rotation", big[:8])
		}
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				env, err := SymmetricEncrypt(cfg, "race-payload")
				if err != nil {
					t.Errorf("encrypt: %v", err)
					return
				}
				if back, err := SymmetricDecrypt(cfg, env); err != nil || back != "race-payload" {
					t.Errorf("rotation round trip = %q, %v", back, err)
					return
				}
				if _, _, ok := ParseEnvelope(env); !ok {
					t.Error("fresh envelope must parse")
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

// Fuzzes password parser with work caps (oversize skips; parser rejects before scrypt).
func FuzzWave10_VerifyPasswordParser(f *testing.F) {
	seedHash, err := HashPassword("seed-password")
	if err != nil {
		f.Fatalf("seed hash: %v", err)
	}
	f.Add(seedHash, "seed-password")
	f.Add(seedHash, "wrong")
	f.Add("", "")
	f.Add("a:b:c", "x")
	f.Add("$2a$10$"+strings.Repeat("0", 53), "x")
	f.Add(strings.Repeat("a", 5000), strings.Repeat("b", 2000))
	f.Fuzz(func(t *testing.T, hash, password string) {
		if len(hash) > wave10MaxFuzzHashLen || len(password) > wave10MaxFuzzPasswordLen {
			t.Skip("over wave10 work cap")
		}
		got := VerifyPassword(hash, password)
		// Determinism check.
		if again := VerifyPassword(hash, password); again != got {
			t.Fatalf("nondeterministic verify of %q", hash)
		}
		// Parser: only hex(16B-salt):hex(64B-key) or real bcrypt passes.
		parts := strings.Split(hash, ":")
		if len(parts) != 2 && !strings.HasPrefix(hash, "$2a$") && !strings.HasPrefix(hash, "$2b$") && !strings.HasPrefix(hash, "$2y$") {
			if got {
				t.Fatalf("non-conforming hash verified: %q", hash)
			}
		}
	})
}

// Fuzzes compact JWT decoder (64KiB cap; accepted are 3-part deterministic).
func FuzzWave10_CompactJWTStructure(f *testing.F) {
	pub, priv, _, err := GenerateKeyPair("EdDSA")
	if err != nil {
		f.Fatalf("generate: %v", err)
	}
	keys := []PublicKey{{Kid: "k1", Alg: "EdDSA", PublicJWKJSON: pub}}
	valid, err := SignJWT(priv, "EdDSA", "k1", map[string]any{"sub": "u", "exp": time.Now().Unix() + 600})
	if err != nil {
		f.Fatalf("sign: %v", err)
	}
	f.Add(valid)
	f.Add("")
	f.Add("a.b.c")
	f.Add("eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.c2ln")
	f.Add(strings.Repeat("A", 1<<16))
	f.Fuzz(func(t *testing.T, token string) {
		if len(token) > 1<<16 {
			t.Skip("over wave10 64KiB cap")
		}
		claims, err := VerifyJWT(token, keys, VerifyOptions{})
		if err != nil {
			return
		}
		if len(strings.Split(token, ".")) != 3 {
			t.Fatalf("accepted non-3-part token: %q", token)
		}
		if claims["sub"] == nil && claims["exp"] == nil {
			t.Fatalf("accepted token carries no claims: %q", token)
		}
		again, err := VerifyJWT(token, keys, VerifyOptions{})
		if err != nil || len(again) != len(claims) {
			t.Fatalf("nondeterministic verify of %q", token)
		}
	})
}

// Fuzzes XChaCha decrypt (capped; oversize-hex at decode; deterministic).
func FuzzWave10_SymmetricDecryptCaps(f *testing.F) {
	cfg := SecretConfig{Keys: map[int]string{1: "w10-s1", 2: "w10-s2"}, CurrentVersion: 2}
	env, err := SymmetricEncrypt(cfg, "seed")
	if err != nil {
		f.Fatalf("encrypt: %v", err)
	}
	bare, err := SymmetricEncrypt("w10-single", "seed")
	if err != nil {
		f.Fatalf("encrypt bare: %v", err)
	}
	f.Add(env)
	f.Add(bare)
	f.Add("")
	f.Add("$ba$99$deadbeef")
	f.Add(strings.Repeat("0", 1<<16))
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 1<<16 {
			t.Skip("over wave10 64KiB cap")
		}
		for _, key := range []any{"w10-single", cfg} {
			first, err := SymmetricDecrypt(key, input)
			if err != nil {
				continue
			}
			second, err := SymmetricDecrypt(key, input)
			if err != nil || second != first {
				t.Fatalf("nondeterministic decrypt of %q", input)
			}
		}
	})
}
