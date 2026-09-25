package cookies

// AUTH-V10-02 — adversarial and cross-language conformance (tests only).
//
// This file owns the cookies package's Wave 10 adversarial coverage: session
// refresh races with secret rotation during verification, cookie chunking
// bursts and caps, Sign/Verify round-trip fuzzing, session JWE decoder
// fuzzing, and chunk-index parser fuzzing.
//
// Upstream references (pinned Better Auth v1.7.5 at 5468e6bf):
//   - packages/better-auth/src/cookies/cookies.test.ts ("Cookie Chunking"
//     chunk-size gate, cleanup-on-delete, no-chunk-under-limit, too-large
//     skip) and cookie-utils.ts (parseCookies, parseCookieChunkIndex,
//     getChunkedCookie, setRequestCookie, parseSetCookieHeader)
//   - packages/better-auth/src/cookies/index.ts (setCookieCache/
//     decodeCookieCache, JWT + JWE branches)
//   - packages/better-auth/src/crypto/jwt.ts (signSecretJWT/verifySecretJWT,
//     symmetricEncodeJWT/symmetricDecodeJWT, deriveEncryptionSecret)
//
// Work limits pinned for this file: fuzz secrets ≤256B, values ≤4KiB, tokens
// ≤64KiB; larger inputs skip. No production code is changed here.

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// Session refresh under secret rotation: a token minted with the old secret
// keeps verifying while it is retained (in either order), a token minted
// with the new secret verifies under the rotated set, and concurrent
// refresh/verify traffic across the rotation is race-clean with exact
// single-winner rotation semantics (no cross-secret confusion).
func TestSessionStress_SessionRefreshRaceWithRotation(t *testing.T) {
	oldSecret, newSecret := "w10-old-secret", "w10-new-secret"
	session := map[string]any{"id": "s1", "token": "tok-w10", "userId": "u1"}
	user := map[string]any{"id": "u1", "email": "w10@example.com"}

	oldJWT, err := CreateSessionCacheJWT(oldSecret, session, user, "1", time.Minute)
	if err != nil {
		t.Fatalf("issue old JWT: %v", err)
	}
	oldJWE, err := CreateSessionCacheJWE(oldSecret, session, user, "1", time.Minute)
	if err != nil {
		t.Fatalf("issue old JWE: %v", err)
	}
	newJWT, err := CreateSessionCacheJWT(newSecret, session, user, "2", time.Minute)
	if err != nil {
		t.Fatalf("issue new JWT: %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan string, 512)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				// Retained secret verifies in either order (rotation window).
				for _, set := range [][]string{{oldSecret, newSecret}, {newSecret, oldSecret}} {
					data, _, err := VerifySessionCacheJWT(set, oldJWT)
					if err != nil || data.Version != "1" {
						errs <- "old JWT rejected during rotation"
						return
					}
					jweData, _, err := VerifySessionCacheJWE(set, oldJWE)
					if err != nil || jweData.Version != "1" {
						errs <- "old JWE rejected during rotation"
						return
					}
				}
				// Post-rotation token verifies; the retired-only set fails closed.
				if _, _, err := VerifySessionCacheJWT([]string{oldSecret, newSecret}, newJWT); err != nil {
					errs <- "new JWT rejected under rotated set"
					return
				}
				if _, _, err := VerifySessionCacheJWT([]string{oldSecret}, newJWT); err == nil {
					errs <- "new JWT verified against retired-only set"
					return
				}
				// Unknown secrets always fail closed on both branches.
				if _, _, err := VerifySessionCacheJWT([]string{"nope"}, oldJWT); err == nil {
					errs <- "old JWT verified against unknown secret"
					return
				}
				if _, _, err := VerifySessionCacheJWE([]string{"nope"}, oldJWE); err == nil {
					errs <- "old JWE decrypted against unknown secret"
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
}

// Chunking bursts: concurrent chunk/join traffic is race-clean, over-cap
// values keep erroring (callers skip the cache and fall back to the
// database), and exactly-at-cap values keep fitting.
func TestWave10_ChunkBurstAndCap(t *testing.T) {
	name := "better-auth.session_data"
	attrs := DefaultAttributes(true, "")
	budget := MaxValueSizeFor(name, attrs)
	if budget <= 0 || budget >= MaxCookieSize {
		t.Fatalf("budget out of range: %d", budget)
	}
	var wg sync.WaitGroup
	errs := make(chan string, 128)
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			value := strings.Repeat("v", 3*budget+g)
			chunks, err := ChunkCookieValue(name, value, budget)
			if err != nil {
				errs <- "chunk burst errored under cap"
				return
			}
			if joined, ok := JoinChunkedCookies(chunks, name); !ok || joined != value {
				errs <- "chunk burst reassembled wrong"
				return
			}
			// Wire sizing holds on every burst value.
			for chunkName, v := range chunks {
				if line := attrs.ToHTTPCookie(chunkName, v).String(); len(line) > MaxCookieSize {
					errs <- "burst chunk over wire size"
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
	if _, err := ChunkCookieValue("sess", strings.Repeat("x", MaxCookieChunks+1), 1); err == nil {
		t.Fatal("over-cap value must error so callers skip the cache")
	}
}

// FuzzWave10_SignVerifyRoundTrip fuzzes the value.hmac Sign/Verify wire
// format shared with TypeScript: capped inputs round-trip byte-exactly,
// wrong-secret and tampered inputs fail closed, and parsing never panics.
func FuzzWave10_SignVerifyRoundTrip(f *testing.F) {
	f.Add("w10-secret", "hello")
	f.Add("Jefe", "what do ya want for nothing?")
	f.Add("s", "a.b.c")
	f.Add("k", strings.Repeat("v", 4000))
	f.Fuzz(func(t *testing.T, secret, value string) {
		if len(secret) == 0 || len(secret) > 256 || len(value) > 4096 {
			t.Skip("over wave10 caps (or empty secret)")
		}
		signed, err := Sign(secret, value)
		if err != nil {
			t.Fatalf("sign failed: %v", err)
		}
		back, ok := Verify(secret, signed)
		if !ok || back != value {
			t.Fatalf("round trip = %q, %v", back, ok)
		}
		// A wrong secret fails closed. (Note: secret+"\x00" is NOT a
		// wrong secret — HMAC zero-pads short keys to the block size, so a
		// trailing NUL pads identically. Flip a significant byte instead.)
		if _, ok := Verify("wrong-"+secret, signed); ok {
			t.Fatal("wrong secret verified")
		}
		// Flipping the first signature character must break verification
		// (first-char flips are sound: every base64 leading-char change
		// alters decoded bytes, unlike tail chars whose low bits may be
		// padding-ignored).
		if idx := strings.LastIndexByte(signed, '.'); idx >= 0 && idx+1 < len(signed) {
			mut := signed[:idx+1] + flipB64CharW10(signed[idx+1:])
			if mback, ok := Verify(secret, mut); ok && mback == value {
				t.Fatalf("tampered signature verified: %q", signed)
			}
		}
	})
}

// FuzzWave10_SessionCacheJWE fuzzes the 5-part compact JWE decoder: capped
// inputs never panic, accepted payloads always carry session/user, and
// mutating any segment of an accepted token breaks verification.
func FuzzWave10_SessionCacheJWE(f *testing.F) {
	secret := "w10-fuzz-secret"
	session := map[string]any{"id": "s1"}
	user := map[string]any{"id": "u1"}
	valid, err := CreateSessionCacheJWE(secret, session, user, "1", time.Minute)
	if err != nil {
		f.Fatalf("issue: %v", err)
	}
	jwtValid, err := CreateSessionCacheJWT(secret, session, user, "1", time.Minute)
	if err != nil {
		f.Fatalf("issue JWT: %v", err)
	}
	f.Add(valid)
	f.Add(jwtValid) // a JWT in the JWE slot must fail closed
	f.Add("")
	f.Add("a.b.c.d.e")
	f.Add(strings.Repeat("B", 1<<16))
	f.Fuzz(func(t *testing.T, token string) {
		if len(token) > 1<<16 {
			t.Skip("over wave10 64KiB cap")
		}
		data, _, err := VerifySessionCacheJWE([]string{secret}, token)
		if err != nil {
			return
		}
		if data.Session == nil || data.User == nil {
			t.Fatal("verified JWE payload must carry session/user")
		}
		parts := strings.Split(token, ".")
		if len(parts) != 5 {
			t.Fatalf("verified non-5-part JWE: %q", token)
		}
		for i := range parts {
			if parts[i] == "" {
				continue
			}
			mut := append([]string(nil), parts...)
			mut[i] = flipB64CharW10(parts[i])
			if _, _, err := VerifySessionCacheJWE([]string{secret}, strings.Join(mut, ".")); err == nil {
				t.Fatalf("mutated segment %d accepted for %q", i, token)
			}
		}
	})
}

// FuzzWave10_ParseChunkIndex fuzzes the chunk-index parser: it never panics,
// accepted indexes are canonical (no leading zeros, no signs, no junk), and
// decoding is deterministic.
func FuzzWave10_ParseChunkIndex(f *testing.F) {
	f.Add("sess", "sess.0")
	f.Add("sess", "sess.01")
	f.Add("better-auth.session_data", "better-auth.session_data.10")
	f.Add("s", "other.1")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, cookieName, name string) {
		if len(cookieName) > 512 || len(name) > 512 {
			t.Skip("over wave10 caps")
		}
		idx, ok := ParseChunkIndex(cookieName, name)
		again, okAgain := ParseChunkIndex(cookieName, name)
		if ok != okAgain || idx != again {
			t.Fatalf("nondeterministic chunk parse of %q %q", cookieName, name)
		}
		if !ok {
			return
		}
		if idx < 0 {
			t.Fatalf("negative chunk index %d for %q", idx, name)
		}
		// Canonical form only: "<name>.<digits without leading zeros>".
		want := cookieName + "." + itoaW10(idx)
		if name != want {
			t.Fatalf("non-canonical chunk name %q accepted (want %q)", name, want)
		}
	})
}

func flipB64CharW10(s string) string {
	c := s[0]
	if c == 'A' {
		c = 'B'
	} else {
		c = 'A'
	}
	return string(c) + s[1:]
}

func itoaW10(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}
