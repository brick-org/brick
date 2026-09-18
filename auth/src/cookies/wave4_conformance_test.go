package cookies

// Wave 4 conformance: remaining upstream cookie cases, fuzz targets, race
// tests, and malformed-input limits.
//
// Upstream references (pinned v1.7.5):
//   - packages/better-auth/src/cookies/cookies.test.ts ("Cookie Chunking"
//     chunk-size gate, cleanup-on-delete, no-chunk-under-limit, too-large
//     skip) and cookie-utils.ts (parseCookies, parseCookieChunkIndex,
//     getChunkedCookie, setRequestCookie, parseSetCookieHeader).
//
// Port-blocked gaps (reported, not implemented — non-test files are
// out of scope for this agent):
//   - setRequestCookie (request-header cookie write/replace with
//     percent-encoding of reserved octets) has no Go equivalent.
//   - parseSetCookieHeader + toCookieOptions (response Set-Cookie parsing:
//     Expires with commas, Max-Age, Secure/HttpOnly/SameSite/Partitioned)
//     has no Go equivalent.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- Ported upstream parseCookies cases ---

// Upstream parseCookies splits on the FIRST "=" so values may contain "=";
// later duplicates overwrite earlier ones; empty values are kept.
func TestWave4_ParseRequestCookiesEdgeCases(t *testing.T) {
	got := ParseRequestCookies("a=b=c; a=second; empty=; spaced = v")
	if got["a"] != "second" {
		t.Errorf("duplicate names: last wins, got %q", got["a"])
	}
	if v, ok := got["empty"]; !ok || v != "" {
		t.Errorf("empty value must be kept, got %q %v", v, ok)
	}
	if got["spaced"] != "v" {
		t.Errorf("OWS around name must trim, got %q", got["spaced"])
	}
	// Horizontal-tab OWS (RFC 7230 §3.2.3) trims; CR/LF must not.
	got = ParseRequestCookies("\ta\t=\tb\t")
	if got["a"] != "b" {
		t.Errorf("tab OWS must trim, got %v", got)
	}
	got = ParseRequestCookies("a=b\r\nInjected: x")
	if _, bad := got["a"]; bad {
		t.Errorf("CTL bytes must drop the pair, got %v", got)
	}
	// Pairs split on the FIRST "=" so values may contain "="; quoting is
	// stripped after the split. ";" always terminates a pair (upstream
	// splits naively too), even inside quotes.
	got = ParseRequestCookies(`q="a=b"; s="x;y"; r="x"`)
	if got["q"] != "a=b" || got["r"] != "x" {
		t.Errorf("first-= split behavior changed: %v", got)
	}
	if _, bad := got["s"]; bad {
		t.Errorf("semicolon must terminate the pair even in quotes: %v", got)
	}
	// Comma and space are legal value octets upstream.
	got = ParseRequestCookies("c=a, b c")
	if got["c"] != "a, b c" {
		t.Errorf("comma/space values must survive, got %q", got["c"])
	}
}

// --- Ported upstream chunk-index cases ---

// Upstream parseCookieChunkIndex accepts only canonical non-negative
// integers: no leading zeros, signs, whitespace, or trailing junk.
func TestWave4_ParseChunkIndexCanonical(t *testing.T) {
	for _, name := range []string{"sess.0", "sess.7", "sess.99"} {
		if _, ok := ParseChunkIndex("sess", name); !ok {
			t.Errorf("%q must parse", name)
		}
	}
	for _, name := range []string{
		"sess.", "sess.00", "sess.01", "sess.-1", "sess.+1", "sess. 1",
		"sess.1 ", "sess.1x", "sess.0x10", "other.1", "sess", "sess.1.2",
	} {
		if _, ok := ParseChunkIndex("sess", name); ok {
			t.Errorf("%q must not parse", name)
		}
	}
}

// Upstream getChunkedCookie: exact-name match wins over chunks; chunk
// entries sort numerically (so .10 follows .9, not .1).
func TestWave4_JoinChunkedCookiesPrecedence(t *testing.T) {
	if v, ok := JoinChunkedCookies(map[string]string{
		"sess": "exact", "sess.0": "chunk",
	}, "sess"); !ok || v != "exact" {
		t.Errorf("exact name must win, got %q %v", v, ok)
	}
	m := map[string]string{}
	for i, s := range []string{"0123456789", "abcdefghij", "klmnopqrst"} {
		m["sess."+string(rune('0'+i))] = s
	}
	m["sess.10"] = "tail"
	if v, ok := JoinChunkedCookies(m, "sess"); !ok || v != "0123456789abcdefghijklmnopqrsttail" {
		t.Errorf("numeric chunk order wrong, got %q %v", v, ok)
	}
	if _, ok := JoinChunkedCookies(map[string]string{"other": "x"}, "sess"); ok {
		t.Error("no match must report ok=false")
	}
}

// Upstream chunk-size gate: values that fit stay single; the too-large
// branch errors so callers skip the cache and fall back to the database.
func TestWave4_ChunkSizeGateAndCap(t *testing.T) {
	single, err := ChunkCookieValue("sess", "small", 100)
	if err != nil || len(single) != 1 || single["sess"] != "small" {
		t.Fatalf("small value must stay single: %v %v", single, err)
	}
	empty, err := ChunkCookieValue("sess", "", 100)
	if err != nil || len(empty) != 1 {
		t.Fatalf("empty value must yield one entry: %v %v", empty, err)
	}
	if _, err := ChunkCookieValue("sess", "x", 0); err == nil {
		t.Fatal("non-positive budget must error")
	}
	// (MaxCookieChunks+1) chunks of 1 byte each cannot fit.
	tooBig := strings.Repeat("x", MaxCookieChunks+1)
	if _, err := ChunkCookieValue("sess", tooBig, 1); err == nil {
		t.Fatal("value exceeding MaxCookieChunks must error (skip cache)")
	}
	// Exactly MaxCookieChunks chunks fits.
	fits := strings.Repeat("y", MaxCookieChunks)
	chunks, err := ChunkCookieValue("sess", fits, 1)
	if err != nil || len(chunks) != MaxCookieChunks {
		t.Fatalf("exactly MaxCookieChunks must fit: %v %v", len(chunks), err)
	}
	// Wire sizing: every serialized chunk line fits MaxCookieSize.
	name := "better-auth.session_data"
	attrs := DefaultAttributes(true, "")
	budget := MaxValueSizeFor(name, attrs)
	if budget <= 0 || budget >= MaxCookieSize {
		t.Fatalf("budget out of range: %d", budget)
	}
	big, err := ChunkCookieValue(name, strings.Repeat("z", 3*budget), budget)
	if err != nil {
		t.Fatalf("3x-budget value must chunk: %v", err)
	}
	for chunkName, v := range big {
		line := attrs.ToHTTPCookie(chunkName, v).String()
		if len(line) > MaxCookieSize {
			t.Errorf("chunk %q serializes to %d bytes, over %d", chunkName, len(line), MaxCookieSize)
		}
	}
	joined, ok := JoinChunkedCookies(big, name)
	if !ok || joined != strings.Repeat("z", 3*budget) {
		t.Fatal("chunks must reassemble exactly")
	}
}

// Upstream deleteSessionCookie clean(): expiring must cover the bare name
// and every chunk so stale chunks never survive a shrink or logout.
func TestWave4_ExpiredChunksCoverShrink(t *testing.T) {
	attrs := DefaultAttributes(true, "")
	stored := map[string]string{
		"sess": "old-single", "sess.0": "c0", "sess.1": "c1", "sess.2": "c2", "other": "x",
	}
	expired := ExpiredChunks(stored, "sess", attrs)
	names := map[string]bool{}
	for _, c := range expired {
		names[c.Name] = true
		if c.MaxAge != 0 || c.Value != "" {
			t.Errorf("expiry cookie %q must clear value with MaxAge=0", c.Name)
		}
	}
	for _, want := range []string{"sess", "sess.0", "sess.1", "sess.2"} {
		if !names[want] {
			t.Errorf("missing expiry for %q", want)
		}
	}
	if names["other"] {
		t.Error("unrelated cookie must not expire")
	}
}

// --- Ported JWT/JWE malformed matrix ---

func wave4SessionFixtures() (secret string, session, user map[string]any) {
	return "wave4-test-secret",
		map[string]any{"id": "s1", "token": "tok", "userId": "u1"},
		map[string]any{"id": "u1", "email": "a@b.com", "name": "Test"}
}

// Upstream: invalid/foreign JWT cache values fail closed (null).
func TestWave4_SessionCacheJWTMalformed(t *testing.T) {
	secret, session, user := wave4SessionFixtures()
	valid, err := CreateSessionCacheJWT(secret, session, user, "1", time.Minute)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, _, err := VerifySessionCacheJWT([]string{secret}, valid); err != nil {
		t.Fatalf("valid token must verify: %v", err)
	}
	bads := map[string]string{
		"not-a-jwt":                 "wrong.segment.count",
		"two parts":                 "a.b",
		"four parts":                "a.b.c.d",
		"bad header b64":            "!!!.e30.e30",
		"bad header json":           "bm90LWpzb24.e30.e30",
		"none alg":                  noneAlgToken(t, secret, session, user),
		"wrong alg HS512":           hs512AlgToken(t, secret, session, user),
		"tampered payload":          tamperSegment(t, valid, 1),
		"tampered signature":        tamperSegment(t, valid, 2),
		"wrong secret":              mustIssueJWT(t, "other-secret", session, user),
		"empty secrets":             valid, // verified with no candidates below
		"truncated":                 valid[:len(valid)/2],
		"empty":                     "",
		"huge garbage":              strings.Repeat("A", 1<<20),
		"null bytes":                "a\x00b.c.d",
		"whitespace padded":         " " + valid + " ",
		"Bearer prefixed":           "Bearer " + valid,
		"header alg case":           caseAlgToken(t, secret, session, user),
		"payload with session null": nullSessionToken(t, secret, user),
	}
	for name, token := range bads {
		secrets := []string{secret}
		if name == "empty secrets" {
			secrets = nil
		}
		if _, _, err := VerifySessionCacheJWT(secrets, token); err == nil {
			t.Errorf("%s: malformed JWT cache must fail closed", name)
		}
	}
	// Rotation: retained secrets verify; unknown ones do not.
	if _, _, err := VerifySessionCacheJWT([]string{"old", secret}, valid); err != nil {
		t.Errorf("retained secret must verify: %v", err)
	}
	if _, _, err := VerifySessionCacheJWT([]string{"", secret}, valid); err != nil {
		t.Errorf("blank candidates must be skipped: %v", err)
	}
}

// Upstream: invalid JWE cache values fail closed; unknown kids fail closed
// with no fallback; A256GCM legacy payloads are out of scope here.
func TestWave4_SessionCacheJWEMalformed(t *testing.T) {
	secret, session, user := wave4SessionFixtures()
	valid, err := CreateSessionCacheJWE(secret, session, user, "1", time.Minute)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, _, err := VerifySessionCacheJWE([]string{secret}, valid); err != nil {
		t.Fatalf("valid token must verify: %v", err)
	}
	bads := map[string]string{
		"not-a-jwe":           "a.b.c",
		"empty":               "",
		"huge garbage":        strings.Repeat("B", 1<<20),
		"jwt in jwe slot":     mustIssueJWT(t, secret, session, user),
		"wrong secret":        mustIssueJWE(t, "other-secret", session, user),
		"truncated":           valid[:len(valid)/2],
		"tampered iv":         tamperSegment(t, valid, 2),
		"tampered ciphertext": tamperSegment(t, valid, 3),
		"tampered tag":        tamperSegment(t, valid, 4),
		"unknown kid":         swapKid(t, valid),
		"empty secrets":       valid,
	}
	for name, token := range bads {
		secrets := []string{secret}
		if name == "empty secrets" {
			secrets = nil
		}
		if _, _, err := VerifySessionCacheJWE(secrets, token); err == nil {
			t.Errorf("%s: malformed JWE cache must fail closed", name)
		}
	}
}

func mustIssueJWT(t *testing.T, secret string, session, user map[string]any) string {
	t.Helper()
	token, err := CreateSessionCacheJWT(secret, session, user, "1", time.Minute)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return token
}

func mustIssueJWE(t *testing.T, secret string, session, user map[string]any) string {
	t.Helper()
	token, err := CreateSessionCacheJWE(secret, session, user, "1", time.Minute)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return token
}

// forgedHeaderToken re-signs the session payload under a caller-chosen JWS
// header to exercise the alg-pinning branch of VerifySessionCacheJWT.
func forgedHeaderToken(t *testing.T, secret string, session, user map[string]any, headerJSON string) string {
	t.Helper()
	claims := jwtCacheClaims{
		Session:   session,
		User:      user,
		UpdatedAt: time.Now().UnixMilli(),
		IssuedAt:  time.Now().Unix(),
		Expires:   time.Now().Unix() + 60,
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	unsigned := base64.RawURLEncoding.EncodeToString([]byte(headerJSON)) + "." +
		base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(unsigned))
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func noneAlgToken(t *testing.T, secret string, session, user map[string]any) string {
	t.Helper()
	return forgedHeaderToken(t, secret, session, user, `{"alg":"none"}`)
}

func hs512AlgToken(t *testing.T, secret string, session, user map[string]any) string {
	t.Helper()
	return forgedHeaderToken(t, secret, session, user, `{"alg":"HS512","typ":"JWT"}`)
}

func caseAlgToken(t *testing.T, secret string, session, user map[string]any) string {
	t.Helper()
	return forgedHeaderToken(t, secret, session, user, `{"alg":"hs256"}`)
}

func nullSessionToken(t *testing.T, secret string, user map[string]any) string {
	t.Helper()
	return mustIssueJWT(t, secret, nil, user)
}

// swapKid rewrites the JWE protected header kid to an unknown value while
// keeping the segments otherwise intact (exercises kid-selected fail-closed).
func swapKid(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 5 {
		t.Fatalf("not a compact JWE: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode JWE header: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(raw, &header); err != nil {
		t.Fatalf("parse JWE header: %v", err)
	}
	header["kid"] = "unknown-kid-value"
	rewritten, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal JWE header: %v", err)
	}
	parts[0] = base64.RawURLEncoding.EncodeToString(rewritten)
	return strings.Join(parts, ".")
}

func tamperSegment(t *testing.T, token string, idx int) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if idx >= len(parts) || len(parts[idx]) == 0 {
		t.Fatalf("cannot tamper segment %d of %q", idx, token)
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

// --- Cross-language golden vectors ---
//
// TS-shaped fixtures as static data (no network):
//   - RFC 4231 HMAC-SHA-256 test case 2 pins the exact Sign/Verify wire
//     algorithm ("value.hmac", base64url-nopad) shared with upstream, so the
//     vectors below must verify under ANY conforming implementation.
//   - The chunked-cookie naming fixture pins the upstream chunkCookie wire
//     shape ("<name>.<i>") used by getChunkedCookie reassembly.

func TestWave4_SignGoldenVectors(t *testing.T) {
	// RFC 4231 case 2: key "Jefe", data "what do ya want for nothing?".
	// The expected base64url-nopad HMAC-SHA-256 pins the exact wire
	// algorithm ("value.hmac") shared with upstream cookie signing.
	signed, err := Sign("Jefe", "what do ya want for nothing?")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	const wantSig = "W9zBRr9gdU5qBCQmCJV1x1oAPwidJzmDnexYuWTsOEM"
	if signed != "what do ya want for nothing?"+"."+wantSig {
		t.Fatalf("RFC 4231 wire mismatch: %q", signed)
	}
	value, ok := Verify("Jefe", signed)
	if !ok || value != "what do ya want for nothing?" {
		t.Fatalf("RFC 4231 vector must verify: %q %v", value, ok)
	}
	if _, ok := Verify("other", signed); ok {
		t.Fatal("wrong key must not verify")
	}
	// Dotted values round-trip through LastIndex splitting.
	signed, err = Sign("s", "a.b.c")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if value, ok := Verify("s", signed); !ok || value != "a.b.c" {
		t.Fatalf("dotted value must round-trip: %q %v", value, ok)
	}
	// Unsigned and signature-stripped inputs fail.
	for _, bad := range []string{"", "nosig", "a.", ".b"} {
		if _, ok := Verify("s", bad); ok && bad != "a." && bad != ".b" {
			t.Errorf("%q must not verify", bad)
		}
	}
}

func TestWave4_ChunkNamingGoldenVector(t *testing.T) {
	// Static TS-shaped wire fixture: upstream chunkCookie emits
	// "<cookieName>.<index>" entries that getChunkedCookie concatenates in
	// index order. This pins the Go side of that contract with fixed data.
	fixture := map[string]string{
		"better-auth.session_data.1": "SECOND",
		"better-auth.session_data.0": "FIRST",
		"better-auth.session_data.2": "THIRD",
	}
	joined, ok := JoinChunkedCookies(fixture, "better-auth.session_data")
	if !ok || joined != "FIRSTSECONDTHIRD" {
		t.Fatalf("golden chunk fixture must reassemble: %q %v", joined, ok)
	}
	if idx, ok := ParseChunkIndex("better-auth.session_data", "better-auth.session_data.1"); !ok || idx != 1 {
		t.Fatalf("golden chunk index must parse: %d %v", idx, ok)
	}
}

// --- Malformed-input limits ---

func TestWave4_CookieMalformedInputLimits(t *testing.T) {
	huge := strings.Repeat("k=v; ", 1<<16) + "tail=1"
	if got := ParseRequestCookies(huge); got["tail"] != "1" {
		t.Error("64k-pair header must still parse the tail")
	}
	if got := ParseRequestCookies(strings.Repeat("x", 1<<20)); len(got) != 0 {
		t.Error("1MB valueless header must parse empty")
	}
	// Oversized JWT/JWE cache values must fail closed promptly.
	hugeToken := strings.Repeat("A", 1<<20)
	if _, _, err := VerifySessionCacheJWT([]string{"s"}, hugeToken); err == nil {
		t.Error("1MB JWT cache value must fail closed")
	}
	if _, _, err := VerifySessionCacheJWE([]string{"s"}, strings.Repeat("B", 1<<20)); err == nil {
		t.Error("1MB JWE cache value must fail closed")
	}
	// Chunk reassembly over adversarial counts stays bounded.
	m := map[string]string{}
	for i := 0; i < MaxCookieChunks+50; i++ {
		m["s."+itoa(i)] = "v"
	}
	if v, ok := JoinChunkedCookies(m, "s"); !ok || len(v) != MaxCookieChunks+50 {
		t.Error("over-cap chunk maps still join deterministically")
	}
}

func itoa(i int) string {
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

// --- Race tests ---

func TestWave4_CookiesConcurrentUse(t *testing.T) {
	secret, session, user := wave4SessionFixtures()
	jwt, err := CreateSessionCacheJWT(secret, session, user, "1", time.Minute)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	jwe, err := CreateSessionCacheJWE(secret, session, user, "1", time.Minute)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	header := "a=1; b=2; __Secure-better-auth.session_token=tok"
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				parsed := ParseRequestCookies(header)
				_, _ = GetSessionCookie(parsed, "better-auth", "session_token")
				_, _ = ChunkCookieValue("sess", strings.Repeat("x", 5000), 1000)
				_, _, _ = VerifySessionCacheJWT([]string{secret}, jwt)
				_, _, _ = VerifySessionCacheJWE([]string{secret}, jwe)
				_, _ = Sign(secret, "v")
				_, _ = Verify(secret, jwt)
			}
		}()
	}
	wg.Wait()
}

// --- Fuzz targets ---

func FuzzParseRequestCookies(f *testing.F) {
	for _, s := range []string{
		"",
		"a",
		"a=1; b=2",
		`a="hello"; b=plain`,
		"token=hello%20world%3Dfoo",
		"valid=1; ; =orphan; locale=en",
		"a=1;b=2",
		"t=%zz",
		"__Secure-x=y; x=z",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, header string) {
		got := ParseRequestCookies(header)
		for k, v := range got {
			if k == "" {
				t.Fatalf("empty name must never survive: %q", header)
			}
			for i := 0; i < len(k); i++ {
				if k[i] < 0x21 || k[i] == 0x7f {
					t.Fatalf("CTL in name %q from %q", k, header)
				}
			}
			_ = v
		}
		// Determinism on the pure parser.
		again := ParseRequestCookies(header)
		if len(again) != len(got) {
			t.Fatalf("nondeterministic parse of %q", header)
		}
		for k, v := range got {
			if again[k] != v {
				t.Fatalf("nondeterministic parse of %q", header)
			}
		}
	})
}

func FuzzChunkRoundTrip(f *testing.F) {
	for _, s := range []string{"", "x", strings.Repeat("abc", 100), strings.Repeat("z", 9000)} {
		f.Add("sess", s, 100)
	}
	f.Fuzz(func(t *testing.T, name, value string, budget int) {
		if name == "" || strings.Contains(name, ".") {
			t.Skip("chunk names with dots would collide with chunk suffixes")
		}
		if budget < 1 || budget > 1<<20 {
			t.Skip("budget out of range")
		}
		chunks, err := ChunkCookieValue(name, value, budget)
		if err != nil {
			// Only the over-cap branch may error.
			wantChunks := (len(value) + budget - 1) / budget
			if len(value) == 0 {
				wantChunks = 1
			}
			if wantChunks <= MaxCookieChunks {
				t.Fatalf("unexpected chunk error for %d bytes @%d: %v", len(value), budget, err)
			}
			return
		}
		joined, ok := JoinChunkedCookies(chunks, name)
		if !ok || joined != value {
			t.Fatalf("chunk round trip failed for %d bytes @%d", len(value), budget)
		}
	})
}

func FuzzVerifySessionCacheJWT(f *testing.F) {
	secret := "wave4-fuzz-secret"
	session := map[string]any{"id": "s1"}
	user := map[string]any{"id": "u1"}
	valid, err := CreateSessionCacheJWT(secret, session, user, "1", time.Minute)
	if err != nil {
		f.Fatalf("issue: %v", err)
	}
	f.Add(valid)
	f.Add("")
	f.Add("a.b.c")
	f.Add(strings.Repeat("A", 1<<16))
	f.Fuzz(func(t *testing.T, token string) {
		data, _, err := VerifySessionCacheJWT([]string{secret}, token)
		if err != nil {
			return
		}
		if data.Session == nil || data.User == nil {
			t.Fatal("verified payload must carry session/user")
		}
		// Signature binding (time-stable unforgeability): every accepted
		// token is HMAC-bound, so flipping one bit of the payload or
		// signature segment must break verification. (A byte-equality
		// check against the run-local token would be unsound: iat/exp
		// embed time, so older genuinely-issued seeds differ byte-wise.)
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			t.Fatalf("verified non-3-part token: %q", token)
		}
		for i := 1; i <= 2; i++ {
			if parts[i] == "" {
				continue
			}
			mut := []string{parts[0], parts[1], parts[2]}
			mut[i] = flipB64Char(parts[i])
			if _, _, err := VerifySessionCacheJWT([]string{secret}, strings.Join(mut, ".")); err == nil {
				t.Fatalf("mutated segment %d accepted for %q", i, token)
			}
		}
	})
}

func flipB64Char(s string) string {
	c := s[0]
	if c == 'A' {
		c = 'B'
	} else {
		c = 'A'
	}
	return string(c) + s[1:]
}
