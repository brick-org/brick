package cookies

// F8 batch: chunked WRITES + minor deviations (upstream v1.7.5 @5468e6bf).

import (
	"strings"
	"testing"
)

// Small values stay single under the bare name.
func TestCookiesChunked_ChunkWriteStaysSingleUnderLimit(t *testing.T) {
	attrs := DefaultAttributes(false, "")
	out, err := BuildChunkedCookies("better-auth.session_data", "small-value", attrs)
	if err != nil {
		t.Fatalf("BuildChunkedCookies: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("single value must emit exactly 1 cookie, got %d", len(out))
	}
	if out[0].Name != "better-auth.session_data" {
		t.Errorf("single cookie must keep bare name, got %q", out[0].Name)
	}
	if out[0].Value != "small-value" {
		t.Errorf("single value mismatch: %q", out[0].Value)
	}
	m := map[string]string{out[0].Name: out[0].Value}
	if got, ok := JoinChunkedCookies(m, "better-auth.session_data"); !ok || got != "small-value" {
		t.Fatalf("single cookie must reassemble via JoinChunkedCookies: %q %v", got, ok)
	}
}

// Large values split into indexed "<name>.<i>" chunks.
func TestCookiesChunked_ChunkWriteSplitsIndexed(t *testing.T) {
	attrs := DefaultAttributes(false, "")
	budget := MaxValueSizeFor("better-auth.session_data", attrs)
	big := strings.Repeat("x", budget*2+10)
	out, err := BuildChunkedCookies("better-auth.session_data", big, attrs)
	if err != nil {
		t.Fatalf("BuildChunkedCookies large: %v", err)
	}
	if len(out) < 2 {
		t.Fatalf("oversize value must emit multiple cookies, got %d", len(out))
	}
	for i, c := range out {
		want := "better-auth.session_data." + itoaF8(i)
		if c.Name != want {
			t.Errorf("chunk %d name = %q, want %q", i, c.Name, want)
		}
		line := attrs.ToHTTPCookie(c.Name, c.Value).String()
		if len(line) > MaxCookieSize {
			t.Errorf("chunk %q serializes to %d bytes, over %d", c.Name, len(line), MaxCookieSize)
		}
	}
	m := map[string]string{}
	for _, c := range out {
		m[c.Name] = c.Value
	}
	if got, ok := JoinChunkedCookies(m, "better-auth.session_data"); !ok || got != big {
		t.Fatal("chunked issuance must reassemble exactly via JoinChunkedCookies")
	}
}

// Oversize beyond MaxCookieChunks errors (DB fallback).
func TestCookiesChunked_ChunkWriteOversizeSkips(t *testing.T) {
	attrs := DefaultAttributes(false, "")
	tooBig := strings.Repeat("x", MaxCookieChunks+1)
	if _, err := BuildChunkedCookies("sess", tooBig, Attributes{Path: "/"}); err == nil {
		t.Log("small-name huge check skipped (fits); trying wire-huge")
	}
	huge := strings.Repeat("z", MaxCookieSize*MaxCookieChunks+1)
	if _, err := BuildChunkedCookies("better-auth.session_data", huge, attrs); err == nil {
		t.Fatal("value exceeding MaxCookieChunks must error (skip cache, DB fallback)")
	}
}

// Upstream #8585: serialized line overflows once name+attrs added.
func TestCookiesChunked_ChunkWriteAttributesPushOverLimit(t *testing.T) {
	longPrefix := "better-auth-" + strings.Repeat("x", 80)
	name := longPrefix + ".session_data"
	attrs := DefaultAttributes(true, "")
	budget := MaxValueSizeFor(name, attrs)
	value := strings.Repeat("y", budget+500)
	out, err := BuildChunkedCookies(name, value, attrs)
	if err != nil {
		t.Fatalf("BuildChunkedCookies long-prefix: %v", err)
	}
	if len(out) < 2 {
		t.Fatalf("long-prefix value must chunk, got %d cookie(s)", len(out))
	}
	for _, c := range out {
		line := attrs.ToHTTPCookie(c.Name, c.Value).String()
		if len(line) > MaxCookieSize {
			t.Errorf("chunk %q serializes to %d bytes, over %d", c.Name, len(line), MaxCookieSize)
		}
	}
	m := map[string]string{}
	for _, c := range out {
		m[c.Name] = c.Value
	}
	if got, ok := JoinChunkedCookies(m, name); !ok || got != value {
		t.Fatal("long-prefix chunks must reassemble exactly")
	}
}

func itoaF8(i int) string {
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

// Upstream: new Date("0") => Invalid Date (ExpiresSet=true + zero Time).

func TestCookiesChunked_ExpiresZeroIsInvalidDate(t *testing.T) {
	m := ParseSetCookieHeader("a=1; Expires=0, b=2")
	if m["a"].Value != "1" || m["b"].Value != "2" {
		t.Fatalf("split failed: %v", m)
	}
	a := m["a"]
	if !a.ExpiresSet {
		t.Fatal("Expires=0 must be defined (Invalid-Date semantics), got ExpiresSet=false")
	}
	if !a.Expires.IsZero() {
		t.Errorf("Expires=0 Invalid Date must be zero Time, got %v", a.Expires)
	}
	if m["b"].ExpiresSet {
		t.Errorf("bare cookie must leave ExpiresSet=false, got %+v", m["b"])
	}
}

// Upstream keeps unknown attrs in parse map; toCookieOptions drops them.

func TestCookiesChunked_UnknownAttrsPreservedInParseMap(t *testing.T) {
	m := ParseSetCookieHeader("a=1; Path=/; X-Custom=foo; FlagAttr; HttpOnly")
	a := m["a"]
	if a.Value != "1" {
		t.Fatalf("value = %q", a.Value)
	}
	if a.Extra == nil {
		t.Fatal("unknown attrs must be preserved in parse map (Extra==nil)")
	}
	if got := a.Extra["x-custom"]; got != "foo" {
		t.Errorf("x-custom = %q, want %q (map %v)", got, "foo", a.Extra)
	}
	v, ok := a.Extra["flagattr"]
	if !ok {
		t.Fatalf("flagattr must be preserved, map %v", a.Extra)
	}
	if v != "true" && v != "" {
		t.Errorf("flagattr = %q, want flag marker", v)
	}
	opts := a.ToAttributes()
	if opts.Path != "/" || !opts.HttpOnly {
		t.Errorf("known attrs lost: %+v", opts)
	}
}

// Upstream serializeCookie emits Max-Age=0 for maxAge:0.

func TestCookiesChunked_MaxAgeZeroWireRendering(t *testing.T) {
	attrs := Attributes{Path: "/", HttpOnly: true, MaxAge: 0, MaxAgeSet: true}
	c := ExpireCookie("test", Attributes{Path: "/", HttpOnly: true})
	if c.MaxAge != 0 {
		t.Fatalf("ExpireCookie struct must keep MaxAge==0, got %d", c.MaxAge)
	}
	line := attrs.Serialize("test", "")
	if !strings.Contains(line, "Max-Age=0") {
		t.Errorf("wire line must contain Max-Age=0, got %q", line)
	}
	pos := Attributes{Path: "/", MaxAge: 300, MaxAgeSet: true}
	if line := pos.Serialize("s", "v"); !strings.Contains(line, "Max-Age=300") {
		t.Errorf("positive Max-Age missing, got %q", line)
	}
	unset := Attributes{Path: "/"}
	if line := unset.Serialize("s", "v"); strings.Contains(line, "Max-Age") {
		t.Errorf("unset Max-Age must be omitted, got %q", line)
	}
}

// JWKS custom signer stays inert (no JWKS API; default-secret rejects JWKS shapes).

func TestCookiesChunked_JWKSShimStaysInert(t *testing.T) {
	header := `{"alg":"RS256","typ":"better-auth.session-cache+jwt","kid":"k1"}`
	payload := `{"session":{"id":"s1"},"user":{"id":"u1"}}`
	fake := "eyJhbGciOiJSUzI1NiJ9.eyJzZXNzaW9uIjp7fX0.c2ln"
	_ = header
	_ = payload
	if _, _, err := VerifySessionCacheJWT([]string{"secret"}, fake); err == nil {
		t.Fatal("JWKS-shaped token must not verify via default secret path")
	}
	if _, _, err := VerifySessionCacheJWT([]string{"secret"}, "bm90LWpzb24.e30.e30"); err == nil {
		t.Fatal("malformed JWT must fail closed (JWKS shim inert)")
	}
}
