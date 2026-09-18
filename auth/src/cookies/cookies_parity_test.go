package cookies

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSecureCookiePrefix(t *testing.T) {
	if CookieName("better-auth", "session_token", true, "") != "__Secure-better-auth.session_token" {
		t.Fatal("secure prefix not applied")
	}
	if CookieName("better-auth", "session_token", false, "") != "better-auth.session_token" {
		t.Fatal("non-secure name changed")
	}
	if CookieName("better-auth", "session_token", true, "custom") != "__Secure-custom" {
		t.Fatal("custom name prefix handling changed")
	}
	if StripSecureCookiePrefix("__Secure-better-auth.session_token") != "better-auth.session_token" {
		t.Fatal("strip __Secure- failed")
	}
	if StripSecureCookiePrefix("__Host-session") != "session" {
		t.Fatal("strip __Host- failed")
	}
	if StripSecureCookiePrefix("plain") != "plain" {
		t.Fatal("strip altered unprefixed name")
	}
}

func TestResolveSecure(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		name     string
		override *bool
		baseURL  string
		prod     bool
		want     bool
	}{
		{"override wins over http", &yes, "http://x", false, true},
		{"override off wins over https", &no, "https://x", true, false},
		{"https baseURL", nil, "https://x", false, true},
		{"http baseURL", nil, "http://x", true, false},
		{"production fallback", nil, "", true, true},
		{"dev fallback", nil, "", false, false},
	}
	for _, tc := range cases {
		if got := ResolveSecure(tc.override, tc.baseURL, tc.prod); got != tc.want {
			t.Errorf("%s = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestResolveDomain(t *testing.T) {
	d, err := ResolveDomain(false, "", "")
	if err != nil || d != "" {
		t.Fatalf("disabled = %q, %v", d, err)
	}
	d, err = ResolveDomain(true, "example.com", "https://app.example.com")
	if err != nil || d != "example.com" {
		t.Fatalf("override = %q, %v", d, err)
	}
	d, err = ResolveDomain(true, "", "https://app.example.com")
	if err != nil || d != "app.example.com" {
		t.Fatalf("baseURL host = %q, %v", d, err)
	}
	if _, err := ResolveDomain(true, "", ""); err == nil {
		t.Fatal("missing domain should error like upstream BetterAuthError")
	}
}

func TestCookieAttributes(t *testing.T) {
	attrs := DefaultAttributes(true, "example.com")
	c := attrs.ToHTTPCookie("__Secure-better-auth.session_token", "v")
	s := c.String()
	for _, want := range []string{"Domain=example.com", "Secure", "HttpOnly", "SameSite=Lax", "Path=/"} {
		if !strings.Contains(s, want) {
			t.Errorf("serialized cookie %q missing %q", s, want)
		}
	}
	// SameSite=None forces Secure; Partitioned forces Secure.
	noneAttrs := DefaultAttributes(false, "").WithOverrides(Attributes{SameSite: http.SameSiteNoneMode})
	if !noneAttrs.Secure {
		t.Error("SameSite=None must force Secure")
	}
	partAttrs := DefaultAttributes(false, "").WithOverrides(Attributes{Partitioned: true})
	if !partAttrs.Secure || !partAttrs.Partitioned {
		t.Error("Partitioned must force Secure")
	}
	if ParseSameSite("NONE") != http.SameSiteNoneMode || ParseSameSite("bogus") != http.SameSiteDefaultMode {
		t.Error("ParseSameSite mismatch")
	}
}

func TestChunkRoundTrip(t *testing.T) {
	attrs := DefaultAttributes(false, "")
	max := MaxValueSizeFor("better-auth.session_data", attrs)
	if max <= 0 || max > MaxCookieSize {
		t.Fatalf("bad max value size %d", max)
	}
	// Small value: single cookie under the bare name.
	single, err := ChunkCookieValue("n", "abc", max)
	if err != nil || len(single) != 1 || single["n"] != "abc" {
		t.Fatalf("single = %v, %v", single, err)
	}
	// Large value: chunked and rejoined in order.
	big := strings.Repeat("x", max*2+10)
	chunks, err := ChunkCookieValue("n", big, max)
	if err != nil || len(chunks) != 3 {
		t.Fatalf("chunks = %d, %v", len(chunks), err)
	}
	joined, ok := JoinChunkedCookies(chunks, "n")
	if !ok || joined != big {
		t.Fatal("chunk rejoin failed")
	}
	// Exact-name match wins over chunks.
	joined, ok = JoinChunkedCookies(map[string]string{"n": "v", "n.0": "x"}, "n")
	if !ok || joined != "v" {
		t.Fatal("exact match should win")
	}
	// Non-canonical chunk names are ignored.
	if _, ok := JoinChunkedCookies(map[string]string{"n.01": "x", "n.-1": "y"}, "n"); ok {
		t.Fatal("non-canonical chunk names must be ignored")
	}
	// Oversize values are rejected so callers fall back to the DB.
	if _, err := ChunkCookieValue("n", strings.Repeat("x", MaxCookieSize*MaxCookieChunks+1), 1); err == nil {
		t.Fatal("oversize value must error")
	}
	// ExpiredChunks covers the bare name and stale chunks.
	expired := ExpiredChunks(map[string]string{"n": "v", "n.0": "a", "n.1": "b", "other": "c"}, "n", attrs)
	if len(expired) != 3 {
		t.Fatalf("expired = %d, want 3", len(expired))
	}
	for _, c := range expired {
		if c.MaxAge != 0 {
			t.Error("expiry cookie must have MaxAge=0")
		}
	}
}

func TestCompactCookieCache(t *testing.T) {
	session := map[string]any{
		"session": map[string]any{"id": "s1"},
		"user":    map[string]any{"id": "u1"},
	}
	value, err := CreateCompactCookieCache("secret", session, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	got, exp, err := VerifyCompactCookieCache([]string{"old", "secret"}, value)
	if err != nil {
		t.Fatalf("verify with rotation: %v", err)
	}
	if exp <= time.Now().UnixMilli() {
		t.Error("expiry not in the future")
	}
	user, _ := got["user"].(map[string]any)
	if user["id"] != "u1" {
		t.Fatalf("payload = %v", got)
	}
	// Tampered values are rejected.
	if _, _, err := VerifyCompactCookieCache([]string{"secret"}, "x"+value[1:]); err == nil {
		t.Error("tampered cache verified")
	}
	if _, _, err := VerifyCompactCookieCache([]string{"wrong"}, value); err == nil {
		t.Error("wrong secret verified")
	}
	// Expired outer window is rejected.
	expiredValue, err := CreateCompactCookieCache("secret", session, -time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyCompactCookieCache([]string{"secret"}, expiredValue); err == nil {
		t.Error("expired cache verified")
	}
	// Embedded session expiry is enforced.
	embExpired := map[string]any{
		"session": map[string]any{"id": "s1", "expiresAt": time.Now().Add(-time.Hour).UnixMilli()},
		"user":    map[string]any{"id": "u1"},
	}
	embValue, err := CreateCompactCookieCache("secret", embExpired, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyCompactCookieCache([]string{"secret"}, embValue); err == nil {
		t.Error("embedded-expired cache verified")
	}
	// Empty secret is rejected at creation.
	if _, err := CreateCompactCookieCache("", session, time.Minute); err == nil {
		t.Error("empty secret must be rejected")
	}
}
