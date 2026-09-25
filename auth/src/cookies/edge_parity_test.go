package cookies

import (
	"strings"
	"testing"
	"time"
)

func TestSignFixedVectors(t *testing.T) {
	// HMAC-SHA256 base64url-nopad vectors (second is textbook key "key" vector).
	for _, tc := range []struct{ secret, value, want string }{
		{"secret", "value", "value.UOA-vmW-mLuL8RuiyJLVTAeayisNOwFidpxtdXolQ08"},
		{"key", "The quick brown fox jumps over the lazy dog", "The quick brown fox jumps over the lazy dog.97yD9DBThCSxMpjmqm-xQ-9NWaFJRhdZl0edvC0aPNg"},
	} {
		got, err := Sign(tc.secret, tc.value)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if got != tc.want {
			t.Errorf("Sign(%q, %q) = %q, want %q", tc.secret, tc.value, got, tc.want)
		}
		if back, ok := Verify(tc.secret, got); !ok || back != tc.value {
			t.Errorf("Verify(Sign(%q)) = %q, %v", tc.value, back, ok)
		}
		if _, ok := Verify("wrong", got); ok {
			t.Errorf("Verify with wrong secret accepted %q", got)
		}
	}
}

func TestGetSessionCookie(t *testing.T) {
	cases := []struct {
		name       string
		cookies    map[string]string
		prefix     string
		cookieName string
		want       string
		wantOK     bool
	}{
		{"bare dot name", map[string]string{"better-auth.session_token": "t"}, "", "", "t", true},
		{"secure preferred over leftover", map[string]string{
			"better-auth.session_token":          "stale",
			"__Secure-better-auth.session_token": "current",
		}, "", "", "current", true},
		{"dash separator", map[string]string{"better-auth-session_token": "t"}, "", "", "t", true},
		{"secure dash separator", map[string]string{"__Secure-better-auth-session_token": "t"}, "", "", "t", true},
		{"custom prefix and name", map[string]string{"myprefix.my_token": "t"}, "myprefix", "my_token", "t", true},
		{"custom prefix secure", map[string]string{"__Secure-myprefix.my_token": "t"}, "myprefix", "my_token", "t", true},
		{
			// Empty __Secure- value does NOT fall back to non-secure leftover.
			"empty secure does not fall back to leftover",
			map[string]string{
				"better-auth.session_token":          "stale",
				"__Secure-better-auth.session_token": "",
			}, "", "", "", false,
		},
		{
			// Dash variant is still tried.
			"empty secure dot falls through to dash",
			map[string]string{
				"__Secure-better-auth.session_token": "",
				"better-auth-session_token":          "t",
			}, "", "", "t", true,
		},
		{"absent", map[string]string{"other": "x"}, "", "", "", false},
		{"nil map", nil, "", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := GetSessionCookie(tc.cookies, tc.prefix, tc.cookieName)
			if ok != tc.wantOK || got != tc.want {
				t.Errorf("GetSessionCookie = %q, %v; want %q, %v", got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestParseRequestCookies(t *testing.T) {
	// Upstream cookie-utils vector: quoted unquoted, bare kept.
	got := ParseRequestCookies(`a="hello"; b=plain; c="with space"`)
	if got["a"] != "hello" || got["b"] != "plain" || got["c"] != "with space" {
		t.Fatalf("quoted parse = %v", got)
	}
	// Percent-decoding; malformed escapes pass through.
	got = ParseRequestCookies("token=hello%20world%3Dfoo; Path=/")
	if got["token"] != "hello world=foo" {
		t.Fatalf("decoded = %v", got["token"])
	}
	// Missing "=" pairs and empty names dropped.
	got = ParseRequestCookies("valid=1; ; =orphan; locale=en")
	if len(got) != 2 || got["valid"] != "1" || got["locale"] != "en" {
		t.Fatalf("malformed parse = %v", got)
	}
	// Tolerates ";" without trailing space.
	got = ParseRequestCookies("a=1;b=2")
	if got["a"] != "1" || got["b"] != "2" {
		t.Fatalf("compact parse = %v", got)
	}
	// Names outside RFC 7230 token set dropped.
	got = ParseRequestCookies("a b=1; ok=2")
	if _, bad := got["a b"]; bad || got["ok"] != "2" {
		t.Fatalf("token validation = %v", got)
	}
	// Headers shorter than 2 bytes carry no pair.
	if len(ParseRequestCookies("")) != 0 || len(ParseRequestCookies("a")) != 0 {
		t.Fatal("short header must parse empty")
	}
	// Malformed escapes survive verbatim.
	got = ParseRequestCookies("t=%zz; u=1")
	if got["t"] != "%zz" || got["u"] != "1" {
		t.Fatalf("escape fallback = %v", got)
	}
}

func TestResolveSecureWithProtocol(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		name     string
		override *bool
		baseURL  string
		protocol string
		prod     bool
		want     bool
	}{
		{"override wins over https protocol", &no, "https://x", "https", true, false},
		{"override wins over http protocol", &yes, "http://x", "http", false, true},
		{"https protocol wins over http baseURL", nil, "http://x", "https", false, true},
		{"http protocol wins over https baseURL", nil, "https://x", "http", true, false},
		{"auto protocol falls back to baseURL", nil, "https://x", "auto", false, true},
		{"empty protocol falls back to baseURL", nil, "http://x", "", true, false},
		{"no baseURL falls back to production", nil, "", "", true, true},
		{"dev fallback", nil, "", "", false, false},
	}
	for _, tc := range cases {
		if got := ResolveSecureWithProtocol(tc.override, tc.baseURL, tc.protocol, tc.prod); got != tc.want {
			t.Errorf("%s = %v, want %v", tc.name, got, tc.want)
		}
	}
	// The legacy entry point keeps static-baseURL behavior.
	if !ResolveSecure(nil, "https://x", false) || ResolveSecure(nil, "http://x", true) {
		t.Error("ResolveSecure static behavior changed")
	}
}

func TestCompactEmbeddedExpiryEdgeCases(t *testing.T) {
	mkValue := func(t *testing.T, session map[string]any) string {
		t.Helper()
		v, err := CreateCompactCookieCache("secret", session, 5*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	base := func(expiresAt any) map[string]any {
		inner := map[string]any{"id": "s1"}
		if expiresAt != nil {
			inner["expiresAt"] = expiresAt
		}
		return map[string]any{"session": inner, "user": map[string]any{"id": "u1"}}
	}
	// Falsy epoch-zero expiries compare as absent (upstream !expiresAt).
	for name, zero := range map[string]any{
		"numeric zero": float64(0),
		"int zero":     int(0),
		"empty string": "",
	} {
		if _, _, err := VerifyCompactCookieCache([]string{"secret"}, mkValue(t, base(zero))); err != nil {
			t.Errorf("%s treated as expired: %v", name, err)
		}
	}
	// Zero time.Time serializes ancient and counts as expired upstream.
	if _, _, err := VerifyCompactCookieCache([]string{"secret"}, mkValue(t, base(time.Time{}))); err == nil {
		t.Error("zero time.Time accepted")
	}
	// time.Time expiries honored both ways.
	if _, _, err := VerifyCompactCookieCache([]string{"secret"}, mkValue(t, base(time.Now().Add(time.Hour)))); err != nil {
		t.Errorf("future time.Time rejected: %v", err)
	}
	if _, _, err := VerifyCompactCookieCache([]string{"secret"}, mkValue(t, base(time.Now().Add(-time.Hour)))); err == nil {
		t.Error("past time.Time accepted")
	} else if !strings.Contains(err.Error(), "embedded") {
		t.Errorf("past time.Time error = %v, want embedded-session-expiry", err)
	}
}
