package cookies

// v1 ports of vendor/better-auth/packages/better-auth/src/cookies/
// cookies.test.ts cases owned by this package: Set-Cookie response parsing
// (parseSetCookieHeader/toCookieOptions), request-cookie writes
// (setRequestCookie/applySetCookies), secure-prefix stripping, expiry, and
// separator tolerance. Integration cases (sign-in flows, cookie cache
// issuance, chunked multi-cookie writes, social/account sync, JWT-plugin
// JWKS paths) belong to the route/plugin layers and are intentionally not
// ported here; chunked writes are an explicit v1 exclusion (authoritative
// lookup fallback instead).

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestV1_ParseSetCookieExpiresWithCommas(t *testing.T) {
	m := ParseSetCookieHeader("a=1; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Path=/, b=2; Expires=Thu, 22 Oct 2015 07:28:00 GMT; Path=/")
	if m["a"].Value != "1" || m["b"].Value != "2" {
		t.Fatalf("values = %q %q", m["a"].Value, m["b"].Value)
	}
	if want := time.Date(2015, 10, 21, 7, 28, 0, 0, time.UTC); !m["a"].ExpiresSet || !m["a"].Expires.Equal(want) {
		t.Errorf("a.expires = %v %v, want %v", m["a"].Expires, m["a"].ExpiresSet, want)
	}
	if want := time.Date(2015, 10, 22, 7, 28, 0, 0, time.UTC); !m["b"].ExpiresSet || !m["b"].Expires.Equal(want) {
		t.Errorf("b.expires = %v %v, want %v", m["b"].Expires, m["b"].ExpiresSet, want)
	}
}

func TestV1_ParseSetCookieDecodesValues(t *testing.T) {
	m := ParseSetCookieHeader("token=hello%20world%3Dfoo; Path=/")
	if m["token"].Value != "hello world=foo" {
		t.Fatalf("value = %q", m["token"].Value)
	}
}

func TestV1_ParseSetCookieExpiresThenBare(t *testing.T) {
	m := ParseSetCookieHeader("session=xyz; Expires=Mon, 01 Jan 2026 00:00:00 GMT, token=abc")
	if m["session"].Value != "xyz" {
		t.Fatalf("session = %q", m["session"].Value)
	}
	if want := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC); !m["session"].ExpiresSet || !m["session"].Expires.Equal(want) {
		t.Errorf("session.expires = %v %v", m["session"].Expires, m["session"].ExpiresSet)
	}
	if m["token"].Value != "abc" || m["token"].ExpiresSet {
		t.Errorf("token = %+v", m["token"])
	}
}

func TestV1_ParseSetCookieGMTSubstring(t *testing.T) {
	m := ParseSetCookieHeader("session_data=testsessiondata; Path=/; Expires=Mon, 02 Mar 2026 05:42:16 GMT; Max-Age=300; Secure; HttpOnly; SameSite=lax")
	if m["session_data"].Value != "testsessiondata" {
		t.Fatalf("value = %q", m["session_data"].Value)
	}
	if want := time.Date(2026, 3, 2, 5, 42, 16, 0, time.UTC); !m["session_data"].ExpiresSet || !m["session_data"].Expires.Equal(want) {
		t.Errorf("expires = %v %v", m["session_data"].Expires, m["session_data"].ExpiresSet)
	}
	if m["session_data"].MaxAge != 300 || !m["session_data"].MaxAgeSet {
		t.Errorf("max-age = %+v", m["session_data"])
	}
}

func TestV1_ParseSetCookieNonStandardExpires(t *testing.T) {
	m := ParseSetCookieHeader("a=1; Expires=0, b=2")
	if m["a"].Value != "1" || m["b"].Value != "2" {
		t.Fatalf("split on non-standard Expires failed: %v", m)
	}
}

func TestV1_ParseSetCookieRFC850Expires(t *testing.T) {
	m := ParseSetCookieHeader("a=1; Expires=Sunday, 06-Nov-94 08:49:37 GMT, b=2")
	if m["a"].Value != "1" || m["b"].Value != "2" {
		t.Fatalf("RFC 850 split failed: %v", m)
	}
	if !m["a"].ExpiresSet || m["a"].Expires.Year() != 1994 || m["a"].Expires.Month() != time.November {
		t.Errorf("RFC 850 date not parsed: %v %v", m["a"].Expires, m["a"].ExpiresSet)
	}
}

func TestV1_ParseSetCookieAsctimeExpires(t *testing.T) {
	m := ParseSetCookieHeader("a=1; Expires=Sun Nov 6 08:49:37 1994, b=2")
	if m["a"].Value != "1" || m["b"].Value != "2" {
		t.Fatalf("asctime split failed: %v", m)
	}
	if !m["a"].ExpiresSet || m["a"].Expires.Year() != 1994 || m["a"].Expires.Month() != time.November {
		t.Errorf("asctime date not parsed: %v %v", m["a"].Expires, m["a"].ExpiresSet)
	}
}

func TestV1_ParseSetCookieMixed(t *testing.T) {
	m := ParseSetCookieHeader("a=1; Path=/; HttpOnly, b=2; Expires=Mon, 01 Jan 2026 00:00:00 GMT; Secure, c=3; SameSite=Lax")
	if m["a"].Value != "1" || m["b"].Value != "2" || m["c"].Value != "3" {
		t.Fatalf("mixed = %v", m)
	}
	if !m["b"].ExpiresSet {
		t.Error("b.expires missing")
	}
	if m["c"].SameSite != http.SameSiteLaxMode {
		t.Errorf("c.samesite = %v", m["c"].SameSite)
	}
}

func TestV1_ParseSetCookiePartitioned(t *testing.T) {
	m := ParseSetCookieHeader("session=xyz; Path=/; Secure; HttpOnly; SameSite=None; Partitioned")
	a := m["session"]
	if a.Value != "xyz" || !a.Secure || !a.HttpOnly || a.SameSite != http.SameSiteNoneMode || !a.Partitioned {
		t.Fatalf("partitioned = %+v", a)
	}
}

func TestV1_ToCookieOptions(t *testing.T) {
	attr := ParseSetCookieHeader("session=xyz; Path=/auth; Expires=Mon, 01 Jan 2026 00:00:00 GMT; Max-Age=300; Secure; HttpOnly; SameSite=None; Partitioned")["session"]
	got := attr.ToAttributes()
	if got.Path != "/auth" {
		t.Errorf("path = %q", got.Path)
	}
	if want := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC); !got.ExpiresSet || !got.Expires.Equal(want) {
		t.Errorf("expires = %v %v", got.Expires, got.ExpiresSet)
	}
	if got.MaxAge != 300 || !got.MaxAgeSet {
		t.Errorf("max-age = %d %v", got.MaxAge, got.MaxAgeSet)
	}
	if !got.Secure || !got.HttpOnly || got.SameSite != http.SameSiteNoneMode || !got.Partitioned {
		t.Errorf("flags = %+v", got)
	}
}

func TestV1_StripSecureCookiePrefixEdges(t *testing.T) {
	if got := StripSecureCookiePrefix(""); got != "" {
		t.Errorf("empty = %q", got)
	}
	if got := StripSecureCookiePrefix(SecureCookiePrefix); got != "" {
		t.Errorf("exact secure prefix = %q", got)
	}
	if got := StripSecureCookiePrefix(HostCookiePrefix); got != "" {
		t.Errorf("exact host prefix = %q", got)
	}
	// __Secure- wins over __Host- when both lead.
	if got := StripSecureCookiePrefix(SecureCookiePrefix + HostCookiePrefix + "test"); got != HostCookiePrefix+"test" {
		t.Errorf("priority = %q", got)
	}
	if got := StripSecureCookiePrefix(SecureCookiePrefix + "better-auth.session_token"); got != "better-auth.session_token" {
		t.Errorf("dotted = %q", got)
	}
	if got := StripSecureCookiePrefix("my__Secure-cookie"); got != "my__Secure-cookie" {
		t.Errorf("middle = %q", got)
	}
}

func TestV1_SetRequestCookieHeader(t *testing.T) {
	if got := SetRequestCookieHeader("", "better-auth.session_token", "abc"); got != "better-auth.session_token=abc" {
		t.Errorf("empty header = %q", got)
	}
	if got := SetRequestCookieHeader("preference=dark; locale=en", "better-auth.session_token", "abc"); got != "preference=dark; locale=en; better-auth.session_token=abc" {
		t.Errorf("preserve+join = %q", got)
	}
	if got := SetRequestCookieHeader("better-auth.session_token=stale; locale=en", "better-auth.session_token", "fresh"); got != "better-auth.session_token=fresh; locale=en" {
		t.Errorf("replace = %q", got)
	}
	if got := SetRequestCookieHeader("valid=1; ; =orphan; locale=en", "better-auth.session_token", "abc"); got != "valid=1; locale=en; better-auth.session_token=abc" {
		t.Errorf("malformed dropped = %q", got)
	}
	if got := SetRequestCookieHeader("locale=en", "session", "foo;bar=baz"); got != "locale=en; session=foo%3Bbar%3Dbaz" {
		t.Errorf("reserved encoded = %q", got)
	}
	if got := SetRequestCookieHeader("", "token", `"abc"`); got != "token=%22abc%22" {
		t.Errorf("quotes encoded = %q", got)
	}
}

func TestV1_ApplySetCookiesHeader(t *testing.T) {
	if got := ApplySetCookiesHeader("", []string{"a=1; Path=/"}); got != "a=1" {
		t.Errorf("empty merge = %q", got)
	}
	if got := ApplySetCookiesHeader("", []string{"a=1; Path=/; HttpOnly; Secure; Max-Age=3600; SameSite=Lax"}); got != "a=1" {
		t.Errorf("attributes stripped = %q", got)
	}
	if got := ApplySetCookiesHeader("", []string{"a=1; Path=/", "b=2; Path=/"}); got != "a=1; b=2" {
		t.Errorf("multi merge = %q", got)
	}
	if got := ApplySetCookiesHeader("a=old; b=keep", []string{"a=new; Path=/"}); got != "a=new; b=keep" {
		t.Errorf("last wins = %q", got)
	}
	if got := ApplySetCookiesHeader("session=safe", []string{"pref=foo%3Bbar=hello; Path=/"}); got != "session=safe; pref=foo%3Bbar%3Dhello" {
		t.Errorf("re-encode = %q", got)
	}
	if got := ApplySetCookiesHeader("", []string{`token="abc"; Path=/`}); got != "token=abc" {
		t.Errorf("quoted stripped = %q", got)
	}
}

func TestV1_ExpireCookie(t *testing.T) {
	c := ExpireCookie("test", Attributes{Path: "/custom", HttpOnly: true})
	if c.Name != "test" || c.Value != "" {
		t.Fatalf("expiry identity = %+v", c)
	}
	if c.Path != "/custom" || !c.HttpOnly {
		t.Errorf("attributes not preserved: %+v", c)
	}
	if c.MaxAge != 0 {
		t.Errorf("expiry must carry MaxAge=0, got %d", c.MaxAge)
	}
}

func TestV1_ScrubSetCookieEntries(t *testing.T) {
	entries := []string{"keep=1; Path=/", "target=valid; Path=/", "target.0=chunk; Path=/"}
	got := ScrubSetCookieEntries(entries, "target")
	if len(got) != 1 || got[0] != "keep=1; Path=/" {
		t.Fatalf("scrubbed = %v", got)
	}
	// Expiring after the scrub leaves exactly one clearing entry.
	expired := ExpireCookie("target", Attributes{Path: "/"})
	got = append(got, expired.Name+"=; Path="+expired.Path)
	joined := strings.Join(got, ", ")
	if !strings.Contains(joined, "keep=1") || strings.Contains(joined, "target=valid") || strings.Contains(joined, "target.0=chunk") {
		t.Fatalf("final = %q", joined)
	}
}

func TestV1_SemicolonOnlySeparators(t *testing.T) {
	parsed := ParseRequestCookies("preference=dark;better-auth.session_token=token-123")
	v, ok := GetSessionCookie(parsed, "", "")
	if !ok || v != "token-123" {
		t.Fatalf(";-only session lookup = %q %v", v, ok)
	}
	// Chunk reassembly across ;-only separators.
	chunks := ParseRequestCookies("better-auth.session_data.0=chunkA;better-auth.session_data.1=chunkB")
	joined, ok := JoinChunkedCookies(chunks, "better-auth.session_data")
	if !ok || joined != "chunkAchunkB" {
		t.Fatalf(";-only chunk join = %q %v", joined, ok)
	}
}

func TestV1_NonCanonicalChunkNamesIgnored(t *testing.T) {
	for _, name := range []string{
		"better-auth.session_data.0junk",
		"better-auth.session_data.nested.0",
		"better-auth.session_data.01",
		"better-auth.session_data.-1",
	} {
		if _, ok := JoinChunkedCookies(map[string]string{name: "chunk"}, "better-auth.session_data"); ok {
			t.Errorf("%q must be ignored", name)
		}
	}
}

func TestV1_CookieOptionsFromConfig(t *testing.T) {
	// Mirrors "should return correct cookie options based on configuration":
	// secure + custom prefix + cross-subdomain domain.
	name := CookieName("test-prefix", "session_token", true, "")
	if !strings.Contains(name, "test-prefix.session_token") || !strings.HasPrefix(name, SecureCookiePrefix) {
		t.Fatalf("name = %q", name)
	}
	attrs := DefaultAttributes(true, "example.com")
	if !attrs.Secure || attrs.SameSite != http.SameSiteLaxMode || attrs.Domain != "example.com" {
		t.Fatalf("attrs = %+v", attrs)
	}
}
