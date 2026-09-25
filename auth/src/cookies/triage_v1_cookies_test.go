package cookies

// Triage ports for vendor/better-auth
// packages/better-auth/src/cookies/cookies.test.ts residual cases owned by
// this package: exact-vector parseCookies cases (separators, padding,
// name/value validation, CR/LF, first-=) plus the chunked-compact-cache READ
// round-trip. Chunked multi-cookie WRITES stay excluded per SCOPE.md (read
// path only); route-integration (sign-in/sign-up issuance), JWKS/jwt-plugin,
// social/account-sync, and sensitive-middleware legs belong to other lanes.

import (
	"strings"
	"testing"
	"time"
)

// Upstream: "parseCookies tolerates mixed `;`, `; `, and `;\t` separators"
// ("a=1; b=2;c=3;\td=4" yields all four pairs).
func TestTriageV1_ParseCookiesMixedSeparators(t *testing.T) {
	got := ParseRequestCookies("a=1; b=2;c=3;\td=4")
	for k, want := range map[string]string{"a": "1", "b": "2", "c": "3", "d": "4"} {
		if got[k] != want {
			t.Errorf("%s = %q, want %q (full map %v)", k, got[k], want, got)
		}
	}
	if len(got) != 4 {
		t.Errorf("map = %v, want exactly 4 pairs", got)
	}
}

// Upstream: "should securely parse the signed cookies with padding"
// (trailing base64 "=" padding survives: split on first "=" only).
func TestTriageV1_ParseCookiesPaddedSignedValues(t *testing.T) {
	got := ParseRequestCookies("better-auth.session_token=session-token.signature=; better-auth.session_data=session-data.signature=")
	if got["better-auth.session_token"] != "session-token.signature=" {
		t.Errorf("session_token = %q, want padding preserved", got["better-auth.session_token"])
	}
	if got["better-auth.session_data"] != "session-data.signature=" {
		t.Errorf("session_data = %q, want padding preserved", got["better-auth.session_data"])
	}
}

// Upstream: "rejects names containing characters outside RFC 7230 token"
// ("bad name", "bad,name", "bad:name" dropped; "ok" kept).
func TestTriageV1_ParseCookiesRejectBadNames(t *testing.T) {
	got := ParseRequestCookies("bad name=v1; ok=v2; bad,name=v3; bad:name=v4")
	if got["ok"] != "v2" {
		t.Errorf("ok = %q, want %q", got["ok"], "v2")
	}
	for _, bad := range []string{"bad name", "bad,name", "bad:name"} {
		if _, found := got[bad]; found {
			t.Errorf("name %q must be rejected, map = %v", bad, got)
		}
	}
}

// Upstream: "rejects values containing control chars, double-quote, or
// backslash" ('b=has\rcr', 'c=has"quote', 'd=has\slash' dropped; "a" kept).
func TestTriageV1_ParseCookiesRejectBadValues(t *testing.T) {
	got := ParseRequestCookies("a=ok; b=has\rcr; c=has\"quote; d=has\\slash")
	if got["a"] != "ok" {
		t.Errorf("a = %q, want %q", got["a"], "ok")
	}
	for _, bad := range []string{"b", "c", "d"} {
		if _, found := got[bad]; found {
			t.Errorf("value for %q must be rejected, map = %v", bad, got)
		}
	}
}

// Upstream: "rejects entries with CR/LF in raw key or value (no trim
// escape)" (CR in value, CR in key, LF in value dropped; "d" kept —
// trimOWS strips space/tab only, so CTLs reach validation and fail).
func TestTriageV1_ParseCookiesRejectCRLFEntries(t *testing.T) {
	got := ParseRequestCookies("a=ok\r; b\r=1; c=v\nv; d=ok")
	for _, bad := range []string{"a", "b", "c"} {
		if _, found := got[bad]; found {
			t.Errorf("entry %q with CR/LF must be rejected, map = %v", bad, got)
		}
	}
	if got["d"] != "ok" {
		t.Errorf("d = %q, want %q", got["d"], "ok")
	}
}

// Upstream: "splits on first `=` only, preserving subsequent `=` in value".
func TestTriageV1_ParseCookiesSplitsOnFirstEquals(t *testing.T) {
	got := ParseRequestCookies("a=b=c=d")
	if got["a"] != "b=c=d" {
		t.Errorf("a = %q, want %q", got["a"], "b=c=d")
	}
}

// Upstream: "should reconstruct chunked cookies correctly" (READ leg only:
// a large compact cache split across chunk cookies reassembles and verifies
// with the large field intact; chunked WRITES stay v1-excluded).
func TestTriageV1_ChunkedCompactCacheReadRoundTrip(t *testing.T) {
	const secret = "better-auth.secret"
	large := strings.Repeat("y", 6000)
	payload := v1CachePayload(time.Now().Add(time.Hour))
	payload["user"].(map[string]any)["largeField"] = large
	value, err := CreateCompactCookieCache(secret, payload, 5*time.Minute)
	if err != nil {
		t.Fatalf("issue compact cache: %v", err)
	}
	name := "better-auth.session_data"
	budget := MaxValueSizeFor(name, DefaultAttributes(false, ""))
	chunks, err := ChunkCookieValue(name, value, budget)
	if err != nil {
		t.Fatalf("chunk compact cache: %v", err)
	}
	if len(chunks) < 2 {
		t.Fatalf("expected multi-chunk value, got %d chunk(s)", len(chunks))
	}
	joined, ok := JoinChunkedCookies(chunks, name)
	if !ok || joined != value {
		t.Fatal("chunked compact cache must reassemble exactly")
	}
	session, _, err := VerifyCompactCookieCache([]string{secret}, joined)
	if err != nil {
		t.Fatalf("reassembled cache must verify: %v", err)
	}
	user, _ := session["user"].(map[string]any)
	if user["email"] != "cache@test.com" {
		t.Errorf("email = %v, want cache@test.com", user["email"])
	}
	if user["largeField"] != large {
		t.Error("large field did not survive the chunk round-trip")
	}
}
