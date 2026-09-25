package routes

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/api/state"
	"github.com/brick-org/brick/auth/src/cookies"
)

// G8 c701-side chunk/skip coverage (PARITY_V2 P05/P10 G5).
// 1. Oversize issuance chunks with upstream <name>.<i> naming.
// 2. Shrink expires stale chunks (incl. bare upstream names).
// 3. shouldSkipSessionRefresh gate suppresses the c701 refresh.

// Oversize session_data must chunk on write via BuildChunkedCookies.
func TestCookiesChunked_OversizeIssuanceYieldsIndexedChunks(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	opts.Session.CookieCache.Enabled = true
	seedSessionUser(t, db, "g8-oversize@example.com", "tok-g8-oversize", time.Now().UTC().Add(time.Hour))
	row, urow, _, err := loadSessionAndUser(ctx, opts, "tok-g8-oversize")
	if err != nil {
		t.Fatal(err)
	}
	session, user := rowToSession(row, opts), rowToUser(urow, opts)
	if user.AdditionalFields == nil {
		user.AdditionalFields = map[string]any{}
	}
	user.AdditionalFields["undeclaredExtra"] = strings.Repeat("x", 12000)

	now := time.Now().UTC()
	out, err := issueSessionCookiesWithContext(ctx, opts, CookieRequestHeaders{}, "tok-g8-oversize", session, user, opts.Session, now, false)
	if err != nil {
		t.Fatalf("issuance must succeed (chunk, not error): %v", err)
	}
	var dataCookies []string
	for _, c := range out {
		if c.Name == sessionDataCookieName || strings.HasPrefix(c.Name, sessionDataCookieName+".") {
			dataCookies = append(dataCookies, c.Name)
		}
	}
	if len(dataCookies) < 2 {
		t.Fatalf("oversize session_data must chunk into >=2 cookies, got %v (all %v)", dataCookies, out)
	}
	for i := range dataCookies {
		_ = i
	}
	seen := map[string]bool{}
	for _, n := range dataCookies {
		seen[n] = true
	}
	for i := 0; i < len(dataCookies); i++ {
		want := sessionDataCookieName + "." + itoaG8(i)
		if !seen[want] {
			t.Fatalf("missing indexed chunk %q in %v", want, dataCookies)
		}
	}
	attrs := cookies.DefaultAttributes(false, "")
	for _, c := range out {
		if c.Name == sessionDataCookieName || strings.HasPrefix(c.Name, sessionDataCookieName+".") {
			line := attrs.Serialize(c.Name, c.Value)
			if len(line) > cookies.MaxCookieSize {
				t.Fatalf("chunk %q serializes to %d bytes, over %d", c.Name, len(line), cookies.MaxCookieSize)
			}
		}
	}
	m := map[string]string{}
	for _, c := range out {
		if c.Name == sessionDataCookieName || strings.HasPrefix(c.Name, sessionDataCookieName+".") {
			m[c.Name] = c.Value
		}
	}
	if _, ok := cookies.JoinChunkedCookies(m, sessionDataCookieName); !ok {
		t.Fatal("chunked issuance must reassemble via JoinChunkedCookies")
	}

	zeroAttrs := cookies.Attributes{Path: "/", HttpOnly: true, MaxAge: 0, MaxAgeSet: true}
	budget := cookies.MaxValueSizeFor("n", zeroAttrs)
	wantBudget := cookies.MaxCookieSize - len(zeroAttrs.Serialize("n.99", ""))
	if budget != wantBudget {
		t.Fatalf("MaxValueSizeFor must use Serialize: got %d, want %d", budget, wantBudget)
	}
}

func itoaG8(i int) string {
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

// Shrink must expire stale chunks plus bare upstream names.
func TestCookiesChunked_ShrinkExpiresStaleChunks(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	opts.Session.CookieCache.Enabled = true
	opts.Advanced.CookiePrefix = "custom"
	header := "custom.session_token=x; better-auth.session_data=stale; better-auth.session_data.0=c0; better-auth.session_data.1=c1"
	got := expiredSessionCookiesWithContext(ctx, opts, CookieRequestHeaders{}, header)
	expired := map[string]bool{}
	for _, c := range got {
		if c.MaxAge < 0 {
			expired[c.Name] = true
		}
	}
	for _, want := range []string{"better-auth.session_data", "better-auth.session_data.0", "better-auth.session_data.1"} {
		if !expired[want] {
			t.Fatalf("stale %q must expire with MaxAge<0, got %v", want, got)
		}
	}
	got2 := expiredStaleSessionDataCookies(ctx, opts, CookieRequestHeaders{}, header)
	expired2 := map[string]bool{}
	for _, c := range got2 {
		if c.MaxAge < 0 {
			expired2[c.Name] = true
		}
	}
	for _, want := range []string{"better-auth.session_data", "better-auth.session_data.0", "better-auth.session_data.1"} {
		if !expired2[want] {
			t.Fatalf("stale-cleanup %q must expire, got %v", want, got2)
		}
	}
}

// Skip-gate must suppress the c701 refresh.
func TestCookiesChunked_SkipGateSuppressesRefresh(t *testing.T) {
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	opts.Session.CookieCache.Enabled = true
	opts.Session.CookieCache.MaxAge = 300
	opts.Session.CookieCache.RefreshCache.Enabled = true
	seedSessionUser(t, db, "g8-skip@example.com", "tok-g8-skip", time.Now().UTC().Add(time.Hour))
	ctx := context.Background()
	row, urow, _, err := loadSessionAndUser(ctx, opts, "tok-g8-skip")
	if err != nil {
		t.Fatal(err)
	}
	session, user := rowToSession(row, opts), rowToUser(urow, opts)
	now := time.Now().UTC()
	payload := &sessionCookieCachePayload{Session: session, User: user, ExpiresAt: now.Add(30 * time.Second), Version: "1"}
	if got := maybeRefreshCookieCacheWithContext(ctx, opts, CookieRequestHeaders{}, "tok-g8-skip", payload, now, false); len(got) == 0 {
		t.Fatal("refresh must fire without the skip flag (sanity)")
	}
	skipped := state.SetShouldSkipSessionRefresh(ctx, true)
	if got := maybeRefreshCookieCacheWithContext(skipped, opts, CookieRequestHeaders{}, "tok-g8-skip", payload, now, false); got != nil {
		t.Fatalf("skip flag must suppress refresh, got %v", got)
	}
}
