package cookies

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// Chunked cookie store, mirroring
// vendor/better-auth/packages/better-auth/src/cookies/session-store.ts
// (chunkCookie, getMaxCookieValueSize, parseCookieChunkIndex, getCleanCookies,
// getChunkedCookie).
//
// The account-cookie encode/decode helpers (setAccountCookie/getAccountCookie,
// upstream symmetricEncodeJWT/symmetricDecodeJWT with the "better-auth-account"
// salt) live in jwt.go alongside the session-cache codecs; this file holds the
// transport-only chunking primitives shared by both stores. Wire behavior is
// unchanged; this split only aligns file boundaries with upstream.

// MaxCookieSize is the per-cookie byte ceiling used by the upstream chunked
// session store (session-store.ts): Safari's ~4093 floor, kept a little under
// it for attributes added after sizing.
const MaxCookieSize = 4050

// MaxCookieChunks is the upstream cap on chunks per cookie. Larger values do
// not belong in a cookie; callers should skip the cache and fall back to the
// database.
const MaxCookieChunks = 100

// ChunkCookieValue splits value into numbered chunk names ("<name>.<i>"),
// mirroring the upstream session-store chunking (chunkCookie). Values that fit
// within maxValueSize are returned as a single entry under name; callers that
// want wire-accurate sizing should pass MaxCookieSize minus the serialized
// overhead of the cookie name and attributes (see MaxValueSizeFor). An error
// is returned when the value cannot fit within MaxCookieChunks chunks — the
// caller must then skip the cache and fall back to the database, matching the
// upstream "too large to store even after chunking" branch.
func ChunkCookieValue(name, value string, maxValueSize int) (map[string]string, error) {
	if maxValueSize <= 0 {
		return nil, fmt.Errorf("cookies: no room for a cookie value under %q with the given attributes", name)
	}
	count := (len(value) + maxValueSize - 1) / maxValueSize
	if len(value) == 0 {
		count = 1
	}
	if count > MaxCookieChunks {
		return nil, fmt.Errorf("cookies: value too large to store even after chunking (%d chunks)", count)
	}
	if count <= 1 {
		return map[string]string{name: value}, nil
	}
	out := make(map[string]string, count)
	for i := 0; i < count; i++ {
		start := i * maxValueSize
		end := start + maxValueSize
		if end > len(value) {
			end = len(value)
		}
		out[name+"."+strconv.Itoa(i)] = value[start:end]
	}
	return out, nil
}

// BuildChunkedCookies issues a session-data value as one or more Set-Cookie
// entries, mirroring upstream chunkCookie (session-store.ts:84-131) wired
// through the session store chunk() path. The value budget comes from
// MaxValueSizeFor (worst-case "<name>.99" sizing, so every emitted line
// fits MaxCookieSize); values fitting the budget emit a single cookie under
// the bare name, larger values split into indexed "<name>.<i>" chunks in
// order. An error is returned when the value cannot fit within
// MaxCookieChunks chunks (or the name+attributes alone overflow) — the
// caller must skip the cache and fall back to the database, matching the
// upstream warn-and-skip branch. Reads reassemble via JoinChunkedCookies.
func BuildChunkedCookies(name, value string, attrs Attributes) ([]*http.Cookie, error) {
	budget := MaxValueSizeFor(name, attrs)
	parts, err := ChunkCookieValue(name, value, budget)
	if err != nil {
		return nil, err
	}
	if len(parts) == 1 {
		if v, ok := parts[name]; ok {
			return []*http.Cookie{attrs.ToHTTPCookie(name, v)}, nil
		}
	}
	out := make([]*http.Cookie, 0, len(parts))
	for i := 0; i < len(parts); i++ {
		key := name + "." + strconv.Itoa(i)
		v, ok := parts[key]
		if !ok {
			return nil, fmt.Errorf("cookies: chunk map missing %q", key)
		}
		out = append(out, attrs.ToHTTPCookie(key, v))
	}
	return out, nil
}

// MaxValueSizeFor estimates the largest value that keeps the serialized
// Set-Cookie for name within MaxCookieSize, mirroring upstream
// getMaxCookieValueSize. The overhead is measured with the real http.Cookie
// serializer so it stays in sync with the wire; the estimate sizes against
// the worst-case chunk name ("<name>.99") so chunked cookies never overflow.
func MaxValueSizeFor(name string, attrs Attributes) int {
	worst := name + ".99"
	overhead := len(attrs.ToHTTPCookie(worst, "").String())
	return MaxCookieSize - overhead
}

// ParseChunkIndex returns the chunk index for cookieName when name has the
// form "<cookieName>.<index>", mirroring upstream parseCookieChunkIndex.
// It returns ok=false unless the suffix is a canonical non-negative integer
// (no leading zeros, no signs, no whitespace).
func ParseChunkIndex(cookieName, name string) (index int, ok bool) {
	prefix := cookieName + "."
	if !strings.HasPrefix(name, prefix) {
		return 0, false
	}
	suffix := strings.TrimPrefix(name, prefix)
	if suffix == "" {
		return 0, false
	}
	n, err := strconv.Atoi(suffix)
	if err != nil || n < 0 || strconv.Itoa(n) != suffix {
		return 0, false
	}
	return n, true
}

// JoinChunkedCookies reconstructs a (possibly chunked) cookie value from
// parsed request cookies, mirroring upstream getChunkedCookie/getCookieCache:
// an exact-name match wins; otherwise "<name>.<index>" entries are sorted by
// index and concatenated. It returns ok=false when nothing matches.
func JoinChunkedCookies(cookies map[string]string, name string) (value string, ok bool) {
	if v, found := cookies[name]; found {
		return v, true
	}
	type chunk struct {
		index int
		value string
	}
	var chunks []chunk
	for k, v := range cookies {
		if i, match := ParseChunkIndex(name, k); match {
			chunks = append(chunks, chunk{index: i, value: v})
		}
	}
	if len(chunks) == 0 {
		return "", false
	}
	// Insertion sort: chunk counts are small (<= MaxCookieChunks) and this
	// avoids importing sort for a trivial loop.
	for i := 1; i < len(chunks); i++ {
		for j := i; j > 0 && chunks[j].index < chunks[j-1].index; j-- {
			chunks[j], chunks[j-1] = chunks[j-1], chunks[j]
		}
	}
	var sb strings.Builder
	for _, c := range chunks {
		sb.WriteString(c.value)
	}
	return sb.String(), true
}

// ExpiredChunks returns expiry cookies (MaxAge=0, preserving attributes) for
// every stored entry under name, mirroring the upstream clean() path used by
// deleteSessionCookie. Both the bare name and any "<name>.<index>" chunks are
// expired so stale chunks never survive a shrink or logout.
func ExpiredChunks(cookies map[string]string, name string, attrs Attributes) []*http.Cookie {
	expired := attrs
	expired.MaxAge = 0
	expired.MaxAgeSet = true
	var out []*http.Cookie
	if _, found := cookies[name]; found {
		out = append(out, expired.ToHTTPCookie(name, ""))
	}
	for k := range cookies {
		if _, match := ParseChunkIndex(name, k); match {
			out = append(out, expired.ToHTTPCookie(k, ""))
		}
	}
	return out
}
