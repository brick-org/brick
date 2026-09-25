package cookies

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// Upstream cookies/session-store.ts; chunking primitives shared by both stores.

// MaxCookieSize is the per-cookie byte ceiling (Safari ~4093 floor, room for attributes).
const MaxCookieSize = 4050

// MaxCookieChunks is the cap; larger values skip cache for database.
const MaxCookieChunks = 100

// ChunkCookieValue splits into "<name>.<i>" chunks; oversize must skip cache for database.
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

// BuildChunkedCookies issues Set-Cookie entries sized by MaxValueSizeFor; oversize must skip cache for database.
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

// MaxValueSizeFor estimates value budget against worst-case "<name>.99" so chunks never overflow.
func MaxValueSizeFor(name string, attrs Attributes) int {
	worst := name + ".99"
	overhead := len(attrs.Serialize(worst, ""))
	return MaxCookieSize - overhead
}

// ParseChunkIndex returns chunk index; suffix must be canonical non-negative integer.
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

// JoinChunkedCookies reconstructs value; exact-name wins, else sorted chunks.
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
	// Insertion sort avoids importing sort for small counts.
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

// ExpiredChunks returns expiry cookies for name and chunks so stale chunks never survive logout.
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
