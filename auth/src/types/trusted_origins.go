package types

import (
	"net/http"
	"net/url"
	"strings"
)

// TrustedOriginsEnvVar is the environment variable upstream reads for
// additional trusted origins (comma-separated). This package never reads it
// directly: match functions stay pure (no os.Getenv side effects). Callers
// read the variable themselves and pass the raw value to
// ParseTrustedOriginsEnv / ResolveTrustedOriginsWithEnv /
// IsTrustedOriginWithEnv.
//
// Upstream: env.BETTER_AUTH_TRUSTED_ORIGINS in
// vendor/better-auth/packages/better-auth/src/context/helpers.ts
// (getTrustedOrigins splits on "," and drops falsy entries).
const TrustedOriginsEnvVar = "BETTER_AUTH_TRUSTED_ORIGINS"

// TrustedOriginsResolver is the sync Go-faithful equivalent of upstream's
// dynamic trustedOrigins function variant.
//
// Upstream TypeScript type (Awaitable): (request?: Request) => string[] |
// Promise<string[]>. Go has no async function values, so async resolution
// must happen before calling into this package: resolve the promise upstream
// of the call and hand the resulting []string back synchronously. A nil
// request is valid (mirrors upstream hooks invoked without one).
//
// Options.TrustedOriginsFunc has the identical underlying shape and keeps
// working; this named type exists so request-aware helpers and integrators
// can declare the contract explicitly.
type TrustedOriginsResolver func(r *http.Request) []string

// ParseTrustedOriginsEnv is a PURE helper for TrustedOriginsEnvVar values.
// It splits on ",", trims ASCII whitespace around each entry, and drops
// empty entries. It never touches the environment; callers pass
// os.Getenv(TrustedOriginsEnvVar) (or a test fixture) in.
//
// Upstream splits on "," and filters falsy values without trimming; trimming
// here is additive hardening so "a, b" does not produce a " b" entry that
// can never match.
func ParseTrustedOriginsEnv(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

// FilterTrustedOrigins drops empty entries (upstream null/empty filtering).
// A nil input yields nil; the backing array is never mutated.
func FilterTrustedOrigins(origins []string) []string {
	out := make([]string, 0, len(origins))
	for _, origin := range origins {
		if origin == "" {
			continue
		}
		out = append(out, origin)
	}
	return out
}

// CollectTrustedOrigins merges a static list with per-request resolver
// results, dropping empty entries. Nil resolvers are skipped; a nil request
// is forwarded as-is.
func CollectTrustedOrigins(static []string, r *http.Request, resolvers ...TrustedOriginsResolver) []string {
	out := FilterTrustedOrigins(static)
	for _, resolver := range resolvers {
		if resolver == nil {
			continue
		}
		out = append(out, FilterTrustedOrigins(resolver(r))...)
	}
	return out
}

// ResolveTrustedOrigins collects the effective trusted-origin patterns for a
// request without touching the environment: the canonical BaseURL origin
// (always trusted), Options.TrustedOrigins, and Options.TrustedOriginsFunc(r)
// results. Empty entries are dropped at every stage.
//
// Upstream equivalent: getTrustedOrigins in
// vendor/better-auth/packages/better-auth/src/context/helpers.ts minus the
// env read and minus dynamic baseURL expansion (BaseURL stays a static
// string in this port; see DynamicBaseURLConfig, types-only).
func ResolveTrustedOrigins(opts Options, r *http.Request) []string {
	var out []string
	if opts.BaseURL != "" {
		if base, err := url.Parse(opts.BaseURL); err == nil && base.Host != "" {
			if origin, ok := webOriginOfURL(base); ok {
				out = append(out, origin)
			}
		}
	}
	out = append(out, FilterTrustedOrigins(opts.TrustedOrigins)...)
	if opts.TrustedOriginsFunc != nil {
		out = append(out, FilterTrustedOrigins(opts.TrustedOriginsFunc(r))...)
	}
	return FilterTrustedOrigins(out)
}

// ResolveTrustedOriginsWithEnv is ResolveTrustedOrigins plus a raw
// TrustedOriginsEnvVar value parsed via ParseTrustedOriginsEnv. The env
// value is a parameter (pure): pass os.Getenv(TrustedOriginsEnvVar) from the
// caller or a fixture in tests.
func ResolveTrustedOriginsWithEnv(opts Options, r *http.Request, envValue string) []string {
	out := ResolveTrustedOrigins(opts, r)
	out = append(out, ParseTrustedOriginsEnv(envValue)...)
	return FilterTrustedOrigins(out)
}

// IsTrustedRedirect accepts a trusted absolute origin or a safe root-relative
// URL. It mirrors Better Auth's allowRelativePaths mode used for callback URLs.
func IsTrustedRedirect(rawURL string, opts Options, r *http.Request) bool {
	if strings.HasPrefix(rawURL, "/") {
		return isSafeRelativeURL(rawURL)
	}
	return IsTrustedOrigin(rawURL, opts, r)
}

// IsTrustedOriginWithEnv is IsTrustedOrigin plus a raw TrustedOriginsEnvVar
// value (pure; see ResolveTrustedOriginsWithEnv).
func IsTrustedOriginWithEnv(rawURL string, opts Options, r *http.Request, envValue string) bool {
	if rawURL == "" {
		return false
	}
	for _, p := range ResolveTrustedOriginsWithEnv(opts, r, envValue) {
		if MatchesOriginPattern(rawURL, p) {
			return true
		}
	}
	return false
}

func isSafeRelativeURL(value string) bool {
	if !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") || strings.Contains(value, "\\") {
		return false
	}
	if hasControlChars(value) {
		return false
	}
	path := value
	if index := strings.IndexAny(path, "?#"); index >= 0 {
		path = path[:index]
	}
	if hasEncodedPathSeparator(path) {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.Host == "" && parsed.Scheme == ""
}

// IsTrustedOrigin reports whether rawURL comes from a trusted origin.
// The origin derived from opts.BaseURL is always trusted.
// opts.TrustedOrigins patterns and opts.TrustedOriginsFunc results are also checked.
// r is forwarded to TrustedOriginsFunc; nil is valid.
//
// Relative URLs ("/...") never match here; use IsTrustedRedirect for the
// allowRelativePaths mode. The environment variable is deliberately NOT
// read here (pure match path); use IsTrustedOriginWithEnv when env
// origins should apply.
func IsTrustedOrigin(rawURL string, opts Options, r *http.Request) bool {
	if rawURL == "" {
		return false
	}
	for _, p := range ResolveTrustedOrigins(opts, r) {
		if MatchesOriginPattern(rawURL, p) {
			return true
		}
	}
	return false
}

// MatchesOriginPattern reports whether rawURL matches a single origin pattern.
//
// Supported shapes (upstream trusted-origins.ts):
//   - Exact web origins: "https://example.com" matches the URL's origin;
//     any URL path, query, or fragment is ignored for the match.
//   - Wildcards: "*.example.com" (host-only) or "https://*.example.com"
//     (protocol-specific). Custom-scheme wildcards ("exp://192.168.*.*:*/*")
//     match against the full URL because custom schemes have no
//     web-platform origin.
//   - Custom schemes ("myapp://callback", "exp://", "myapp:/", ...): the
//     scheme must match; when the pattern pins an authority it must match
//     exactly (so "myapp://callback" rejects "myapp://callback.attacker.tld");
//     a host-less pattern trusts every host of the scheme. When the pattern
//     pins a path, the URL path must equal it or sit beneath it after
//     percent-decoding and dot-segment resolution, so traversal cannot
//     bypass the pin.
//
// Host canonicalization: scheme and host compare lowercased, one trailing
// "." is stripped (FQDN root), and explicit default ports (80 for http, 443
// for https) are ignored on both sides.
//
// Absolute URLs containing control characters (U+0000-U+001F, U+007F-U+009F),
// a backslash, or an encoded path separator (%2f/%5c, any case) in the path
// segment are rejected. Relative handling stays in isSafeRelativeURL.
func MatchesOriginPattern(rawURL, pattern string) bool {
	return matchesOriginPattern(rawURL, pattern, false)
}

// MatchesOriginPatternAllowRelative is MatchesOriginPattern with explicit
// upstream allowRelativePaths semantics: a root-relative rawURL ignores the
// pattern and reports isSafeRelativeURL(rawURL) when allow is true, and
// never matches when false.
func MatchesOriginPatternAllowRelative(rawURL, pattern string, allowRelativePaths bool) bool {
	return matchesOriginPattern(rawURL, pattern, allowRelativePaths)
}

func matchesOriginPattern(rawURL, pattern string, allowRelativePaths bool) bool {
	if rawURL == "" || pattern == "" {
		return false
	}
	if strings.HasPrefix(rawURL, "/") {
		return allowRelativePaths && isSafeRelativeURL(rawURL)
	}
	if hasControlChars(rawURL) || hasControlChars(pattern) {
		return false
	}
	if strings.Contains(rawURL, "\\") {
		return false
	}

	hasWildcard := strings.ContainsAny(pattern, "*?")

	if !hasWildcard {
		return matchExactOrigin(rawURL, pattern)
	}

	if strings.Contains(pattern, "://") {
		if isWebSchemePattern(pattern) {
			origin, ok := webOriginOfRawURL(rawURL)
			if !ok {
				return false
			}
			return WildcardMatch(strings.ToLower(pattern), origin)
		}
		// Custom-scheme wildcard: no web origin exists upstream
		// (getOrigin returns null), so the full URL is the sample.
		return WildcardMatch(pattern, rawURL)
	}

	host, ok := canonicalHostOfRawURL(rawURL)
	if !ok {
		return false
	}
	return WildcardMatch(strings.ToLower(pattern), host)
}

// matchExactOrigin handles the non-wildcard branch. Web (http/https/empty
// protocol) URLs compare canonical origins; every other scheme uses the
// custom-scheme authority + path-pinning rules.
func matchExactOrigin(rawURL, pattern string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "http" || scheme == "https" || scheme == "" {
		if scheme == "" || u.Host == "" {
			return false
		}
		if hasEncodedPathSeparator(escapedPathOf(u)) {
			return false
		}
		urlOrigin, ok := webOriginOfURL(u)
		if !ok {
			return false
		}
		patternOrigin, ok := webOriginOfPattern(pattern)
		if !ok {
			return false
		}
		return urlOrigin == patternOrigin
	}
	parsed := parseCustomSchemeOrigin(rawURL)
	parsedPattern := parseCustomSchemeOrigin(pattern)
	if parsed == nil || parsedPattern == nil || parsed.scheme != parsedPattern.scheme {
		return false
	}
	if parsedPattern.authority != "" && parsed.authority != parsedPattern.authority {
		return false
	}
	// A pattern without a path trusts every path; otherwise the URL path
	// must equal the pattern path or be nested beneath it.
	if parsedPattern.path == "" {
		return true
	}
	return parsed.path == parsedPattern.path ||
		strings.HasPrefix(parsed.path, parsedPattern.path+"/")
}

// isWebSchemePattern reports whether a "://" pattern targets http/https.
// The scheme is the substring before "://", compared case-insensitively.
func isWebSchemePattern(pattern string) bool {
	idx := strings.Index(pattern, "://")
	if idx <= 0 {
		return false
	}
	switch strings.ToLower(pattern[:idx]) {
	case "http", "https":
		return true
	default:
		return false
	}
}

// webOriginOfRawURL returns the canonical "scheme://host" origin of an
// http/https URL, or false when the URL has no usable web origin.
func webOriginOfRawURL(rawURL string) (string, bool) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "", false
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return webOriginOfURL(u)
	default:
		return "", false
	}
}

// webOriginOfPattern parses a non-wildcard web pattern into its canonical
// origin. Path, query, and fragment on the pattern are ignored for web
// origins (upstream compares pattern === getOrigin(url)).
func webOriginOfPattern(pattern string) (string, bool) {
	p, err := url.Parse(pattern)
	if err != nil || p.Host == "" {
		return "", false
	}
	switch strings.ToLower(p.Scheme) {
	case "http", "https":
		return webOriginOfURL(p)
	default:
		return "", false
	}
}

// canonicalHostOfRawURL returns the canonical "host[:port]" of an absolute
// URL: lowercased hostname with one trailing dot stripped, plus the explicit
// port unless it is the scheme default. It returns false when the URL has
// no host.
func canonicalHostOfRawURL(rawURL string) (string, bool) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "", false
	}
	host := canonicalHostname(u.Hostname())
	if host == "" {
		return "", false
	}
	port := u.Port()
	if isDefaultPort(strings.ToLower(u.Scheme), port) {
		port = ""
	}
	if port != "" {
		return host + ":" + port, true
	}
	return host, true
}

// webOriginOfURL returns the canonical origin of a parsed http/https URL.
func webOriginOfURL(u *url.URL) (string, bool) {
	if u == nil || u.Host == "" {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	host := canonicalHostname(u.Hostname())
	if host == "" {
		return "", false
	}
	port := u.Port()
	if isDefaultPort(scheme, port) {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		return scheme + "://" + host + ":" + port, true
	}
	return scheme + "://" + host, true
}

// canonicalHostname lowercases and strips one trailing dot (FQDN root).
//
// NOTE (IDNA/punycode decision, Wave 4): unicode hostnames are only
// lowercased here. Upstream relies on the WHATWG URL parser, which emits
// punycode for non-ASCII hosts. A faithful Go equivalent needs
// golang.org/x/net/idna, which is NOT in auth/go.mod (not even an indirect
// dependency), so no punycode conversion is applied and no new dependency is
// introduced. The gap is fail-closed: a unicode pattern only matches the
// same unicode spelling, and an xn-- punycode pattern does not match its
// unicode form (nor vice versa) — mismatches reject rather than bypass
// trust. Pinned by TestPublicTrustedOrigins_IDNADecision; deployments that
// need WHATWG-equivalent matching must add x/net explicitly.
func canonicalHostname(name string) string {
	lower := strings.ToLower(name)
	return strings.TrimSuffix(lower, ".")
}

// canonicalCustomAuthority lowercases a custom-scheme authority and strips
// one trailing dot so "myapp://callback." matches "myapp://callback".
func canonicalCustomAuthority(authority string) string {
	return strings.TrimSuffix(strings.ToLower(authority), ".")
}

func isDefaultPort(scheme, port string) bool {
	return (scheme == "http" && port == "80") || (scheme == "https" && port == "443")
}

func escapedPathOf(u *url.URL) string {
	if u == nil {
		return ""
	}
	escaped := u.EscapedPath()
	if escaped != "" {
		return escaped
	}
	return u.Path
}

// hasControlChars mirrors upstream CONTROL_CHARACTER_PATTERN
// (/[\u0000-\u001f\u007f-\u009f]/): any rune in U+0000-U+001F or U+007F-U+009F.
func hasControlChars(value string) bool {
	for _, r := range value {
		if r <= 0x1f || (r >= 0x7f && r <= 0x9f) {
			return true
		}
	}
	return false
}

// hasEncodedPathSeparator mirrors upstream ENCODED_PATH_SEPARATOR_PATTERN
// (/%2[fF]|%5[cC]/): an encoded "/" or "\" inside the path segment. Callers
// pass only the path slice (before ?#); encoded separators in the query or
// fragment are legitimate (e.g. "/callback?next=%2Fdashboard").
func hasEncodedPathSeparator(path string) bool {
	lower := strings.ToLower(path)
	return strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c")
}

// customSchemeOrigin is the string-parsed form of a custom-scheme URL.
// Plain string splitting is deliberate: net/url behavior for non-special
// schemes is not a stable cross-runtime contract upstream, so the authority
// boundary (first "/", "?", or "#") is located by hand, exactly like the
// TypeScript parseCustomSchemeOrigin.
type customSchemeOrigin struct {
	scheme    string
	authority string
	path      string
}

func parseCustomSchemeOrigin(value string) *customSchemeOrigin {
	if hasControlChars(value) {
		return nil
	}
	schemeEnd := strings.Index(value, ":")
	if schemeEnd <= 0 {
		return nil
	}
	scheme := strings.ToLower(value[:schemeEnd])
	rest := value[schemeEnd+1:]
	var authority string
	if strings.HasPrefix(rest, "//") {
		rest = rest[2:]
		if end := strings.IndexAny(rest, "/?#"); end == -1 {
			authority = rest
			rest = ""
		} else {
			authority = rest[:end]
			rest = rest[end:]
		}
	}
	if end := strings.IndexAny(rest, "?#"); end != -1 {
		rest = rest[:end]
	}
	return &customSchemeOrigin{
		scheme:    scheme,
		authority: canonicalCustomAuthority(authority),
		path:      normalizeCustomSchemePath(rest),
	}
}

// normalizeCustomSchemePath percent-decodes once (falling back to the raw
// path when the escaping is invalid) and resolves "." and ".." segments so
// a path-pinned pattern cannot be bypassed with traversal: e.g.
// "myapp://host/cb/../evil" normalizes to "/evil" and no longer satisfies
// pattern "myapp://host/cb". Returns "" for an empty or root path.
func normalizeCustomSchemePath(path string) string {
	decoded := path
	if unescaped, err := url.PathUnescape(path); err == nil {
		decoded = unescaped
	}
	segments := make([]string, 0, 8)
	for _, segment := range strings.Split(decoded, "/") {
		switch segment {
		case "..":
			if len(segments) > 0 {
				segments = segments[:len(segments)-1]
			}
		case ".", "":
		default:
			segments = append(segments, segment)
		}
	}
	if len(segments) == 0 {
		return ""
	}
	return "/" + strings.Join(segments, "/")
}

// WildcardMatch reports whether str matches pattern.
// * matches any sequence of characters; ? matches any single character.
func WildcardMatch(pattern, str string) bool {
	p, s := 0, 0
	starP, starS := -1, 0

	for s < len(str) {
		// Check '*' before literal equality: when the input itself
		// contains a literal '*' (legal URI sub-delim) at a wildcard
		// position, the equality branch would otherwise consume the
		// wildcard without registering backtrack state, turning a match
		// into a false negative (fail-closed, but wrong).
		if p < len(pattern) && pattern[p] == '*' {
			starP = p
			starS = s
			p++
		} else if p < len(pattern) && (pattern[p] == '?' || pattern[p] == str[s]) {
			p++
			s++
		} else if starP >= 0 {
			starS++
			s = starS
			p = starP + 1
		} else {
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}
