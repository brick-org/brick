package cookies

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Cookie prefix constants mirroring
// vendor/better-auth/packages/better-auth/src/cookies/cookie-utils.ts.
//
//   - SecureCookiePrefix ("__Secure-") marks cookies that must only be sent
//     over HTTPS. Upstream prepends it whenever the secure-cookie heuristic
//     resolves true.
//   - HostCookiePrefix ("__Host-") is the stricter variant (Secure + Path=/ +
//     no Domain). Upstream defines it but only applies __Secure- by default;
//     it is exported here so callers can opt into __Host- semantics.
const (
	SecureCookiePrefix = "__Secure-"
	HostCookiePrefix   = "__Host-"
)

// StripSecureCookiePrefix removes a leading __Secure- or __Host- prefix,
// mirroring upstream stripSecureCookiePrefix.
func StripSecureCookiePrefix(name string) string {
	if strings.HasPrefix(name, SecureCookiePrefix) {
		return strings.TrimPrefix(name, SecureCookiePrefix)
	}
	if strings.HasPrefix(name, HostCookiePrefix) {
		return strings.TrimPrefix(name, HostCookiePrefix)
	}
	return name
}

// CookiePrefix returns name with the __Secure- prefix applied when secure is
// true, mirroring upstream createCookieGetter (secureCookiePrefix).
func CookiePrefix(name string, secure bool) string {
	if secure {
		return SecureCookiePrefix + name
	}
	return name
}

// ResolveSecureWithProtocol mirrors the full upstream secure-cookie
// resolution order (createCookieGetter in cookies/index.ts):
//
//  1. useSecureCookies explicit override wins when non-nil.
//  2. A dynamic baseURL protocol of "https"/"http" wins next (explicit
//     per-request scheme for object baseURL configs; "auto"/"" falls
//     through because the request scheme is unknown at init time).
//  3. Otherwise a static baseURL starting with "https://" enables secure.
//  4. Otherwise fall back to isProduction (NODE_ENV === "production").
//
// The production flag is passed in because net/http has no process-wide
// NODE_ENV equivalent; callers typically derive it from their environment.
func ResolveSecureWithProtocol(useSecureCookies *bool, baseURL, protocol string, isProduction bool) bool {
	if useSecureCookies != nil {
		return *useSecureCookies
	}
	switch protocol {
	case "https":
		return true
	case "http":
		return false
	}
	if baseURL != "" {
		return strings.HasPrefix(baseURL, "https://")
	}
	return isProduction
}

// ResolveSecure mirrors the upstream secure-cookie resolution for static
// string baseURLs (no dynamic protocol). It delegates to
// ResolveSecureWithProtocol with an empty protocol.
func ResolveSecure(useSecureCookies *bool, baseURL string, isProduction bool) bool {
	return ResolveSecureWithProtocol(useSecureCookies, baseURL, "", isProduction)
}

// CookieName builds the wire cookie name for cookieName under prefix,
// applying the __Secure- prefix when secure. It mirrors upstream
// createCookie: `${secureCookiePrefix}${prefix}.${cookieName}` (or a
// per-cookie override name when customName is set).
func CookieName(prefix, cookieName string, secure bool, customName string) string {
	name := customName
	if name == "" {
		if prefix == "" {
			prefix = "better-auth"
		}
		name = prefix + "." + cookieName
	}
	return CookiePrefix(name, secure)
}

// ResolveDomain mirrors the upstream crossSubDomainCookies handling: when
// enabled, the cookie Domain is the explicit domain override or the hostname
// of the static baseURL. It returns an error when cross-subdomain cookies are
// enabled but no domain can be determined, matching the upstream
// BetterAuthError ("baseURL is required when crossSubdomainCookies are
// enabled").
func ResolveDomain(crossSubDomainEnabled bool, domainOverride, baseURL string) (string, error) {
	if !crossSubDomainEnabled {
		return "", nil
	}
	if domainOverride != "" {
		return domainOverride, nil
	}
	if baseURL != "" {
		if u, err := url.Parse(baseURL); err == nil && u.Hostname() != "" {
			return u.Hostname(), nil
		}
	}
	return "", fmt.Errorf("baseURL is required when crossSubdomainCookies are enabled")
}

// Attributes describes the Set-Cookie attributes for a Better Auth cookie.
// It mirrors better-call CookieOptions as used by upstream createCookie:
// Secure, SameSite (default "lax"), Path (default "/"), HttpOnly (default
// true), plus optional Domain (cross-subdomain), MaxAge, Expires, and
// Partitioned (CHIPS). Per-cookie attribute overrides win over defaults,
// matching the upstream spread order (defaults, then overrideAttributes,
// then advanced.cookies[name].attributes).
type Attributes struct {
	Secure      bool
	SameSite    http.SameSite
	Path        string
	HttpOnly    bool
	Domain      string
	MaxAge      int
	MaxAgeSet   bool
	Expires     time.Time
	ExpiresSet  bool
	Partitioned bool
}

// DefaultAttributes returns the upstream createCookie attribute defaults for
// the given secure/domain resolution.
func DefaultAttributes(secure bool, domain string) Attributes {
	return Attributes{
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		HttpOnly: true,
		Domain:   domain,
	}
}

// WithOverrides returns attrs with non-zero override fields applied on top,
// mirroring the upstream attribute spread order. SameSiteStrictMode,
// SameSiteLaxMode, and SameSiteNoneMode override the default; SameSiteDefaultMode
// leaves it unchanged. A Partitioned=true override forces Secure (Partitioned
// cookies are rejected by browsers without Secure, and SameSite=None likewise
// requires Secure), mirroring the upstream secure-prefix invariant.
func (a Attributes) WithOverrides(o Attributes) Attributes {
	out := a
	if o.Path != "" {
		out.Path = o.Path
	}
	if o.Domain != "" {
		out.Domain = o.Domain
	}
	if o.SameSite != http.SameSiteDefaultMode {
		out.SameSite = o.SameSite
	}
	if o.MaxAgeSet {
		out.MaxAge = o.MaxAge
		out.MaxAgeSet = true
	}
	if o.ExpiresSet {
		out.Expires = o.Expires
		out.ExpiresSet = true
	}
	// Booleans only override toward true here; clearing Secure/HttpOnly is
	// done via explicit constructors to avoid ambiguous zero values.
	if o.Secure {
		out.Secure = true
	}
	if o.HttpOnly {
		out.HttpOnly = true
	}
	if o.Partitioned {
		out.Partitioned = true
		out.Secure = true
	}
	if out.SameSite == http.SameSiteNoneMode {
		out.Secure = true
	}
	return out
}

// ToHTTPCookie converts Attributes to a *http.Cookie for name=value.
func (a Attributes) ToHTTPCookie(name, value string) *http.Cookie {
	c := &http.Cookie{
		Name:        name,
		Value:       value,
		Path:        a.Path,
		Domain:      a.Domain,
		Secure:      a.Secure,
		HttpOnly:    a.HttpOnly,
		SameSite:    a.SameSite,
		Partitioned: a.Partitioned,
	}
	if a.MaxAgeSet {
		c.MaxAge = a.MaxAge
	}
	if a.ExpiresSet {
		c.Expires = a.Expires
	}
	return c
}

// ParseSameSite parses an upstream-style SameSite attribute value
// ("strict" | "lax" | "none", case-insensitive) into http.SameSite,
// mirroring parseSetCookieHeader. Unknown values yield SameSiteDefaultMode.
func ParseSameSite(s string) http.SameSite {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "strict":
		return http.SameSiteStrictMode
	case "lax":
		return http.SameSiteLaxMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteDefaultMode
	}
}

// SameSiteString renders an http.SameSite back to its upstream attribute
// spelling.
func SameSiteString(s http.SameSite) string {
	switch s {
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return ""
	}
}

// Request-cookie parsing and session-cookie lookup, mirroring
// vendor/better-auth/packages/better-auth/src/cookies/cookie-utils.ts
// (parseCookies) and the getSessionCookie helper in cookies/index.ts.
//
// Wire behavior of issued cookies is unchanged; these helpers only read the
// Cookie request header with upstream's tolerance rules.

// ParseRequestCookies parses a Cookie request header into name/value pairs,
// mirroring upstream parseCookies:
//
//   - Pairs are split on ";" (the single space mandated by RFC 6265 §4.2.1 is
//     tolerated when missing, since proxies commonly strip it).
//   - Chunks without "=" are dropped; names and values are trimmed of OWS
//     (space / horizontal tab only, per RFC 7230 §3.2.3).
//   - Optional surrounding double-quotes are stripped per RFC 6265 §4.1.1.
//   - Entries whose name violates the RFC 7230 token set or whose value
//     violates the RFC 6265 cookie-octet set (plus space and comma) are
//     silently dropped; surviving values are percent-decoded with malformed
//     escapes passed through verbatim (tryDecode).
func ParseRequestCookies(header string) map[string]string {
	out := map[string]string{}
	if len(header) < 2 {
		return out
	}
	for _, chunk := range strings.Split(header, ";") {
		eq := strings.IndexByte(chunk, '=')
		if eq < 0 {
			continue
		}
		key := trimOWS(chunk[:eq])
		val := unquoteCookieValue(trimOWS(chunk[eq+1:]))
		if !validCookieName(key) || !validCookieValue(val) {
			continue
		}
		out[key] = tryDecodeCookieValue(val)
	}
	return out
}

// GetSessionCookie returns the session-token cookie value from parsed request
// cookies, mirroring upstream getSessionCookie:
//
//   - Both "." and "-" separators are accepted
//     ("<prefix>.<name>" and "<prefix>-<name>"); writers always emit ".".
//   - A "__Secure-" prefixed cookie is preferred over a non-secure leftover
//     with the same name.
//   - An empty "__Secure-" value does NOT fall back to the non-secure
//     leftover for the same separator (upstream nullish semantics); lookup
//     then continues with the "-" separator variant.
//
// Empty prefix defaults to "better-auth" and an empty cookieName to
// "session_token", matching upstream defaults.
func GetSessionCookie(cookies map[string]string, prefix, cookieName string) (string, bool) {
	if prefix == "" {
		prefix = "better-auth"
	}
	if cookieName == "" {
		cookieName = "session_token"
	}
	if v, ok := preferSecureCookie(cookies, prefix+"."+cookieName); ok && v != "" {
		return v, true
	}
	if v, ok := preferSecureCookie(cookies, prefix+"-"+cookieName); ok && v != "" {
		return v, true
	}
	return "", false
}

// preferSecureCookie returns the "__Secure-" variant when present (even when
// empty, mirroring upstream "??" nullish semantics), else the bare name.
func preferSecureCookie(cookies map[string]string, name string) (string, bool) {
	if v, ok := cookies[SecureCookiePrefix+name]; ok {
		return v, true
	}
	if v, ok := cookies[name]; ok {
		return v, true
	}
	return "", false
}

// trimOWS trims leading/trailing OWS (space / horizontal tab) per RFC 7230
// §3.2.3. Narrower than strings.TrimSpace, which would strip CR/LF and let
// CTLs escape validCookieValue.
func trimOWS(s string) string {
	return strings.Trim(s, " \t")
}

// unquoteCookieValue strips one pair of surrounding double-quotes per
// RFC 6265 §4.1.1 quoted-string form.
func unquoteCookieValue(value string) string {
	if len(value) < 2 || !strings.HasPrefix(value, `"`) || !strings.HasSuffix(value, `"`) {
		return value
	}
	return value[1 : len(value)-1]
}

// validCookieName reports whether name is a valid cookie-name token per
// RFC 7230 §3.2.6 (upstream cookieNameRegex).
func validCookieName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		ok := c == 0x21 || (c >= 0x23 && c <= 0x27) || c == 0x2A || c == 0x2B ||
			c == 0x2D || c == 0x2E || (c >= 0x30 && c <= 0x39) ||
			(c >= 0x41 && c <= 0x5A) || c == 0x5E || c == 0x5F || c == 0x60 ||
			(c >= 0x61 && c <= 0x7A) || c == 0x7C || c == 0x7E
		if !ok {
			return false
		}
	}
	return true
}

// validCookieValue reports whether value uses only cookie-octets per
// RFC 6265 §4.1.1 plus space and comma (upstream cookieValueRegex).
func validCookieValue(value string) bool {
	for i := 0; i < len(value); i++ {
		c := value[i]
		ok := c == 0x20 || c == 0x21 || (c >= 0x23 && c <= 0x3A) ||
			(c >= 0x3C && c <= 0x5B) || (c >= 0x5D && c <= 0x7E)
		if !ok {
			return false
		}
	}
	return true
}

// tryDecodeCookieValue percent-decodes value, returning it verbatim when it
// holds no "%" or the escapes are malformed (upstream tryDecode).
func tryDecodeCookieValue(value string) string {
	if !strings.Contains(value, "%") {
		return value
	}
	// PathUnescape decodes %XX without treating "+" as space, matching
	// decodeURIComponent semantics for cookie values.
	if decoded, err := url.PathUnescape(value); err == nil {
		return decoded
	}
	return value
}

// Set-Cookie response parsing and request-cookie writes, mirroring
// vendor/better-auth/packages/better-auth/src/cookies/cookie-utils.ts
// (splitSetCookieHeader, parseSetCookieHeader, toCookieOptions,
// setRequestCookie, applySetCookies) and the expireCookie helper in
// cookies/index.ts.
//
// The request-header writers operate on serialized Cookie header strings
// (net/http has no JS-Headers equivalent here) with order-preserving
// parse-mutate-serialize semantics matching the upstream Map-based merge.

// SetCookieAttributes is one parsed Set-Cookie line, mirroring upstream
// CookieAttributes: the decoded value plus the recognized attributes.
// Unrecognized attributes are dropped (toCookieOptions ignores them too).
type SetCookieAttributes struct {
	Value       string
	MaxAge      int
	MaxAgeSet   bool
	Expires     time.Time
	ExpiresSet  bool
	Domain      string
	Path        string
	Secure      bool
	HttpOnly    bool
	Partitioned bool
	SameSite    http.SameSite
}

// SetCookieEntry pairs a cookie name with its parsed attributes, preserving
// wire order for multi-cookie headers.
type SetCookieEntry struct {
	Name string
	Attr SetCookieAttributes
}

// SplitSetCookieHeader splits a comma-joined Set-Cookie header into
// individual cookie strings, mirroring upstream splitSetCookieHeader: a
// comma starts a new cookie only when the text after it (past spaces) runs
// to "=" before any ";" or "," — so Expires dates ("Mon, 02 Mar ... GMT;
// ...") never split.
func SplitSetCookieHeader(setCookie string) []string {
	if setCookie == "" {
		return nil
	}
	var result []string
	start := 0
	i := 0
	for i < len(setCookie) {
		if setCookie[i] == ',' {
			j := i + 1
			for j < len(setCookie) && setCookie[j] == ' ' {
				j++
			}
			for j < len(setCookie) && setCookie[j] != '=' && setCookie[j] != ';' && setCookie[j] != ',' {
				j++
			}
			if j < len(setCookie) && setCookie[j] == '=' {
				if part := strings.TrimSpace(setCookie[start:i]); part != "" {
					result = append(result, part)
				}
				start = i + 1
				for start < len(setCookie) && setCookie[start] == ' ' {
					start++
				}
				i = start
				continue
			}
		}
		i++
	}
	if last := strings.TrimSpace(setCookie[start:]); last != "" {
		result = append(result, last)
	}
	return result
}

// parseSetCookieList parses a Set-Cookie header into ordered entries,
// mirroring upstream parseSetCookieHeader before its Map assembly.
func parseSetCookieList(setCookie string) []SetCookieEntry {
	var out []SetCookieEntry
	for _, line := range SplitSetCookieHeader(setCookie) {
		rawParts := strings.Split(line, ";")
		parts := make([]string, len(rawParts))
		for i, p := range rawParts {
			parts[i] = strings.TrimSpace(p)
		}
		nameValue := parts[0]
		var name, rawValue string
		if eq := strings.IndexByte(nameValue, '='); eq < 0 {
			name = nameValue
		} else {
			name = nameValue[:eq]
			rawValue = nameValue[eq+1:]
		}
		if name == "" {
			continue
		}
		attr := SetCookieAttributes{Value: tryDecodeCookieValue(unquoteCookieValue(rawValue))}
		for _, a := range parts[1:] {
			var attrName, attrValue string
			if eq := strings.IndexByte(a, '='); eq < 0 {
				attrName = a
			} else {
				attrName = a[:eq]
				attrValue = a[eq+1:]
			}
			switch strings.ToLower(strings.TrimSpace(attrName)) {
			case "max-age":
				if attrValue != "" {
					if n, ok := parseJSInt(attrValue); ok {
						attr.MaxAge, attr.MaxAgeSet = n, true
					}
				}
			case "expires":
				if attrValue != "" {
					if t, ok := parseSetCookieDate(strings.TrimSpace(attrValue)); ok {
						attr.Expires, attr.ExpiresSet = t, true
					}
				}
			case "domain":
				if attrValue != "" {
					attr.Domain = strings.TrimSpace(attrValue)
				}
			case "path":
				if attrValue != "" {
					attr.Path = strings.TrimSpace(attrValue)
				}
			case "secure":
				attr.Secure = true
			case "httponly":
				attr.HttpOnly = true
			case "samesite":
				if attrValue != "" {
					attr.SameSite = ParseSameSite(attrValue)
				}
			case "partitioned":
				attr.Partitioned = true
			default:
				// Any other attribute is ignored (toCookieOptions drops it).
			}
		}
		out = append(out, SetCookieEntry{Name: name, Attr: attr})
	}
	return out
}

// ParseSetCookieHeader parses a Set-Cookie header into name/attributes
// pairs, mirroring upstream parseSetCookieHeader. Values are unquoted per
// RFC 6265 §4.1.1 quoted-string form and percent-decoded (malformed escapes
// pass through verbatim). Duplicate names resolve last-wins, matching the
// upstream Map assembly.
func ParseSetCookieHeader(setCookie string) map[string]SetCookieAttributes {
	out := map[string]SetCookieAttributes{}
	for _, e := range parseSetCookieList(setCookie) {
		out[e.Name] = e.Attr
	}
	return out
}

// ToAttributes converts parsed Set-Cookie attributes into cookie options,
// mirroring upstream toCookieOptions.
func (a SetCookieAttributes) ToAttributes() Attributes {
	return Attributes{
		Path:        a.Path,
		Expires:     a.Expires,
		ExpiresSet:  a.ExpiresSet,
		MaxAge:      a.MaxAge,
		MaxAgeSet:   a.MaxAgeSet,
		Secure:      a.Secure,
		HttpOnly:    a.HttpOnly,
		SameSite:    a.SameSite,
		Partitioned: a.Partitioned,
		Domain:      a.Domain,
	}
}

// setCookieDateLayouts parses the Expires formats upstream accepts via
// `new Date(...)`: IMF-fixdate (RFC 1123), the RFC 850 variant, and asctime.
var setCookieDateLayouts = []string{
	time.RFC1123,
	time.RFC850,
	time.ANSIC,
	"Monday, 02-Jan-2006 15:04:05 MST",
}

func parseSetCookieDate(s string) (time.Time, bool) {
	for _, layout := range setCookieDateLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// parseJSInt parses an integer with JavaScript parseInt(s, 10) semantics:
// leading whitespace, an optional sign, then the longest leading digit run.
// It returns ok=false when no digits follow (NaN upstream).
func parseJSInt(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	i := 0
	if s[0] == '+' || s[0] == '-' {
		i = 1
	}
	j := i
	for j < len(s) && s[j] >= '0' && s[j] <= '9' {
		j++
	}
	if j == i {
		return 0, false
	}
	n, err := strconv.Atoi(s[:j])
	if err != nil {
		return 0, false
	}
	return n, true
}

type cookiePair struct {
	name  string
	value string
}

// parseRequestPairs parses a Cookie header into ordered, decoded pairs with
// a name index, mirroring upstream parseCookies plus Map insertion order
// (duplicate names update in place, keeping first position).
func parseRequestPairs(header string) ([]cookiePair, map[string]int) {
	index := map[string]int{}
	if len(header) < 2 {
		return nil, index
	}
	var pairs []cookiePair
	for _, chunk := range strings.Split(header, ";") {
		eq := strings.IndexByte(chunk, '=')
		if eq < 0 {
			continue
		}
		key := trimOWS(chunk[:eq])
		val := unquoteCookieValue(trimOWS(chunk[eq+1:]))
		if !validCookieName(key) || !validCookieValue(val) {
			continue
		}
		val = tryDecodeCookieValue(val)
		if i, ok := index[key]; ok {
			pairs[i].value = val
		} else {
			index[key] = len(pairs)
			pairs = append(pairs, cookiePair{name: key, value: val})
		}
	}
	return pairs, index
}

func serializeCookiePairs(pairs []cookiePair) string {
	parts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		parts = append(parts, p.name+"="+EncodeCookieValue(p.value))
	}
	return strings.Join(parts, "; ")
}

// EncodeCookieValue percent-encodes a semantic cookie value for the Cookie
// wire header, mirroring encodeURIComponent on write (upstream
// setRequestCookie/applySetCookies): every byte outside the unreserved set
// becomes %XX (uppercase hex), including UTF-8 continuation bytes.
func EncodeCookieValue(s string) string {
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~*'()"
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if strings.IndexByte(unreserved, c) >= 0 {
			sb.WriteByte(c)
		} else {
			const hexd = "0123456789ABCDEF"
			sb.WriteByte('%')
			sb.WriteByte(hexd[c>>4])
			sb.WriteByte(hexd[c&0x0F])
		}
	}
	return sb.String()
}

// SetRequestCookieHeader adds or replaces name in the Cookie request header,
// mirroring upstream setRequestCookie: existing pairs are preserved in order
// (RFC 6265 "; " join), a same-name entry is replaced in place, malformed
// pairs are dropped, and the value is percent-encoded on serialize. Names
// outside the RFC 7230 token set are ignored (the header is still rebuilt
// from the surviving pairs).
func SetRequestCookieHeader(header, name, value string) string {
	pairs, index := parseRequestPairs(header)
	if validCookieName(name) {
		if i, ok := index[name]; ok {
			pairs[i].value = value
		} else {
			pairs = append(pairs, cookiePair{name: name, value: value})
		}
	}
	return serializeCookiePairs(pairs)
}

// ApplySetCookiesHeader merges Set-Cookie header values into the Cookie
// request header, mirroring upstream applySetCookies: only name=value lands
// (attributes stripped), last-wins on duplicate names keeping first
// position, values re-encoded on the wire join, and quoted-string wrapping
// stripped via the Set-Cookie parse.
func ApplySetCookiesHeader(header string, setCookies []string) string {
	pairs, index := parseRequestPairs(header)
	for _, sc := range setCookies {
		for _, e := range parseSetCookieList(sc) {
			if !validCookieName(e.Name) {
				continue
			}
			if i, ok := index[e.Name]; ok {
				pairs[i].value = e.Attr.Value
			} else {
				index[e.Name] = len(pairs)
				pairs = append(pairs, cookiePair{name: e.Name, value: e.Attr.Value})
			}
		}
	}
	return serializeCookiePairs(pairs)
}

// ExpireCookie builds the expiry cookie for name (empty value, MaxAge=0,
// attributes preserved), mirroring upstream expireCookie's setCookie call.
// Wire rendering of MaxAge=0 follows net/http (absent attribute; MaxAge<0
// renders "Max-Age=0"); callers that need the explicit wire attribute map
// through their serializer.
func ExpireCookie(name string, attrs Attributes) *http.Cookie {
	expired := attrs
	expired.MaxAge = 0
	expired.MaxAgeSet = true
	return expired.ToHTTPCookie(name, "")
}

// ScrubSetCookieEntries removes prior Set-Cookie entries for name and its
// chunked variants ("<name>.<i>") from serialized entries, mirroring the
// collapsed-header fallback of upstream removeSetCookieEntries (used when
// Headers.getSetCookie is unavailable). Survivors keep wire order.
func ScrubSetCookieEntries(entries []string, name string) []string {
	exact, chunk := name+"=", name+"."
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasPrefix(e, exact) || strings.HasPrefix(e, chunk) {
			continue
		}
		out = append(out, e)
	}
	return out
}
