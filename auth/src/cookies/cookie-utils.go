package cookies

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Upstream cookies/cookie-utils.ts
// SecureCookiePrefix marks HTTPS-only cookies; HostCookiePrefix is stricter (Secure+Path=/+no Domain).
const (
	SecureCookiePrefix = "__Secure-"
	HostCookiePrefix   = "__Host-"
)

// StripSecureCookiePrefix removes a leading __Secure- or __Host- prefix.
func StripSecureCookiePrefix(name string) string {
	if strings.HasPrefix(name, SecureCookiePrefix) {
		return strings.TrimPrefix(name, SecureCookiePrefix)
	}
	if strings.HasPrefix(name, HostCookiePrefix) {
		return strings.TrimPrefix(name, HostCookiePrefix)
	}
	return name
}

// CookiePrefix applies __Secure- prefix when secure.
func CookiePrefix(name string, secure bool) string {
	if secure {
		return SecureCookiePrefix + name
	}
	return name
}

// ResolveSecureWithProtocol resolves secure-cookie order: override, protocol, baseURL, production.
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

// ResolveSecure resolves secure for static baseURLs.
func ResolveSecure(useSecureCookies *bool, baseURL string, isProduction bool) bool {
	return ResolveSecureWithProtocol(useSecureCookies, baseURL, "", isProduction)
}

// CookieName builds wire name with __Secure- prefix when secure.
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

// ResolveDomain resolves cross-subdomain Domain or errors when undeterminable.
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

// Attributes describes Set-Cookie attributes; per-cookie overrides win over defaults.
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

// DefaultAttributes returns attribute defaults.
func DefaultAttributes(secure bool, domain string) Attributes {
	return Attributes{
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		HttpOnly: true,
		Domain:   domain,
	}
}

// WithOverrides applies non-zero overrides; Partitioned/SameSite=None force Secure (browsers reject otherwise).
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

// Serialize renders wire-accurate Set-Cookie; Max-Age emits even when 0 if set (net/http omits it).
func (a Attributes) Serialize(name, value string) string {
	var sb strings.Builder
	sb.WriteString(name)
	sb.WriteByte('=')
	sb.WriteString(value)
	if a.Path != "" {
		sb.WriteString("; Path=")
		sb.WriteString(a.Path)
	}
	if a.Domain != "" {
		sb.WriteString("; Domain=")
		sb.WriteString(a.Domain)
	}
	if a.ExpiresSet && !a.Expires.IsZero() {
		sb.WriteString("; Expires=")
		sb.WriteString(a.Expires.UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"))
	}
	if a.MaxAgeSet {
		sb.WriteString("; Max-Age=")
		sb.WriteString(strconv.Itoa(a.MaxAge))
	}
	if a.HttpOnly {
		sb.WriteString("; HttpOnly")
	}
	if a.Secure {
		sb.WriteString("; Secure")
	}
	if s := SameSiteString(a.SameSite); s != "" {
		sb.WriteString("; SameSite=")
		sb.WriteString(s)
	}
	if a.Partitioned {
		sb.WriteString("; Partitioned")
	}
	return sb.String()
}

// ToHTTPCookie converts Attributes to *http.Cookie.
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

// ParseSameSite parses upstream SameSite value; unknown yields DefaultMode.
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

// SameSiteString renders SameSite spelling.
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

// Request-cookie parsing only reads headers with upstream tolerance.

// ParseRequestCookies parses Cookie header; invalid names/values dropped, malformed escapes pass through.
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

// GetSessionCookie returns session cookie; __Secure- preferred, empty __Secure- does NOT fall back (nullish).
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

// preferSecureCookie prefers __Secure- variant even when empty (nullish).
func preferSecureCookie(cookies map[string]string, name string) (string, bool) {
	if v, ok := cookies[SecureCookiePrefix+name]; ok {
		return v, true
	}
	if v, ok := cookies[name]; ok {
		return v, true
	}
	return "", false
}

// trimOWS trims space/tab only; wider TrimSpace would let CTLs escape validation.
func trimOWS(s string) string {
	return strings.Trim(s, " \t")
}

// unquoteCookieValue strips one surrounding quote pair.
func unquoteCookieValue(value string) string {
	if len(value) < 2 || !strings.HasPrefix(value, `"`) || !strings.HasSuffix(value, `"`) {
		return value
	}
	return value[1 : len(value)-1]
}

// validCookieName reports RFC 7230 token validity.
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

// validCookieValue reports cookie-octet validity plus space/comma.
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

// tryDecodeCookieValue percent-decodes; malformed escapes pass through.
func tryDecodeCookieValue(value string) string {
	if !strings.Contains(value, "%") {
		return value
	}
	// PathUnescape matches decodeURIComponent (no "+" as space).
	if decoded, err := url.PathUnescape(value); err == nil {
		return decoded
	}
	return value
}

// Set-Cookie parsing and header writers preserve order like upstream Map merge.

// SetCookieAttributes is one parsed Set-Cookie line; unknown attrs preserved in Extra.
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
	Extra       map[string]string
}

// SetCookieEntry pairs name with attributes in wire order.
type SetCookieEntry struct {
	Name string
	Attr SetCookieAttributes
}

// SplitSetCookieHeader splits joined Set-Cookie; Expires commas never split.
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

// parseSetCookieList parses Set-Cookie into ordered entries.
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
				// Upstream: attrValue ? new Date(attrValue.trim()) : undefined.
				// A present-but-unparsable Expires (e.g. "0") yields an
				// Invalid Date (defined, not undefined). Go has no Invalid
				// Date; mirror with ExpiresSet=true + zero Time. Absent
				// (attrValue=="") stays unset. Callers must treat
				// zero+Set as invalid, never as epoch.
				if attrValue != "" {
					trimmed := strings.TrimSpace(attrValue)
					if t, ok := parseSetCookieDate(trimmed); ok {
						attr.Expires, attr.ExpiresSet = t, true
					} else {
						attr.Expires, attr.ExpiresSet = time.Time{}, true
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
				// Preserve unknown attributes in the parse map (upstream keeps
				// them; toCookieOptions drops them). Keys are lowercased;
				// flag-style attributes (no value) map to "true".
				key := strings.ToLower(strings.TrimSpace(attrName))
				if key == "" {
					continue
				}
				val := strings.TrimSpace(attrValue)
				if attrValue == "" {
					val = "true"
				}
				if attr.Extra == nil {
					attr.Extra = map[string]string{}
				}
				attr.Extra[key] = val
			}
		}
		out = append(out, SetCookieEntry{Name: name, Attr: attr})
	}
	return out
}

// ParseSetCookieHeader parses Set-Cookie; duplicates last-wins.
func ParseSetCookieHeader(setCookie string) map[string]SetCookieAttributes {
	out := map[string]SetCookieAttributes{}
	for _, e := range parseSetCookieList(setCookie) {
		out[e.Name] = e.Attr
	}
	return out
}

// ToAttributes converts to cookie options.
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

// setCookieDateLayouts parses Expires formats upstream accepts.
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

// parseJSInt parses with JS parseInt semantics; no digits yields ok=false.
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

// parseRequestPairs parses ordered pairs; duplicates update in place.
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

// EncodeCookieValue percent-encodes like encodeURIComponent (%XX uppercase).
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

// SetRequestCookieHeader adds/replaces name in place; malformed pairs dropped.
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

// ApplySetCookiesHeader merges Set-Cookie values; attributes stripped, last-wins.
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

// ExpireCookie builds expiry cookie; render via Serialize for explicit Max-Age=0 (net/http omits it).
func ExpireCookie(name string, attrs Attributes) *http.Cookie {
	expired := attrs
	expired.MaxAge = 0
	expired.MaxAgeSet = true
	return expired.ToHTTPCookie(name, "")
}

// ScrubSetCookieEntries removes prior entries for name and chunks; survivors keep order.
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
