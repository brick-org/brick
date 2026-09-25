package routes

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"time"

	"github.com/brick-org/brick/auth/src/cookies"
	"github.com/brick-org/brick/auth/src/types"
)

// AUTH-C7-01: session cookie-name/chunk recovery, dynamic secure/domain via
// request context, AdditionalCookies propagation, custom JWKS signer path,
// and stateless guards.
//
// Upstream refs (pinned 5468e6bf):
//   - cookies/index.ts (getCookies, createCookieGetter, setCookieCache,
//     decodeCookieCache, deleteSessionCookie chunk clean, getSessionCookie
//     "."/"-" + __Secure- handling)
//   - cookies/session-store.ts (getChunkedCookie, chunkCookie, clean)
//   - cookies/jwt.ts (verifySessionCookieJwtWithJwks typ/kid/aud/iss/sub/sid)
//   - crypto/jwt.ts (signJWT/verifyJWT, symmetricEncode/DecodeJWT)
//   - api/routes/session.ts (cache fast path, version/token/expiry binding,
//     cookieRefreshCache, isStateful, fresh middleware, authoritative reads)
//   - plugins/jwt/cookie-cache.ts (createCookieCacheSigner sign/verify)
//   - context/create-context.ts (sessionConfig defaults, isStateful)
//   - core init-options.ts (crossSubDomainCookies.additionalCookies)

const (
	// sessionDataCookieBase is the upstream session_data cookie key
	// (getCookies: "<prefix>.session_data").
	sessionDataCookieBase = "session_data"
)

// resolveSessionDataCookieName mirrors resolveSessionCookieName for the
// session_data cookie: "<prefix>.session_data" (or the Advanced.Cookies
// override), with the __Secure- prefix under secure cookies.
func resolveSessionDataCookieName(opts types.Options, secure bool) string {
	baseName := defaultCookiePrefix + "." + sessionDataCookieBase
	if opts.Advanced.CookiePrefix != "" {
		baseName = opts.Advanced.CookiePrefix + "." + sessionDataCookieBase
	}
	if override, ok := opts.Advanced.Cookies[sessionDataCookieBase]; ok && override.Name != "" {
		baseName = override.Name
	}
	if secure {
		return secureCookiePrefix + baseName
	}
	return baseName
}

// sessionDataCookieLookupNames returns the cookie names accepted when reading
// the session_data cache, mirroring upstream recovery:
//
//   - The configured names (secure + non-secure, custom prefix/override
//     aware) so current deployments read their own cookies.
//   - The Go legacy "auth_session_data" so pre-migration cookies still read.
//   - The upstream defaults ("better-auth.session_data" + __Secure- + dash
//     variants) so TS-issued cookies and cross-subdomain leftovers recover
//     instead of forcing a logout (cookie-cache-fallback.test.ts).
//
// Exact-name matches win; otherwise "<name>.<index>" chunks reassemble via
// cookies.JoinChunkedCookies (session-store.ts getChunkedCookie).
func sessionDataCookieLookupNames(opts types.Options) []string {
	names := []string{
		resolveSessionDataCookieName(opts, false),
		resolveSessionDataCookieName(opts, true),
		sessionDataCookieName,
		"better-auth.session_data",
		"__Secure-better-auth.session_data",
		"better-auth-session_data",
		"__Secure-better-auth-session_data",
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(names))
	for _, name := range names {
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}

// sessionDataCookieValue recovers the session_data value from a Cookie
// header, trying each lookup name with exact-then-chunk reassembly.
func sessionDataCookieValue(cookieHeader string, opts types.Options) (string, bool) {
	if cookieHeader == "" {
		return "", false
	}
	parsed := cookies.ParseRequestCookies(cookieHeader)
	for _, name := range sessionDataCookieLookupNames(opts) {
		if value, ok := cookies.JoinChunkedCookies(parsed, name); ok && value != "" {
			return value, true
		}
	}
	return "", false
}

// sessionDataCookieValueForSession is the SessionOptions-only recovery used
// by the frozen cachedSessionFromRequest wrapper (no Advanced context):
// default + legacy + upstream names with chunk reassembly.
func sessionDataCookieValueForSession(cookieHeader string) (string, bool) {
	if cookieHeader == "" {
		return "", false
	}
	parsed := cookies.ParseRequestCookies(cookieHeader)
	for _, name := range []string{
		sessionDataCookieName,
		"better-auth.session_data",
		"__Secure-better-auth.session_data",
		"better-auth-session_data",
		"__Secure-better-auth-session_data",
	} {
		if value, ok := cookies.JoinChunkedCookies(parsed, name); ok && value != "" {
			return value, true
		}
	}
	return "", false
}

// cachedSessionFromRequestFull is the context-aware cookie-cache fast path
// (upstream session.ts:114-284 + decodeCookieCache):
//
//   - Chunk-aware, cookie-name-aware recovery (including custom
//     Advanced.Cookies names and upstream defaults).
//   - Strategy-aware decode with the custom JWKS signer first when a JWT
//     plugin provides it (key rotation, typ/kid/aud/iss/sub/sid binding),
//     then the default-secret codecs. Any failure falls through to the
//     database (fail closed, never trust); a custom-signer deployment never
//     trusts secret-signed values as cache hits (authoritative fallback).
//   - Token, outer-window, embedded-session-expiry, and version binding
//     exactly like cachedSessionFromRequest.
func cachedSessionFromRequestFull(ctx context.Context, cookieHeader string, secrets []string, token string, opts types.Options) (*sessionCookieCachePayload, bool) {
	if !opts.Session.CookieCache.Enabled || token == "" || cookieHeader == "" {
		return nil, false
	}
	value, ok := sessionDataCookieValue(cookieHeader, opts)
	if !ok {
		return nil, false
	}
	var payload *sessionCookieCachePayload
	strategy := cookieCacheStrategy(opts.Session)
	if strategy == cookies.StrategyJWT {
		if signer, found := findCookieCacheSigner(opts); found {
			if custom, ok := verifyViaCustomSigner(ctx, opts, signer, value); ok {
				payload = custom
			} else {
				// Custom-signer deployments fail closed to the
				// authoritative store: a secret-signed or foreign token
				// is never a cache hit (session-api.test.ts: secret-signed
				// rejection, tamper fallback).
				return nil, false
			}
		} else {
			payload, _ = jwtCachePayloadWarn(value, secrets, opts)
		}
	} else if strategy == cookies.StrategyJWE {
		payload, _ = jweCachePayloadWarn(value, secrets, opts)
	} else {
		payload, _ = compactCachePayloadWarn(value, secrets, opts)
	}
	if payload == nil {
		return nil, false
	}
	now := time.Now().UTC()
	if payload.Session.Token != token || now.After(payload.ExpiresAt) || now.After(payload.Session.ExpiresAt) {
		return nil, false
	}
	if expected, verr := resolveCookieCacheVersion(payload.Session, payload.User, opts.Session); verr != nil || normalizeCookieCacheVersion(payload.Version) != expected {
		return nil, false
	}
	return payload, true
}

// findCookieCacheSigner returns the JWT plugin's custom signer when present,
// without importing plugins/jwt (which would cycle via the auth root).
// Detection is duck-typed: a types.Plugin with ID "jwt" exposing
// SignCookieCache/VerifyCookieCache methods.
func findCookieCacheSigner(opts types.Options) (any, bool) {
	for _, p := range opts.Plugins {
		if p == nil {
			continue
		}
		if p.ID() != "jwt" {
			continue
		}
		v := reflect.ValueOf(p)
		if !v.IsValid() {
			continue
		}
		sign := v.MethodByName("SignCookieCache")
		verify := v.MethodByName("VerifyCookieCache")
		if !sign.IsValid() || !verify.IsValid() {
			continue
		}
		return p, true
	}
	return nil, false
}

// signViaCustomSigner issues a session_data value through the JWT plugin's
// custom signer (upstream setCookieCache jwt branch with cookieCacheSigner).
// Session/user convert via the Go-canonical nested shape; maxAge uses the
// upstream `maxAge || 60*5` default. The effective opts (BaseURL already
// resolved to the request origin) bind the iss claim.
//
// The maps are filtered for schema-declared returned:false additional fields
// (upstream setCookieCache filterOutputFields/parseUserOutput) so the custom
// signer shares the same cache-payload contract as the secret strategies;
// core columns and unknown fields are always kept.
func signViaCustomSigner(ctx context.Context, opts types.Options, signer any, session types.Session, user types.User, version string, maxAge time.Duration) (string, error) {
	sm, err := cacheStructMap(session)
	if err != nil {
		return "", err
	}
	um, err := cacheStructMap(user)
	if err != nil {
		return "", err
	}
	filterCookieCacheMaps(sm, um, opts, opts.Session)
	if maxAge <= 0 {
		maxAge = 5 * time.Minute
	}
	v := reflect.ValueOf(signer)
	method := v.MethodByName("SignCookieCache")
	if !method.IsValid() {
		return "", errCustomSignerMissing
	}
	payloadType := method.Type().In(2)
	payload := reflect.New(payloadType).Elem()
	if f := payload.FieldByName("Session"); f.IsValid() && f.CanSet() {
		f.Set(reflect.ValueOf(sm))
	}
	if f := payload.FieldByName("User"); f.IsValid() && f.CanSet() {
		f.Set(reflect.ValueOf(um))
	}
	if f := payload.FieldByName("UpdatedAt"); f.IsValid() && f.CanSet() {
		f.SetInt(time.Now().UnixMilli())
	}
	if f := payload.FieldByName("Version"); f.IsValid() && f.CanSet() {
		f.SetString(version)
	}
	results := method.Call([]reflect.Value{
		reflect.ValueOf(ctx),
		reflect.ValueOf(opts),
		payload,
		reflect.ValueOf(maxAge),
	})
	if len(results) != 2 {
		return "", errCustomSignerMissing
	}
	token, _ := results[0].Interface().(string)
	if err, _ := results[1].Interface().(error); err != nil {
		return "", err
	}
	if token == "" {
		return "", errCustomSignerMissing
	}
	return token, nil
}

// verifyViaCustomSigner verifies a session_data value through the JWT
// plugin's custom signer, converting the verified payload into the shared
// cache shape. Any failure is a miss (authoritative fallback).
// warnCacheSchemaIssue routes schema-invalid cache payloads to the
// configured logger (upstream parseCookieCachePayload warn in
// cookies/cache.ts:32-35). All such payloads miss regardless — the warn is
// observability only, never a throw.
func warnCacheSchemaIssue(opts types.Options, err error) {
	if errors.Is(err, cookies.ErrCachePayloadSchema) {
		Logf(opts, "warn", "Cookie cache payload failed schema validation")
	}
}

func jwtCachePayloadWarn(value string, secrets []string, opts types.Options) (*sessionCookieCachePayload, bool) {
	payload, err := jwtCachePayload(value, secrets)
	warnCacheSchemaIssue(opts, err)
	if err != nil {
		return nil, false
	}
	return payload, true
}

func jweCachePayloadWarn(value string, secrets []string, opts types.Options) (*sessionCookieCachePayload, bool) {
	payload, err := jweCachePayload(value, secrets)
	warnCacheSchemaIssue(opts, err)
	if err != nil {
		return nil, false
	}
	return payload, true
}

func compactCachePayloadWarn(value string, secrets []string, opts types.Options) (*sessionCookieCachePayload, bool) {
	payload, err := compactCachePayload(value, secrets)
	warnCacheSchemaIssue(opts, err)
	if err != nil {
		return nil, false
	}
	return payload, true
}

// verifyViaCustomSigner verifies a session_data value through the JWT
// plugin's custom signer, converting the verified payload into the shared
// cache shape. Any failure is a miss (authoritative fallback).
func verifyViaCustomSigner(ctx context.Context, opts types.Options, signer any, value string) (*sessionCookieCachePayload, bool) {
	v := reflect.ValueOf(signer)
	method := v.MethodByName("VerifyCookieCache")
	if !method.IsValid() {
		return nil, false
	}
	results := method.Call([]reflect.Value{
		reflect.ValueOf(ctx),
		reflect.ValueOf(opts),
		reflect.ValueOf(value),
	})
	if len(results) != 2 {
		return nil, false
	}
	if err, _ := results[1].Interface().(error); err != nil {
		return nil, false
	}
	verified := results[0]
	payloadField := verified.FieldByName("Payload")
	expiresField := verified.FieldByName("ExpiresAt")
	if !payloadField.IsValid() || !expiresField.IsValid() {
		return nil, false
	}
	sessionMap, _ := payloadField.FieldByName("Session").Interface().(map[string]any)
	userMap, _ := payloadField.FieldByName("User").Interface().(map[string]any)
	version, _ := payloadField.FieldByName("Version").Interface().(string)
	if sessionMap == nil || userMap == nil {
		return nil, false
	}
	// Schema-shape validation shared with the secret codecs (upstream
	// parseCookieCachePayload): a verified-but-invalid custom payload
	// misses with a configured-logger warn, never a hit.
	if verr := cookies.ValidateCachePayloadSchema(sessionMap, userMap); verr != nil {
		warnCacheSchemaIssue(opts, verr)
		return nil, false
	}
	data := cookies.SessionCacheData{
		Session:   sessionMap,
		User:      userMap,
		Version:   version,
		ExpiresAt: expiresField.Int(),
	}
	typed, err := typedCachePayload(data)
	if err != nil {
		return nil, false
	}
	return typed, true
}

var errCustomSignerMissing = errors.New("auth: cookie-cache signer unavailable")

// filterCookieCacheSessionUser returns copies of session/user with
// schema-declared returned:false additional fields stripped from the
// AdditionalFields maps (upstream setCookieCache filterOutputFields for the
// session and parseUserOutput for the user, cookies/index.ts:169-174).
// Core columns are untouched (they never live in AdditionalFields) and
// unknown fields are kept for backward compatibility. The inputs are copied
// by value with fresh maps, so callers' structs are never mutated.
func filterCookieCacheSessionUser(session types.Session, user types.User, opts types.Options, sessionOpts types.SessionOptions) (types.Session, types.User) {
	sessionFields := fullSessionFields(opts)
	for name, field := range sessionOpts.Model.AdditionalFields {
		sessionFields[name] = field
	}
	userFields := fullUserFields(opts)
	session.AdditionalFields = stripReturnedFalseFields(session.AdditionalFields, sessionFields)
	user.AdditionalFields = stripReturnedFalseFields(user.AdditionalFields, userFields)
	return session, user
}

// stripReturnedFalseFields drops entries declared with returned:false in
// fields, keeping everything else including keys unknown to the schema
// (upstream filterOutputFields keeps unknown keys). A nil/empty input stays
// nil; an input filtered to empty becomes nil.
func stripReturnedFalseFields(in map[string]any, fields map[string]types.FieldAttribute) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for key, value := range in {
		if name, ok := CanonicalInputKey(key, fields); ok {
			if field := fields[name]; field.Returned != nil && !*field.Returned {
				continue
			}
		}
		out[key] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// filterCookieCacheMaps strips schema-declared returned:false additional
// fields from cacheStructMap outputs in place (the map-level equivalent of
// filterCookieCacheSessionUser for the JWT/JWE/custom-signer codecs, whose
// maps carry additional fields nested under "additionalFields"). Core
// columns and unknown fields are kept. Safe on nil/empty maps.
func filterCookieCacheMaps(sm, um map[string]any, opts types.Options, sessionOpts types.SessionOptions) {
	sessionFields := fullSessionFields(opts)
	for name, field := range sessionOpts.Model.AdditionalFields {
		sessionFields[name] = field
	}
	userFields := fullUserFields(opts)
	filterCookieCacheMap(sm, sessionFields)
	filterCookieCacheMap(um, userFields)
}

// filterCookieCacheMap strips one cache map: the nested "additionalFields"
// entries first, then (defensively) any flattened top-level additional keys.
// Core cache keys are explicitly exempt so a misconfigured schema can never
// drop them.
func filterCookieCacheMap(m map[string]any, fields map[string]types.FieldAttribute) {
	if len(m) == 0 {
		return
	}
	if nested, ok := m["additionalFields"].(map[string]any); ok {
		if stripped := stripReturnedFalseFields(nested, fields); len(stripped) == 0 {
			delete(m, "additionalFields")
		} else {
			m["additionalFields"] = stripped
		}
	}
	for key := range m {
		if key == "additionalFields" || isCookieCacheCoreKey(key) {
			continue
		}
		if name, ok := CanonicalInputKey(key, fields); ok {
			if field := fields[name]; field.Returned != nil && !*field.Returned {
				delete(m, key)
			}
		}
	}
}

// isCookieCacheCoreKey reports the core session/user columns that the cache
// filter must always keep (constraint: only schema-declared additional
// fields with explicit returned:false are dropped).
func isCookieCacheCoreKey(key string) bool {
	switch key {
	case "id", "email", "emailVerified", "name", "image", "createdAt", "updatedAt",
		"userId", "token", "expiresAt", "ipAddress", "userAgent",
		"activeOrganizationId", "activeTeamId":
		return true
	default:
		return false
	}
}

// headersWithStoredRequest supplements empty Host/proxy headers from the
// middleware-reconstructed request (StoredRequestFromStd) so cross-subdomain
// domain and secure inference see the real host even when the typed Huma
// headers are absent (Wave 6 request-context adoption).
func headersWithStoredRequest(ctx context.Context, headers CookieRequestHeaders) CookieRequestHeaders {
	if headers.Host != "" && headers.XForwardedHost != "" && headers.XForwardedProto != "" {
		return headers
	}
	stored := StoredRequestFromStd(ctx)
	if stored == nil {
		return headers
	}
	out := headers
	if out.Host == "" && stored.Host != "" {
		out.Host = stored.Host
	}
	if out.XForwardedHost == "" {
		if forwarded := stored.Header.Get("X-Forwarded-Host"); forwarded != "" {
			out.XForwardedHost = forwarded
		}
	}
	if out.XForwardedProto == "" {
		if proto := stored.Header.Get("X-Forwarded-Proto"); proto != "" {
			out.XForwardedProto = proto
		}
	}
	return out
}

// resolveSessionCookieConfigWithContext mirrors resolveSessionCookieConfig
// with the authoritative request origin (EffectiveBaseURL via
// ResolveSecureCookiesWithContext / ResolveCrossSubDomainCookieDomainWithContext).
// Static behavior is unchanged when no request value is present.
func resolveSessionCookieConfigWithContext(ctx context.Context, opts types.Options, headers CookieRequestHeaders) resolvedSessionCookieConfig {
	headers = headersWithStoredRequest(ctx, headers)
	secure := ResolveSecureCookiesWithContext(ctx, opts, headers)
	cfg := resolvedSessionCookieConfig{
		Name:     resolveSessionCookieName(opts, secure),
		Path:     "/",
		Secure:   secure,
		HTTPOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	if opts.Advanced.CrossSubDomainCookies.Enabled {
		cfg.Domain = ResolveCrossSubDomainCookieDomainWithContext(ctx, opts, headers)
	}
	applyCookieAttributes(&cfg, opts.Advanced.DefaultCookieAttributes)
	if override, ok := opts.Advanced.Cookies[defaultSessionCookieName]; ok {
		if override.Name != "" {
			if secure {
				cfg.Name = secureCookiePrefix + override.Name
			} else {
				cfg.Name = override.Name
			}
		}
		applyCookieAttributes(&cfg, override.Attributes)
	}
	return cfg
}

// resolveDontRememberCookieConfigWithContext mirrors
// resolveDontRememberCookieConfig with request-aware secure/domain.
func resolveDontRememberCookieConfigWithContext(ctx context.Context, opts types.Options, headers CookieRequestHeaders) resolvedSessionCookieConfig {
	headers = headersWithStoredRequest(ctx, headers)
	secure := ResolveSecureCookiesWithContext(ctx, opts, headers)
	cfg := resolvedSessionCookieConfig{
		Name:     resolveDontRememberCookieName(opts, secure),
		Path:     "/",
		Secure:   secure,
		HTTPOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	if opts.Advanced.CrossSubDomainCookies.Enabled {
		cfg.Domain = ResolveCrossSubDomainCookieDomainWithContext(ctx, opts, headers)
	}
	applyCookieAttributes(&cfg, opts.Advanced.DefaultCookieAttributes)
	if override, ok := opts.Advanced.Cookies[dontRememberCookieName]; ok {
		applyCookieAttributes(&cfg, override.Attributes)
	}
	return cfg
}

// resolveSessionDataCookieConfigWithContext mirrors the session-cookie
// attribute pipeline for the session_data cache cookie (secure resolution,
// cross-subdomain domain, default attributes, per-cookie overrides).
func resolveSessionDataCookieConfigWithContext(ctx context.Context, opts types.Options, headers CookieRequestHeaders) resolvedSessionCookieConfig {
	headers = headersWithStoredRequest(ctx, headers)
	secure := ResolveSecureCookiesWithContext(ctx, opts, headers)
	cfg := resolvedSessionCookieConfig{
		Name:     resolveSessionDataCookieName(opts, secure),
		Path:     "/",
		Secure:   secure,
		HTTPOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	if opts.Advanced.CrossSubDomainCookies.Enabled {
		cfg.Domain = ResolveCrossSubDomainCookieDomainWithContext(ctx, opts, headers)
	}
	applyCookieAttributes(&cfg, opts.Advanced.DefaultCookieAttributes)
	if override, ok := opts.Advanced.Cookies[sessionDataCookieBase]; ok {
		applyCookieAttributes(&cfg, override.Attributes)
	}
	return cfg
}

// additionalCookieNames returns the configured cross-subdomain extra cookies
// (upstream advanced.crossSubDomainCookies.additionalCookies).
func additionalCookieNames(opts types.Options) []string {
	return append([]string(nil), opts.Advanced.CrossSubDomainCookies.AdditionalCookies...)
}

// additionalCookiesDomain resolves the shared domain propagated to
// AdditionalCookies when cross-subdomain cookies are enabled ("" when
// disabled). Explicit Domain wins, then the effective request origin, then
// the Host header — the same pipeline as the session cookies.
func additionalCookiesDomain(ctx context.Context, opts types.Options, headers CookieRequestHeaders) string {
	if !opts.Advanced.CrossSubDomainCookies.Enabled {
		return ""
	}
	headers = headersWithStoredRequest(ctx, headers)
	return ResolveCrossSubDomainCookieDomainWithContext(ctx, opts, headers)
}

// isStatefulSessionStore mirrors upstream hasServerSessionStore for the
// session-cookie-cache defaults (context/create-context.ts:102-117): a
// database or secondary storage is a durable server-side store. Stateless
// (DB-less) deployments default the cookie cache to enabled/JWE with
// refresh; stateful deployments leave the configured values untouched.
func isStatefulSessionStore(opts types.Options) bool {
	return opts.DB != nil || opts.SecondaryStorage != nil
}

// issueSessionCookieWithContext mints the session_token cookie with the
// authoritative request origin (secure/domain via StoredRequest +
// EffectiveBaseURL). Static behavior is unchanged without request values.
func issueSessionCookieWithContext(ctx context.Context, opts types.Options, headers CookieRequestHeaders, token string, expiresAt time.Time, dontRememberMe bool) (http.Cookie, error) {
	signed, err := cookies.Sign(opts.CurrentSecret(), token)
	if err != nil {
		return http.Cookie{}, err
	}
	cfg := resolveSessionCookieConfigWithContext(ctx, opts, headers)
	cookie := http.Cookie{
		Name:     cfg.Name,
		Value:    signed,
		Path:     cfg.Path,
		Domain:   cfg.Domain,
		HttpOnly: cfg.HTTPOnly,
		SameSite: cfg.SameSite,
		Secure:   cfg.Secure,
	}
	if dontRememberMe {
		return cookie, nil
	}
	cookie.Expires = expiresAt.UTC()
	if cfg.MaxAge != nil {
		cookie.MaxAge = *cfg.MaxAge
	} else {
		// Same persistent default as issueSessionCookie (upstream
		// getCookies sessionMaxAge; refresh override session.ts:386-397).
		cookie.MaxAge = int(opts.Session.ExpiresInDuration().Seconds())
	}
	return cookie, nil
}

// newSessionDataCookieWithContext mints the session_data cache cookie with
// request-aware naming/attributes and the custom JWKS signer when present
// (upstream setCookieCache jwt branch with cookieCacheSigner, including key
// rotation via the plugin's live keys, typ/kid/aud/iss/sub/sid claim
// binding, and authoritative fallback on any failure).
func newSessionDataCookieWithContext(ctx context.Context, opts types.Options, session types.Session, user types.User, sessionOpts types.SessionOptions, now time.Time, dontRememberMe bool) (http.Cookie, error) {
	version, err := resolveCookieCacheVersion(session, user, sessionOpts)
	if err != nil {
		return http.Cookie{}, err
	}
	// Cookie-cache field filtering (upstream setCookieCache, cookies/index.ts:
	// 169-174): schema-declared returned:false additional fields are stripped
	// from the cache payload for every strategy, while core columns and
	// unknown fields are kept. Version resolution above sees the unfiltered
	// pair, matching upstream's order (filter, then version from the original).
	session, user = filterCookieCacheSessionUser(session, user, opts, sessionOpts)
	maxAge := sessionOpts.CookieCacheMaxAgeDuration()
	if dontRememberMe {
		maxAge = time.Minute
	}
	expiresAt := now.Add(maxAge).UTC()
	if session.ExpiresAt.Before(expiresAt) {
		expiresAt = session.ExpiresAt.UTC()
	}
	var value string
	strategy := cookieCacheStrategy(sessionOpts)
	if strategy == cookies.StrategyJWT {
		if signer, found := findCookieCacheSigner(opts); found {
			effective := opts
			if full := RequestFullBaseURLFromStd(ctx); full != "" {
				if origin, ok := originOfFull(full); ok {
					effective.BaseURL = origin
				} else {
					effective.BaseURL = full
				}
			}
			window := time.Until(expiresAt)
			if window < 0 {
				window = 0
			}
			custom, cerr := signViaCustomSigner(ctx, effective, signer, session, user, version, window)
			if cerr != nil {
				return http.Cookie{}, cerr
			}
			value = custom
		} else {
			sm, err := cacheStructMap(session)
			if err != nil {
				return http.Cookie{}, err
			}
			um, err := cacheStructMap(user)
			if err != nil {
				return http.Cookie{}, err
			}
			filterCookieCacheMaps(sm, um, opts, sessionOpts)
			value, err = cookies.CreateSessionCacheJWT(opts.CurrentSecret(), sm, um, version, time.Until(expiresAt))
			if err != nil {
				return http.Cookie{}, err
			}
		}
	} else if strategy == cookies.StrategyJWE {
		sm, err := cacheStructMap(session)
		if err != nil {
			return http.Cookie{}, err
		}
		um, err := cacheStructMap(user)
		if err != nil {
			return http.Cookie{}, err
		}
		filterCookieCacheMaps(sm, um, opts, sessionOpts)
		value, err = cookies.CreateSessionCacheJWE(opts.CurrentSecret(), sm, um, version, time.Until(expiresAt))
		if err != nil {
			return http.Cookie{}, err
		}
	} else {
		// Compact uses the frozen secret-envelope codec; route callers
		// pass the current secret (rotation reads accept older secrets).
		// session/user were filtered for returned:false above, so the
		// delegated frozen issuance carries a clean payload.
		// Wire name stays the legacy Go cookie (sessionDataCookieName) for
		// backward compatibility; reads accept the upstream and custom
		// names via sessionDataCookieValue. Only re-attribute Domain/Secure
		// from the request-aware config.
		single, err := newSessionDataCookie(opts.CurrentSecret(), session, user, opts, sessionOpts, now, dontRememberMe)
		if err != nil {
			return http.Cookie{}, err
		}
		cfg := resolveSessionDataCookieConfigWithContext(ctx, opts, CookieRequestHeaders{})
		single.Domain = cfg.Domain
		single.Secure = cfg.Secure
		return single, nil
	}
	// JWT/JWE issuance likewise keeps the legacy wire name for
	// compatibility (reads recover upstream/custom names + chunks).
	name := sessionDataCookieName
	cfg := resolveSessionDataCookieConfigWithContext(ctx, opts, CookieRequestHeaders{})
	if override, ok := opts.Advanced.Cookies[sessionDataCookieBase]; ok && override.Name != "" {
		name = cfg.Name
	}
	maxAgeSecs := int(time.Until(expiresAt).Seconds())
	if maxAgeSecs < 0 {
		maxAgeSecs = 0
	}
	return http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Domain:   cfg.Domain,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   cfg.Secure,
		Expires:  expiresAt,
		MaxAge:   maxAgeSecs,
	}, nil
}

// issueSessionCookiesWithContext mints the full issuance set with request
// context (session_token + dont_remember marker + strategy-aware cache),
// mirroring upstream setSessionCookie + setCookieCache.
func issueSessionCookiesWithContext(ctx context.Context, authOpts types.Options, headers CookieRequestHeaders, token string, session types.Session, user types.User, sessionOpts types.SessionOptions, now time.Time, dontRememberMe bool) ([]http.Cookie, error) {
	headers = headersWithStoredRequest(ctx, headers)
	sessionCookie, err := issueSessionCookieWithContext(ctx, authOpts, headers, token, session.ExpiresAt, dontRememberMe)
	if err != nil {
		return nil, err
	}
	out := []http.Cookie{sessionCookie}
	if dontRememberMe {
		signed, err := cookies.Sign(authOpts.CurrentSecret(), "true")
		if err != nil {
			return nil, err
		}
		cfg := resolveDontRememberCookieConfigWithContext(ctx, authOpts, headers)
		out = append(out, http.Cookie{
			Name:     cfg.Name,
			Value:    signed,
			Path:     cfg.Path,
			Domain:   cfg.Domain,
			HttpOnly: cfg.HTTPOnly,
			SameSite: cfg.SameSite,
			Secure:   cfg.Secure,
		})
	}
	if sessionOpts.CookieCache.Enabled {
		cacheCookie, err := newSessionDataCookieWithContext(ctx, authOpts, session, user, sessionOpts, now, dontRememberMe)
		if err != nil {
			return nil, err
		}
		out = append(out, cacheCookie)
	}
	return out, nil
}

// expiredSessionCookiesWithContext expires the session set with request
// context, including chunk-aware session_data cleanup (upstream
// deleteSessionCookie clean(): bare name + every "<name>.<index>" chunk so
// stale chunks never survive a shrink or logout).
func expiredSessionCookiesWithContext(ctx context.Context, authOpts types.Options, headers CookieRequestHeaders, cookieHeader string) []http.Cookie {
	headers = headersWithStoredRequest(ctx, headers)
	sessCfg := resolveSessionCookieConfigWithContext(ctx, authOpts, headers)
	out := []http.Cookie{{
		Name:     sessCfg.Name,
		Value:    "",
		Path:     sessCfg.Path,
		Domain:   sessCfg.Domain,
		HttpOnly: sessCfg.HTTPOnly,
		SameSite: sessCfg.SameSite,
		Secure:   sessCfg.Secure,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0).UTC(),
	}}
	if authOpts.Session.CookieCache.Enabled {
		dataCfg := resolveSessionDataCookieConfigWithContext(ctx, authOpts, headers)
		base := http.Cookie{
			Name:     dataCfg.Name,
			Value:    "",
			Path:     "/",
			Domain:   dataCfg.Domain,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   dataCfg.Secure,
			MaxAge:   -1,
			Expires:  time.Unix(0, 0).UTC(),
		}
		out = append(out, base)
		// Expire any chunked variants present in the request so a
		// shrunken cache cannot leave stale chunks behind.
		if cookieHeader != "" {
			parsed := cookies.ParseRequestCookies(cookieHeader)
			for name := range parsed {
				for _, candidate := range sessionDataCookieLookupNames(authOpts) {
					if idx, ok := cookies.ParseChunkIndex(candidate, name); ok && idx >= 0 {
						chunk := base
						chunk.Name = name
						out = append(out, chunk)
						break
					}
				}
			}
		}
	}
	dontCfg := resolveDontRememberCookieConfigWithContext(ctx, authOpts, headers)
	out = append(out, http.Cookie{
		Name:     dontCfg.Name,
		Value:    "",
		Path:     dontCfg.Path,
		Domain:   dontCfg.Domain,
		HttpOnly: dontCfg.HTTPOnly,
		SameSite: dontCfg.SameSite,
		Secure:   dontCfg.Secure,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0).UTC(),
	})
	return out
}

// expiredStaleSessionDataCookies expires a retired or undecodable session_data
// value plus any chunk variants present in the request, mirroring upstream
// get-session's retired-cache clean() and decode-failure expireCookie
// (session.ts:102-109,120-122) with the chunk-aware session-store clean.
// The expired entries ride alongside the authoritative database result (and
// any re-issued cache), so stale caches cannot linger in the browser or
// shadow the fresh value. Expiry entries always precede fresh ones on the
// wire so the fresh value wins.
func expiredStaleSessionDataCookies(ctx context.Context, opts types.Options, headers CookieRequestHeaders, cookieHeader string) []http.Cookie {
	headers = headersWithStoredRequest(ctx, headers)
	dataCfg := resolveSessionDataCookieConfigWithContext(ctx, opts, headers)
	expire := func(name string) http.Cookie {
		return http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			Domain:   dataCfg.Domain,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   dataCfg.Secure,
			MaxAge:   -1,
			Expires:  time.Unix(0, 0).UTC(),
		}
	}
	out := []http.Cookie{expire(dataCfg.Name)}
	seen := map[string]struct{}{dataCfg.Name: {}}
	if cookieHeader != "" {
		parsed := cookies.ParseRequestCookies(cookieHeader)
		candidates := sessionDataCookieLookupNames(opts)
		for name := range parsed {
			if _, dup := seen[name]; dup {
				continue
			}
			matched := false
			for _, candidate := range candidates {
				if name == candidate {
					matched = true
					break
				}
				if _, ok := cookies.ParseChunkIndex(candidate, name); ok {
					matched = true
					break
				}
			}
			if matched {
				seen[name] = struct{}{}
				out = append(out, expire(name))
			}
		}
	}
	return out
}

// maybeRefreshCookieCacheWithContext re-issues the stateless cache with
// request context (same threshold/ShouldRefresh gates as
// maybeRefreshCookieCache).
func maybeRefreshCookieCacheWithContext(ctx context.Context, authOpts types.Options, headers CookieRequestHeaders, token string, payload *sessionCookieCachePayload, now time.Time, dontRememberMe bool) []http.Cookie {
	rc := authOpts.Session.CookieCache.RefreshCache
	threshold, ok := cookies.CookieCacheRefreshThreshold(rc.Enabled, rc.UpdateAge, authOpts.Session.CookieCacheMaxAgeDuration())
	if !ok {
		return nil
	}
	if payload.ExpiresAt.Sub(now) >= threshold {
		return nil
	}
	if rc.ShouldRefresh != nil && !rc.ShouldRefresh(payload.Session, payload.User) {
		return nil
	}
	refreshed, err := issueSessionCookiesWithContext(ctx, authOpts, headers, token, payload.Session, payload.User, authOpts.Session, now, dontRememberMe)
	if err != nil {
		return nil
	}
	return refreshed
}
