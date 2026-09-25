package routes

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/brick-org/brick/auth/src/api/state"
	"github.com/brick-org/brick/auth/src/cookies"
	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"reflect"
)

type getSessionInput struct {
	Authorization string `header:"Authorization"`
	Cookie        string `header:"Cookie"`
	// DisableCookieCache forces an authoritative server-side read, bypassing
	// the signed cookie cache (upstream getSessionQuerySchema,
	// session-store.ts:281-301; types.SessionQueryOptions).
	DisableCookieCache bool `query:"disableCookieCache"`
	// DisableRefresh skips the session-refresh write for this request
	// (upstream getSessionQuerySchema; session.ts:309,340).
	DisableRefresh bool `query:"disableRefresh"`
	CookieRequestHeaders
}

type getSessionBody struct {
	// Pointer fields so a missing/expired session serializes as
	// upstream's 200 literal null (session.ts:94-112,287-303,
	// ctx.json(null)) instead of an error. The Body itself is nil
	// for the null case so Huma marshals literal `null`.
	User    *types.User    `json:"user"`
	Session *types.Session `json:"session"`
	// NeedsRefresh is set only on deferred GET reads (DeferSessionRefresh
	// without POST): the database is never written, so the refresh need
	// is reported for the client to act on (upstream session.ts:350-365).
	NeedsRefresh *bool `json:"needsRefresh,omitempty"`
}

type getSessionOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	// Upstream pins cache-control: no-store + pragma: no-cache on the
	// get-session response (session.ts:72-73) so session reads are never
	// cached by intermediaries. The headers apply to the 200-null
	// unauthenticated response as well (upstream test:2735-2745).
	CacheControl string `header:"Cache-Control"`
	Pragma       string `header:"Pragma"`
	Body         *getSessionBody
}

// GetSession registers GET and POST /get-session.
//
// Upstream serves both methods from one endpoint (session.ts:29-38): POST
// performs the refresh writes and requires deferSessionRefresh, surfacing
// METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED otherwise (session.ts:79-84).
// Huma models one method per operation, so POST is a second registration
// sharing the handler below. Its OperationID differs only because Huma
// requires unique IDs; upstream uses "getSession" for both methods.
// DisabledPaths gating stays a single "/get-session" entry (auth/api/index.go)
// because both registrations live in this registrar.
func GetSession(api huma.API, basePath string, opts types.Options) {
	serve := func(ctx context.Context, input *getSessionInput, isPost bool) (*getSessionOutput, error) {
		if isPost && !opts.Session.DeferSessionRefresh {
			return nil, sessionRouteError(types.ErrMethodNotAllowedDeferSessionRequired)
		}
		res, err := resolveGetSession(ctx, opts, getSessionRequest{
			token:          sessionTokenFromRequest(input.Cookie, input.Authorization, opts),
			cookieHeader:   input.Cookie,
			headers:        input.CookieRequestHeaders,
			query:          types.SessionQueryOptions{DisableCookieCache: input.DisableCookieCache, DisableRefresh: input.DisableRefresh},
			dontRememberMe: hasDontRememberCookie(input.Cookie, opts),
			readOnly:       !isPost && opts.Session.DeferSessionRefresh,
		})
		if err != nil {
			// B14 (upstream session.ts:94-112,287-303, ctx.json(null)): a
			// missing, expired, or user-missing session answers 200 literal
			// null instead of failing closed. The internal resolveGetSession
			// contract still returns the FAILED_TO_GET_SESSION /
			// SESSION_EXPIRED errors (kept for middleware callers via
			// GetSessionFromRequest); only this HTTP layer maps them to the
			// null shape (Body nil marshals to literal `null`). Operational
			// failures (500s) and other codes keep their error status.
			if res != nil && isNullSessionError(err) {
				out := &getSessionOutput{}
				out.SetCookie = res.cookies
				out.CacheControl = "no-store"
				out.Pragma = "no-cache"
				// Body stays nil for literal null.
				return out, nil
			}
			// P05-GAP-1: surface the retired session_data cleanup (Max-Age=0
			// Set-Cookie) even on auth failure. Huma error responses discard
			// the output struct, so append directly to the wire headers.
			if res != nil && len(res.cookies) > 0 {
				if humaCtx, ok := ctx.Value(humaContextKey{}).(huma.Context); ok && humaCtx != nil {
					for _, c := range res.cookies {
						cookie := c
						humaCtx.AppendHeader("Set-Cookie", cookie.String())
					}
				}
			}
			return nil, err
		}
		out := &getSessionOutput{}
		out.SetCookie = res.cookies
		out.CacheControl = "no-store"
		out.Pragma = "no-cache"
		out.Body = &getSessionBody{
			User:         &res.user,
			Session:      &res.session,
			NeedsRefresh: res.needsRefresh,
		}
		return out, nil
	}
	registerAuthOperation(api, huma.Operation{
		Tags:        []string{"Auth"},
		Method:      http.MethodGet,
		Path:        basePath + "/get-session",
		OperationID: "getSession",
		Summary:     "Get the current session",
	}, opts, func(ctx context.Context, input *getSessionInput) (*getSessionOutput, error) {
		return serve(ctx, input, false)
	})
	registerAuthOperation(api, huma.Operation{
		Tags:        []string{"Auth"},
		Method:      http.MethodPost,
		Path:        basePath + "/get-session",
		OperationID: "getSessionPost",
		Summary:     "Get the current session with refresh (requires deferSessionRefresh)",
	}, opts, func(ctx context.Context, input *getSessionInput) (*getSessionOutput, error) {
		return serve(ctx, input, true)
	})
}

// getSessionRequest carries the resolved inputs for a get-session read: the
// query knobs (types.SessionQueryOptions), the remember-me persistence
// marker, and whether the read must stay write-free.
type getSessionRequest struct {
	token          string
	cookieHeader   string
	headers        CookieRequestHeaders
	query          types.SessionQueryOptions
	dontRememberMe bool
	// readOnly mirrors deferSessionRefresh on GET (upstream session.ts:350):
	// the database is never written; a due refresh is reported instead of
	// performed.
	readOnly bool
}

type getSessionResult struct {
	session      types.Session
	user         types.User
	cookies      []http.Cookie
	needsRefresh *bool
}

// resolveGetSession is the shared get-session read used by the route handler
// and GetSessionFromRequest. It mirrors the upstream order (session.ts):
// cookie-cache fast path (unless ?disableCookieCache), authoritative
// database read, then refresh/cookie policy.
//
// B14 (upstream session.ts:94-112,287-303 returns 200 literal null for
// missing/expired/user-missing sessions): the null shape is served at the
// HTTP layer (GetSession maps the FAILED_TO_GET_SESSION / SESSION_EXPIRED
// errors below to a 200 literal-null body); this resolver keeps returning
// those errors so middleware callers via GetSessionFromRequest see the
// failure. Only the stale-cleanup cookie emission on failure changed here
// (P05-GAP-1).
//
// The fast path is context-aware (AUTH-C7-01): chunk/name recovery across
// the Go legacy, configured, and upstream defaults, plus the JWT plugin
// custom JWKS signer (rotation, typ/kid/aud/iss/sub/sid binding) with
// authoritative fallback. Cookie issuance honors the request origin
// (StoredRequest + EffectiveBaseURL) for Secure/Domain.
func resolveGetSession(ctx context.Context, opts types.Options, req getSessionRequest) (*getSessionResult, error) {
	now := time.Now().UTC()
	headers := headersWithStoredRequest(ctx, req.headers)
	cacheEnabled := opts.Session.CookieCache.Enabled
	// A session_data value may be present even when the fast path cannot use
	// it: retired while caching is disabled (upstream clean(),
	// session.ts:102-109), or present but undecodable/mismatched while
	// enabled (upstream expireCookie, session.ts:120-122). Either way the
	// stale entries expire alongside the authoritative result below — including
	// on auth-failure returns (P05-GAP-1; fallback.test.ts:91-136), so the
	// caller surfaces them via the result even when err != nil.
	_, cachePresent := sessionDataCookieValue(req.cookieHeader, opts)
	var staleCleanup []http.Cookie
	if cachePresent && !cacheEnabled {
		staleCleanup = expiredStaleSessionDataCookies(ctx, opts, headers, req.cookieHeader)
	}
	if req.token == "" {
		return &getSessionResult{cookies: staleCleanup}, sessionRouteError(types.ErrFailedToGetSession)
	}
	if !req.query.DisableCookieCache {
		if cached, ok := cachedSessionFromRequestFull(ctx, req.cookieHeader, opts.AllSecrets(), req.token, opts); ok {
			// shouldSkipSessionRefresh gates the cookie-cache refresh
			// (upstream session.ts:201-204). The c701 helper itself is
			// owned by another agent; this session.go call site suppresses
			// the refresh so database and cookie data cannot diverge.
			var refreshCookies []http.Cookie
			if !state.GetShouldSkipSessionRefresh(ctx) {
				refreshCookies = maybeRefreshCookieCacheWithContext(ctx, opts, headers, req.token, cached, now, req.dontRememberMe)
			}
			return &getSessionResult{
				session: cached.Session,
				user:    cached.User,
				cookies: refreshCookies,
			}, nil
		}
		// B4 (upstream session.ts:138-154 with the endpoint catch-all): a
		// rejecting cookie-cache VersionFunc is an operational failure that
		// 500s instead of failing closed to the authoritative database read.
		// The c701 fast-path helper itself still reports a miss; this
		// session.go call site re-checks version resolution on an otherwise
		// bound cache entry so the version error surfaces as a 500.
		if verr := cookieCacheVersionErr(ctx, req.cookieHeader, opts.AllSecrets(), req.token, opts); verr != nil {
			return &getSessionResult{cookies: staleCleanup}, sessionInternalError(types.ErrFailedToGetSession)
		}
		if cachePresent && cacheEnabled {
			staleCleanup = expiredStaleSessionDataCookies(ctx, opts, headers, req.cookieHeader)
		}
	}

	sessionRow, userRow, refreshed, needsRefresh, err := loadSessionWithRefresh(ctx, opts, req.token, sessionRefreshConfig{
		disableRefresh: req.query.DisableRefresh,
		dontRememberMe: req.dontRememberMe,
		readOnly:       req.readOnly,
	})
	if err != nil {
		// P05-GAP-1: the retired session_data cleanup rides alongside the
		// auth failure (upstream clean()/expireCookie emit Set-Cookie even
		// when the session read fails; fallback.test.ts:91-136). Callers
		// surface res.cookies even when err != nil (see GetSession huma
		// header append and GetSessionFromRequest cookie return).
		// G4 + session minors: on EXPIRED/invalid/user-missing failures also
		// emit the expired session_token cleanup alongside the session_data
		// cleanup, plus the dont_remember marker expiry (upstream
		// deleteSessionCookie clears all three by default; session.ts:291,380
		// with cookies/index.ts:506-542). DB row deletion already happened in
		// the loader; this only clears the browser copy. Upstream findSession
		// returns null when the user row is missing, so user-missing joins
		// the null path (not 404). DB/operational errors keep the token.
		failedCookies := staleCleanup
		if req.token != "" && (errors.Is(err, errSessionExpired) || errors.Is(err, errUnauthorized) || errors.Is(err, errUserMissing)) {
			failedCookies = append([]http.Cookie{expiredSessionTokenCleanupCookie(ctx, opts, headers)}, failedCookies...)
			failedCookies = append(failedCookies, expiredDontRememberCleanupCookie(ctx, opts, headers))
		}
		failed := &getSessionResult{cookies: failedCookies}
		switch {
		case errors.Is(err, errSessionExpired):
			return failed, sessionRouteError(types.ErrSessionExpired)
		case errors.Is(err, errUnauthorized):
			return failed, sessionRouteError(types.ErrFailedToGetSession)
		case errors.Is(err, errUserMissing):
			return failed, sessionRouteError(types.ErrFailedToGetSession)
		default:
			return failed, sessionInternalError(types.ErrFailedToGetSession)
		}
	}
	session := rowToSession(sessionRow, opts)
	user := rowToUser(userRow, opts)

	// The persistence marker and the per-request disableRefresh knob skip
	// the refresh write AND the cookie writes: upstream returns the parsed
	// session/user directly (session.ts:309-323). The global
	// DisableSessionRefresh flag only skips the database write (it feeds
	// needsRefresh instead); cookie-cache emission below is unaffected.
	if req.dontRememberMe || req.query.DisableRefresh {
		return &getSessionResult{session: session, user: user, cookies: staleCleanup}, nil
	}
	if req.readOnly {
		// Deferred GET (upstream session.ts:350-365): no database writes,
		// cache re-issue only, refresh need reported to the caller.
		res := &getSessionResult{session: session, user: user, needsRefresh: &needsRefresh}
		if opts.Session.CookieCache.Enabled {
			if cacheCookie, cacheErr := newSessionDataCookieWithContext(ctx, opts, session, user, opts.Session, now, req.dontRememberMe); cacheErr == nil {
				res.cookies = append(staleCleanup, cacheCookie)
			} else if len(staleCleanup) > 0 {
				res.cookies = staleCleanup
			}
		} else if len(staleCleanup) > 0 {
			res.cookies = staleCleanup
		}
		return res, nil
	}
	if refreshed || opts.Session.CookieCache.Enabled {
		cookiesOut, cookieErr := issueSessionCookiesWithContext(ctx, opts, headers, req.token, session, user, opts.Session, now, false)
		if cookieErr == nil {
			return &getSessionResult{session: session, user: user, cookies: append(staleCleanup, cookiesOut...)}, nil
		}
	}
	return &getSessionResult{session: session, user: user, cookies: staleCleanup}, nil
}

// GetSessionFromRequest extracts the session and user from the HTTP request.
// Returns session, user, optional refresh cookies, and error.
// Use this in middleware to attach session data to the request context.
//
// The get-session query knobs are honored from the request URL
// (?disableCookieCache=, ?disableRefresh=), mirroring how upstream
// getSessionFromCtx merges the caller config with the request query
// (session.ts:479-490). Like upstream, resolution is GET-style, so an
// enabled DeferSessionRefresh keeps this helper read-only.
//
// B14 (upstream session.ts:94-112,287-303 returns 200 null for
// missing/expired sessions): the null shape is served at the HTTP layer by
// GetSession only; this helper keeps returning the failure so middleware
// callers can distinguish unauthenticated requests.
func GetSessionFromRequest(r *http.Request, opts types.Options) (*types.Session, *types.User, []http.Cookie, error) {
	cookieHeader := r.Header.Get("Cookie")
	res, err := resolveGetSession(r.Context(), opts, getSessionRequest{
		token:          sessionTokenFromRequest(cookieHeader, r.Header.Get("Authorization"), opts),
		cookieHeader:   cookieHeader,
		headers:        cookieRequestHeadersFromRequest(r),
		query:          sessionQueryFromURL(r),
		dontRememberMe: hasDontRememberCookie(cookieHeader, opts),
		readOnly:       opts.Session.DeferSessionRefresh,
	})
	if err != nil {
		// P05-GAP-1: surface stale cleanup cookies even on failure so
		// middleware callers can clear retired session_data.
		if res != nil && len(res.cookies) > 0 {
			return nil, nil, res.cookies, err
		}
		return nil, nil, nil, err
	}
	return &res.session, &res.user, res.cookies, nil
}

// sessionQueryFromURL reads the get-session query knobs from a request URL
// (?disableCookieCache=, ?disableRefresh=), mirroring the route input
// binding for callers that bypass Huma (middleware via
// GetSessionFromRequest).
func sessionQueryFromURL(r *http.Request) types.SessionQueryOptions {
	if r == nil || r.URL == nil {
		return types.SessionQueryOptions{}
	}
	query := r.URL.Query()
	return types.SessionQueryOptions{
		DisableCookieCache: parseSessionQueryBool(query.Get("disableCookieCache")),
		DisableRefresh:     parseSessionQueryBool(query.Get("disableRefresh")),
	}
}

// parseSessionQueryBool parses a get-session query knob with strconv
// semantics (matching Huma's bool query binding: "1", "t", "true", ...).
// Empty and unparseable values fail closed to false.
func parseSessionQueryBool(raw string) bool {
	if raw == "" {
		return false
	}
	enabled, err := strconv.ParseBool(raw)
	return err == nil && enabled
}

func cookieRequestHeadersFromRequest(r *http.Request) CookieRequestHeaders {
	return CookieRequestHeaders{
		Host:            r.Header.Get("Host"),
		XForwardedHost:  r.Header.Get("X-Forwarded-Host"),
		XForwardedProto: r.Header.Get("X-Forwarded-Proto"),
	}
}

type listSessionsInput struct {
	Authorization string `header:"Authorization"`
	Cookie        string `header:"Cookie"`
	CookieRequestHeaders
}

type listSessionsOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      []types.Session
}

// ListSessions registers GET /list-sessions.
func ListSessions(api huma.API, basePath string, opts types.Options) {
	registerAuthOperation(api, huma.Operation{
		Tags:        []string{"Auth"},
		Method:      http.MethodGet,
		Path:        basePath + "/list-sessions",
		OperationID: "listUserSessions",
		Summary:     "List active sessions for the current user",
	}, opts, func(ctx context.Context, input *listSessionsInput) (*listSessionsOutput, error) {
		token := sessionTokenFromRequest(input.Cookie, input.Authorization, opts)
		if token == "" {
			return nil, sessionRouteError(types.ErrFailedToGetSession)
		}

		sessionRow, userRow, refreshed, err := loadSessionAndUser(ctx, opts, token)
		if err != nil {
			if errors.Is(err, errSessionExpired) {
				// Kept 401 (differs from StatusForCode 400): upstream
				// listSessions sits behind freshSessionMiddleware, which
				// answers UNAUTHORIZED for expired sessions
				// (session.ts:598-616); see the note in ChangePassword
				// (password.go).
				return nil, huma.Error401Unauthorized(types.ErrSessionExpired)
			}
			return nil, sessionRouteError(types.ErrFailedToGetSession)
		}

		// Fresh-session gate (upstream freshSessionMiddleware guarding
		// listSessions, session.ts:598-616): sessions older than FreshAge
		// (default 1 day, explicit 0 disables) cannot enumerate sessions.
		// Rows without a legible createdAt fail open, matching upstream's
		// NaN comparison (never fresh-rejected).
		if freshAge, enabled := opts.Session.FreshAgeDuration(); enabled {
			if created, ok := timeField(sessionRow, "created_at", "createdAt"); ok && !created.IsZero() && !time.Now().UTC().Before(created.Add(freshAge)) {
				return nil, sessionRouteError(types.ErrSessionNotFresh)
			}
		}

		userID := stringField(sessionRow, "user_id", "userId")
		var sessions []types.Session
		if opts.SecondaryStorage != nil {
			// Secondary-storage list (upstream listSessions secondary
			// branch): live cached sessions only, no database round-trip.
			// Backend errors are operational failures (500), matching the
			// database error branch below.
			cached, cerr := listSecondarySessions(opts, userID)
			if cerr != nil {
				return nil, sessionInternalError(types.ErrFailedToGetSession)
			}
			sessions = cached
		} else {
			rows, ferr := opts.DB.FindMany(ctx, "session", []types.Where{
				{Field: "userId", Value: userID},
			}, 0, 0, nil, nil)
			if ferr != nil {
				return nil, sessionInternalError(types.ErrFailedToGetSession)
			}
			now := time.Now().UTC()
			sessions = make([]types.Session, 0, len(rows))
			for _, row := range rows {
				if exp, ok := timeField(row, "expires_at", "expiresAt"); ok && now.Before(exp) {
					sessions = append(sessions, rowToSession(row, opts))
				}
			}
		}

		out := &listSessionsOutput{Body: sessions}
		if refreshed {
			headers := headersWithStoredRequest(ctx, input.CookieRequestHeaders)
			cookiesOut, cookieErr := issueSessionCookiesWithContext(ctx, opts, headers, token, rowToSession(sessionRow, opts), rowToUser(userRow, opts), opts.Session, time.Now().UTC(), false)
			if cookieErr == nil {
				out.SetCookie = cookiesOut
			}
		}
		return out, nil
	})
}

type revokeSessionInput struct {
	Authorization string `header:"Authorization"`
	Cookie        string `header:"Cookie"`
	CookieRequestHeaders
	Body struct {
		Token string `json:"token" required:"true"`
	}
}

type revokeSessionOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      struct {
		Status bool `json:"status"`
	}
}

// RevokeSession registers POST /revoke-session.
func RevokeSession(api huma.API, basePath string, opts types.Options) {
	registerAuthOperation(api, huma.Operation{
		Tags:        []string{"Auth"},
		Method:      http.MethodPost,
		Path:        basePath + "/revoke-session",
		OperationID: "revokeSession",
		Summary:     "Revoke a specific session for the current user",
	}, opts, func(ctx context.Context, input *revokeSessionInput) (*revokeSessionOutput, error) {
		currentToken := sessionTokenFromRequest(input.Cookie, input.Authorization, opts)
		if currentToken == "" {
			return nil, sessionRouteError(types.ErrFailedToGetSession)
		}

		sessionRow, userRow, refreshed, err := loadSessionAndUser(ctx, opts, currentToken)
		if err != nil {
			if errors.Is(err, errSessionExpired) {
				// Kept 401 (differs from StatusForCode 400): upstream
				// revokeSession sits behind sensitiveSessionMiddleware,
				// which answers UNAUTHORIZED for expired sessions
				// (session.ts:561-572); same convention as RevokeSessions.
				return nil, huma.Error401Unauthorized(types.ErrSessionExpired)
			}
			return nil, sessionRouteError(types.ErrFailedToGetSession)
		}

		targetUserID, targetFound, terr := secondaryAwareSessionOwner(ctx, opts, input.Body.Token)
		if terr != nil {
			return nil, sessionInternalError(types.ErrFailedToGetSession)
		}

		if targetFound && targetUserID == stringField(sessionRow, "user_id", "userId") {
			if err := deleteSecondaryAwareSession(ctx, opts, input.Body.Token); err != nil {
				return nil, sessionInternalError(types.ErrFailedToGetSession)
			}
		}

		out := &revokeSessionOutput{}
		if refreshed {
			headers := headersWithStoredRequest(ctx, input.CookieRequestHeaders)
			cookiesOut, cookieErr := issueSessionCookiesWithContext(ctx, opts, headers, currentToken, rowToSession(sessionRow, opts), rowToUser(userRow, opts), opts.Session, time.Now().UTC(), false)
			if cookieErr == nil {
				out.SetCookie = cookiesOut
			}
		}
		out.Body.Status = true
		return out, nil
	})
}

func rowToSession(row map[string]any, opts types.Options) types.Session {
	s := types.Session{}
	if v := stringField(row, "id"); v != "" {
		s.ID = v
	}
	if v := stringField(row, "user_id", "userId"); v != "" {
		s.UserID = v
	}
	if v := stringField(row, "token"); v != "" {
		s.Token = v
	}
	if v, ok := timeField(row, "expires_at", "expiresAt"); ok {
		s.ExpiresAt = v
	}
	if v := stringField(row, "ip_address", "ipAddress"); v != "" {
		s.IPAddress = &v
	}
	if v := stringField(row, "user_agent", "userAgent"); v != "" {
		s.UserAgent = &v
	}
	if v := stringField(row, "active_organization_id", "activeOrganizationId"); v != "" {
		s.ActiveOrganizationID = &v
	}
	if v := stringField(row, "active_team_id", "activeTeamId"); v != "" {
		s.ActiveTeamID = &v
	}
	if v, ok := timeField(row, "created_at", "createdAt"); ok {
		s.CreatedAt = v
	}
	if v, ok := timeField(row, "updated_at", "updatedAt"); ok {
		s.UpdatedAt = v
	}
	s.AdditionalFields = ExtractAdditionalFieldsFull(row, fullSessionFields(opts), isCoreSessionColumn)
	if len(s.AdditionalFields) == 0 {
		s.AdditionalFields = nil
	}
	return s
}

// creationSessionExpiry resolves the issuance lifetime for a fresh session,
// mirroring upstream createSession's remember-me branch
// (internal-adapter.ts:509-511): non-persistent (dontRememberMe) sessions
// live 1 day; persistent sessions live the configured ExpiresIn.
func creationSessionExpiry(opts types.Options, dontRememberMe bool, now time.Time) time.Time {
	if dontRememberMe {
		return now.Add(24 * time.Hour)
	}
	return now.Add(opts.Session.ExpiresInDuration())
}

func isCoreSessionColumn(key string) bool {
	switch key {
	case "id", "user_id", "userId", "token", "expires_at", "expiresAt", "ip_address", "ipAddress", "user_agent", "userAgent", "active_organization_id", "activeOrganizationId", "active_team_id", "activeTeamId", "created_at", "createdAt", "updated_at", "updatedAt":
		return true
	default:
		return false
	}
}

var (
	errUnauthorized   = errors.New("unauthorized")
	errSessionExpired = errors.New("session expired")
	errUserMissing    = errors.New("user missing")
)

type CookieRequestHeaders struct {
	Host            string `header:"Host"`
	XForwardedHost  string `header:"X-Forwarded-Host"`
	XForwardedProto string `header:"X-Forwarded-Proto"`
}

const (
	defaultSessionCookieName = "session_token"
	defaultCookiePrefix      = "better-auth"
	legacySessionCookieName  = "auth_session"
	secureCookiePrefix       = "__Secure-"
	sessionDataCookieName    = "auth_session_data"
)

type sessionCookieCachePayload struct {
	Session   types.Session `json:"session"`
	User      types.User    `json:"user"`
	ExpiresAt time.Time     `json:"expiresAt"`
	// Version stamps the resolved cookie-cache version (static Version or
	// VersionFunc output, defaulting to "1"). Rotation invalidates older
	// caches on read (upstream session.ts:138-154). Omitted payloads predate
	// stamping and read as "1".
	Version string `json:"version,omitempty"`
}

func loadSessionAndUser(ctx context.Context, opts types.Options, token string) (map[string]any, map[string]any, bool, error) {
	sessionRow, userRow, refreshed, _, err := loadSessionWithRefresh(ctx, opts, token, sessionRefreshConfig{})
	return sessionRow, userRow, refreshed, err
}

// sessionRefreshConfig carries the per-request refresh policy for a
// get-session read. The zero value preserves the historical refresh behavior
// for the non-get-session callers of loadSessionAndUser (owned by other
// routes); the get-session paths populate it from the query knobs, the
// remember-me marker, and the deferral config.
type sessionRefreshConfig struct {
	// disableRefresh mirrors ?disableRefresh (upstream session.ts:309,340).
	disableRefresh bool
	// dontRememberMe mirrors the dont_remember persistence marker: a
	// non-persistent session is served but never extended (upstream
	// session.ts:124-127,309-323; types.SessionPersistenceOptions).
	dontRememberMe bool
	// readOnly mirrors deferSessionRefresh on GET (upstream session.ts:350):
	// the database is never written; a due refresh is reported via
	// needsRefresh instead of performed.
	readOnly bool
}

// loadSessionWithRefresh loads the session/user rows for token, applying the
// refresh policy in cfg. Besides the rows it reports whether the session was
// extended (refreshed) and — for read-only deferred reads — whether it is
// due for a refresh (needsRefresh).
//
// With Options.SecondaryStorage configured the read goes through the
// secondary-storage session runtime below (upstream db/internal-adapter.ts
// findSession/updateSession/deleteSession); otherwise the database path is
// used unchanged.
func loadSessionWithRefresh(ctx context.Context, opts types.Options, token string, cfg sessionRefreshConfig) (map[string]any, map[string]any, bool, bool, error) {
	if opts.SecondaryStorage != nil {
		return loadSecondarySessionWithRefresh(ctx, opts, token, cfg)
	}
	return loadDatabaseSessionWithRefresh(ctx, opts, token, cfg)
}

// loadDatabaseSessionWithRefresh is the database-backed get-session read
// (upstream findSession without secondary storage): authoritative row lookup,
// expiry gate, refresh write, and user join.
func loadDatabaseSessionWithRefresh(ctx context.Context, opts types.Options, token string, cfg sessionRefreshConfig) (map[string]any, map[string]any, bool, bool, error) {
	// Stateless (DB-less) deployments keep the session in the signed cookie
	// cache only (upstream isStateful == false,
	// context/create-context.ts:102-117): without a database or secondary
	// store there is no authoritative row to consult, so a cache miss is
	// unauthorized instead of a nil-pointer panic. Cache hits return
	// before this function runs.
	if opts.DB == nil {
		return nil, nil, false, false, errUnauthorized
	}
	sessionRow, err := opts.DB.FindOne(ctx, "session", []types.Where{
		{Field: "token", Value: token},
	}, nil)
	if err != nil || sessionRow == nil {
		return nil, nil, false, false, errUnauthorized
	}

	exp := sessionExpiresAt(sessionRow)
	if exp.IsZero() || time.Now().UTC().After(exp) {
		if !cfg.readOnly {
			// Upstream deletes the expired row when (!deferSessionRefresh
			// || POST) (session.ts:297-301); deferred GET guarantees no
			// writes at all. Cleanup is best-effort: a failing delete must
			// not mask the expiry itself.
			_ = opts.DB.Delete(ctx, "session", []types.Where{
				{Field: "token", Value: token},
			})
		}
		return nil, nil, false, false, errSessionExpired
	}

	now := time.Now().UTC()
	var refreshed, needsRefresh bool
	if cfg.readOnly {
		// shouldSkipSessionRefresh suppresses the reported refresh need as
		// well as the write (upstream session.ts:342-344 gating the
		// refresh path; deferred GET reports via needsRefresh).
		if !state.GetShouldSkipSessionRefresh(ctx) {
			needsRefresh = sessionRefreshDue(sessionRow, opts, cfg.disableRefresh, now)
		}
	} else {
		var refreshedSession map[string]any
		refreshedSession, refreshed = refreshSessionIfNeeded(ctx, opts, sessionRow, now, cfg)
		sessionRow = refreshedSession
	}

	userID := stringField(sessionRow, "user_id", "userId")
	userRow, err := opts.DB.FindOne(ctx, "user", []types.Where{
		{Field: "id", Value: userID},
	}, nil)
	if err != nil {
		return nil, nil, false, false, err
	}
	if userRow == nil {
		return nil, nil, false, false, errUserMissing
	}
	return sessionRow, userRow, refreshed, needsRefresh, nil
}

// sessionRefreshDue reports whether a read-only (deferred) get-session would
// refresh the session, using the same due formula as the refresh write
// (upstream session.ts:334-344). The per-request disableRefresh knob and the
// global DisableSessionRefresh flag both suppress it.
func sessionRefreshDue(sessionRow map[string]any, opts types.Options, disableRefresh bool, now time.Time) bool {
	if disableRefresh || opts.Session.DisableSessionRefresh {
		return false
	}
	expiresAt := sessionExpiresAt(sessionRow)
	if expiresAt.IsZero() {
		return false
	}
	expiresIn := opts.Session.ExpiresInDuration()
	updateAge := sessionUpdateAge(opts.Session)
	refreshAt := expiresAt.Add(-expiresIn).Add(updateAge)
	return !now.Before(refreshAt)
}

func refreshSessionIfNeeded(ctx context.Context, opts types.Options, sessionRow map[string]any, now time.Time, cfg sessionRefreshConfig) (map[string]any, bool) {
	// DisableSessionRefresh disables the refresh write regardless of
	// UpdateAge (upstream session.ts:339-341). The per-request
	// ?disableRefresh knob and the dont_remember persistence marker skip it
	// the same way (upstream session.ts:309): the session is still served,
	// just never extended. The server-side shouldSkipSessionRefresh flag
	// (upstream session.ts:342-344) suppresses the write so database and
	// cookie data cannot diverge within one request.
	if state.GetShouldSkipSessionRefresh(ctx) {
		return sessionRow, false
	}
	if opts.Session.DisableSessionRefresh || cfg.disableRefresh || cfg.dontRememberMe {
		return sessionRow, false
	}

	expiresAt := sessionExpiresAt(sessionRow)
	if expiresAt.IsZero() {
		return sessionRow, false
	}

	expiresIn := opts.Session.ExpiresInDuration()
	updateAge := sessionUpdateAge(opts.Session)
	refreshAt := expiresAt.Add(-expiresIn).Add(updateAge)
	if now.Before(refreshAt) {
		return sessionRow, false
	}

	updated, err := opts.DB.Update(ctx, "session", []types.Where{
		{Field: "token", Value: sessionRow["token"]},
	}, map[string]any{
		"expiresAt": now.Add(expiresIn),
		"updatedAt": now,
	})
	if err != nil || updated == nil {
		return sessionRow, false
	}
	return updated, true
}

func sessionExpiresAt(row map[string]any) time.Time {
	if exp, ok := timeField(row, "expires_at", "expiresAt"); ok {
		return exp
	}
	return time.Time{}
}

func sessionUpdateAge(opts types.SessionOptions) time.Duration {
	// Canonical tri-state lives in (SessionOptions).UpdateAgeDuration
	// (types/; F9): nil => 24h default, explicit 0 => always-refresh,
	// >0 => seconds (upstream session.ts:324-344).
	return opts.UpdateAgeDuration()
}

func newSessionCookie(opts types.Options, headers CookieRequestHeaders, token string, expiresAt time.Time) (http.Cookie, error) {
	return issueSessionCookie(opts, headers, token, expiresAt, false)
}

// issueSessionCookie mints the session_token cookie. A non-persistent
// (dontRememberMe) session gets a true session cookie — no Expires/Max-Age —
// mirroring upstream setSessionCookie's cleared maxAge
// (cookies/index.ts:373-386). The frozen newSessionCookie wrapper preserves
// the persistent form for the sibling-owned issuance paths (account, social,
// email-verification), which do not thread remember-me.
func issueSessionCookie(opts types.Options, headers CookieRequestHeaders, token string, expiresAt time.Time, dontRememberMe bool) (http.Cookie, error) {
	signed, err := cookies.Sign(opts.CurrentSecret(), token)
	if err != nil {
		return http.Cookie{}, err
	}
	cfg := resolveSessionCookieConfig(opts, headers)
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
		// Upstream always carries Max-Age=expiresIn on the persistent
		// session_token cookie (getCookies sessionMaxAge default,
		// cookies/index.ts:122-125; refresh override session.ts:386-397).
		// The 400-day browser ceiling (#9609) is then exactly expiresIn.
		cookie.MaxAge = int(opts.Session.ExpiresInDuration().Seconds())
	}
	return cookie, nil
}

func expiredSessionCookie(opts types.Options, headers CookieRequestHeaders) http.Cookie {
	cfg := resolveSessionCookieConfig(opts, headers)
	return http.Cookie{
		Name:     cfg.Name,
		Value:    "",
		Path:     cfg.Path,
		Domain:   cfg.Domain,
		HttpOnly: cfg.HTTPOnly,
		SameSite: cfg.SameSite,
		Secure:   cfg.Secure,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0).UTC(),
	}
}

// expiredSessionTokenCleanupCookie builds the request-aware expired
// session_token cleanup emitted alongside the session_data cleanup on
// EXPIRED/invalid get-session failures (G4; upstream deleteSessionCookie
// clears both, session.ts:291,380). Request-aware naming/attributes mirror
// the issuance path via resolveSessionCookieConfigWithContext (owned by
// session-c701.go; this session.go call site only consumes it).
func expiredSessionTokenCleanupCookie(ctx context.Context, opts types.Options, headers CookieRequestHeaders) http.Cookie {
	cfg := resolveSessionCookieConfigWithContext(ctx, opts, headers)
	return http.Cookie{
		Name:     cfg.Name,
		Value:    "",
		Path:     cfg.Path,
		Domain:   cfg.Domain,
		HttpOnly: cfg.HTTPOnly,
		SameSite: cfg.SameSite,
		Secure:   cfg.Secure,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0).UTC(),
	}
}

func newSessionDataCookie(secret string, session types.Session, user types.User, fullOpts types.Options, opts types.SessionOptions, now time.Time, dontRememberMe bool) (http.Cookie, error) {
	// Stamp the resolved version (upstream setCookieCache version block):
	// rotation invalidates older caches on read. A failing VersionFunc fails
	// the write, matching upstream where the awaited version rejects the
	// set-cookie path.
	version, err := resolveCookieCacheVersion(session, user, opts)
	if err != nil {
		return http.Cookie{}, err
	}
	// Strip schema-declared returned:false fields after version resolution.
	// Upstream setCookieCache filters first textually but resolves the
	// version from the original unfiltered pair; Go resolves version first
	// and filters after, which is the same data-flow (version always sees
	// unfiltered inputs). Shared helper with the context-aware issuance
	// path in session-c701.go.
	session, user = filterCookieCacheSessionUser(session, user, fullOpts, opts)
	maxAge := opts.CookieCacheMaxAgeDuration()
	if dontRememberMe {
		// Upstream clears the cache maxAge for non-persistent sessions
		// (setCookieCache maxAge undefined); the 60s floor in getDate
		// applies (cookies/index.ts:194-201).
		maxAge = time.Minute
	}
	expiresAt := now.Add(maxAge).UTC()
	if session.ExpiresAt.Before(expiresAt) {
		expiresAt = session.ExpiresAt.UTC()
	}
	// Strategy-aware encoding (upstream setCookieCache strategy branch):
	// compact uses the upstream base64url+HMAC envelope via
	// cookies.CreateCompactCookieCache (so Go values verify upstream and
	// TS-issued values hit); jwt issues an HS256 JWT and jwe a
	// dir/A256CBC-HS512 JWE via the cookies package. The legacy Go
	// signed-envelope codec stays as a read fallback in compactCachePayload.
	var value string
	switch cookieCacheStrategy(opts) {
	case cookies.StrategyJWT:
		sessionMap, err := cacheStructMap(session)
		if err != nil {
			return http.Cookie{}, err
		}
		userMap, err := cacheStructMap(user)
		if err != nil {
			return http.Cookie{}, err
		}
		value, err = cookies.CreateSessionCacheJWT(secret, sessionMap, userMap, version, time.Until(expiresAt))
		if err != nil {
			return http.Cookie{}, err
		}
	case cookies.StrategyJWE:
		sessionMap, err := cacheStructMap(session)
		if err != nil {
			return http.Cookie{}, err
		}
		userMap, err := cacheStructMap(user)
		if err != nil {
			return http.Cookie{}, err
		}
		value, err = cookies.CreateSessionCacheJWE(secret, sessionMap, userMap, version, time.Until(expiresAt))
		if err != nil {
			return http.Cookie{}, err
		}
	default:
		sessionMap, err := cacheStructMap(session)
		if err != nil {
			return http.Cookie{}, err
		}
		userMap, err := cacheStructMap(user)
		if err != nil {
			return http.Cookie{}, err
		}
		filterCookieCacheMaps(sessionMap, userMap, fullOpts, opts)
		sessionData := map[string]any{
			"session":   sessionMap,
			"user":      userMap,
			"updatedAt": now.UnixMilli(),
			"version":   version,
		}
		value, err = cookies.CreateCompactCookieCache(secret, sessionData, time.Until(expiresAt))
		if err != nil {
			return http.Cookie{}, err
		}
	}
	maxAgeSecs := int(time.Until(expiresAt).Seconds())
	if maxAgeSecs < 0 {
		maxAgeSecs = 0
	}
	return http.Cookie{
		Name:     sessionDataCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  expiresAt,
		MaxAge:   maxAgeSecs,
	}, nil
}

// cacheStructMap converts a session/user struct into the generic map the
// JWT/JWE cache codecs sign or encrypt. The JSON round-trip keeps the
// Go-canonical nested shape (additional fields under "additionalFields"),
// which typedCachePayload restores on read.
func cacheStructMap(v any) (map[string]any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func expiredSessionDataCookie() http.Cookie {
	return http.Cookie{
		Name:     sessionDataCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0).UTC(),
	}
}

func newSessionCookies(authOpts types.Options, headers CookieRequestHeaders, token string, session types.Session, user types.User, opts types.SessionOptions, now time.Time) ([]http.Cookie, error) {
	return issueSessionCookies(authOpts, headers, token, session, user, opts, now, false)
}

// issueSessionCookies mints the full issuance cookie set, mirroring upstream
// setSessionCookie (cookies/index.ts:356-398): the session_token cookie
// (without a persistent lifetime for dontRememberMe sessions), the signed
// dont_remember marker when the session is non-persistent, and the
// strategy-aware cache cookie when enabled. The frozen newSessionCookies
// wrapper preserves the persistent form for the sibling-owned issuance paths
// (account, social, email-verification), which do not thread remember-me.
//
// Cookie-cache writes chunk oversize values via cookies.BuildChunkedCookies
// (upstream chunkCookie on write, session-store.ts:84-131 wired through
// index.ts:245-250): values fitting the budget stay single under the bare
// name, larger values split into "<name>.<i>" chunks. A value exceeding
// MaxCookieChunks warns-and-skips (Logf warn, serve authoritative with no
// cache) instead of failing the issuance. The context-aware issuance in
// session-c701.go is owned by another agent; this session.go site covers the
// static issuance legs.
func issueSessionCookies(authOpts types.Options, headers CookieRequestHeaders, token string, session types.Session, user types.User, opts types.SessionOptions, now time.Time, dontRememberMe bool) ([]http.Cookie, error) {
	sessionCookie, err := issueSessionCookie(authOpts, headers, token, session.ExpiresAt, dontRememberMe)
	if err != nil {
		return nil, err
	}
	cookiesOut := []http.Cookie{sessionCookie}
	if dontRememberMe {
		marker, err := newDontRememberCookie(authOpts, headers)
		if err != nil {
			return nil, err
		}
		cookiesOut = append(cookiesOut, marker)
	}
	if opts.CookieCache.Enabled {
		cacheCookie, err := newSessionDataCookie(authOpts.CurrentSecret(), session, user, authOpts, opts, now, dontRememberMe)
		if err != nil {
			return nil, err
		}
		attrs := cookies.Attributes{
			Path:       cacheCookie.Path,
			Domain:     cacheCookie.Domain,
			Secure:     cacheCookie.Secure,
			HttpOnly:   cacheCookie.HttpOnly,
			SameSite:   cacheCookie.SameSite,
			MaxAge:     cacheCookie.MaxAge,
			MaxAgeSet:  true,
			Expires:    cacheCookie.Expires,
			ExpiresSet: !cacheCookie.Expires.IsZero(),
		}
		if attrs.Path == "" {
			attrs.Path = "/"
		}
		chunked, cerr := cookies.BuildChunkedCookies(cacheCookie.Name, cacheCookie.Value, attrs)
		if cerr != nil {
			Logf(authOpts, "warn", "session_data too large to store even after chunking; skipping cookie cache")
		} else {
			for _, c := range chunked {
				if c != nil {
					cookiesOut = append(cookiesOut, *c)
				}
			}
		}
	}
	return cookiesOut, nil
}

// newDontRememberCookie mints the signed dont_remember persistence marker
// (upstream setSessionCookie, cookies/index.ts:388-395): a true session
// cookie (no Expires/Max-Age) carrying the signed "true" value under the
// configured dont_remember name.
func newDontRememberCookie(opts types.Options, headers CookieRequestHeaders) (http.Cookie, error) {
	signed, err := cookies.Sign(opts.CurrentSecret(), "true")
	if err != nil {
		return http.Cookie{}, err
	}
	cfg := resolveDontRememberCookieConfig(opts, headers)
	return http.Cookie{
		Name:     cfg.Name,
		Value:    signed,
		Path:     cfg.Path,
		Domain:   cfg.Domain,
		HttpOnly: cfg.HTTPOnly,
		SameSite: cfg.SameSite,
		Secure:   cfg.Secure,
	}, nil
}

// expiredDontRememberCookie expires the persistence marker, mirroring
// upstream deleteSessionCookie (cookies/index.ts:506-542), which always
// clears it alongside the session cookies.
func expiredDontRememberCookie(authOpts types.Options, headers CookieRequestHeaders) http.Cookie {
	cfg := resolveDontRememberCookieConfig(authOpts, headers)
	return http.Cookie{
		Name:     cfg.Name,
		Value:    "",
		Path:     cfg.Path,
		Domain:   cfg.Domain,
		HttpOnly: cfg.HTTPOnly,
		SameSite: cfg.SameSite,
		Secure:   cfg.Secure,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0).UTC(),
	}
}

// expiredDontRememberCleanupCookie builds the request-aware expired
// dont_remember cleanup emitted alongside the session_token cleanup on
// EXPIRED/invalid/user-missing get-session failures (upstream
// deleteSessionCookie clears it by default; session.ts:291,380 with
// cookies/index.ts:506-542). Request-aware naming/attributes mirror the
// issuance path via resolveDontRememberCookieConfigWithContext (owned by
// session-c701.go; this session.go call site only consumes it).
func expiredDontRememberCleanupCookie(ctx context.Context, opts types.Options, headers CookieRequestHeaders) http.Cookie {
	cfg := resolveDontRememberCookieConfigWithContext(ctx, opts, headers)
	return http.Cookie{
		Name:     cfg.Name,
		Value:    "",
		Path:     cfg.Path,
		Domain:   cfg.Domain,
		HttpOnly: cfg.HTTPOnly,
		SameSite: cfg.SameSite,
		Secure:   cfg.Secure,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0).UTC(),
	}
}

// resolveDontRememberCookieConfig mirrors the session-cookie attribute
// pipeline (secure resolution, cross-subdomain domain, default attributes,
// per-cookie overrides) for the dont_remember marker name.
func resolveDontRememberCookieConfig(opts types.Options, headers CookieRequestHeaders) resolvedSessionCookieConfig {
	secure := resolveSecureCookies(opts, headers)
	cfg := resolvedSessionCookieConfig{
		Name:     resolveDontRememberCookieName(opts, secure),
		Path:     "/",
		Secure:   secure,
		HTTPOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	if opts.Advanced.CrossSubDomainCookies.Enabled {
		cfg.Domain = resolveCrossSubDomainCookieDomain(opts, headers)
	}
	applyCookieAttributes(&cfg, opts.Advanced.DefaultCookieAttributes)
	if override, ok := opts.Advanced.Cookies[dontRememberCookieName]; ok {
		applyCookieAttributes(&cfg, override.Attributes)
	}
	return cfg
}

func expiredSessionCookies(authOpts types.Options, headers CookieRequestHeaders) []http.Cookie {
	cookiesOut := []http.Cookie{expiredSessionCookie(authOpts, headers)}
	if authOpts.Session.CookieCache.Enabled {
		cookiesOut = append(cookiesOut, expiredSessionDataCookie())
	}
	cookiesOut = append(cookiesOut, expiredDontRememberCookie(authOpts, headers))
	return cookiesOut
}

// cookieCacheVersionErr re-resolves the cookie-cache version for an
// otherwise bound cache entry, surfacing a rejecting VersionFunc as an error
// (upstream session.ts:138-154, where the rejected version promise 500s via
// the endpoint catch-all). It returns nil when there is no usable cache entry
// (nothing to version-check), when the entry is unbound (token mismatch or
// expired — the fast path missed for that reason, not the version), or when
// the version resolves (match or rotation mismatch both fall through to the
// authoritative database read). Only a VersionFunc failure itself errors.
//
// The fast-path helper (cachedSessionFromRequestFull, owned by another agent)
// reports every version outcome as a miss; resolveGetSession consults this
// helper on a miss so the rejection surfaces as a 500 instead of failing
// closed to the database.
func cookieCacheVersionErr(ctx context.Context, cookieHeader string, secrets []string, token string, opts types.Options) error {
	if !opts.Session.CookieCache.Enabled || token == "" || cookieHeader == "" {
		return nil
	}
	value, ok := sessionDataCookieValue(cookieHeader, opts)
	if !ok {
		return nil
	}
	var payload *sessionCookieCachePayload
	switch cookieCacheStrategy(opts.Session) {
	case cookies.StrategyJWT:
		if signer, found := findCookieCacheSigner(opts); found {
			custom, ok := verifyViaCustomSigner(ctx, opts, signer, value)
			if !ok {
				return nil
			}
			payload = custom
		} else {
			payload, _ = jwtCachePayload(value, secrets)
		}
	case cookies.StrategyJWE:
		payload, _ = jweCachePayload(value, secrets)
	default:
		payload, _ = compactCachePayload(value, secrets)
	}
	if payload == nil {
		return nil
	}
	now := time.Now().UTC()
	if payload.Session.Token != token || now.After(payload.ExpiresAt) || now.After(payload.Session.ExpiresAt) {
		return nil
	}
	_, verr := resolveCookieCacheVersion(payload.Session, payload.User, opts.Session)
	return verr
}

func cachedSessionFromRequest(cookieHeader string, secrets []string, token string, opts types.SessionOptions) (*sessionCookieCachePayload, bool) {
	if !opts.CookieCache.Enabled || token == "" || cookieHeader == "" {
		return nil, false
	}
	// Chunk-aware, cookie-name-aware recovery (upstream
	// session-store.ts getChunkedCookie + cookie-cache-fallback.test.ts):
	// exact-name wins, otherwise "<name>.<index>" chunks reassemble. The
	// legacy Go name and the upstream defaults are all accepted so
	// TS-issued and cross-subdomain leftovers recover instead of forcing
	// a logout. Custom Advanced.Cookies names go through
	// cachedSessionFromRequestFull (which has full Options).
	value, ok := sessionDataCookieValueForSession(cookieHeader)
	if !ok {
		return nil, false
	}
	// Strategy-aware decode (upstream decodeCookieCache, cookies/index.ts):
	// compact verifies the outer HMAC envelope, jwt verifies the HS256
	// signature, jwe decrypts with the kid-selected derived key. Every
	// failure falls through to the database (fail closed, never trust).
	var payload *sessionCookieCachePayload
	switch cookieCacheStrategy(opts) {
	case cookies.StrategyJWT:
		payload, _ = jwtCachePayload(value, secrets)
	case cookies.StrategyJWE:
		payload, _ = jweCachePayload(value, secrets)
	default:
		payload, _ = compactCachePayload(value, secrets)
	}
	if payload == nil {
		return nil, false
	}
	now := time.Now().UTC()
	if payload.Session.Token != token || now.After(payload.ExpiresAt) || now.After(payload.Session.ExpiresAt) {
		return nil, false
	}
	// Version rotation invalidates existing caches (upstream
	// session.ts:138-154). A stale version — or a VersionFunc rejection,
	// e.g. after a credential change — is a miss, and the database read
	// below re-issues the cache. Missing versions predate stamping and mean
	// "1", matching upstream's `session.version || "1"`. A failing
	// VersionFunc itself is an operational failure: unlike upstream (whose
	// rejected version promise 500s via the endpoint catch-all), this frozen
	// helper still reports a miss; the get-session route surfaces the 500
	// instead via cookieCacheVersionErr in resolveGetSession (B4), so the
	// served data is never silently stale.
	if expected, verr := resolveCookieCacheVersion(payload.Session, payload.User, opts); verr != nil || normalizeCookieCacheVersion(payload.Version) != expected {
		return nil, false
	}
	return payload, true
}

// compactCachePayload decodes the compact strategy with upstream interop:
// the upstream base64url envelope (cookies/cache.go VerifyCompactCookieCache,
// mirroring setCookieCache/decodeCookieCache compact branch) is tried first
// so TS-issued values hit; the Go legacy signed-envelope codec stays as a
// fallback so pre-migration cookies still read. Signature verification comes
// first in both paths; the typed unmarshal alone is not a shape check (it
// silently coerces e.g. null `emailVerified` to `false`), so the decoded
// bytes are also validated as raw maps against the shared cookie-cache
// contract (upstream parseCookieCachePayload, cookies/cache.ts:20-39). A
// schema-invalid payload surfaces the shared sentinel — callers must treat
// it as a miss (Logf-warn through the configured logger + fall through to
// the database, never throw), exactly like the codec-level verdict.
func compactCachePayload(value string, secrets []string) (*sessionCookieCachePayload, error) {
	// Upstream compact first (TS-issued values hit; Go values verify upstream).
	if sessionData, outerMs, verr := cookies.VerifyCompactCookieCache(secrets, value); verr == nil {
		innerSession, _ := sessionData["session"].(map[string]any)
		innerUser, _ := sessionData["user"].(map[string]any)
		version, _ := sessionData["version"].(string)
		data := cookies.SessionCacheData{
			Session:   innerSession,
			User:      innerUser,
			Version:   version,
			ExpiresAt: outerMs,
		}
		if typed, terr := typedCachePayload(data); terr == nil {
			return typed, nil
		} else if errors.Is(terr, cookies.ErrCachePayloadSchema) {
			return nil, terr
		}
		// Conversion failure (non-schema) falls through to legacy attempt
		// below so a corrupt-but-signed upstream value still misses cleanly.
	} else if errors.Is(verr, cookies.ErrCachePayloadSchema) {
		// Correctly-signed but schema-invalid upstream payload: miss with
		// sentinel (warn at the session layer), never legacy fallback.
		return nil, verr
	}
	// Legacy Go signed-envelope fallback.
	raw, ok := cookies.VerifyAny(secrets, value)
	if !ok {
		return nil, errors.New("auth: invalid compact cache signature")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	var payload sessionCookieCachePayload
	if err := json.Unmarshal(decoded, &payload); err != nil {
		return nil, err
	}
	var shape struct {
		Session map[string]any `json:"session"`
		User    map[string]any `json:"user"`
	}
	if err := json.Unmarshal(decoded, &shape); err != nil {
		return nil, err
	}
	if err := cookies.ValidateCachePayloadSchema(shape.Session, shape.User); err != nil {
		return nil, fmt.Errorf("auth: invalid compact cache payload schema: %w", err)
	}
	return &payload, nil
}

// jwtCachePayload decodes a StrategyJWT cache value into the shared payload
// shape. The JWT claims carry the Go-canonical nested session/user structs
// (see newSessionDataCookie); maps convert back via a JSON round-trip so
// additional fields survive exactly as issued.
func jwtCachePayload(value string, secrets []string) (*sessionCookieCachePayload, error) {
	data, _, err := cookies.VerifySessionCacheJWT(secrets, value)
	if err != nil {
		return nil, err
	}
	return typedCachePayload(data)
}

// jweCachePayload decodes a StrategyJWE cache value into the shared payload
// shape, mirroring jwtCachePayload.
func jweCachePayload(value string, secrets []string) (*sessionCookieCachePayload, error) {
	data, _, err := cookies.VerifySessionCacheJWE(secrets, value)
	if err != nil {
		return nil, err
	}
	return typedCachePayload(data)
}

// typedCachePayload converts a decoded JWT/JWE payload into the shared cache
// payload: the outer window becomes ExpiresAt, the stamped version is
// preserved ("" reads back as the default at the check site).
func typedCachePayload(data cookies.SessionCacheData) (*sessionCookieCachePayload, error) {
	sessionJSON, err := json.Marshal(data.Session)
	if err != nil {
		return nil, err
	}
	userJSON, err := json.Marshal(data.User)
	if err != nil {
		return nil, err
	}
	var session types.Session
	if err := json.Unmarshal(sessionJSON, &session); err != nil {
		return nil, err
	}
	var user types.User
	if err := json.Unmarshal(userJSON, &user); err != nil {
		return nil, err
	}
	return &sessionCookieCachePayload{
		Session:   session,
		User:      user,
		ExpiresAt: time.UnixMilli(data.ExpiresAt).UTC(),
		Version:   data.Version,
	}, nil
}

// isNullSessionError reports whether err is a missing/expired/user-missing
// failure that the get-session HTTP layer answers with the upstream 200
// literal null (session.ts:94-112,287-303, ctx.json(null)): 401
// FAILED_TO_GET_SESSION (no/invalid token, plus user-missing which
// findSession surfaces as null) and 400 SESSION_EXPIRED. Operational failures
// reuse the same code at 500 via sessionInternalError and must NOT map to
// null; other codes (METHOD_NOT_ALLOWED_*, ...) keep their error status.
func isNullSessionError(err error) bool {
	var statusErr huma.StatusError
	if !errors.As(err, &statusErr) {
		return false
	}
	detail := statusErr.Error()
	switch statusErr.GetStatus() {
	case http.StatusUnauthorized:
		return strings.Contains(detail, types.ErrFailedToGetSession)
	case http.StatusBadRequest:
		return strings.Contains(detail, types.ErrSessionExpired)
	default:
		return false
	}
}

// sessionRouteError maps an auth error code to its canonical upstream HTTP
// status (types.StatusForCode), keeping session-route errors pinned to the
// better-auth contract instead of hand-picked Huma constructors.
//
// Adjudicated divergences (upstream pins only {code,message} per key; the
// status varies by throw site, see types.StatusForCode):
//   - SESSION_EXPIRED resolves to 400: its sole upstream throw site is
//     BAD_REQUEST (update-user.ts:543). The get-session HTTP layer maps this
//     (with 401 FAILED_TO_GET_SESSION) to the upstream 200 null shape via
//     isNullSessionError (session.ts:94-112,287-303); the resolver itself
//     keeps surfacing the error, so the code's canonical 400 applies here
//     (previously 401 here).
//   - FAILED_TO_GET_SESSION resolves to 401, matching the UNAUTHORIZED
//     throw sites (session.ts:381-384, update-session.ts:88-93). The
//     get-session HTTP layer maps this (with 400 SESSION_EXPIRED) to the
//     upstream 200 null shape via isNullSessionError; the resolver itself
//     keeps surfacing the error. Internal failures carrying the same code
//     upstream (session.ts:427-435, update-user.ts:290-297, both
//     INTERNAL_SERVER_ERROR) keep an explicit 500 via sessionInternalError
//     below — StatusForCode must not launder them into 401s (and the 500
//     variant never maps to null).
//   - USER_NOT_FOUND resolves to 404 (majority throw-site status). Upstream
//     findSession returns null when the user row is missing, so the
//     get-session resolver maps user-missing to FAILED_TO_GET_SESSION (401)
//     for the 200 literal-null path above; this 404 mapping remains for the
//     non-get-session callers that surface USER_NOT_FOUND directly.
//   - METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED resolves to 405, matching
//     the upstream throw status (session.ts:79-84).
func sessionRouteError(code string) error {
	return huma.NewError(types.StatusForCode(code), code)
}

// sessionInternalError keeps database and cookie failures that carry an auth
// error code at 500, mirroring the upstream INTERNAL_SERVER_ERROR throw
// sites that reuse the same codes (see sessionRouteError).
func sessionInternalError(code string) error {
	return huma.NewError(http.StatusInternalServerError, code)
}

// cookieCacheStrategy resolves the effective cookie-cache encoding,
// defaulting to compact (upstream default, cookies/index.ts setCookieCache).
// All three strategies have Go codecs (compact in cookies/session_cache.go,
// jwt/jwe in cookies/session_jwt.go); the custom-JWKS signer path owned by
// the JWT plugin is wired at the route layer (cachedSessionFromRequestFull /
// newSessionDataCookieWithContext via findCookieCacheSigner, with rotation,
// typ/kid/aud/iss/sub/sid binding, and authoritative fallback).
func cookieCacheStrategy(opts types.SessionOptions) string {
	if opts.CookieCache.Strategy == "" {
		return cookies.StrategyCompact
	}
	return string(opts.CookieCache.Strategy)
}

// resolveCookieCacheVersion derives the expected cookie-cache version for a
// session/user pair (upstream setCookieCache and get-session version
// blocks): VersionFunc takes precedence over the static Version; both
// default to "1" (cookies.DefaultCookieCacheVersion).
func resolveCookieCacheVersion(session types.Session, user types.User, opts types.SessionOptions) (string, error) {
	if opts.CookieCache.VersionFunc != nil {
		return opts.CookieCache.VersionFunc(session, user)
	}
	if opts.CookieCache.Version != "" {
		return opts.CookieCache.Version, nil
	}
	return cookies.DefaultCookieCacheVersion, nil
}

// normalizeCookieCacheVersion maps an unstamped cache payload to the default
// version, matching upstream's `session.version || "1"`.
func normalizeCookieCacheVersion(version string) string {
	if version == "" {
		return cookies.DefaultCookieCacheVersion
	}
	return version
}

// maybeRefreshCookieCache re-issues the stateless cookie cache when its
// remaining lifetime drops below the RefreshCache threshold, without
// touching the database (upstream session.ts:199-259). It returns the
// cookies to attach, or nil when no refresh is due.
//
// Mapping notes:
//   - Upstream disables refreshCache with a warning when a server-side store
//     is configured (create-context.ts:318-351); the Go runtime always has a
//     store, so the knob is honored literally instead: Enabled refreshes,
//     unset serves the cache as-is until it expires.
//   - The per-request ?disableRefresh knob does NOT gate this path upstream
//     (only the server-side shouldSkipSessionRefresh flag does, consulted at
//     the session.go call sites with request context — resolveGetSession
//     fast-path — and in refreshSessionIfNeeded for the DB write; the
//     context-aware c701 helper is owned by another agent); ShouldRefresh is
//     the per-session gate here. This ctx-free static helper keeps its
//     signature for existing callers/tests and does not consult the flag
//     itself.
//   - For dontRememberMe sessions the session_token cookie is re-issued
//     without a persistent lifetime and the cache window is capped at 60s,
//     mirroring upstream's cleared maxAge (session.ts:217-230).
func maybeRefreshCookieCache(authOpts types.Options, headers CookieRequestHeaders, token string, payload *sessionCookieCachePayload, now time.Time, dontRememberMe bool) []http.Cookie {
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
	refreshed, err := issueSessionCookies(authOpts, headers, token, payload.Session, payload.User, authOpts.Session, now, dontRememberMe)
	if err != nil {
		return nil
	}
	return refreshed
}

const dontRememberCookieName = "dont_remember"

// resolveDontRememberCookieName mirrors the upstream dont_remember cookie
// name (`<prefix>.dont_remember`, cookies/index.ts getCookies): the secure
// prefix applies under secure cookies and Advanced.Cookies may override the
// name, exactly like the session_token cookie.
func resolveDontRememberCookieName(opts types.Options, secure bool) string {
	baseName := defaultCookiePrefix + "." + dontRememberCookieName
	if opts.Advanced.CookiePrefix != "" {
		baseName = opts.Advanced.CookiePrefix + "." + dontRememberCookieName
	}
	if override, ok := opts.Advanced.Cookies[dontRememberCookieName]; ok && override.Name != "" {
		baseName = override.Name
	}
	if secure {
		return secureCookiePrefix + baseName
	}
	return baseName
}

// hasDontRememberCookie reports whether the request carries a valid signed
// dont_remember marker (upstream session.ts:124-127). Both the secure and
// non-secure spellings are accepted, mirroring sessionCookieLookupNames.
//
// The mint side lives in issueSessionCookies: rememberMe === false shortens
// the session expiry to 1 day (creationSessionExpiry, upstream
// internal-adapter.ts:509) and issues the marker via the issuance cookie set
// (upstream setSessionCookie, cookies/index.ts:388-395); sign-out and the
// other session-ending paths clear it via expiredSessionCookies (upstream
// deleteSessionCookie).
func hasDontRememberCookie(cookieHeader string, opts types.Options) bool {
	if cookieHeader == "" {
		return false
	}
	req := &http.Request{Header: http.Header{"Cookie": []string{cookieHeader}}}
	for _, name := range []string{
		resolveDontRememberCookieName(opts, false),
		resolveDontRememberCookieName(opts, true),
	} {
		cookie, err := req.Cookie(name)
		if err != nil {
			continue
		}
		if _, ok := cookies.VerifyAny(opts.AllSecrets(), cookie.Value); ok {
			return true
		}
	}
	return false
}

func sessionTokenFromRequest(cookieHeader, authHeader string, opts types.Options) string {
	if token := signedSessionCookie(cookieHeader, opts); token != "" {
		return token
	}
	return bearerToken(authHeader)
}

func signedSessionCookie(cookieHeader string, opts types.Options) string {
	if cookieHeader == "" {
		return ""
	}
	req := &http.Request{Header: http.Header{"Cookie": []string{cookieHeader}}}
	for _, name := range sessionCookieLookupNames(opts) {
		cookie, err := req.Cookie(name)
		if err != nil {
			continue
		}
		value, ok := cookies.VerifyAny(opts.AllSecrets(), cookie.Value)
		if ok {
			return value
		}
	}
	return ""
}

func bearerToken(authHeader string) string {
	const prefix = "Bearer "
	if strings.HasPrefix(authHeader, prefix) {
		return strings.TrimPrefix(authHeader, prefix)
	}
	return ""
}

type resolvedSessionCookieConfig struct {
	Name     string
	Domain   string
	Path     string
	Secure   bool
	HTTPOnly bool
	SameSite http.SameSite
	MaxAge   *int
}

func resolveSessionCookieConfig(opts types.Options, headers CookieRequestHeaders) resolvedSessionCookieConfig {
	secure := resolveSecureCookies(opts, headers)
	cfg := resolvedSessionCookieConfig{
		Name:     resolveSessionCookieName(opts, secure),
		Path:     "/",
		Secure:   secure,
		HTTPOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	if opts.Advanced.CrossSubDomainCookies.Enabled {
		cfg.Domain = resolveCrossSubDomainCookieDomain(opts, headers)
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

func applyCookieAttributes(cfg *resolvedSessionCookieConfig, attrs types.CookieAttributes) {
	if attrs.Domain != "" {
		cfg.Domain = attrs.Domain
	}
	if attrs.Path != "" {
		cfg.Path = attrs.Path
	}
	if attrs.Secure != nil {
		cfg.Secure = *attrs.Secure
	}
	if attrs.HTTPOnly != nil {
		cfg.HTTPOnly = *attrs.HTTPOnly
	}
	if attrs.SameSite != 0 {
		cfg.SameSite = attrs.SameSite
	}
	if attrs.MaxAge != nil {
		v := *attrs.MaxAge
		cfg.MaxAge = &v
	}
}

func resolveSessionCookieName(opts types.Options, secure bool) string {
	baseName := defaultCookiePrefix + "." + defaultSessionCookieName
	if opts.Advanced.CookiePrefix != "" {
		baseName = opts.Advanced.CookiePrefix + "." + defaultSessionCookieName
	}
	if override, ok := opts.Advanced.Cookies[defaultSessionCookieName]; ok && override.Name != "" {
		baseName = override.Name
	}
	if secure {
		return secureCookiePrefix + baseName
	}
	return baseName
}

func sessionCookieLookupNames(opts types.Options) []string {
	names := []string{
		resolveSessionCookieName(opts, false),
		resolveSessionCookieName(opts, true),
		legacySessionCookieName,
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

// resolveSecureCookies is the static-fallback secure inference used by
// direct-API/background callers. Request handlers prefer the context-aware
// variant (dynamic protocol via EffectiveBaseURL); both agree whenever no
// per-request DynamicBaseURL override applies.
func resolveSecureCookies(opts types.Options, headers CookieRequestHeaders) bool {
	if opts.Advanced.UseSecureCookies != nil {
		return *opts.Advanced.UseSecureCookies
	}
	if trustedProxyHeadersEnabled(opts) {
		switch trustedProxyProto(headers.XForwardedProto) {
		case "https":
			return true
		case "http":
			return false
		}
	}
	// Dynamic baseURL mode has no static origin: infer the scheme from the
	// request host and the configured protocol (mirroring
	// ResolveDynamicBaseURLForRequest scheme logic). An explicit http/https
	// protocol wins; auto/unset uses http for loopback hosts, https
	// otherwise. Static behavior is unchanged when BaseURL is set.
	if strings.TrimSpace(opts.BaseURL) == "" && opts.DynamicBaseURL != nil {
		switch opts.DynamicBaseURL.Protocol {
		case types.BaseURLProtocolHTTP:
			return false
		case types.BaseURLProtocolHTTPS:
			return true
		default:
			if host := strings.TrimSpace(headers.Host); host != "" {
				if isLoopbackHostPort(host) {
					return false
				}
				return true
			}
			return false
		}
	}
	return strings.HasPrefix(strings.ToLower(opts.BaseURL), "https://")
}

// resolveCrossSubDomainCookieDomain is the static-fallback domain resolver
// used by direct-API/background callers. Request handlers prefer the
// context-aware variant; both agree whenever no per-request DynamicBaseURL
// override applies.
func resolveCrossSubDomainCookieDomain(opts types.Options, headers CookieRequestHeaders) string {
	if opts.Advanced.CrossSubDomainCookies.Domain != "" {
		return opts.Advanced.CrossSubDomainCookies.Domain
	}
	if trustedProxyHeadersEnabled(opts) {
		if host, ok := trustedProxyHost(headers.XForwardedHost); ok {
			return host
		}
	}
	if opts.BaseURL != "" {
		if parsed, err := url.Parse(opts.BaseURL); err == nil {
			if host := parsed.Hostname(); host != "" {
				return host
			}
		}
	}
	if host, ok := trustedProxyHost(headers.Host); ok {
		return host
	}
	return ""
}

func trustedProxyHeadersEnabled(opts types.Options) bool {
	return opts.Advanced.TrustedProxyHeaders != nil && *opts.Advanced.TrustedProxyHeaders
}

func trustedProxyProto(raw string) string {
	if raw == "http" || raw == "https" {
		return raw
	}
	return ""
}

var trustedProxyHostRE = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*(:[0-9]{1,5})?$`)

func trustedProxyHost(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	if strings.Contains(raw, "..") || strings.ContainsAny(raw, "<>'\" \t\r\n") ||
		strings.HasPrefix(raw, ".") || strings.Contains(strings.ToLower(raw), "javascript:") ||
		strings.Contains(strings.ToLower(raw), "file:") || strings.Contains(strings.ToLower(raw), "data:") {
		return "", false
	}
	if raw != "localhost" && !trustedProxyHostRE.MatchString(raw) {
		host, port, err := net.SplitHostPort(raw)
		if err != nil || host == "" || port == "" {
			return "", false
		}
	}
	if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		return strings.Trim(raw, "[]"), true
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		return host, true
	}
	return raw, true
}

// --- Secondary-storage session runtime ---
//
// Mirrors the secondary-storage branches of upstream db/internal-adapter.ts
// (createSession mirroring, findSession, updateSession, deleteSession,
// deleteUserSessions, deleteSessions, listSessions). Sessions are cached as
// JSON {session,user} values under the token key; the per-user
// `active-sessions-<userId>` list holds [{token, expiresAt}] references with
// millisecond-epoch expirations, sorted ascending, TTL'd to the furthest
// expiration. Secondary get returns unknown (string or already-parsed
// object); both shapes are accepted, matching upstream safeJSONParse.
//
// Flag matrix (upstream, internal-adapter.ts:429,479-482,899-905,946-958):
//
//   - SecondaryStorage unset → database only (this section is inert).
//   - Secondary set, StoreSessionInDatabase false → secondary only; reads
//     never consult the database, deletes skip it.
//   - StoreSessionInDatabase true → both stores; reads fall back to the
//     database on a secondary miss and backfill it.
//   - PreserveSessionInDatabase true (requires StoreSessionInDatabase) →
//     revokes delete the secondary entries but only end the database rows
//     (expiresAt=now, live rows only) instead of deleting them, so audit
//     history survives while liveness checks treat them as ended. Revoked
//     sessions never resolve from the database because the secondary miss
//     short-circuits the fallback in preserve mode.
//
// Session.StoreSessionInDatabase and Session.PreserveSessionInDatabase are
// upstream names (types.SessionOptions); the secondary backend is
// Options.SecondaryStorage (types.SecondaryStorage, TTLs in seconds).
//
// TRANSITIONAL DEVIATION (loud, intentional): sibling creation paths
// (sign-up/sign-in auto-sign-in, OAuth linking) still write database rows
// directly and do not mirror into secondary storage yet. Until they call
// writeSecondarySession, a secondary miss with StoreSessionInDatabase falls
// back to the database and backfills the entry (upstream would return null
// outside the storeSessionInDatabase && !preserve case). Revocation stays
// safe in every mode: revoked tokens are deleted from secondary storage, and
// preserve-ended rows read as expired, so the fallback cannot resurrect a
// revoked session. Remove the fallback once all creation paths mirror.

// secondarySessionValue is the cached {session,user} pair stored under a
// session token key. Upstream TypeScript name: { session, user } (anonymous).
type secondarySessionValue struct {
	Session types.Session `json:"session"`
	User    types.User    `json:"user"`
}

// secondarySessionRef is one active-sessions list entry. ExpiresAt is
// milliseconds since the epoch, matching upstream ActiveSessionReference.
// Upstream TypeScript name: ActiveSessionReference.
type secondarySessionRef struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expiresAt"`
}

// activeSessionsKey names the per-user live-session reference list.
// Upstream TypeScript value: `active-sessions-${userId}`.
func activeSessionsKey(userID string) string {
	return "active-sessions-" + userID
}

// secondarySessionTTL mirrors upstream getTTLSeconds
// (internal-adapter.ts:42-46): whole seconds from now until expiresAt,
// floored at zero. Non-positive means "do not store".
func secondarySessionTTL(expiresAt, now time.Time) int {
	ttl := int(expiresAt.Sub(now) / time.Second)
	if ttl < 0 {
		return 0
	}
	return ttl
}

// sessionToRow converts a session struct to a logical-key row map for the
// shared row plumbing (rowToSession, expiry math). Core columns use camelCase
// keys, which stringField/timeField accept alongside snake_case; additional
// fields ride top-level like unmapped adapter columns.
func sessionToRow(s types.Session) map[string]any {
	row := map[string]any{
		"id":        s.ID,
		"userId":    s.UserID,
		"token":     s.Token,
		"expiresAt": s.ExpiresAt,
		"createdAt": s.CreatedAt,
		"updatedAt": s.UpdatedAt,
	}
	if s.IPAddress != nil {
		row["ipAddress"] = *s.IPAddress
	}
	if s.UserAgent != nil {
		row["userAgent"] = *s.UserAgent
	}
	if s.ActiveOrganizationID != nil {
		row["activeOrganizationId"] = *s.ActiveOrganizationID
	}
	if s.ActiveTeamID != nil {
		row["activeTeamId"] = *s.ActiveTeamID
	}
	for key, value := range s.AdditionalFields {
		if _, exists := row[key]; !exists {
			row[key] = value
		}
	}
	return row
}

// userToRow converts a user struct to a logical-key row map for rowToUser.
func userToRow(u types.User) map[string]any {
	row := map[string]any{
		"id":            u.ID,
		"email":         u.Email,
		"emailVerified": u.EmailVerified,
		"name":          u.Name,
		"createdAt":     u.CreatedAt,
		"updatedAt":     u.UpdatedAt,
	}
	if u.Image != nil {
		row["image"] = *u.Image
	}
	for key, value := range u.AdditionalFields {
		if _, exists := row[key]; !exists {
			row[key] = value
		}
	}
	return row
}

// parseSecondarySessionValue decodes a secondary-storage token value into
// the cached pair, accepting JSON strings and already-parsed objects
// (upstream safeJSONParse). It returns ok false for missing, empty, or
// corrupt values and for pairs without a token.
func parseSecondarySessionValue(raw any) (*secondarySessionValue, bool) {
	if raw == nil {
		return nil, false
	}
	var data []byte
	switch v := raw.(type) {
	case string:
		if v == "" {
			return nil, false
		}
		data = []byte(v)
	case []byte:
		if len(v) == 0 {
			return nil, false
		}
		data = v
	default:
		encoded, err := json.Marshal(v)
		if err != nil {
			return nil, false
		}
		data = encoded
	}
	var value secondarySessionValue
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, false
	}
	if value.Session.Token == "" {
		return nil, false
	}
	return &value, true
}

// parseSecondarySessionRefs decodes an active-sessions list value, accepting
// JSON strings and already-parsed arrays. Corrupt entries are skipped, never
// fatal — mirroring upstream's `safeJSONParse(...) || []`.
func parseSecondarySessionRefs(raw any) []secondarySessionRef {
	if raw == nil {
		return nil
	}
	var data []byte
	switch v := raw.(type) {
	case string:
		if v == "" {
			return nil
		}
		data = []byte(v)
	case []byte:
		if len(v) == 0 {
			return nil
		}
		data = v
	default:
		encoded, err := json.Marshal(v)
		if err != nil {
			return nil
		}
		data = encoded
	}
	var flexible []struct {
		Token     string `json:"token"`
		ExpiresAt any    `json:"expiresAt"`
	}
	if err := json.Unmarshal(data, &flexible); err != nil {
		return nil
	}
	refs := make([]secondarySessionRef, 0, len(flexible))
	for _, entry := range flexible {
		if entry.Token == "" {
			continue
		}
		var expiresMs int64
		switch n := entry.ExpiresAt.(type) {
		case float64:
			expiresMs = int64(n)
		case int64:
			expiresMs = n
		case int:
			expiresMs = int64(n)
		case json.Number:
			if parsed, err := n.Int64(); err == nil {
				expiresMs = parsed
			} else {
				continue
			}
		default:
			continue
		}
		refs = append(refs, secondarySessionRef{Token: entry.Token, ExpiresAt: expiresMs})
	}
	return refs
}

// encodeSecondarySessionValue serializes the cached pair for Set.
func encodeSecondarySessionValue(session types.Session, user types.User) (string, error) {
	raw, err := json.Marshal(secondarySessionValue{Session: session, User: user})
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// findSecondarySession returns the cached pair for token, or (nil, nil) on a
// miss. Backend errors are returned for the caller to map to 500s (upstream
// throws). Upstream TypeScript name: secondaryStorage.get(token).
func findSecondarySession(opts types.Options, token string) (*secondarySessionValue, error) {
	if opts.SecondaryStorage == nil || token == "" {
		return nil, nil
	}
	raw, err := opts.SecondaryStorage.Get(token)
	if err != nil {
		return nil, err
	}
	value, ok := parseSecondarySessionValue(raw)
	if !ok {
		return nil, nil
	}
	return value, nil
}

// writeSecondarySession mirrors a session/user pair into secondary storage:
// the token key plus the sorted active-sessions list entry, TTL'd to the
// session (token key) and furthest-listed (list key) expirations. A nil
// backend is a no-op so shared creation paths can call it unconditionally.
// Expired sessions are not stored. Upstream TypeScript name:
// mirrorSessionToSecondaryStorage (internal-adapter.ts:520-564).
func writeSecondarySession(opts types.Options, session types.Session, user types.User) error {
	if opts.SecondaryStorage == nil {
		return nil
	}
	now := time.Now()
	sessionTTL := secondarySessionTTL(session.ExpiresAt, now)
	if sessionTTL <= 0 {
		return nil
	}
	nowMs := now.UnixMilli()
	refs := getSecondarySessionRefs(opts, session.UserID)
	kept := make([]secondarySessionRef, 0, len(refs)+1)
	for _, ref := range refs {
		if ref.ExpiresAt > nowMs && ref.Token != session.Token {
			kept = append(kept, ref)
		}
	}
	kept = append(kept, secondarySessionRef{Token: session.Token, ExpiresAt: session.ExpiresAt.UnixMilli()})
	sortSecondarySessionRefs(kept)
	furthestTTL := secondarySessionTTL(time.UnixMilli(kept[len(kept)-1].ExpiresAt).UTC(), now)
	if furthestTTL > 0 {
		encoded, err := json.Marshal(kept)
		if err != nil {
			return err
		}
		ttl := furthestTTL
		if err := opts.SecondaryStorage.Set(activeSessionsKey(session.UserID), string(encoded), &ttl); err != nil {
			return err
		}
	}
	encoded, err := encodeSecondarySessionValue(session, user)
	if err != nil {
		return err
	}
	ttl := sessionTTL
	return opts.SecondaryStorage.Set(session.Token, encoded, &ttl)
}

// getSecondarySessionRefs reads the live active-sessions references for a
// user (no liveness filtering here; callers compare against now).
// Upstream TypeScript name: getActiveSessionReferences.
func getSecondarySessionRefs(opts types.Options, userID string) []secondarySessionRef {
	if opts.SecondaryStorage == nil || userID == "" {
		return nil
	}
	raw, err := opts.SecondaryStorage.Get(activeSessionsKey(userID))
	if err != nil || raw == nil {
		return nil
	}
	return parseSecondarySessionRefs(raw)
}

// sortSecondarySessionRefs orders references by ascending expiration,
// mirroring upstream's `.sort((a, b) => a.expiresAt - b.expiresAt)`.
func sortSecondarySessionRefs(refs []secondarySessionRef) {
	sort.Slice(refs, func(i, j int) bool { return refs[i].ExpiresAt < refs[j].ExpiresAt })
}

// storeSecondarySessionRefs persists the reference list, deleting the key
// when no live reference remains. furthestMs selects the TTL.
func storeSecondarySessionRefs(opts types.Options, userID string, refs []secondarySessionRef, nowMs int64) error {
	key := activeSessionsKey(userID)
	if len(refs) == 0 {
		return opts.SecondaryStorage.Delete(key)
	}
	sortSecondarySessionRefs(refs)
	furthestTTL := secondarySessionTTL(time.UnixMilli(refs[len(refs)-1].ExpiresAt).UTC(), time.UnixMilli(nowMs).UTC())
	if furthestTTL <= 0 {
		return opts.SecondaryStorage.Delete(key)
	}
	encoded, err := json.Marshal(refs)
	if err != nil {
		return err
	}
	ttl := furthestTTL
	return opts.SecondaryStorage.Set(key, string(encoded), &ttl)
}

// removeSecondarySessionRef drops one token from the user's active-sessions
// list, deleting the list key when nothing live remains. It mirrors the list
// maintenance inside upstream deleteSession (internal-adapter.ts:864-895).
func removeSecondarySessionRef(opts types.Options, userID, token string) error {
	nowMs := time.Now().UnixMilli()
	refs := getSecondarySessionRefs(opts, userID)
	kept := make([]secondarySessionRef, 0, len(refs))
	for _, ref := range refs {
		if ref.ExpiresAt > nowMs && ref.Token != token {
			kept = append(kept, ref)
		}
	}
	return storeSecondarySessionRefs(opts, userID, kept, nowMs)
}

// deleteSecondarySession removes a token and its list entry from secondary
// storage, mirroring the secondary half of upstream deleteSession
// (internal-adapter.ts:850-897): a missing entry still deletes the token key
// and proceeds (upstream logs and continues).
func deleteSecondarySession(opts types.Options, token string) error {
	if opts.SecondaryStorage == nil {
		return nil
	}
	if cached, err := findSecondarySession(opts, token); err != nil {
		return err
	} else if cached != nil {
		if err := removeSecondarySessionRef(opts, cached.Session.UserID, token); err != nil {
			return err
		}
	}
	return opts.SecondaryStorage.Delete(token)
}

// listSecondarySessions returns the live cached sessions for a user,
// skipping expired, duplicated, and corrupt entries. It mirrors upstream
// listSessions' secondary branch (internal-adapter.ts:329-373).
func listSecondarySessions(opts types.Options, userID string) ([]types.Session, error) {
	nowMs := time.Now().UnixMilli()
	seen := map[string]struct{}{}
	var out []types.Session
	for _, ref := range getSecondarySessionRefs(opts, userID) {
		if ref.ExpiresAt <= nowMs {
			continue
		}
		if _, dup := seen[ref.Token]; dup {
			continue
		}
		seen[ref.Token] = struct{}{}
		cached, err := findSecondarySession(opts, ref.Token)
		if err != nil {
			return nil, err
		}
		if cached == nil {
			continue
		}
		out = append(out, cached.Session)
	}
	if out == nil {
		out = []types.Session{}
	}
	return out, nil
}

// refreshSecondarySession extends a cached session's expiration (and stamps
// updatedAt), maintaining the active-sessions entry. A miss returns
// (nil, nil): the caller falls back to the database or reports the session
// gone. It mirrors the secondary fn inside upstream updateSession
// (internal-adapter.ts:768-845) specialized to the refresh write.
func refreshSecondarySession(opts types.Options, token string, newExpiry, now time.Time) (*secondarySessionValue, error) {
	cached, err := findSecondarySession(opts, token)
	if err != nil || cached == nil {
		return cached, err
	}
	updated := &secondarySessionValue{
		Session: cached.Session,
		User:    cached.User,
	}
	updated.Session.ExpiresAt = newExpiry
	updated.Session.UpdatedAt = now
	if err := persistSecondarySessionValue(opts, token, updated, now); err != nil {
		return nil, err
	}
	return updated, nil
}

// mergeSecondarySessionFields merges additional update fields into the cached
// session (top-level merge like upstream updateSession's
// `{...parsedSession.session, ...data}`, internal-adapter.ts:782-792 —
// additional fields ride on the struct's AdditionalFields map) and persists
// the pair plus the list entry. A miss returns (nil, nil) so the route can
// expire cookies instead of re-minting from stale data.
func mergeSecondarySessionFields(opts types.Options, token string, fields map[string]any, now time.Time) (*secondarySessionValue, error) {
	cached, err := findSecondarySession(opts, token)
	if err != nil || cached == nil {
		return cached, err
	}
	updated := &secondarySessionValue{
		Session: cached.Session,
		User:    cached.User,
	}
	if updated.Session.AdditionalFields == nil && len(fields) > 0 {
		updated.Session.AdditionalFields = make(map[string]any, len(fields))
	}
	for key, value := range fields {
		updated.Session.AdditionalFields[key] = value
	}
	updated.Session.UpdatedAt = now
	if err := persistSecondarySessionValue(opts, token, updated, now); err != nil {
		return nil, err
	}
	return updated, nil
}

// persistSecondarySessionValue writes a mutated cached pair back to the token
// key and refreshes its active-sessions entry, mirroring the write-back tail
// of upstream updateSession (internal-adapter.ts:799-839).
func persistSecondarySessionValue(opts types.Options, token string, updated *secondarySessionValue, now time.Time) error {
	expiresMs := updated.Session.ExpiresAt.UnixMilli()
	sessionTTL := secondarySessionTTL(updated.Session.ExpiresAt, now)
	if sessionTTL <= 0 {
		return nil
	}
	encoded, err := encodeSecondarySessionValue(updated.Session, updated.User)
	if err != nil {
		return err
	}
	ttl := sessionTTL
	if err := opts.SecondaryStorage.Set(token, encoded, &ttl); err != nil {
		return err
	}
	nowMs := now.UnixMilli()
	refs := getSecondarySessionRefs(opts, updated.Session.UserID)
	kept := make([]secondarySessionRef, 0, len(refs)+1)
	for _, ref := range refs {
		if ref.Token != token && ref.ExpiresAt > nowMs {
			kept = append(kept, ref)
		}
	}
	kept = append(kept, secondarySessionRef{Token: token, ExpiresAt: expiresMs})
	return storeSecondarySessionRefs(opts, updated.Session.UserID, kept, nowMs)
}

// refreshSecondaryUserSessions rewrites the cached user on every live
// secondary session of the user, mirroring upstream refreshUserSessions
// (db/internal-adapter.ts:108-137), which updateUser/updateUserByEmail run
// after the commit: one Set per live token carrying {session (unchanged),
// user (new)}, TTL'd to the cached session expiry; the active-sessions list
// is untouched, so one update costs exactly one write per token. Expired
// references and missing/corrupt entries are skipped, never fatal. A nil
// backend (or empty user ID) is a no-op so update paths can call it
// unconditionally. Backend errors abort with the error for the caller to map
// (upstream surfaces them via the after-transaction hook's onError).
// Upstream TypeScript name: refreshUserSessions.
func refreshSecondaryUserSessions(opts types.Options, user types.User) error {
	if opts.SecondaryStorage == nil || user.ID == "" {
		return nil
	}
	raw, err := opts.SecondaryStorage.Get(activeSessionsKey(user.ID))
	if err != nil {
		return err
	}
	if raw == nil {
		return nil
	}
	now := time.Now()
	nowMs := now.UnixMilli()
	for _, ref := range parseSecondarySessionRefs(raw) {
		if ref.ExpiresAt <= nowMs {
			continue
		}
		cached, err := findSecondarySession(opts, ref.Token)
		if err != nil {
			return err
		}
		if cached == nil {
			continue
		}
		encoded, err := encodeSecondarySessionValue(cached.Session, user)
		if err != nil {
			return err
		}
		ttl := secondarySessionTTL(cached.Session.ExpiresAt, now)
		if err := opts.SecondaryStorage.Set(ref.Token, encoded, &ttl); err != nil {
			return err
		}
	}
	return nil
}

// secondaryAwareSessionOwner resolves the owning user ID of a session token
// across both stores, mirroring the ownership check before upstream
// deleteSession. A secondary hit wins; a miss falls back to the database
// only when rows are persisted there (StoreSessionInDatabase without
// preserve), matching the read fallback in
// loadSecondarySessionWithRefresh. Backend errors are returned for the
// caller to map to 500s.
func secondaryAwareSessionOwner(ctx context.Context, opts types.Options, token string) (string, bool, error) {
	if opts.SecondaryStorage != nil {
		cached, err := findSecondarySession(opts, token)
		if err != nil {
			return "", false, err
		}
		if cached != nil {
			return cached.Session.UserID, true, nil
		}
		if !opts.Session.StoreSessionInDatabase || opts.Session.PreserveSessionInDatabase {
			return "", false, nil
		}
	}
	if opts.DB == nil {
		return "", false, nil
	}
	row, err := opts.DB.FindOne(ctx, "session", []types.Where{
		{Field: "token", Value: token},
	}, nil)
	if err != nil || row == nil {
		return "", false, err
	}
	return stringField(row, "user_id", "userId"), true, nil
}

// endPreservedSessionRows ends (instead of deleting) the live session rows
// matched by where, mirroring upstream endPreservedSessions
// (internal-adapter.ts:91-106): matching is restricted to still-live rows so
// a repeat delete of an already-ended session matches nothing. The row's
// expiresAt is set to now so every liveness check treats it as ended, while
// the session-delete hooks still run (OAuth revocation and back-channel
// logout fire on session end) via HookedAdapter.EndPreservedSessions.
// Adapters without the primitive fall back to a plain UpdateMany (update
// hooks fire instead of delete hooks).
func endPreservedSessionRows(ctx context.Context, opts types.Options, where []types.Where) (int, error) {
	now := time.Now().UTC()
	live := append(append([]types.Where(nil), where...), types.Where{
		Field:    "expiresAt",
		Operator: types.OpGt,
		Value:    now,
	})
	endUpdate := map[string]any{
		"expiresAt": now,
		"updatedAt": now,
	}
	if h, ok := opts.DB.(interface {
		EndPreservedSessions(context.Context, string, []types.Where, map[string]any) (int, error)
	}); ok {
		return h.EndPreservedSessions(ctx, "session", live, endUpdate)
	}
	return opts.DB.UpdateMany(ctx, "session", live, endUpdate)
}

// deleteSecondaryAwareSession deletes one session by token across both
// stores per the flag matrix, mirroring upstream deleteSession
// (internal-adapter.ts:849-913): secondary entries go first, then — only
// with StoreSessionInDatabase — the database row (ended, not deleted, with
// PreserveSessionInDatabase). A nil database with persistence flags is a
// misconfiguration and surfaces as an error, never a panic.
func deleteSecondaryAwareSession(ctx context.Context, opts types.Options, token string) error {
	if opts.SecondaryStorage == nil {
		return opts.DB.Delete(ctx, "session", []types.Where{
			{Field: "token", Value: token},
		})
	}
	if err := deleteSecondarySession(opts, token); err != nil {
		return err
	}
	if !opts.Session.StoreSessionInDatabase {
		return nil
	}
	if opts.DB == nil {
		return errors.New("auth: Session.StoreSessionInDatabase requires options.DB")
	}
	if opts.Session.PreserveSessionInDatabase {
		_, err := endPreservedSessionRows(ctx, opts, []types.Where{{Field: "token", Value: token}})
		return err
	}
	return opts.DB.Delete(ctx, "session", []types.Where{
		{Field: "token", Value: token},
	})
}

// deleteSecondaryAwareUserSessions deletes every session of a user across
// both stores per the flag matrix, mirroring upstream deleteUserSessions
// (internal-adapter.ts:943-973): without database persistence only the cache
// is cleared; with preserve mode live rows are ended and the cache is
// cleared; otherwise rows are deleted and the cache is cleared.
func deleteSecondaryAwareUserSessions(ctx context.Context, opts types.Options, userID string) error {
	if opts.SecondaryStorage == nil {
		_, err := opts.DB.DeleteMany(ctx, "session", []types.Where{
			{Field: "userId", Value: userID},
		})
		return err
	}
	refs := getSecondarySessionRefs(opts, userID)
	clearCached := func() error {
		for _, ref := range refs {
			if err := opts.SecondaryStorage.Delete(ref.Token); err != nil {
				return err
			}
		}
		return opts.SecondaryStorage.Delete(activeSessionsKey(userID))
	}
	if !opts.Session.StoreSessionInDatabase {
		return clearCached()
	}
	if opts.DB == nil {
		return errors.New("auth: Session.StoreSessionInDatabase requires options.DB")
	}
	if opts.Session.PreserveSessionInDatabase {
		if _, err := endPreservedSessionRows(ctx, opts, []types.Where{{Field: "userId", Value: userID}}); err != nil {
			return err
		}
		return clearCached()
	}
	if _, err := opts.DB.DeleteMany(ctx, "session", []types.Where{
		{Field: "userId", Value: userID},
	}); err != nil {
		return err
	}
	return clearCached()
}

// loadSecondarySessionWithRefresh is the secondary-storage get-session read,
// mirroring upstream findSession (internal-adapter.ts:602-642) plus the
// route-level expiry/refresh policy in session.ts:287-344:
//
//   - A secondary hit serves the cached pair without a database round-trip
//     (the cached user is authoritative, matching upstream).
//   - A miss with StoreSessionInDatabase (and without preserve) falls back
//     to the database and backfills the entry; otherwise the session is gone
//     (upstream null). Preserve mode never falls back: revoked sessions stay
//     revoked even though their rows are kept.
//   - Expired sessions report expiry; outside read-only deferred reads the
//     expired entry is cleaned across both stores (upstream deletes via
//     deleteSession when !deferSessionRefresh || POST).
func loadSecondarySessionWithRefresh(ctx context.Context, opts types.Options, token string, cfg sessionRefreshConfig) (map[string]any, map[string]any, bool, bool, error) {
	cached, err := findSecondarySession(opts, token)
	if err != nil {
		return nil, nil, false, false, err
	}
	if cached == nil {
		if !opts.Session.StoreSessionInDatabase || opts.Session.PreserveSessionInDatabase {
			return nil, nil, false, false, errUnauthorized
		}
		if opts.DB == nil {
			// Secondary-only deployment without a database: nothing else to
			// consult.
			return nil, nil, false, false, errUnauthorized
		}
		sessionRow, userRow, refreshed, needsRefresh, derr := loadDatabaseSessionWithRefresh(ctx, opts, token, cfg)
		if derr != nil {
			return nil, nil, false, false, derr
		}
		// Read-through backfill (transitional — see the deviation note
		// above): a failing backfill must not fail the served read.
		_ = writeSecondarySession(opts, rowToSession(sessionRow, opts), rowToUser(userRow, opts))
		return sessionRow, userRow, refreshed, needsRefresh, nil
	}
	now := time.Now().UTC()
	if cached.Session.ExpiresAt.IsZero() || !now.Before(cached.Session.ExpiresAt) {
		if !cfg.readOnly {
			// Best-effort expired cleanup across both stores; a failing
			// cleanup must not mask the expiry itself.
			_ = deleteSecondaryAwareSession(ctx, opts, token)
		}
		return nil, nil, false, false, errSessionExpired
	}
	if cfg.readOnly {
		sessionRow, userRow := sessionToRow(cached.Session), userToRow(cached.User)
		var needsRefresh bool
		if !state.GetShouldSkipSessionRefresh(ctx) {
			needsRefresh = sessionRefreshDue(sessionRow, opts, cfg.disableRefresh, now)
		}
		return sessionRow, userRow, false, needsRefresh, nil
	}
	if state.GetShouldSkipSessionRefresh(ctx) || opts.Session.DisableSessionRefresh || cfg.disableRefresh || cfg.dontRememberMe {
		return sessionToRow(cached.Session), userToRow(cached.User), false, false, nil
	}
	expiresIn := opts.Session.ExpiresInDuration()
	updateAge := sessionUpdateAge(opts.Session)
	refreshAt := cached.Session.ExpiresAt.Add(-expiresIn).Add(updateAge)
	if now.Before(refreshAt) {
		return sessionToRow(cached.Session), userToRow(cached.User), false, false, nil
	}
	newExpiry := now.Add(expiresIn)
	updated, uerr := refreshSecondarySession(opts, token, newExpiry, now)
	if uerr != nil || updated == nil {
		// Tolerant like the database path: serve unextended on write failure.
		return sessionToRow(cached.Session), userToRow(cached.User), false, false, nil
	}
	if opts.Session.StoreSessionInDatabase {
		// Mirror the extension into the database row; a transitional miss
		// (nil row) is tolerated, real errors fail the refresh loudly below
		// via the served-but-unextended contract — keep tolerant: ignore.
		updatedRow, derr := opts.DB.Update(ctx, "session", []types.Where{
			{Field: "token", Value: token},
		}, map[string]any{
			"expiresAt": newExpiry,
			"updatedAt": now,
		})
		if derr == nil && updatedRow != nil {
			return updatedRow, userToRow(updated.User), true, false, nil
		}
	}
	return sessionToRow(updated.Session), userToRow(updated.User), true, false, nil
}

// Merged from session-extra.go (revoke variants + UpdateSession; upstream session.ts + update-session.ts). Same package, no behavior change (B8).

type revokeSessionsInput struct {
	Authorization string `header:"Authorization"`
	Cookie        string `header:"Cookie"`
	CookieRequestHeaders
}

type revokeSessionsOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      struct {
		Status bool `json:"status"`
	}
}

// RevokeSessions registers POST /revoke-sessions.
func RevokeSessions(api huma.API, basePath string, opts types.Options) {
	registerAuthOperation(api, huma.Operation{
		Tags:        []string{"Auth"},
		Method:      http.MethodPost,
		Path:        basePath + "/revoke-sessions",
		OperationID: "revokeSessions",
		Summary:     "Revoke all sessions for the current user",
	}, opts, func(ctx context.Context, input *revokeSessionsInput) (*revokeSessionsOutput, error) {
		token := sessionTokenFromRequest(input.Cookie, input.Authorization, opts)
		if token == "" {
			return nil, huma.NewError(types.StatusForCode(types.ErrFailedToGetSession), types.ErrFailedToGetSession)
		}

		sessionRow, _, _, err := loadSessionAndUser(ctx, opts, token)
		if err != nil {
			if errors.Is(err, errSessionExpired) {
				// Kept 401 (differs from StatusForCode 400): expired-session auth
				// guard, matching upstream's 401-for-auth-failures convention; see
				// the note in ChangePassword (password.go).
				return nil, huma.Error401Unauthorized(types.ErrSessionExpired)
			}
			return nil, huma.NewError(types.StatusForCode(types.ErrFailedToGetSession), types.ErrFailedToGetSession)
		}

		// Secondary-aware bulk revoke (upstream deleteUserSessions): cache
		// entries go first per the flag matrix; database rows are deleted —
		// or ended with preserve mode — only when persisted. Backend errors
		// are operational failures (500), as before.
		if err := deleteSecondaryAwareUserSessions(ctx, opts, stringField(sessionRow, "user_id", "userId")); err != nil {
			// Kept 500 (differs from StatusForCode 401 for FAILED_TO_GET_SESSION):
			// adapter/cookie failure while revoking or updating sessions, not a
			// semantic session-lookup failure.
			return nil, huma.Error500InternalServerError(types.ErrFailedToGetSession)
		}

		out := &revokeSessionsOutput{}
		// The current session is gone, so expire the session cookies outright
		// with request context (Secure/Domain + chunk-aware session_data
		// cleanup, upstream deleteSessionCookie clean()).
		out.SetCookie = expiredSessionCookiesWithContext(ctx, opts, input.CookieRequestHeaders, input.Cookie)
		out.Body.Status = true
		return out, nil
	})
}

type revokeOtherSessionsInput struct {
	Authorization string `header:"Authorization"`
	Cookie        string `header:"Cookie"`
	CookieRequestHeaders
}

type revokeOtherSessionsOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      struct {
		Status bool `json:"status"`
	}
}

// RevokeOtherSessions registers POST /revoke-other-sessions.
func RevokeOtherSessions(api huma.API, basePath string, opts types.Options) {
	registerAuthOperation(api, huma.Operation{
		Tags:        []string{"Auth"},
		Method:      http.MethodPost,
		Path:        basePath + "/revoke-other-sessions",
		OperationID: "revokeOtherSessions",
		Summary:     "Revoke all other sessions for the current user",
	}, opts, func(ctx context.Context, input *revokeOtherSessionsInput) (*revokeOtherSessionsOutput, error) {
		token := sessionTokenFromRequest(input.Cookie, input.Authorization, opts)
		if token == "" {
			return nil, huma.NewError(types.StatusForCode(types.ErrFailedToGetSession), types.ErrFailedToGetSession)
		}

		sessionRow, _, _, err := loadSessionAndUser(ctx, opts, token)
		if err != nil {
			if errors.Is(err, errSessionExpired) {
				// Kept 401 (differs from StatusForCode 400): expired-session auth
				// guard, matching upstream's 401-for-auth-failures convention; see
				// the note in ChangePassword (password.go).
				return nil, huma.Error401Unauthorized(types.ErrSessionExpired)
			}
			return nil, huma.NewError(types.StatusForCode(types.ErrFailedToGetSession), types.ErrFailedToGetSession)
		}

		userID := stringField(sessionRow, "user_id", "userId")
		// Live-only others (upstream session.ts:853-870): listSessions then
		// filter expiresAt > now, excluding the current token. Expired rows
		// survive; no cookies are written on this path.
		now := time.Now().UTC()
		var otherTokens []string
		if opts.SecondaryStorage != nil {
			nowMs := now.UnixMilli()
			refs := getSecondarySessionRefs(opts, userID)
			otherTokens = make([]string, 0, len(refs))
			for _, ref := range refs {
				if ref.Token != token && ref.Token != "" && ref.ExpiresAt > nowMs {
					otherTokens = append(otherTokens, ref.Token)
				}
			}
		} else {
			rows, ferr := opts.DB.FindMany(ctx, "session", []types.Where{
				{Field: "userId", Value: userID},
			}, 0, 0, nil, nil)
			if ferr != nil {
				// Kept 500 (differs from StatusForCode 401 for FAILED_TO_GET_SESSION):
				// adapter/cookie failure while revoking or updating sessions, not a
				// semantic session-lookup failure.
				return nil, huma.Error500InternalServerError(types.ErrFailedToGetSession)
			}
			otherTokens = make([]string, 0, len(rows))
			for _, row := range rows {
				target := stringField(row, "token")
				if target == "" || target == token {
					continue
				}
				if exp := sessionExpiresAt(row); exp.IsZero() || !exp.After(now) {
					continue
				}
				otherTokens = append(otherTokens, target)
			}
		}

		for _, other := range otherTokens {
			if err := deleteSecondaryAwareSession(ctx, opts, other); err != nil {
				// Kept 500 (differs from StatusForCode 401 for FAILED_TO_GET_SESSION):
				// adapter/cookie failure while revoking or updating sessions, not a
				// semantic session-lookup failure.
				return nil, huma.Error500InternalServerError(types.ErrFailedToGetSession)
			}
		}

		out := &revokeOtherSessionsOutput{}
		out.Body.Status = true
		return out, nil
	})
}

type updateSessionInput struct {
	Authorization string `header:"Authorization"`
	Cookie        string `header:"Cookie"`
	CookieRequestHeaders
	Body map[string]any
}

type updateSessionOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      struct {
		Session flatSession `json:"session"`
	}
}

// flatSession serializes a types.Session the way upstream parseSessionOutput
// does: additional fields merge flat onto the session object instead of
// nesting under "additionalFields" (precedent: flatUser in sign-up.go).
// types.Session keeps the nested Go shape; only the update-session JSON
// boundary flattens, so get-session/list-sessions shapes are untouched.
type flatSession types.Session

// MarshalJSON implements json.Marshaler.
func (s flatSession) MarshalJSON() ([]byte, error) {
	out := map[string]any{
		"id":        s.ID,
		"userId":    s.UserID,
		"token":     s.Token,
		"expiresAt": s.ExpiresAt,
		"createdAt": s.CreatedAt,
		"updatedAt": s.UpdatedAt,
	}
	if s.IPAddress != nil {
		out["ipAddress"] = *s.IPAddress
	}
	if s.UserAgent != nil {
		out["userAgent"] = *s.UserAgent
	}
	if s.ActiveOrganizationID != nil {
		out["activeOrganizationId"] = *s.ActiveOrganizationID
	}
	if s.ActiveTeamID != nil {
		out["activeTeamId"] = *s.ActiveTeamID
	}
	for k, v := range s.AdditionalFields {
		out[k] = v
	}
	return json.Marshal(out)
}

// sessionUpdateFields validates an update-session body against the full
// session schema (upstream update-session.ts:64-74,
// session-api.test.ts:2509-2518): unknown keys are dropped by
// FilterSessionUpdateFieldsFull per parseSessionInput, so unknown-only (and
// empty/core-only) bodies 400 with "No fields to update". Declared
// additionalFields still pass through.
//
// B2 (upstream parity): unknown-only-update bodies 400; truly-unknown keys
// never reach the store.
func sessionUpdateFields(body map[string]any, opts types.Options) (map[string]any, error) {
	if body == nil {
		return nil, huma.NewError(types.StatusForCode(types.ErrBodyMustBeAnObject), types.ErrBodyMustBeAnObject)
	}
	// Full-schema update fields (upstream parseSessionInput): known fields
	// get upstream update semantics (input:false rejection, validator and
	// transform input hooks); unknown keys are dropped, so unknown-only
	// bodies yield no fields and 400 below.
	additionalFields, ferr := FilterSessionUpdateFieldsFull(body, fullSessionFields(opts))
	if ferr != nil {
		var parseErr *FieldParseError
		if errors.As(ferr, &parseErr) {
			return nil, huma.NewError(types.StatusForCode(parseErr.Code), parseErr.Code)
		}
		// Transform failures propagate raw upstream; surface them as a
		// 500 like the other adapter/cookie failures in this handler.
		return nil, huma.Error500InternalServerError(ferr.Error())
	}
	if len(additionalFields) == 0 {
		return nil, huma.Error400BadRequest("No fields to update")
	}
	return additionalFields, nil
}

// UpdateSession registers POST /update-session.
func UpdateSession(api huma.API, basePath string, opts types.Options) {
	registerAuthOperation(api, huma.Operation{
		Tags:        []string{"Auth"},
		Method:      http.MethodPost,
		Path:        basePath + "/update-session",
		OperationID: "updateSession",
		Summary:     "Update the current session",
	}, opts, func(ctx context.Context, input *updateSessionInput) (*updateSessionOutput, error) {
		token := sessionTokenFromRequest(input.Cookie, input.Authorization, opts)
		if token == "" {
			return nil, huma.NewError(types.StatusForCode(types.ErrFailedToGetSession), types.ErrFailedToGetSession)
		}

		// Stateless (DB-less) deployments keep the session in the signed
		// cookie cache only (upstream update-session.ts !isStateful branch):
		// the cached pair is the record, so the update merges into it and
		// re-issues the cookies. A missing or unverifiable cache fails
		// closed like a revoked session.
		if !isStatefulSessionStore(opts) {
			return updateSessionStateless(ctx, input, opts, token)
		}

		_, userRow, _, err := loadSessionAndUser(ctx, opts, token)
		if err != nil {
			if errors.Is(err, errSessionExpired) {
				// Kept 401 (differs from StatusForCode 400): expired-session auth
				// guard, matching upstream's 401-for-auth-failures convention; see
				// the note in ChangePassword (password.go).
				return nil, huma.Error401Unauthorized(types.ErrSessionExpired)
			}
			return nil, huma.NewError(types.StatusForCode(types.ErrFailedToGetSession), types.ErrFailedToGetSession)
		}

		additionalFields, ferr := sessionUpdateFields(input.Body, opts)
		if ferr != nil {
			return nil, ferr
		}

		now := time.Now().UTC()
		// Secondary-storage update (upstream updateSession secondary fn):
		// merge into the cached pair and the list entry; a miss expires
		// cookies instead of re-minting from stale data. The database row is
		// mirrored only when sessions are persisted there.
		if opts.SecondaryStorage != nil {
			updated, uerr := mergeSecondarySessionFields(opts, token, additionalFields, now)
			if uerr != nil {
				// Kept 500 (differs from StatusForCode 401 for
				// FAILED_TO_GET_SESSION): backend failure while updating.
				return nil, huma.Error500InternalServerError(types.ErrFailedToGetSession)
			}
			if updated == nil {
				out := &updateSessionOutput{}
				out.SetCookie = expiredSessionCookiesWithContext(ctx, opts, input.CookieRequestHeaders, input.Cookie)
				return nil, huma.NewError(types.StatusForCode(types.ErrFailedToGetSession), types.ErrFailedToGetSession)
			}
			if opts.Session.StoreSessionInDatabase {
				update := make(map[string]any, len(additionalFields)+1)
				for key, value := range additionalFields {
					update[key] = value
				}
				update["updatedAt"] = now
				if _, derr := opts.DB.Update(ctx, "session", []types.Where{
					{Field: "token", Value: token},
				}, update); derr != nil {
					return nil, huma.Error500InternalServerError(types.ErrFailedToGetSession)
				}
			}
			cookiesOut, cookieErr := issueSessionCookiesWithContext(ctx, opts, headersWithStoredRequest(ctx, input.CookieRequestHeaders), token, updated.Session, rowToUser(userRow, opts), opts.Session, now, false)
			if cookieErr != nil {
				// Kept 500 (differs from StatusForCode 401 for FAILED_TO_GET_SESSION):
				// adapter/cookie failure while revoking or updating sessions, not a
				// semantic session-lookup failure.
				return nil, huma.Error500InternalServerError(types.ErrFailedToGetSession)
			}
			out := &updateSessionOutput{}
			out.SetCookie = cookiesOut
			out.Body.Session = flatSession(updated.Session)
			return out, nil
		}

		update := make(map[string]any, len(additionalFields)+1)
		for key, value := range additionalFields {
			update[key] = value
		}
		update["updatedAt"] = now

		updatedRow, err := opts.DB.Update(ctx, "session", []types.Where{
			{Field: "token", Value: token},
		}, update)
		if err != nil {
			// Kept 500 (differs from StatusForCode 401 for FAILED_TO_GET_SESSION):
			// adapter/cookie failure while revoking or updating sessions, not a
			// semantic session-lookup failure.
			return nil, huma.Error500InternalServerError(types.ErrFailedToGetSession)
		}
		if updatedRow == nil {
			// A durable session that vanished server-side was revoked or
			// expired; fail closed instead of re-minting from stale data.
			out := &updateSessionOutput{}
			out.SetCookie = expiredSessionCookiesWithContext(ctx, opts, input.CookieRequestHeaders, input.Cookie)
			return nil, huma.NewError(types.StatusForCode(types.ErrFailedToGetSession), types.ErrFailedToGetSession)
		}

		session := rowToSession(updatedRow, opts)
		cookiesOut, cookieErr := issueSessionCookiesWithContext(ctx, opts, headersWithStoredRequest(ctx, input.CookieRequestHeaders), token, session, rowToUser(userRow, opts), opts.Session, now, false)
		if cookieErr != nil {
			// Kept 500 (differs from StatusForCode 401 for FAILED_TO_GET_SESSION):
			// adapter/cookie failure while revoking or updating sessions, not a
			// semantic session-lookup failure.
			return nil, huma.Error500InternalServerError(types.ErrFailedToGetSession)
		}

		out := &updateSessionOutput{}
		out.SetCookie = cookiesOut
		out.Body.Session = flatSession(session)
		return out, nil
	})
}

// updateSessionStateless serves POST /update-session for DB-less deployments,
// where the signed cookie cache is the session record (upstream
// update-session.ts `updatedSession ?? {...session.session, ...fields}` fall
// back under !isStateful). The cached pair authenticates (a missing or
// unverifiable cache fails closed with expired cookies), the validated fields
// merge over it, and the issuance set refreshes the cookies.
func updateSessionStateless(ctx context.Context, input *updateSessionInput, opts types.Options, token string) (*updateSessionOutput, error) {
	cached, ok := cachedSessionFromRequestFull(ctx, input.Cookie, opts.AllSecrets(), token, opts)
	if !ok || cached == nil {
		out := &updateSessionOutput{}
		out.SetCookie = expiredSessionCookiesWithContext(ctx, opts, input.CookieRequestHeaders, input.Cookie)
		return nil, huma.NewError(types.StatusForCode(types.ErrFailedToGetSession), types.ErrFailedToGetSession)
	}

	additionalFields, ferr := sessionUpdateFields(input.Body, opts)
	if ferr != nil {
		return nil, ferr
	}

	now := time.Now().UTC()
	merged := cached.Session
	if merged.AdditionalFields == nil {
		merged.AdditionalFields = make(map[string]any, len(additionalFields))
	}
	for key, value := range additionalFields {
		merged.AdditionalFields[key] = value
	}
	merged.UpdatedAt = now

	cookiesOut, cookieErr := issueSessionCookiesWithContext(ctx, opts, headersWithStoredRequest(ctx, input.CookieRequestHeaders), token, merged, cached.User, opts.Session, now, false)
	if cookieErr != nil {
		// Kept 500 (differs from StatusForCode 401 for FAILED_TO_GET_SESSION):
		// cookie failure while updating, not a semantic lookup failure.
		return nil, huma.Error500InternalServerError(types.ErrFailedToGetSession)
	}

	out := &updateSessionOutput{}
	out.SetCookie = cookiesOut
	out.Body.Session = flatSession(merged)
	return out, nil
}

// Merged from session-c701.go (cookie-cache issuance/refresh; upstream session.ts + cookies/*). Same package, no behavior change (B8).

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

// sessionDataCookieAttributes maps the request-aware session_data config plus
// the computed cache expiry to cookie Attributes for chunked issuance.
// Sizing budgets derive from Attributes.Serialize (upstream serializeCookie),
// never ToHTTPCookie.String(). Wire preserves the legacy issuance shape:
// Path "/", HttpOnly, SameSite Lax with Domain/Secure from the request-aware
// config (matching the pre-chunk single-cookie wire).
func sessionDataCookieAttributes(cfg resolvedSessionCookieConfig, expiresAt time.Time) cookies.Attributes {
	maxAgeSecs := int(time.Until(expiresAt).Seconds())
	if maxAgeSecs < 0 {
		maxAgeSecs = 0
	}
	return cookies.Attributes{
		Path:       "/",
		Domain:     cfg.Domain,
		Secure:     cfg.Secure,
		HttpOnly:   true,
		SameSite:   http.SameSiteLaxMode,
		Expires:    expiresAt,
		ExpiresSet: true,
		MaxAge:     maxAgeSecs,
		MaxAgeSet:  true,
	}
}

// mintSessionDataValueWithContext mints the raw session_data cache value with
// request-aware naming/attributes and the custom JWKS signer when present
// (upstream setCookieCache jwt branch with cookieCacheSigner, including key
// rotation via the plugin's live keys, typ/kid/aud/iss/sub/sid claim
// binding, and authoritative fallback on any failure).
//
// It returns the value plus the wire name and Attributes for chunked issuance
// via cookies.BuildChunkedCookies (upstream session-store chunkCookie with
// <name>.<i> naming). Sizing uses Attributes.Serialize through
// MaxValueSizeFor, matching upstream serializeCookie.
func mintSessionDataValueWithContext(ctx context.Context, opts types.Options, session types.Session, user types.User, sessionOpts types.SessionOptions, now time.Time, dontRememberMe bool) (string, string, cookies.Attributes, error) {
	version, err := resolveCookieCacheVersion(session, user, sessionOpts)
	if err != nil {
		return "", "", cookies.Attributes{}, err
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
				return "", "", cookies.Attributes{}, cerr
			}
			value = custom
		} else {
			sm, err := cacheStructMap(session)
			if err != nil {
				return "", "", cookies.Attributes{}, err
			}
			um, err := cacheStructMap(user)
			if err != nil {
				return "", "", cookies.Attributes{}, err
			}
			filterCookieCacheMaps(sm, um, opts, sessionOpts)
			value, err = cookies.CreateSessionCacheJWT(opts.CurrentSecret(), sm, um, version, time.Until(expiresAt))
			if err != nil {
				return "", "", cookies.Attributes{}, err
			}
		}
	} else if strategy == cookies.StrategyJWE {
		sm, err := cacheStructMap(session)
		if err != nil {
			return "", "", cookies.Attributes{}, err
		}
		um, err := cacheStructMap(user)
		if err != nil {
			return "", "", cookies.Attributes{}, err
		}
		filterCookieCacheMaps(sm, um, opts, sessionOpts)
		value, err = cookies.CreateSessionCacheJWE(opts.CurrentSecret(), sm, um, version, time.Until(expiresAt))
		if err != nil {
			return "", "", cookies.Attributes{}, err
		}
	} else {
		// Compact uses the upstream base64url+HMAC envelope via
		// newSessionDataCookie (cookies.CreateCompactCookieCache, so Go values
		// verify upstream and TS-issued values hit); route callers pass the
		// current secret (rotation reads accept older secrets). Session/user
		// were filtered for returned:false above, so the delegated issuance
		// carries a clean payload. Legacy signed-envelope reads stay as a
		// fallback in compactCachePayload.
		single, err := newSessionDataCookie(opts.CurrentSecret(), session, user, opts, sessionOpts, now, dontRememberMe)
		if err != nil {
			return "", "", cookies.Attributes{}, err
		}
		value = single.Value
	}
	// JWT/JWE issuance keeps the legacy wire name for compatibility (reads
	// recover upstream/custom names + chunks); compact always keeps it.
	// Only re-attribute Domain/Secure from the request-aware config.
	name := sessionDataCookieName
	cfg := resolveSessionDataCookieConfigWithContext(ctx, opts, CookieRequestHeaders{})
	if strategy != cookies.StrategyCompact {
		if override, ok := opts.Advanced.Cookies[sessionDataCookieBase]; ok && override.Name != "" {
			name = cfg.Name
		}
	}
	attrs := sessionDataCookieAttributes(cfg, expiresAt)
	// Compact keeps the legacy wire name; Domain/Secure already in attrs.
	return value, name, attrs, nil
}

// newSessionDataCookiesWithContext mints the session_data cache as one or more
// Set-Cookie entries via cookies.BuildChunkedCookies (upstream chunkCookie,
// session-store.ts:84-131, with <name>.<i> naming). Values fitting the
// Serialize-sized budget emit a single cookie under the bare name; larger
// values split into indexed chunks. A >100-chunk overflow warns and errors so
// callers serve authoritative with no cache (upstream warn-and-skip).
func newSessionDataCookiesWithContext(ctx context.Context, opts types.Options, session types.Session, user types.User, sessionOpts types.SessionOptions, now time.Time, dontRememberMe bool) ([]http.Cookie, error) {
	value, name, attrs, err := mintSessionDataValueWithContext(ctx, opts, session, user, sessionOpts, now, dontRememberMe)
	if err != nil {
		return nil, err
	}
	chunked, err := cookies.BuildChunkedCookies(name, value, attrs)
	if err != nil {
		Logf(opts, "warn", "session_data too large to store even after chunking; skipping cookie cache")
		return nil, err
	}
	out := make([]http.Cookie, 0, len(chunked))
	for _, c := range chunked {
		out = append(out, *c)
	}
	return out, nil
}

// newSessionDataCookieWithContext mints the session_data cache cookie with
// request-aware naming/attributes and the custom JWKS signer when present
// (upstream setCookieCache jwt branch with cookieCacheSigner, including key
// rotation via the plugin's live keys, typ/kid/aud/iss/sub/sid claim
// binding, and authoritative fallback on any failure).
//
// Chunked issuance lives in newSessionDataCookiesWithContext; this
// single-cookie wrapper preserves the legacy call shape (session.go readOnly
// path, filter tests) for values fitting one cookie. Values requiring
// chunking error so callers fall back to the plural helper or serve
// authoritative with no cache.
func newSessionDataCookieWithContext(ctx context.Context, opts types.Options, session types.Session, user types.User, sessionOpts types.SessionOptions, now time.Time, dontRememberMe bool) (http.Cookie, error) {
	all, err := newSessionDataCookiesWithContext(ctx, opts, session, user, sessionOpts, now, dontRememberMe)
	if err != nil {
		return http.Cookie{}, err
	}
	if len(all) == 1 {
		return all[0], nil
	}
	return http.Cookie{}, fmt.Errorf("auth: session_data requires %d chunked cookies; use newSessionDataCookiesWithContext", len(all))
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
		value, name, attrs, merr := mintSessionDataValueWithContext(ctx, authOpts, session, user, sessionOpts, now, dontRememberMe)
		if merr != nil {
			return nil, merr
		}
		chunked, cerr := cookies.BuildChunkedCookies(name, value, attrs)
		if cerr != nil {
			// Upstream warn-and-skip (session-store.ts:106-112): the value
			// cannot fit even after chunking (>100 chunks), so serve
			// authoritative with no cache.
			Logf(authOpts, "warn", "session_data too large to store even after chunking; skipping cookie cache")
			return out, nil
		}
		for _, c := range chunked {
			out = append(out, *c)
		}
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
		// Chunk enumeration lives in cookies.ExpiredChunks (upstream clean()):
		// expire the bare name plus every "<name>.<index>" chunk present so a
		// shrunken cache cannot leave stale chunks behind. Results map to the
		// route wire shape (MaxAge -1 + epoch, pinned by stalecache tests).
		if cookieHeader != "" {
			parsed := cookies.ParseRequestCookies(cookieHeader)
			attrs := cookies.Attributes{Path: "/", Domain: dataCfg.Domain, Secure: dataCfg.Secure, HttpOnly: true, SameSite: http.SameSiteLaxMode}
			seen := map[string]struct{}{dataCfg.Name: {}}
			for _, candidate := range sessionDataCookieLookupNames(authOpts) {
				for _, expired := range cookies.ExpiredChunks(parsed, candidate, attrs) {
					if _, dup := seen[expired.Name]; dup {
						continue
					}
					seen[expired.Name] = struct{}{}
					chunk := base
					chunk.Name = expired.Name
					out = append(out, chunk)
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
		attrs := cookies.Attributes{Path: "/", Domain: dataCfg.Domain, Secure: dataCfg.Secure, HttpOnly: true, SameSite: http.SameSiteLaxMode}
		// Single enumeration via cookies.ExpiredChunks (upstream clean()).
		for _, candidate := range sessionDataCookieLookupNames(opts) {
			for _, expired := range cookies.ExpiredChunks(parsed, candidate, attrs) {
				if _, dup := seen[expired.Name]; dup {
					continue
				}
				seen[expired.Name] = struct{}{}
				out = append(out, expire(expired.Name))
			}
		}
	}
	return out
}

// maybeRefreshCookieCacheWithContext re-issues the stateless cache with
// request context (same threshold/ShouldRefresh gates as
// maybeRefreshCookieCache, plus the per-request shouldSkipSessionRefresh
// gate per upstream session.ts:201-204,342-344).
func maybeRefreshCookieCacheWithContext(ctx context.Context, authOpts types.Options, headers CookieRequestHeaders, token string, payload *sessionCookieCachePayload, now time.Time, dontRememberMe bool) []http.Cookie {
	if state.GetShouldSkipSessionRefresh(ctx) {
		return nil
	}
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
