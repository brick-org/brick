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

	"github.com/brick-org/brick/auth/src/cookies"
	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
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

type getSessionOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	// Upstream pins cache-control: no-store + pragma: no-cache on the
	// get-session response (session.ts:72-73) so session reads are never
	// cached by intermediaries.
	CacheControl string `header:"Cache-Control"`
	Pragma       string `header:"Pragma"`
	Body         struct {
		User    types.User    `json:"user"`
		Session types.Session `json:"session"`
		// NeedsRefresh is set only on deferred GET reads (DeferSessionRefresh
		// without POST): the database is never written, so the refresh need
		// is reported for the client to act on (upstream session.ts:350-365).
		NeedsRefresh *bool `json:"needsRefresh,omitempty"`
	}
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
		out.Body.User = res.user
		out.Body.Session = res.session
		out.Body.NeedsRefresh = res.needsRefresh
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
// HELD (merge-owner sign-off; upstream session.ts:94-112,287-303 returns 200
// null for missing/expired sessions while Go fails closed with 401/400 per
// the pinned SCOPE.md deviation): null-shape behavior is unchanged here;
// only the stale-cleanup cookie emission on failure changed (P05-GAP-1).
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
			return &getSessionResult{
				session: cached.Session,
				user:    cached.User,
				cookies: maybeRefreshCookieCacheWithContext(ctx, opts, headers, req.token, cached, now, req.dontRememberMe),
			}, nil
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
		failed := &getSessionResult{cookies: staleCleanup}
		switch {
		case errors.Is(err, errSessionExpired):
			return failed, sessionRouteError(types.ErrSessionExpired)
		case errors.Is(err, errUnauthorized):
			return failed, sessionRouteError(types.ErrFailedToGetSession)
		case errors.Is(err, errUserMissing):
			return failed, sessionRouteError(types.ErrUserNotFound)
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
// HELD (merge-owner sign-off; upstream session.ts:94-112,287-303 returns 200
// null for missing/expired sessions while Go fails closed with 401/400 per
// the pinned SCOPE.md deviation): null-shape behavior is unchanged here.
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
		needsRefresh = sessionRefreshDue(sessionRow, opts, cfg.disableRefresh, now)
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
	// just never extended.
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

// sessionUpdateAgeFromPtr implements the upstream updateAge tri-state
// (session.ts:324-344; update-session.ts; session-api.test.ts:252-273):
// nil (unset) => 24h default, explicit 0 => always-refresh (0 duration),
// >0 => seconds. types.SessionOptions.UpdateAge is migrating int -> *int
// under a concurrent owner; this helper pins the *int contract so the merge
// owner only rewires the call sites to pass the pointer directly.
func sessionUpdateAgeFromPtr(updateAge *int) time.Duration {
	if updateAge == nil {
		return 24 * time.Hour
	}
	if *updateAge == 0 {
		return 0
	}
	return time.Duration(*updateAge) * time.Second
}

func sessionUpdateAge(opts types.SessionOptions) time.Duration {
	// Tri-state bridge while types.SessionOptions.UpdateAge is still int:
	// explicit 0 maps to always-refresh (0) per upstream. The unset default
	// (24h) is covered by sessionUpdateAgeFromPtr(nil); once types lands
	// *int, this wrapper becomes sessionUpdateAgeFromPtr(opts.UpdateAge).
	if opts.UpdateAge == 0 {
		return 0
	}
	return time.Duration(opts.UpdateAge) * time.Second
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
	// compact keeps the Go signed-envelope codec; jwt issues an HS256 JWT
	// and jwe a dir/A256CBC-HS512 JWE via the cookies package.
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
		payload, err := json.Marshal(sessionCookieCachePayload{
			Session:   session,
			User:      user,
			ExpiresAt: expiresAt,
			Version:   version,
		})
		if err != nil {
			return http.Cookie{}, err
		}
		encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
		value, err = cookies.Sign(secret, encodedPayload)
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
		cookiesOut = append(cookiesOut, cacheCookie)
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
	// "1", matching upstream's `session.version || "1"`. Unlike upstream
	// (whose rejected version promise 500s via the endpoint catch-all), a
	// failing VersionFunc fails closed to the authoritative database read
	// instead of erroring: the served data stays fresh, only slower.
	if expected, verr := resolveCookieCacheVersion(payload.Session, payload.User, opts); verr != nil || normalizeCookieCacheVersion(payload.Version) != expected {
		return nil, false
	}
	return payload, true
}

// compactCachePayload decodes the compact outer envelope: signed value,
// base64url JSON, then the typed payload. Signature verification comes
// first; the typed unmarshal alone is not a shape check (it silently coerces
// e.g. null `emailVerified` to `false`), so the decoded bytes are also
// validated as raw maps against the shared cookie-cache contract
// (upstream parseCookieCachePayload, cookies/cache.ts:20-39). A
// schema-invalid payload surfaces the shared sentinel — callers must treat
// it as a miss (Logf-warn through the configured logger + fall through to
// the database, never throw), exactly like the codec-level verdict.
func compactCachePayload(value string, secrets []string) (*sessionCookieCachePayload, error) {
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

// sessionRouteError maps an auth error code to its canonical upstream HTTP
// status (types.StatusForCode), keeping session-route errors pinned to the
// better-auth contract instead of hand-picked Huma constructors.
//
// Adjudicated divergences (upstream pins only {code,message} per key; the
// status varies by throw site, see types.StatusForCode):
//   - SESSION_EXPIRED resolves to 400: its sole upstream throw site is
//     BAD_REQUEST (update-user.ts:543). get-session itself returns null for
//     expired sessions; this port surfaces an error instead, so the code's
//     canonical 400 applies (previously 401 here).
//   - FAILED_TO_GET_SESSION resolves to 401, matching the UNAUTHORIZED
//     throw sites (session.ts:381-384, update-session.ts:88-93). Internal
//     failures carrying the same code upstream (session.ts:427-435,
//     update-user.ts:290-297, both INTERNAL_SERVER_ERROR) keep an explicit
//     500 via sessionInternalError below — StatusForCode must not launder
//     them into 401s.
//   - USER_NOT_FOUND resolves to 404 (majority throw-site status). Upstream
//     findSession returns null when the user row is missing; this port
//     surfaces an error instead, so the canonical 404 applies (previously
//     401 here).
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
//     (only the server-side shouldSkipSessionRefresh flag does, which has no
//     Go equivalent); ShouldRefresh is the per-session gate here.
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
		return sessionRow, userRow, false, sessionRefreshDue(sessionRow, opts, cfg.disableRefresh, now), nil
	}
	if opts.Session.DisableSessionRefresh || cfg.disableRefresh || cfg.dontRememberMe {
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
