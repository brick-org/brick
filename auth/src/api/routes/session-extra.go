package routes

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
)

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
