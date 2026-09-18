package routes

import (
	"context"
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

		sessionRow, userRow, refreshed, err := loadSessionAndUser(ctx, opts, token)
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
		// Tokens to revoke: secondary references when a secondary backend is
		// configured (upstream deleteSessions over the cached set), else the
		// database rows. Listing errors are operational failures (500).
		var otherTokens []string
		if opts.SecondaryStorage != nil {
			refs := getSecondarySessionRefs(opts, userID)
			otherTokens = make([]string, 0, len(refs))
			for _, ref := range refs {
				if ref.Token != token {
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
				if target := stringField(row, "token"); target != "" && target != token {
					otherTokens = append(otherTokens, target)
				}
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
		if refreshed {
			headers := headersWithStoredRequest(ctx, input.CookieRequestHeaders)
			cookiesOut, cookieErr := issueSessionCookiesWithContext(ctx, opts, headers, token, rowToSession(sessionRow, opts), rowToUser(userRow, opts), opts.Session, time.Now().UTC(), false)
			if cookieErr == nil {
				out.SetCookie = cookiesOut
			}
		}
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
		Session types.Session `json:"session"`
	}
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

		if input.Body == nil {
			return nil, huma.NewError(types.StatusForCode(types.ErrBodyMustBeAnObject), types.ErrBodyMustBeAnObject)
		}
		// Full-schema update fields (union semantics): known fields get
		// upstream update semantics (input:false rejection, validator and
		// transform input hooks); fields unknown to the full schema keep
		// the legacy passthrough so previously accepted bodies are never
		// newly rejected.
		additionalFields, ferr := FilterSessionUpdateFieldsFull(input.Body, fullSessionFields(opts))
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
			out.Body.Session = updated.Session
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
		out.Body.Session = session
		return out, nil
	})
}
