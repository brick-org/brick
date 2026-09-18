package routes

import (
	"encoding/json"
	"net/http"

	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
)

// DeleteUserCallback registers GET /delete-user/callback.
// With a valid session and a single-use delete-account token it deletes the
// user, expires the session cookies, and either redirects to callbackURL or
// returns a JSON confirmation. Invalid tokens and missing sessions return
// 404, mirroring upstream.
func DeleteUserCallback(api huma.API, basePath string, opts types.Options) {
	op := &huma.Operation{
		Tags:        []string{"Auth"},
		Method:      http.MethodGet,
		Path:        basePath + "/delete-user/callback",
		OperationID: "deleteUserCallback",
		Summary:     "Complete user deletion with a verification token",
	}

	api.Adapter().Handle(op, func(ctx huma.Context) {
		writeJSON := func(status int, body map[string]any) {
			payload, _ := json.Marshal(body)
			ctx.SetHeader("Content-Type", "application/json")
			ctx.SetStatus(status)
			_, _ = ctx.BodyWriter().Write(payload)
		}
		// writeNotFound mirrors upstream deleteUserCallback, which throws
		// NOT_FOUND for a disabled handler, a missing session, and an invalid
		// token alike (update-user.ts:617-620,629-632,641-642). 404 is kept for
		// all of these even though FAILED_TO_GET_USER_INFO and INVALID_TOKEN
		// resolve to 401 under StatusForCode.
		writeNotFound := func(detail string) {
			writeJSON(http.StatusNotFound, map[string]any{
				"status": http.StatusNotFound,
				"title":  http.StatusText(http.StatusNotFound),
				"detail": detail,
			})
		}
		// Headers must be set BEFORE SetStatus (which calls WriteHeader immediately).
		redirect := func(location string) {
			ctx.SetHeader("Location", location)
			ctx.SetStatus(http.StatusFound)
		}

		if !opts.User.DeleteUser.Enabled {
			writeNotFound("Not found")
			return
		}

		token := sessionTokenFromRequest(ctx.Header("Cookie"), ctx.Header("Authorization"), opts)
		if token == "" {
			writeNotFound(types.ErrFailedToGetUserInfo)
			return
		}

		sessionRow, userRow, _, err := loadSessionAndUser(ctx.Context(), opts, token)
		if err != nil {
			writeNotFound(types.ErrFailedToGetUserInfo)
			return
		}

		deleteToken := ctx.Query("token")
		callbackURL := ctx.Query("callbackURL")
		if deleteToken == "" {
			writeNotFound(types.ErrInvalidToken)
			return
		}

		userID, _ := sessionRow["userId"].(string)
		// Consume the single-use delete token atomically before any
		// destructive work so concurrent callbacks with the same token can
		// only delete the account once: the first caller wins, later racers
		// get an error. A wrong-owner token is still burned by this consume
		// (upstream update-user.ts:634-643).
		storedUserID, consumeErr := consumeDeleteAccountToken(ctx.Context(), opts, deleteToken)
		if consumeErr != nil || storedUserID != userID {
			writeNotFound(types.ErrInvalidToken)
			return
		}

		currentUser := rowToUser(userRow, opts)
		// Wrap the request context so request-aware delete hooks receive the
		// live request even when the API middleware wrap is not installed.
		if err := finishDeleteUser(humaRequestContext(ctx.Context(), ctx), opts, userID, currentUser); err != nil {
			// Kept 500 (differs from StatusForCode 401 for INVALID_USER):
			// delete-transaction/hook failure, not a semantic invalid user.
			writeJSON(http.StatusInternalServerError, map[string]any{
				"status": http.StatusInternalServerError,
				"title":  http.StatusText(http.StatusInternalServerError),
				"detail": types.ErrInvalidUser,
			})
			return
		}

		headers := CookieRequestHeaders{
			Host:            ctx.Header("Host"),
			XForwardedHost:  ctx.Header("X-Forwarded-Host"),
			XForwardedProto: ctx.Header("X-Forwarded-Proto"),
		}
		for _, cookie := range expiredSessionCookies(opts, headers) {
			ctx.AppendHeader("Set-Cookie", cookie.String())
		}

		reqForTrust := StoredRequestFromStd(ctx.Context())
		if reqForTrust == nil {
			reqForTrust = RequestFromHuma(ctx)
		}
		if callbackURL != "" && types.IsTrustedRedirect(callbackURL, opts, reqForTrust) {
			redirect(callbackURL)
			return
		}
		writeJSON(http.StatusOK, map[string]any{
			"success": true,
			"message": "User deleted",
		})
	})
}
