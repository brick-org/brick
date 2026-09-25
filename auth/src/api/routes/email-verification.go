package routes

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/brick-org/brick/auth/src/crypto"
	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
)

// verificationAntiEnumerationFloorMs mirrors upstream's MINIMUM_MS floor on
// at least this long so response timing does not reveal whether the email
const verificationAntiEnumerationFloorMs = 500

type sendVerificationEmailInput struct {
	Authorization string `header:"Authorization"`
	Cookie        string `header:"Cookie"`
	Body          struct {
		Email       string  `json:"email" format:"email" required:"true"`
		CallbackURL *string `json:"callbackURL,omitempty"`
	}
}

type sendVerificationEmailOutput struct {
	Body struct {
		Status bool `json:"status"`
	}
}

// SendVerificationEmail registers POST /send-verification-email.
// Upstream contract notes: an authenticated caller must verify the session's
// own email (EMAIL_MISMATCH / EMAIL_ALREADY_VERIFIED otherwise); the
// unauthenticated path always returns {status:true} after a 500ms timing
func SendVerificationEmail(api huma.API, basePath string, opts types.Options) {
	registerAuthOperation(api, huma.Operation{
		Tags:        []string{"Auth"},
		Method:      http.MethodPost,
		Path:        basePath + "/send-verification-email",
		OperationID: "sendVerificationEmail",
		Summary:     "Send a verification email",
	}, opts, func(ctx context.Context, input *sendVerificationEmailInput) (*sendVerificationEmailOutput, error) {
		if opts.EmailVerification.SendVerificationEmail == nil && opts.EmailVerification.SendVerificationEmailRequest == nil {
			return nil, huma.NewError(types.StatusForCode(types.ErrVerificationEmailNotEnabled), types.ErrVerificationEmailNotEnabled)
		}

		// Authenticated path mirrors upstream: the session user's own email
		// must match and must not already be verified.
		if token := sessionTokenFromRequest(input.Cookie, input.Authorization, opts); token != "" {
			if sessionRow, userRow, _, err := loadSessionAndUser(ctx, opts, token); err == nil && sessionRow != nil && userRow != nil {
				sessionUser := rowToUser(userRow, opts)
				if !strings.EqualFold(sessionUser.Email, input.Body.Email) {
					return nil, huma.NewError(types.StatusForCode(types.ErrEmailMismatch), types.ErrEmailMismatch)
				}
				if sessionUser.EmailVerified {
					return nil, huma.NewError(types.StatusForCode(types.ErrEmailAlreadyVerified), types.ErrEmailAlreadyVerified)
				}
				if err := sendVerificationEmailForUser(ctx, opts, userRow, input.Body.CallbackURL); err != nil {
					return nil, err
				}
				out := &sendVerificationEmailOutput{}
				out.Body.Status = true
				return out, nil
			}
		}

		start := time.Now()
		var sendErr error
		userRow, err := opts.DB.FindOne(ctx, "user", []types.Where{
			{Field: "email", Value: strings.ToLower(input.Body.Email)},
		}, nil)
		if err == nil && userRow != nil && !rowToUser(userRow, opts).EmailVerified {
			sendErr = sendVerificationEmailForUser(ctx, opts, userRow, input.Body.CallbackURL)
		} else {
			// Equalize work for unknown or already-verified emails so the
			// fast local path is indistinguishable from a real send: sign a
			// dummy HS256 token, mirroring upstream's
			_, _ = crypto.CreateEmailVerificationToken(opts.CurrentSecret(), input.Body.Email, "", emailVerificationExpirySeconds(opts), nil)
		}
		enforceAntiEnumerationFloor(start)
		if sendErr != nil {
			return nil, sendErr
		}
		out := &sendVerificationEmailOutput{}
		out.Body.Status = true
		return out, nil
	})
}

// seconds, mirroring the upstream default (3600s) of
func emailVerificationExpirySeconds(opts types.Options) int {
	if opts.EmailVerification.ExpiresIn > 0 {
		return opts.EmailVerification.ExpiresIn
	}
	return crypto.DefaultEmailVerificationExpirySeconds
}

// (upstream sendVerificationEmail(data, request)). Delivery failures never
// fail the route: upstream logs and continues.
func sendVerificationEmailWithRequest(ctx context.Context, opts types.Options, data types.VerificationEmailData) {
	if opts.EmailVerification.SendVerificationEmailRequest != nil {
		req := callbackRequest(ctx)
		runBackgroundOrAwait(opts, func() error {
			return opts.EmailVerification.SendVerificationEmailRequest(data, req)
		})
		return
	}
	if opts.EmailVerification.SendVerificationEmail != nil {
		runBackgroundOrAwait(opts, func() error {
			return opts.EmailVerification.SendVerificationEmail(data)
		})
	}
}

// errors. Upstream sendVerificationEmailFn awaits directly instead of using
// runInBackgroundOrAwait (email-verification.ts:69-70, see #8757), so a
// failing send fails the send-verification-email route.
func deliverVerificationEmail(ctx context.Context, opts types.Options, data types.VerificationEmailData) error {
	if opts.EmailVerification.SendVerificationEmailRequest != nil {
		return opts.EmailVerification.SendVerificationEmailRequest(data, callbackRequest(ctx))
	}
	if opts.EmailVerification.SendVerificationEmail != nil {
		return opts.EmailVerification.SendVerificationEmail(data)
	}
	return nil
}

// request-aware variant when set (upstream
func runBeforeEmailVerificationHook(ctx context.Context, opts types.Options, user *types.User) error {
	if opts.EmailVerification.BeforeEmailVerificationRequest != nil {
		return opts.EmailVerification.BeforeEmailVerificationRequest(user, callbackRequest(ctx))
	}
	if opts.EmailVerification.BeforeEmailVerification != nil {
		return opts.EmailVerification.BeforeEmailVerification(user)
	}
	return nil
}

// request-aware variant when set (upstream
func runAfterEmailVerificationHook(ctx context.Context, opts types.Options, user *types.User) error {
	if opts.EmailVerification.AfterEmailVerificationRequest != nil {
		return opts.EmailVerification.AfterEmailVerificationRequest(user, callbackRequest(ctx))
	}
	if opts.EmailVerification.AfterEmailVerification != nil {
		return opts.EmailVerification.AfterEmailVerification(user)
	}
	return nil
}

// enforceAntiEnumerationFloor sleeps until at least
// verificationAntiEnumerationFloorMs milliseconds have elapsed since start.
func enforceAntiEnumerationFloor(start time.Time) {
	remaining := time.Duration(verificationAntiEnumerationFloorMs)*time.Millisecond - time.Since(start)
	if remaining > 0 {
		time.Sleep(remaining)
	}
}

// awaited directly (upstream sendVerificationEmailFn awaits instead of using
// runInBackgroundOrAwait). Issuance is the upstream HS256 email JWT
// migration bridge but are never issued here.
func sendVerificationEmailForUser(ctx context.Context, opts types.Options, userRow map[string]any, callbackURL *string) error {
	user := rowToUser(userRow, opts)
	token, err := crypto.CreateEmailVerificationToken(opts.CurrentSecret(), user.Email, "", emailVerificationExpirySeconds(opts), nil)
	if err != nil {
		return huma.Error500InternalServerError("failed to generate token")
	}
	target := "/"
	if callbackURL != nil {
		target = *callbackURL
	}
	// Upstream originCheck throws FORBIDDEN for an untrusted callbackURL
	// (origin-check.ts:123-124); StatusForCode pins 403. The stored request
	// (when present) is authoritative for trust decisions.
	reqForTrust := trustRequest(ctx)
	if !types.IsTrustedRedirect(target, opts, reqForTrust) {
		return huma.NewError(types.StatusForCode(types.ErrInvalidCallbackURL), types.ErrInvalidCallbackURL)
	}
	verificationURL := fmt.Sprintf("%s/verify-email?token=%s&callbackURL=%s", opts.BasePath, url.QueryEscape(token), url.QueryEscape(target))
	if err := deliverVerificationEmail(ctx, opts, types.VerificationEmailData{User: &user, URL: verificationURL, Token: token}); err != nil {
		// Upstream sendVerificationEmailFn awaits the sender directly
		// (e.g. rate-limit TOO_MANY_REQUESTS) keeps its own status instead
		// of collapsing to 500. Non-APIError delivery failures stay 500.
		var httpErr types.HttpError
		if errors.As(err, &httpErr) {
			return huma.NewError(httpErr.Status, httpErr.Code)
		}
		return huma.Error500InternalServerError("failed to send verification email")
	}
	return nil
}

type verifyEmailInput struct {
	CookieRequestHeaders
	Cookie        string `header:"Cookie"`
	Authorization string `header:"Authorization"`
	Body          struct {
		Token string `json:"token" required:"true"`
	}
}

type verifyEmailOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      struct {
		Status bool      `json:"status"`
		User   *flatUser `json:"user"`
	}
}

// registrar handles both methods so DisabledPaths gating stays a single
// request for downstream hooks (upstream safeCloneRequest semantics): the
// middleware-reconstructed StoredRequestFromStd is authoritative for URL,
// neither, a bare POST / fallback is built only if auth headers are present
// (otherwise ctx passes through). Cloning preserves the real URL so hooks
// observe the verify-email route instead of POST /.
func mergeVerifyPostStoredRequest(ctx context.Context, cookie, authorization string) context.Context {
	stored := StoredRequestFromStd(ctx)
	if stored == nil {
		if cb := callbackRequest(ctx); cb != nil {
			stored = cb
		}
	}
	if stored == nil {
		if cookie == "" && authorization == "" {
			return ctx
		}
		req, _ := http.NewRequest(http.MethodPost, "/", nil)
		if req == nil {
			return ctx
		}
		if req.Header == nil {
			req.Header = make(http.Header)
		}
		if cookie != "" {
			req.Header.Set("Cookie", cookie)
		}
		if authorization != "" {
			req.Header.Set("Authorization", authorization)
		}
		return context.WithValue(ctx, storedRequestKey{}, req)
	}
	if cookie == "" && authorization == "" {
		if StoredRequestFromStd(ctx) == nil {
			return context.WithValue(ctx, storedRequestKey{}, stored)
		}
		return ctx
	}
	cloned := stored.Clone(ctx)
	if cloned == nil {
		return ctx
	}
	if cloned.Header == nil {
		cloned.Header = make(http.Header)
	}
	if cookie != "" {
		cloned.Header.Set("Cookie", cookie)
	}
	if authorization != "" {
		cloned.Header.Set("Authorization", authorization)
	}
	return context.WithValue(ctx, storedRequestKey{}, cloned)
}

func VerifyEmail(api huma.API, basePath string, opts types.Options) {
	registerAuthOperation(api, huma.Operation{
		Tags:        []string{"Auth"},
		Method:      http.MethodPost,
		Path:        basePath + "/verify-email",
		OperationID: "verifyEmail",
		Summary:     "Verify email address",
	}, opts, func(ctx context.Context, input *verifyEmailInput) (*verifyEmailOutput, error) {
		rctx := mergeVerifyPostStoredRequest(ctx, input.Cookie, input.Authorization)
		user, cookies, errCode, status := processVerifyEmail(rctx, opts, input.Body.Token, input.CookieRequestHeaders)
		if errCode != "" {
			return nil, huma.NewError(status, errCode)
		}
		out := &verifyEmailOutput{}
		out.Body.Status = true
		if user != nil {
			flat := flatUser(*user)
			out.Body.User = &flat
		}
		out.SetCookie = cookies
		return out, nil
	})

	VerifyEmailGet(api, basePath, opts)
}

// VerifyEmailGet registers GET /verify-email with the upstream query
// returned. An untrusted callbackURL is a 403 INVALID_CALLBACK_URL,
func VerifyEmailGet(api huma.API, basePath string, opts types.Options) {
	op := &huma.Operation{
		Tags:        []string{"Auth"},
		Method:      http.MethodGet,
		Path:        basePath + "/verify-email",
		OperationID: "verifyEmailGet",
		Summary:     "Verify email address via query token",
	}

	api.Adapter().Handle(op, func(ctx huma.Context) {
		writeJSON := func(status int, body map[string]any) {
			payload, _ := json.Marshal(body)
			ctx.SetHeader("Content-Type", "application/json")
			ctx.SetStatus(status)
			_, _ = ctx.BodyWriter().Write(payload)
		}
		writeError := func(status int, code string) {
			writeJSON(status, map[string]any{
				"status": status,
				"title":  http.StatusText(status),
				"detail": code,
			})
		}
		// Headers must be set BEFORE SetStatus (which calls WriteHeader immediately).
		redirect := func(location string) {
			ctx.SetHeader("Location", location)
			ctx.SetStatus(http.StatusFound)
		}

		token := ctx.Query("token")
		callbackURL := ctx.Query("callbackURL")
		reqForTrust := trustRequestFromHuma(ctx)
		if callbackURL != "" && !types.IsTrustedRedirect(callbackURL, opts, reqForTrust) {
			writeError(types.StatusForCode(types.ErrInvalidCallbackURL), types.ErrInvalidCallbackURL)
			return
		}
		redirectOnError := func(code string, status int) {
			if callbackURL != "" {
				redirect(appendRedirectQuery(callbackURL, "error", code))
				return
			}
			writeError(status, code)
		}

		if token == "" {
			redirectOnError(types.ErrInvalidToken, types.StatusForCode(types.ErrInvalidToken))
			return
		}

		headers := CookieRequestHeaders{
			Host:            ctx.Header("Host"),
			XForwardedHost:  ctx.Header("X-Forwarded-Host"),
			XForwardedProto: ctx.Header("X-Forwarded-Proto"),
		}
		// Wrap the request context so request-aware verification hooks and
		// resends receive the live request even when the API middleware wrap
		// is not installed. The stored request (when present) is authoritative
		rctx := humaRequestContext(ctx.Context(), ctx)
		if StoredRequestFromStd(ctx.Context()) == nil {
			if req := RequestFromHuma(ctx); req != nil {
				rctx = context.WithValue(rctx, storedRequestKey{}, req)
			}
		}
		sessionEmail := sessionEmailForVerify(rctx, opts, ctx.Header("Cookie"), ctx.Header("Authorization"))
		user, cookies, errCode, status := processVerifyEmailWithSession(rctx, opts, token, headers, callbackURL, sessionEmail)
		for _, cookie := range cookies {
			ctx.AppendHeader("Set-Cookie", cookie.String())
		}
		if errCode != "" {
			redirectOnError(errCode, status)
			return
		}
		if callbackURL != "" {
			redirect(callbackURL)
			return
		}
		var respUser any
		if user != nil {
			respUser = flatUser(*user)
		}
		writeJSON(http.StatusOK, map[string]any{"status": true, "user": respUser})
	})
}

// HTTP status; fatal transport errors surface as 500 INVALID paths. It backs
func processVerifyEmail(ctx context.Context, opts types.Options, token string, headers CookieRequestHeaders) (user *types.User, cookies []http.Cookie, errCode string, status int) {
	return processVerifyEmailWithSession(ctx, opts, token, headers, "", "")
}

// processVerifyEmailWithSession is processVerifyEmail plus the upstream
// carrying updateTo are handled without any verification row. callbackURL
// ("" when unknown, in which case the INVALID_USER mismatch check is
func processVerifyEmailWithSession(ctx context.Context, opts types.Options, token string, headers CookieRequestHeaders, callbackURL, sessionEmail string) (user *types.User, cookies []http.Cookie, errCode string, status int) {
	// Issuance is the upstream HS256 email JWT; verify it first across all
	// migration remain readable as a fallback below.
	if payload, jwtErr := crypto.VerifyEmailVerificationTokenAny(opts.AllSecrets(), token); jwtErr == nil {
		if payload.UpdateTo == "" {
			return verifyEmailForAddress(ctx, opts, payload.Email, headers)
		}
		return processStatelessUpdateTo(ctx, opts, payload, headers, callbackURL, sessionEmail)
	} else if jwtErr != nil && isTokenExpiredError(jwtErr) {
		return processLegacyVerifyToken(ctx, opts, token, true, headers)
	}
	return processLegacyVerifyToken(ctx, opts, token, false, headers)
}

// the verify-email INVALID_USER mismatch check (upstream
// (a fresh session is minted where upstream requires one).
func sessionEmailForVerify(ctx context.Context, opts types.Options, cookie, authorization string) string {
	token := sessionTokenFromRequest(cookie, authorization, opts)
	if token == "" {
		return ""
	}
	_, userRow, _, err := loadSessionAndUser(ctx, opts, token)
	if err != nil || userRow == nil {
		return ""
	}
	return rowToUser(userRow, opts).Email
}

// processStatelessUpdateTo runs the three upstream updateTo branches
func processStatelessUpdateTo(ctx context.Context, opts types.Options, payload *crypto.EmailVerificationPayload, headers CookieRequestHeaders, callbackURL, sessionEmail string) (*types.User, []http.Cookie, string, int) {
	if callbackURL == "" {
		callbackURL = "/"
	}
	userRow, err := opts.DB.FindOne(ctx, "user", []types.Where{
		{Field: "email", Value: strings.ToLower(payload.Email)},
	}, nil)
	if err != nil || userRow == nil {
		return nil, nil, types.ErrUserNotFound, types.StatusForCode(types.ErrUserNotFound)
	}
	if sessionEmail != "" && !strings.EqualFold(sessionEmail, payload.Email) {
		return nil, nil, types.ErrInvalidUser, types.StatusForCode(types.ErrInvalidUser)
	}
	basePath := opts.BasePath
	now := time.Now().UTC()

	switch payload.RequestType {
	case "change-email-confirmation":
		nextToken, tokenErr := crypto.CreateEmailVerificationToken(opts.CurrentSecret(), payload.Email, payload.UpdateTo, emailVerificationExpirySeconds(opts), map[string]any{"requestType": "change-email-verification"})
		if tokenErr != nil {
			return nil, nil, types.ErrFailedToCreateVerification, types.StatusForCode(types.ErrFailedToCreateVerification)
		}
		if opts.EmailVerification.SendVerificationEmail == nil && opts.EmailVerification.SendVerificationEmailRequest == nil {
			return nil, nil, types.ErrVerificationEmailNotEnabled, types.StatusForCode(types.ErrVerificationEmailNotEnabled)
		}
		verificationUser := rowToUser(userRow, opts)
		verificationUser.Email = payload.UpdateTo
		sendVerificationEmailWithRequest(requestContextForCallbacks(ctx), opts, types.VerificationEmailData{
			User:  &verificationUser,
			URL:   fmt.Sprintf("%s/verify-email?token=%s&callbackURL=%s", basePath, url.QueryEscape(nextToken), url.QueryEscape(callbackURL)),
			Token: nextToken,
		})
		return nil, nil, "", http.StatusOK
	case "change-email-verification":
		// token when present (matched against the OLD email before the
		// mint only when absent/mismatched.
		preToken, preSession, hasPre := capturePreUpdateVerificationSession(ctx, opts, payload.Email)
		updatedRow, err := opts.DB.Update(ctx, "user", []types.Where{
			{Field: "email", Value: strings.ToLower(payload.Email)},
		}, map[string]any{
			"email":         strings.ToLower(payload.UpdateTo),
			"emailVerified": true,
			"updatedAt":     now,
		})
		if err != nil {
			return nil, nil, "failed to update user", http.StatusInternalServerError
		}
		updated := rowToUser(updatedRow, opts)
		// Secondary-storage fan-out (upstream refreshUserSessions, queued by
		// log-only, never fails the route.
		if err := refreshSecondaryUserSessions(opts, updated); err != nil {
			Logf(opts, "error", "failed to refresh secondary sessions: %v", err)
		}
		if err := runAfterEmailVerificationHook(requestContextForCallbacks(ctx), opts, &updated); err != nil {
			// A hook-thrown APIError keeps its own status (upstream hooks
			// are awaited directly); non-APIError failures stay 500.
			var httpErr types.HttpError
			if errors.As(err, &httpErr) {
				return nil, nil, httpErr.Code, httpErr.Status
			}
			return nil, nil, "failed to handle email verification", http.StatusInternalServerError
		}
		if hasPre {
			if reused, rerr := newSessionCookies(opts, headers, preToken, preSession, updated, opts.Session, now); rerr == nil {
				return &updated, reused, "", http.StatusOK
			}
		}
		sessionCookies, sessionErr := createVerificationSession(ctx, opts, headers, updated, now)
		if sessionErr != nil {
			return nil, nil, types.ErrFailedToCreateSession, types.StatusForCode(types.ErrFailedToCreateSession)
		}
		return &updated, sessionCookies, "", http.StatusOK
	default:
		// token when present (upstream email-verification.ts:421-478 reuses
		// mint only on mismatch.
		preToken, preSession, hasPre := capturePreUpdateVerificationSession(ctx, opts, payload.Email)
		updatedRow, err := opts.DB.Update(ctx, "user", []types.Where{
			{Field: "email", Value: strings.ToLower(payload.Email)},
		}, map[string]any{
			"email":         strings.ToLower(payload.UpdateTo),
			"emailVerified": false,
			"updatedAt":     now,
		})
		if err != nil {
			return nil, nil, "failed to update user", http.StatusInternalServerError
		}
		updated := rowToUser(updatedRow, opts)
		// Secondary-storage fan-out (upstream refreshUserSessions, queued by
		// log-only, never fails the route.
		if err := refreshSecondaryUserSessions(opts, updated); err != nil {
			Logf(opts, "error", "failed to refresh secondary sessions: %v", err)
		}
		nextToken, tokenErr := crypto.CreateEmailVerificationToken(opts.CurrentSecret(), payload.UpdateTo, "", emailVerificationExpirySeconds(opts), nil)
		if tokenErr != nil {
			return nil, nil, types.ErrFailedToCreateVerification, types.StatusForCode(types.ErrFailedToCreateVerification)
		}
		if opts.EmailVerification.SendVerificationEmail != nil || opts.EmailVerification.SendVerificationEmailRequest != nil {
			sendVerificationEmailWithRequest(requestContextForCallbacks(ctx), opts, types.VerificationEmailData{
				User:  &updated,
				URL:   fmt.Sprintf("%s/verify-email?token=%s&callbackURL=%s", basePath, url.QueryEscape(nextToken), url.QueryEscape(callbackURL)),
				Token: nextToken,
			})
		}
		if hasPre {
			if reused, rerr := newSessionCookies(opts, headers, preToken, preSession, updated, opts.Session, now); rerr == nil {
				return &updated, reused, "", http.StatusOK
			}
		}
		sessionCookies, sessionErr := createVerificationSession(ctx, opts, headers, updated, now)
		if sessionErr != nil {
			return nil, nil, types.ErrFailedToCreateSession, types.StatusForCode(types.ErrFailedToCreateSession)
		}
		return &updated, sessionCookies, "", http.StatusOK
	}
}

// reports an already-observed expired HS256 JWT so a token that matches no
// row still reports TOKEN_EXPIRED (mirroring upstream's JWTExpired branch).
func processLegacyVerifyToken(ctx context.Context, opts types.Options, token string, jwtExpired bool, headers CookieRequestHeaders) (*types.User, []http.Cookie, string, int) {
	email, err := crypto.VerifyTokenAny(opts.AllSecrets(), token)
	if err == nil {
		return verifyEmailForAddress(ctx, opts, email, headers)
	}
	// HMAC verification failed. Change-email tokens are random
	// verification rows rather than signed tokens, so resolve those
	// TOKEN_EXPIRED to mirror upstream's JWTExpired branch.
	expired := jwtExpired || isTokenExpiredError(err)
	verificationRow, storedIdentifier, findErr := findChangeEmailVerificationRow(ctx, opts, token)
	if findErr != nil || verificationRow == nil {
		if findErr != nil {
			// Backend failure while resolving the verification row: fail
			// loudly (500) instead of misreporting an invalid token.
			return nil, nil, "failed to verify email", http.StatusInternalServerError
		}
		if expired {
			return nil, nil, types.ErrTokenExpired, types.StatusForCode(types.ErrTokenExpired)
		}
		return nil, nil, types.ErrInvalidToken, types.StatusForCode(types.ErrInvalidToken)
	}
	return processChangeEmailVerification(ctx, opts, token, storedIdentifier, verificationRow)
}

// success. A nil user with no error code means the confirmation email was
// sent and there is no user to return (upstream answers {status:true} or
func processChangeEmailVerification(ctx context.Context, opts types.Options, token, storedIdentifier string, verificationRow map[string]any) (user *types.User, cookies []http.Cookie, errCode string, status int) {
	expiresAt, _ := verificationRow["expiresAt"].(time.Time)
	if expiresAt.IsZero() || time.Now().UTC().After(expiresAt) {
		return nil, nil, types.ErrInvalidToken, types.StatusForCode(types.ErrInvalidToken)
	}

	var payload changeEmailVerificationPayload
	rawPayload, _ := verificationRow["value"].(string)
	if err := json.Unmarshal([]byte(rawPayload), &payload); err != nil {
		return nil, nil, types.ErrInvalidToken, types.StatusForCode(types.ErrInvalidToken)
	}

	switch payload.RequestType {
	case "change-email-confirmation":
		nextToken, createErr := createChangeEmailVerification(ctx, opts, payload.CurrentEmail, payload.NewEmail, "change-email-verification", changeEmailTokenTTL(opts.EmailVerification.ExpiresIn))
		if createErr != nil {
			return nil, nil, types.ErrFailedToCreateVerification, types.StatusForCode(types.ErrFailedToCreateVerification)
		}
		userRow, userErr := opts.DB.FindOne(ctx, "user", []types.Where{
			{Field: "email", Value: payload.CurrentEmail},
		}, nil)
		if userErr != nil || userRow == nil {
			// Upstream USER_NOT_FOUND resolves to 404 by majority (e.g. NOT_FOUND
			// the 401 redirectOnError (email-verification.ts:300,328) but the
			return nil, nil, types.ErrUserNotFound, types.StatusForCode(types.ErrUserNotFound)
		}
		verificationUser := rowToUser(userRow, opts)
		verificationUser.Email = payload.NewEmail
		if opts.EmailVerification.SendVerificationEmail == nil && opts.EmailVerification.SendVerificationEmailRequest == nil {
			return nil, nil, types.ErrVerificationEmailNotEnabled, types.StatusForCode(types.ErrVerificationEmailNotEnabled)
		}
		// Delivery failures never fail the route: upstream awaits via
		sendVerificationEmailWithRequest(ctx, opts, types.VerificationEmailData{
			User:  &verificationUser,
			URL:   fmt.Sprintf("%s/verify-email?token=%s", opts.BasePath, nextToken),
			Token: nextToken,
		})
		if err := deleteChangeEmailVerification(ctx, opts, token, storedIdentifier); err != nil {
			return nil, nil, types.ErrFailedToCreateVerification, types.StatusForCode(types.ErrFailedToCreateVerification)
		}
		return nil, nil, "", http.StatusOK
	case "change-email-verification":
		now := time.Now().UTC()
		updatedRow, err := opts.DB.Update(ctx, "user", []types.Where{
			{Field: "email", Value: payload.CurrentEmail},
		}, map[string]any{
			"email":         payload.NewEmail,
			"emailVerified": true,
			"updatedAt":     now,
		})
		if err != nil {
			return nil, nil, "failed to update user", http.StatusInternalServerError
		}
		if err := deleteChangeEmailVerification(ctx, opts, token, storedIdentifier); err != nil {
			return nil, nil, types.ErrFailedToCreateVerification, types.StatusForCode(types.ErrFailedToCreateVerification)
		}
		updated := rowToUser(updatedRow, opts)
		// Secondary-storage fan-out (upstream refreshUserSessions, queued by
		// log-only, never fails the route.
		if err := refreshSecondaryUserSessions(opts, updated); err != nil {
			Logf(opts, "error", "failed to refresh secondary sessions: %v", err)
		}
		if err := runAfterEmailVerificationHook(ctx, opts, &updated); err != nil {
			// A hook-thrown APIError keeps its own status (upstream hooks
			// are awaited directly); non-APIError failures stay 500.
			var httpErr types.HttpError
			if errors.As(err, &httpErr) {
				return nil, nil, httpErr.Code, httpErr.Status
			}
			return nil, nil, "failed to handle email verification", http.StatusInternalServerError
		}
		return &updated, nil, "", http.StatusOK
	default:
		return nil, nil, types.ErrInvalidToken, types.StatusForCode(types.ErrInvalidToken)
	}
}

func verifyEmailForAddress(ctx context.Context, opts types.Options, email string, headers CookieRequestHeaders) (*types.User, []http.Cookie, string, int) {
	userRow, err := opts.DB.FindOne(ctx, "user", []types.Where{
		{Field: "email", Value: strings.ToLower(email)},
	}, nil)
	if err != nil || userRow == nil {
		// Upstream USER_NOT_FOUND resolves to 404 by majority (e.g. NOT_FOUND
		// the 401 redirectOnError (email-verification.ts:300,328) but the
		return nil, nil, types.ErrUserNotFound, types.StatusForCode(types.ErrUserNotFound)
	}
	user := rowToUser(userRow, opts)
	if user.EmailVerified {
		// Upstream already-verified without callbackURL answers
		// (the GET handler still 302s on success when callbackURL is set).
		return nil, nil, "", http.StatusOK
	}
	if err := runBeforeEmailVerificationHook(ctx, opts, &user); err != nil {
		// A hook-thrown APIError keeps its own status (upstream hooks are
		// awaited directly); non-APIError failures stay 500.
		var httpErr types.HttpError
		if errors.As(err, &httpErr) {
			return nil, nil, httpErr.Code, httpErr.Status
		}
		return nil, nil, "failed to handle email verification", http.StatusInternalServerError
	}
	now := time.Now().UTC()
	updatedRow, err := opts.DB.Update(ctx, "user", []types.Where{
		{Field: "email", Value: strings.ToLower(email)},
	}, map[string]any{
		"emailVerified": true,
		"updatedAt":     now,
	})
	if err != nil {
		return nil, nil, "failed to update user", http.StatusInternalServerError
	}
	updated := rowToUser(updatedRow, opts)
	// Secondary-storage fan-out (upstream refreshUserSessions, queued by
	// never fails the route.
	if err := refreshSecondaryUserSessions(opts, updated); err != nil {
		Logf(opts, "error", "failed to refresh secondary sessions: %v", err)
	}
	if err := runAfterEmailVerificationHook(ctx, opts, &updated); err != nil {
		// A hook-thrown APIError keeps its own status (upstream hooks are
		// awaited directly); non-APIError failures stay 500.
		var httpErr types.HttpError
		if errors.As(err, &httpErr) {
			return nil, nil, httpErr.Code, httpErr.Status
		}
		return nil, nil, "failed to handle email verification", http.StatusInternalServerError
	}
	var cookies []http.Cookie
	if opts.EmailVerification.AutoSignInAfterVerification {
		if reused, ok := tryReuseVerificationSession(ctx, opts, headers, updated, now); ok {
			cookies = reused
		} else {
			sessionCookies, sessionErr := createVerificationSession(ctx, opts, headers, updated, now)
			if sessionErr != nil {
				return nil, nil, types.ErrFailedToCreateSession, types.StatusForCode(types.ErrFailedToCreateSession)
			}
			cookies = sessionCookies
		}
	}
	return nil, cookies, "", http.StatusOK
}

// (upstream email-verification.ts:527-534). It returns (nil,false) when there
// is no reusable session so the caller mints a new row. Email comparison is
func tryReuseVerificationSession(ctx context.Context, opts types.Options, headers CookieRequestHeaders, updated types.User, now time.Time) ([]http.Cookie, bool) {
	req := StoredRequestFromStd(ctx)
	if req == nil {
		req = callbackRequest(ctx)
	}
	if req == nil {
		return nil, false
	}
	token := sessionTokenFromRequest(req.Header.Get("Cookie"), req.Header.Get("Authorization"), opts)
	if token == "" {
		return nil, false
	}
	sessionRow, userRow, _, err := loadSessionAndUser(ctx, opts, token)
	if err != nil || sessionRow == nil || userRow == nil {
		return nil, false
	}
	if !strings.EqualFold(rowToUser(userRow, opts).Email, updated.Email) {
		return nil, false
	}
	session := rowToSession(sessionRow, opts)
	if session.Token == "" {
		session.Token = token
	}
	reused, err := newSessionCookies(opts, headers, session.Token, session, updated, opts.Session, now)
	if err != nil {
		return nil, false
	}
	return reused, true
}

// oldEmail before the email update (upstream activeSession in
// email-verification.ts:372-387,422-437). The INVALID_USER gate already
// cookie reuse so the post-update reload (which would see the new email,
// especially with a lagging/log-only secondary fan-out) is not used for the
func capturePreUpdateVerificationSession(ctx context.Context, opts types.Options, oldEmail string) (string, types.Session, bool) {
	req := StoredRequestFromStd(ctx)
	if req == nil {
		req = callbackRequest(ctx)
	}
	if req == nil {
		return "", types.Session{}, false
	}
	token := sessionTokenFromRequest(req.Header.Get("Cookie"), req.Header.Get("Authorization"), opts)
	if token == "" {
		return "", types.Session{}, false
	}
	sessionRow, userRow, _, err := loadSessionAndUser(ctx, opts, token)
	if err != nil || sessionRow == nil || userRow == nil {
		return "", types.Session{}, false
	}
	if !strings.EqualFold(rowToUser(userRow, opts).Email, oldEmail) {
		return "", types.Session{}, false
	}
	session := rowToSession(sessionRow, opts)
	if session.Token == "" {
		session.Token = token
	}
	return session.Token, session, true
}

// mirroring upstream's autoSignInAfterVerification cookie handling. The row
// goes through the shared issuance seam (upstream createSession): with
// row is written only with StoreSessionInDatabase, since secondary-only
func createVerificationSession(ctx context.Context, opts types.Options, headers CookieRequestHeaders, user types.User, now time.Time) ([]http.Cookie, error) {
	token := crypto.GenerateID()
	session, err := createIssuedSession(ctx, opts, user.ID, token, now.Add(opts.Session.ExpiresInDuration()), now)
	if err != nil {
		return nil, err
	}
	if opts.SecondaryStorage != nil {
		if err := writeSecondarySession(opts, session, user); err != nil {
			return nil, err
		}
	}
	return newSessionCookies(opts, headers, session.Token, session, user, opts.Session, now)
}

func isTokenExpiredError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "expired")
}

// Mirrors the verification branches of upstream db/internal-adapter.ts
// Storage-convention differences from upstream are intentional and loud:
// upstream change-email tokens are stateless HS256 JWTs with no rows at all,

// Upstream TypeScript value: `verification:${identifier}`.
func verificationSecondaryKey(storedIdentifier string) string {
	return "verification:" + storedIdentifier
}

// option for identifier, mirroring upstream getStorageOption
func resolveVerificationStoreOption(identifier string, config types.VerificationStoreIdentifier) types.VerificationStoreIdentifier {
	for prefix, override := range config.Overrides {
		if prefix != "" && strings.HasPrefix(identifier, prefix) {
			return override
		}
	}
	return types.VerificationStoreIdentifier{Mode: config.Mode, Hash: config.Hash}
}

// mirroring upstream processIdentifier
func processVerificationIdentifier(identifier string, option types.VerificationStoreIdentifier) (string, error) {
	switch option.Mode {
	case "", types.StoreIdentifierPlain:
		if option.Hash != nil {
			return option.Hash(identifier)
		}
		return identifier, nil
	case types.StoreIdentifierHashed:
		if option.Hash != nil {
			return option.Hash(identifier)
		}
		sum := sha256.Sum256([]byte(identifier))
		return base64.RawURLEncoding.EncodeToString(sum[:]), nil
	default:
		if option.Hash != nil {
			return option.Hash(identifier)
		}
		return identifier, nil
	}
}

// verificationStoreUsesPlainFallback reports whether lookups must also try
// the plain identifier, mirroring upstream's `storageOption !== "plain"`
// keeps the plain fallback for rows written before hashing was enabled.
func verificationStoreUsesPlainFallback(option types.VerificationStoreIdentifier) bool {
	if option.Hash != nil {
		return true
	}
	return option.Mode != "" && option.Mode != types.StoreIdentifierPlain
}

// (upstream safeJSONParse revives ISO dates the same way).
func reviveVerificationRowDates(row map[string]any) {
	for _, key := range []string{"expiresAt", "createdAt", "updatedAt"} {
		if raw, ok := row[key].(string); ok {
			if parsed, err := time.Parse(time.RFC3339Nano, raw); err == nil {
				row[key] = parsed.UTC()
			} else if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
				row[key] = parsed.UTC()
			}
		}
	}
}

// expiry are not stored (TTL<=0), mirroring upstream's `if (ttl > 0)` guard
// in createVerificationValue. Upstream TypeScript name: the secondaryStorage
func writeSecondaryVerification(opts types.Options, identifier string, row map[string]any) error {
	if opts.SecondaryStorage == nil {
		return nil
	}
	stored, err := processVerificationIdentifier(identifier, resolveVerificationStoreOption(identifier, opts.Verification.StoreIdentifier))
	if err != nil {
		return err
	}
	expiresAt, _ := row["expiresAt"].(time.Time)
	ttl := secondarySessionTTL(expiresAt, time.Now().UTC())
	if ttl <= 0 {
		return nil
	}
	encoded, err := json.Marshal(row)
	if err != nil {
		return err
	}
	return opts.SecondaryStorage.Set(verificationSecondaryKey(stored), string(encoded), &ttl)
}

// mirroring upstream's `safeJSONParse(...)` null path.
func findSecondaryVerificationByStored(opts types.Options, stored string) (map[string]any, error) {
	raw, err := opts.SecondaryStorage.Get(verificationSecondaryKey(stored))
	if err != nil {
		return nil, err
	}
	return reviveSecondaryVerificationValue(raw), nil
}

// store-identifier option, including the plain fallback for non-plain
// options (upstream findVerificationValue secondary branch). It returns
func findSecondaryVerification(opts types.Options, identifier string) (map[string]any, error) {
	if opts.SecondaryStorage == nil {
		return nil, nil
	}
	option := resolveVerificationStoreOption(identifier, opts.Verification.StoreIdentifier)
	stored, err := processVerificationIdentifier(identifier, option)
	if err != nil {
		return nil, err
	}
	row, err := findSecondaryVerificationByStored(opts, stored)
	if err != nil || row != nil {
		return row, err
	}
	if verificationStoreUsesPlainFallback(option) && stored != identifier {
		return findSecondaryVerificationByStored(opts, identifier)
	}
	return nil, nil
}

// (stored plus the plain fallback when applicable), mirroring the secondary
// half of upstream deleteVerificationByIdentifier.
func deleteSecondaryVerification(opts types.Options, identifier string) error {
	if opts.SecondaryStorage == nil {
		return nil
	}
	option := resolveVerificationStoreOption(identifier, opts.Verification.StoreIdentifier)
	stored, err := processVerificationIdentifier(identifier, option)
	if err != nil {
		return err
	}
	if err := opts.SecondaryStorage.Delete(verificationSecondaryKey(stored)); err != nil {
		return err
	}
	if verificationStoreUsesPlainFallback(option) && stored != identifier {
		return opts.SecondaryStorage.Delete(verificationSecondaryKey(identifier))
	}
	return nil
}

// identifier it was found under. It mirrors upstream findVerificationValue:
// the database is consulted only when there is no secondary backend or
// on a database hit. Expired database rows are swept unless
func findChangeEmailVerificationRow(ctx context.Context, opts types.Options, token string) (map[string]any, string, error) {
	identifier := changeEmailIdentifier(token)
	option := resolveVerificationStoreOption(identifier, opts.Verification.StoreIdentifier)
	stored, err := processVerificationIdentifier(identifier, option)
	if err != nil {
		return nil, "", err
	}
	if opts.SecondaryStorage != nil {
		row, serr := findSecondaryVerification(opts, identifier)
		if serr != nil {
			return nil, "", serr
		}
		if row != nil {
			return row, stored, nil
		}
		if !opts.Verification.StoreInDatabase {
			return nil, stored, nil
		}
		// secondary entry on a hit so later reads stay cache-warm.
	}
	if opts.DB == nil {
		// Secondary-only deployment without a database: nothing else to
		return nil, stored, nil
	}
	row, derr := findVerificationRowByStored(ctx, opts, stored, option, identifier)
	if derr != nil {
		return nil, "", derr
	}
	if row != nil && opts.SecondaryStorage != nil {
		// Best-effort secondary mirror: the authoritative row above is the
		// source of truth; a failed mirror never fails the read.
		_ = writeSecondaryVerification(opts, identifier, row)
	}
	sweepExpiredVerificationRows(ctx, opts)
	return row, stored, nil
}

// the plain fallback for non-plain options (upstream findVerificationValue
func findVerificationRowByStored(ctx context.Context, opts types.Options, stored string, option types.VerificationStoreIdentifier, identifier string) (map[string]any, error) {
	rows, err := opts.DB.FindMany(ctx, "verification", []types.Where{
		{Field: "identifier", Value: stored},
	}, 1, 0, nil, nil)
	if err != nil {
		return nil, err
	}
	if len(rows) > 0 {
		return rows[0], nil
	}
	if verificationStoreUsesPlainFallback(option) && stored != identifier {
		plain, err := opts.DB.FindMany(ctx, "verification", []types.Where{
			{Field: "identifier", Value: identifier},
		}, 1, 0, nil, nil)
		if err != nil {
			return nil, err
		}
		if len(plain) > 0 {
			return plain[0], nil
		}
	}
	return nil, nil
}

// sweepExpiredVerificationRows deletes expired verification rows unless
// Verification.DisableCleanup, mirroring upstream's cleanup in
// findVerificationValue. Failures are best-effort and ignored so a failing
// sweep never breaks verification.
func sweepExpiredVerificationRows(ctx context.Context, opts types.Options) {
	if opts.Verification.DisableCleanup {
		return
	}
	_, _ = opts.DB.DeleteMany(ctx, "verification", []types.Where{
		{Field: "expiresAt", Operator: types.OpLt, Value: time.Now().UTC()},
	})
}

// across both stores, mirroring upstream deleteVerificationByIdentifier: the
// (stored plus the plain fallback) are removed, matching the consume path's
func deleteChangeEmailVerification(ctx context.Context, opts types.Options, token, stored string) error {
	identifier := changeEmailIdentifier(token)
	if opts.SecondaryStorage != nil {
		if err := deleteSecondaryVerification(opts, identifier); err != nil {
			return err
		}
	}
	if opts.DB == nil || (opts.SecondaryStorage != nil && !opts.Verification.StoreInDatabase) {
		return nil
	}
	if err := opts.DB.Delete(ctx, "verification", []types.Where{
		{Field: "identifier", Value: stored},
	}); err != nil {
		return err
	}
	option := resolveVerificationStoreOption(identifier, opts.Verification.StoreIdentifier)
	if verificationStoreUsesPlainFallback(option) && stored != identifier {
		return opts.DB.Delete(ctx, "verification", []types.Where{
			{Field: "identifier", Value: identifier},
		})
	}
	return nil
}

// consumeSecondaryVerification atomically consumes the single-use secondary
// verification value for identifier, mirroring the secondary-only branch of
// upstream consumeVerificationValue: GetAndDelete is the race gate (the
// interface requires it so single-use values are never read and deleted as
// already invalid (the row is gone and cannot be replayed).
func consumeSecondaryVerification(opts types.Options, identifier string) (map[string]any, error) {
	if opts.SecondaryStorage == nil {
		return nil, nil
	}
	option := resolveVerificationStoreOption(identifier, opts.Verification.StoreIdentifier)
	stored, err := processVerificationIdentifier(identifier, option)
	if err != nil {
		return nil, err
	}
	candidates := verificationCandidates(option, identifier, stored)
	for _, candidate := range candidates {
		raw, err := opts.SecondaryStorage.GetAndDelete(verificationSecondaryKey(candidate))
		if err != nil {
			return nil, err
		}
		row := reviveSecondaryVerificationValue(raw)
		if row == nil {
			continue
		}
		for _, sibling := range candidates {
			if sibling != candidate {
				_ = opts.SecondaryStorage.Delete(verificationSecondaryKey(sibling))
			}
		}
		return row, nil
	}
	return nil, nil
}

// into a row map, or nil on a miss/corrupt value (mirroring upstream's
func reviveSecondaryVerificationValue(raw any) map[string]any {
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
	var row map[string]any
	if err := json.Unmarshal(data, &row); err != nil || row == nil {
		return nil
	}
	reviveVerificationRowDates(row)
	return row
}
