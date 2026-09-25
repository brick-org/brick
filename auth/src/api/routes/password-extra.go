package routes

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/brick-org/brick/auth/src/crypto"
	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
)

type verifyPasswordInput struct {
	Authorization string `header:"Authorization"`
	Cookie        string `header:"Cookie"`
	Body          struct {
		Password string `json:"password" required:"true"`
	}
}

type verifyPasswordOutput struct {
	Body struct {
		Status bool `json:"status"`
	}
}

// VerifyPassword registers POST /verify-password.
func VerifyPassword(api huma.API, basePath string, opts types.Options) {
	registerAuthOperation(api, huma.Operation{
		Tags:        []string{"Auth"},
		Method:      http.MethodPost,
		Path:        basePath + "/verify-password",
		OperationID: "verifyPassword",
		Summary:     "Verify the current user's password",
	}, opts, func(ctx context.Context, input *verifyPasswordInput) (*verifyPasswordOutput, error) {
		token := sessionTokenFromRequest(input.Cookie, input.Authorization, opts)
		if token == "" {
			return nil, huma.NewError(types.StatusForCode(types.ErrFailedToGetSession), types.ErrFailedToGetSession)
		}

		sessionRow, _, _, err := loadSessionAndUser(ctx, opts, token)
		if err != nil {
			if errors.Is(err, errSessionExpired) {
				// Kept 401 (differs from StatusForCode 400): expired-session
				// auth guard; see the note in ChangePassword.
				return nil, huma.Error401Unauthorized(types.ErrSessionExpired)
			}
			return nil, huma.NewError(types.StatusForCode(types.ErrFailedToGetSession), types.ErrFailedToGetSession)
		}

		userID := stringField(sessionRow, "user_id", "userId")
		accountRow, err := opts.DB.FindOne(ctx, "account", []types.Where{
			{Field: "userId", Value: userID},
			{Field: "providerId", Value: "credential", Connector: "AND"},
		}, nil)
		if err != nil || accountRow == nil {
			return nil, huma.NewError(types.StatusForCode(types.ErrInvalidPassword), types.ErrInvalidPassword)
		}

		storedHash, _ := accountRow["password"].(string)
		valid, verifyErr := verifyPassword(opts, storedHash, input.Body.Password)
		if verifyErr != nil {
			return nil, huma.Error500InternalServerError("failed to verify password")
		}
		if storedHash == "" || !valid {
			return nil, huma.NewError(types.StatusForCode(types.ErrInvalidPassword), types.ErrInvalidPassword)
		}

		out := &verifyPasswordOutput{}
		out.Body.Status = true
		return out, nil
	})
}

// RequestPasswordResetCallback registers GET /reset-password/{token}.
// Upstream redirects the user to the callback URL with the token appended, or
// to an error URL with ?error=INVALID_TOKEN when the token is missing,
// expired, or unknown.
func RequestPasswordResetCallback(api huma.API, basePath string, opts types.Options) {
	op := &huma.Operation{
		Tags:        []string{"Auth"},
		Method:      http.MethodGet,
		Path:        basePath + "/reset-password/{token}",
		OperationID: "resetPasswordCallback",
		Summary:     "Redirect the user to the password reset callback URL",
	}

	api.Adapter().Handle(op, func(ctx huma.Context) {
		token := ctx.Param("token")
		callbackURL := ctx.Query("callbackURL")

		// Authoritative per-request error URL (upstream parseState).
		defaultErrorURL := DefaultErrorURLWithHuma(ctx, opts)

		// Headers must be set BEFORE SetStatus (which calls WriteHeader immediately).
		redirect := func(location string) {
			ctx.SetHeader("Location", location)
			ctx.SetStatus(http.StatusFound)
		}

		errorBase := defaultErrorURL
		reqForTrust := StoredRequestFromStd(ctx.Context())
		if reqForTrust == nil {
			reqForTrust = RequestFromHuma(ctx)
		}
		if callbackURL != "" && types.IsTrustedRedirect(callbackURL, opts, reqForTrust) {
			errorBase = callbackURL
		}
		redirectInvalid := func() {
			redirect(appendRedirectQuery(errorBase, "error", "INVALID_TOKEN"))
		}

		if token == "" || callbackURL == "" {
			redirectInvalid()
			return
		}
		if !types.IsTrustedRedirect(callbackURL, opts, reqForTrust) {
			redirect(appendRedirectQuery(defaultErrorURL, "error", "INVALID_TOKEN"))
			return
		}

		if !resetTokenValid(ctx.Context(), opts, token) {
			redirectInvalid()
			return
		}

		redirect(appendRedirectQuery(callbackURL, "token", token))
	})
}

// resetTokenValid reports whether token is a live password-reset token.
// It accepts upstream-style single-use verification rows
// (identifier "reset-password:<token>", resolved across both stores with the
// store-identifier option) as well as the legacy signed email
// tokens issued by POST /request-password-reset. The token is not consumed
// here; consumption happens in POST /reset-password.
func resetTokenValid(ctx context.Context, opts types.Options, token string) bool {
	if row, err := findResetVerification(ctx, opts, token); err == nil && row != nil {
		return true
	}
	_, err := crypto.VerifyTokenAny(opts.AllSecrets(), token)
	return err == nil
}

func resetPasswordIdentifier(token string) string {
	return "reset-password:" + token
}

// isVerificationLive reports whether a verification expiry is still in the future.
func isVerificationLive(expiresAt time.Time) bool {
	return !expiresAt.IsZero() && !time.Now().UTC().After(expiresAt)
}

func appendRedirectQuery(rawURL, key, value string) string {
	sep := "?"
	if strings.Contains(rawURL, "?") {
		sep = "&"
	}
	return rawURL + sep + url.QueryEscape(key) + "=" + url.QueryEscape(value)
}

// --- set-password (server-only) ---

// SetPassword is the server-only counterpart of upstream `setPassword`
// (update-user.ts:314-368, `createAuthEndpoint.serverOnly`): it sets the
// password on the caller's existing passwordless credential account and
// reports `{status: true}`. There is intentionally no HTTP route — upstream
// exposes it only as `auth.api.setPassword`, so Go callers invoke this
// function with the already-authenticated user ID (the sensitive-session
// gate lives at the HTTP layer and has no server-only equivalent).
//
// Behavior mirrors upstream exactly: length gates with warn logs, link a new
// credential account when none exists, fill a null password, and reject an
// already-set password with PASSWORD_ALREADY_SET. Errors are
// types.HttpError values carrying the canonical status.
func SetPassword(ctx context.Context, opts types.Options, userID, newPassword string) (bool, error) {
	if len(newPassword) < passwordMinLength(opts) {
		Logf(opts, "warn", "Password is too short")
		return false, types.NewHttpError(types.ErrPasswordTooShort)
	}
	if len(newPassword) > passwordMaxLength(opts) {
		Logf(opts, "warn", "Password is too long")
		return false, types.NewHttpError(types.ErrPasswordTooLong)
	}
	if opts.DB == nil {
		return false, types.NewHttpError(types.ErrFailedToGetSession)
	}
	accountRow, err := opts.DB.FindOne(ctx, "account", []types.Where{
		{Field: "userId", Value: userID},
		{Field: "providerId", Value: "credential", Connector: "AND"},
	}, nil)
	if err != nil {
		return false, err
	}
	hash, err := hashPassword(opts, newPassword)
	if err != nil {
		return false, err
	}
	now := time.Now().UTC()
	if accountRow == nil {
		credentialID, credentialHasID := mintModelID(opts, "account")
		credentialData := map[string]any{
			"userId":     userID,
			"providerId": "credential",
			"accountId":  userID,
			"password":   hash,
			"createdAt":  now,
			"updatedAt":  now,
		}
		setRowID(credentialData, credentialID, credentialHasID)
		if _, err := opts.DB.Create(ctx, "account", credentialData, nil); err != nil {
			return false, err
		}
		return true, nil
	}
	stored, _ := accountRow["password"].(string)
	if stored != "" {
		return false, types.NewHttpError(types.ErrPasswordAlreadySet)
	}
	if _, err := opts.DB.Update(ctx, "account", []types.Where{
		{Field: "userId", Value: userID},
		{Field: "providerId", Value: "credential", Connector: "AND"},
	}, map[string]any{
		"password":  hash,
		"updatedAt": now,
	}); err != nil {
		return false, err
	}
	return true, nil
}
