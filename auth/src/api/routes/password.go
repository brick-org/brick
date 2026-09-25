package routes

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"encoding/json"
	"github.com/brick-org/brick/auth/src/crypto"
	"github.com/brick-org/brick/auth/src/db"
	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
)


type requestPasswordResetInput struct {
	Body struct {
		Email string `json:"email" format:"email" required:"true"`
		// with ?token= on success or ?error=INVALID_TOKEN on failure.
		RedirectTo *string `json:"redirectTo,omitempty"`
	}
}

type requestPasswordResetOutput struct {
	Body struct {
		Status  bool   `json:"status"`
		Message string `json:"message"`
	}
}

// RequestPasswordReset registers POST /request-password-reset.
// Upstream stores a random single-use verification row
func RequestPasswordReset(api huma.API, basePath string, opts types.Options) {
	registerAuthOperation(api, huma.Operation{
		Tags:        []string{"Auth"},
		Method:      http.MethodPost,
		Path:        basePath + "/request-password-reset",
		OperationID: "requestPasswordReset",
		Summary:     "Request a password reset email",
	}, opts, func(ctx context.Context, input *requestPasswordResetInput) (*requestPasswordResetOutput, error) {
		genericOK := &requestPasswordResetOutput{}
		genericOK.Body.Status = true
		genericOK.Body.Message = "If this email exists in our system, check your email for the reset link"

		if opts.EmailAndPassword.SendResetPassword == nil && opts.EmailAndPassword.SendResetPasswordRequest == nil {
			// Upstream password.ts:90-98 throws BAD_REQUEST with code
			// RESET_PASSWORD_DISABLED and message "Reset password isn't
			// lookup so existing and unknown emails answer identically
			// (no per-email oracle).
			Logf(opts, "error", "Reset password isn't enabled. Please pass an emailAndPassword.sendResetPassword function in your auth config!")
			return nil, huma.NewError(http.StatusBadRequest, "RESET_PASSWORD_DISABLED: Reset password isn't enabled")
		}

		redirectTo := ""
		if input.Body.RedirectTo != nil {
			redirectTo = *input.Body.RedirectTo
		}
		// Upstream gates redirectTo via originCheck (password.ts:87); the
		// stored request is authoritative when present.
		reqForTrust := trustRequest(ctx)
		if redirectTo != "" && !types.IsTrustedRedirect(redirectTo, opts, reqForTrust) {
			return nil, huma.NewError(types.StatusForCode(types.ErrInvalidRedirectURL), types.ErrInvalidRedirectURL)
		}

		email := strings.ToLower(input.Body.Email)
		userRow, err := opts.DB.FindOne(ctx, "user", []types.Where{
			{Field: "email", Value: email},
		}, nil)
		if err != nil || userRow == nil {
			// Mitigate timing attacks: simulate token generation and the
			// verification lookup a real user would trigger (upstream
			// timing stays comparable under every storage configuration.
			_ = crypto.GenerateRandomString(24)
			_, _ = findResetVerification(ctx, opts, "dummy-verification-token")
			// while still answering the generic success below.
			Logf(opts, "warn", "Reset Password: User not found")
			return genericOK, nil // avoid leaking whether email exists
		}

		expiresIn := opts.EmailAndPassword.ResetPasswordTokenExpiresIn
		if expiresIn == 0 {
			expiresIn = 3600
		}
		verificationToken := crypto.GenerateRandomString(24)
		now := time.Now().UTC()
		userID := stringField(userRow, "id")
		if err := createResetVerification(ctx, opts, verificationToken, userID, now.Add(time.Duration(expiresIn)*time.Second)); err != nil {
			return nil, huma.Error500InternalServerError("failed to create reset verification")
		}

		user := rowToUser(userRow, opts)
		resetURL := opts.BasePath + "/reset-password/" + verificationToken + "?callbackURL=" + url.QueryEscape(redirectTo)
		// Delivery failures never fail the route: upstream awaits via
		// "should not reveal failure of email sending").
		sendResetPasswordMail(ctx, opts, types.ResetPasswordData{User: &user, URL: resetURL, Token: verificationToken})

		return genericOK, nil
	})
}

// (upstream sendResetPassword(data, request)).
func sendResetPasswordMail(ctx context.Context, opts types.Options, data types.ResetPasswordData) {
	if opts.EmailAndPassword.SendResetPasswordRequest != nil {
		req := callbackRequest(ctx)
		runBackgroundOrAwait(opts, func() error {
			return opts.EmailAndPassword.SendResetPasswordRequest(data, req)
		})
		return
	}
	if opts.EmailAndPassword.SendResetPassword != nil {
		runBackgroundOrAwait(opts, func() error {
			return opts.EmailAndPassword.SendResetPassword(data)
		})
	}
}

// route, mirroring upstream's direct await.
func runOnPasswordResetHook(ctx context.Context, opts types.Options, data types.PasswordResetData) error {
	if opts.EmailAndPassword.OnPasswordResetRequest != nil {
		return opts.EmailAndPassword.OnPasswordResetRequest(data, callbackRequest(ctx))
	}
	if opts.EmailAndPassword.OnPasswordReset != nil {
		return opts.EmailAndPassword.OnPasswordReset(data)
	}
	return nil
}

// row for token across both stores, mirroring upstream
// written only with Verification.StoreInDatabase (or when no secondary
func createResetVerification(ctx context.Context, opts types.Options, token, userID string, expiresAt time.Time) error {
	now := time.Now().UTC()
	identifier := resetPasswordIdentifier(token)
	stored, err := processVerificationIdentifier(identifier, resolveVerificationStoreOption(identifier, opts.Verification.StoreIdentifier))
	if err != nil {
		return err
	}
	verificationID, verificationHasID := mintModelID(opts, "verification")
	row := map[string]any{
		"identifier": stored,
		"value":      userID,
		"expiresAt":  expiresAt,
		"createdAt":  now,
		"updatedAt":  now,
	}
	setRowID(row, verificationID, verificationHasID)
	if opts.SecondaryStorage != nil {
		if err := writeSecondaryVerification(opts, identifier, row); err != nil {
			return err
		}
	}
	if opts.DB != nil && (opts.SecondaryStorage == nil || opts.Verification.StoreInDatabase) {
		if _, err := opts.DB.Create(ctx, "verification", row, nil); err != nil {
			return err
		}
	}
	return nil
}

// token without consuming it (for the redirect callback check), or
// (nil, nil) when missing/expired. It mirrors upstream findVerificationValue:
func findResetVerification(ctx context.Context, opts types.Options, token string) (map[string]any, error) {
	identifier := resetPasswordIdentifier(token)
	if opts.SecondaryStorage != nil {
		row, err := findSecondaryVerification(opts, identifier)
		if err != nil {
			return nil, err
		}
		if row != nil {
			if expiresAt, _ := row["expiresAt"].(time.Time); isVerificationLive(expiresAt) {
				return row, nil
			}
			return nil, nil
		}
		if !opts.Verification.StoreInDatabase {
			return nil, nil
		}
	}
	if opts.DB == nil {
		return nil, nil
	}
	option := resolveVerificationStoreOption(identifier, opts.Verification.StoreIdentifier)
	stored, err := processVerificationIdentifier(identifier, option)
	if err != nil {
		return nil, err
	}
	row, err := findVerificationRowByStored(ctx, opts, stored, option, identifier)
	if err != nil {
		return nil, err
	}
	// upstream findVerificationValue), gated by DisableCleanup.
	sweepExpiredVerificationRows(ctx, opts)
	if row == nil {
		return nil, nil
	}
	if expiresAt, _ := row["expiresAt"].(time.Time); !isVerificationLive(expiresAt) {
		return nil, nil
	}
	return row, nil
}


type resetPasswordInput struct {
	// Token mirrors upstream's ?token= query support; the body token takes
	Token string `query:"token"`
	Body  struct {
		Token       *string `json:"token,omitempty"`
		NewPassword string  `json:"newPassword" required:"true"`
	}
}

type resetPasswordOutput struct {
	Body struct {
		Status bool `json:"status"`
	}
}

// ResetPassword registers POST /reset-password.
// tokens get INVALID_TOKEN). Legacy reusable HMAC email tokens issued by
func ResetPassword(api huma.API, basePath string, opts types.Options) {
	registerAuthOperation(api, huma.Operation{
		Tags:        []string{"Auth"},
		Method:      http.MethodPost,
		Path:        basePath + "/reset-password",
		OperationID: "resetPassword",
		Summary:     "Reset password using a reset token",
	}, opts, func(ctx context.Context, input *resetPasswordInput) (*resetPasswordOutput, error) {
		token := input.Token
		if input.Body.Token != nil && *input.Body.Token != "" {
			token = *input.Body.Token
		}
		// Kept 400 (differs from StatusForCode 401): upstream reset-password
		// throws BAD_REQUEST for a missing/consumed token (password.ts:277,299).
		if token == "" {
			return nil, huma.Error400BadRequest(types.ErrInvalidToken)
		}

		if len(input.Body.NewPassword) < passwordMinLength(opts) {
			return nil, huma.NewError(types.StatusForCode(types.ErrPasswordTooShort), types.ErrPasswordTooShort)
		}
		if len(input.Body.NewPassword) > passwordMaxLength(opts) {
			return nil, huma.NewError(types.StatusForCode(types.ErrPasswordTooLong), types.ErrPasswordTooLong)
		}

		userID, legacyEmail, errCode, status := consumeResetPasswordToken(ctx, opts, token)
		if errCode != "" {
			return nil, huma.NewError(status, errCode)
		}

		var userRow map[string]any
		var findErr error
		if userID != "" {
			userRow, findErr = opts.DB.FindOne(ctx, "user", []types.Where{
				{Field: "id", Value: userID},
			}, nil)
		} else {
			userRow, findErr = opts.DB.FindOne(ctx, "user", []types.Where{
				{Field: "email", Value: legacyEmail},
			}, nil)
		}
		// Upstream reset-password throws BAD_REQUEST for a missing user
		// (password.ts:304 BASE_ERROR_CODES.USER_NOT_FOUND); the route-level
		// status wins over the canonical 404 majority.
		if findErr != nil || userRow == nil {
			return nil, huma.NewError(http.StatusBadRequest, types.ErrUserNotFound)
		}
		userID = stringField(userRow, "id")

		hash, err := hashPassword(opts, input.Body.NewPassword)
		if err != nil {
			return nil, huma.Error500InternalServerError("failed to hash password")
		}

		now := time.Now().UTC()
		accountRow, err := opts.DB.FindOne(ctx, "account", []types.Where{
			{Field: "userId", Value: userID},
			{Field: "providerId", Value: "credential", Connector: "AND"},
		}, nil)
		if err != nil {
			return nil, huma.Error500InternalServerError("failed to update password")
		}
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
				return nil, huma.Error500InternalServerError("failed to update password")
			}
		} else if _, err := opts.DB.Update(ctx, "account", []types.Where{
			{Field: "userId", Value: userID},
			{Field: "providerId", Value: "credential", Connector: "AND"},
		}, map[string]any{
			"password":  hash,
			"updatedAt": now,
		}); err != nil {
			return nil, huma.Error500InternalServerError("failed to update password")
		}

		if opts.EmailAndPassword.OnPasswordReset != nil || opts.EmailAndPassword.OnPasswordResetRequest != nil {
			user := rowToUser(userRow, opts)
			if err := runOnPasswordResetHook(ctx, opts, types.PasswordResetData{User: &user}); err != nil {
				return nil, huma.Error500InternalServerError("failed to handle password reset")
			}
		}

		if opts.EmailAndPassword.RevokeSessionsOnPasswordReset {
			if err := deleteSecondaryAwareUserSessions(ctx, opts, userID); err != nil {
				return nil, huma.Error500InternalServerError("failed to revoke sessions")
			}
		}

		out := &resetPasswordOutput{}
		out.Body.Status = true
		return out, nil
	})
}

var errResetTokenNotFound = errors.New("reset token not found")

// consumeResetPasswordToken atomically consumes the single-use verification
// tokens get INVALID_TOKEN), mirroring upstream consumeVerificationValue:
// secondary-only deployments consume via GetAndDelete (the required atomic
// the store-identifier option with the plain fallback for non-plain modes.
// email instead (migration bridge for rotation-era links).
func consumeResetPasswordToken(ctx context.Context, opts types.Options, token string) (userID, legacyEmail, errCode string, status int) {
	identifier := resetPasswordIdentifier(token)
	if opts.SecondaryStorage != nil && !opts.Verification.StoreInDatabase {
		row, err := consumeSecondaryVerification(opts, identifier)
		if err == nil && row != nil {
			// value still reports INVALID_TOKEN and can never replay.
			if expiresAt, _ := row["expiresAt"].(time.Time); isVerificationLive(expiresAt) {
				if v, _ := row["value"].(string); v != "" {
					return v, "", "", http.StatusOK
				}
			}
			// Kept 400 (differs from StatusForCode 401): upstream
			// reset-password throws BAD_REQUEST for a consumed/empty token
			return "", "", types.ErrInvalidToken, http.StatusBadRequest
		}
	} else if opts.DB != nil {
		option := resolveVerificationStoreOption(identifier, opts.Verification.StoreIdentifier)
		stored, err := processVerificationIdentifier(identifier, option)
		if err == nil {
			// Atomic consume via the adapter race gate
			// (db.ConsumeOneWithFallback: ConsumeOne fast path, id-pinned
			// FindOne+Delete fallback). Dual-key iteration preserves the
			// stored+plain fallback: the first consumed row wins.
			candidates := verificationCandidates(option, identifier, stored)
			var row map[string]any
			for _, candidate := range candidates {
				consumed, cerr := db.ConsumeOneWithFallback(ctx, opts.DB, "verification", []types.Where{
					{Field: "identifier", Value: candidate},
				})
				if cerr != nil {
					// Fail-safe: a consume error behaves like a miss and
					row = nil
					break
				}
				if consumed != nil {
					row = consumed
					break
				}
			}
			var value string
			consumed := false
			if row != nil {
				expiresAt, ok := timeField(row, "expires_at", "expiresAt")
				if ok && isVerificationLive(expiresAt) {
					if v, _ := row["value"].(string); v != "" {
						value = v
					}
					consumed = true
				}
				for _, candidate := range candidates {
					_ = opts.DB.Delete(ctx, "verification", []types.Where{
						{Field: "identifier", Value: candidate},
					})
				}
				if !consumed {
					row = nil
				}
			}
			if consumed {
				if opts.SecondaryStorage != nil {
					_ = deleteSecondaryVerification(opts, identifier)
				}
				if value == "" {
					// Kept 400 (differs from StatusForCode 401): upstream
					// reset-password throws BAD_REQUEST for a consumed/empty token
					return "", "", types.ErrInvalidToken, http.StatusBadRequest
				}
				return value, "", "", http.StatusOK
			}
		}
	}
	// Legacy fallback: reusable HMAC-signed email tokens from deployments
	// predating single-use DB rows. Any secret rotation still applies via
	email, err := crypto.VerifyTokenAny(opts.AllSecrets(), token)
	if err != nil {
		// Kept 400 (differs from StatusForCode 401): upstream reset-password
		// throws BAD_REQUEST for an invalid token (password.ts:277,299).
		return "", "", types.ErrInvalidToken, http.StatusBadRequest
	}
	return "", strings.ToLower(email), "", http.StatusOK
}

// Merged from password-extra.go (upstream password.ts: VerifyPassword,

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

		reqForTrust := trustRequestFromHuma(ctx)
		// Upstream originCheck guards the query callbackURL
		// (origin-check.ts, password.ts:162): an untrusted value fails with
		// 403 INVALID_CALLBACK_URL instead of redirecting with INVALID_TOKEN.
		if callbackURL != "" && !types.IsTrustedRedirect(callbackURL, opts, reqForTrust) {
			payload, _ := json.Marshal(map[string]any{
				"status": http.StatusForbidden,
				"title":  http.StatusText(http.StatusForbidden),
				"detail": types.ErrInvalidCallbackURL,
			})
			ctx.SetHeader("Content-Type", "application/json")
			ctx.SetStatus(http.StatusForbidden)
			_, _ = ctx.BodyWriter().Write(payload)
			return
		}

		errorBase := defaultErrorURL
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

		if !resetTokenValid(ctx.Context(), opts, token) {
			redirectInvalid()
			return
		}

		redirect(appendRedirectQuery(callbackURL, "token", token))
	})
}

// It accepts upstream-style single-use verification rows
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


// SetPassword is the server-only counterpart of upstream `setPassword`
// already-set password with PASSWORD_ALREADY_SET. Errors are
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
