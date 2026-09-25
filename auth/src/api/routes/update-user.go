package routes

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/brick-org/brick/auth/src/crypto"
	"github.com/brick-org/brick/auth/src/db"
	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
)

// Update-user family (upstream api/routes/update-user.ts: UpdateUser,

type updateUserBody struct {
	Name  *string        `json:"name,omitempty"`
	Image nullableString `json:"image,omitempty"`
	// Email is never updatable here (upstream EMAIL_CAN_NOT_BE_UPDATED);
	// it is declared only to detect and reject the field.
	Email *string `json:"email,omitempty"`
	// Extra carries additional user fields (upstream parseUserInput
	// schema instead of being dropped. See UnmarshalJSON/MarshalJSON.
	Extra map[string]any `json:"-"`
}

// UnmarshalJSON captures known fields plus any additional user fields into
func (b *updateUserBody) UnmarshalJSON(data []byte) error {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw == nil {
		return nil
	}
	if v, ok := raw["name"]; ok {
		if s, ok := v.(string); ok {
			b.Name = &s
		} else if v == nil {
			b.Name = nil
		}
		delete(raw, "name")
	}
	if v, ok := raw["image"]; ok {
		var n nullableString
		rv, _ := json.Marshal(v)
		if err := json.Unmarshal(rv, &n); err != nil {
			return err
		}
		b.Image = n
		delete(raw, "image")
	}
	if v, ok := raw["email"]; ok {
		if s, ok := v.(string); ok {
			b.Email = &s
		} else if v == nil {
			empty := ""
			b.Email = &empty
		}
		delete(raw, "email")
	}
	// callbackURL-style and other known non-user keys are never user fields;
	if len(raw) > 0 {
		b.Extra = raw
	}
	return nil
}

// MarshalJSON round-trips known fields plus Extra so test clients encoding
func (b updateUserBody) MarshalJSON() ([]byte, error) {
	out := map[string]any{}
	if b.Extra != nil {
		for k, v := range b.Extra {
			out[k] = v
		}
	}
	if b.Name != nil {
		out["name"] = *b.Name
	}
	if b.Image.Set {
		out["image"] = b.Image.Value
	}
	if b.Email != nil {
		out["email"] = *b.Email
	}
	return json.Marshal(out)
}

// TransformSchema permits additional properties on the update-user body,
// 422 before the handler runs.
func (b updateUserBody) TransformSchema(r huma.Registry, s *huma.Schema) *huma.Schema {
	s.AdditionalProperties = true
	return s
}

type updateUserInput struct {
	Authorization string `header:"Authorization"`
	Cookie        string `header:"Cookie"`
	CookieRequestHeaders
	Body updateUserBody
}

type updateUserOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      struct {
		Status bool `json:"status"`
	}
}

type changeEmailInput struct {
	Authorization string `header:"Authorization"`
	Cookie        string `header:"Cookie"`
	CookieRequestHeaders
	Body struct {
		NewEmail    string  `json:"newEmail" format:"email" required:"true"`
		CallbackURL *string `json:"callbackURL,omitempty"`
	}
}

type changeEmailOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      struct {
		Status bool `json:"status"`
	}
}

// UpdateUser registers POST /update-user.
func UpdateUser(api huma.API, basePath string, opts types.Options) {
	registerAuthOperation(api, huma.Operation{
		Tags:        []string{"Auth"},
		Method:      http.MethodPost,
		Path:        basePath + "/update-user",
		OperationID: "updateUser",
		Summary:     "Update the current user",
	}, opts, func(ctx context.Context, input *updateUserInput) (*updateUserOutput, error) {
		token := sessionTokenFromRequest(input.Cookie, input.Authorization, opts)
		if token == "" {
			return nil, huma.NewError(types.StatusForCode(types.ErrFailedToGetSession), types.ErrFailedToGetSession)
		}

		sessionRow, _, _, err := loadSessionAndUser(ctx, opts, token)
		if err != nil {
			if errors.Is(err, errSessionExpired) {
				// Kept 401 (differs from StatusForCode 400): expired-session auth
				// guard, matching upstream's 401-for-auth-failures convention. The
				// sole BAD_REQUEST throw site (update-user.ts:543) covers
				// delete-user freshness, which stays 400 (see DeleteUser below).
				return nil, huma.Error401Unauthorized(types.ErrSessionExpired)
			}
			return nil, huma.NewError(types.StatusForCode(types.ErrFailedToGetSession), types.ErrFailedToGetSession)
		}

		if input.Body.Email != nil {
			return nil, huma.NewError(types.StatusForCode(types.ErrEmailCanNotBeUpdated), types.ErrEmailCanNotBeUpdated)
		}

		update := map[string]any{"updatedAt": time.Now().UTC()}
		if input.Body.Name != nil {
			update["name"] = *input.Body.Name
		}
		// Explicit null unsets the image (upstream update-user.test.ts
		if input.Body.Image.Set {
			if input.Body.Image.Value != nil {
				update["image"] = *input.Body.Image.Value
			} else {
				update["image"] = nil
			}
		}
		// Additional user fields (upstream parseUserInput "update",
		if len(input.Body.Extra) > 0 {
			additional, perr := ParseUserInputFull(input.Body.Extra, FullUserFields(opts), "update")
			if perr != nil {
				if fp, ok := perr.(*FieldParseError); ok {
					// The message carries the upstream detail (e.g.
					return nil, huma.NewError(types.StatusForCode(fp.Code), fp.Message)
				}
				return nil, huma.Error400BadRequest(perr.Error())
			}
			for k, v := range additional {
				update[k] = v
			}
		}
		if len(update) == 1 {
			return nil, huma.NewError(types.StatusForCode(types.ErrBodyMustBeAnObject), types.ErrBodyMustBeAnObject)
		}

		updatedUserRow, err := opts.DB.Update(ctx, "user", []types.Where{
			{Field: "id", Value: sessionRow["userId"]},
		}, update)
		if err != nil {
			return nil, huma.NewError(types.StatusForCode(types.ErrFailedToUpdateUser), types.ErrFailedToUpdateUser)
		}

		// Secondary-storage fan-out (upstream refreshUserSessions,
		// live session after the commit. A failing mirror fails loudly
		// writeSecondarySession failures on the issuance paths (never
		if err := refreshSecondaryUserSessions(opts, rowToUser(updatedUserRow, opts)); err != nil {
			return nil, huma.NewError(types.StatusForCode(types.ErrFailedToUpdateUser), types.ErrFailedToUpdateUser)
		}

		out := &updateUserOutput{}
		// Upstream always refreshes the session cookie with the new user
		// data (update-user.ts:137-140), not only on session refresh.
		cookiesOut, cookieErr := newSessionCookies(opts, input.CookieRequestHeaders, token, rowToSession(sessionRow, opts), rowToUser(updatedUserRow, opts), opts.Session, time.Now().UTC())
		if cookieErr == nil {
			out.SetCookie = cookiesOut
		}
		out.Body.Status = true
		return out, nil
	})
}

// ChangeEmail registers POST /change-email.
func ChangeEmail(api huma.API, basePath string, opts types.Options) {
	huma.Register(api, huma.Operation{
		Tags:        []string{"Auth"},
		Method:      http.MethodPost,
		Path:        basePath + "/change-email",
		OperationID: "changeEmail",
		Summary:     "Change the current user's email",
	}, func(ctx context.Context, input *changeEmailInput) (*changeEmailOutput, error) {
		if !opts.User.ChangeEmail.Enabled {
			return nil, huma.NewError(types.StatusForCode(types.ErrChangeEmailDisabled), types.ErrChangeEmailDisabled)
		}

		token := sessionTokenFromRequest(input.Cookie, input.Authorization, opts)
		if token == "" {
			return nil, huma.NewError(types.StatusForCode(types.ErrFailedToGetSession), types.ErrFailedToGetSession)
		}

		sessionRow, userRow, refreshed, err := loadSessionAndUser(ctx, opts, token)
		if err != nil {
			if errors.Is(err, errSessionExpired) {
				// Kept 401 (differs from StatusForCode 400): expired-session auth
				// guard, matching upstream's 401-for-auth-failures convention. The
				// sole BAD_REQUEST throw site (update-user.ts:543) covers
				// delete-user freshness, which stays 400 (see DeleteUser below).
				return nil, huma.Error401Unauthorized(types.ErrSessionExpired)
			}
			return nil, huma.NewError(types.StatusForCode(types.ErrFailedToGetSession), types.ErrFailedToGetSession)
		}

		currentUser := rowToUser(userRow, opts)
		newEmail := strings.ToLower(input.Body.NewEmail)
		if newEmail == currentUser.Email {
			return nil, huma.Error400BadRequest("Email is the same")
		}

		canUpdateWithoutVerification := !currentUser.EmailVerified && opts.User.ChangeEmail.UpdateEmailWithoutVerification
		canSendVerification := opts.EmailVerification.SendVerificationEmail != nil || opts.EmailVerification.SendVerificationEmailRequest != nil
		// mints a change-email-verification send), so it additionally
		// requires the verification sender (upstream update-user.ts:750-752).
		canSendConfirmation := canSendVerification && currentUser.EmailVerified && (opts.User.ChangeEmail.SendChangeEmailConfirmation != nil || opts.User.ChangeEmail.SendChangeEmailConfirmationRequest != nil)
		if !canUpdateWithoutVerification && !canSendConfirmation && !canSendVerification {
			return nil, huma.Error400BadRequest("Verification email isn't enabled")
		}

		// Upstream originCheck guards the body callbackURL
		// (origin-check.ts): an untrusted value fails with 403
		// INVALID_CALLBACK_URL instead of being embedded in the mailed link.
		if input.Body.CallbackURL != nil && *input.Body.CallbackURL != "" {
			reqForTrust := trustRequest(ctx)
			if !types.IsTrustedRedirect(*input.Body.CallbackURL, opts, reqForTrust) {
				return nil, huma.NewError(types.StatusForCode(types.ErrInvalidCallbackURL), types.ErrInvalidCallbackURL)
			}
		}

		existingUser, err := opts.DB.FindOne(ctx, "user", []types.Where{
			{Field: "email", Value: newEmail},
		}, nil)
		if err != nil {
			return nil, huma.NewError(types.StatusForCode(types.ErrFailedToUpdateUser), types.ErrFailedToUpdateUser)
		}
		if existingUser != nil {
			// Simulate token generation to prevent timing attacks
			// (upstream update-user.ts:769-774 signs a verification JWT
			_, _ = crypto.CreateEmailVerificationToken(opts.CurrentSecret(), currentUser.Email, newEmail, emailVerificationExpirySeconds(opts), nil)
			// info while still answering success below.
			Logf(opts, "info", "Change email attempt for existing email")
			out := &changeEmailOutput{}
			if refreshed {
				cookie, cookieErr := newSessionCookie(opts, input.CookieRequestHeaders, token, sessionExpiresAt(sessionRow))
				if cookieErr == nil {
					out.SetCookie = []http.Cookie{cookie}
				}
			}
			out.Body.Status = true
			return out, nil
		}

		out := &changeEmailOutput{}
		if refreshed {
			cookie, cookieErr := newSessionCookie(opts, input.CookieRequestHeaders, token, sessionExpiresAt(sessionRow))
			if cookieErr == nil {
				out.SetCookie = []http.Cookie{cookie}
			}
		}

		callbackURL := "/"
		if input.Body.CallbackURL != nil && *input.Body.CallbackURL != "" {
			callbackURL = *input.Body.CallbackURL
		}

		if canUpdateWithoutVerification {
			updatedRow, err := opts.DB.Update(ctx, "user", []types.Where{
				{Field: "id", Value: currentUser.ID},
			}, map[string]any{
				"email":     newEmail,
				"updatedAt": time.Now().UTC(),
			})
			if err != nil {
				return nil, huma.NewError(types.StatusForCode(types.ErrFailedToUpdateUser), types.ErrFailedToUpdateUser)
			}
			currentUser.Email = newEmail
			if updatedRow != nil {
				if cookiesOut, cookieErr := newSessionCookies(opts, input.CookieRequestHeaders, token, rowToSession(sessionRow, opts), rowToUser(updatedRow, opts), opts.Session, time.Now().UTC()); cookieErr == nil {
					out.SetCookie = cookiesOut
				}
				if serr := refreshSecondaryUserSessions(opts, rowToUser(updatedRow, opts)); serr != nil {
					return nil, huma.NewError(types.StatusForCode(types.ErrFailedToUpdateUser), types.ErrFailedToUpdateUser)
				}
			}
			if canSendVerification {
				// Issuance is the upstream HS256 email JWT
				verificationToken, tokenErr := crypto.CreateEmailVerificationToken(opts.CurrentSecret(), newEmail, "", emailVerificationExpirySeconds(opts), nil)
				if tokenErr != nil {
					return nil, huma.NewError(types.StatusForCode(types.ErrFailedToCreateVerification), types.ErrFailedToCreateVerification)
				}
				sendVerificationEmailWithRequest(requestContextForCallbacks(ctx), opts, types.VerificationEmailData{
					User:  &currentUser,
					URL:   basePath + "/verify-email?token=" + verificationToken + "&callbackURL=" + url.QueryEscape(callbackURL),
					Token: verificationToken,
				})
			}
			out.Body.Status = true
			return out, nil
		}

		if canSendConfirmation {
			// Stateless upstream issuance: HS256 JWT with updateTo=newEmail
			confirmationToken, createErr := crypto.CreateEmailVerificationToken(opts.CurrentSecret(), currentUser.Email, newEmail, emailVerificationExpirySeconds(opts), map[string]any{"requestType": "change-email-confirmation"})
			if createErr != nil {
				return nil, huma.NewError(types.StatusForCode(types.ErrFailedToCreateVerification), types.ErrFailedToCreateVerification)
			}
			// Delivery failures never fail the route: upstream awaits via
			sendChangeEmailConfirmationMail(requestContextForCallbacks(ctx), opts, types.ChangeEmailData{
				User:     &currentUser,
				NewEmail: newEmail,
				URL:      basePath + "/verify-email?token=" + confirmationToken + "&callbackURL=" + url.QueryEscape(callbackURL),
				Token:    confirmationToken,
			})
			out.Body.Status = true
			return out, nil
		}

		// Stateless upstream issuance with
		verificationToken, createErr := crypto.CreateEmailVerificationToken(opts.CurrentSecret(), currentUser.Email, newEmail, emailVerificationExpirySeconds(opts), map[string]any{"requestType": "change-email-verification"})
		if createErr != nil {
			return nil, huma.NewError(types.StatusForCode(types.ErrFailedToCreateVerification), types.ErrFailedToCreateVerification)
		}
		verificationUser := currentUser
		verificationUser.Email = newEmail
		// Delivery failures never fail the route (see above).
		sendVerificationEmailWithRequest(requestContextForCallbacks(ctx), opts, types.VerificationEmailData{
			User:  &verificationUser,
			URL:   basePath + "/verify-email?token=" + verificationToken + "&callbackURL=" + url.QueryEscape(callbackURL),
			Token: verificationToken,
		})

		out.Body.Status = true
		return out, nil
	})
}

type deleteUserInput struct {
	Authorization string `header:"Authorization"`
	Cookie        string `header:"Cookie"`
	CookieRequestHeaders
	Body struct {
		CallbackURL *string `json:"callbackURL,omitempty"`
		Password    *string `json:"password,omitempty"`
		Token       *string `json:"token,omitempty"`
	}
}

type deleteUserOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
}

// DeleteUser registers POST /delete-user.
func DeleteUser(api huma.API, basePath string, opts types.Options) {
	registerAuthOperation(api, huma.Operation{
		Tags:        []string{"Auth"},
		Method:      http.MethodPost,
		Path:        basePath + "/delete-user",
		OperationID: "deleteUser",
		Summary:     "Delete the current user",
	}, opts, func(ctx context.Context, input *deleteUserInput) (*deleteUserOutput, error) {
		if !opts.User.DeleteUser.Enabled {
			return nil, huma.Error404NotFound("Not found")
		}

		token := sessionTokenFromRequest(input.Cookie, input.Authorization, opts)
		if token == "" {
			return nil, huma.NewError(types.StatusForCode(types.ErrFailedToGetSession), types.ErrFailedToGetSession)
		}

		sessionRow, userRow, _, err := loadSessionAndUser(ctx, opts, token)
		if err != nil {
			if errors.Is(err, errSessionExpired) {
				// Kept 401 (differs from StatusForCode 400): expired-session auth
				// guard, matching upstream's 401-for-auth-failures convention. The
				// sole BAD_REQUEST throw site (update-user.ts:543) covers
				// delete-user freshness, which stays 400 (see DeleteUser below).
				return nil, huma.Error401Unauthorized(types.ErrSessionExpired)
			}
			return nil, huma.NewError(types.StatusForCode(types.ErrFailedToGetSession), types.ErrFailedToGetSession)
		}

		userID, _ := sessionRow["userId"].(string)
		currentUser := rowToUser(userRow, opts)
		// Upstream originCheck guards the body callbackURL
		// (origin-check.ts): an untrusted value fails with 403
		// INVALID_CALLBACK_URL instead of being embedded in the mailed link.
		// Checked before any token issuance or mail dispatch so the
		// rejection is fail-closed with no side effects.
		if input.Body.CallbackURL != nil && *input.Body.CallbackURL != "" {
			reqForTrust := trustRequest(ctx)
			if !types.IsTrustedRedirect(*input.Body.CallbackURL, opts, reqForTrust) {
				return nil, huma.NewError(types.StatusForCode(types.ErrInvalidCallbackURL), types.ErrInvalidCallbackURL)
			}
		}
		if input.Body.Password != nil {
			accountRow, err := opts.DB.FindOne(ctx, "account", []types.Where{
				{Field: "userId", Value: userID},
				{Field: "providerId", Value: "credential", Connector: "AND"},
			}, nil)
			if err != nil || accountRow == nil {
				// Upstream throws BAD_REQUEST for a missing credential account
				// StatusForCode pins 400.
				return nil, huma.NewError(types.StatusForCode(types.ErrCredentialAccountNotFound), types.ErrCredentialAccountNotFound)
			}
			hash, _ := accountRow["password"].(string)
			valid, verifyErr := verifyPassword(opts, hash, *input.Body.Password)
			if verifyErr != nil {
				return nil, huma.Error500InternalServerError("failed to verify password")
			}
			if hash == "" || !valid {
				return nil, huma.NewError(types.StatusForCode(types.ErrInvalidPassword), types.ErrInvalidPassword)
			}
		}

		if input.Body.Token != nil {
			// even on a stale session, so no freshness check applies here.
			// the single-use token is consumed atomically first (burned even
			storedUserID, consumeErr := consumeDeleteAccountToken(ctx, opts, *input.Body.Token)
			if consumeErr != nil || storedUserID != userID {
				// deleteUserCallback, which throws NOT_FOUND with INVALID_TOKEN
				// on a bad or owner-mismatch token (update-user.ts:492-499,
				// :641-642); the GET callback path already 404s. Mirror that
				// 404 here even though StatusForCode maps INVALID_TOKEN to 401.
				return nil, huma.Error404NotFound(types.ErrInvalidToken)
			}
			if err := finishDeleteUser(ctx, opts, userID, currentUser); err != nil {
				// A hook-thrown APIError keeps its own status (upstream
				// beforeDelete/afterDelete are awaited directly, so a thrown
				var httpErr types.HttpError
				if errors.As(err, &httpErr) {
					return nil, huma.NewError(httpErr.Status, httpErr.Code)
				}
				// Kept 500 (differs from StatusForCode 401 for INVALID_USER):
				// delete-transaction/hook failure, not a semantic invalid user.
				return nil, huma.Error500InternalServerError(types.ErrInvalidUser)
			}
			out := &deleteUserOutput{}
			out.SetCookie = expiredSessionCookies(opts, input.CookieRequestHeaders)
			out.Body.Success = true
			out.Body.Message = "User deleted"
			return out, nil
		}

		if opts.User.DeleteUser.SendDeleteAccountVerification != nil || opts.User.DeleteUser.SendDeleteAccountVerificationRequest != nil {
			deleteToken, createErr := createDeleteAccountVerification(ctx, opts, userID)
			if createErr != nil {
				return nil, huma.NewError(types.StatusForCode(types.ErrFailedToCreateVerification), types.ErrFailedToCreateVerification)
			}
			callbackURL := "/"
			if input.Body.CallbackURL != nil && *input.Body.CallbackURL != "" {
				callbackURL = *input.Body.CallbackURL
			}
			// Delivery failures never fail the route: upstream awaits via
			sendDeleteAccountVerificationMail(ctx, opts, types.DeleteAccountVerificationData{
				User:  &currentUser,
				URL:   basePath + "/delete-user/callback?token=" + deleteToken + "&callbackURL=" + url.QueryEscape(callbackURL),
				Token: deleteToken,
			})
			out := &deleteUserOutput{}
			out.Body.Success = true
			out.Body.Message = "Verification email sent"
			return out, nil
		}

		freshAge := sessionFreshAge(opts.Session)
		if input.Body.Password == nil && freshAge > 0 {
			createdAt, _ := sessionRow["createdAt"].(time.Time)
			if !createdAt.IsZero() && time.Since(createdAt) >= freshAge {
				return nil, huma.NewError(types.StatusForCode(types.ErrSessionExpired), types.ErrSessionExpired)
			}
		}

		if err := finishDeleteUser(ctx, opts, userID, currentUser); err != nil {
			// path above); non-APIError delete failures stay 500.
			var httpErr types.HttpError
			if errors.As(err, &httpErr) {
				return nil, huma.NewError(httpErr.Status, httpErr.Code)
			}
			// Kept 500 (differs from StatusForCode 401 for INVALID_USER):
			// delete-transaction/hook failure, not a semantic invalid user.
			return nil, huma.Error500InternalServerError(types.ErrInvalidUser)
		}

		out := &deleteUserOutput{}
		out.SetCookie = expiredSessionCookies(opts, input.CookieRequestHeaders)
		out.Body.Success = true
		out.Body.Message = "User deleted"
		return out, nil
	})
}

type changeEmailVerificationPayload struct {
	CurrentEmail string `json:"currentEmail"`
	NewEmail     string `json:"newEmail"`
	RequestType  string `json:"requestType"`
}

func createChangeEmailVerification(ctx context.Context, opts types.Options, currentEmail, newEmail, requestType string, ttl time.Duration) (string, error) {
	now := time.Now().UTC()
	// The token is randomness (upstream change-email tokens are stateless
	// honors the context generator (upstream createVerificationValue flows
	token := crypto.GenerateID()
	payload, err := json.Marshal(changeEmailVerificationPayload{
		CurrentEmail: strings.ToLower(currentEmail),
		NewEmail:     strings.ToLower(newEmail),
		RequestType:  requestType,
	})
	if err != nil {
		return "", err
	}
	identifier := changeEmailIdentifier(token)
	stored, err := processVerificationIdentifier(identifier, resolveVerificationStoreOption(identifier, opts.Verification.StoreIdentifier))
	if err != nil {
		return "", err
	}
	verificationID, verificationHasID := mintModelID(opts, "verification")
	row := map[string]any{
		"identifier": stored,
		"value":      string(payload),
		"expiresAt":  now.Add(ttl),
		"createdAt":  now,
		"updatedAt":  now,
	}
	setRowID(row, verificationID, verificationHasID)
	// Mirror upstream createVerificationValue (executeMainFn:
	// written only with Verification.StoreInDatabase (or when no secondary
	if opts.SecondaryStorage != nil {
		if err := writeSecondaryVerification(opts, identifier, row); err != nil {
			return "", err
		}
	}
	if opts.DB != nil && (opts.SecondaryStorage == nil || opts.Verification.StoreInDatabase) {
		if _, err := opts.DB.Create(ctx, "verification", row, nil); err != nil {
			return "", err
		}
	}
	return token, nil
}

func createDeleteAccountVerification(ctx context.Context, opts types.Options, userID string) (string, error) {
	now := time.Now().UTC()
	token := crypto.GenerateID()
	ttl := 24 * time.Hour
	if opts.User.DeleteUser.DeleteTokenExpiresIn > 0 {
		ttl = time.Duration(opts.User.DeleteUser.DeleteTokenExpiresIn) * time.Second
	}
	identifier := deleteAccountIdentifier(token)
	stored, err := processVerificationIdentifier(identifier, resolveVerificationStoreOption(identifier, opts.Verification.StoreIdentifier))
	if err != nil {
		return "", err
	}
	verificationID, verificationHasID := mintModelID(opts, "verification")
	row := map[string]any{
		"identifier": stored,
		"value":      userID,
		"expiresAt":  now.Add(ttl),
		"createdAt":  now,
		"updatedAt":  now,
	}
	setRowID(row, verificationID, verificationHasID)
	// Mirror upstream createVerificationValue (executeMainFn:
	// written only with Verification.StoreInDatabase (or when no secondary
	if opts.SecondaryStorage != nil {
		if err := writeSecondaryVerification(opts, identifier, row); err != nil {
			return "", err
		}
	}
	if opts.DB != nil && (opts.SecondaryStorage == nil || opts.Verification.StoreInDatabase) {
		if _, err := opts.DB.Create(ctx, "verification", row, nil); err != nil {
			return "", err
		}
	}
	return token, nil
}

var errDeleteTokenNotFound = errors.New("delete token not found")

// consumeDeleteAccountToken atomically consumes the single-use delete-account
// verification row for token across both stores, mirroring upstream
// consumeVerificationValue: the first concurrent caller wins and every racer
// userID on success (callers still check ownership).
func consumeDeleteAccountToken(ctx context.Context, opts types.Options, token string) (string, error) {
	identifier := deleteAccountIdentifier(token)
	if opts.SecondaryStorage != nil && !opts.Verification.StoreInDatabase {
		row, err := consumeSecondaryVerification(opts, identifier)
		if err != nil {
			return "", err
		}
		if row == nil {
			return "", errDeleteTokenNotFound
		}
		// Single expiry gate (upstream consumeVerificationValue): a row past
		// its expiresAt is already consumed (deleted above), so it reports
		// not-found and can never be replayed.
		if expiresAt, _ := row["expiresAt"].(time.Time); expiresAt.IsZero() || time.Now().UTC().After(expiresAt) {
			return "", errDeleteTokenNotFound
		}
		userID, _ := row["value"].(string)
		if userID == "" {
			return "", errDeleteTokenNotFound
		}
		return userID, nil
	}
	var userID string
	consumed := false
	if opts.DB != nil {
		option := resolveVerificationStoreOption(identifier, opts.Verification.StoreIdentifier)
		stored, err := processVerificationIdentifier(identifier, option)
		if err != nil {
			return "", err
		}
		// Atomic consume via the adapter race gate
		// (db.ConsumeOneWithFallback): the first concurrent caller wins and
		candidates := verificationCandidates(option, identifier, stored)
		var row map[string]any
		for _, candidate := range candidates {
			consumed, cerr := db.ConsumeOneWithFallback(ctx, opts.DB, "verification", []types.Where{
				{Field: "identifier", Value: candidate},
			})
			if cerr != nil {
				return "", cerr
			}
			if consumed != nil {
				row = consumed
				break
			}
		}
		if row == nil {
			return "", errDeleteTokenNotFound
		}
		for _, candidate := range candidates {
			_ = opts.DB.Delete(ctx, "verification", []types.Where{
				{Field: "identifier", Value: candidate},
			})
		}
		expiresAt, _ := row["expiresAt"].(time.Time)
		live := !expiresAt.IsZero() && !time.Now().UTC().After(expiresAt)
		if v, _ := row["value"].(string); v != "" && live {
			userID = v
		}
		if userID != "" {
			consumed = true
		}
	}
	if opts.SecondaryStorage != nil && consumed {
		_ = deleteSecondaryVerification(opts, identifier)
	}
	if !consumed {
		return "", errDeleteTokenNotFound
	}
	return userID, nil
}

// the user/session/account deletes. Upstream runs those deletes as sequential
// intentional hardening (all-or-nothing instead of partial state on mid-flow
// failure).
func finishDeleteUser(ctx context.Context, opts types.Options, userID string, user types.User) error {
	if err := runBeforeDeleteHook(ctx, &opts.User.DeleteUser, &user); err != nil {
		return err
	}
	if err := deleteUserRecords(ctx, opts.DB, userID); err != nil {
		return err
	}
	// the transactional delete above purges only DB rows, so without this
	if opts.SecondaryStorage != nil {
		if err := deleteSecondaryAwareUserSessions(ctx, opts, userID); err != nil {
			return err
		}
	}
	if err := runAfterDeleteHook(ctx, &opts.User.DeleteUser, &user); err != nil {
		return err
	}
	return nil
}

func deleteUserRecords(ctx context.Context, db types.Adapter, userID string) error {
	return db.Transaction(ctx, func(tx types.Adapter) error {
		if _, err := tx.DeleteMany(ctx, "session", []types.Where{{Field: "userId", Value: userID}}); err != nil {
			return err
		}
		if _, err := tx.DeleteMany(ctx, "account", []types.Where{{Field: "userId", Value: userID}}); err != nil {
			return err
		}
		return tx.Delete(ctx, "user", []types.Where{{Field: "id", Value: userID}})
	})
}

func changeEmailTokenTTL(expiresIn int) time.Duration {
	if expiresIn <= 0 {
		return time.Hour
	}
	return time.Duration(expiresIn) * time.Second
}

func sessionFreshAge(opts types.SessionOptions) time.Duration {
	age, enabled := opts.FreshAgeDuration()
	if !enabled {
		return 0
	}
	return age
}

func changeEmailIdentifier(token string) string {
	return "change-email:" + token
}

// Upstream TypeScript value: `delete-account-${token}` (update-user.ts).
func deleteAccountIdentifier(token string) string {
	return "delete-account-" + token
}


type changePasswordInput struct {
	Authorization string `header:"Authorization"`
	Cookie        string `header:"Cookie"`
	CookieRequestHeaders
	Body struct {
		CurrentPassword string `json:"currentPassword" required:"true"`
		NewPassword     string `json:"newPassword" required:"true"`
		// RevokeOtherSessions mirrors upstream's revokeOtherSessions
		RevokeOtherSessions *bool `json:"revokeOtherSessions,omitempty"`
	}
}

type changePasswordOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      struct {
		Status bool      `json:"status"`
		Token  *string   `json:"token"`
		User   *flatUser `json:"user,omitempty"`
	}
}

// ChangePassword registers POST /change-password.
func ChangePassword(api huma.API, basePath string, opts types.Options) {
	registerAuthOperation(api, huma.Operation{
		Tags:        []string{"Auth"},
		Method:      http.MethodPost,
		Path:        basePath + "/change-password",
		OperationID: "changePassword",
		Summary:     "Change password for authenticated user",
	}, opts, func(ctx context.Context, input *changePasswordInput) (*changePasswordOutput, error) {
		token := sessionTokenFromRequest(input.Cookie, input.Authorization, opts)
		if token == "" {
			return nil, huma.NewError(types.StatusForCode(types.ErrFailedToGetSession), types.ErrFailedToGetSession)
		}

		sessionRow, err := opts.DB.FindOne(ctx, "session", []types.Where{
			{Field: "token", Value: token},
		}, nil)
		if err != nil || sessionRow == nil {
			// Kept 401 (differs from StatusForCode 400): expired-session auth
			// guard, matching upstream's 401-for-auth-failures convention. The
			// sole BAD_REQUEST throw site (update-user.ts:543) covers
			// delete-user freshness, which stays 400 (see DeleteUser).
			return nil, huma.Error401Unauthorized(types.ErrSessionExpired)
		}

		userID, _ := sessionRow["userId"].(string)

		// Upstream validates the new password length before touching the
		if len(input.Body.NewPassword) < passwordMinLength(opts) {
			return nil, huma.NewError(types.StatusForCode(types.ErrPasswordTooShort), types.ErrPasswordTooShort)
		}
		if len(input.Body.NewPassword) > passwordMaxLength(opts) {
			return nil, huma.NewError(types.StatusForCode(types.ErrPasswordTooLong), types.ErrPasswordTooLong)
		}

		accountRow, err := opts.DB.FindOne(ctx, "account", []types.Where{
			{Field: "userId", Value: userID},
			{Field: "providerId", Value: "credential", Connector: "AND"},
		}, nil)
		if err != nil || accountRow == nil {
			// Upstream throws BAD_REQUEST for a missing credential account
			// StatusForCode pins 400.
			return nil, huma.NewError(types.StatusForCode(types.ErrCredentialAccountNotFound), types.ErrCredentialAccountNotFound)
		}

		// (update-user.ts:276-283): a hashing failure breaks before any
		hash, err := hashPassword(opts, input.Body.NewPassword)
		if err != nil {
			return nil, huma.Error500InternalServerError("failed to hash password")
		}

		storedHash, _ := accountRow["password"].(string)
		valid, verifyErr := verifyPassword(opts, storedHash, input.Body.CurrentPassword)
		if verifyErr != nil {
			return nil, huma.Error500InternalServerError("failed to verify password")
		}
		if !valid {
			return nil, huma.NewError(types.StatusForCode(types.ErrInvalidPassword), types.ErrInvalidPassword)
		}

		now := time.Now().UTC()
		_, err = opts.DB.Update(ctx, "account", []types.Where{
			{Field: "userId", Value: userID},
			{Field: "providerId", Value: "credential", Connector: "AND"},
		}, map[string]any{
			"password":  hash,
			"updatedAt": now,
		})
		if err != nil {
			return nil, huma.Error500InternalServerError("failed to update password")
		}

		out := &changePasswordOutput{}
		out.Body.Status = true
		// field stays true so existing clients keep working.
		if input.Body.RevokeOtherSessions != nil && *input.Body.RevokeOtherSessions {
			if err := deleteSecondaryAwareUserSessions(ctx, opts, userID); err != nil {
				return nil, huma.Error500InternalServerError("failed to revoke sessions")
			}
			newToken := crypto.GenerateID()
			newExpires := now.Add(opts.Session.ExpiresInDuration())
			session, serr := createIssuedSession(ctx, opts, userID, newToken, newExpires, now)
			if serr != nil {
				return nil, huma.NewError(types.StatusForCode(types.ErrFailedToGetSession), types.ErrFailedToGetSession)
			}
			userRow, uerr := opts.DB.FindOne(ctx, "user", []types.Where{
				{Field: "id", Value: userID},
			}, nil)
			if uerr != nil || userRow == nil {
				return nil, huma.NewError(types.StatusForCode(types.ErrUserNotFound), types.ErrUserNotFound)
			}
			user := rowToUser(userRow, opts)
			if serr := writeSecondarySession(opts, session, user); serr != nil {
				return nil, huma.NewError(types.StatusForCode(types.ErrFailedToCreateSession), types.ErrFailedToCreateSession)
			}
			// cookie-only clients need the replacement session cookie, not
			// just the in-body token. A mint failure fails the route 500
			// (FAILED_TO_CREATE_SESSION, canonical 500); the already-minted
			// session row is kept (upstream create-then-cookie order, no
			cookiesOut, cookieErr := newSessionCookies(opts, input.CookieRequestHeaders, newToken, session, user, opts.Session, now)
			if cookieErr != nil {
				return nil, huma.NewError(types.StatusForCode(types.ErrFailedToCreateSession), types.ErrFailedToCreateSession)
			}
			out.SetCookie = cookiesOut
			out.Body.Token = &newToken
			flat := flatUser(user)
			out.Body.User = &flat
		} else {
			userRow, uerr := opts.DB.FindOne(ctx, "user", []types.Where{
				{Field: "id", Value: userID},
			}, nil)
			if uerr != nil || userRow == nil {
				return nil, huma.NewError(types.StatusForCode(types.ErrUserNotFound), types.ErrUserNotFound)
			}
			user := rowToUser(userRow, opts)
			flat := flatUser(user)
			out.Body.User = &flat
		}
		return out, nil
	})
}
