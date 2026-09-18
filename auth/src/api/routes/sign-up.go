package routes

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/brick-org/brick/auth/src/crypto"
	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
)

type signUpInput struct {
	CookieRequestHeaders
	Body struct {
		Name     string  `json:"name" required:"true"`
		Email    string  `json:"email" format:"email" required:"true"`
		Password string  `json:"password" required:"true"`
		Image    *string `json:"image,omitempty"`
		// CallbackURL feeds the email-verification link (upstream
		// sign-up.ts:402-405; "/" when absent).
		CallbackURL *string `json:"callbackURL,omitempty"`
		// RememberMe mirrors upstream's rememberMe (sign-up.ts:24,86-90):
		// explicit false creates a non-persistent session (1-day expiry
		// plus the dont_remember marker); absent or true remembers.
		RememberMe *bool `json:"rememberMe,omitempty"`
	}
}

type signUpOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      struct {
		Token *string    `json:"token"`
		User  types.User `json:"user"`
	}
}

// SignUpEmail registers POST /sign-up/email.
func SignUpEmail(api huma.API, basePath string, opts types.Options) {
	registerAuthOperation(api, huma.Operation{
		Tags:        []string{"Auth"},
		Method:      http.MethodPost,
		Path:        basePath + "/sign-up/email",
		OperationID: "signUpWithEmailAndPassword",
		Summary:     "Sign up with email and password",
	}, opts, func(ctx context.Context, input *signUpInput) (*signUpOutput, error) {
		if !opts.EmailAndPassword.Enabled || opts.EmailAndPassword.DisableSignUp {
			return nil, huma.Error400BadRequest("email/password sign-up is not enabled")
		}

		if len(input.Body.Password) < passwordMinLength(opts) {
			return nil, huma.NewError(types.StatusForCode(types.ErrPasswordTooShort), types.ErrPasswordTooShort)
		}
		if len(input.Body.Password) > passwordMaxLength(opts) {
			return nil, huma.NewError(types.StatusForCode(types.ErrPasswordTooLong), types.ErrPasswordTooLong)
		}

		email := strings.ToLower(input.Body.Email)
		shouldReturnGenericDuplicateResponse := opts.EmailAndPassword.RequireEmailVerification
		shouldSkipAutoSignIn := !autoSignInEnabled(opts) || shouldReturnGenericDuplicateResponse

		// Check for duplicate
		existing, err := opts.DB.FindOne(ctx, "user", []types.Where{
			{Field: "email", Value: email},
		}, nil)
		if err != nil {
			return nil, huma.Error500InternalServerError("failed to check existing user")
		}
		if existing != nil {
			if shouldReturnGenericDuplicateResponse {
				if _, err := hashPassword(opts, input.Body.Password); err != nil {
					return nil, huma.Error500InternalServerError("failed to hash password")
				}
				// Upstream passes (data, request) via safeCloneRequest and
				// awaits via runInBackgroundOrAwait (sign-up.ts:319-326): the
				// request-aware variant wins when set; delivery runs in the
				// background and never fails the opaque success.
				if opts.EmailAndPassword.OnExistingUserSignUpRequest != nil {
					user := rowToUser(existing, opts)
					req := StoredRequestFromStd(ctx)
					if req == nil {
						req = callbackRequest(ctx)
					}
					data := types.ExistingUserSignUpData{User: &user}
					runBackgroundOrAwait(opts, func() error {
						return opts.EmailAndPassword.OnExistingUserSignUpRequest(data, req)
					})
				} else if opts.EmailAndPassword.OnExistingUserSignUp != nil {
					user := rowToUser(existing, opts)
					data := types.ExistingUserSignUpData{User: &user}
					runBackgroundOrAwait(opts, func() error {
						return opts.EmailAndPassword.OnExistingUserSignUp(data)
					})
				}
				now := time.Now().UTC()
				// Upstream buildGenericDuplicateResponse mints one context ID
				// shared by the synthetic row and the custom synthesizer
				// (`ctx.context.generateId({model:"user"}) || generateId()`):
				// the synthetic user is never persisted, so a generator that
				// defers to the database falls back to random here.
				syntheticID, syntheticHasID := mintModelID(opts, "user")
				if !syntheticHasID || syntheticID == "" {
					syntheticID = crypto.GenerateID()
				}
				syntheticRow := map[string]any{
					"id":            syntheticID,
					"email":         email,
					"emailVerified": false,
					"name":          input.Body.Name,
					"image":         input.Body.Image,
					"createdAt":     now,
					"updatedAt":     now,
				}
				if opts.EmailAndPassword.CustomSyntheticUser != nil {
					syntheticRow = opts.EmailAndPassword.CustomSyntheticUser(types.SyntheticUserData{
						ID: syntheticID,
						CoreFields: types.SyntheticUserCoreFields{
							Name:          input.Body.Name,
							Email:         email,
							EmailVerified: false,
							Image:         input.Body.Image,
							CreatedAt:     now,
							UpdatedAt:     now,
						},
						AdditionalFields: map[string]any{},
					})
				}
				out := &signUpOutput{}
				out.Body.Token = nil
				out.Body.User = rowToUser(syntheticRow, opts)
				return out, nil
			}
			return nil, huma.NewError(types.StatusForCode(types.ErrUserAlreadyExistsUseAnotherEmail), types.ErrUserAlreadyExistsUseAnotherEmail)
		}

		// ValidateUserInfo create seam (upstream internalAdapter.createUser ->
		// assertValidUserInfo, method email-password, action create-user).
		// Programmatic flow: rejection surfaces 403; under generic-duplicate
		// mode the rejection returns the same opaque success as an existing
		// email (sign-up.ts:366-368) to close enumeration.
		if err := assertValidUserInfoLocal(ctx, opts, map[string]any{
			"email": email, "name": input.Body.Name,
		}, types.ValidateUserInfoSource{
			Action: types.ValidateUserInfoActionCreateUser,
			Method: types.ValidateUserInfoMethodEmailPassword,
		}); err != nil {
			if httpErr, ok := err.(types.HttpError); ok && httpErr.Status == 403 && shouldReturnGenericDuplicateResponse {
				if _, herr := hashPassword(opts, input.Body.Password); herr != nil {
					return nil, huma.Error500InternalServerError("failed to hash password")
				}
				now := time.Now().UTC()
				syntheticID, syntheticHasID := mintModelID(opts, "user")
				if !syntheticHasID || syntheticID == "" {
					syntheticID = crypto.GenerateID()
				}
				syntheticRow := map[string]any{
					"id": syntheticID, "email": email, "emailVerified": false,
					"name": input.Body.Name, "image": input.Body.Image,
					"createdAt": now, "updatedAt": now,
				}
				out := &signUpOutput{}
				out.Body.Token = nil
				out.Body.User = rowToUser(syntheticRow, opts)
				return out, nil
			}
			return nil, huma.NewError(403, err.Error())
		}

		hash, err := hashPassword(opts, input.Body.Password)
		if err != nil {
			return nil, huma.Error500InternalServerError("failed to hash password")
		}

		now := time.Now().UTC()
		// Model-row IDs honor the context generator (upstream adapter
		// defaultValue honoring generateId): mint user/account IDs, omit
		// them when generation defers to the database, and consume the
		// persisted-row return so adapter/database-issued IDs win.
		userID, userHasID := mintModelID(opts, "user")

		userData := map[string]any{
			"email":         email,
			"emailVerified": false,
			"name":          input.Body.Name,
			"image":         input.Body.Image,
			"createdAt":     now,
			"updatedAt":     now,
		}
		setRowID(userData, userID, userHasID)
		// Upstream wraps creation in runWithTransaction (sign-up.ts:183): the
		// user + credential-account writes commit atomically with rollback on
		// failure (no orphan user when the account link fails).
		var userRow map[string]any
		txErr := opts.DB.Transaction(ctx, func(tx types.Adapter) error {
			created, err := tx.Create(ctx, "user", userData, nil)
			if err != nil {
				return err
			}
			createdID := persistedRowID(created, userID)
			accountID, accountHasID := mintModelID(opts, "account")
			accountData := map[string]any{
				"userId":     createdID,
				"providerId": "credential",
				"accountId":  createdID,
				"password":   hash,
				"createdAt":  now,
				"updatedAt":  now,
			}
			setRowID(accountData, accountID, accountHasID)
			if _, err := tx.Create(ctx, "account", accountData, nil); err != nil {
				return err
			}
			userRow = created
			userID = createdID
			return nil
		})
		if txErr != nil {
			// A post-commit after-hook failure (D05: flush fails the
			// Transaction call after the rows committed) surfaces the
			// hook's own error identity — mirroring upstream
			// organization-hook.test.ts, which expects the hook's code
			// (e.g. ORGANIZATION_ALREADY_EXISTS) as the sign-up response
			// with the user row kept. Creation failures keep 422 below.
			var httpErr types.HttpError
			if errors.As(txErr, &httpErr) {
				return nil, huma.NewError(httpErr.Status, httpErr.Code)
			}
			// Upstream throws UNPROCESSABLE_ENTITY when user creation fails
			// (sign-up.ts:375-384; majority over the BAD_REQUEST at :356-359).
			return nil, huma.NewError(types.StatusForCode(types.ErrFailedToCreateUser), types.ErrFailedToCreateUser)
		}

		shouldSendVerificationEmail := opts.EmailVerification.SendOnSignUp || opts.EmailAndPassword.RequireEmailVerification
		if shouldSendVerificationEmail && (opts.EmailVerification.SendVerificationEmail != nil || opts.EmailVerification.SendVerificationEmailRequest != nil) {
			// Issuance is the upstream HS256 email JWT
			// (createEmailVerificationToken, email-verification.ts:17-43).
			token, err := crypto.CreateEmailVerificationToken(opts.CurrentSecret(), email, "", emailVerificationExpirySeconds(opts), nil)
			if err != nil {
				return nil, huma.Error500InternalServerError("failed to generate verification token")
			}
			url := fmt.Sprintf("%s/verify-email?token=%s&callbackURL=%s", opts.BasePath, token, verificationCallbackURL(input.Body.CallbackURL))
			user := rowToUser(userRow, opts)
			// Upstream awaits via runInBackgroundOrAwait (sign-up.ts:408-417):
			// delivery failures are logged and swallowed, the route still
			// answers success. Prefer the request-aware variant when set.
			wctx := requestContextForCallbacks(ctx)
			sendVerificationEmailWithRequest(wctx, opts, types.VerificationEmailData{User: &user, URL: url, Token: token})
		}

		if shouldSkipAutoSignIn {
			out := &signUpOutput{}
			out.Body.Token = nil
			out.Body.User = rowToUser(userRow, opts)
			return out, nil
		}

		// The session token is caller-minted randomness (upstream token:
		// generateId(32) direct, bypassing the context generator); the row
		// itself goes through the shared issuance seam so secondary-only
		// deployments skip the primary DB (upstream createSession
		// executeMainFn: storeInDb).
		token := crypto.GenerateID()

		// Explicit rememberMe=false creates a non-persistent session
		// (upstream createSession dontRememberMe, internal-adapter.ts:509).
		dontRememberMe := input.Body.RememberMe != nil && !*input.Body.RememberMe
		expiresAt := creationSessionExpiry(opts, dontRememberMe, now)

		session, err := createIssuedSession(ctx, opts, userID, token, expiresAt, now)
		if err != nil {
			return nil, huma.NewError(types.StatusForCode(types.ErrFailedToCreateSession), types.ErrFailedToCreateSession)
		}

		user := rowToUser(userRow, opts)
		out := &signUpOutput{}
		// Mirror the pair into secondary storage when configured (upstream
		// createSession mirroring, internal-adapter.ts:520-564). A failing
		// mirror fails issuance loudly, like the database create above.
		if err := writeSecondarySession(opts, session, user); err != nil {
			return nil, huma.NewError(types.StatusForCode(types.ErrFailedToCreateSession), types.ErrFailedToCreateSession)
		}
		cookiesOut, err := issueSessionCookies(opts, input.CookieRequestHeaders, token, session, user, opts.Session, now, dontRememberMe)
		if err != nil {
			return nil, huma.NewError(types.StatusForCode(types.ErrFailedToCreateSession), types.ErrFailedToCreateSession)
		}
		out.SetCookie = cookiesOut
		out.Body.Token = &token
		out.Body.User = user
		return out, nil
	})
}

// verificationCallbackURL resolves the verification-link callback: the
// request callbackURL when present, "/" otherwise (upstream sign-up.ts:402-405
// and sign-in.ts:584-587).
func verificationCallbackURL(callbackURL *string) string {
	if callbackURL != nil && *callbackURL != "" {
		return *callbackURL
	}
	return "/"
}

func rowToUser(row map[string]any, opts types.Options) types.User {
	u := types.User{}
	if v := stringField(row, "id"); v != "" {
		u.ID = v
	}
	if v := stringField(row, "email"); v != "" {
		u.Email = v
	}
	if v, ok := boolField(row, "email_verified", "emailVerified"); ok {
		u.EmailVerified = v
	}
	if v := stringField(row, "name"); v != "" {
		u.Name = v
	}
	if v := stringField(row, "image"); v != "" {
		u.Image = &v
	}
	if v, ok := timeField(row, "created_at", "createdAt"); ok {
		u.CreatedAt = v
	}
	if v, ok := timeField(row, "updated_at", "updatedAt"); ok {
		u.UpdatedAt = v
	}
	u.AdditionalFields = ExtractAdditionalFieldsFull(row, fullUserFields(opts), isCoreUserColumn)
	if len(u.AdditionalFields) == 0 {
		u.AdditionalFields = nil
	}
	return u
}

func isCoreUserColumn(key string) bool {
	switch key {
	case "id", "email", "email_verified", "emailVerified", "name", "image", "created_at", "createdAt", "updated_at", "updatedAt":
		return true
	default:
		return false
	}
}

func passwordMinLength(opts types.Options) int {
	if opts.EmailAndPassword.MinPasswordLength == 0 {
		return 8
	}
	return opts.EmailAndPassword.MinPasswordLength
}

func passwordMaxLength(opts types.Options) int {
	if opts.EmailAndPassword.MaxPasswordLength == 0 {
		return 128
	}
	return opts.EmailAndPassword.MaxPasswordLength
}

func autoSignInEnabled(opts types.Options) bool {
	return opts.EmailAndPassword.AutoSignIn == nil || *opts.EmailAndPassword.AutoSignIn
}

func hashPassword(opts types.Options, password string) (string, error) {
	if opts.EmailAndPassword.Password.Hash != nil {
		return opts.EmailAndPassword.Password.Hash(password)
	}
	return crypto.HashPassword(password)
}

func verifyPassword(opts types.Options, hash, password string) (bool, error) {
	if opts.EmailAndPassword.Password.Verify != nil {
		return opts.EmailAndPassword.Password.Verify(types.PasswordVerifyData{
			Hash:     hash,
			Password: password,
		})
	}
	return crypto.VerifyPassword(hash, password), nil
}

// assertValidUserInfoLocal mirrors upstream assertValidUserInfo
// (utils/validate-user-info.ts) without importing the root auth package
// (routes cannot import it: auth/index.go imports routes, so that would
// cycle). A nil hook allows; a throwing hook fails closed as
// validation_failed (403); a gate result with Error maps to that code with
// ErrorDescription (or Error) as the message. Source validation requires
// the method (oauth additionally requires a provider id; sso-oidc/sso-saml
// require a provider id), failing closed as validation_source_missing.
func assertValidUserInfoLocal(ctx context.Context, opts types.Options, user map[string]any, src types.ValidateUserInfoSource) error {
	hook := opts.User.ValidateUserInfo
	if hook == nil {
		return nil
	}
	if src.Method == "" {
		return types.HttpError{Code: "validation_source_missing", Message: "User validation source is required", Status: 403}
	}
	if src.Method == types.ValidateUserInfoMethodOAuth && src.ProviderID == "" {
		return types.HttpError{Code: "validation_source_missing", Message: "OAuth user validation source requires oauth.providerId", Status: 403}
	}
	if (src.Method == types.ValidateUserInfoMethodSSOOIDC || src.Method == types.ValidateUserInfoMethodSSOSAML) && src.ProviderID == "" {
		return types.HttpError{Code: "validation_source_missing", Message: "SSO user validation source requires sso.providerId", Status: 403}
	}
	req := StoredRequestFromStd(ctx)
	if req == nil {
		req = callbackRequest(ctx)
	}
	epCtx := types.RequestEndpointContext(req, types.AuthContext{}, "", "")
	result, err := hook(types.ValidateUserInfoData{User: user, Source: src}, epCtx)
	if err != nil {
		return types.HttpError{Code: "validation_failed", Message: "User validation failed", Status: 403}
	}
	if result != nil && result.Error != "" {
		msg := result.ErrorDescription
		if msg == "" {
			msg = result.Error
		}
		return types.HttpError{Code: result.Error, Message: msg, Status: 403}
	}
	return nil
}

// requestContextForCallbacks wraps ctx so request-aware callbacks receive
// the live request: prefer the middleware-reconstructed stored request,
// falling back to the huma-rebuilt one. Both may be nil outside the
// middleware pipeline; callbacks must tolerate nil (upstream invokes with
// request undefined in those cases).
func requestContextForCallbacks(ctx context.Context) context.Context {
	if StoredRequestFromStd(ctx) != nil {
		return ctx
	}
	if req := callbackRequest(ctx); req != nil {
		return context.WithValue(ctx, storedRequestKey{}, req)
	}
	return ctx
}

func stringField(row map[string]any, keys ...string) string {
	for _, key := range keys {
		if v, _ := row[key].(string); v != "" {
			return v
		}
	}
	return ""
}

func boolField(row map[string]any, keys ...string) (bool, bool) {
	for _, key := range keys {
		if v, ok := row[key].(bool); ok {
			return v, true
		}
	}
	return false, false
}

func timeField(row map[string]any, keys ...string) (time.Time, bool) {
	for _, key := range keys {
		if v, ok := row[key].(time.Time); ok {
			return v, true
		}
	}
	return time.Time{}, false
}
