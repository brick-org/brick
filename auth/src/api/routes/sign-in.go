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

// Fixed Better Auth-compatible scrypt hash used to equalize unknown-user
// password work without creating a fresh hash on each failed request.
const dummyPasswordHash = "000102030405060708090a0b0c0d0e0f:a19e0608dfb1eddd747ebea06aa44ba8e5ce829ab792340ee8c6a4665d850f912e26dae00afd3f9f51fd1320dfa27c9fe1288a527494da28d7e2ec37a9c4fbde"

type signInInput struct {
	CookieRequestHeaders
	Body struct {
		Email    string `json:"email" required:"true"`
		Password string `json:"password" required:"true"`
		// CallbackURL drives the redirect/url response pair (upstream
		// sign-in.ts:625-632).
		CallbackURL *string `json:"callbackURL,omitempty"`
		// RememberMe mirrors upstream's rememberMe (sign-in.ts:436-443):
		// explicit false creates a non-persistent session (1-day expiry
		// plus the dont_remember marker); absent or true remembers.
		RememberMe *bool `json:"rememberMe,omitempty"`
	}
}

type signInOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      struct {
		Token    string     `json:"token"`
		Redirect bool       `json:"redirect"`
		URL      *string    `json:"url,omitempty"`
		User     types.User `json:"user"`
	}
}

// SignInEmail registers POST /sign-in/email.
func SignInEmail(api huma.API, basePath string, opts types.Options) {
	registerAuthOperation(api, huma.Operation{
		Tags:        []string{"Auth"},
		Method:      http.MethodPost,
		Path:        basePath + "/sign-in/email",
		OperationID: "signInEmail",
		Summary:     "Sign in with email and password",
	}, opts, func(ctx context.Context, input *signInInput) (*signInOutput, error) {
		if !opts.EmailAndPassword.Enabled {
			return nil, huma.Error400BadRequest("email/password sign-in is not enabled")
		}

		email := strings.ToLower(input.Body.Email)

		userRow, err := opts.DB.FindOne(ctx, "user", []types.Where{
			{Field: "email", Value: email},
		}, nil)
		if err != nil || userRow == nil {
			crypto.VerifyPassword(dummyPasswordHash, input.Body.Password) // timing guard
			return nil, huma.NewError(types.StatusForCode(types.ErrInvalidEmailOrPassword), types.ErrInvalidEmailOrPassword)
		}

		userID, _ := userRow["id"].(string)

		accountRow, err := opts.DB.FindOne(ctx, "account", []types.Where{
			{Field: "userId", Value: userID},
			{Field: "providerId", Value: "credential", Connector: "AND"},
		}, nil)
		if err != nil || accountRow == nil {
			crypto.VerifyPassword(dummyPasswordHash, input.Body.Password)
			return nil, huma.NewError(types.StatusForCode(types.ErrInvalidEmailOrPassword), types.ErrInvalidEmailOrPassword)
		}

		storedHash, _ := accountRow["password"].(string)
		validPassword, err := verifyPassword(opts, storedHash, input.Body.Password)
		if err != nil {
			return nil, huma.Error500InternalServerError("failed to verify password")
		}
		if storedHash == "" || !validPassword {
			return nil, huma.NewError(types.StatusForCode(types.ErrInvalidEmailOrPassword), types.ErrInvalidEmailOrPassword)
		}
		if opts.EmailAndPassword.RequireEmailVerification {
			emailVerified, _ := boolField(userRow, "email_verified", "emailVerified")
			if !emailVerified {
				if opts.EmailVerification.SendOnSignIn && (opts.EmailVerification.SendVerificationEmail != nil || opts.EmailVerification.SendVerificationEmailRequest != nil) {
					// Issuance is the upstream HS256 email JWT
					// (createEmailVerificationToken); delivery awaits via
					// runInBackgroundOrAwait so failures never fail sign-in
					// (sign-in.ts:588-597). Prefer the request-aware variant.
					token, tokenErr := crypto.CreateEmailVerificationToken(opts.CurrentSecret(), email, "", emailVerificationExpirySeconds(opts), nil)
					if tokenErr != nil {
						return nil, huma.Error500InternalServerError("failed to generate verification token")
					}
					url := fmt.Sprintf("%s/verify-email?token=%s&callbackURL=%s", opts.BasePath, token, verificationCallbackURL(input.Body.CallbackURL))
					user := rowToUser(userRow, opts)
					wctx := requestContextForCallbacks(ctx)
					sendVerificationEmailWithRequest(wctx, opts, types.VerificationEmailData{User: &user, URL: url, Token: token})
				}
				return nil, huma.NewError(types.StatusForCode(types.ErrEmailNotVerified), types.ErrEmailNotVerified)
			}
		}

		// ValidateUserInfo sign-in seam (upstream internalAdapter sign-in path,
		// method email-password, action sign-in). Programmatic flow: rejection
		// surfaces its 403 code verbatim.
		if err := assertValidUserInfoLocal(ctx, opts, map[string]any{
			"email": email, "id": userID,
		}, types.ValidateUserInfoSource{
			Action: types.ValidateUserInfoActionSignIn,
			Method: types.ValidateUserInfoMethodEmailPassword,
		}); err != nil {
			if httpErr, ok := err.(types.HttpError); ok {
				return nil, huma.NewError(httpErr.Status, httpErr.Code)
			}
			return nil, huma.NewError(403, err.Error())
		}

		now := time.Now().UTC()
		// Explicit rememberMe=false creates a non-persistent session
		// (upstream createSession dontRememberMe, sign-in.ts:603-605 and
		// internal-adapter.ts:509).
		dontRememberMe := input.Body.RememberMe != nil && !*input.Body.RememberMe
		expiresAt := creationSessionExpiry(opts, dontRememberMe, now)
		// The session token is caller-minted randomness (upstream token:
		// generateId(32) direct); the row goes through the shared issuance
		// seam so secondary-only deployments skip the primary DB.
		token := crypto.GenerateID()

		session, err := createIssuedSession(ctx, opts, userID, token, expiresAt, now)
		if err != nil {
			var statusErr huma.StatusError
			if errors.As(err, &statusErr) {
				return nil, statusErr
			}
			return nil, huma.NewError(types.StatusForCode(types.ErrFailedToCreateSession), types.ErrFailedToCreateSession)
		}

		out := &signInOutput{}
		user := rowToUser(userRow, opts)
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
		out.Body.Token = token
		// callbackURL drives the redirect/url pair (upstream
		// sign-in.ts:625-637): redirect is set and url echoes the
		// callbackURL only when one was supplied.
		if input.Body.CallbackURL != nil && *input.Body.CallbackURL != "" {
			out.Body.Redirect = true
			out.Body.URL = input.Body.CallbackURL
		} else {
			out.Body.Redirect = false
		}
		out.Body.User = user
		return out, nil
	})
}

func rowString(row map[string]any, key string) string {
	if value, _ := row[key].(string); value != "" {
		return value
	}
	return ""
}
