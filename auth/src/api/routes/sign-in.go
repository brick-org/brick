package routes

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
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
	// Location echoes a present, trusted callbackURL (upstream
	// sign-in.ts:625-627). Empty (absent or untrusted) emits no header:
	// huma skips empty string headers.
	Location string `header:"Location"`
	Body     struct {
		Token    string   `json:"token"`
		Redirect bool     `json:"redirect"`
		URL      *string  `json:"url,omitempty"`
		User     flatUser `json:"user"`
	}
}

// isValidSignInEmail mirrors the upstream email-format gate (z.email(),
// sign-in.ts:522-525): a single @, a non-empty dotless-free local part,
// and a multi-label domain. Rejections answer 400 INVALID_EMAIL before any
// user lookup, so the format gate never leaks existence.
func isValidSignInEmail(email string) bool {
	if email == "" || len(email) > 254 {
		return false
	}
	if strings.ContainsAny(email, " \t\r\n") {
		return false
	}
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	local, domain := parts[0], parts[1]
	if local == "" || domain == "" {
		return false
	}
	if strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") {
		return false
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	parsed, err := mail.ParseAddress(email)
	if err != nil || parsed.Address != email {
		return false
	}
	return true
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

		// Upstream sign-in.ts:522-525 rejects a malformed email format with
		// 400 INVALID_EMAIL before any user lookup, so malformed input
		// never reaches the credential checks and cannot leak existence.
		if !isValidSignInEmail(input.Body.Email) {
			return nil, huma.NewError(types.StatusForCode(types.ErrInvalidEmail), types.ErrInvalidEmail)
		}

		email := strings.ToLower(input.Body.Email)

		userRow, err := opts.DB.FindOne(ctx, "user", []types.Where{
			{Field: "email", Value: email},
		}, nil)
		if err != nil || userRow == nil {
			crypto.VerifyPassword(dummyPasswordHash, input.Body.Password) // timing guard
			// Upstream sign-in.ts:540 logs "User not found" for a missing
			// user or credential account alike.
			Logf(opts, "warn", "User not found")
			return nil, huma.NewError(types.StatusForCode(types.ErrInvalidEmailOrPassword), types.ErrInvalidEmailOrPassword)
		}

		userID, _ := userRow["id"].(string)

		accountRow, err := opts.DB.FindOne(ctx, "account", []types.Where{
			{Field: "userId", Value: userID},
			{Field: "providerId", Value: "credential", Connector: "AND"},
		}, nil)
		if err != nil || accountRow == nil {
			crypto.VerifyPassword(dummyPasswordHash, input.Body.Password)
			Logf(opts, "warn", "User not found")
			return nil, huma.NewError(types.StatusForCode(types.ErrInvalidEmailOrPassword), types.ErrInvalidEmailOrPassword)
		}

		storedHash, _ := accountRow["password"].(string)
		if storedHash == "" {
			// Upstream sign-in.ts:551 logs "Password not found" when the
			// credential account carries no password.
			crypto.VerifyPassword(dummyPasswordHash, input.Body.Password)
			Logf(opts, "warn", "Password not found")
			return nil, huma.NewError(types.StatusForCode(types.ErrInvalidEmailOrPassword), types.ErrInvalidEmailOrPassword)
		}
		validPassword, err := verifyPassword(opts, storedHash, input.Body.Password)
		if err != nil {
			return nil, huma.Error500InternalServerError("failed to verify password")
		}
		if !validPassword {
			// Upstream sign-in.ts:562 logs "Invalid password".
			Logf(opts, "warn", "Invalid password")
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
					url := fmt.Sprintf("%s/verify-email?token=%s&callbackURL=%s", opts.BasePath, token, url.QueryEscape(verificationCallbackURL(input.Body.CallbackURL)))
					user := rowToUser(userRow, opts)
					wctx := requestContextForCallbacks(ctx)
					sendVerificationEmailWithRequest(wctx, opts, types.VerificationEmailData{User: &user, URL: url, Token: token})
				}
				return nil, huma.NewError(types.StatusForCode(types.ErrEmailNotVerified), types.ErrEmailNotVerified)
			}
		}

		// ValidateUserInfo sign-in seam (upstream internalAdapter sign-in path,
		// method email-password, action sign-in). Programmatic flow: rejection
		// surfaces its 403 code verbatim. The upstream email leg
		// (sign-in.ts:505-637) has no equivalent call — this Go-only
		// fail-closed extension is kept intentionally.
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
			// Kept 401 (differs from StatusForCode 500): upstream
			// sign-in.ts:608-613 throws UNAUTHORIZED when session creation
			// fails after credential checks.
			return nil, huma.Error401Unauthorized(types.ErrFailedToCreateSession)
		}

		out := &signInOutput{}
		user := rowToUser(userRow, opts)
		// Mirror the pair into secondary storage when configured (upstream
		// createSession mirroring, internal-adapter.ts:520-564). A failing
		// mirror fails issuance loudly, like the database create above. The
		// upstream email leg has no equivalent failure mode here — this
		// fail-closed 500 (canonical status for FAILED_TO_CREATE_SESSION)
		// is kept intentionally.
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
		// callbackURL only when one was supplied. A present, trusted
		// callbackURL additionally sets the Location response header
		// (upstream sign-in.ts:625-627); an untrusted absolute URL keeps
		// the body pair but emits no header (no open redirect). The stored
		// request (when present) is authoritative for the trust decision.
		if input.Body.CallbackURL != nil && *input.Body.CallbackURL != "" {
			out.Body.Redirect = true
			out.Body.URL = input.Body.CallbackURL
			reqForTrust := StoredRequestFromStd(ctx)
			if reqForTrust == nil {
				reqForTrust = callbackRequest(ctx)
			}
			if types.IsTrustedRedirect(*input.Body.CallbackURL, opts, reqForTrust) {
				out.Location = *input.Body.CallbackURL
			}
		} else {
			out.Body.Redirect = false
		}
		out.Body.User = flatUser(user)
		return out, nil
	})
}

func rowString(row map[string]any, key string) string {
	if value, _ := row[key].(string); value != "" {
		return value
	}
	return ""
}
