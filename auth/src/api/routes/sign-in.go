package routes

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
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

// signInFormMediaType is the additional request media type upstream accepts
// on POST /sign-in/email (sign-in.ts:406-407,446-449 allowedMediaTypes
// json+form).
const signInFormMediaType = "application/x-www-form-urlencoded"

// parseSignInForm decodes an application/x-www-form-urlencoded body into the
// JSON-equivalent object the sign-in schema validates: every present key
// lands verbatim (single value → string, repeated key → string array) with
// rememberMe "true"/"false" coerced to bool (case-insensitive; anything else
// stays a string so schema validation rejects it exactly like the JSON
// path). Absent keys stay absent so required-field validation matches the
// JSON path.
func parseSignInForm(values url.Values) map[string]any {
	obj := make(map[string]any, len(values))
	for key, vals := range values {
		if len(vals) == 0 {
			continue
		}
		if len(vals) == 1 {
			obj[key] = vals[0]
			continue
		}
		arr := make([]any, len(vals))
		for i, v := range vals {
			arr[i] = v
		}
		obj[key] = arr
	}
	if raw, ok := obj["rememberMe"].(string); ok {
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "true":
			obj["rememberMe"] = true
		case "false":
			obj["rememberMe"] = false
		}
	}
	return obj
}

// isSignInFormRequest reports whether ctx carries a form-urlencoded body.
func isSignInFormRequest(ctx huma.Context) bool {
	ct := ctx.Header("Content-Type")
	if ct == "" {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.EqualFold(strings.TrimSpace(ct), signInFormMediaType)
}

// signInFormContext presents the transcoded JSON body to huma's pipeline,
// delegating everything else to the wrapped context (same pattern as the
// api-layer capturedContext and signUpFormContext).
type signInFormContext struct {
	inner huma.Context
	body  []byte
}

func (c *signInFormContext) Operation() *huma.Operation { return c.inner.Operation() }
func (c *signInFormContext) Context() context.Context   { return c.inner.Context() }
func (c *signInFormContext) TLS() *tls.ConnectionState  { return c.inner.TLS() }
func (c *signInFormContext) Version() huma.ProtoVersion { return c.inner.Version() }
func (c *signInFormContext) Method() string             { return c.inner.Method() }
func (c *signInFormContext) Host() string               { return c.inner.Host() }
func (c *signInFormContext) RemoteAddr() string         { return c.inner.RemoteAddr() }
func (c *signInFormContext) URL() url.URL               { return c.inner.URL() }
func (c *signInFormContext) Param(name string) string   { return c.inner.Param(name) }
func (c *signInFormContext) Query(name string) string   { return c.inner.Query(name) }
func (c *signInFormContext) EachHeader(cb func(name, value string)) {
	c.inner.EachHeader(cb)
}
func (c *signInFormContext) GetMultipartForm() (*multipart.Form, error) {
	return c.inner.GetMultipartForm()
}
func (c *signInFormContext) SetReadDeadline(deadline time.Time) error {
	return c.inner.SetReadDeadline(deadline)
}
func (c *signInFormContext) SetStatus(code int)           { c.inner.SetStatus(code) }
func (c *signInFormContext) Status() int                  { return c.inner.Status() }
func (c *signInFormContext) SetHeader(name, value string) { c.inner.SetHeader(name, value) }
func (c *signInFormContext) AppendHeader(name, value string) {
	c.inner.AppendHeader(name, value)
}
func (c *signInFormContext) BodyWriter() io.Writer { return c.inner.BodyWriter() }
func (c *signInFormContext) Unwrap() huma.Context  { return c.inner }

func (c *signInFormContext) Header(name string) string {
	if strings.EqualFold(name, "Content-Type") {
		return "application/json"
	}
	return c.inner.Header(name)
}

func (c *signInFormContext) BodyReader() io.Reader {
	return bytes.NewReader(c.body)
}

// signInFormMiddleware transcodes application/x-www-form-urlencoded bodies to
// JSON before huma's JSON-only body pipeline runs (same pattern as
// signUpFormMiddleware: huma ships no form format; registering one would
// require touching the shared Router). Non-form requests pass through
// untouched. Malformed form bodies short-circuit 400; empty form bodies fall
// through to the required body check like empty JSON bodies.
func signInFormMiddleware(api huma.API) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		if !isSignInFormRequest(ctx) {
			next(ctx)
			return
		}
		var buf bytes.Buffer
		if r := ctx.BodyReader(); r != nil {
			if _, err := io.Copy(&buf, r); err != nil {
				_ = huma.WriteErr(api, ctx, http.StatusBadRequest, "invalid form body")
				return
			}
		}
		if buf.Len() == 0 {
			next(ctx)
			return
		}
		values, err := url.ParseQuery(buf.String())
		if err != nil {
			_ = huma.WriteErr(api, ctx, http.StatusBadRequest, "invalid form body")
			return
		}
		transcoded, err := json.Marshal(parseSignInForm(values))
		if err != nil {
			_ = huma.WriteErr(api, ctx, http.StatusBadRequest, "invalid form body")
			return
		}
		next(&signInFormContext{inner: ctx, body: transcoded})
	}
}

// SignInEmail registers POST /sign-in/email.
func SignInEmail(api huma.API, basePath string, opts types.Options) {
	op := huma.Operation{
		Tags:        []string{"Auth"},
		Method:      http.MethodPost,
		Path:        basePath + "/sign-in/email",
		OperationID: "signInEmail",
		Summary:     "Sign in with email and password",
	}
	// Upstream allowedMediaTypes json+form (sign-in.ts:406-407,446-449): the
	// middleware transcodes form bodies to JSON (runtime); the OpenAPI stays
	// JSON-shaped.
	op.Middlewares = append(op.Middlewares, signInFormMiddleware(api))
	registerAuthOperation(api, op, opts, func(ctx context.Context, input *signInInput) (*signInOutput, error) {
		// Upstream global middleware validates callbackURL before the handler
		// (origin-check.ts:89-151): an untrusted value 403s INVALID_CALLBACK_URL.
		// The Location-drop below stays as hardening for the trusted decision.
		if input.Body.CallbackURL != nil && *input.Body.CallbackURL != "" {
			reqForTrust := trustRequest(ctx)
			if !types.IsTrustedRedirect(*input.Body.CallbackURL, opts, reqForTrust) {
				return nil, huma.NewError(types.StatusForCode(types.ErrInvalidCallbackURL), types.ErrInvalidCallbackURL)
			}
		}
		if !opts.EmailAndPassword.Enabled {
			// Upstream sign-in.ts:512-520 throws BAD_REQUEST with code
			// EMAIL_PASSWORD_DISABLED and message "Email and password is
			// not enabled". The code is ad-hoc (absent from upstream
			// codes.ts and types), so it rides the "CODE: msg" detail
			// convention like RESET_PASSWORD_DISABLED in password.go.
			Logf(opts, "error", "Email and password is not enabled")
			return nil, huma.NewError(http.StatusBadRequest, "EMAIL_PASSWORD_DISABLED: Email and password is not enabled")
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
		// Hash rotation (crypto.UpgradeHashIfNeeded, P11): a legacy bcrypt
		// bridge hash that verified rotates to a fresh scrypt hash,
		// persisted to the credential account row. Only the default backend
		// rotates — a custom Password.Verify hook owns its own hash format,
		// so the helper (which re-verifies with the default backend) already
		// returns false there; the explicit Verify==nil guard keeps that
		// contract obvious. Best-effort: a persist failure never fails the
		// verified sign-in.
		if opts.EmailAndPassword.Password.Verify == nil {
			if newHash, upgraded := crypto.UpgradeHashIfNeeded(storedHash, input.Body.Password); upgraded {
				_, _ = opts.DB.Update(ctx, "account", []types.Where{
					{Field: "userId", Value: userID},
					{Field: "providerId", Value: "credential", Connector: "AND"},
				}, map[string]any{
					"password":  newHash,
					"updatedAt": time.Now().UTC(),
				})
			}
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
			reqForTrust := trustRequest(ctx)
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
