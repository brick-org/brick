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
	"net/url"
	"strings"
	"time"

	"github.com/brick-org/brick/auth/src/crypto"
	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
)

type signUpBody struct {
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
	// Extra carries additional user fields (upstream parseUserInput
	// "create", sign-up.ts:242-246): unknown top-level keys are parsed
	// against the full user schema instead of being dropped. See
	// UnmarshalJSON/MarshalJSON.
	Extra map[string]any `json:"-"`
}

// UnmarshalJSON captures known fields plus any additional user fields into
// Extra, mirroring upstream's `{name, email, password, image, callbackURL,
// rememberMe, ...rest}` split (sign-up.ts:200-208). Unknown keys are
// preserved verbatim for ParseUserInputFull.
func (b *signUpBody) UnmarshalJSON(data []byte) error {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw == nil {
		return nil
	}
	if v, ok := raw["name"]; ok {
		if v == nil {
			// JSON null reads as absent; required validation downstream
			// reports the missing field.
		} else if s, ok := v.(string); ok {
			b.Name = s
		} else {
			return fmt.Errorf("name must be a string")
		}
		delete(raw, "name")
	}
	if v, ok := raw["email"]; ok {
		if v == nil {
			// Null reads as absent; required validation downstream reports it.
		} else if s, ok := v.(string); ok {
			b.Email = s
		} else {
			return fmt.Errorf("email must be a string")
		}
		delete(raw, "email")
	}
	if v, ok := raw["password"]; ok {
		if v == nil {
			// Null reads as absent; required validation downstream reports it.
		} else if s, ok := v.(string); ok {
			b.Password = s
		} else {
			return fmt.Errorf("password must be a string")
		}
		delete(raw, "password")
	}
	if v, ok := raw["image"]; ok {
		if v == nil {
			// Null reads as absent for the optional field.
		} else if s, ok := v.(string); ok {
			b.Image = &s
		} else {
			return fmt.Errorf("image must be a string")
		}
		delete(raw, "image")
	}
	if v, ok := raw["callbackURL"]; ok {
		if v == nil {
			// Null reads as absent for the optional field.
		} else if s, ok := v.(string); ok {
			b.CallbackURL = &s
		} else {
			return fmt.Errorf("callbackURL must be a string")
		}
		delete(raw, "callbackURL")
	}
	if v, ok := raw["rememberMe"]; ok {
		if v == nil {
			// Null reads as absent for the optional field.
		} else if bv, ok := v.(bool); ok {
			b.RememberMe = &bv
		} else {
			return fmt.Errorf("rememberMe must be a boolean")
		}
		delete(raw, "rememberMe")
	}
	if len(raw) > 0 {
		b.Extra = raw
	}
	return nil
}

// MarshalJSON round-trips known fields plus Extra so test clients encoding
// this body preserve additional fields.
func (b signUpBody) MarshalJSON() ([]byte, error) {
	out := map[string]any{}
	if b.Extra != nil {
		for k, v := range b.Extra {
			out[k] = v
		}
	}
	out["name"] = b.Name
	out["email"] = b.Email
	out["password"] = b.Password
	if b.Image != nil {
		out["image"] = *b.Image
	}
	if b.CallbackURL != nil {
		out["callbackURL"] = *b.CallbackURL
	}
	if b.RememberMe != nil {
		out["rememberMe"] = *b.RememberMe
	}
	return json.Marshal(out)
}

// signUpFormMediaType is the additional request media type upstream accepts
// on POST /sign-up/email (sign-up.ts:38-41 allowedMediaTypes json+form).
const signUpFormMediaType = "application/x-www-form-urlencoded"

// parseSignUpForm decodes an application/x-www-form-urlencoded body into the
// JSON-equivalent object the sign-up schema validates: known fields coerced
// (rememberMe "true"/"false" → bool, case-insensitive; anything else stays a
// string so schema validation rejects it exactly like the JSON path), every
// other present key preserved verbatim as an additional user field (single
// value → string, repeated key → string array). Absent keys stay absent so
// required-field validation matches the JSON path.
func parseSignUpForm(values url.Values) map[string]any {
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

// isSignUpFormRequest reports whether ctx carries a form-urlencoded body.
func isSignUpFormRequest(ctx huma.Context) bool {
	ct := ctx.Header("Content-Type")
	if ct == "" {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.EqualFold(strings.TrimSpace(ct), signUpFormMediaType)
}

// signUpFormContext presents the transcoded JSON body to huma's pipeline,
// delegating everything else to the wrapped context (same pattern as the
// api-layer capturedContext).
type signUpFormContext struct {
	inner huma.Context
	body  []byte
}

func (c *signUpFormContext) Operation() *huma.Operation { return c.inner.Operation() }
func (c *signUpFormContext) Context() context.Context   { return c.inner.Context() }
func (c *signUpFormContext) TLS() *tls.ConnectionState  { return c.inner.TLS() }
func (c *signUpFormContext) Version() huma.ProtoVersion { return c.inner.Version() }
func (c *signUpFormContext) Method() string             { return c.inner.Method() }
func (c *signUpFormContext) Host() string               { return c.inner.Host() }
func (c *signUpFormContext) RemoteAddr() string         { return c.inner.RemoteAddr() }
func (c *signUpFormContext) URL() url.URL               { return c.inner.URL() }
func (c *signUpFormContext) Param(name string) string   { return c.inner.Param(name) }
func (c *signUpFormContext) Query(name string) string   { return c.inner.Query(name) }
func (c *signUpFormContext) EachHeader(cb func(name, value string)) {
	c.inner.EachHeader(cb)
}
func (c *signUpFormContext) GetMultipartForm() (*multipart.Form, error) {
	return c.inner.GetMultipartForm()
}
func (c *signUpFormContext) SetReadDeadline(deadline time.Time) error {
	return c.inner.SetReadDeadline(deadline)
}
func (c *signUpFormContext) SetStatus(code int)           { c.inner.SetStatus(code) }
func (c *signUpFormContext) Status() int                  { return c.inner.Status() }
func (c *signUpFormContext) SetHeader(name, value string) { c.inner.SetHeader(name, value) }
func (c *signUpFormContext) AppendHeader(name, value string) {
	c.inner.AppendHeader(name, value)
}
func (c *signUpFormContext) BodyWriter() io.Writer { return c.inner.BodyWriter() }
func (c *signUpFormContext) Unwrap() huma.Context  { return c.inner }

func (c *signUpFormContext) Header(name string) string {
	if strings.EqualFold(name, "Content-Type") {
		return "application/json"
	}
	return c.inner.Header(name)
}

func (c *signUpFormContext) BodyReader() io.Reader {
	return bytes.NewReader(c.body)
}

// signUpFormMiddleware transcodes application/x-www-form-urlencoded bodies to
// JSON before huma's JSON-only body pipeline runs (huma ships no form
// format; registering one would require touching the shared Router, owned by
// another lane). Non-form requests pass through untouched. Malformed form
// bodies short-circuit 400; empty form bodies fall through to the required
// body check like empty JSON bodies.
func signUpFormMiddleware(api huma.API) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		if !isSignUpFormRequest(ctx) {
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
		transcoded, err := json.Marshal(parseSignUpForm(values))
		if err != nil {
			_ = huma.WriteErr(api, ctx, http.StatusBadRequest, "invalid form body")
			return
		}
		next(&signUpFormContext{inner: ctx, body: transcoded})
	}
}

// TransformSchema permits additional properties on the sign-up body,
// mirroring upstream's `z.object({...}).and(z.record(z.string(), z.any()))`
// (sign-up.ts:17-26): unknown top-level keys are additional user fields for
// parseUserInput, not validation failures. Without it huma rejects
// additional-field sign-ups with 422 before the handler runs.
func (b signUpBody) TransformSchema(r huma.Registry, s *huma.Schema) *huma.Schema {
	s.AdditionalProperties = true
	return s
}

type signUpInput struct {
	CookieRequestHeaders
	Body signUpBody
}

type signUpOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      struct {
		Token *string  `json:"token"`
		User  flatUser `json:"user"`
	}
}

// SignUpEmail registers POST /sign-up/email.
func SignUpEmail(api huma.API, basePath string, opts types.Options) {
	op := huma.Operation{
		Tags:        []string{"Auth"},
		Method:      http.MethodPost,
		Path:        basePath + "/sign-up/email",
		OperationID: "signUpWithEmailAndPassword",
		Summary:     "Sign up with email and password",
	}
	// Upstream allowedMediaTypes json+form (sign-up.ts:38-41): the middleware
	// transcodes form bodies to JSON (runtime); the OpenAPI stays JSON-shaped.
	op.Middlewares = append(op.Middlewares, signUpFormMiddleware(api))
	registerAuthOperation(api, op, opts, func(ctx context.Context, input *signUpInput) (*signUpOutput, error) {
		if !opts.EmailAndPassword.Enabled || opts.EmailAndPassword.DisableSignUp {
			return nil, huma.Error400BadRequest("email/password sign-up is not enabled")
		}

		if len(input.Body.Password) < passwordMinLength(opts) {
			Logf(opts, "warn", "Password is too short")
			return nil, huma.NewError(types.StatusForCode(types.ErrPasswordTooShort), types.ErrPasswordTooShort)
		}
		if len(input.Body.Password) > passwordMaxLength(opts) {
			Logf(opts, "warn", "Password is too long")
			return nil, huma.NewError(types.StatusForCode(types.ErrPasswordTooLong), types.ErrPasswordTooLong)
		}

		email := strings.ToLower(input.Body.Email)
		// Upstream sign-up.ts:236-238: the generic-duplicate response
		// applies when requireEmailVerification OR autoSignIn === false.
		shouldReturnGenericDuplicateResponse := opts.EmailAndPassword.RequireEmailVerification || !autoSignInEnabled(opts)
		shouldSkipAutoSignIn := !autoSignInEnabled(opts) || shouldReturnGenericDuplicateResponse

		// Additional user fields (upstream parseUserInput "create",
		// sign-up.ts:242-246): validated/transformed against the full
		// schema with create semantics (defaults applied, required
		// enforced, input:false rejected); unknown keys are dropped by the
		// parser, never persisted. Parsed before the duplicate check so a
		// truthy input:false value fails even for an existing email,
		// mirroring upstream's parse-before-lookup order.
		additional, perr := ParseUserInputFull(input.Body.Extra, normalizeCreateFields(FullUserFields(opts)), "create")
		if perr != nil {
			if fp, ok := perr.(*FieldParseError); ok {
				return nil, huma.NewError(types.StatusForCode(fp.Code), fp.Message)
			}
			return nil, huma.Error400BadRequest(perr.Error())
		}

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
						AdditionalFields: additional,
					})
				} else {
					for k, v := range additional {
						syntheticRow[k] = v
					}
				}
				out := &signUpOutput{}
				out.Body.Token = nil
				out.Body.User = flatUser(rowToUser(syntheticRow, opts))
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
						AdditionalFields: additional,
					})
				} else {
					for k, v := range additional {
						syntheticRow[k] = v
					}
				}
				out := &signUpOutput{}
				out.Body.Token = nil
				out.Body.User = flatUser(rowToUser(syntheticRow, opts))
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
		// Persist parsed additional fields alongside the core columns
		// (upstream internalAdapter.createUser, sign-up.ts:345-354).
		for k, v := range additional {
			userData[k] = v
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

		shouldSendVerificationEmail := types.ResolveSendOnSignUp(opts.EmailVerification.SendOnSignUp, opts.EmailAndPassword.RequireEmailVerification)
		if shouldSendVerificationEmail && (opts.EmailVerification.SendVerificationEmail != nil || opts.EmailVerification.SendVerificationEmailRequest != nil) {
			// Issuance is the upstream HS256 email JWT
			// (createEmailVerificationToken, email-verification.ts:17-43).
			token, err := crypto.CreateEmailVerificationToken(opts.CurrentSecret(), email, "", emailVerificationExpirySeconds(opts), nil)
			if err != nil {
				return nil, huma.Error500InternalServerError("failed to generate verification token")
			}
			url := fmt.Sprintf("%s/verify-email?token=%s&callbackURL=%s", opts.BasePath, token, url.QueryEscape(verificationCallbackURL(input.Body.CallbackURL)))
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
			out.Body.User = flatUser(rowToUser(userRow, opts))
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
			// Kept 400 (differs from StatusForCode 500): upstream
			// sign-up.ts:435-439 throws BAD_REQUEST when session creation
			// fails after the user was created.
			cleanupOrphanSignUp(ctx, opts, userID, token)
			return nil, huma.Error400BadRequest(types.ErrFailedToCreateSession)
		}

		user := rowToUser(userRow, opts)
		out := &signUpOutput{}
		// Mirror the pair into secondary storage when configured (upstream
		// createSession mirroring, internal-adapter.ts:520-564). A failing
		// mirror fails issuance loudly, like the database create above.
		if err := writeSecondarySession(opts, session, user); err != nil {
			cleanupOrphanSignUp(ctx, opts, userID, token)
			return nil, huma.NewError(types.StatusForCode(types.ErrFailedToCreateSession), types.ErrFailedToCreateSession)
		}
		cookiesOut, err := issueSessionCookies(opts, input.CookieRequestHeaders, token, session, user, opts.Session, now, dontRememberMe)
		if err != nil {
			cleanupOrphanSignUp(ctx, opts, userID, token)
			return nil, huma.NewError(types.StatusForCode(types.ErrFailedToCreateSession), types.ErrFailedToCreateSession)
		}
		out.SetCookie = cookiesOut
		out.Body.Token = &token
		out.Body.User = flatUser(user)
		return out, nil
	})
}

// cleanupOrphanSignUp best-effort deletes the just-committed user+account
// rows after a post-commit session-issuance failure (upstream
// sign-up.test.ts:125 "should rollback when session creation fails"). The
// user+account transaction already committed, so a spanning transaction is
// impossible; compensating deletes run instead. When token != "" the already
// persisted session row for this issuance is removed too (mirror/cookie
// failures happen after the primary row exists; at session-create failure
// the delete is a harmless no-op). Nil-guarded: secondary-only deployments
// have no primary rows to clean. Delete errors are ignored so callers
// return their original status/code unchanged.
func cleanupOrphanSignUp(ctx context.Context, opts types.Options, userID, token string) {
	if opts.DB == nil || userID == "" {
		return
	}
	_, _ = opts.DB.DeleteMany(ctx, "account", []types.Where{{Field: "userId", Value: userID}})
	_, _ = opts.DB.DeleteMany(ctx, "user", []types.Where{{Field: "id", Value: userID}})
	if token != "" {
		_, _ = opts.DB.DeleteMany(ctx, "session", []types.Where{{Field: "token", Value: token}})
	}
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

// normalizeCreateFields bridges the option-field required default to
// upstream parseInputData semantics (db/schema.ts:206: `if
// (fields[key].required && action === "create")`): an unset required flag is
// falsy, so the field is optional on create. types.FieldAttribute documents
// nil as default-true (the column default); route input parsing must not
// inherit that, or every optional additional field would 400 sign-ups that
// omit it. Explicit required:true survives the normalization and is still
// enforced with MISSING_FIELD.
func normalizeCreateFields(fields map[string]types.FieldAttribute) map[string]types.FieldAttribute {
	out := make(map[string]types.FieldAttribute, len(fields))
	optional := false
	for k, f := range fields {
		if f.Required == nil {
			f.Required = &optional
		}
		out[k] = f
	}
	return out
}

// flatUser serializes a types.User the way upstream parseUserOutput does:
// additional fields merge flat onto the user object instead of nesting
// under "additionalFields" (PARITY_V2.md AUTH-AUDIT-TMODELS-02 prescribes
// "flatten in the response serializer"). types.User keeps the nested Go
// shape (types/ is frozen to this lane); only the JSON boundary flattens,
// so `res.user.newField` reads hold and real-vs-synthetic key order is
// identical (both sides serialize here).
type flatUser types.User

// MarshalJSON implements json.Marshaler.
func (u flatUser) MarshalJSON() ([]byte, error) {
	out := map[string]any{
		"id":            u.ID,
		"email":         u.Email,
		"emailVerified": u.EmailVerified,
		"name":          u.Name,
		"createdAt":     u.CreatedAt,
		"updatedAt":     u.UpdatedAt,
	}
	if u.Image != nil {
		out["image"] = *u.Image
	}
	for k, v := range u.AdditionalFields {
		out[k] = v
	}
	return json.Marshal(out)
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
		switch v := row[key].(type) {
		case string:
			if v != "" {
				return v
			}
		case *string:
			// Pointer cells arise when a create row carries an optional
			// field straight from a decoded body (e.g. sign-up image) into
			// an in-memory adapter; unwrap so they read like database
			// strings. A nil pointer reads as absent, as before.
			if v != nil && *v != "" {
				return *v
			}
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
