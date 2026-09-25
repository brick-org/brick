package routes

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/brick-org/brick/auth/src/crypto"
	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
)

type accountRecord struct {
	ID         string    `json:"id"`
	ProviderID string    `json:"providerId"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
	AccountID  string    `json:"accountId"`
	UserID     string    `json:"userId"`
	Scopes     []string  `json:"scopes"`
}

// nullableString tracks presence for update-user's image field: upstream
// distinguishes absent (undefined, keep) from explicit null (unset), while
// Go's *string cannot. It unmarshals any JSON value as set, with null
// recorded as a set-but-nil value that clears the column.
type nullableString struct {
	Set   bool
	Value *string
}

// UnmarshalJSON implements json.Unmarshaler.
func (n *nullableString) UnmarshalJSON(data []byte) error {
	n.Set = true
	if string(data) == "null" {
		n.Value = nil
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	n.Value = &s
	return nil
}

// TransformSchema implements huma.SchemaTransformer so request validation
// accepts the wire forms UnmarshalJSON handles (JSON string or null).
// Without it huma generates an object schema from the struct shape and
// rejects plain `"image":"..."` payloads with 422 before the handler runs.
func (n *nullableString) TransformSchema(r huma.Registry, s *huma.Schema) *huma.Schema {
	return &huma.Schema{Type: huma.TypeString, Nullable: true}
}

// callbackRequest rebuilds a best-effort *http.Request from the huma.Context
// carried in ctx values (stored by WithAuthRouteContext in the API
// middleware, or by humaRequestContext in direct-handle GET routes) for
// request-aware callbacks (upstream ctx.request via safeCloneRequest).
// Limits mirror api.requestFromContext: only method, URL, host, remote
// address, and headers are carried; the body is referenced, not cloned. It
// returns nil when no huma context is present (e.g. direct unit calls, or
// POST routes running without the API middleware wrap); *Request callbacks
// must tolerate a nil request, matching upstream invocations with request
// undefined.
func callbackRequest(ctx context.Context) *http.Request {
	hc, _ := ctx.Value(humaContextKey{}).(huma.Context)
	return requestFromHuma(hc)
}

// humaRequestContext returns a context carrying hc under the auth-route
// context key so callbackRequest can rebuild the *http.Request for
// request-aware hooks. Direct-handle GET routes (which own their
// huma.Context) wrap their context with this instead of depending on the API
// middleware wrap.
func humaRequestContext(parent context.Context, hc huma.Context) context.Context {
	if hc == nil {
		return parent
	}
	return context.WithValue(parent, humaContextKey{}, hc)
}

// requestFromHuma rebuilds a best-effort *http.Request from hc. It returns
// nil when hc is nil (e.g. direct unit calls); *Request callbacks must
// tolerate a nil request, matching upstream invocations with request
// undefined.
func requestFromHuma(hc huma.Context) *http.Request {
	if hc == nil {
		return nil
	}
	u := hc.URL()
	var body io.Reader
	if reader := hc.BodyReader(); reader != nil {
		body = reader
	}
	req, err := http.NewRequest(hc.Method(), u.String(), body)
	if err != nil {
		return nil
	}
	req.Host = hc.Host()
	req.RemoteAddr = hc.RemoteAddr()
	hc.EachHeader(func(name, value string) {
		req.Header.Add(name, value)
	})
	return req
}

func logBackgroundError(opts types.Options, msg string, err error) {
	if opts.Logger.Disabled || opts.Logger.Log == nil {
		return
	}
	opts.Logger.Log("error", msg+": "+err.Error())
}

// runBackgroundOrAwait mirrors upstream runInBackgroundOrAwait
// (context/create-context.ts): with Advanced.BackgroundTasks.Handler the work
// is deferred to the handler (task panics and errors contained, never failing
// the route); without a handler it runs synchronously and failures are logged
// and swallowed so routes still answer success (upstream logs "Failed to run
// background task" and continues — e.g. password.test.ts "should not reveal
// failure of email sending"). Callers that must fail the route on error
// (direct-await sites like sendVerificationEmailFn) invoke callbacks directly
// instead.
func runBackgroundOrAwait(opts types.Options, task func() error) {
	if handler := opts.Advanced.BackgroundTasks.Handler; handler != nil {
		handler(func() {
			defer func() { _ = recover() }()
			if err := task(); err != nil {
				logBackgroundError(opts, "Failed to run background task", err)
			}
		})
		return
	}
	if err := task(); err != nil {
		logBackgroundError(opts, "Failed to run background task", err)
	}
}

// sendChangeEmailConfirmationMail dispatches SendChangeEmailConfirmation,
// preferring the request-aware variant when set (upstream
// sendChangeEmailConfirmation(data, request)).
func sendChangeEmailConfirmationMail(ctx context.Context, opts types.Options, data types.ChangeEmailData) {
	if opts.User.ChangeEmail.SendChangeEmailConfirmationRequest != nil {
		req := callbackRequest(ctx)
		runBackgroundOrAwait(opts, func() error {
			return opts.User.ChangeEmail.SendChangeEmailConfirmationRequest(data, req)
		})
		return
	}
	if opts.User.ChangeEmail.SendChangeEmailConfirmation != nil {
		runBackgroundOrAwait(opts, func() error {
			return opts.User.ChangeEmail.SendChangeEmailConfirmation(data)
		})
	}
}

// sendDeleteAccountVerificationMail dispatches SendDeleteAccountVerification,
// preferring the request-aware variant when set (upstream
// sendDeleteAccountVerification(data, request)).
func sendDeleteAccountVerificationMail(ctx context.Context, opts types.Options, data types.DeleteAccountVerificationData) {
	if opts.User.DeleteUser.SendDeleteAccountVerificationRequest != nil {
		req := callbackRequest(ctx)
		runBackgroundOrAwait(opts, func() error {
			return opts.User.DeleteUser.SendDeleteAccountVerificationRequest(data, req)
		})
		return
	}
	if opts.User.DeleteUser.SendDeleteAccountVerification != nil {
		runBackgroundOrAwait(opts, func() error {
			return opts.User.DeleteUser.SendDeleteAccountVerification(data)
		})
	}
}

// runBeforeDeleteHook runs beforeDelete, preferring the request-aware variant
// when set (upstream beforeDelete(user, request)); errors abort deletion.
func runBeforeDeleteHook(ctx context.Context, opts *types.DeleteUserOptions, user *types.User) error {
	if opts == nil {
		return nil
	}
	if opts.BeforeDeleteRequest != nil {
		return opts.BeforeDeleteRequest(user, callbackRequest(ctx))
	}
	if opts.BeforeDelete != nil {
		return opts.BeforeDelete(user)
	}
	return nil
}

// runAfterDeleteHook runs afterDelete, preferring the request-aware variant
// when set (upstream afterDelete(user, request)); errors fail the route,
// mirroring upstream's direct await.
func runAfterDeleteHook(ctx context.Context, opts *types.DeleteUserOptions, user *types.User) error {
	if opts == nil {
		return nil
	}
	if opts.AfterDeleteRequest != nil {
		return opts.AfterDeleteRequest(user, callbackRequest(ctx))
	}
	if opts.AfterDelete != nil {
		return opts.AfterDelete(user)
	}
	return nil
}

type listAccountsInput struct {
	Authorization string `header:"Authorization"`
	Cookie        string `header:"Cookie"`
	CookieRequestHeaders
}

type listAccountsOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      []accountRecord
}

// ListUserAccounts registers GET /list-accounts.
func ListUserAccounts(api huma.API, basePath string, opts types.Options) {
	registerAuthOperation(api, huma.Operation{
		Tags:        []string{"Auth"},
		Method:      http.MethodGet,
		Path:        basePath + "/list-accounts",
		OperationID: "listUserAccounts",
		Summary:     "List linked accounts for the current user",
	}, opts, func(ctx context.Context, input *listAccountsInput) (*listAccountsOutput, error) {
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

		rows, err := opts.DB.FindMany(ctx, "account", []types.Where{
			{Field: "userId", Value: sessionRow["userId"]},
		}, 0, 0, nil, nil)
		if err != nil {
			// Kept 500 (differs from StatusForCode 400 for ACCOUNT_NOT_FOUND):
			// adapter failure listing accounts, not a semantic "not found".
			return nil, huma.Error500InternalServerError(types.ErrAccountNotFound)
		}

		out := &listAccountsOutput{Body: make([]accountRecord, 0, len(rows))}
		if refreshed {
			cookiesOut, cookieErr := newSessionCookies(opts, input.CookieRequestHeaders, token, rowToSession(sessionRow, opts), rowToUser(userRow, opts), opts.Session, time.Now().UTC())
			if cookieErr == nil {
				out.SetCookie = cookiesOut
			}
		}
		for _, row := range rows {
			out.Body = append(out.Body, rowToAccount(row))
		}
		return out, nil
	})
}

type updateUserBody struct {
	Name  *string        `json:"name,omitempty"`
	Image nullableString `json:"image,omitempty"`
	// Email is never updatable here (upstream EMAIL_CAN_NOT_BE_UPDATED);
	// it is declared only to detect and reject the field.
	Email *string `json:"email,omitempty"`
	// Extra carries additional user fields (upstream parseUserInput
	// "update"): unknown top-level keys are parsed against the full user
	// schema instead of being dropped. See UnmarshalJSON/MarshalJSON.
	Extra map[string]any `json:"-"`
}

// UnmarshalJSON captures known fields plus any additional user fields into
// Extra, mirroring upstream's `{name, image, ...rest}` split
// (update-user.ts:104-110). Unknown keys are preserved verbatim for
// ParseUserInputFull.
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
	// everything else is a candidate additional field.
	if len(raw) > 0 {
		b.Extra = raw
	}
	return nil
}

// MarshalJSON round-trips known fields plus Extra so test clients encoding
// this body preserve additional fields.
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
// mirroring upstream's `{name, image, ...rest}` split (update-user.ts:104-110):
// unknown top-level keys are additional user fields for parseUserInput, not
// validation failures. Without it huma rejects additional-field updates with
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

		// Upstream rejects email updates here (update-user.ts:98-103); the
		// dedicated change-email flow owns address changes.
		if input.Body.Email != nil {
			return nil, huma.NewError(types.StatusForCode(types.ErrEmailCanNotBeUpdated), types.ErrEmailCanNotBeUpdated)
		}

		update := map[string]any{"updatedAt": time.Now().UTC()}
		if input.Body.Name != nil {
			update["name"] = *input.Body.Name
		}
		// Explicit null unsets the image (upstream update-user.test.ts
		// "should unset image"); an absent field keeps it.
		if input.Body.Image.Set {
			if input.Body.Image.Value != nil {
				update["image"] = *input.Body.Image.Value
			} else {
				update["image"] = nil
			}
		}
		// Additional user fields (upstream parseUserInput "update",
		// update-user.ts:106-110): validated/transformed against the full
		// schema; unknown keys pass through via the Full union.
		if len(input.Body.Extra) > 0 {
			additional, perr := ParseUserInputFull(input.Body.Extra, FullUserFields(opts), "update")
			if perr != nil {
				if fp, ok := perr.(*FieldParseError); ok {
					// The message carries the upstream detail (e.g.
					// "newField is not allowed to be set"), mirroring the
					// APIError message the TS client surfaces.
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
		// internal-adapter.ts:108-137): rewrite the cached user on every
		// live session after the commit. A failing mirror fails loudly
		// with the surrounding update convention, mirroring the
		// writeSecondarySession failures on the issuance paths (never
		// swallowed).
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
		// The confirmation leg depends on the verification leg (confirming
		// mints a change-email-verification send), so it additionally
		// requires the verification sender (upstream update-user.ts:750-752).
		canSendConfirmation := canSendVerification && currentUser.EmailVerified && (opts.User.ChangeEmail.SendChangeEmailConfirmation != nil || opts.User.ChangeEmail.SendChangeEmailConfirmationRequest != nil)
		if !canUpdateWithoutVerification && !canSendConfirmation && !canSendVerification {
			return nil, huma.Error400BadRequest("Verification email isn't enabled")
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
			// for the existing address before answering success).
			_, _ = crypto.CreateEmailVerificationToken(opts.CurrentSecret(), currentUser.Email, newEmail, emailVerificationExpirySeconds(opts), nil)
			// Upstream update-user.ts:776 logs the existing-email attempt at
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
			// Upstream refreshes the session cookie with the new email
			// (update-user.ts:789-795).
			if updatedRow != nil {
				if cookiesOut, cookieErr := newSessionCookies(opts, input.CookieRequestHeaders, token, rowToSession(sessionRow, opts), rowToUser(updatedRow, opts), opts.Session, time.Now().UTC()); cookieErr == nil {
					out.SetCookie = cookiesOut
				}
				// Fan out to secondary sessions like UpdateUser post-commit
				// (upstream updateUser -> refreshUserSessions).
				if serr := refreshSecondaryUserSessions(opts, rowToUser(updatedRow, opts)); serr != nil {
					return nil, huma.NewError(types.StatusForCode(types.ErrFailedToUpdateUser), types.ErrFailedToUpdateUser)
				}
			}
			if canSendVerification {
				// Issuance is the upstream HS256 email JWT
				// (createEmailVerificationToken, email-verification.ts:17-43).
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
			// plus requestType=change-email-confirmation
			// (update-user.ts:832-840). Stateful rows remain readable in
			// verify-email as a bounded legacy bridge.
			confirmationToken, createErr := crypto.CreateEmailVerificationToken(opts.CurrentSecret(), currentUser.Email, newEmail, emailVerificationExpirySeconds(opts), map[string]any{"requestType": "change-email-confirmation"})
			if createErr != nil {
				return nil, huma.NewError(types.StatusForCode(types.ErrFailedToCreateVerification), types.ErrFailedToCreateVerification)
			}
			// Delivery failures never fail the route: upstream awaits via
			// runInBackgroundOrAwait, which logs and continues.
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
		// requestType=change-email-verification (update-user.ts:869-877).
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
		if input.Body.Password != nil {
			accountRow, err := opts.DB.FindOne(ctx, "account", []types.Where{
				{Field: "userId", Value: userID},
				{Field: "providerId", Value: "credential", Connector: "AND"},
			}, nil)
			if err != nil || accountRow == nil {
				// Upstream throws BAD_REQUEST for a missing credential account
				// (update-user.ts:271-274 set-password, :478-481 delete-user);
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
			// Upstream token path returns early (update-user.ts:492-504)
			// before the freshAge gate (:539-545): a valid token deletes
			// even on a stale session, so no freshness check applies here.
			// The non-token path enforces freshness via the gate below.
			// Upstream delegates to deleteUserCallback (update-user.ts:492-503):
			// the single-use token is consumed atomically first (burned even
			// for a wrong owner), then the account is deleted with hooks.
			storedUserID, consumeErr := consumeDeleteAccountToken(ctx, opts, *input.Body.Token)
			if consumeErr != nil || storedUserID != userID {
				// Upstream INVALID_TOKEN resolves to 401 by majority (e.g. UNAUTHORIZED
				// in sign-in.ts:293, account.ts:288, email-verification.ts:300). Note
				// POST /delete-user with a token delegates to deleteUserCallback
				// upstream, which throws NOT_FOUND (update-user.ts:641-642); Go
				// validates inline, so the canonical status applies.
				return nil, huma.NewError(types.StatusForCode(types.ErrInvalidToken), types.ErrInvalidToken)
			}
			if err := finishDeleteUser(ctx, opts, userID, currentUser); err != nil {
				// A hook-thrown APIError keeps its own status (upstream
				// beforeDelete/afterDelete are awaited directly, so a thrown
				// status propagates); hook errors arrive unwrapped through
				// runBeforeDeleteHook/runAfterDeleteHook/finishDeleteUser.
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
			// runInBackgroundOrAwait, which logs and continues.
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
			// A hook-thrown APIError keeps its own status (see the token
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
	// JWTs; the Go stateful row keeps a random token too); only the row ID
	// honors the context generator (upstream createVerificationValue flows
	// through the adapter defaultValue honoring generateId).
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
	// storeInDatabase): secondary storage leads and the database row is
	// written only with Verification.StoreInDatabase (or when no secondary
	// backend exists).
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
	// storeInDatabase): secondary storage leads and the database row is
	// written only with Verification.StoreInDatabase (or when no secondary
	// backend exists).
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
// gets an error; a wrong-owner token is still burned. It returns the stored
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
		// The transaction commits the consuming delete — including
		// expired-row cleanup — so concurrent callbacks with the same token
		// can only delete the account once.
		// The transaction result is intentionally unobserved: success is
		// carried by the consumed flag (unconsumed returns the not-found
		// error below). Fail-safe by construction.
		_ = opts.DB.Transaction(ctx, func(tx types.Adapter) error {
			row, err := tx.FindOne(ctx, "verification", []types.Where{
				{Field: "identifier", Value: stored},
			}, nil)
			if err != nil || row == nil {
				if verificationStoreUsesPlainFallback(option) && stored != identifier {
					row, err = tx.FindOne(ctx, "verification", []types.Where{
						{Field: "identifier", Value: identifier},
					}, nil)
				}
				if err != nil || row == nil {
					return errDeleteTokenNotFound
				}
			}
			expiresAt, _ := row["expiresAt"].(time.Time)
			live := !expiresAt.IsZero() && !time.Now().UTC().After(expiresAt)
			if v, _ := row["value"].(string); v != "" && live {
				userID = v
			}
			if err := tx.Delete(ctx, "verification", []types.Where{
				{Field: "identifier", Value: stored},
			}); err != nil {
				return err
			}
			if verificationStoreUsesPlainFallback(option) && stored != identifier {
				_ = tx.Delete(ctx, "verification", []types.Where{
					{Field: "identifier", Value: identifier},
				})
			}
			if userID != "" {
				consumed = true
			}
			return nil
		})
	}
	if opts.SecondaryStorage != nil && consumed {
		_ = deleteSecondaryVerification(opts, identifier)
	}
	if !consumed {
		return "", errDeleteTokenNotFound
	}
	return userID, nil
}

// finishDeleteUser runs the shared delete-user tail used by POST /delete-user
// (direct and token paths) and GET /delete-user/callback: beforeDelete hooks
// (request-aware), the transactional record delete, the secondary-storage
// session purge, then afterDelete hooks (request-aware). Cleanup ordering
// mirrors upstream deleteUserCallback (update-user.ts:644-657): hooks bracket
// the user/session/account deletes. Upstream runs those deletes as sequential
// awaits with no rollback; Go keeps the historical transactional delete as
// intentional hardening (all-or-nothing instead of partial state on mid-flow
// failure).
func finishDeleteUser(ctx context.Context, opts types.Options, userID string, user types.User) error {
	if err := runBeforeDeleteHook(ctx, &opts.User.DeleteUser, &user); err != nil {
		return err
	}
	if err := deleteUserRecords(ctx, opts.DB, userID); err != nil {
		return err
	}
	// Secondary-storage fan-out (P08-G2; upstream deleteUserSessions):
	// the transactional delete above purges only DB rows, so without this
	// the active-sessions-* index + per-token entries survive deletion.
	// Mirrors the deleteSecondaryAwareUserSessions call in ChangePassword
	// (password.go); guarded on a configured backend so the DB-only path is
	// a single transaction with no extra round-trip.
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

// deleteAccountIdentifier names the delete-account verification identifier.
// Upstream TypeScript value: `delete-account-${token}` (update-user.ts).
func deleteAccountIdentifier(token string) string {
	return "delete-account-" + token
}

func rowToAccount(row map[string]any) accountRecord {
	rec := accountRecord{}
	if v, _ := row["id"].(string); v != "" {
		rec.ID = v
	}
	if v, _ := row["providerId"].(string); v != "" {
		rec.ProviderID = v
	}
	if v, ok := row["createdAt"].(time.Time); ok {
		rec.CreatedAt = v
	}
	if v, ok := row["updatedAt"].(time.Time); ok {
		rec.UpdatedAt = v
	}
	if v, _ := row["accountId"].(string); v != "" {
		rec.AccountID = v
	}
	if v, _ := row["userId"].(string); v != "" {
		rec.UserID = v
	}
	if v, _ := row["scope"].(string); v != "" {
		rec.Scopes = strings.Split(v, ",")
	} else {
		rec.Scopes = []string{}
	}
	return rec
}
