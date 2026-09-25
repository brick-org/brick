package routes

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

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

// nullableString tracks presence: absent keeps, explicit null clears (upstream).
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
// rejects plain `"image":"..."` payloads with 422 before the handler runs.
func (n *nullableString) TransformSchema(r huma.Registry, s *huma.Schema) *huma.Schema {
	return &huma.Schema{Type: huma.TypeString, Nullable: true}
}

// Rebuilds *http.Request for request-aware callbacks; nil when absent (upstream).
func callbackRequest(ctx context.Context) *http.Request {
	hc, _ := ctx.Value(humaContextKey{}).(huma.Context)
	return requestFromHuma(hc)
}

// Wraps context so request-aware hooks see the live request.
func humaRequestContext(parent context.Context, hc huma.Context) context.Context {
	if hc == nil {
		return parent
	}
	return context.WithValue(parent, humaContextKey{}, hc)
}

// Nil when absent; callers must tolerate nil (upstream).
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

// runBackgroundOrAwait mirrors upstream runInBackgroundOrAwait.
// Failures never fail the route; callers that must fail invoke directly.
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

// Prefers request-aware variant when set (upstream).
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

// Prefers request-aware variant when set (upstream).
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

// Prefers request-aware variant; errors abort deletion (upstream).
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

// Prefers request-aware variant; errors fail the route (upstream).
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
