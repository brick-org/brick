package routes

import (
	"context"
	"net/http"

	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
)

type signOutBody struct {
	// CallbackURL is parsed for parity (upstream sign-out.ts:5-26) but has
	// no effect here: it only feeds the provider OIDC RP-initiated logout
	CallbackURL *string `json:"callbackURL,omitempty"`
	// DisableRedirect is parsed for parity but has no effect: it only
	DisableRedirect *bool `json:"disableRedirect,omitempty"`
	// State is parsed for parity but has no effect: it only feeds the
	State *string `json:"state,omitempty"`
}

type signOutInput struct {
	Authorization string `header:"Authorization"`
	Cookie        string `header:"Cookie"`
	CookieRequestHeaders
	// Optional body (upstream signOutBodySchema.optional()): nil when the
	// so headerless-vs-bodyless still reaches the requireHeaders gate.
	Body *signOutBody
}

type signOutOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      struct {
		Success bool `json:"success"`
	}
}

// SignOut registers POST /sign-out.
func SignOut(api huma.API, basePath string, opts types.Options) {
	registerAuthOperation(api, huma.Operation{
		Tags:        []string{"Auth"},
		Method:      http.MethodPost,
		Path:        basePath + "/sign-out",
		OperationID: "signOut",
		Summary:     "Sign out the current user",
	}, opts, func(ctx context.Context, input *signOutInput) (*signOutOutput, error) {
		// requireHeaders (upstream sign-out.ts:42): a call with neither a
		// 401 FAILED_TO_GET_SESSION instead of success:true. A present-but-
		// unreadable session still succeeds (upstream never throws for a
		if input.Cookie == "" && input.Authorization == "" {
			return nil, huma.NewError(types.StatusForCode(types.ErrFailedToGetSession), types.ErrFailedToGetSession)
		}
		_ = input.Body
		token := sessionTokenFromRequest(input.Cookie, input.Authorization, opts)
		if token != "" && (opts.SecondaryStorage != nil || opts.DB != nil) {
			// (upstream deleteSession, internal-adapter.ts:849-913): with no
			// succeeds and clears cookies either way (upstream never throws
			_ = deleteSecondaryAwareSession(ctx, opts, token) //nolint:errcheck
		}
		out := &signOutOutput{}
		// cleanup, upstream deleteSessionCookie clean()).
		out.SetCookie = expiredSessionCookiesWithContext(ctx, opts, input.CookieRequestHeaders, input.Cookie)
		out.Body.Success = true
		return out, nil
	})
}
