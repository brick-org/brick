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
	// (post_logout_redirect_uri), which stays EXCLUDED as social per
	// SCOPE.md (no social providers in core scope).
	CallbackURL *string `json:"callbackURL,omitempty"`
	// DisableRedirect is parsed for parity but has no effect: it only
	// toggles the provider logout redirect/Location contract, which is
	// explicitly NOT implemented (excluded as social).
	DisableRedirect *bool `json:"disableRedirect,omitempty"`
	// State is parsed for parity but has no effect: it only feeds the
	// provider logout endpoint, excluded as social.
	State *string `json:"state,omitempty"`
}

type signOutInput struct {
	Authorization string `header:"Authorization"`
	Cookie        string `header:"Cookie"`
	CookieRequestHeaders
	// Optional body (upstream signOutBodySchema.optional()): nil when the
	// caller sends no body. Pointer keeps the huma request body optional
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
//
// Core parity (upstream sign-out.ts:5-26,42,78-100 @ 5468e6bf): the optional
// body {callbackURL,disableRedirect,state} is parsed above but intentionally
// has no effect — it only drives the provider OIDC RP-initiated logout flow,
// which stays EXCLUDED as social. The provider url/redirect/Location
// contract is explicitly NOT implemented: the response is always
// {success:true} and no Location header is ever set. Core delete + cookie
// clear (incl. chunked session_data cleanup) matches upstream.
func SignOut(api huma.API, basePath string, opts types.Options) {
	registerAuthOperation(api, huma.Operation{
		Tags:        []string{"Auth"},
		Method:      http.MethodPost,
		Path:        basePath + "/sign-out",
		OperationID: "signOut",
		Summary:     "Sign out the current user",
	}, opts, func(ctx context.Context, input *signOutInput) (*signOutOutput, error) {
		// requireHeaders (upstream sign-out.ts:42): a call with neither a
		// Cookie nor an Authorization header is invalid usage and answers
		// 401 FAILED_TO_GET_SESSION instead of success:true. A present-but-
		// unreadable session still succeeds (upstream never throws for a
		// missing session).
		if input.Cookie == "" && input.Authorization == "" {
			return nil, huma.NewError(types.StatusForCode(types.ErrFailedToGetSession), types.ErrFailedToGetSession)
		}
		// Body fields are accepted for schema parity only; the provider
		// logout flow is excluded (see signOutBody docs).
		_ = input.Body
		token := sessionTokenFromRequest(input.Cookie, input.Authorization, opts)
		if token != "" && (opts.SecondaryStorage != nil || opts.DB != nil) {
			// Secondary-aware delete across both stores per the flag matrix
			// (upstream deleteSession, internal-adapter.ts:849-913): with no
			// secondary backend this is a plain database delete, as before.
			// Best-effort like the previous direct delete — sign-out always
			// succeeds and clears cookies either way (upstream never throws
			// for a missing session either).
			_ = deleteSecondaryAwareSession(ctx, opts, token) //nolint:errcheck
		}
		out := &signOutOutput{}
		// Request-aware clearing (Secure/Domain + chunk-aware session_data
		// cleanup, upstream deleteSessionCookie clean()).
		out.SetCookie = expiredSessionCookiesWithContext(ctx, opts, input.CookieRequestHeaders, input.Cookie)
		out.Body.Success = true
		return out, nil
	})
}
