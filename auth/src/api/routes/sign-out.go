package routes

import (
	"context"
	"net/http"

	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
)

type signOutInput struct {
	Authorization string `header:"Authorization"`
	Cookie        string `header:"Cookie"`
	CookieRequestHeaders
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
