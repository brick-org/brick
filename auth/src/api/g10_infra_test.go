package api

import (
	"net/http"
	"testing"

	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2/humatest"
)

// G10 narrowing (PARITY_V2 P09 R4): upstream formCsrfMiddleware is
// per-endpoint `use:` ONLY on /sign-in/email (sign-in.ts:406) and
// /sign-up/email (sign-up.ts:34); the global middleware uses
// forceValidate=false (origin-check.ts:67-76,247-251). Cookie-less
// cross-site-navigate / bare-Origin force validation therefore applies to
// the two login legs only; all other routes keep origin+cookie validation
// with the permissive cookie-less fallback.

func g10OriginOptions(baseURL string) types.Options {
	return types.Options{BaseURL: baseURL, BasePath: "/api/auth"}
}

// Non-login routes keep the permissive cookie-less fallback: a bare
// untrusted Origin without cookies must NOT 403 on sign-out.
func TestG10_SignOut_CookieLessBareOriginPasses(t *testing.T) {
	opts := g10OriginOptions("https://app.example")
	api := Router(humatest.NewAdapter(), "/api/auth", opts)
	resp := humatest.Wrap(t, api).Post("/api/auth/sign-out",
		"Origin: https://evil.example",
	)
	if resp.Code == http.StatusForbidden {
		t.Fatalf("non-login cookie-less bare origin must pass (global forceValidate=false), got 403: %s", resp.Body.String())
	}
}

// Same permissive fallback on another non-login mutating route.
func TestG10_OtherRoute_CookieLessBareOriginPasses(t *testing.T) {
	opts := g10OriginOptions("https://app.example")
	api := Router(humatest.NewAdapter(), "/api/auth", opts)
	resp := humatest.Wrap(t, api).Post("/api/auth/revoke-session",
		"Origin: https://evil.example",
	)
	if resp.Code == http.StatusForbidden {
		t.Fatalf("non-login cookie-less bare origin must pass (global forceValidate=false), got 403: %s", resp.Body.String())
	}
}

// Non-login routes must not block cookie-less cross-site navigations.
func TestG10_SignOut_CrossSiteNavigatePasses(t *testing.T) {
	opts := g10OriginOptions("https://app.example")
	api := Router(humatest.NewAdapter(), "/api/auth", opts)
	resp := humatest.Wrap(t, api).Post("/api/auth/sign-out",
		"Sec-Fetch-Site: cross-site",
		"Sec-Fetch-Mode: navigate",
	)
	if resp.Code == http.StatusForbidden {
		t.Fatalf("non-login cross-site navigate must pass (formCsrf per-endpoint only), got 403: %s", resp.Body.String())
	}
}

// Login legs keep the force gate: cross-site navigations 403.
func TestG10_SignIn_CrossSiteNavigateBlocked(t *testing.T) {
	opts := g10OriginOptions("https://app.example")
	api := Router(humatest.NewAdapter(), "/api/auth", opts)
	resp := humatest.Wrap(t, api).Post("/api/auth/sign-in/email",
		"Sec-Fetch-Site: cross-site",
		"Sec-Fetch-Mode: navigate",
	)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("sign-in cross-site navigation must be 403, got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestG10_SignUp_CrossSiteNavigateBlocked(t *testing.T) {
	opts := g10OriginOptions("https://app.example")
	api := Router(humatest.NewAdapter(), "/api/auth", opts)
	resp := humatest.Wrap(t, api).Post("/api/auth/sign-up/email",
		"Sec-Fetch-Site: cross-site",
		"Sec-Fetch-Mode: navigate",
	)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("sign-up cross-site navigation must be 403, got %d: %s", resp.Code, resp.Body.String())
	}
}

// Login legs keep the force gate: cookie-less untrusted bare Origin 403.
func TestG10_SignIn_CookieLessUntrustedOriginBlocked(t *testing.T) {
	opts := g10OriginOptions("https://app.example")
	api := Router(humatest.NewAdapter(), "/api/auth", opts)
	resp := humatest.Wrap(t, api).Post("/api/auth/sign-in/email",
		"Origin: https://evil.example",
	)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("sign-in cookie-less untrusted origin must be 403, got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestG10_SignUp_CookieLessUntrustedOriginBlocked(t *testing.T) {
	opts := g10OriginOptions("https://app.example")
	api := Router(humatest.NewAdapter(), "/api/auth", opts)
	resp := humatest.Wrap(t, api).Post("/api/auth/sign-up/email",
		"Origin: https://evil.example",
	)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("sign-up cookie-less untrusted origin must be 403, got %d: %s", resp.Code, resp.Body.String())
	}
}
