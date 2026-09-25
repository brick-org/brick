package routes

import (
	"context"
	"strings"
	"testing"

	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

// Pinned upstream: sign-out.test.ts core legs (provider-logout URL legs are
// v1-excluded: no social providers in scope).

func credsSignOutAPI(t *testing.T, opts types.Options) humatest.TestAPI {
	t.Helper()
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	SignUpEmail(api, "/api/auth", opts)
	SignInEmail(api, "/api/auth", opts)
	SignOut(api, "/api/auth", opts)
	GetSession(api, "/api/auth", opts)
	return api
}

// sign-out.test.ts "should sign out": the session row is gone afterwards and
func TestCredsV1_SignOutDeletesSessionAndClearsCookies(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	api := credsSignOutAPI(t, opts)
	resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "Seed", "email": "signout@test.com", "password": "password123",
	})
	if resp.Code != 200 {
		t.Fatalf("seed sign-up = %d: %s", resp.Code, resp.Body.String())
	}
	cookie := sessionCookieOf(t, resp)
	resp = api.Post("/api/auth/sign-out", map[string]any{}, "Cookie: "+cookie)
	if resp.Code != 200 {
		t.Fatalf("sign-out = %d: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), `"success":true`) {
		t.Fatalf("success:true required, got %s", resp.Body.String())
	}
	if len(resp.Header().Values("Set-Cookie")) == 0 {
		t.Fatal("sign-out must clear local session cookies via Set-Cookie")
	}
	userRow, _ := db.FindOne(ctx, "user", []types.Where{{Field: "email", Value: "signout@test.com"}}, nil)
	sessions, _ := db.FindMany(ctx, "session", []types.Where{
		{Field: "userId", Value: stringField(userRow, "id")},
	}, 0, 0, nil, nil)
	if len(sessions) != 0 {
		t.Fatalf("sessions remaining after sign-out = %d, want 0", len(sessions))
	}
}

// clearing (upstream never throws for a missing session).
func TestCredsV1_SignOutClearsCookiesOnUnreadableSession(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	api := credsSignOutAPI(t, opts)
	resp := api.Post("/api/auth/sign-out", map[string]any{}, "Cookie: better-auth.session_token=garbage-token; auth_session_data=garbage")
	if resp.Code != 200 {
		t.Fatalf("sign-out = %d: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), `"success":true`) {
		t.Fatalf("success:true required, got %s", resp.Body.String())
	}
	if len(resp.Header().Values("Set-Cookie")) == 0 {
		t.Fatal("unreadable-session sign-out must still clear local cookies")
	}
}
