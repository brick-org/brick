package routes

import (
	"context"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/types"
)

// Wiring: the sign-up/sign-in/session issuance legs (issueSessionCookies →
// newSessionDataCookie in session.go) must carry the same returned:false
// filtering proven for the context path in filter_v1_test.go. Upstream:
// cookies.test.ts "Cookie Cache Field Filtering" (all strategies).

func TestIssuanceFilter_IssuanceLegFiltersReturnedFalse(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	opts.Session.CookieCache.Enabled = true
	opts.User.Model.AdditionalFields = map[string]types.FieldAttribute{
		"internalNote": {Type: "string", DefaultValue: "", Returned: filterV1BoolPtr(false)},
		"publicBio":    {Type: "string", DefaultValue: "", Returned: filterV1BoolPtr(true)},
	}
	now := time.Now().UTC()
	session := types.Session{
		ID: "sess-issue", UserID: "user-1", Token: "tok-issue",
		ExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	}
	user := types.User{
		ID: "user-1", Email: "issue@example.com", EmailVerified: true,
		CreatedAt: now, UpdatedAt: now,
		AdditionalFields: map[string]any{
			"internalNote": "secret-note", "publicBio": "hello",
		},
	}
	out, err := issueSessionCookies(opts, CookieRequestHeaders{}, "tok-issue", session, user, opts.Session, now, false)
	if err != nil {
		t.Fatalf("issueSessionCookies: %v", err)
	}
	var cacheVal string
	for _, c := range out {
		if c.Name != "better-auth.session_token" && c.Name != "better-auth.session_data" {
			continue
		}
		if c.Name == "better-auth.session_data" {
			cacheVal = c.Name + "=" + c.Value
		}
	}
	if cacheVal == "" {
		for _, c := range out {
			if c.Value != "" {
				if _, ok := cachedSessionFromRequestFull(ctx, c.Name+"="+c.Value, opts.AllSecrets(), "tok-issue", opts); ok {
					cacheVal = c.Name + "=" + c.Value
					break
				}
			}
		}
	}
	if cacheVal == "" {
		t.Fatal("no decodable session_data cache cookie issued")
	}
	payload, ok := cachedSessionFromRequestFull(ctx, "better-auth.session_token=sessTok; "+cacheVal, opts.AllSecrets(), "tok-issue", opts)
	if !ok || payload == nil {
		t.Fatal("issued cache must decode via cachedSessionFromRequestFull")
	}
	filterV1AssertAbsent(t, payload.User.AdditionalFields, "internalNote")
	filterV1AssertPresent(t, payload.User.AdditionalFields, "publicBio", "hello")
	if payload.User.Email != "issue@example.com" {
		t.Fatalf("email = %q, want issue@example.com", payload.User.Email)
	}
}
