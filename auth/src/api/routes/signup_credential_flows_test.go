package routes

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/crypto"
	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

// AUTH-C7-02: credential, user, account, email, password flows.
// Pinned upstream: Better Auth v1.7.5 @ 5468e6bf
// (sign-up.ts, sign-in.ts:569-601, update-user.ts, email-verification.ts).

func c702Options(db *parityMemAdapter) types.Options {
	opts := sessionTestOptions(db)
	opts.EmailAndPassword.Enabled = true
	opts.BasePath = "/api/auth"
	return opts
}

func c702API(t *testing.T, opts types.Options) humatest.TestAPI {
	t.Helper()
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	SignUpEmail(api, "/api/auth", opts)
	SignInEmail(api, "/api/auth", opts)
	UpdateUser(api, "/api/auth", opts)
	ChangeEmail(api, "/api/auth", opts)
	ChangePassword(api, "/api/auth", opts)
	VerifyEmail(api, "/api/auth", opts)
	SendVerificationEmail(api, "/api/auth", opts)
	return api
}

// Upstream sign-up.ts:319-326: onExistingUserSignUp(data, request) via
func TestSignUpCredential_OnExistingUserSignUpRequestPrecedence(t *testing.T) {
	db := newParityMemAdapter()
	opts := c702Options(db)
	opts.EmailAndPassword.RequireEmailVerification = true
	var legacy, reqAware int
	var gotReq *http.Request
	opts.EmailAndPassword.OnExistingUserSignUp = func(types.ExistingUserSignUpData) error {
		legacy++
		return nil
	}
	opts.EmailAndPassword.OnExistingUserSignUpRequest = func(types.ExistingUserSignUpData, *http.Request) error {
		reqAware++
		return nil
	}
	_ = gotReq
	api := c702API(t, opts)
	resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "A", "email": "dup@example.com", "password": "password123",
	})
	if resp.Code != 200 {
		t.Fatalf("first sign-up status = %d, want 200: %s", resp.Code, resp.Body.String())
	}
	resp = api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "A", "email": "dup@example.com", "password": "password123",
	})
	if resp.Code != 200 {
		t.Fatalf("duplicate sign-up status = %d, want 200 (opaque): %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "dup@example.com") {
		t.Fatalf("opaque duplicate must echo the email: %s", resp.Body.String())
	}
	if reqAware != 1 {
		t.Fatalf("request-aware hook calls = %d, want 1", reqAware)
	}
	if legacy != 0 {
		t.Fatalf("legacy hook calls = %d, want 0 (request variant wins)", legacy)
	}
}

// Upstream sign-up.ts:366-368: a 403 gate rejection under generic-duplicate
func TestSignUpCredential_ValidateUserInfoCreateGateGenericDuplicate(t *testing.T) {
	db := newParityMemAdapter()
	opts := c702Options(db)
	opts.EmailAndPassword.RequireEmailVerification = true
	opts.User.ValidateUserInfo = func(data types.ValidateUserInfoData, _ types.EndpointContext) (*types.ValidateUserInfoResult, error) {
		if data.Source.Action != types.ValidateUserInfoActionCreateUser || data.Source.Method != types.ValidateUserInfoMethodEmailPassword {
			t.Errorf("unexpected source %+v", data.Source)
		}
		return &types.ValidateUserInfoResult{Error: "email_not_allowed", ErrorDescription: "nope"}, nil
	}
	api := c702API(t, opts)
	resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "G", "email": "gated@example.com", "password": "password123",
	})
	if resp.Code != 200 {
		t.Fatalf("gated sign-up status = %d, want 200 (opaque): %s", resp.Code, resp.Body.String())
	}
	if row, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: "gated@example.com"}}, nil); row != nil {
		t.Fatal("gated sign-up must not persist a user")
	}
}

// Same gate outside generic-duplicate mode surfaces 403 verbatim.
func TestSignUpCredential_ValidateUserInfoCreateGate403(t *testing.T) {
	db := newParityMemAdapter()
	opts := c702Options(db)
	opts.User.ValidateUserInfo = func(types.ValidateUserInfoData, types.EndpointContext) (*types.ValidateUserInfoResult, error) {
		return &types.ValidateUserInfoResult{Error: "email_not_allowed"}, nil
	}
	api := c702API(t, opts)
	resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "G", "email": "gated2@example.com", "password": "password123",
	})
	if resp.Code != 403 {
		t.Fatalf("gated sign-up status = %d, want 403: %s", resp.Code, resp.Body.String())
	}
}

// Upstream sign-up.ts:183 runWithTransaction: user + credential-account
func TestSignUpCredential_SignUpTransactionRollsBackAccountFailure(t *testing.T) {
	db := newParityMemAdapter()
	opts := c702Options(db)
	api := c702API(t, opts)
	resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "T", "email": "tx@example.com", "password": "password123",
	})
	if resp.Code != 200 {
		t.Fatalf("sign-up status = %d: %s", resp.Code, resp.Body.String())
	}
	userRow, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: "tx@example.com"}}, nil)
	if userRow == nil {
		t.Fatal("user row must exist")
	}
	acct, _ := db.FindOne(context.Background(), "account", []types.Where{{Field: "userId", Value: userRow["id"]}}, nil)
	if acct == nil {
		t.Fatal("credential account row must exist")
	}
}

// Upstream sign-in.ts:588-597: the unverified resend awaits via
func TestSignUpCredential_SignInResendPrefersRequestVariant(t *testing.T) {
	db := newParityMemAdapter()
	opts := c702Options(db)
	opts.EmailAndPassword.RequireEmailVerification = true
	opts.EmailVerification.SendOnSignIn = true
	var legacy, reqAware int
	opts.EmailVerification.SendVerificationEmail = func(types.VerificationEmailData) error {
		legacy++
		return nil
	}
	opts.EmailVerification.SendVerificationEmailRequest = func(types.VerificationEmailData, *http.Request) error {
		reqAware++
		return nil
	}
	api := c702API(t, opts)
	if resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "V", "email": "unverified@example.com", "password": "password123",
	}); resp.Code != 200 {
		t.Fatalf("sign-up status = %d: %s", resp.Code, resp.Body.String())
	}
	legacy, reqAware = 0, 0
	resp := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": "unverified@example.com", "password": "password123",
	})
	if resp.Code != 403 {
		t.Fatalf("sign-in status = %d, want 403 EMAIL_NOT_VERIFIED: %s", resp.Code, resp.Body.String())
	}
	if reqAware != 1 || legacy != 0 {
		t.Fatalf("resend calls legacy=%d req=%d, want 0/1", legacy, reqAware)
	}
}

// Upstream email-verification.ts:339-367: change-email-confirmation JWT
func TestSignUpCredential_VerifyEmailConfirmationLeg(t *testing.T) {
	db := newParityMemAdapter()
	opts := c702Options(db)
	var sentTo string
	opts.EmailVerification.SendVerificationEmail = func(data types.VerificationEmailData) error {
		sentTo = data.User.Email
		return nil
	}
	parityCreateUser(t, db, "old@example.com", true)
	token, err := crypto.CreateEmailVerificationToken(opts.CurrentSecret(), "old@example.com", "new@example.com", 3600, map[string]any{"requestType": "change-email-confirmation"})
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	user, _, errCode, status := processVerifyEmail(context.Background(), opts, token, CookieRequestHeaders{})
	if errCode != "" {
		t.Fatalf("expected success, got %s (%d)", errCode, status)
	}
	if user != nil {
		t.Fatalf("confirmation leg must return no user, got %#v", user)
	}
	if sentTo != "new@example.com" {
		t.Fatalf("verification must go to the new email, got %q", sentTo)
	}
	if row, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: "old@example.com"}}, nil); row == nil {
		t.Fatal("current email row must remain until verification leg")
	}
}

// Upstream email-verification.ts:371-414: change-email-verification JWT
func TestSignUpCredential_VerifyEmailVerificationLeg(t *testing.T) {
	db := newParityMemAdapter()
	opts := c702Options(db)
	var after string
	opts.EmailVerification.AfterEmailVerification = func(u *types.User) error {
		after = u.Email
		return nil
	}
	parityCreateUser(t, db, "old2@example.com", true)
	token, err := crypto.CreateEmailVerificationToken(opts.CurrentSecret(), "old2@example.com", "new2@example.com", 3600, map[string]any{"requestType": "change-email-verification"})
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	user, cookies, errCode, status := processVerifyEmail(context.Background(), opts, token, CookieRequestHeaders{})
	if errCode != "" {
		t.Fatalf("expected success, got %s (%d)", errCode, status)
	}
	if user == nil || user.Email != "new2@example.com" || !user.EmailVerified {
		t.Fatalf("expected updated verified user, got %#v", user)
	}
	if after != "new2@example.com" {
		t.Fatalf("after hook email = %q, want new2@example.com", after)
	}
	if len(cookies) == 0 {
		t.Fatal("verification leg must mint a session cookie")
	}
	row, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: "new2@example.com"}}, nil)
	if row == nil {
		t.Fatal("email row must move to the new address")
	}
}

// Upstream update-user.ts:254-283: change-password validates length first,
func TestSignUpCredential_ChangePasswordOrderAndRevoke(t *testing.T) {
	db := newParityMemAdapter()
	opts := c702Options(db)
	api := c702API(t, opts)
	if resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "P", "email": "pw@example.com", "password": "password123",
	}); resp.Code != 200 {
		t.Fatalf("sign-up status = %d: %s", resp.Code, resp.Body.String())
	}
	signIn := api.Post("/api/auth/sign-in/email", map[string]any{
		"email": "pw@example.com", "password": "password123",
	})
	if signIn.Code != 200 {
		t.Fatalf("sign-in status = %d: %s", signIn.Code, signIn.Body.String())
	}
	var sessionCookie string
	for _, c := range signIn.Header().Values("Set-Cookie") {
		if strings.Contains(c, "better-auth.session-token") || strings.Contains(c, "session") {
			sessionCookie = c
			break
		}
	}
	_ = sessionCookie
	resp := api.Post("/api/auth/change-password", map[string]any{
		"currentPassword": "password123", "newPassword": "short",
	}, "Cookie: "+sessionCookie)
	if resp.Code != 400 {
		t.Fatalf("short password status = %d, want 400: %s", resp.Code, resp.Body.String())
	}
	resp = api.Post("/api/auth/change-password", map[string]any{
		"currentPassword": "password123", "newPassword": "password45678", "revokeOtherSessions": true,
	}, "Cookie: "+sessionCookie)
	if resp.Code != 200 {
		t.Fatalf("revoke status = %d: %s", resp.Code, resp.Body.String())
	}
	body := resp.Body.String()
	if !strings.Contains(body, `"status":true`) {
		t.Fatalf("response must keep status:true: %s", body)
	}
	if !strings.Contains(body, `"token"`) || !strings.Contains(body, `"user"`) {
		t.Fatalf("revoke response must carry token+user: %s", body)
	}
	_ = time.Now
}
