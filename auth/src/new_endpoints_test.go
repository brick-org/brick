package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/brick-org/brick/auth/src"
)

// newCoreTestServer mounts auth with the given DB, defaulting BaseURL to the
// test server URL so absolute redirect URLs stay trusted.
func newCoreTestServer(t *testing.T, db auth.DBAdapter, opts auth.Options) *httptest.Server {
	t.Helper()
	adapter, srv := newTestAdapter(t)
	opts.Secret = "test-secret"
	opts.Adapter = adapter
	opts.DB = db
	if opts.BaseURL == "" {
		opts.BaseURL = srv.URL
	}
	mustBetterAuth(t, opts)
	return srv
}

func postJSON(t *testing.T, target, cookie, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post %s failed: %v", target, err)
	}
	return resp
}

func getWithCookie(t *testing.T, target, cookie string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get %s failed: %v", target, err)
	}
	return resp
}

func noRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func baseTestOptions() auth.Options {
	return auth.Options{
		Session:          auth.SessionOptions{ExpiresIn: 3600, UpdateAge: intPtr(3600)},
		EmailAndPassword: auth.EmailAndPasswordOptions{Enabled: true},
	}
}

func userIDByEmail(t *testing.T, db auth.DBAdapter, email string) string {
	t.Helper()
	row, err := db.FindOne(context.Background(), "user", []auth.Where{
		{Field: "email", Value: email},
	}, nil)
	if err != nil || row == nil {
		t.Fatalf("expected user row for %s (err=%v)", email, err)
	}
	id, _ := row["id"].(string)
	return id
}

func createSocialAccount(t *testing.T, db auth.DBAdapter, userID string, fields map[string]any) string {
	t.Helper()
	now := time.Now().UTC()
	data := map[string]any{
		"id":         "acc-" + userID[:8],
		"userId":     userID,
		"providerId": "mock",
		"accountId":  "mock-" + userID[:8],
		"createdAt":  now,
		"updatedAt":  now,
	}
	for key, value := range fields {
		data[key] = value
	}
	row, err := db.Create(context.Background(), "account", data, nil)
	if err != nil {
		t.Fatalf("create social account: %v", err)
	}
	id, _ := row["id"].(string)
	return id
}

func TestRevokeSessions_RevokesAllIncludingCurrent(t *testing.T) {
	db := newMemoryAdapter()
	srv := newCoreTestServer(t, db, baseTestOptions())

	resp, cookie1 := signUp(t, srv.URL, "revoke-all@example.com")
	resp.Body.Close()

	signInResp, err := http.Post(srv.URL+"/api/auth/sign-in/email", "application/json", strings.NewReader(`{"email":"revoke-all@example.com","password":"password123"}`))
	if err != nil {
		t.Fatalf("sign-in failed: %v", err)
	}
	cookie2 := cookieHeaderFromSetCookies(signInResp.Header.Values("Set-Cookie"))
	signInResp.Body.Close()

	revokeResp := postJSON(t, srv.URL+"/api/auth/revoke-sessions", cookie1, `{}`)
	defer revokeResp.Body.Close()
	if revokeResp.StatusCode != http.StatusOK {
		t.Fatalf("revoke-sessions expected 200, got %d", revokeResp.StatusCode)
	}
	var revokeBody struct {
		Status bool `json:"status"`
	}
	decodeJSON(t, revokeResp, &revokeBody)
	if !revokeBody.Status {
		t.Fatal("expected status=true")
	}

	for name, cookie := range map[string]string{"first": cookie1, "second": cookie2} {
		sessionResp := getSession(t, srv.URL, cookie)
		var nullBody map[string]any
		decodeJSON(t, sessionResp, &nullBody)
		sessionResp.Body.Close()
		if sessionResp.StatusCode != http.StatusOK {
			t.Fatalf("%s session: expected 200 null after revoke-all, got %d", name, sessionResp.StatusCode)
		}
		if nullBody["session"] != nil || nullBody["user"] != nil {
			t.Fatalf("%s session: expected null session/user after revoke-all, got %v", name, nullBody)
		}
	}

	unauthResp := postJSON(t, srv.URL+"/api/auth/revoke-sessions", "", `{}`)
	defer unauthResp.Body.Close()
	if unauthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated revoke-sessions expected 401, got %d", unauthResp.StatusCode)
	}
}

func TestRevokeOtherSessions_KeepsCurrent(t *testing.T) {
	db := newMemoryAdapter()
	srv := newCoreTestServer(t, db, baseTestOptions())

	resp, cookie1 := signUp(t, srv.URL, "revoke-other@example.com")
	resp.Body.Close()

	signInResp, err := http.Post(srv.URL+"/api/auth/sign-in/email", "application/json", strings.NewReader(`{"email":"revoke-other@example.com","password":"password123"}`))
	if err != nil {
		t.Fatalf("sign-in failed: %v", err)
	}
	cookie2 := cookieHeaderFromSetCookies(signInResp.Header.Values("Set-Cookie"))
	signInResp.Body.Close()

	revokeResp := postJSON(t, srv.URL+"/api/auth/revoke-other-sessions", cookie1, `{}`)
	defer revokeResp.Body.Close()
	if revokeResp.StatusCode != http.StatusOK {
		t.Fatalf("revoke-other-sessions expected 200, got %d", revokeResp.StatusCode)
	}

	keptResp := getSession(t, srv.URL, cookie1)
	keptResp.Body.Close()
	if keptResp.StatusCode != http.StatusOK {
		t.Fatalf("current session should survive, got %d", keptResp.StatusCode)
	}
	revokedResp := getSession(t, srv.URL, cookie2)
	var revokedBody map[string]any
	decodeJSON(t, revokedResp, &revokedBody)
	revokedResp.Body.Close()
	if revokedResp.StatusCode != http.StatusOK {
		t.Fatalf("other session: expected 200 null after revoke, got %d", revokedResp.StatusCode)
	}
	if revokedBody["session"] != nil || revokedBody["user"] != nil {
		t.Fatalf("other session should be revoked (null), got %v", revokedBody)
	}

	unauthResp := postJSON(t, srv.URL+"/api/auth/revoke-other-sessions", "", `{}`)
	defer unauthResp.Body.Close()
	if unauthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated revoke-other-sessions expected 401, got %d", unauthResp.StatusCode)
	}
}

func TestUpdateSession_PersistsAdditionalFields(t *testing.T) {
	db := newMemoryAdapter()
	// B2 upstream parity: undeclared-only bodies 400, so declare the field
	opts := baseTestOptions()
	opts.Session.Model.AdditionalFields = map[string]auth.FieldAttribute{"favoriteColor": {}}
	srv := newCoreTestServer(t, db, opts)

	resp, cookie := signUp(t, srv.URL, "update-session@example.com")
	resp.Body.Close()

	updateResp := postJSON(t, srv.URL+"/api/auth/update-session", cookie, `{"favoriteColor":"blue"}`)
	defer updateResp.Body.Close()
	if updateResp.StatusCode != http.StatusOK {
		t.Fatalf("update-session expected 200, got %d", updateResp.StatusCode)
	}
	var updateBody struct {
		Session struct {
			Token string `json:"token"`
		} `json:"session"`
	}
	decodeJSON(t, updateResp, &updateBody)
	if updateBody.Session.Token == "" {
		t.Fatal("expected session token in response")
	}

	token := verifySignedCookieValue(t, extractCookieValue(t, cookie, "better-auth.session_token"))
	row, err := db.FindOne(context.Background(), "session", []auth.Where{
		{Field: "token", Value: token},
	}, nil)
	if err != nil || row == nil {
		t.Fatalf("expected session row (err=%v)", err)
	}
	if row["favoriteColor"] != "blue" {
		t.Fatalf("expected favorite_color persisted, got %#v", row)
	}

	emptyResp := postJSON(t, srv.URL+"/api/auth/update-session", cookie, `{}`)
	defer emptyResp.Body.Close()
	if emptyResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty update-session expected 400, got %d", emptyResp.StatusCode)
	}

	unauthResp := postJSON(t, srv.URL+"/api/auth/update-session", "", `{"favoriteColor":"red"}`)
	defer unauthResp.Body.Close()
	if unauthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated update-session expected 401, got %d", unauthResp.StatusCode)
	}
}

func TestVerifyPassword_AcceptsCurrentPassword(t *testing.T) {
	db := newMemoryAdapter()
	srv := newCoreTestServer(t, db, baseTestOptions())

	resp, cookie := signUp(t, srv.URL, "verify-password@example.com")
	resp.Body.Close()

	okResp := postJSON(t, srv.URL+"/api/auth/verify-password", cookie, `{"password":"password123"}`)
	defer okResp.Body.Close()
	if okResp.StatusCode != http.StatusOK {
		t.Fatalf("verify-password expected 200, got %d", okResp.StatusCode)
	}
	var okBody struct {
		Status bool `json:"status"`
	}
	decodeJSON(t, okResp, &okBody)
	if !okBody.Status {
		t.Fatal("expected status=true")
	}

	wrongResp := postJSON(t, srv.URL+"/api/auth/verify-password", cookie, `{"password":"wrong-password"}`)
	defer wrongResp.Body.Close()
	if wrongResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("wrong password expected 400, got %d", wrongResp.StatusCode)
	}

	unauthResp := postJSON(t, srv.URL+"/api/auth/verify-password", "", `{"password":"password123"}`)
	defer unauthResp.Body.Close()
	if unauthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated verify-password expected 401, got %d", unauthResp.StatusCode)
	}
}
func TestDeleteUserCallback_DeletesUserWithRedirect(t *testing.T) {
	var sent auth.DeleteAccountVerificationData
	srv, db := newMemoryAuthServer(t, auth.Options{
		Session:          auth.SessionOptions{ExpiresIn: 3600, UpdateAge: intPtr(3600)},
		EmailAndPassword: auth.EmailAndPasswordOptions{Enabled: true},
		User: auth.UserOptions{
			DeleteUser: auth.DeleteUserOptions{
				Enabled: true,
				SendDeleteAccountVerification: func(data auth.DeleteAccountVerificationData) error {
					sent = data
					return nil
				},
			},
		},
	})

	resp, cookie := signUp(t, srv.URL, "delete-cb@example.com")
	resp.Body.Close()

	deleteReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/auth/delete-user", strings.NewReader(`{}`))
	deleteReq.Header.Set("Content-Type", "application/json")
	deleteReq.Header.Set("Cookie", cookie)
	deleteResp, err := http.DefaultClient.Do(deleteReq)
	if err != nil {
		t.Fatalf("delete-user failed: %v", err)
	}
	deleteResp.Body.Close()
	if sent.Token == "" {
		t.Fatal("expected delete verification token")
	}

	client := noRedirectClient()
	cbReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/auth/delete-user/callback?token="+sent.Token+"&callbackURL=/goodbye", nil)
	cbReq.Header.Set("Cookie", cookie)
	cbResp, err := client.Do(cbReq)
	if err != nil {
		t.Fatalf("delete-user callback failed: %v", err)
	}
	defer cbResp.Body.Close()
	if cbResp.StatusCode != http.StatusFound {
		t.Fatalf("callback with callbackURL expected 302, got %d", cbResp.StatusCode)
	}
	if loc := cbResp.Header.Get("Location"); loc != "/goodbye" {
		t.Fatalf("expected redirect to /goodbye, got %q", loc)
	}

	users, _ := db.Count(context.Background(), "user", []auth.Where{
		{Field: "email", Value: "delete-cb@example.com"},
	})
	if users != 0 {
		t.Fatalf("expected user deleted, got %d rows", users)
	}
}

func TestDeleteUserCallback_JSONSuccessAndInvalidToken(t *testing.T) {
	var sent auth.DeleteAccountVerificationData
	srv, _ := newMemoryAuthServer(t, auth.Options{
		Session:          auth.SessionOptions{ExpiresIn: 3600, UpdateAge: intPtr(3600)},
		EmailAndPassword: auth.EmailAndPasswordOptions{Enabled: true},
		User: auth.UserOptions{
			DeleteUser: auth.DeleteUserOptions{
				Enabled: true,
				SendDeleteAccountVerification: func(data auth.DeleteAccountVerificationData) error {
					sent = data
					return nil
				},
			},
		},
	})

	resp, cookie := signUp(t, srv.URL, "delete-cb-json@example.com")
	resp.Body.Close()

	deleteReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/auth/delete-user", strings.NewReader(`{}`))
	deleteReq.Header.Set("Content-Type", "application/json")
	deleteReq.Header.Set("Cookie", cookie)
	deleteResp, err := http.DefaultClient.Do(deleteReq)
	if err != nil {
		t.Fatalf("delete-user failed: %v", err)
	}
	deleteResp.Body.Close()

	cbResp := getWithCookie(t, srv.URL+"/api/auth/delete-user/callback?token="+sent.Token, cookie)
	defer cbResp.Body.Close()
	if cbResp.StatusCode != http.StatusOK {
		t.Fatalf("callback without callbackURL expected 200, got %d", cbResp.StatusCode)
	}
	var cbBody struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	decodeJSON(t, cbResp, &cbBody)
	if !cbBody.Success || cbBody.Message != "User deleted" {
		t.Fatalf("unexpected callback body %+v", cbBody)
	}

	reuseResp := getWithCookie(t, srv.URL+"/api/auth/delete-user/callback?token="+sent.Token, cookie)
	defer reuseResp.Body.Close()
	if reuseResp.StatusCode != http.StatusNotFound {
		t.Fatalf("reused token expected 404, got %d", reuseResp.StatusCode)
	}

	resp2, cookie2 := signUp(t, srv.URL, "delete-cb-bad@example.com")
	resp2.Body.Close()
	badResp := getWithCookie(t, srv.URL+"/api/auth/delete-user/callback?token=bogus", cookie2)
	defer badResp.Body.Close()
	if badResp.StatusCode != http.StatusNotFound {
		t.Fatalf("bogus token expected 404, got %d", badResp.StatusCode)
	}
}

func TestRequestPasswordResetCallback_RedirectsWithToken(t *testing.T) {
	db := newMemoryAdapter()
	srv := newCoreTestServer(t, db, baseTestOptions())

	resp, _ := signUp(t, srv.URL, "reset-cb@example.com")
	resp.Body.Close()
	userID := userIDByEmail(t, db, "reset-cb@example.com")

	now := time.Now().UTC()
	if _, err := db.Create(context.Background(), "verification", map[string]any{
		"id":         "ver-reset-1",
		"identifier": "reset-password:tok-123",
		"value":      userID,
		"expiresAt":  now.Add(time.Hour),
		"createdAt":  now,
		"updatedAt":  now,
	}, nil); err != nil {
		t.Fatalf("create verification: %v", err)
	}

	client := noRedirectClient()
	cbResp, err := client.Get(srv.URL + "/api/auth/reset-password/tok-123?callbackURL=" + url.QueryEscape(srv.URL+"/new-password"))
	if err != nil {
		t.Fatalf("reset callback failed: %v", err)
	}
	defer cbResp.Body.Close()
	if cbResp.StatusCode != http.StatusFound {
		t.Fatalf("valid token expected 302, got %d", cbResp.StatusCode)
	}
	location := cbResp.Header.Get("Location")
	if !strings.Contains(location, "token=tok-123") {
		t.Fatalf("expected token in redirect Location, got %q", location)
	}

	badResp, err := client.Get(srv.URL + "/api/auth/reset-password/nope?callbackURL=" + url.QueryEscape(srv.URL+"/new-password"))
	if err != nil {
		t.Fatalf("reset callback failed: %v", err)
	}
	defer badResp.Body.Close()
	if badResp.StatusCode != http.StatusFound {
		t.Fatalf("invalid token expected 302, got %d", badResp.StatusCode)
	}
	if loc := badResp.Header.Get("Location"); !strings.Contains(loc, "error=INVALID_TOKEN") {
		t.Fatalf("expected INVALID_TOKEN redirect, got %q", loc)
	}

	missingResp, err := client.Get(srv.URL + "/api/auth/reset-password/tok-123")
	if err != nil {
		t.Fatalf("reset callback failed: %v", err)
	}
	defer missingResp.Body.Close()
	if missingResp.StatusCode != http.StatusFound {
		t.Fatalf("missing callbackURL expected 302, got %d", missingResp.StatusCode)
	}
	if loc := missingResp.Header.Get("Location"); !strings.Contains(loc, "error=INVALID_TOKEN") {
		t.Fatalf("expected INVALID_TOKEN redirect, got %q", loc)
	}
}

func TestRequestPasswordResetCallback_AcceptsIssuedResetToken(t *testing.T) {
	var resetToken string
	opts := baseTestOptions()
	opts.EmailAndPassword.SendResetPassword = func(data auth.ResetPasswordData) error {
		resetToken = data.Token
		return nil
	}
	db := newMemoryAdapter()
	srv := newCoreTestServer(t, db, opts)

	signUpResp, _ := signUp(t, srv.URL, "reset-cb-compat@example.com")
	signUpResp.Body.Close()

	requestResp, err := http.Post(srv.URL+"/api/auth/request-password-reset", "application/json", strings.NewReader(`{"email":"reset-cb-compat@example.com"}`))
	if err != nil {
		t.Fatalf("request-password-reset failed: %v", err)
	}
	requestResp.Body.Close()
	if resetToken == "" {
		t.Fatal("expected reset token")
	}

	client := noRedirectClient()
	cbResp, err := client.Get(srv.URL + "/api/auth/reset-password/" + resetToken + "?callbackURL=" + url.QueryEscape(srv.URL+"/new-password"))
	if err != nil {
		t.Fatalf("reset callback failed: %v", err)
	}
	defer cbResp.Body.Close()
	if cbResp.StatusCode != http.StatusFound {
		t.Fatalf("issued token expected 302, got %d", cbResp.StatusCode)
	}
	if loc := cbResp.Header.Get("Location"); !strings.Contains(loc, "token=") {
		t.Fatalf("expected token in redirect Location, got %q", loc)
	}
}

func TestNewEndpoints_DisabledPathsReturn404(t *testing.T) {
	api := newTestAPI(t)
	mustBetterAuth(t, auth.Options{
		Secret:        "test-secret",
		Adapter:       api.Adapter(),
		DisabledPaths: []string{"/verify-password", "/revoke-sessions", "/delete-user/callback", "/reset-password/:token"},
	})

	for path, method := range map[string]string{
		"/api/auth/verify-password":       http.MethodPost,
		"/api/auth/revoke-sessions":       http.MethodPost,
		"/api/auth/delete-user/callback":  http.MethodGet,
		"/api/auth/reset-password/abc123": http.MethodGet,
	} {
		var resp *httptest.ResponseRecorder
		if method == http.MethodPost {
			resp = api.Post(path, map[string]any{"password": "x"})
		} else {
			resp = api.Get(path)
		}
		if resp.Code != http.StatusNotFound {
			t.Fatalf("disabled %s expected 404, got %d", path, resp.Code)
		}
	}
}
