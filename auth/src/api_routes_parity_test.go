package auth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/brick-org/brick/auth/src"
)

// newParityHTTPServer mounts auth with BaseURL defaulting to the test server
// URL so absolute redirect URLs stay trusted.
func newParityHTTPServer(t *testing.T, opts auth.Options) (*httptest.Server, auth.DBAdapter) {
	t.Helper()
	adapter, srv := newTestAdapter(t)
	db := newMemoryAdapter()
	opts.Secret = "test-secret"
	opts.Adapter = adapter
	opts.DB = db
	if opts.BaseURL == "" {
		opts.BaseURL = srv.URL
	}
	mustBetterAuth(t, opts)
	return srv, db
}

func TestParity_VerifyEmailGetRedirectsOnSuccessAndError(t *testing.T) {
	var verificationToken string
	srv, _ := newParityHTTPServer(t, auth.Options{
		Session: auth.SessionOptions{ExpiresIn: 3600, UpdateAge: 3600},
		EmailAndPassword: auth.EmailAndPasswordOptions{
			Enabled: true,
		},
		EmailVerification: auth.EmailVerificationOptions{
			SendVerificationEmail: func(data auth.VerificationEmailData) error {
				verificationToken = data.Token
				return nil
			},
		},
	})

	resp, _ := signUp(t, srv.URL, "parity-verify@example.com")
	resp.Body.Close()

	sendResp, err := http.Post(srv.URL+"/api/auth/send-verification-email", "application/json",
		strings.NewReader(`{"email":"parity-verify@example.com","callbackURL":"/"}`))
	if err != nil {
		t.Fatalf("send-verification-email failed: %v", err)
	}
	sendResp.Body.Close()
	if verificationToken == "" {
		t.Fatal("expected verification token to be issued")
	}

	client := noRedirectClient()
	callback := srv.URL + "/welcome"
	success, err := client.Get(srv.URL + "/api/auth/verify-email?token=" + url.QueryEscape(verificationToken) + "&callbackURL=" + url.QueryEscape(callback))
	if err != nil {
		t.Fatalf("verify-email GET failed: %v", err)
	}
	success.Body.Close()
	if success.StatusCode != http.StatusFound {
		t.Fatalf("valid token with callbackURL expected 302, got %d", success.StatusCode)
	}
	if loc := success.Header.Get("Location"); loc != callback {
		t.Fatalf("expected redirect to callbackURL, got %q", loc)
	}

	failure, err := client.Get(srv.URL + "/api/auth/verify-email?token=bogus&callbackURL=" + url.QueryEscape(callback))
	if err != nil {
		t.Fatalf("verify-email GET failed: %v", err)
	}
	failure.Body.Close()
	if failure.StatusCode != http.StatusFound {
		t.Fatalf("invalid token with callbackURL expected 302, got %d", failure.StatusCode)
	}
	if loc := failure.Header.Get("Location"); !strings.Contains(loc, "error=INVALID_TOKEN") {
		t.Fatalf("expected INVALID_TOKEN redirect, got %q", loc)
	}
}

func TestParity_VerifyEmailGetReturnsUserWithoutCallback(t *testing.T) {
	var verificationToken string
	srv, _ := newParityHTTPServer(t, auth.Options{
		Session: auth.SessionOptions{ExpiresIn: 3600, UpdateAge: 3600},
		EmailAndPassword: auth.EmailAndPasswordOptions{
			Enabled: true,
		},
		EmailVerification: auth.EmailVerificationOptions{
			SendVerificationEmail: func(data auth.VerificationEmailData) error {
				verificationToken = data.Token
				return nil
			},
		},
	})

	resp, _ := signUp(t, srv.URL, "parity-verify-json@example.com")
	resp.Body.Close()

	sendResp, err := http.Post(srv.URL+"/api/auth/send-verification-email", "application/json",
		strings.NewReader(`{"email":"parity-verify-json@example.com"}`))
	if err != nil {
		t.Fatalf("send-verification-email failed: %v", err)
	}
	sendResp.Body.Close()

	getResp, err := http.Get(srv.URL + "/api/auth/verify-email?token=" + url.QueryEscape(verificationToken))
	if err != nil {
		t.Fatalf("verify-email GET failed: %v", err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", getResp.StatusCode)
	}
	var body struct {
		Status bool       `json:"status"`
		User   *auth.User `json:"user"`
	}
	if err := json.NewDecoder(getResp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !body.Status || body.User == nil || body.User.Email != "parity-verify-json@example.com" || !body.User.EmailVerified {
		t.Fatalf("expected verified user object, got %#v", body)
	}
}

func TestParity_VerifyEmailPostAliasStillWorks(t *testing.T) {
	var verificationToken string
	srv, _ := newParityHTTPServer(t, auth.Options{
		Session: auth.SessionOptions{ExpiresIn: 3600, UpdateAge: 3600},
		EmailAndPassword: auth.EmailAndPasswordOptions{
			Enabled: true,
		},
		EmailVerification: auth.EmailVerificationOptions{
			SendVerificationEmail: func(data auth.VerificationEmailData) error {
				verificationToken = data.Token
				return nil
			},
		},
	})

	resp, _ := signUp(t, srv.URL, "parity-verify-post@example.com")
	resp.Body.Close()

	sendResp, err := http.Post(srv.URL+"/api/auth/send-verification-email", "application/json",
		strings.NewReader(`{"email":"parity-verify-post@example.com"}`))
	if err != nil {
		t.Fatalf("send-verification-email failed: %v", err)
	}
	sendResp.Body.Close()

	postResp, err := http.Post(srv.URL+"/api/auth/verify-email", "application/json",
		strings.NewReader(`{"token":"`+verificationToken+`"}`))
	if err != nil {
		t.Fatalf("verify-email POST failed: %v", err)
	}
	defer postResp.Body.Close()
	if postResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", postResp.StatusCode)
	}
	var body struct {
		Status bool       `json:"status"`
		User   *auth.User `json:"user"`
	}
	if err := json.NewDecoder(postResp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !body.Status || body.User == nil || !body.User.EmailVerified {
		t.Fatalf("expected verified user object, got %#v", body)
	}
}

func TestParity_SendVerificationEmailUnauthenticatedFloor(t *testing.T) {
	srv, _ := newParityHTTPServer(t, auth.Options{
		Session: auth.SessionOptions{ExpiresIn: 3600, UpdateAge: 3600},
		EmailAndPassword: auth.EmailAndPasswordOptions{
			Enabled: true,
		},
		EmailVerification: auth.EmailVerificationOptions{
			SendVerificationEmail: func(data auth.VerificationEmailData) error { return nil },
		},
	})

	start := time.Now()
	sendResp, err := http.Post(srv.URL+"/api/auth/send-verification-email", "application/json",
		strings.NewReader(`{"email":"unknown-parity@example.com"}`))
	if err != nil {
		t.Fatalf("send-verification-email failed: %v", err)
	}
	sendResp.Body.Close()
	if elapsed := time.Since(start); elapsed < 500*time.Millisecond {
		t.Fatalf("unauthenticated send must take >=500ms, took %v", elapsed)
	}
	if sendResp.StatusCode != http.StatusOK {
		t.Fatalf("unknown email must still return success, got %d", sendResp.StatusCode)
	}
}

func TestParity_PasswordResetSingleUseDBToken(t *testing.T) {
	var resetToken, resetURL string
	srv, _ := newParityHTTPServer(t, auth.Options{
		Session: auth.SessionOptions{ExpiresIn: 3600, UpdateAge: 3600},
		EmailAndPassword: auth.EmailAndPasswordOptions{
			Enabled: true,
			SendResetPassword: func(data auth.ResetPasswordData) error {
				resetToken = data.Token
				resetURL = data.URL
				return nil
			},
		},
	})

	resp, _ := signUp(t, srv.URL, "parity-reset@example.com")
	resp.Body.Close()

	requestResp, err := http.Post(srv.URL+"/api/auth/request-password-reset", "application/json",
		strings.NewReader(`{"email":"parity-reset@example.com"}`))
	if err != nil {
		t.Fatalf("request-password-reset failed: %v", err)
	}
	requestResp.Body.Close()
	if resetToken == "" {
		t.Fatal("expected reset token")
	}
	if !strings.Contains(resetURL, "/reset-password/"+resetToken) {
		t.Fatalf("emailed URL must carry the single-use token path, got %q", resetURL)
	}

	first, err := http.Post(srv.URL+"/api/auth/reset-password", "application/json",
		strings.NewReader(`{"token":"`+resetToken+`","newPassword":"new-password123"}`))
	if err != nil {
		t.Fatalf("reset-password failed: %v", err)
	}
	first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first consume expected 200, got %d", first.StatusCode)
	}

	second, err := http.Post(srv.URL+"/api/auth/reset-password", "application/json",
		strings.NewReader(`{"token":"`+resetToken+`","newPassword":"another-password123"}`))
	if err != nil {
		t.Fatalf("reset-password failed: %v", err)
	}
	second.Body.Close()
	if second.StatusCode != http.StatusBadRequest {
		t.Fatalf("replay must be rejected, got %d", second.StatusCode)
	}
}

func TestParity_PasswordResetAcceptsQueryToken(t *testing.T) {
	var resetToken string
	srv, _ := newParityHTTPServer(t, auth.Options{
		Session: auth.SessionOptions{ExpiresIn: 3600, UpdateAge: 3600},
		EmailAndPassword: auth.EmailAndPasswordOptions{
			Enabled: true,
			SendResetPassword: func(data auth.ResetPasswordData) error {
				resetToken = data.Token
				return nil
			},
		},
	})

	resp, _ := signUp(t, srv.URL, "parity-reset-query@example.com")
	resp.Body.Close()

	requestResp, err := http.Post(srv.URL+"/api/auth/request-password-reset", "application/json",
		strings.NewReader(`{"email":"parity-reset-query@example.com"}`))
	if err != nil {
		t.Fatalf("request-password-reset failed: %v", err)
	}
	requestResp.Body.Close()

	resetResp, err := http.Post(srv.URL+"/api/auth/reset-password?token="+url.QueryEscape(resetToken), "application/json",
		strings.NewReader(`{"newPassword":"new-password123"}`))
	if err != nil {
		t.Fatalf("reset-password failed: %v", err)
	}
	resetResp.Body.Close()
	if resetResp.StatusCode != http.StatusOK {
		t.Fatalf("query token expected 200, got %d", resetResp.StatusCode)
	}
}

func TestParity_PasswordResetRedirectToFlow(t *testing.T) {
	var resetURL string
	srv, _ := newParityHTTPServer(t, auth.Options{
		Session: auth.SessionOptions{ExpiresIn: 3600, UpdateAge: 3600},
		EmailAndPassword: auth.EmailAndPasswordOptions{
			Enabled: true,
			SendResetPassword: func(data auth.ResetPasswordData) error {
				resetURL = data.URL
				return nil
			},
		},
	})

	resp, _ := signUp(t, srv.URL, "parity-reset-redirect@example.com")
	resp.Body.Close()

	// Untrusted redirectTo is rejected.
	badResp, err := http.Post(srv.URL+"/api/auth/request-password-reset", "application/json",
		strings.NewReader(`{"email":"parity-reset-redirect@example.com","redirectTo":"https://evil.example/reset"}`))
	if err != nil {
		t.Fatalf("request-password-reset failed: %v", err)
	}
	badResp.Body.Close()
	if badResp.StatusCode != http.StatusForbidden {
		t.Fatalf("untrusted redirectTo expected 403, got %d", badResp.StatusCode)
	}

	// Trusted redirectTo lands in the emailed callback URL.
	okResp, err := http.Post(srv.URL+"/api/auth/request-password-reset", "application/json",
		strings.NewReader(`{"email":"parity-reset-redirect@example.com","redirectTo":"`+srv.URL+`/new-password"}`))
	if err != nil {
		t.Fatalf("request-password-reset failed: %v", err)
	}
	okResp.Body.Close()
	if !strings.Contains(resetURL, "/reset-password/") || !strings.Contains(resetURL, "callbackURL=") {
		t.Fatalf("emailed URL must carry token path and callbackURL, got %q", resetURL)
	}
}

func TestParity_DisabledPathsNormalization(t *testing.T) {
	adapter, srv := newTestAdapter(t)
	mustBetterAuth(t, auth.Options{
		Secret:        "test-secret",
		Adapter:       adapter,
		DB:            newMemoryAdapter(),
		DisabledPaths: []string{"verify-email/", "/reset-password/{token}"},
	})

	for _, target := range []string{"/api/auth/verify-email", "/api/auth/reset-password/abc123"} {
		resp, err := http.Get(srv.URL + target)
		if err != nil {
			t.Fatalf("get %s failed: %v", target, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("disabled %s expected 404, got %d", target, resp.StatusCode)
		}
	}
	postResp, err := http.Post(srv.URL+"/api/auth/verify-email", "application/json", strings.NewReader(`{"token":"x"}`))
	if err != nil {
		t.Fatalf("post verify-email failed: %v", err)
	}
	postResp.Body.Close()
	if postResp.StatusCode != http.StatusNotFound {
		t.Fatalf("disabled POST verify-email expected 404, got %d", postResp.StatusCode)
	}
}
