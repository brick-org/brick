package routes

// B5: HTTP-level concurrent same-token reset pin.
// Upstream: password.test.ts:217-266 @5468e6bf — Promise.all, exactly 1x200
// + rest 400, winner signs in.
// Fires N=8 concurrent POST /reset-password with the same single-use token
// over real HTTP (httptest.Server over the huma adapter, like upstream

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

func b5RaceAPI(t *testing.T, opts types.Options) humatest.TestAPI {
	t.Helper()
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	SignUpEmail(api, "/api/auth", opts)
	SignInEmail(api, "/api/auth", opts)
	RequestPasswordReset(api, "/api/auth", opts)
	ResetPassword(api, "/api/auth", opts)
	return api
}

func b5PostJSON(url, body string) (int, string, error) {
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw), nil
}

// TestResetPasswordRace_ConcurrentSameTokenResetPin fires 8 concurrent POST
func TestResetPasswordRace_ConcurrentSameTokenResetPin(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	var token string
	opts.EmailAndPassword.SendResetPassword = func(data types.ResetPasswordData) error {
		token = data.Token
		return nil
	}
	api := b5RaceAPI(t, opts)
	srv := httptest.NewServer(api.Adapter())
	t.Cleanup(srv.Close)

	const email = "b5-race@test.com"

	if code, body, err := b5PostJSON(srv.URL+"/api/auth/sign-up/email",
		`{"name":"B5","email":"`+email+`","password":"password123"}`); err != nil || code != 200 {
		t.Fatalf("sign-up = %d, err=%v: %s", code, err, body)
	}
	if code, body, err := b5PostJSON(srv.URL+"/api/auth/request-password-reset",
		`{"email":"`+email+`"}`); err != nil || code != 200 {
		t.Fatalf("request reset = %d, err=%v: %s", code, err, body)
	}
	if token == "" {
		t.Fatal("expected a reset token")
	}

	const racers = 8
	passwords := make([]string, racers)
	for i := range passwords {
		passwords[i] = fmt.Sprintf("B5-winner-pass-%d-xyz123", i)
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	codes := make([]int, racers)
	bodies := make([]string, racers)
	errs := make([]error, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			code, body, err := b5PostJSON(srv.URL+"/api/auth/reset-password",
				`{"token":"`+token+`","newPassword":"`+passwords[i]+`"}`)
			codes[i] = code
			bodies[i] = body
			errs[i] = err
		}(i)
	}
	close(start)
	wg.Wait()

	for i := 0; i < racers; i++ {
		if errs[i] != nil {
			t.Fatalf("racer %d request failed: %v", i, errs[i])
		}
	}

	okCount, badCount := 0, 0
	winner := -1
	for i, code := range codes {
		switch code {
		case 200:
			okCount++
			if winner == -1 {
				winner = i
			}
			if !strings.Contains(bodies[i], `"status":true`) {
				t.Errorf("racer %d 200 body must carry status:true, got %s", i, bodies[i])
			}
		case 400:
			badCount++
			if !strings.Contains(bodies[i], types.ErrInvalidToken) {
				t.Errorf("racer %d 400 body must carry INVALID_TOKEN, got %s", i, bodies[i])
			}
		default:
			t.Errorf("racer %d status = %d, want 200 or 400: %s", i, code, bodies[i])
		}
	}
	t.Logf("B5 race distribution: 200x%d 400x%d codes=%v", okCount, badCount, codes)
	if okCount != 1 || badCount != racers-1 {
		t.Fatalf("concurrent same-token reset: got %dx200 + %dx400 (codes %v), want exactly 1x200 + %dx400",
			okCount, badCount, codes, racers-1)
	}

	if winner == -1 {
		t.Fatal("no winner recorded despite 1x200")
	}
	if code, body, err := b5PostJSON(srv.URL+"/api/auth/sign-in/email",
		`{"email":"`+email+`","password":"`+passwords[winner]+`"}`); err != nil || code != 200 {
		t.Fatalf("sign-in with winner password (racer %d) = %d, err=%v: %s (codes %v)",
			winner, code, err, body, codes)
	}
}
