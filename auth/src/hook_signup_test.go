package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/brick-org/brick/auth/src"
	authbun "github.com/brick-org/brick/auth/src/adapters/bun"
	"github.com/brick-org/brick/auth/src/types"
)

// TestSignupHook_PostCommitFailureSurfacesHookCode mirrors
// organization-hook.test.ts "keeps the committed user and surfaces a
// post-commit hook failure as the sign-up response": the user.create.after
// hook runs after the sign-up transaction commits, so a hook failure keeps
// the committed user and its error code becomes the sign-up response.
func TestSignupHook_PostCommitFailureSurfacesHookCode(t *testing.T) {
	db := openDB(t)
	migrate(t, db)

	var hookCalls int
	adapter, srv := newTestAdapter(t)
	mustBetterAuth(t, auth.Options{
		Secret:  "test-secret",
		Adapter: adapter,
		DB:      authbun.New(db, authbun.Config{}),
		Session: auth.SessionOptions{ExpiresIn: 3600, UpdateAge: intPtr(1)},
		EmailAndPassword: auth.EmailAndPasswordOptions{
			Enabled: true,
		},
		DatabaseHooks: auth.DBHooks{
			"user": auth.ModelHooks{
				Create: auth.OperationHooks{
					After: func(_ context.Context, data map[string]any) error {
						email, _ := data["email"].(string)
						if !strings.Contains(email, "-hook@") {
							return nil
						}
						hookCalls++
						if hookCalls > 1 {
							return types.HttpError{Code: "ORGANIZATION_ALREADY_EXISTS", Message: "organization already exists", Status: 409}
						}
						return nil
					},
				},
			},
		},
	})

	post := func(email string) (int, string) {
		t.Helper()
		resp, err := http.Post(srv.URL+"/api/auth/sign-up/email", "application/json",
			strings.NewReader(`{"name":"Hook User","email":"`+email+`","password":"password123"}`))
		if err != nil {
			t.Fatalf("sign-up request failed: %v", err)
		}
		defer resp.Body.Close()
		var body struct {
			Detail string `json:"detail"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		return resp.StatusCode, body.Detail
	}

	if code, _ := post("user1-hook@example.com"); code != http.StatusOK {
		t.Fatalf("first sign-up expected 200, got %d", code)
	}
	code, detail := post("user2-hook@example.com")
	if code == http.StatusOK {
		t.Fatal("second sign-up must fail on the post-commit hook error")
	}
	if !strings.Contains(detail, "ORGANIZATION_ALREADY_EXISTS") {
		t.Fatalf("hook error code must surface, got status=%d detail=%q", code, detail)
	}

	// The second user's row committed before its hook ran.
	row, err := authbun.New(db, authbun.Config{}).FindOne(context.Background(), "user", []auth.Where{
		{Field: "email", Value: "user2-hook@example.com"},
	}, nil)
	if err != nil {
		t.Fatalf("find user: %v", err)
	}
	if row == nil {
		t.Fatal("second user row must exist despite the hook failure")
	}
}
