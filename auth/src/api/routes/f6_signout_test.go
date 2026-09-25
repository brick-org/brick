package routes

import (
	"reflect"
	"strings"
	"testing"

	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

// F6 sign-out core parity (upstream sign-out.ts:5-26,42,78-100 @ 5468e6bf):
// optional body {callbackURL,disableRedirect,state} parsed (provider OIDC
// flow stays EXCLUDED as social), requireHeaders enforced (headerless 401),
// response always {success:true} with core+chunked cookie clear. Provider
// url/redirect/Location contract explicitly NOT implemented (excluded).

func f6SignOutAPI(t *testing.T, opts types.Options) humatest.TestAPI {
	t.Helper()
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	SignUpEmail(api, "/api/auth", opts)
	SignInEmail(api, "/api/auth", opts)
	SignOut(api, "/api/auth", opts)
	GetSession(api, "/api/auth", opts)
	return api
}

// Body must be parsed: input carries optional callbackURL/disableRedirect/state.
func TestF6_SignOutParsesOptionalBody(t *testing.T) {
	typ := reflect.TypeOf(signOutInput{})
	bodyField, ok := typ.FieldByName("Body")
	if !ok {
		t.Fatal("signOutInput must carry optional Body {callbackURL,disableRedirect,state}")
	}
	bt := bodyField.Type
	if bt.Kind() == reflect.Pointer {
		bt = bt.Elem()
	}
	if bt.Kind() != reflect.Struct {
		t.Fatalf("signOutInput.Body must be struct/pointer-to-struct, got %v", bodyField.Type)
	}
	for _, want := range []string{"callbackURL", "disableRedirect", "state"} {
		found := false
		for i := 0; i < bt.NumField(); i++ {
			tag := bt.Field(i).Tag.Get("json")
			name := strings.SplitN(tag, ",", 2)[0]
			if name == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("signOutInput.Body must contain json tag %q, got type %v", want, bt)
		}
	}

	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	api := f6SignOutAPI(t, opts)
	resp := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "F6", "email": "f6body@test.com", "password": "password123",
	})
	if resp.Code != 200 {
		t.Fatalf("seed sign-up = %d: %s", resp.Code, resp.Body.String())
	}
	cookie := sessionCookieOf(t, resp)
	resp = api.Post("/api/auth/sign-out", map[string]any{
		"callbackURL": "/login", "disableRedirect": true, "state": "logout-state",
	}, "Cookie: "+cookie)
	if resp.Code != 200 {
		t.Fatalf("sign-out with body = %d: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), `"success":true`) {
		t.Fatalf("sign-out with body must keep success:true, got %s", resp.Body.String())
	}
}

// requireHeaders (upstream sign-out.ts:42): headerless calls 401, not success:true.
func TestF6_SignOutHeaderless401(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	api := f6SignOutAPI(t, opts)
	resp := api.Post("/api/auth/sign-out")
	if resp.Code != 401 {
		t.Fatalf("headerless sign-out = %d, want 401: %s", resp.Code, resp.Body.String())
	}
	if strings.Contains(resp.Body.String(), `"success":true`) {
		t.Fatalf("headerless sign-out must not return success:true, got %s", resp.Body.String())
	}
	// Headerless with body must also 401 (headers gate runs regardless of body).
	resp = api.Post("/api/auth/sign-out", map[string]any{
		"callbackURL": "/login", "disableRedirect": true, "state": "s",
	})
	if resp.Code != 401 {
		t.Fatalf("headerless sign-out with body = %d, want 401: %s", resp.Code, resp.Body.String())
	}
}

// Success is always 200 with cookie clear when headers are present.
func TestF6_SignOutSuccessAlways200(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	api := f6SignOutAPI(t, opts)
	resp := api.Post("/api/auth/sign-out", map[string]any{}, "Cookie: better-auth.session_token=garbage-token; auth_session_data=garbage")
	if resp.Code != 200 {
		t.Fatalf("garbage-cookie sign-out = %d, want 200: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), `"success":true`) {
		t.Fatalf("garbage-cookie sign-out must keep success:true, got %s", resp.Body.String())
	}
	if len(resp.Header().Values("Set-Cookie")) == 0 {
		t.Fatal("garbage-cookie sign-out must clear cookies via Set-Cookie")
	}
}
