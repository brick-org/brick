package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	auth "github.com/brick-org/brick/auth/src"
	jwtplugin "github.com/brick-org/brick/auth/src/plugins/jwt"
)

func TestJWTPluginMountedRoutesUseStaticBaseURLAndCustomBasePath(t *testing.T) {
	adapter, server := newTestAdapter(t)
	plugin := jwtplugin.New(jwtplugin.Options{})
	opts := auth.Options{
		Secret:           "test-secret",
		BaseURL:          "https://auth.example.test",
		BasePath:         "/v1/auth",
		Adapter:          adapter,
		DB:               newMemoryAdapter(),
		EmailAndPassword: auth.EmailAndPasswordOptions{Enabled: true},
	}
	opts.Plugins = append(opts.Plugins, plugin)
	mustBetterAuth(t, opts)

	unauthenticated, err := http.Get(server.URL + "/v1/auth/token")
	if err != nil {
		t.Fatalf("GET /token without a session: %v", err)
	}
	unauthenticated.Body.Close()
	if unauthenticated.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET /token without a session status = %d, want 401", unauthenticated.StatusCode)
	}
	wrongSession, err := http.NewRequest(http.MethodGet, server.URL+"/v1/auth/token", nil)
	if err != nil {
		t.Fatal(err)
	}
	wrongSession.Header.Set("Authorization", "Bearer not-a-session")
	wrongSessionResponse, err := http.DefaultClient.Do(wrongSession)
	if err != nil {
		t.Fatalf("GET /token with an invalid bearer: %v", err)
	}
	wrongSessionResponse.Body.Close()
	if wrongSessionResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET /token with an invalid bearer status = %d, want 401", wrongSessionResponse.StatusCode)
	}

	signUp, err := http.Post(server.URL+"/v1/auth/sign-up/email", "application/json", strings.NewReader(
		`{"name":"JWT Test","email":"jwt-plugin@example.test","password":"password123"}`,
	))
	if err != nil {
		t.Fatalf("sign-up request: %v", err)
	}
	defer signUp.Body.Close()
	if signUp.StatusCode != http.StatusOK {
		t.Fatalf("sign-up status = %d, want 200", signUp.StatusCode)
	}
	cookie := cookieHeaderFromSetCookies(signUp.Header.Values("Set-Cookie"))
	if cookie == "" {
		t.Fatal("sign-up response did not set a session cookie")
	}

	requestWithCookie := func(path string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
		if err != nil {
			t.Fatalf("new request for %s: %v", path, err)
		}
		req.Header.Set("Cookie", cookie)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		return resp
	}

	tokenResponse := requestWithCookie("/v1/auth/token")
	var tokenBody struct {
		Token string `json:"token"`
	}
	if tokenResponse.StatusCode != http.StatusOK {
		body := make([]byte, 4096)
		n, _ := tokenResponse.Body.Read(body)
		tokenResponse.Body.Close()
		t.Fatalf("GET /token status = %d, want 200; body=%s", tokenResponse.StatusCode, body[:n])
	}
	if err := json.NewDecoder(tokenResponse.Body).Decode(&tokenBody); err != nil {
		tokenResponse.Body.Close()
		t.Fatalf("decode GET /token response: %v", err)
	}
	tokenResponse.Body.Close()
	if tokenBody.Token == "" {
		t.Fatal("GET /token returned an empty JWT")
	}
	claims, err := plugin.VerifyJWT(context.Background(), tokenBody.Token, jwtplugin.VerifyOptions{})
	if err != nil {
		t.Fatalf("verify /token JWT with configured defaults: %v", err)
	}
	if claims.Issuer != "https://auth.example.test" || len(claims.Audience) != 1 || claims.Audience[0] != "https://auth.example.test" {
		t.Fatalf("/token issuer/audience = %q/%v, want configured BaseURL origin", claims.Issuer, claims.Audience)
	}

	getSession := requestWithCookie("/v1/auth/get-session")
	defer getSession.Body.Close()
	if getSession.StatusCode != http.StatusOK {
		t.Fatalf("GET /get-session status = %d, want 200", getSession.StatusCode)
	}
	headerToken := getSession.Header.Get("set-auth-jwt")
	if headerToken == "" {
		t.Fatal("GET /get-session did not set the session JWT response header")
	}
	if _, err := plugin.VerifyJWT(context.Background(), headerToken, jwtplugin.VerifyOptions{}); err != nil {
		t.Fatalf("verify /get-session JWT header with configured defaults: %v", err)
	}
	if exposed := getSession.Header.Get("Access-Control-Expose-Headers"); !strings.Contains(strings.ToLower(exposed), "set-auth-jwt") {
		t.Fatalf("Access-Control-Expose-Headers = %q, want set-auth-jwt", exposed)
	}

	jwksResponse, err := http.Get(server.URL + "/v1/auth/jwks")
	if err != nil {
		t.Fatalf("GET /jwks: %v", err)
	}
	defer jwksResponse.Body.Close()
	if jwksResponse.StatusCode != http.StatusOK {
		t.Fatalf("GET /jwks status = %d, want 200", jwksResponse.StatusCode)
	}
	var jwks struct {
		Keys []map[string]json.RawMessage `json:"keys"`
	}
	if err := json.NewDecoder(jwksResponse.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode GET /jwks response: %v", err)
	}
	if len(jwks.Keys) == 0 {
		t.Fatal("GET /jwks returned no public keys")
	}
	for _, privateField := range []string{"privateKey", "d", "p", "q"} {
		if _, exists := jwks.Keys[0][privateField]; exists {
			t.Errorf("GET /jwks leaked private field %q", privateField)
		}
	}
}
