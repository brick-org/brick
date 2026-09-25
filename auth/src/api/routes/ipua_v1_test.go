package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

// Pinned upstream: Better Auth v1.7.5 session ipAddress/userAgent issuance
// (db/internal-adapter.ts:500-502, createSession):
//	ipAddress: headers ? getIP(headers, options) || "" : ""
//	userAgent: headers?.get("user-agent") || ""
// createIssuedSession (generate-id.go) is the Go issuance seam and must

// ipuaTestAPI registers the credential issuance + read routes behind the
func ipuaTestAPI(t *testing.T, opts types.Options) humatest.TestAPI {
	t.Helper()
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	api.UseMiddleware(func(ctx huma.Context, next func(huma.Context)) {
		next(WithStoredRequest(ctx, RequestFromHuma(ctx)))
	})
	SignUpEmail(api, "/api/auth", opts)
	SignInEmail(api, "/api/auth", opts)
	GetSession(api, "/api/auth", opts)
	return api
}

func ipuaSessionToken(t *testing.T, respBody []byte) string {
	t.Helper()
	var body struct {
		Token *string `json:"token"`
	}
	if err := json.Unmarshal(respBody, &body); err != nil {
		t.Fatalf("decode token: %v", err)
	}
	if body.Token == nil || *body.Token == "" {
		t.Fatal("expected a session token")
	}
	return *body.Token
}

func ipuaGetSession(t *testing.T, api humatest.TestAPI, authHeader string) (ip, ua string) {
	t.Helper()
	resp := api.Get("/api/auth/get-session", authHeader)
	if resp.Code != http.StatusOK {
		t.Fatalf("get-session = %d: %s", resp.Code, resp.Body.String())
	}
	var got struct {
		Session struct {
			IPAddress string `json:"ipAddress"`
			UserAgent string `json:"userAgent"`
		} `json:"session"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode get-session: %v", err)
	}
	return got.Session.IPAddress, got.Session.UserAgent
}

func ipuaStoredSession(t *testing.T, db *parityMemAdapter, token string) map[string]any {
	t.Helper()
	row, err := db.FindOne(context.Background(), "session", []types.Where{{Field: "token", Value: token}}, nil)
	if err != nil || row == nil {
		t.Fatalf("session row lookup: %v (row=%v)", err, row != nil)
	}
	return row
}

// sign-up.test.ts "should get the ipAddress and userAgent from headers":
func TestIPUA_SignUpStoresIPAndUserAgent(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	api := ipuaTestAPI(t, opts)

	resp := api.Post("/api/auth/sign-up/email",
		"x-forwarded-for: 127.0.0.1",
		"user-agent: test-user-agent",
		map[string]any{
			"name": "Test Name", "email": "email2@test.com", "password": "password123",
		})
	if resp.Code != http.StatusOK {
		t.Fatalf("sign-up = %d: %s", resp.Code, resp.Body.String())
	}
	token := ipuaSessionToken(t, resp.Body.Bytes())

	if ip, ua := ipuaGetSession(t, api, "Authorization: Bearer "+token); ip != "127.0.0.1" || ua != "test-user-agent" {
		t.Fatalf("get-session ip/ua = %q/%q, want 127.0.0.1/test-user-agent", ip, ua)
	}
	row := ipuaStoredSession(t, db, token)
	if got, _ := row["ipAddress"].(string); got != "127.0.0.1" {
		t.Fatalf("stored ipAddress = %#v, want 127.0.0.1", row["ipAddress"])
	}
	if got, _ := row["userAgent"].(string); got != "test-user-agent" {
		t.Fatalf("stored userAgent = %#v, want test-user-agent", row["userAgent"])
	}
}

// sign-in.test.ts "should read the ip address and user agent from the
func TestIPUA_SignInStoresIPAndUserAgent(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	api := ipuaTestAPI(t, opts)

	seed := api.Post("/api/auth/sign-up/email", map[string]any{
		"name": "Seed", "email": "signin-ipua@test.com", "password": "password123",
	})
	if seed.Code != http.StatusOK {
		t.Fatalf("seed sign-up = %d: %s", seed.Code, seed.Body.String())
	}

	resp := api.Post("/api/auth/sign-in/email",
		"X-Forwarded-For: 127.0.0.1",
		"User-Agent: Test",
		map[string]any{
			"email": "signin-ipua@test.com", "password": "password123",
		})
	if resp.Code != http.StatusOK {
		t.Fatalf("sign-in = %d: %s", resp.Code, resp.Body.String())
	}
	token := ipuaSessionToken(t, resp.Body.Bytes())

	if ip, ua := ipuaGetSession(t, api, "Authorization: Bearer "+token); ip != "127.0.0.1" || ua != "Test" {
		t.Fatalf("get-session ip/ua = %q/%q, want 127.0.0.1/Test", ip, ua)
	}
	row := ipuaStoredSession(t, db, token)
	if got, _ := row["ipAddress"].(string); got != "127.0.0.1" {
		t.Fatalf("stored ipAddress = %#v, want 127.0.0.1", row["ipAddress"])
	}
	if got, _ := row["userAgent"].(string); got != "Test" {
		t.Fatalf("stored userAgent = %#v, want Test", row["userAgent"])
	}
}

// The ""-default leg: with no request on ctx (programmatic issuance),
func TestIPUA_NoRequestStoresEmptyStrings(t *testing.T) {
	db := newParityMemAdapter()
	opts := emailAuthTestOptions(db)
	now := time.Now().UTC()

	sess, err := createIssuedSession(context.Background(), opts, "user-ipua", "tok-ipua", now.Add(time.Hour), now)
	if err != nil {
		t.Fatalf("createIssuedSession: %v", err)
	}
	row := ipuaStoredSession(t, db, "tok-ipua")
	if got, ok := row["ipAddress"].(string); !ok || got != "" {
		t.Fatalf("stored ipAddress = %#v, want empty string", row["ipAddress"])
	}
	if got, ok := row["userAgent"].(string); !ok || got != "" {
		t.Fatalf("stored userAgent = %#v, want empty string", row["userAgent"])
	}
	if sess.IPAddress == nil || *sess.IPAddress != "" {
		t.Fatalf("returned IPAddress = %#v, want pointer to empty string", sess.IPAddress)
	}
	if sess.UserAgent == nil || *sess.UserAgent != "" {
		t.Fatalf("returned UserAgent = %#v, want pointer to empty string", sess.UserAgent)
	}
}

// Direct IP resolution order: X-Forwarded-For leftmost non-empty hop, then
func TestIPUA_ClientIPResolution(t *testing.T) {
	cases := []struct {
		name      string
		xff       string
		xRealIP   string
		remote    string
		userAgent string
		wantIP    string
		wantUA    string
	}{
		{"xff single", "127.0.0.1", "", "", "Test", "127.0.0.1", "Test"},
		{"xff leftmost hop wins", "203.0.113.7, 70.41.3.18, 150.172.238.4", "", "", "", "203.0.113.7", ""},
		{"xff skips empty hops", " , 203.0.113.7 ,", "", "", "", "203.0.113.7", ""},
		{"x-real-ip fallback", "", "10.1.2.3", "", "", "10.1.2.3", ""},
		{"remote strips port", "", "", "192.0.2.9:5432", "", "192.0.2.9", ""},
		{"remote bare ipv6", "", "", "::1", "", "::1", ""},
		{"remote bracketed ipv6 with port", "", "", "[2001:db8::1]:443", "", "2001:db8::1", ""},
		{"empty", "", "", "", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, "http://example.com/api/auth/sign-up/email", nil)
			req.RemoteAddr = tc.remote
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}
			if tc.xRealIP != "" {
				req.Header.Set("X-Real-IP", tc.xRealIP)
			}
			if tc.userAgent != "" {
				req.Header.Set("User-Agent", tc.userAgent)
			}
			ctx := context.WithValue(context.Background(), storedRequestKey{}, req)
			ip, ua := sessionRequestMeta(ctx)
			if ip != tc.wantIP || ua != tc.wantUA {
				t.Fatalf("ip/ua = %q/%q, want %q/%q", ip, ua, tc.wantIP, tc.wantUA)
			}
		})
	}
}
