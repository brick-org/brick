package routes

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/cookies"
	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

// C7-01 port: upstream cookie-name/chunk recovery, TS fixture interop,
// dynamic secure/domain via request context, AdditionalCookies propagation,
// custom JWKS signer path, and stateless guards.
// Upstream refs (pinned 5468e6bf):
//   - cookies/index.ts (setCookieCache/decodeCookieCache, getCookies,

func c701TestOptions(db *parityMemAdapter) types.Options {
	opts := sessionTestOptions(db)
	opts.Session.CookieCache.Enabled = true
	return opts
}

func c701MintJWT(t *testing.T, secret string, session, user map[string]any, version string) string {
	t.Helper()
	token, err := cookies.CreateSessionCacheJWT(secret, session, user, version, 5*time.Minute)
	if err != nil {
		t.Fatalf("mint jwt: %v", err)
	}
	return token
}

// Upstream session_data name must be accepted (cookie-name recovery).
func TestSessionCookieCache_SessionDataUpstreamNameRecovery(t *testing.T) {
	db := newParityMemAdapter()
	opts := c701TestOptions(db)
	opts.Session.CookieCache.Strategy = types.SessionCookieCacheJWT
	seedSessionUser(t, db, "upstream-name@example.com", "tok-upstream", time.Now().UTC().Add(time.Hour))
	ctx := context.Background()
	row, urow, _, err := loadSessionAndUser(ctx, opts, "tok-upstream")
	if err != nil {
		t.Fatal(err)
	}
	session, user := rowToSession(row, opts), rowToUser(urow, opts)
	sm, err := cacheStructMap(session)
	if err != nil {
		t.Fatal(err)
	}
	um, err := cacheStructMap(user)
	if err != nil {
		t.Fatal(err)
	}
	value := c701MintJWT(t, opts.CurrentSecret(), sm, um, "1")
	header := signedSessionHeader(t, opts, "tok-upstream") + "; better-auth.session_data=" + value
	cached, ok := cachedSessionFromRequest(header, opts.AllSecrets(), "tok-upstream", opts.Session)
	if !ok || cached == nil {
		t.Fatal("upstream better-auth.session_data name must hit (cookie-name recovery)")
	}
}

// Chunked session_data must reassemble (chunk recovery).
func TestSessionCookieCache_SessionDataChunkRecovery(t *testing.T) {
	db := newParityMemAdapter()
	opts := c701TestOptions(db)
	opts.Session.CookieCache.Strategy = types.SessionCookieCacheCompact
	seedSessionUser(t, db, "chunk@example.com", "tok-chunk", time.Now().UTC().Add(time.Hour))
	ctx := context.Background()
	row, urow, _, err := loadSessionAndUser(ctx, opts, "tok-chunk")
	if err != nil {
		t.Fatal(err)
	}
	session, user := rowToSession(row, opts), rowToUser(urow, opts)
	single, err := newSessionDataCookie(opts.CurrentSecret(), session, user, opts, opts.Session, time.Now().UTC(), false)
	if err != nil {
		t.Fatal(err)
	}
	attrs := cookies.DefaultAttributes(false, "")
	budget := cookies.MaxValueSizeFor(single.Name, attrs)
	chunks, err := cookies.ChunkCookieValue(single.Name, single.Value, budget)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) == 1 {
		half := len(single.Value) / 2
		chunks = map[string]string{
			single.Name + ".0": single.Value[:half],
			single.Name + ".1": single.Value[half:],
		}
	}
	var parts []string
	parts = append(parts, signedSessionHeader(t, opts, "tok-chunk"))
	for k, v := range chunks {
		parts = append(parts, k+"="+v)
	}
	header := strings.Join(parts, "; ")
	cached, ok := cachedSessionFromRequest(header, opts.AllSecrets(), "tok-chunk", opts.Session)
	if !ok || cached == nil {
		t.Fatalf("chunked session_data must reassemble, chunks=%v", chunks)
	}
}

// Custom session_data name via Advanced.Cookies must be accepted.
func TestSessionCookieCache_SessionDataCustomName(t *testing.T) {
	db := newParityMemAdapter()
	opts := c701TestOptions(db)
	opts.Advanced.Cookies = map[string]types.CookieConfig{
		"session_data": {Name: "custom.session"},
	}
	opts.Session.CookieCache.Strategy = types.SessionCookieCacheCompact
	seedSessionUser(t, db, "custom@example.com", "tok-custom", time.Now().UTC().Add(time.Hour))
	ctx := context.Background()
	row, urow, _, err := loadSessionAndUser(ctx, opts, "tok-custom")
	if err != nil {
		t.Fatal(err)
	}
	session, user := rowToSession(row, opts), rowToUser(urow, opts)
	single, err := newSessionDataCookie(opts.CurrentSecret(), session, user, opts, opts.Session, time.Now().UTC(), false)
	if err != nil {
		t.Fatal(err)
	}
	header := signedSessionHeader(t, opts, "tok-custom") + "; custom.session=" + single.Value
	cached, ok := cachedSessionFromRequestFull(ctx, header, opts.AllSecrets(), "tok-custom", opts)
	if !ok || cached == nil {
		t.Fatal("custom session_data name must hit via Full reader")
	}
}

func c701LoadFixture(t *testing.T, rel string) (secret, token, sessionToken, version string, session, user map[string]any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", rel))
	if err != nil {
		t.Fatalf("read fixture %s: %v", rel, err)
	}
	var doc struct {
		Secret  string         `json:"secret"`
		Token   string         `json:"token"`
		Session map[string]any `json:"session"`
		User    map[string]any `json:"user"`
		Version string         `json:"version"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse fixture %s: %v", rel, err)
	}
	tok, _ := doc.Session["token"].(string)
	return doc.Secret, doc.Token, tok, doc.Version, doc.Session, doc.User
}

// TS-produced JWT fixture must verify at the route layer with rotation.
func TestSessionCookieCache_TSFixtureJWTInteropAtRoute(t *testing.T) {
	secret, token, sessionToken, version, _, _ := c701LoadFixture(t, "session_jwt.json")
	db := newParityMemAdapter()
	opts := c701TestOptions(db)
	opts.Session.CookieCache.Strategy = types.SessionCookieCacheJWT
	header := signedSessionHeader(t, opts, sessionToken) + "; better-auth.session_data=" + token
	if _, ok := cachedSessionFromRequestFull(context.Background(), header, []string{"wrong"}, sessionToken, opts); ok {
		t.Fatal("wrong secret must miss at route layer")
	}
	cached, ok := cachedSessionFromRequestFull(context.Background(), header, []string{"rotated", secret}, sessionToken, opts)
	if !ok || cached == nil {
		t.Fatal("TS JWT fixture must hit under rotation at route layer")
	}
	if cached.Version != version {
		t.Fatalf("version = %q, want %q", cached.Version, version)
	}
	if _, ok := cachedSessionFromRequestFull(context.Background(), header, []string{secret}, "other-token", opts); ok {
		t.Fatal("token mismatch must miss")
	}
	for _, bad := range []string{"", "not.a.jwt", strings.Repeat("A", 1<<20)} {
		badHeader := signedSessionHeader(t, opts, sessionToken) + "; better-auth.session_data=" + bad
		if _, ok := cachedSessionFromRequestFull(context.Background(), badHeader, []string{secret}, sessionToken, opts); ok {
			t.Fatalf("malformed %q must miss", bad[:min16(len(bad))])
		}
	}
}

func min16(n int) int {
	if n > 16 {
		return 16
	}
	return n
}

// TS-produced JWE fixture must decrypt at the route layer with kid rotation.
func TestSessionCookieCache_TSFixtureJWEInteropAtRoute(t *testing.T) {
	secret, token, sessionToken, version, _, _ := c701LoadFixture(t, "session_jwe.json")
	db := newParityMemAdapter()
	opts := c701TestOptions(db)
	opts.Session.CookieCache.Strategy = types.SessionCookieCacheJWE
	opts.Session.CookieCache.Version = version
	header := signedSessionHeader(t, opts, sessionToken) + "; better-auth.session_data=" + token
	cached, ok := cachedSessionFromRequestFull(context.Background(), header, []string{"rotated", secret}, sessionToken, opts)
	if !ok || cached == nil {
		t.Fatal("TS JWE fixture must hit under rotation at route layer")
	}
	if _, ok := cachedSessionFromRequestFull(context.Background(), header, []string{"other-a", "other-b"}, sessionToken, opts); ok {
		t.Fatal("unknown kid must miss")
	}
	tampered := token[:len(token)-4] + "xxxx"
	badHeader := signedSessionHeader(t, opts, sessionToken) + "; better-auth.session_data=" + tampered
	if _, ok := cachedSessionFromRequestFull(context.Background(), badHeader, []string{secret}, sessionToken, opts); ok {
		t.Fatal("tampered JWE must miss")
	}
}

// Dynamic secure/domain via request context must win over static BaseURL.
func TestSessionCookieCache_DynamicSecureDomainViaContext(t *testing.T) {
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	opts.BaseURL = "http://app.example.com"
	ctx := WithRequestFullBaseURLValue(context.Background(), "https://tenant.example.com/api/auth")
	if !ResolveSecureCookiesWithContext(ctx, opts, CookieRequestHeaders{}) {
		t.Fatal("https request context must resolve Secure=true")
	}
	cfg := resolveSessionCookieConfigWithContext(ctx, opts, CookieRequestHeaders{Host: "tenant.example.com"})
	if !cfg.Secure {
		t.Fatal("session cookie must be Secure under https context")
	}
	if !strings.HasPrefix(cfg.Name, "__Secure-") {
		t.Fatalf("secure context must use __Secure- name, got %q", cfg.Name)
	}
	opts.Advanced.CrossSubDomainCookies.Enabled = true
	domain := ResolveCrossSubDomainCookieDomainWithContext(ctx, opts, CookieRequestHeaders{})
	if domain != "tenant.example.com" {
		t.Fatalf("domain = %q, want tenant.example.com", domain)
	}
	stored, _ := newStoredRequestForTest("tenant.example.com")
	ctx2 := withStoredRequestForTest(context.Background(), stored)
	filled := headersWithStoredRequest(ctx2, CookieRequestHeaders{})
	if filled.Host != "tenant.example.com" {
		t.Fatalf("stored request must supply Host, got %q", filled.Host)
	}
}

// AdditionalCookies domain propagation must resolve the shared domain.
func TestSessionCookieCache_AdditionalCookiesDomain(t *testing.T) {
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	opts.BaseURL = "https://app.example.com"
	opts.Advanced.CrossSubDomainCookies.Enabled = true
	opts.Advanced.CrossSubDomainCookies.AdditionalCookies = []string{"better-auth.account_data", "custom.extra"}
	domain := additionalCookiesDomain(context.Background(), opts, CookieRequestHeaders{})
	if domain != "app.example.com" {
		t.Fatalf("additional cookies domain = %q, want app.example.com", domain)
	}
	names := additionalCookieNames(opts)
	if len(names) != 2 {
		t.Fatalf("additional cookie names = %v, want 2", names)
	}
}

// Custom JWKS signer path must verify with claim binding and fall back.
func TestSessionCookieCache_CustomSignerClaimBindingAndFallback(t *testing.T) {
	db := newParityMemAdapter()
	opts := c701TestOptions(db)
	opts.Session.CookieCache.Strategy = types.SessionCookieCacheJWT
	seedSessionUser(t, db, "customsigner@example.com", "tok-signer", time.Now().UTC().Add(time.Hour))
	ctx := context.Background()
	row, urow, _, err := loadSessionAndUser(ctx, opts, "tok-signer")
	if err != nil {
		t.Fatal(err)
	}
	session, user := rowToSession(row, opts), rowToUser(urow, opts)
	fake := newFakeCookieCacheSignerForTest("issuer-test", "better-auth:session-cache")
	sm, _ := cacheStructMap(session)
	um, _ := cacheStructMap(user)
	custom, err := fake.SignForTest(sm, um, "1", 5*time.Minute)
	if err != nil {
		t.Fatalf("fake sign: %v", err)
	}
	opts.Plugins = []types.Plugin{fake}
	header := signedSessionHeader(t, opts, "tok-signer") + "; " + resolveSessionDataCookieName(opts, false) + "=" + custom
	cached, ok := cachedSessionFromRequestFull(ctx, header, opts.AllSecrets(), "tok-signer", opts)
	if !ok || cached == nil {
		t.Fatal("custom signer token must hit with claim binding")
	}
	badSession := map[string]any{"token": "other", "id": "x"}
	bad, _ := fake.SignForTest(badSession, um, "1", 5*time.Minute)
	badHeader := signedSessionHeader(t, opts, "tok-signer") + "; " + resolveSessionDataCookieName(opts, false) + "=" + bad
	if _, ok := cachedSessionFromRequestFull(ctx, badHeader, opts.AllSecrets(), "tok-signer", opts); ok {
		t.Fatal("sid mismatch must miss")
	}
	secretVal := c701MintJWT(t, opts.CurrentSecret(), sm, um, "1")
	secretHeader := signedSessionHeader(t, opts, "tok-signer") + "; " + resolveSessionDataCookieName(opts, false) + "=" + secretVal
	if _, ok := cachedSessionFromRequestFull(ctx, secretHeader, opts.AllSecrets(), "tok-signer", opts); ok {
		t.Fatal("secret-signed token must miss when custom signer is configured (fallback is DB, not cache)")
	}
}

// Stateless (no DB, no secondary) reads must not panic; cache hit serves,
func TestSessionCookieCache_StatelessNoDBGuard(t *testing.T) {
	opts := sessionTestOptions(newParityMemAdapter())
	opts.DB = nil
	opts.SecondaryStorage = nil
	opts.Session.CookieCache.Enabled = true
	opts.Session.CookieCache.Strategy = types.SessionCookieCacheCompact
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("stateless miss panicked: %v", r)
		}
	}()
	_, _, _, _, err := loadDatabaseSessionWithRefresh(context.Background(), opts, "tok-missing", sessionRefreshConfig{})
	if err == nil {
		t.Fatal("stateless miss must error")
	}
}

func newStoredRequestForTest(host string) (*http.Request, error) {
	return http.NewRequest(http.MethodGet, "https://"+host+"/api/auth/get-session", nil)
}

func withStoredRequestForTest(ctx context.Context, r *http.Request) context.Context {
	return context.WithValue(ctx, storedRequestKey{}, r)
}

type fakeCookieCachePayloadForTest struct {
	Session   map[string]any
	User      map[string]any
	UpdatedAt int64
	Version   string
}

type fakeCookieCacheVerifiedForTest struct {
	Payload   fakeCookieCachePayloadForTest
	ExpiresAt int64
}

type fakeCookieCacheSignerForTest struct {
	issuer   string
	audience string
	secret   []byte
}

func newFakeCookieCacheSignerForTest(issuer, audience string) *fakeCookieCacheSignerForTest {
	return &fakeCookieCacheSignerForTest{issuer: issuer, audience: audience, secret: []byte("fake-jwks-hmac-secret-for-c701-tests-32b!!")}
}

func (f *fakeCookieCacheSignerForTest) ID() string { return "jwt" }

func (f *fakeCookieCacheSignerForTest) Init(_ types.AuthContext) error { return nil }

func (f *fakeCookieCacheSignerForTest) Endpoints() []types.Endpoint { return nil }

func (f *fakeCookieCacheSignerForTest) Schema() types.PluginSchema { return nil }

func (f *fakeCookieCacheSignerForTest) Hooks() types.DBHooks { return nil }

func (f *fakeCookieCacheSignerForTest) RouteHooks() types.PluginRouteHooks {
	return types.PluginRouteHooks{}
}

func (f *fakeCookieCacheSignerForTest) ErrorCodes() map[string]string { return nil }

func (f *fakeCookieCacheSignerForTest) SignForTest(session, user map[string]any, version string, maxAge time.Duration) (string, error) {
	if maxAge <= 0 {
		maxAge = 5 * time.Minute
	}
	nowSec := time.Now().Unix()
	sessionToken, _ := session["token"].(string)
	userID, _ := user["id"].(string)
	claims := map[string]any{
		"session":   session,
		"user":      user,
		"updatedAt": time.Now().UnixMilli(),
		"version":   version,
		"sid":       sessionToken,
		"sub":       userID,
		"iss":       f.issuer,
		"aud":       f.audience,
		"iat":       nowSec,
		"exp":       nowSec + int64(maxAge.Seconds()),
	}
	raw, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	header, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "better-auth.session-cache+jwt"})
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, f.secret)
	mac.Write([]byte(unsigned))
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (f *fakeCookieCacheSignerForTest) SignCookieCache(_ context.Context, _ types.Options, payload fakeCookieCachePayloadForTest, maxAge time.Duration) (string, error) {
	return f.SignForTest(payload.Session, payload.User, payload.Version, maxAge)
}

func (f *fakeCookieCacheSignerForTest) VerifyCookieCache(_ context.Context, _ types.Options, token string) (fakeCookieCacheVerifiedForTest, error) {
	fail := func(msg string) (fakeCookieCacheVerifiedForTest, error) {
		return fakeCookieCacheVerifiedForTest{}, errFakeVerify(msg)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fail("encoding")
	}
	unsigned := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fail("sig")
	}
	mac := hmac.New(sha256.New, f.secret)
	mac.Write([]byte(unsigned))
	if !hmac.Equal(mac.Sum(nil), sig) {
		return fail("signature")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fail("payload")
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return fail("json")
	}
	session, _ := claims["session"].(map[string]any)
	user, _ := claims["user"].(map[string]any)
	if session == nil || user == nil {
		return fail("shape")
	}
	if iss, _ := claims["iss"].(string); iss != f.issuer {
		return fail("iss")
	}
	if aud, _ := claims["aud"].(string); aud != f.audience {
		return fail("aud")
	}
	if sub, _ := claims["sub"].(string); sub == "" || sub != user["id"] {
		return fail("sub")
	}
	if sid, _ := claims["sid"].(string); sid == "" || sid != session["token"] {
		return fail("sid")
	}
	expF, _ := claims["exp"].(float64)
	if expF == 0 || time.Now().Unix() >= int64(expF) {
		return fail("exp")
	}
	version, _ := claims["version"].(string)
	updatedF, _ := claims["updatedAt"].(float64)
	return fakeCookieCacheVerifiedForTest{
		Payload: fakeCookieCachePayloadForTest{
			Session:   session,
			User:      user,
			UpdatedAt: int64(updatedF),
			Version:   version,
		},
		ExpiresAt: int64(expF) * 1000,
	}, nil
}

func errFakeVerify(msg string) error {
	return &fakeVerifyError{msg: msg}
}

type fakeVerifyError struct{ msg string }

func (e *fakeVerifyError) Error() string { return "fake verify: " + e.msg }

// No-store semantics: get-session responses are never cached by intermediaries.
func TestSessionCookieCache_NoStoreHeaders(t *testing.T) {
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	seedSessionUser(t, db, "nostore@example.com", "tok-nostore", time.Now().UTC().Add(time.Hour))
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	GetSession(api, "/api/auth", opts)
	resp := api.Get("/api/auth/get-session", "Cookie: "+signedSessionHeader(t, opts, "tok-nostore"))
	if resp.Code != 200 {
		t.Fatalf("GET expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if cc := resp.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", cc)
	}
	if pragma := resp.Header().Get("Pragma"); pragma != "no-cache" {
		t.Fatalf("Pragma = %q, want no-cache", pragma)
	}
}

// Expiration cleanup: authoritative reads delete expired rows (best-effort).
func TestSessionCookieCache_ExpiredRowCleanup(t *testing.T) {
	ctx := context.Background()
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	seedSessionUser(t, db, "expired-clean@example.com", "tok-expired-clean", time.Now().UTC().Add(-time.Hour))
	_, _, _, _, err := loadDatabaseSessionWithRefresh(ctx, opts, "tok-expired-clean", sessionRefreshConfig{})
	if err == nil {
		t.Fatal("expired session must error")
	}
	if row, _ := db.FindOne(ctx, "session", []types.Where{{Field: "token", Value: "tok-expired-clean"}}, nil); row != nil {
		t.Fatal("expired row must be deleted on authoritative read")
	}
	db2 := newParityMemAdapter()
	opts2 := sessionTestOptions(db2)
	seedSessionUser(t, db2, "expired-defer@example.com", "tok-expired-defer", time.Now().UTC().Add(-time.Hour))
	_, _, _, _, _ = loadDatabaseSessionWithRefresh(ctx, opts2, "tok-expired-defer", sessionRefreshConfig{readOnly: true})
	if row, _ := db2.FindOne(ctx, "session", []types.Where{{Field: "token", Value: "tok-expired-defer"}}, nil); row == nil {
		t.Fatal("deferred GET must not delete expired rows")
	}
}

// Revoke with a foreign token still returns status:true (upstream matrix).
func TestSessionCookieCache_RevokeForeignTokenMatrix(t *testing.T) {
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	seedSessionUser(t, db, "revoke-a@example.com", "tok-revoke-a", time.Now().UTC().Add(time.Hour))
	seedSessionUser(t, db, "revoke-b@example.com", "tok-revoke-b", time.Now().UTC().Add(time.Hour))
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	RevokeSession(api, "/api/auth", opts)
	headerA := signedSessionHeader(t, opts, "tok-revoke-a")
	resp := api.Post("/api/auth/revoke-session", "Cookie: "+headerA, map[string]any{"token": "tok-revoke-b"})
	if resp.Code != 200 {
		t.Fatalf("revoke foreign expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), `"status":true`) {
		t.Fatalf("revoke foreign must return status:true, got %s", resp.Body.String())
	}
	if _, _, _, err := loadSessionAndUser(context.Background(), opts, "tok-revoke-b"); err != nil {
		t.Fatalf("foreign session must survive: %v", err)
	}
	_, api2 := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	UpdateSession(api2, "/api/auth", opts)
	emptyResp := api2.Post("/api/auth/update-session", "Cookie: "+headerA, map[string]any{})
	if emptyResp.Code != 400 {
		t.Fatalf("empty update expected 400, got %d: %s", emptyResp.Code, emptyResp.Body.String())
	}
	badResp := api2.Post("/api/auth/update-session", "Cookie: "+signedSessionHeader(t, opts, "tok-missing"), map[string]any{"x": "1"})
	if badResp.Code != 401 {
		t.Fatalf("unknown token update expected 401, got %d: %s", badResp.Code, badResp.Body.String())
	}
}

// Stateful/stateless refresh defaults pin upstream create-context behavior.
func TestSessionCookieCache_StatefulStatelessDefaults(t *testing.T) {
	withDB := sessionTestOptions(newParityMemAdapter())
	if !isStatefulSessionStore(withDB) {
		t.Fatal("DB deployment must be stateful")
	}
	stateless := sessionTestOptions(newParityMemAdapter())
	stateless.DB = nil
	stateless.SecondaryStorage = nil
	if isStatefulSessionStore(stateless) {
		t.Fatal("DB-less deployment must be stateless")
	}
	opts := parityTestOptions(newParityMemAdapter())
	if got := opts.Session.ExpiresInDuration(); got != 7*24*time.Hour {
		t.Fatalf("default ExpiresIn = %v, want 7d", got)
	}
}
