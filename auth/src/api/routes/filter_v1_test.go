package routes

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/types"
)

// Cookie-cache field filtering (v1 core port).
//
// Upstream: vendor/.../src/cookies/cookies.test.ts, describe
// "Cookie Cache Field Filtering" (pinned 5468e6bf). Upstream setCookieCache
// (cookies/index.ts:169-174) strips schema-declared `returned:false` fields
// via filterOutputFields (session) and parseUserOutput (user) before signing,
// for every strategy. Unknown fields are kept (backward compatibility).
//
// Adaptation: Go keeps additional fields nested under AdditionalFields (not
// flat), and DB reads (rowToUser/rowToSession) already strip returned:false.
// These tests therefore build Session/User structs directly with
// AdditionalFields values (simulating defaults applied at creation, as in the
// upstream getTestInstance configs) and mint via newSessionDataCookieWithContext
// (the owned issuance path), reading back via cachedSessionFromRequestFull.
// The sign-up/sign-in HTTP issuance legs are sibling-owned and untouched here.

func filterV1BoolPtr(v bool) *bool { return &v }

func filterV1BaseOpts() (types.Options, *parityMemAdapter) {
	db := newParityMemAdapter()
	opts := sessionTestOptions(db)
	opts.Session.CookieCache.Enabled = true
	return opts, db
}

func filterV1Pair(token string) (types.Session, types.User) {
	now := time.Now().UTC()
	session := types.Session{
		ID:        "sess-" + token,
		UserID:    "user-1",
		Token:     token,
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
		UpdatedAt: now,
	}
	user := types.User{
		ID:            "user-1",
		Email:         "filter@example.com",
		EmailVerified: true,
		Name:          "Filter User",
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	return session, user
}

func filterV1Mint(t *testing.T, ctx context.Context, opts types.Options, session types.Session, user types.User) (*sessionCookieCachePayload, string) {
	t.Helper()
	cookie, err := newSessionDataCookieWithContext(ctx, opts, session, user, opts.Session, time.Now().UTC(), false)
	if err != nil {
		t.Fatalf("mint cache cookie: %v", err)
	}
	header := signedSessionHeader(t, opts, session.Token) + "; " + cookie.Name + "=" + cookie.Value
	payload, ok := cachedSessionFromRequestFull(ctx, header, opts.AllSecrets(), session.Token, opts)
	if !ok || payload == nil {
		t.Fatal("minted cache must hit via cachedSessionFromRequestFull")
	}
	return payload, cookie.Value
}

func filterV1AssertAbsent(t *testing.T, m map[string]any, key string) {
	t.Helper()
	if _, ok := m[key]; ok {
		t.Fatalf("field %q must be filtered from cookie cache, got %#v", key, m[key])
	}
}

func filterV1AssertPresent(t *testing.T, m map[string]any, key string, want any) {
	t.Helper()
	got, ok := m[key]
	if !ok {
		t.Fatalf("field %q must be present in cookie cache", key)
	}
	if want != nil && got != want {
		t.Fatalf("field %q = %#v, want %#v", key, got, want)
	}
}

// Upstream: "should exclude user fields with returned: false from cookie cache"
// (internalNote undefined, email kept).
func TestFilterV1_ExcludeSingleUserField(t *testing.T) {
	ctx := context.Background()
	opts, _ := filterV1BaseOpts()
	opts.User.Model.AdditionalFields = map[string]types.FieldAttribute{
		"internalNote": {Type: "string", DefaultValue: "", Returned: filterV1BoolPtr(false)},
	}
	session, user := filterV1Pair("tok-f1")
	user.AdditionalFields = map[string]any{"internalNote": "secret-note"}
	payload, _ := filterV1Mint(t, ctx, opts, session, user)
	if payload.User.Email != user.Email {
		t.Fatalf("email = %q, want %q", payload.User.Email, user.Email)
	}
	filterV1AssertAbsent(t, payload.User.AdditionalFields, "internalNote")
}

// Upstream: "should correctly filter multiple user fields based on returned config".
func TestFilterV1_MultipleUserFields(t *testing.T) {
	ctx := context.Background()
	opts, _ := filterV1BaseOpts()
	opts.User.Model.AdditionalFields = map[string]types.FieldAttribute{
		"publicBio":     {Type: "string", DefaultValue: "default-bio", Returned: filterV1BoolPtr(true)},
		"internalNotes": {Type: "string", DefaultValue: "internal-notes", Returned: filterV1BoolPtr(false)},
		"preferences":   {Type: "string", DefaultValue: "default-prefs", Returned: filterV1BoolPtr(true)},
		"adminFlags":    {Type: "string", DefaultValue: "admin-flags", Returned: filterV1BoolPtr(false)},
	}
	session, user := filterV1Pair("tok-f2")
	user.AdditionalFields = map[string]any{
		"publicBio": "bio", "internalNotes": "secret",
		"preferences": "prefs", "adminFlags": "flags",
	}
	payload, _ := filterV1Mint(t, ctx, opts, session, user)
	filterV1AssertPresent(t, payload.User.AdditionalFields, "publicBio", "bio")
	filterV1AssertPresent(t, payload.User.AdditionalFields, "preferences", "prefs")
	filterV1AssertAbsent(t, payload.User.AdditionalFields, "internalNotes")
	filterV1AssertAbsent(t, payload.User.AdditionalFields, "adminFlags")
}

// Upstream: "should reduce cookie size when large fields are excluded".
func TestFilterV1_LargeFieldExcluded(t *testing.T) {
	ctx := context.Background()
	opts, _ := filterV1BaseOpts()
	largeString := strings.Repeat("x", 2000)
	opts.User.Model.AdditionalFields = map[string]types.FieldAttribute{
		"largeBio":   {Type: "string", DefaultValue: largeString, Returned: filterV1BoolPtr(false)},
		"smallField": {Type: "string", DefaultValue: "small-value", Returned: filterV1BoolPtr(true)},
	}
	session, user := filterV1Pair("tok-f3")
	user.AdditionalFields = map[string]any{"largeBio": largeString, "smallField": "small-value"}
	payload, raw := filterV1Mint(t, ctx, opts, session, user)
	if payload == nil {
		t.Fatal("cache must exist (not exceed size limit)")
	}
	filterV1AssertAbsent(t, payload.User.AdditionalFields, "largeBio")
	filterV1AssertPresent(t, payload.User.AdditionalFields, "smallField", "small-value")
	if len(raw) >= 2000 {
		t.Fatalf("filtered cookie value length = %d, want < 2000 (large field excluded)", len(raw))
	}
}

// Upstream: "should maintain session field filtering (regression check)".
func TestFilterV1_SessionFieldFiltering(t *testing.T) {
	ctx := context.Background()
	opts, _ := filterV1BaseOpts()
	opts.Session.Model.AdditionalFields = map[string]types.FieldAttribute{
		"internalSessionData": {Type: "string", DefaultValue: "internal-data", Returned: filterV1BoolPtr(false)},
		"publicSessionData":   {Type: "string", DefaultValue: "public-data", Returned: filterV1BoolPtr(true)},
	}
	session, user := filterV1Pair("tok-f4")
	session.AdditionalFields = map[string]any{
		"internalSessionData": "internal-data", "publicSessionData": "public-data",
	}
	payload, _ := filterV1Mint(t, ctx, opts, session, user)
	if payload.Session.Token == "" {
		t.Fatal("session token must survive filtering")
	}
	if payload.Session.Token != "tok-f4" {
		t.Fatalf("session token = %q, want tok-f4", payload.Session.Token)
	}
	filterV1AssertAbsent(t, payload.Session.AdditionalFields, "internalSessionData")
	filterV1AssertPresent(t, payload.Session.AdditionalFields, "publicSessionData", "public-data")
}

// Upstream: "should include unknown user fields for backward compatibility"
// (known returned:false dropped; email/name kept; unknown kept).
func TestFilterV1_UnknownFieldsKept(t *testing.T) {
	ctx := context.Background()
	opts, _ := filterV1BaseOpts()
	opts.User.Model.AdditionalFields = map[string]types.FieldAttribute{
		"knownField": {Type: "string", DefaultValue: "known-value", Returned: filterV1BoolPtr(false)},
	}
	session, user := filterV1Pair("tok-f5")
	user.AdditionalFields = map[string]any{"knownField": "known-value", "undeclaredExtra": "kept"}
	payload, _ := filterV1Mint(t, ctx, opts, session, user)
	filterV1AssertAbsent(t, payload.User.AdditionalFields, "knownField")
	if payload.User.Email != user.Email {
		t.Fatalf("email = %q, want %q", payload.User.Email, user.Email)
	}
	if payload.User.Name == "" {
		t.Fatal("name must be present (backward compatibility)")
	}
	filterV1AssertPresent(t, payload.User.AdditionalFields, "undeclaredExtra", "kept")
}

// Upstream: "should work with JWT strategy" (email + token round-trip;
// plus filtering, which must apply to every strategy).
func TestFilterV1_JWTStrategy(t *testing.T) {
	ctx := context.Background()
	opts, _ := filterV1BaseOpts()
	opts.Session.CookieCache.Strategy = types.SessionCookieCacheJWT
	opts.User.Model.AdditionalFields = map[string]types.FieldAttribute{
		"hiddenNote": {Type: "string", DefaultValue: "", Returned: filterV1BoolPtr(false)},
	}
	session, user := filterV1Pair("tok-f6")
	user.AdditionalFields = map[string]any{"hiddenNote": "secret"}
	payload, _ := filterV1Mint(t, ctx, opts, session, user)
	if payload.User.Email != user.Email {
		t.Fatalf("email = %q, want %q", payload.User.Email, user.Email)
	}
	if payload.Session.Token == "" {
		t.Fatal("session token must survive JWT filtering")
	}
	filterV1AssertAbsent(t, payload.User.AdditionalFields, "hiddenNote")
}

// Upstream: "should work with compact strategy" (email + token round-trip;
// plus filtering).
func TestFilterV1_CompactStrategy(t *testing.T) {
	ctx := context.Background()
	opts, _ := filterV1BaseOpts()
	opts.Session.CookieCache.Strategy = types.SessionCookieCacheCompact
	opts.User.Model.AdditionalFields = map[string]types.FieldAttribute{
		"hiddenNote": {Type: "string", DefaultValue: "", Returned: filterV1BoolPtr(false)},
	}
	session, user := filterV1Pair("tok-f7")
	user.AdditionalFields = map[string]any{"hiddenNote": "secret"}
	payload, _ := filterV1Mint(t, ctx, opts, session, user)
	if payload.User.Email != user.Email {
		t.Fatalf("email = %q, want %q", payload.User.Email, user.Email)
	}
	if payload.Session.Token == "" {
		t.Fatal("session token must survive compact filtering")
	}
	filterV1AssertAbsent(t, payload.User.AdditionalFields, "hiddenNote")
}

// Custom-signer path (no direct upstream case; constraint: JWT/custom-signer
// paths share the filter). Exercises signViaCustomSigner + verify round-trip.
type filterV1Payload struct {
	Session   map[string]any
	User      map[string]any
	UpdatedAt int64
	Version   string
}

type filterV1Verified struct {
	Payload   filterV1Payload
	ExpiresAt int64
}

type filterV1FakeSigner struct {
	issuer   string
	audience string
	secret   []byte
}

func (f *filterV1FakeSigner) ID() string { return "jwt" }

func (f *filterV1FakeSigner) Init(_ types.AuthContext) error { return nil }

func (f *filterV1FakeSigner) Endpoints() []types.Endpoint { return nil }

func (f *filterV1FakeSigner) Schema() types.PluginSchema { return nil }

func (f *filterV1FakeSigner) Hooks() types.DBHooks { return nil }

func (f *filterV1FakeSigner) RouteHooks() types.PluginRouteHooks {
	return types.PluginRouteHooks{}
}

func (f *filterV1FakeSigner) ErrorCodes() map[string]string { return nil }

func (f *filterV1FakeSigner) signMap(session, user map[string]any, version string, maxAge time.Duration) (string, error) {
	if maxAge <= 0 {
		maxAge = 5 * time.Minute
	}
	nowSec := time.Now().Unix()
	sessionToken, _ := session["token"].(string)
	userID, _ := user["id"].(string)
	claims := map[string]any{
		"session": session, "user": user,
		"updatedAt": time.Now().UnixMilli(), "version": version,
		"sid": sessionToken, "sub": userID,
		"iss": f.issuer, "aud": f.audience,
		"iat": nowSec, "exp": nowSec + int64(maxAge.Seconds()),
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

func (f *filterV1FakeSigner) SignCookieCache(_ context.Context, _ types.Options, payload filterV1Payload, maxAge time.Duration) (string, error) {
	return f.signMap(payload.Session, payload.User, payload.Version, maxAge)
}

func (f *filterV1FakeSigner) VerifyCookieCache(_ context.Context, _ types.Options, token string) (filterV1Verified, error) {
	fail := func(msg string) (filterV1Verified, error) {
		return filterV1Verified{}, &filterV1VerifyError{msg: msg}
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
	expF, _ := claims["exp"].(float64)
	if expF == 0 || time.Now().Unix() >= int64(expF) {
		return fail("exp")
	}
	version, _ := claims["version"].(string)
	updatedF, _ := claims["updatedAt"].(float64)
	return filterV1Verified{
		Payload: filterV1Payload{
			Session: session, User: user,
			UpdatedAt: int64(updatedF), Version: version,
		},
		ExpiresAt: int64(expF) * 1000,
	}, nil
}

type filterV1VerifyError struct{ msg string }

func (e *filterV1VerifyError) Error() string { return "filterv1 verify: " + e.msg }

func TestFilterV1_CustomSignerFiltering(t *testing.T) {
	ctx := context.Background()
	opts, _ := filterV1BaseOpts()
	opts.Session.CookieCache.Strategy = types.SessionCookieCacheJWT
	opts.User.Model.AdditionalFields = map[string]types.FieldAttribute{
		"hiddenNote": {Type: "string", DefaultValue: "", Returned: filterV1BoolPtr(false)},
	}
	opts.Plugins = []types.Plugin{&filterV1FakeSigner{
		issuer: "filter-test", audience: "better-auth:session-cache",
		secret: []byte("filter-v1-fake-signer-secret-32bytes!!"),
	}}
	session, user := filterV1Pair("tok-f8")
	user.AdditionalFields = map[string]any{"hiddenNote": "secret"}
	payload, _ := filterV1Mint(t, ctx, opts, session, user)
	if payload.User.Email != user.Email {
		t.Fatalf("email = %q, want %q", payload.User.Email, user.Email)
	}
	filterV1AssertAbsent(t, payload.User.AdditionalFields, "hiddenNote")
}
