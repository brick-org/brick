package auth_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	auth "github.com/brick-org/brick/auth/src"
	authbun "github.com/brick-org/brick/auth/src/adapters/bun"
	routes "github.com/brick-org/brick/auth/src/api/routes"
	"github.com/brick-org/brick/auth/src/crypto"
	authdb "github.com/brick-org/brick/auth/src/db"
	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
	"golang.org/x/crypto/bcrypt"
)

// D01: Options.DB naming.
// Upstream: BetterAuthOptions.database
func TestDecisions_D01_OptionsDBNaming(t *testing.T) {
	rt := reflect.TypeOf(types.Options{})
	if _, ok := rt.FieldByName("DB"); !ok {
		t.Fatal("types.Options must keep the DB field (decision D01)")
	}
	if _, ok := rt.FieldByName("Database"); ok {
		t.Fatal("types.Options must NOT gain a Database alias (decision D01)")
	}
}

// D02: random-ID alphabet.
// Upstream generateId is alphanumeric only
func TestDecisions_D02_RandomIDAlphabet(t *testing.T) {
	id := crypto.GenerateID()
	if len(id) != 32 {
		t.Fatalf("GenerateID length = %d, want 32", len(id))
	}
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_"
	for _, c := range id {
		if !strings.ContainsRune(alphabet, c) {
			t.Fatalf("GenerateID char %q outside documented -_ alphabet", c)
		}
	}
	if got := crypto.GenerateIDWithSize(0); len(got) != 32 {
		t.Fatalf("GenerateIDWithSize(0) length = %d, want 32", len(got))
	}
	seen := map[rune]bool{}
	for i := 0; i < 200; i++ {
		for _, c := range crypto.GenerateID() {
			seen[c] = true
		}
	}
	if !seen['-'] || !seen['_'] {
		t.Fatal("GenerateID must use the -_ alphabet (decision D02)")
	}
}

// D03: PKCE plain mode is not implemented.
// Upstream only ever emits S256
func TestDecisions_D03_PKCEPlainRejected(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := crypto.S256Challenge(verifier)
	if !crypto.VerifyPKCE(verifier, challenge) {
		t.Fatal("S256 challenge must verify (decision D03)")
	}
	if got := crypto.GenerateCodeChallenge(verifier); got != challenge {
		t.Fatal("GenerateCodeChallenge must equal S256Challenge (decision D03)")
	}
	if crypto.VerifyPKCE(verifier, verifier) {
		t.Fatal("plain challenge (challenge == verifier) must not verify (decision D03)")
	}
	if crypto.VerifyPKCE("something", "something") {
		t.Fatal("plain equality fallback must not exist (decision D03)")
	}
}

// D04: IDNA/punycode.
// Upstream canonicalizes hosts via URL parsing; Go lowercases only and
func TestDecisions_D04_IDNANoPunycode(t *testing.T) {
	if !types.MatchesOriginPattern("https://münchen.de/", "https://münchen.de") {
		t.Fatal("identical unicode origins must match (decision D04)")
	}
	if types.MatchesOriginPattern("https://xn--mnchen-3ya.de/", "https://münchen.de") {
		t.Fatal("punycode URL must NOT match unicode pattern without idna (decision D04)")
	}
	if types.MatchesOriginPattern("https://münchen.de/", "https://xn--mnchen-3ya.de") {
		t.Fatal("unicode URL must NOT match punycode pattern without idna (decision D04)")
	}
}

// D05: non-transactional after-hook errors.
// Upstream queueAfterTransactionHook outside a transaction executes
func TestDecisions_D05_NonTransactionalAfterHookThrows(t *testing.T) {
	ctx := context.Background()
	inner := newMemoryAdapter()
	hooks := auth.DBHooks{
		"user": types.ModelHooks{
			Create: types.OperationHooks{
				After: func(_ context.Context, _ map[string]any) error {
					return errors.New("boom")
				},
			},
		},
	}
	wrapped := auth.NewHookedAdapter(inner, nil, hooks)
	row, err := wrapped.Create(ctx, "user", map[string]any{"id": "d05", "name": "x"}, nil)
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("non-transactional after-hook error must propagate (decision D05, AUTH-S6-01), got row=%v err=%v", row, err)
	}
	if row == nil {
		t.Fatal("Create must still return the persisted row alongside the after-hook error (decision D05)")
	}
	if n, _ := inner.Count(ctx, "user", nil); n != 1 {
		t.Fatal("write must stay committed despite the after-hook failure (decision D05)")
	}
}
// D07: MSSQL OUTPUT inserted.
// Upstream kysely adapter uses top(1)+OUTPUT on mssql
func TestDecisions_D07_MSSQLFallbackDialect(t *testing.T) {
	mssql, ok := authbun.NewWithDialect(nil, nil, authdb.Config{}, "mssql").(*authbun.Adapter)
	if !ok {
		t.Fatal("NewWithDialect must return *Adapter (decision D07)")
	}
	if got := mssql.Dialect(); got != "mssql" {
		t.Fatalf("mssql dialect label = %q, want mssql (decision D07)", got)
	}
	mysql, ok := authbun.NewWithDialect(nil, nil, authdb.Config{}, "mysql").(*authbun.Adapter)
	if !ok {
		t.Fatal("NewWithDialect must return *Adapter (decision D07)")
	}
	if got := mysql.Dialect(); got != "mysql" {
		t.Fatalf("mysql dialect label = %q, want mysql (decision D07)", got)
	}
	pg, ok := authbun.NewWithDialect(nil, nil, authdb.Config{}, "pg").(*authbun.Adapter)
	if !ok {
		t.Fatal("NewWithDialect must return *Adapter (decision D07)")
	}
	if got := pg.Dialect(); got != "pg" {
		t.Fatalf("pg dialect label = %q, want pg (decision D07)", got)
	}
}
// D14: verify-email POST alias.
// Upstream serves GET /verify-email only
func TestDecisions_D14_VerifyEmailPOSTAlias(t *testing.T) {
	_, api := humatest.New(t, huma.DefaultConfig("Test", "1.0.0"))
	routes.VerifyEmail(api, "/api/auth", types.Options{Secret: "test-secret-for-registration"})
	spec := api.OpenAPI()
	item, ok := spec.Paths["/api/auth/verify-email"]
	if !ok || item == nil || item.Post == nil {
		t.Fatal("POST /verify-email alias must stay registered (decision D14)")
	}
	getResp := api.Get("/api/auth/verify-email?token=bad-token")
	if getResp.Code == 404 {
		t.Fatal("GET /verify-email (upstream contract) must stay registered (decision D14)")
	}
	postResp := api.Post("/api/auth/verify-email", map[string]any{"token": "bad-token"})
	if postResp.Code == 404 {
		t.Fatal("POST /verify-email alias must stay registered (decision D14)")
	}
}

// D15: bounded legacy HMAC/bcrypt reads.
// Upstream password hashing is scrypt
func TestDecisions_D15_LegacyPasswordAndTokenReads(t *testing.T) {
	hash, err := crypto.HashPassword("correct horse")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !crypto.VerifyPassword(hash, "correct horse") {
		t.Fatal("scrypt hash must verify (decision D15)")
	}
	if crypto.VerifyPassword(hash, "wrong") {
		t.Fatal("scrypt hash must reject wrong password (decision D15)")
	}
	bcryptHash, err := bcrypt.GenerateFromPassword([]byte("legacy-pass"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if !crypto.VerifyPassword(string(bcryptHash), "legacy-pass") {
		t.Fatal("legacy bcrypt hash must verify (decision D15)")
	}
	if crypto.VerifyPassword(string(bcryptHash), "wrong") {
		t.Fatal("legacy bcrypt hash must reject wrong password (decision D15)")
	}
	legacy, err := crypto.GenerateToken("s3cret", "a@b.c", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if email, err := crypto.VerifyEmailTokenWithFallback([]string{"s3cret"}, legacy); err != nil || email != "a@b.c" {
		t.Fatalf("legacy HMAC email token must verify via fallback: %v %q (decision D15)", err, email)
	}
	jwt, err := crypto.CreateEmailVerificationToken("s3cret", "a@b.c", "", 3600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if email, err := crypto.VerifyEmailTokenWithFallback([]string{"s3cret"}, jwt); err != nil || email != "a@b.c" {
		t.Fatalf("HS256 email JWT must verify via fallback: %v %q (decision D15)", err, email)
	}
	if _, err := crypto.VerifyEmailVerificationTokenAny([]string{"new", "s3cret"}, jwt); err != nil {
		t.Fatalf("retained secret must verify email JWT: %v (decision D15)", err)
	}
}

// D16: $brick$ AES-GCM writers vs upstream XChaCha readers.
func TestDecisions_D16_BrickWriterUpstreamReader(t *testing.T) {
	brick, err := crypto.EncryptString("secret", "plaintext")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(brick, "$brick$") {
		t.Fatalf("EncryptString must keep the $brick$ write format (decision D16): %q", brick)
	}
	if plain, err := crypto.DecryptString("secret", brick); err != nil || plain != "plaintext" {
		t.Fatalf("$brick$ payload must decrypt: %v %q (decision D16)", err, plain)
	}
	upstream, err := crypto.SymmetricEncrypt("secret", "plaintext")
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(upstream, "$brick$") {
		t.Fatal("SymmetricEncrypt must emit the upstream format, not $brick$ (decision D16)")
	}
	if plain, err := crypto.DecryptString("secret", upstream); err != nil || plain != "plaintext" {
		t.Fatalf("DecryptString must read upstream XChaCha payloads: %v %q (decision D16)", err, plain)
	}
	if plain, err := crypto.DecryptStringCompatible([]string{"old", "secret"}, brick); err != nil || plain != "plaintext" {
		t.Fatalf("DecryptStringCompatible must read $brick$: %v %q (decision D16)", err, plain)
	}
	if plain, err := crypto.DecryptStringCompatible([]string{"old", "secret"}, upstream); err != nil || plain != "plaintext" {
		t.Fatalf("DecryptStringCompatible must read upstream: %v %q (decision D16)", err, plain)
	}
	versioned, err := crypto.SymmetricEncrypt(crypto.SecretConfig{Keys: map[int]string{2: "secret"}, CurrentVersion: 2}, "plaintext")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(versioned, "$ba$2$") {
		t.Fatalf("versioned encrypt must emit $ba$ envelope: %q (decision D16)", versioned)
	}
}
