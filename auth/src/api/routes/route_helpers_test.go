package routes

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/crypto"
	"github.com/brick-org/brick/auth/src/types"
)

// --- HS256 email-JWT issuance + legacy HMAC read migration ---

func TestProcessVerifyEmail_HS256JWTMarksVerified(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	parityCreateUser(t, db, "jwt-verify@example.com", false)

	token, err := crypto.CreateEmailVerificationToken(opts.CurrentSecret(), "jwt-verify@example.com", "", 3600, nil)
	if err != nil {
		t.Fatalf("issue JWT: %v", err)
	}
	user, _, errCode, status := processVerifyEmail(context.Background(), opts, token, CookieRequestHeaders{})
	if errCode != "" {
		t.Fatalf("expected success, got %s (%d)", errCode, status)
	}
	if user != nil {
		t.Fatalf("fresh verify must return null user, got %#v", user)
	}
}

func TestProcessVerifyEmail_ExpiredJWTReportsTokenExpired(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	parityCreateUser(t, db, "jwt-expired@example.com", false)

	token, err := crypto.CreateEmailVerificationToken(opts.CurrentSecret(), "jwt-expired@example.com", "", -3600, nil)
	if err != nil {
		t.Fatalf("issue JWT: %v", err)
	}
	_, _, errCode, status := processVerifyEmail(context.Background(), opts, token, CookieRequestHeaders{})
	if errCode != types.ErrTokenExpired || status != 401 {
		t.Fatalf("expected TOKEN_EXPIRED/401, got %s/%d", errCode, status)
	}
}

func TestProcessVerifyEmail_JWTRotationFallback(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	opts.Secrets = []types.Secret{{Version: 2, Value: "new-secret"}, {Version: 1, Value: opts.Secret}}
	parityCreateUser(t, db, "jwt-rotated@example.com", false)

	token, err := crypto.CreateEmailVerificationToken("parity-secret", "jwt-rotated@example.com", "", 3600, nil)
	if err != nil {
		t.Fatalf("issue JWT: %v", err)
	}
	if _, _, errCode, _ := processVerifyEmail(context.Background(), opts, token, CookieRequestHeaders{}); errCode != "" {
		t.Fatalf("retained secret must still verify JWT, got %s", errCode)
	}
}

func TestSendVerificationEmailForUser_IssuesHS256(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	opts.BasePath = "/api/auth"
	var gotToken string
	opts.EmailVerification.SendVerificationEmail = func(data types.VerificationEmailData) error {
		gotToken = data.Token
		return nil
	}
	parityCreateUser(t, db, "jwt-issued@example.com", false)
	userRow, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: "jwt-issued@example.com"}}, nil)

	if err := sendVerificationEmailForUser(context.Background(), opts, userRow, nil); err != nil {
		t.Fatalf("send: %v", err)
	}
	payload, err := crypto.VerifyEmailVerificationTokenAny(opts.AllSecrets(), gotToken)
	if err != nil {
		t.Fatalf("issued token must be an HS256 email JWT, got %q: %v", gotToken, err)
	}
	if payload.Email != "jwt-issued@example.com" {
		t.Fatalf("wrong JWT email: %+v", payload)
	}
}

func TestSendVerificationEmailForUser_RequestVariantPrecedence(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	opts.BasePath = "/api/auth"
	var order []string
	opts.EmailVerification.SendVerificationEmail = func(types.VerificationEmailData) error {
		order = append(order, "legacy")
		return nil
	}
	opts.EmailVerification.SendVerificationEmailRequest = func(types.VerificationEmailData, *http.Request) error {
		order = append(order, "request")
		return nil
	}
	parityCreateUser(t, db, "jwt-req@example.com", false)
	userRow, _ := db.FindOne(context.Background(), "user", []types.Where{{Field: "email", Value: "jwt-req@example.com"}}, nil)

	if err := sendVerificationEmailForUser(context.Background(), opts, userRow, nil); err != nil {
		t.Fatalf("send: %v", err)
	}
	if len(order) != 1 || order[0] != "request" {
		t.Fatalf("request-aware variant must win, got %#v", order)
	}
}

func TestFinishDeleteUser_HookOrderAndRequestPrecedence(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	var order []string
	opts.User.DeleteUser.BeforeDelete = func(*types.User) error {
		order = append(order, "before-legacy")
		return nil
	}
	opts.User.DeleteUser.AfterDelete = func(*types.User) error {
		order = append(order, "after-legacy")
		return nil
	}
	opts.User.DeleteUser.BeforeDeleteRequest = func(*types.User, *http.Request) error {
		order = append(order, "before-request")
		return nil
	}
	opts.User.DeleteUser.AfterDeleteRequest = func(*types.User, *http.Request) error {
		order = append(order, "after-request")
		return nil
	}
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := db.Create(ctx, "user", map[string]any{"id": "u-del", "email": "del@example.com", "createdAt": now, "updatedAt": now}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Create(ctx, "session", map[string]any{"id": "s-del", "userId": "u-del", "token": "tok", "createdAt": now, "updatedAt": now}, nil); err != nil {
		t.Fatal(err)
	}
	user := types.User{ID: "u-del", Email: "del@example.com"}
	if err := finishDeleteUser(ctx, opts, "u-del", user); err != nil {
		t.Fatalf("finish: %v", err)
	}
	if len(order) != 2 || order[0] != "before-request" || order[1] != "after-request" {
		t.Fatalf("expected request hooks in order, got %#v", order)
	}
	if row, _ := db.FindOne(ctx, "user", []types.Where{{Field: "id", Value: "u-del"}}, nil); row != nil {
		t.Fatal("user row must be deleted")
	}
	if row, _ := db.FindOne(ctx, "session", []types.Where{{Field: "id", Value: "s-del"}}, nil); row != nil {
		t.Fatal("session rows must be deleted")
	}
}

func TestFinishDeleteUser_BeforeHookAborts(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	opts.User.DeleteUser.BeforeDelete = func(*types.User) error {
		return errors.New("nope")
	}
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := db.Create(ctx, "user", map[string]any{"id": "u-keep", "email": "keep@example.com", "createdAt": now, "updatedAt": now}, nil); err != nil {
		t.Fatal(err)
	}
	if err := finishDeleteUser(ctx, opts, "u-keep", types.User{ID: "u-keep"}); err == nil {
		t.Fatal("before hook failure must abort deletion")
	}
	if row, _ := db.FindOne(ctx, "user", []types.Where{{Field: "id", Value: "u-keep"}}, nil); row == nil {
		t.Fatal("user row must survive an aborted delete")
	}
}

func TestRunBackgroundOrAwait_SyncSwallowWithoutHandler(t *testing.T) {
	opts := parityTestOptions(newParityMemAdapter())
	ran := false
	runBackgroundOrAwait(opts, func() error {
		ran = true
		return errors.New("send failed")
	})
	if !ran {
		t.Fatal("without a handler the task must run synchronously")
	}
}

func TestRunBackgroundOrAwait_HandlerDeferred(t *testing.T) {
	opts := parityTestOptions(newParityMemAdapter())
	done := make(chan error, 1)
	var ran atomic.Bool
	opts.Advanced.BackgroundTasks.Handler = func(task func()) {
		go func() {
			defer func() { _ = recover() }()
			task()
			done <- nil
		}()
	}
	runBackgroundOrAwait(opts, func() error {
		ran.Store(true)
		return errors.New("send failed")
	})
	if ran.Load() {
		t.Fatal("with a handler the task must be deferred, not run inline")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("deferred task never ran")
	}
}

func TestDeleteAccountIdentifier_UpstreamSpelling(t *testing.T) {
	if got := deleteAccountIdentifier("tok"); got != "delete-account-tok" {
		t.Fatalf("must match upstream `delete-account-${token}`, got %q", got)
	}
}

func TestConsumeDeleteAccountToken_SingleUse(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	ctx := context.Background()

	token, err := createDeleteAccountVerification(ctx, opts, "user-1")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	userID, err := consumeDeleteAccountToken(ctx, opts, token)
	if err != nil || userID != "user-1" {
		t.Fatalf("first consume must win with user-1, got %q/%v", userID, err)
	}
	if _, err := consumeDeleteAccountToken(ctx, opts, token); err == nil {
		t.Fatal("second consume must fail")
	}
}

func TestConsumeDeleteAccountToken_WrongOwnerBurned(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	ctx := context.Background()

	token, err := createDeleteAccountVerification(ctx, opts, "user-a")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	storedUserID, err := consumeDeleteAccountToken(ctx, opts, token)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if storedUserID == "user-b" {
		t.Fatal("owner check happens at the call site")
	}
	if _, err := consumeDeleteAccountToken(ctx, opts, token); err == nil {
		t.Fatal("wrong-owner token must be burned on first consume")
	}
}

func TestConsumeDeleteAccountToken_ExpiredBurned(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	ctx := context.Background()

	now := time.Now().UTC()
	token := "tok-expired"
	if _, err := db.Create(ctx, "verification", map[string]any{
		"id": "ver-expired", "identifier": deleteAccountIdentifier(token),
		"value": "user-1", "expiresAt": now.Add(-time.Hour),
		"createdAt": now, "updatedAt": now,
	}, nil); err != nil {
		t.Fatalf("create expired row: %v", err)
	}
	if _, err := consumeDeleteAccountToken(ctx, opts, token); err == nil {
		t.Fatal("expired token must be rejected")
	}
	if _, err := consumeDeleteAccountToken(ctx, opts, token); err == nil {
		t.Fatal("expired token must be cleaned up, no replay")
	}
}

func TestCreateDeleteAccountVerification_SecondaryMirror(t *testing.T) {
	store := newMapSecondaryStorage(true)
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	opts.SecondaryStorage = store
	opts.Verification.StoreInDatabase = true
	ctx := context.Background()

	token, err := createDeleteAccountVerification(ctx, opts, "user-1")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if found, _ := findSecondaryVerification(opts, deleteAccountIdentifier(token)); found == nil {
		t.Fatal("creation must mirror into secondary storage")
	}
	if row, _ := db.FindOne(ctx, "verification", []types.Where{{Field: "identifier", Value: deleteAccountIdentifier(token)}}, nil); row == nil {
		t.Fatal("StoreInDatabase must keep the database row")
	}
}

func TestConsumeDeleteAccountToken_SecondaryOnly(t *testing.T) {
	store := newMapSecondaryStorage(true)
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	opts.SecondaryStorage = store
	ctx := context.Background()

	token, err := createDeleteAccountVerification(ctx, opts, "user-1")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if row, _ := db.FindOne(ctx, "verification", []types.Where{{Field: "identifier", Value: deleteAccountIdentifier(token)}}, nil); row != nil {
		t.Fatal("secondary-only creation must skip the database row")
	}
	userID, err := consumeDeleteAccountToken(ctx, opts, token)
	if err != nil || userID != "user-1" {
		t.Fatalf("secondary consume must win, got %q/%v", userID, err)
	}
	if _, err := consumeDeleteAccountToken(ctx, opts, token); err == nil {
		t.Fatal("secondary consume must be single-use")
	}
}

func TestCreateChangeEmailVerification_SecondaryMirror(t *testing.T) {
	store := newMapSecondaryStorage(true)
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	opts.SecondaryStorage = store
	opts.Verification.StoreInDatabase = true
	ctx := context.Background()

	token, err := createChangeEmailVerification(ctx, opts, "old@example.com", "new@example.com", "change-email-verification", time.Hour)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	row, stored, err := findChangeEmailVerificationRow(ctx, opts, token)
	if err != nil || row == nil {
		t.Fatalf("created row must resolve, got %+v/%v", row, err)
	}
	if stored == "" {
		t.Fatal("stored identifier must be reported")
	}
}

func TestCreateChangeEmailVerification_SecondaryOnlySkipsDB(t *testing.T) {
	store := newMapSecondaryStorage(true)
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	opts.SecondaryStorage = store
	ctx := context.Background()

	token, err := createChangeEmailVerification(ctx, opts, "old@example.com", "new@example.com", "change-email-verification", time.Hour)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	rows, _ := db.FindMany(ctx, "verification", nil, 0, 0, nil, nil)
	if len(rows) != 0 {
		t.Fatalf("secondary-only creation must skip the database, got %d rows", len(rows))
	}
	row, _, err := findChangeEmailVerificationRow(ctx, opts, token)
	if err != nil || row == nil {
		t.Fatalf("secondary row must resolve without the database, got %+v/%v", row, err)
	}
}

func TestCreateChangeEmailVerification_HashedIdentifier(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	opts.Verification.StoreIdentifier.Mode = types.StoreIdentifierHashed
	ctx := context.Background()

	token, err := createChangeEmailVerification(ctx, opts, "old@example.com", "new@example.com", "change-email-verification", time.Hour)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	plain := changeEmailIdentifier(token)
	if row, _ := db.FindOne(ctx, "verification", []types.Where{{Field: "identifier", Value: plain}}, nil); row != nil {
		t.Fatal("hashed mode must not store the plain identifier")
	}
	row, stored, err := findChangeEmailVerificationRow(ctx, opts, token)
	if err != nil || row == nil {
		t.Fatalf("hashed row must resolve with plain fallback, got %+v/%v", row, err)
	}
	if stored == plain {
		t.Fatal("stored identifier must be the hashed form")
	}
}

func TestCreateConsumeResetVerification_SecondaryOnly(t *testing.T) {
	store := newMapSecondaryStorage(true)
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	opts.SecondaryStorage = store
	ctx := context.Background()

	expires := time.Now().UTC().Add(time.Hour)
	if err := createResetVerification(ctx, opts, "tok-sec", "user-9", expires); err != nil {
		t.Fatalf("create: %v", err)
	}
	rows, _ := db.FindMany(ctx, "verification", nil, 0, 0, nil, nil)
	if len(rows) != 0 {
		t.Fatalf("secondary-only creation must skip the database, got %d rows", len(rows))
	}
	if !resetTokenValid(ctx, opts, "tok-sec") {
		t.Fatal("secondary row must validate without the database")
	}
	userID, _, errCode, _ := consumeResetPasswordToken(ctx, opts, "tok-sec")
	if errCode != "" || userID != "user-9" {
		t.Fatalf("secondary consume must win, got %q/%s", userID, errCode)
	}
	if resetTokenValid(ctx, opts, "tok-sec") {
		t.Fatal("consumed token must not validate")
	}
}

func TestConsumeResetPasswordToken_HashedIdentifier(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	opts.Verification.StoreIdentifier.Mode = types.StoreIdentifierHashed
	ctx := context.Background()

	expires := time.Now().UTC().Add(time.Hour)
	if err := createResetVerification(ctx, opts, "tok-hash", "user-1", expires); err != nil {
		t.Fatalf("create: %v", err)
	}
	if row, _ := db.FindOne(ctx, "verification", []types.Where{{Field: "identifier", Value: resetPasswordIdentifier("tok-hash")}}, nil); row != nil {
		t.Fatal("hashed mode must not store the plain identifier")
	}
	userID, _, errCode, _ := consumeResetPasswordToken(ctx, opts, "tok-hash")
	if errCode != "" || userID != "user-1" {
		t.Fatalf("hashed consume must win, got %q/%s", userID, errCode)
	}
}

func TestFindResetVerification_SweepHonorsDisableCleanup(t *testing.T) {
	newExpiredRow := func(t *testing.T, db types.Adapter, id string) {
		t.Helper()
		now := time.Now().UTC()
		if _, err := db.Create(context.Background(), "verification", map[string]any{
			"id": id, "identifier": "stale:" + id,
			"value": "user-1", "expiresAt": now.Add(-time.Hour),
			"createdAt": now, "updatedAt": now,
		}, nil); err != nil {
			t.Fatalf("create stale row: %v", err)
		}
	}

	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	newExpiredRow(t, db, "sweep-me")
	ctx := context.Background()
	if _, err := findResetVerification(ctx, opts, "missing"); err != nil {
		t.Fatalf("find: %v", err)
	}
	if row, _ := db.FindOne(ctx, "verification", []types.Where{{Field: "identifier", Value: "stale:sweep-me"}}, nil); row != nil {
		t.Fatal("database reads must sweep expired rows by default")
	}

	db2 := newParityMemAdapter()
	opts2 := parityTestOptions(db2)
	opts2.Verification.DisableCleanup = true
	newExpiredRow(t, db2, "keep-me")
	if _, err := findResetVerification(context.Background(), opts2, "missing"); err != nil {
		t.Fatalf("find: %v", err)
	}
	if row, _ := db2.FindOne(context.Background(), "verification", []types.Where{{Field: "identifier", Value: "stale:keep-me"}}, nil); row == nil {
		t.Fatal("DisableCleanup must preserve expired rows")
	}
}

func TestNullableStringUnmarshal(t *testing.T) {
	var absent struct {
		Image nullableString `json:"image,omitempty"`
	}
	if err := json.Unmarshal([]byte(`{}`), &absent); err != nil {
		t.Fatal(err)
	}
	if absent.Image.Set {
		t.Fatal("absent field must stay unset")
	}

	var nulled struct {
		Image nullableString `json:"image,omitempty"`
	}
	if err := json.Unmarshal([]byte(`{"image":null}`), &nulled); err != nil {
		t.Fatal(err)
	}
	if !nulled.Image.Set || nulled.Image.Value != nil {
		t.Fatalf("explicit null must record set-but-nil, got %+v", nulled.Image)
	}

	var valued struct {
		Image nullableString `json:"image,omitempty"`
	}
	if err := json.Unmarshal([]byte(`{"image":"https://example.com/u.png"}`), &valued); err != nil {
		t.Fatal(err)
	}
	if !valued.Image.Set || valued.Image.Value == nil || *valued.Image.Value != "https://example.com/u.png" {
		t.Fatalf("string value must record set value, got %+v", valued.Image)
	}
}

func TestSendResetPasswordMail_RequestPrecedence(t *testing.T) {
	opts := parityTestOptions(newParityMemAdapter())
	var order []string
	opts.EmailAndPassword.SendResetPassword = func(types.ResetPasswordData) error {
		order = append(order, "legacy")
		return nil
	}
	opts.EmailAndPassword.SendResetPasswordRequest = func(types.ResetPasswordData, *http.Request) error {
		order = append(order, "request")
		return nil
	}
	sendResetPasswordMail(context.Background(), opts, types.ResetPasswordData{})
	if len(order) != 1 || order[0] != "request" {
		t.Fatalf("request-aware variant must win, got %#v", order)
	}
}

func TestRunOnPasswordResetHook_RequestPrecedence(t *testing.T) {
	opts := parityTestOptions(newParityMemAdapter())
	var order []string
	opts.EmailAndPassword.OnPasswordReset = func(types.PasswordResetData) error {
		order = append(order, "legacy")
		return nil
	}
	opts.EmailAndPassword.OnPasswordResetRequest = func(types.PasswordResetData, *http.Request) error {
		order = append(order, "request")
		return nil
	}
	if err := runOnPasswordResetHook(context.Background(), opts, types.PasswordResetData{}); err != nil {
		t.Fatalf("hook: %v", err)
	}
	if len(order) != 1 || order[0] != "request" {
		t.Fatalf("request-aware variant must win, got %#v", order)
	}
}

func TestConsumeSecondaryVerification_RoundTrip(t *testing.T) {
	store := newMapSecondaryStorage(true)
	opts := parityTestOptions(newParityMemAdapter())
	opts.SecondaryStorage = store

	identifier := "change-email:tok-roundtrip"
	row := map[string]any{
		"id": "v9", "identifier": identifier, "value": "{}",
		"expiresAt": time.Now().UTC().Add(time.Hour),
		"createdAt": time.Now().UTC(), "updatedAt": time.Now().UTC(),
	}
	if err := writeSecondaryVerification(opts, identifier, row); err != nil {
		t.Fatal(err)
	}
	consumed, err := consumeSecondaryVerification(opts, identifier)
	if err != nil || consumed == nil {
		t.Fatalf("consume must win, got %+v/%v", consumed, err)
	}
	if _, ok := consumed["expiresAt"].(time.Time); !ok {
		t.Fatalf("dates must revive to time.Time, got %#v", consumed["expiresAt"])
	}
	if again, _ := consumeSecondaryVerification(opts, identifier); again != nil {
		t.Fatal("consume must be single-use")
	}
}

func TestChangeEmailDisabledCode(t *testing.T) {
	if got := types.StatusForCode(types.ErrChangeEmailDisabled); got != http.StatusBadRequest {
		t.Fatalf("CHANGE_EMAIL_DISABLED must stay 400, got %d", got)
	}
	if !strings.Contains(types.ErrChangeEmailDisabled, "CHANGE_EMAIL") {
		t.Fatalf("unexpected code %q", types.ErrChangeEmailDisabled)
	}
}
