package routes

import (
	"context"
	"testing"
	"time"

	"github.com/brick-org/brick/auth/src/crypto"
	"github.com/brick-org/brick/auth/src/types"
)

func parityCreateResetRow(t *testing.T, db types.Adapter, token, userID string, ttl time.Duration) {
	t.Helper()
	now := time.Now().UTC()
	if _, err := db.Create(context.Background(), "verification", map[string]any{
		"id": "ver-" + token, "identifier": resetPasswordIdentifier(token),
		"value": userID, "expiresAt": now.Add(ttl),
		"createdAt": now, "updatedAt": now,
	}, nil); err != nil {
		t.Fatalf("create reset row: %v", err)
	}
}

func TestConsumeResetPasswordToken_SingleUse(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)

	parityCreateResetRow(t, db, "tok-single", "user-1", time.Hour)
	userID, _, errCode, _ := consumeResetPasswordToken(context.Background(), opts, "tok-single")
	if errCode != "" || userID != "user-1" {
		t.Fatalf("first consume must win with user-1, got %q/%s", userID, errCode)
	}
	if _, _, errCode, status := consumeResetPasswordToken(context.Background(), opts, "tok-single"); errCode != types.ErrInvalidToken || status != 400 {
		t.Fatalf("second consume must be INVALID_TOKEN/400, got %s/%d", errCode, status)
	}
	row, _ := db.FindOne(context.Background(), "verification", []types.Where{{Field: "identifier", Value: resetPasswordIdentifier("tok-single")}}, nil)
	if row != nil {
		t.Fatal("consumed row must be deleted")
	}
}

func TestConsumeResetPasswordToken_ExpiredRowDeletedAndRejected(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)

	parityCreateResetRow(t, db, "tok-old", "user-1", -time.Hour)
	if _, _, errCode, _ := consumeResetPasswordToken(context.Background(), opts, "tok-old"); errCode != types.ErrInvalidToken {
		t.Fatalf("expired token must be INVALID_TOKEN, got %s", errCode)
	}
	row, _ := db.FindOne(context.Background(), "verification", []types.Where{{Field: "identifier", Value: resetPasswordIdentifier("tok-old")}}, nil)
	if row != nil {
		t.Fatal("expired row must be cleaned up on consume")
	}
}

func TestConsumeResetPasswordToken_LegacyHMACFallback(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)

	legacy, err := crypto.GenerateToken(opts.CurrentSecret(), "legacy@example.com", time.Hour)
	if err != nil {
		t.Fatalf("generate legacy token: %v", err)
	}
	userID, email, errCode, _ := consumeResetPasswordToken(context.Background(), opts, legacy)
	if errCode != "" || userID != "" || email != "legacy@example.com" {
		t.Fatalf("legacy token must fall back to email, got %q/%q/%s", userID, email, errCode)
	}
}

func TestConsumeResetPasswordToken_LegacyRotationFallback(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)
	opts.Secrets = []types.Secret{{Version: 2, Value: "new-secret"}, {Version: 1, Value: opts.Secret}}

	legacy, err := crypto.GenerateToken("parity-secret", "rotated@example.com", time.Hour)
	if err != nil {
		t.Fatalf("generate legacy token: %v", err)
	}
	_, email, errCode, _ := consumeResetPasswordToken(context.Background(), opts, legacy)
	if errCode != "" || email != "rotated@example.com" {
		t.Fatalf("retained secret must still verify legacy token, got %q/%s", email, errCode)
	}
}

func TestConsumeResetPasswordToken_EmptyValueRejected(t *testing.T) {
	db := newParityMemAdapter()
	opts := parityTestOptions(db)

	now := time.Now().UTC()
	if _, err := db.Create(context.Background(), "verification", map[string]any{
		"id": "ver-empty", "identifier": resetPasswordIdentifier("tok-empty"),
		"value": "", "expiresAt": now.Add(time.Hour),
		"createdAt": now, "updatedAt": now,
	}, nil); err != nil {
		t.Fatalf("create reset row: %v", err)
	}
	if _, _, errCode, _ := consumeResetPasswordToken(context.Background(), opts, "tok-empty"); errCode != types.ErrInvalidToken {
		t.Fatalf("empty value must be INVALID_TOKEN, got %s", errCode)
	}
}

func TestResetPasswordIdentifier(t *testing.T) {
	if got := resetPasswordIdentifier("abc"); got != "reset-password:abc" {
		t.Fatalf("unexpected identifier %q", got)
	}
	if !isVerificationLive(time.Now().UTC().Add(time.Hour)) {
		t.Fatal("future expiry must be live")
	}
	if isVerificationLive(time.Now().UTC().Add(-time.Hour)) {
		t.Fatal("past expiry must not be live")
	}
}
