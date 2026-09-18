package crypto

import (
	"strings"
	"testing"
	"time"
)

func TestCreateEmailVerificationTokenRoundTrip(t *testing.T) {
	token, err := CreateEmailVerificationToken("secret", "User@Example.com", "", 3600, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Compact JWT shape with HS256 header.
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token is not a compact JWT: %q", token)
	}
	payload, err := VerifyEmailVerificationToken("secret", token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if payload.Email != "user@example.com" {
		t.Fatalf("email = %q (must be lowercased like upstream)", payload.Email)
	}
	if payload.UpdateTo != "" || payload.RequestType != "" {
		t.Fatalf("unexpected payload: %+v", payload)
	}
	if time.Until(payload.ExpiresAt) < 59*time.Minute {
		t.Fatalf("expiry too short: %v", payload.ExpiresAt)
	}
}

func TestCreateEmailVerificationTokenUpdateToAndExtras(t *testing.T) {
	token, err := CreateEmailVerificationToken("secret", "user@example.com", "New@Example.com", 0, map[string]any{
		"requestType": "change-email-verification",
		"custom":      "kept",
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := VerifyEmailVerificationToken("secret", token)
	if err != nil {
		t.Fatal(err)
	}
	if payload.UpdateTo != "new@example.com" {
		t.Fatalf("updateTo = %q (must be lowercased)", payload.UpdateTo)
	}
	if payload.RequestType != "change-email-verification" {
		t.Fatalf("requestType = %q", payload.RequestType)
	}
	if payload.Extra["custom"] != "kept" {
		t.Fatalf("extra = %v", payload.Extra)
	}
	// Zero expiry selects the upstream 3600s default.
	if time.Until(payload.ExpiresAt) < 59*time.Minute {
		t.Fatalf("default expiry too short: %v", payload.ExpiresAt)
	}
}

func TestVerifyEmailVerificationTokenRotationAndTampering(t *testing.T) {
	token, err := CreateEmailVerificationToken("current", "user@example.com", "", 3600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyEmailVerificationTokenAny([]string{"old", "current"}, token); err != nil {
		t.Fatalf("rotation verify: %v", err)
	}
	if _, err := VerifyEmailVerificationTokenAny([]string{"wrong"}, token); err == nil {
		t.Fatal("wrong secret verified")
	}
	parts := strings.Split(token, ".")
	for _, tampered := range []string{
		"x" + parts[0][1:] + "." + parts[1] + "." + parts[2],
		parts[0] + "." + parts[1] + ".x" + parts[2][1:],
		token + "a",
		"not-a-jwt",
		"",
	} {
		if _, err := VerifyEmailVerificationToken("current", tampered); err == nil {
			t.Errorf("tampered token verified: %q", tampered)
		}
	}
	// Cross-algorithm confusion: legacy custom-HMAC tokens must NOT verify
	// as JWTs.
	legacy, err := GenerateToken("current", "user@example.com", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyEmailVerificationToken("current", legacy); err == nil {
		t.Error("legacy token verified as JWT")
	}
}

func TestVerifyEmailVerificationTokenExpiry(t *testing.T) {
	token, err := CreateEmailVerificationToken("secret", "user@example.com", "", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	// A 1s-lived token verifies immediately...
	if _, err := VerifyEmailVerificationToken("secret", token); err != nil {
		t.Fatalf("fresh token rejected: %v", err)
	}
	expired, err := CreateEmailVerificationToken("secret", "user@example.com", "", -60, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyEmailVerificationToken("secret", expired); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired error = %v", err)
	}
}

func TestVerifyEmailTokenWithFallback(t *testing.T) {
	jwtToken, err := CreateEmailVerificationToken("secret", "User@Example.com", "", 3600, nil)
	if err != nil {
		t.Fatal(err)
	}
	legacyToken, err := GenerateToken("secret", "legacy@example.com", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	email, err := VerifyEmailTokenWithFallback([]string{"secret"}, jwtToken)
	if err != nil || email != "user@example.com" {
		t.Fatalf("jwt fallback = %q, %v", email, err)
	}
	email, err = VerifyEmailTokenWithFallback([]string{"secret"}, legacyToken)
	if err != nil || email != "legacy@example.com" {
		t.Fatalf("legacy fallback = %q, %v", email, err)
	}
	if _, err := VerifyEmailTokenWithFallback([]string{"secret"}, "garbage"); err == nil {
		t.Fatal("garbage verified")
	}
	if _, err := VerifyEmailTokenWithFallback(nil, jwtToken); err == nil {
		t.Fatal("empty secrets verified")
	}
}
