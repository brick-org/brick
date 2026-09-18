package crypto

import (
	"strings"
	"testing"
	"time"
)

func TestMakeSignatureFixedVector(t *testing.T) {
	// Cross-language known answer: standard-base64 HMAC-SHA256 (upstream
	// makeSignature returns btoa(...) — padded standard base64).
	const want = "97yD9DBThCSxMpjmqm+xQ+9NWaFJRhdZl0edvC0aPNg="
	if got := MakeSignature("The quick brown fox jumps over the lazy dog", "key"); got != want {
		t.Fatalf("MakeSignature = %q, want %q", got, want)
	}
	if !VerifySignature("The quick brown fox jumps over the lazy dog", want, []string{"old", "key"}) {
		t.Fatal("rotation verify failed")
	}
	if VerifySignature("The quick brown fox jumps over the lazy dog", want, []string{"wrong"}) {
		t.Fatal("wrong secret verified")
	}
}

func TestGenerateTokenWithExpiry(t *testing.T) {
	future := time.Now().Add(time.Hour).Truncate(time.Second)
	token, err := GenerateTokenWithExpiry("secret", "User@Example.com", future)
	if err != nil {
		t.Fatal(err)
	}
	email, err := VerifyTokenAny([]string{"old", "secret"}, token)
	if err != nil || email != "user@example.com" {
		t.Fatalf("explicit-expiry verify = %q, %v", email, err)
	}
	// Wire format is unchanged (two-part HMAC like GenerateToken).
	if len(strings.Split(token, ".")) != 2 {
		t.Fatalf("token format changed: %q", token)
	}
	past, err := GenerateTokenWithExpiry("secret", "user@example.com", time.Now().Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyToken("secret", past); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired error = %v", err)
	}
}

func TestEncryptedTokenRoundTripRotationAndTampering(t *testing.T) {
	token, err := GenerateEncryptedToken("current", "User@Example.com", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Upstream XChaCha20 wire format: bare hex, no HMAC dot separator.
	if strings.Contains(token, ".") {
		t.Fatalf("encrypted token must be bare hex, got %q", token)
	}
	for _, c := range token {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("encrypted token must be bare hex, got %q", token)
		}
	}
	email, err := VerifyEncryptedTokenAny([]string{"old", "current"}, token)
	if err != nil || email != "user@example.com" {
		t.Fatalf("rotation verify = %q, %v", email, err)
	}
	if _, err := VerifyEncryptedToken("current", token); err != nil {
		t.Fatalf("single-secret verify: %v", err)
	}
	// Tampered, wrong-secret, and malformed inputs fail closed.
	// Flip the first hex char to a guaranteed-different value (a fixed
	// "0" prefix flakes 1/16 when the token already starts with "0").
	tamperChar := byte('0')
	if token[0] == '0' {
		tamperChar = '1'
	}
	tampered := string([]byte{tamperChar}) + token[1:]
	if _, err := VerifyEncryptedToken("current", tampered); err == nil {
		t.Error("tampered token verified")
	}
	if _, err := VerifyEncryptedToken("wrong", token); err == nil {
		t.Error("wrong secret verified")
	}
	legacy, err := GenerateToken("current", "user@example.com", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyEncryptedToken("current", legacy); err == nil {
		t.Error("HMAC token verified as encrypted token (formats must stay distinct)")
	}
	if _, err := VerifyEncryptedTokenAny(nil, token); err == nil {
		t.Error("empty secrets verified")
	}
	if _, err := GenerateEncryptedToken("", "user@example.com", time.Hour); err == nil {
		t.Error("empty secret must be rejected")
	}
}

func TestEncryptedTokenExpiry(t *testing.T) {
	token, err := GenerateEncryptedToken("secret", "user@example.com", -time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyEncryptedToken("secret", token); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired error = %v", err)
	}
	fresh, err := GenerateEncryptedToken("secret", "user@example.com", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyEncryptedToken("secret", fresh); err != nil {
		t.Fatalf("fresh token rejected: %v", err)
	}
}
