package crypto

import (
	"strings"
	"testing"
	"time"
)

func TestTokenRoundTripRotationAndTampering(t *testing.T) {
	token, err := GenerateToken("current", "User@Example.com", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	email, err := VerifyTokenAny([]string{"old", "current"}, token)
	if err != nil || email != "user@example.com" {
		t.Fatalf("VerifyTokenAny = %q, %v", email, err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		t.Fatalf("token format = %q", token)
	}
	for _, tampered := range []string{
		flipFirstChar(parts[0]) + "." + parts[1],
		parts[0] + "." + flipFirstChar(parts[1]),
	} {
		if _, err := VerifyToken("current", tampered); err == nil {
			t.Errorf("tampered token verified: %q", tampered)
		}
	}
}

// Deterministic first-char flip (old "x"-prefix flaked ~1/64).
func flipFirstChar(s string) string {
	if s == "" {
		return "x"
	}
	if s[0] == 'x' {
		return "y" + s[1:]
	}
	return "x" + s[1:]
}

func TestTokenExpiryAndMalformedInput(t *testing.T) {
	expired, err := GenerateToken("secret", "user@example.com", -time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyToken("secret", expired); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired token error = %v", err)
	}
	for _, token := range []string{"", "nodot", "a.b.c", "!!!.sig"} {
		if _, err := VerifyToken("secret", token); err == nil {
			t.Errorf("malformed token %q verified", token)
		}
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	a, err := EncryptString("secret", "plaintext")
	if err != nil {
		t.Fatal(err)
	}
	b, err := EncryptString("secret", "plaintext")
	if err != nil {
		t.Fatal(err)
	}
	if a == b || !strings.HasPrefix(a, "$brick$") {
		t.Fatal("encryption must use random nonces and the format prefix")
	}
	plain, err := DecryptString("secret", a)
	if err != nil || plain != "plaintext" {
		t.Fatalf("DecryptString = %q, %v", plain, err)
	}
	if _, err := DecryptString("wrong", a); err == nil {
		t.Fatal("wrong secret decrypted ciphertext")
	}
}
