package crypto

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestPasswordHashMatchesBetterAuthFormat(t *testing.T) {
	hash, err := HashPassword("mySecurePassword123!")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	parts := strings.Split(hash, ":")
	if len(parts) != 2 || len(parts[0]) != 32 || len(parts[1]) != 128 {
		t.Fatalf("hash = %q, want 16-byte salt and 64-byte key in hex", hash)
	}
	if !VerifyPassword(hash, "mySecurePassword123!") {
		t.Fatal("correct password did not verify")
	}
	if VerifyPassword(hash, "wrongPassword456!") {
		t.Fatal("wrong password verified")
	}
}

func TestPasswordHashRandomSalt(t *testing.T) {
	a, err := HashPassword("samePassword123!")
	if err != nil {
		t.Fatal(err)
	}
	b, err := HashPassword("samePassword123!")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two hashes must use different salts")
	}
}

func TestPasswordNFKCCompatibility(t *testing.T) {
	// U+212B ANGSTROM SIGN and U+00C5 LATIN CAPITAL A WITH RING normalize alike.
	hash, err := HashPassword("pass\u212Bword")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(hash, "pass\u00C5word") {
		t.Fatal("NFKC-equivalent password did not verify")
	}
}

func TestPasswordVerifiesBetterAuthScryptVector(t *testing.T) {
	// Generated with Better Auth v1.7.5 parameters and the fixed 16-byte salt.
	hash := "000102030405060708090a0b0c0d0e0f:a19e0608dfb1eddd747ebea06aa44ba8e5ce829ab792340ee8c6a4665d850f912e26dae00afd3f9f51fd1320dfa27c9fe1288a527494da28d7e2ec37a9c4fbde"
	if !VerifyPassword(hash, "better-auth-dummy-password") {
		t.Fatal("Better Auth-compatible scrypt vector did not verify")
	}
}

func TestPasswordVerifiesLegacyBcrypt(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("legacy"), 4)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(string(hash), "legacy") {
		t.Fatal("legacy Go bcrypt hash did not verify")
	}
}

func TestPasswordRejectsMalformedHash(t *testing.T) {
	for _, hash := range []string{"", "no-colon", "00:00", "zz:zz", "a:b:c"} {
		if VerifyPassword(hash, "password") {
			t.Errorf("malformed hash %q verified", hash)
		}
	}
}
