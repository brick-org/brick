package crypto

// v1 ports of password.test.ts (scrypt N=16384 r=16 p=1 dkLen=64, hex salt, NFKC).

import (
	"strings"
	"testing"
)

func TestV1_PasswordLong(t *testing.T) {
	password := strings.Repeat("a", 1000)
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(hash, password) {
		t.Fatal("1000-char password did not verify")
	}
}

func TestV1_PasswordCaseSensitive(t *testing.T) {
	password := "CaseSensitivePassword123!"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyPassword(hash, strings.ToLower(password)) {
		t.Error("lowercased password verified")
	}
	if VerifyPassword(hash, strings.ToUpper(password)) {
		t.Error("uppercased password verified")
	}
	if !VerifyPassword(hash, password) {
		t.Error("exact password did not verify")
	}
}

func TestV1_PasswordUnicode(t *testing.T) {
	for _, password := range []string{
		"пароль123!",
		"비밀번호🔑密码🔒パスワード",
	} {
		hash, err := HashPassword(password)
		if err != nil {
			t.Fatalf("%q: %v", password, err)
		}
		if !VerifyPassword(hash, password) {
			t.Errorf("%q did not verify", password)
		}
	}
}

func TestV1_PasswordEmptyAndVeryLong(t *testing.T) {
	// Same scrypt params as @noble/hashes.
	for _, password := range []string{"", strings.Repeat("x", 10000)} {
		hash, err := HashPassword(password)
		if err != nil {
			t.Fatalf("len %d: %v", len(password), err)
		}
		if !VerifyPassword(hash, password) {
			t.Errorf("len %d did not verify", len(password))
		}
		if VerifyPassword(hash, password+"!") {
			t.Errorf("len %d: wrong password verified", len(password))
		}
	}
}

func TestV1_PasswordRejectsWrongAgainstStoredHash(t *testing.T) {
	hash, err := HashPassword("ExistingUser123!")
	if err != nil {
		t.Fatal(err)
	}
	if VerifyPassword(hash, "WrongPassword!") {
		t.Error("wrong password verified against stored hash")
	}
	if !VerifyPassword(hash, "ExistingUser123!") {
		t.Error("stored hash did not verify")
	}
}
