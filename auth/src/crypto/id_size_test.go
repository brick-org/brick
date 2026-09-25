package crypto

import (
	"strings"
	"testing"
)

func TestGenerateIDWithSize(t *testing.T) {
	if DefaultIDSize != 32 {
		t.Fatalf("DefaultIDSize = %d, want 32 (upstream generateId default)", DefaultIDSize)
	}
	// Arbitrary lengths use the established alphabet.
	for _, n := range []int{1, 8, 16, 32, 64, 128} {
		id := GenerateIDWithSize(n)
		if len(id) != n {
			t.Fatalf("GenerateIDWithSize(%d) len = %d", n, len(id))
		}
		for _, char := range id {
			if !strings.ContainsRune(idAlphabet, char) {
				t.Fatalf("GenerateIDWithSize(%d) contains %q outside the alphabet", n, char)
			}
		}
	}
	// Upstream `size || 32`: non-positive sizes fall back to the default.
	if len(GenerateIDWithSize(0)) != 32 || len(GenerateIDWithSize(-5)) != 32 {
		t.Fatal("non-positive size must fall back to 32")
	}
	if len(GenerateID()) != 32 {
		t.Fatal("GenerateID default length changed")
	}
}

func TestGenerateRandomStringNeverPanics(t *testing.T) {
	// Negative lengths previously panicked in make(); they now yield "".
	if GenerateRandomString(0) != "" || GenerateRandomString(-1) != "" {
		t.Fatal("non-positive lengths must return empty strings")
	}
	s := GenerateRandomString(24)
	if len(s) != 24 {
		t.Fatalf("len = %d, want 24", len(s))
	}
}
