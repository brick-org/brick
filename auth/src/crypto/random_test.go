package crypto

import (
	"strings"
	"testing"
)

func TestGenerateIDLengthAlphabetAndUniqueness(t *testing.T) {
	seen := make(map[string]struct{}, 100)
	for range 100 {
		id := GenerateID()
		if len(id) != 32 {
			t.Fatalf("len(GenerateID()) = %d, want 32", len(id))
		}
		for _, char := range id {
			if !strings.ContainsRune(idAlphabet, char) {
				t.Fatalf("GenerateID contains %q outside Better Auth alphabet", char)
			}
		}
		if _, duplicate := seen[id]; duplicate {
			t.Fatalf("duplicate random ID %q", id)
		}
		seen[id] = struct{}{}
	}
}

func TestGenerateRandomStringLength(t *testing.T) {
	for _, n := range []int{1, 32, 64} {
		s := GenerateRandomString(n)
		if len(s) != n {
			t.Fatalf("len(GenerateRandomString(%d)) = %d", n, len(s))
		}
	}
}

func TestGenerateCodeChallengeMatchesS256(t *testing.T) {
	if got := GenerateCodeChallenge("verifier"); got != S256Challenge("verifier") {
		t.Fatalf("GenerateCodeChallenge diverged from S256Challenge")
	}
}
