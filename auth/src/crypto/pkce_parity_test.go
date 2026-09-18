package crypto

import (
	"strings"
	"testing"
)

func TestPKCES256RFC7636Vector(t *testing.T) {
	// RFC 7636 Appendix B cross-language vector.
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const want = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := S256Challenge(verifier); got != want {
		t.Fatalf("S256Challenge = %q, want %q", got, want)
	}
	if got := GenerateCodeChallenge(verifier); got != want {
		t.Fatalf("GenerateCodeChallenge = %q, want %q", got, want)
	}
	if !VerifyPKCE(verifier, want) {
		t.Fatal("RFC 7636 verifier did not verify")
	}
}

func TestPKCERejectsNonS256(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	for _, bad := range []string{
		"",
		verifier, // plain mode: challenge == verifier must NOT verify
		"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cMx",
		"e9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", // case flip
	} {
		if VerifyPKCE(verifier, bad) {
			t.Errorf("VerifyPKCE accepted non-S256 challenge %q", bad)
		}
	}
	if VerifyPKCE("other-verifier", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM") {
		t.Error("wrong verifier accepted")
	}
	// Random verifiers round-trip through S256 only.
	v := GenerateRandomString(64)
	if !VerifyPKCE(v, S256Challenge(v)) {
		t.Fatal("S256 round trip failed")
	}
	if strings.Contains(S256Challenge(v), "=") {
		t.Fatal("challenge must be unpadded base64url")
	}
}
