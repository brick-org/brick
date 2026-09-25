package types

import (
	"strings"
	"testing"
)

// TestDPoPOptionDefaults pins the upstream oauth-provider plugin defaults
func TestDPoPOptionDefaults(t *testing.T) {
	var opts DPoPOptions
	if got := opts.EffectiveProofMaxAgeSeconds(); got != DefaultDPoPProofMaxAgeSeconds {
		t.Errorf("EffectiveProofMaxAgeSeconds() = %d, want %d", got, DefaultDPoPProofMaxAgeSeconds)
	}
	if DefaultDPoPProofMaxAgeSeconds != 300 {
		t.Errorf("DefaultDPoPProofMaxAgeSeconds = %d, want 300 (upstream default)", DefaultDPoPProofMaxAgeSeconds)
	}
	algs := opts.EffectiveSigningAlgorithms()
	want := []string{"EdDSA", "ES256", "ES512", "PS256", "RS256"}
	if len(algs) != len(want) {
		t.Fatalf("EffectiveSigningAlgorithms() = %v, want %v", algs, want)
	}
	for i := range want {
		if algs[i] != want[i] {
			t.Fatalf("EffectiveSigningAlgorithms() = %v, want %v", algs, want)
		}
	}
}

// TestDPoPOptionExplicitValues ensures explicit integrator values survive:
// upstream applies defaults only when the option is unset (?? semantics), so
func TestDPoPOptionExplicitValues(t *testing.T) {
	opts := DPoPOptions{ProofMaxAgeSeconds: 60, SigningAlgorithms: []string{"ES256"}}
	if got := opts.EffectiveProofMaxAgeSeconds(); got != 60 {
		t.Errorf("EffectiveProofMaxAgeSeconds() = %d, want 60", got)
	}
	if got := opts.EffectiveSigningAlgorithms(); len(got) != 1 || got[0] != "ES256" {
		t.Errorf("EffectiveSigningAlgorithms() = %v, want [ES256]", got)
	}

	empty := DPoPOptions{SigningAlgorithms: []string{}}
	if got := empty.EffectiveSigningAlgorithms(); got == nil || len(got) != 0 {
		t.Errorf("explicit empty SigningAlgorithms = %v, want empty (fail closed)", got)
	}
	negative := DPoPOptions{ProofMaxAgeSeconds: -5}
	if got := negative.EffectiveProofMaxAgeSeconds(); got != DefaultDPoPProofMaxAgeSeconds {
		t.Errorf("negative ProofMaxAgeSeconds = %d, want default %d", got, DefaultDPoPProofMaxAgeSeconds)
	}
}

// TestValidDPoPJkt pins the upstream dpop_jkt shape (base64url-encoded
func TestValidDPoPJkt(t *testing.T) {
	valid := strings.Repeat("aB3_-", 8) + "abc" // 43 chars from [A-Za-z0-9_-]
	if len(valid) != 43 {
		t.Fatalf("fixture length = %d, want 43", len(valid))
	}
	if !ValidDPoPJkt(valid) {
		t.Errorf("ValidDPoPJkt(%q) = false, want true", valid)
	}
	for _, bad := range []string{
		"",
		strings.Repeat("a", 42),
		strings.Repeat("a", 44),
		strings.Repeat("a", 42) + "=",
		strings.Repeat("a", 42) + "+",
		strings.Repeat("a", 42) + "/",
		strings.Repeat("a", 42) + " ",
		"!!!invalid!!!invalid!!!invalid!!!invalid!!!",
	} {
		if ValidDPoPJkt(bad) {
			t.Errorf("ValidDPoPJkt(%q) = true, want false", bad)
		}
	}
}
