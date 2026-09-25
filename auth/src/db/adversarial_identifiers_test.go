package db

// AUTH-V10-02 — adversarial and cross-language conformance (tests only).

import (
	"strings"
	"sync"
	"testing"
)

// Identifier validation under burst: hostile identifiers keep rejecting, clean ones keep passing.
func TestAdversarial_ValidateIdentifierBurst(t *testing.T) {
	valid := []string{"user", "session", "sch.tab", "_x", "abc123", "A_Z_09"}
	invalid := []string{
		"", "0a", "a b", "a-b", "a\"b", "a'b", "a;b", "a.b.c", ".a", "a.",
		"sch..tab", "a\nb", "a\x00b", "tab; DROP TABLE x;--", `"quoted"`,
		strings.Repeat("x", 1<<20) + "!",
	}
	var wg sync.WaitGroup
	errs := make(chan string, 256)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				for _, name := range valid {
					if err := ValidateIdentifier(name); err != nil {
						errs <- "valid identifier rejected under burst"
						return
					}
				}
				for _, name := range invalid {
					if err := ValidateIdentifier(name); err == nil {
						errs <- "hostile identifier accepted under burst"
						return
					}
				}
				_ = NormalizeConnector("OR")
				_ = NormalizeWhereMode("insensitive")
				_ = NormalizeSortDirection("desc")
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
}

// FuzzWave10_ValidateIdentifierStrict fuzzes the identifier trust boundary against the reference predicate.
func FuzzWave10_ValidateIdentifierStrict(f *testing.F) {
	f.Add("user")
	f.Add("sch.tab")
	f.Add("")
	f.Add("a; DROP TABLE x;--")
	f.Add("a\x00b")
	f.Add(strings.Repeat("x", 600))
	f.Fuzz(func(t *testing.T, name string) {
		if len(name) > 512 {
			t.Skip("over wave10 512B cap")
		}
		err := ValidateIdentifier(name)
		want := referenceValidateIdentifier(name)
		if (err == nil) != want {
			t.Fatalf("ValidateIdentifier(%q) = %v, reference = %v", name, err, want)
		}
	})
}
