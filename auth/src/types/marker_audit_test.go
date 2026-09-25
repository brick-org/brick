package types

// marker_audit_test.go: upstream conformance (Better Auth v1.7.5).

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// pendingMarkerLedger is the full AUTH-R5-02 reconciled set (7 markers).
var excludedMarkerLedger = []string{
	"oauth.go|TokenEndpointAuth|W10-01",
	"oauth.go|ClientAssertionProvider|W10-01",
	"oauth.go|TokenAuthMethodProvider|W10-01",
	"oauth.go|DiscoveryProvider|W10-01",
	"oauth.go|PrimaryClientID|W10-01",
	"auth.go|AccountOptions.StoreAccountCookie|W10-04",
	"auth.go|CrossSubDomainCookiesOptions.AdditionalCookies|W10-05",
}

// TestExcludedMarkerLedger pins the exclusion set. Any new
func TestExcludedMarkerLedger(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test file")
	}
	dir := filepath.Dir(thisFile)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	type found struct {
		file   string
		line   int
		symbol string
		owner  string
	}
	var got []found
	var gotPending []found
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		if strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(raw), "\n")
		currentSymbol := ""
		for i, ln := range lines {
			trimmed := strings.TrimSpace(ln)
			if sym := declSymbol(trimmed); sym != "" {
				currentSymbol = sym
			}
			if !strings.Contains(ln, "Runtime: pending") && !strings.Contains(ln, "Runtime: excluded") {
				continue
			}
			if strings.Contains(ln, "Runtime: pending") {
				gotPending = append(gotPending, found{file: e.Name(), line: i + 1, symbol: currentSymbol, owner: pendingOwner(ln)})
				continue
			}
			owner := excludedOwner(ln)
			sym := currentSymbol
			if next := nextFieldSymbol(lines, i); next != "" {
				sym = next
			}
			got = append(got, found{file: e.Name(), line: i + 1, symbol: sym, owner: owner})
		}
	}
	if len(gotPending) != 0 {
		t.Fatalf("Runtime: pending markers must be zero (Wave-10 closure); found %d.\n"+
			"Wire the option (`Runtime: wired:<file:line>`) or file an intentional "+
			"exclusion (`Runtime: excluded(W10-XX)` + ledger entry).",
			len(gotPending))
		for _, f := range gotPending {
			t.Logf("  %s:%d %s pending:%s", f.file, f.line, f.symbol, f.owner)
		}
	}
	if len(got) != len(excludedMarkerLedger) {
		t.Fatalf("excluded marker count = %d, want %d (ledger).\n"+
			"New exclusions require a ledger entry; "+
			"wired options must flip to `Runtime: wired:<file:line>`.\nFound:",
			len(got), len(excludedMarkerLedger))
		for _, f := range got {
			t.Logf("  %s:%d %s excluded:%s", f.file, f.line, f.symbol, f.owner)
		}
	}
	want := map[string]bool{}
	for _, k := range excludedMarkerLedger {
		want[k] = true
	}
	for _, f := range got {
		matched := false
		for k := range want {
			parts := strings.SplitN(k, "|", 3)
			if len(parts) != 3 {
				continue
			}
			if parts[0] == f.file && ledgerSymbolMatch(parts[1], f.symbol) && strings.HasPrefix(f.owner, ownerPrefix(parts[2])) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("unledgered excluded marker %s:%d symbol %q owner %q — add a ledger entry",
				f.file, f.line, f.symbol, f.owner)
		}
	}
}

// declSymbol extracts a type/func name from a declaration line, or "".
func declSymbol(trimmed string) string {
	for _, kw := range []string{"type ", "func "} {
		if !strings.HasPrefix(trimmed, kw) {
			continue
		}
		rest := strings.TrimPrefix(trimmed, kw)
		if strings.HasPrefix(rest, "(") {
			if idx := strings.Index(rest, ")"); idx != -1 {
				rest = strings.TrimSpace(rest[idx+1:])
			}
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			return ""
		}
		name := fields[0]
		name = strings.Trim(name, "(*)")
		if idx := strings.Index(name, "("); idx != -1 {
			name = name[:idx]
		}
		return name
	}
	return ""
}

// nextFieldSymbol returns the struct field or type name declared within the
// next few lines after a marker comment (comment-above-field style, where
// the marker comment itself may span several // lines).
func nextFieldSymbol(lines []string, markerIdx int) string {
	for j := markerIdx + 1; j < len(lines) && j <= markerIdx+8; j++ {
		trimmed := strings.TrimSpace(lines[j])
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}
		if sym := declSymbol(trimmed); sym != "" {
			return sym
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 {
			name := strings.Trim(fields[0], "(*)")
			if name == "" || strings.ContainsAny(name, "(){};=*") {
				continue
			}
			if c := name[0]; c >= 'A' && c <= 'Z' {
				return name
			}
		}
		break
	}
	return ""
}

// pendingOwner extracts the text after "pending:" on a marker line.
func pendingOwner(line string) string {
	idx := strings.Index(line, "pending:")
	if idx == -1 {
		return ""
	}
	rest := strings.TrimSpace(line[idx+len("pending:"):])
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return ""
	}
	return strings.Trim(fields[0], "(),")
}

// excludedOwner extracts the W10-XX id from a
// "Runtime: excluded(W10-XX):..." marker line.
func excludedOwner(line string) string {
	idx := strings.Index(line, "excluded(")
	if idx == -1 {
		return ""
	}
	rest := line[idx+len("excluded("):]
	if end := strings.Index(rest, ")"); end != -1 {
		return strings.TrimSpace(rest[:end])
	}
	return ""
}

// ownerPrefix strips a trailing :line suffix so line shifts do not break
// the ledger (e.g. "auth/index.go:281" -> "auth/index.go").
func ownerPrefix(ledgerOwner string) string {
	if i := strings.LastIndex(ledgerOwner, ":"); i != -1 {
		if ledgerOwner[i+1:] != "" && ledgerOwner[i+1] >= '0' && ledgerOwner[i+1] <= '9' {
			return ledgerOwner[:i]
		}
	}
	return ledgerOwner
}

// ledgerSymbolMatch allows "Parent.Field" ledger symbols to match a bare
// field symbol found by the scanner.
func ledgerSymbolMatch(ledger, found string) bool {
	if ledger == found {
		return true
	}
	if idx := strings.LastIndex(ledger, "."); idx != -1 {
		return ledger[idx+1:] == found
	}
	return false
}
