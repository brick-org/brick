package auth_test

// parity_ledger_test.go: upstream conformance (Better Auth v1.7.5).

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	auth "github.com/brick-org/brick/auth/src"
)

const (
	ledgerPinnedVersion = "1.7.5"
	ledgerPinnedCommit  = "5468e6bfcdff799848537cf5ad06ebab15aad9dd"
)

// ledgerCoreRoutes is the 30-path core route catalog (basePath-relative,
var ledgerCoreRoutes = []string{
	"/sign-up/email",
	"/sign-in/email",
	"/sign-out",
	"/ok",
	"/error",
	"/get-session",
	"/list-sessions",
	"/revoke-session",
	"/request-password-reset",
	"/reset-password",
	"/reset-password/{token}",
	"/change-password",
	"/send-verification-email",
	"/verify-email",
	"/list-accounts",
	"/update-user",
	"/change-email",
	"/delete-user",
	"/delete-user/callback",
	"/verify-password",
	"/revoke-sessions",
	"/revoke-other-sessions",
	"/update-session",
}

func ledgerAuthDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for dir := wd; ; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "parity_ledger.json")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
	}
	t.Fatalf("parity_ledger.json not found from %s", wd)
	return ""
}

func ledgerRepoRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Dir(ledgerAuthDir(t))
	if _, err := os.Stat(filepath.Join(root, "vendor", "better-auth")); err != nil {
		t.Fatalf("vendor/better-auth not found under %s: %v", root, err)
	}
	return root
}

func ledgerRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

type ledgerManifest struct {
	Pin struct {
		Version string `json:"version"`
		Commit  string `json:"commit"`
	} `json:"pin"`
	Pending struct {
		Count  int            `json:"count"`
		ByFile map[string]int `json:"byFile"`
	} `json:"pending"`
	UpstreamTests []struct {
		File     string   `json:"file"`
		Cases    int      `json:"cases"`
		CaseName []string `json:"caseNames"`
	} `json:"upstreamTests"`
}

func ledgerLoadManifest(t *testing.T) ledgerManifest {
	t.Helper()
	var m ledgerManifest
	b, err := os.ReadFile(filepath.Join(ledgerAuthDir(t), "parity_ledger.json"))
	if err != nil {
		t.Fatalf("read parity_ledger.json: %v (AUTH-R5-01 manifest missing)", err)
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("parse parity_ledger.json: %v", err)
	}
	return m
}

func TestParityLedger_PinVersion(t *testing.T) {
	if auth.BetterAuthVersion != ledgerPinnedVersion {
		t.Fatalf("BetterAuthVersion = %q, want %q", auth.BetterAuthVersion, ledgerPinnedVersion)
	}
	root := ledgerRepoRoot(t)
	pkgJSON := ledgerRead(t, filepath.Join(root, "vendor", "better-auth", "packages", "better-auth", "package.json"))
	var pkg struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal([]byte(pkgJSON), &pkg); err != nil {
		t.Fatalf("parse package.json: %v", err)
	}
	if pkg.Version != ledgerPinnedVersion {
		t.Fatalf("upstream package.json version = %q, want %q", pkg.Version, ledgerPinnedVersion)
	}
	out, err := exec.Command("git", "-C", filepath.Join(root, "vendor", "better-auth"), "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatalf("rev-parse vendor/better-auth: %v", err)
	}
	if head := strings.TrimSpace(string(out)); head != ledgerPinnedCommit {
		t.Fatalf("vendor/better-auth HEAD = %q, want %q", head, ledgerPinnedCommit)
	}
	m := ledgerLoadManifest(t)
	if m.Pin.Version != ledgerPinnedVersion || m.Pin.Commit != ledgerPinnedCommit {
		t.Fatalf("manifest pin = %s/%s, want %s/%s", m.Pin.Version, m.Pin.Commit, ledgerPinnedVersion, ledgerPinnedCommit)
	}
}

func ledgerGoSources(t *testing.T, includeTests bool) []string {
	t.Helper()
	var out []string
	root := ledgerAuthDir(t)
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		if !includeTests && strings.HasSuffix(p, "_test.go") {
			return nil
		}
		if filepath.Base(p) == "parity_ledger_test.go" {
			return nil
		}
		out = append(out, p)
		return nil
	})
	if err != nil {
		t.Fatalf("walk go sources: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("no go sources found")
	}
	return out
}

func TestParityLedger_CoreRouteCatalog(t *testing.T) {
	if len(ledgerCoreRoutes) != 23 {
		t.Fatalf("core route catalog has %d entries, want 23 (v1 core-only, see docs/SCOPE.md)", len(ledgerCoreRoutes))
	}
	var blob strings.Builder
	for _, f := range ledgerGoSources(t, false) {
		blob.WriteString(ledgerRead(t, f))
		blob.WriteString("\n")
	}
	src := blob.String()
	for _, p := range ledgerCoreRoutes {
		needle := `"` + p + `"`
		if !strings.Contains(src, needle) {
			t.Errorf("core route %q not registered in non-test Go sources", p)
		}
	}
}

func TestParityLedger_PendingMarkers(t *testing.T) {
	m := ledgerLoadManifest(t)
	byFile := map[string]int{}
	total := 0
	for _, f := range ledgerGoSources(t, false) {
		content := ledgerRead(t, f)
		n := strings.Count(content, "Runtime: pending")
		if n == 0 {
			continue
		}
		rel, err := filepath.Rel(ledgerAuthDir(t), f)
		if err != nil {
			t.Fatalf("rel: %v", err)
		}
		byFile[filepath.ToSlash(rel)] = n
		total += n
	}
	if total != m.Pending.Count {
		t.Fatalf("Runtime: pending markers = %d, manifest expects %d; update the AUTH-R5-01 ledger instead of this test", total, m.Pending.Count)
	}
	for file, want := range m.Pending.ByFile {
		if got := byFile[file]; got != want {
			t.Errorf("Runtime: pending in %s = %d, manifest expects %d", file, got, want)
		}
	}
	for file := range byFile {
		if _, ok := m.Pending.ByFile[file]; !ok {
			t.Errorf("Runtime: pending in %s not recorded in manifest", file)
		}
	}
}

var ledgerCaseRe = regexp.MustCompile(`(?m)^\s*(describe|it|test)(?:\.\w+)?\(`)

func TestParityLedger_UpstreamTestManifest(t *testing.T) {
	m := ledgerLoadManifest(t)
	root := ledgerRepoRoot(t)
	areaCounts := map[string]int{}
	for _, e := range m.UpstreamTests {
		full := filepath.Join(root, filepath.FromSlash(e.File))
		content := ledgerRead(t, full)
		got := len(ledgerCaseRe.FindAllString(content, -1))
		if got != e.Cases {
			t.Errorf("%s: manifest cases = %d, upstream has %d describe/it/test blocks", e.File, e.Cases, got)
		}
		if len(e.CaseName) != e.Cases {
			t.Errorf("%s: manifest lists %d case names but cases = %d", e.File, len(e.CaseName), e.Cases)
		}
		switch {
		case strings.Contains(e.File, "/api/routes/"):
			areaCounts["core-routes"]++
		case strings.Contains(e.File, "plugins/admin/"):
			areaCounts["admin"]++
		case strings.Contains(e.File, "plugins/jwt/"):
			areaCounts["jwt"]++
		case strings.Contains(e.File, "plugins/organization/"):
			areaCounts["organization"]++
		case strings.Contains(e.File, "oauth-provider/"):
			areaCounts["oauth-provider"]++
		case strings.Contains(e.File, "/cookies/") || strings.Contains(e.File, "/crypto/") || strings.Contains(e.File, "/oauth2/"):
			areaCounts["cookies-crypto-oauth2"]++
		default:
			t.Errorf("%s: file outside ledger scope", e.File)
		}
	}
	want := map[string]int{
		"core-routes": 10, "cookies-crypto-oauth2": 3,
	}
	for area, n := range want {
		if areaCounts[area] != n {
			t.Errorf("area %s: manifest has %d files, want %d", area, areaCounts[area], n)
		}
	}
	if total := len(m.UpstreamTests); total != 13 {
		t.Errorf("manifest has %d upstream test files, want 13 (v1 core-only, see docs/SCOPE.md)", total)
	}
}
