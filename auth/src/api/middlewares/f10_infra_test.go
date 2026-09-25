package middlewares

import "testing"

// F10 origin/CSRF infra coverage (P09-GAP-1..4).

// P09-GAP-4: upstream skips only GET/OPTIONS/HEAD (origin-check.ts:69-76); all other methods validate.
func TestF10_IsMutatingMethod_MatchesUpstreamNotGetOptionsHead(t *testing.T) {
	cases := []struct {
		method string
		want   bool
	}{
		{"GET", false},
		{"OPTIONS", false},
		{"HEAD", false},
		{"get", false},
		{"options", false},
		{"head", false},
		{"POST", true},
		{"PUT", true},
		{"PATCH", true},
		{"DELETE", true},
		{"TRACE", true},
		{"trace", true},
		{"PROPFIND", true},
		{"PURGE", true},
		{"QUERY", true},
		{"CUSTOM", true},
	}
	for _, tc := range cases {
		if got := IsMutatingMethod(tc.method); got != tc.want {
			t.Errorf("IsMutatingMethod(%q) = %v, want %v", tc.method, got, tc.want)
		}
	}
}

// OriginOrReferer wiring pin (P09-GAP-1): Origin wins, Referer is the fallback.
func TestF10_OriginOrReferer_PrefersOriginFallsBack(t *testing.T) {
	if got := OriginOrReferer("https://app.example", "https://ref.example/page"); got != "https://app.example" {
		t.Fatalf("origin must win, got %q", got)
	}
	if got := OriginOrReferer("", "https://ref.example/page"); got != "https://ref.example/page" {
		t.Fatalf("referer must back up an empty origin, got %q", got)
	}
	if got := OriginOrReferer("  ", "https://ref.example/page"); got != "https://ref.example/page" {
		t.Fatalf("blank origin must back up to referer, got %q", got)
	}
	if got := OriginOrReferer("", ""); got != "" {
		t.Fatalf("both empty must stay empty, got %q", got)
	}
}

// ShouldSkipOriginCheck slash-boundary pin (P09-GAP-3): skipping one path never skips prefix-siblings.
func TestF10_ShouldSkipOriginCheck_SlashBoundary(t *testing.T) {
	paths := []string{"/public/data"}
	if !ShouldSkipOriginCheck(false, paths, "/public/data") {
		t.Fatal("exact path must skip")
	}
	if !ShouldSkipOriginCheck(false, paths, "/public/data/item") {
		t.Fatal("slash-boundary child must skip")
	}
	if ShouldSkipOriginCheck(false, paths, "/public/database") {
		t.Fatal("prefix sibling must not skip")
	}
	if ShouldSkipOriginCheck(false, paths, "/public/data-delete") {
		t.Fatal("hyphen sibling must not skip")
	}
	if ShouldSkipOriginCheck(false, paths, "/other") {
		t.Fatal("unrelated path must not skip")
	}
	if !ShouldSkipOriginCheck(true, nil, "/anything") {
		t.Fatal("boolean skip-all must skip")
	}
	if ShouldSkipOriginCheck(false, nil, "/anything") {
		t.Fatal("no skip config must not skip")
	}
}

// ResolveOriginCandidate pin (P09-GAP-1): Origin wins, Referer backs up, null-Origin infers request-target origin.
func TestF10_ResolveOriginCandidate_NullInference(t *testing.T) {
	if got := ResolveOriginCandidate("https://app.example", "https://ref.example/x", "", "http", "app.example"); got != "https://app.example" {
		t.Fatalf("origin must win, got %q", got)
	}
	if got := ResolveOriginCandidate("", "https://ref.example/x", "", "http", "h"); got != "https://ref.example/x" {
		t.Fatalf("referer must back up, got %q", got)
	}
	if got := ResolveOriginCandidate("null", "", "same-origin", "http", "app.example"); got != "http://app.example" {
		t.Fatalf("null + same-origin must infer the request target, got %q", got)
	}
	if got := ResolveOriginCandidate("null", "", "same-origin", "https", "app.example"); got != "https://app.example" {
		t.Fatalf("inference must honor the TLS scheme, got %q", got)
	}
	if got := ResolveOriginCandidate("null", "", "same-origin", "http", ""); got != "null" {
		t.Fatalf("inference without a host must keep null, got %q", got)
	}
	if got := ResolveOriginCandidate("null", "", "cross-site", "http", "app.example"); got != "null" {
		t.Fatalf("null without same-origin metadata must stay null, got %q", got)
	}
	if got := ResolveOriginCandidate("null", "https://ref.example/x", "same-origin", "http", "app.example"); got != "http://app.example" {
		t.Fatalf("null inference wins over the referer (upstream origin === \"null\" branch), got %q", got)
	}
}

// Fetch-Metadata routing pins (P09-GAP-2, upstream validateFormCsrf, origin-check.ts:316-375).
func TestF10_FetchMetadataRouting(t *testing.T) {
	if !HasFetchMetadata("same-origin", "", "") {
		t.Fatal("site alone is metadata")
	}
	if !HasFetchMetadata("", "navigate", "") {
		t.Fatal("mode alone is metadata")
	}
	if !HasFetchMetadata("", "", "document") {
		t.Fatal("dest alone is metadata")
	}
	if HasFetchMetadata("", "", "") {
		t.Fatal("no headers is no metadata")
	}
	if HasFetchMetadata("  ", "", "") {
		t.Fatal("blank headers are no metadata")
	}
	if !IsCrossSiteNavigation("cross-site", "navigate") {
		t.Fatal("cross-site + navigate is the blocked pattern")
	}
	if IsCrossSiteNavigation("cross-site", "no-cors") {
		t.Fatal("cross-site without navigate is force-validated, not blocked")
	}
	if IsCrossSiteNavigation("same-origin", "navigate") {
		t.Fatal("same-origin navigate is not the attack pattern")
	}
	if !RequiresForceOriginValidation("", "", "same-origin", "", "") {
		t.Fatal("metadata alone forces validation")
	}
	if !RequiresForceOriginValidation("https://evil.example", "", "", "", "") {
		t.Fatal("bare origin forces validation")
	}
	if !RequiresForceOriginValidation("", "https://evil.example/x", "", "", "") {
		t.Fatal("bare referer forces validation")
	}
	if RequiresForceOriginValidation("", "", "", "", "") {
		t.Fatal("no evidence keeps the permissive fallback")
	}
}

// NeedsOriginValidation evidence gate pin: browser evidence (origin + cookies) is challenged.
func TestF10_NeedsOriginValidation_EvidenceGate(t *testing.T) {
	if !NeedsOriginValidation("https://app.example", "session=abc") {
		t.Fatal("origin + cookie must need validation")
	}
	if NeedsOriginValidation("https://app.example", "") {
		t.Fatal("origin without cookies must not need validation")
	}
	if NeedsOriginValidation("", "session=abc") {
		t.Fatal("cookies without origin must not need validation here")
	}
}
