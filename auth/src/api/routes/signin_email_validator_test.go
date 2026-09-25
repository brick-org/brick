package routes

// C1 email-validator characterization (PARITY_V2.md P02, second-pass note:
// Upstream: z.email().safeParse(email) (vendor/better-auth
// packages/better-auth/src/api/routes/sign-in.ts:522-525). The zod pin for
// the vendored Better Auth (1.7.5 @ 5468e6bf) resolves via the
// zod@4.5.4 (z.email().safeParse) and are pinned per row below as
// "zod: accept|reject". Pure characterization: the test asserts ONLY the Go

import (
	"strings"
	"testing"
)

func TestSignInEmailValidator_SignInEmailValidatorDivergence(t *testing.T) {
	overlongLabel := "a@" + strings.Repeat("x", 64) + ".com"
	if got := strings.Split(strings.SplitN(overlongLabel, "@", 2)[1], ".")[0]; len(got) != 64 {
		t.Fatalf("fixture error: overlong label is %d bytes, want 64", len(got))
	}
	total255 := strings.Repeat("a", 64) + "@" + strings.Repeat("b", 63) + "." +
		strings.Repeat("c", 63) + "." + strings.Repeat("d", 59) + ".ff"
	if len(total255) != 255 {
		t.Fatalf("fixture error: total255 is %d bytes, want 255", len(total255))
	}

	cases := []struct {
		name      string
		email     string
		wantGo    bool
		zodAccept bool
	}{
		{name: "simple_valid", email: "test@example.com", wantGo: true, zodAccept: true},                 // zod: accept (canonical shape)
		{name: "plus_tag", email: "plus+tag@example.com", wantGo: true, zodAccept: true},                 // zod: accept ('+' in local class)
		{name: "apostrophe_local", email: "o'brien@example.com", wantGo: true, zodAccept: true},          // zod: accept ('\'' in local class)
		{name: "punycode_domain", email: "test@xn--mnchen-3ya.de", wantGo: true, zodAccept: true},        // zod: accept (punycode is ASCII alnum/hyphen)
		{name: "multi_subdomain", email: "user@sub.domain.example.com", wantGo: true, zodAccept: true},   // zod: accept (repeated label group)

		{name: "quoted_local_space", email: `"a b"@x.com`, wantGo: false, zodAccept: false}, // zod: reject (no quote/space in local class; Go: Split("@")+ParseAddress round-trip)
		{name: "quoted_local_plain", email: `"abc"@example.com`, wantGo: false, zodAccept: false}, // zod: reject (quotes outside local class)

		{name: "single_label_host", email: "a@localhost", wantGo: false, zodAccept: false}, // zod: reject (domain group needs >= 1 dot); Go: < 2 labels
		{name: "empty_local", email: "@missing-local.com", wantGo: false, zodAccept: false}, // zod: reject (local needs trailing [A-Za-z0-9_+-]); Go: empty local
		{name: "empty_domain", email: "a@", wantGo: false, zodAccept: false},                 // zod: reject (no domain); Go: empty domain
		{name: "double_at", email: "a@@b.com", wantGo: false, zodAccept: false},              // zod: reject ('@' outside classes); Go: Split gives 3 parts

		{name: "leading_dot_local", email: ".a@example.com", wantGo: false, zodAccept: false},   // zod: reject ((?!\.)); Go: leading-dot rule
		{name: "trailing_dot_local", email: "a.@example.com", wantGo: false, zodAccept: false}, // zod: reject (local must end [A-Za-z0-9_+-]); Go: trailing-dot rule
		{name: "double_dot_local", email: "a..b@example.com", wantGo: false, zodAccept: false}, // zod: reject ((?!.*\.\.)); Go: double-dot rule
		{name: "double_dot_domain", email: "a@b..com", wantGo: false, zodAccept: false},         // zod: reject (empty label can't match); Go: empty label
		{name: "trailing_dot_fqdn", email: "a@b.com.", wantGo: false, zodAccept: false},         // zod: reject (trailing dot breaks TLD anchor); Go: empty final label
		{name: "leading_hyphen_label", email: "a@-example.com", wantGo: false, zodAccept: false}, // zod: reject (label must open alnum); Go: leading-hyphen rule

		{name: "ipv6_literal", email: "a@[IPv6:2001:db8::1]", wantGo: false, zodAccept: false}, // zod: reject (brackets/colons outside classes); Go: no dot => single label
		{name: "ws_space_middle", email: "a b@example.com", wantGo: false, zodAccept: false},   // zod: reject (space outside classes); Go: whitespace gate
		{name: "ws_leading_space", email: " a@example.com", wantGo: false, zodAccept: false},   // zod: reject; Go: whitespace gate
		{name: "ws_trailing_space", email: "a@example.com ", wantGo: false, zodAccept: false},  // zod: reject; Go: whitespace gate (+ParseAddress mismatch)
		{name: "ws_tab", email: "a\tb@example.com", wantGo: false, zodAccept: false},           // zod: reject; Go: whitespace gate

		{name: "DIVERGE_single_char_tld", email: "a@b.c", wantGo: true, zodAccept: false}, // zod: reject (TLD needs >= 2 letters)
		{name: "DIVERGE_numeric_tld", email: "a@b.12", wantGo: true, zodAccept: false},    // zod: reject (TLD letters-only)
		{name: "DIVERGE_dotted_quad", email: "a@1.2.3.4", wantGo: true, zodAccept: false}, // zod: reject (final "4" not [A-Za-z]{2,})

		{name: "DIVERGE_bang_local", email: "a!b@example.com", wantGo: true, zodAccept: false},  // zod: reject ('!' outside class)
		{name: "DIVERGE_hash_local", email: "a#b@example.com", wantGo: true, zodAccept: false},  // zod: reject ('#' outside class)
		{name: "DIVERGE_slash_local", email: "a/b@example.com", wantGo: true, zodAccept: false}, // zod: reject ('/' outside class)

		{name: "DIVERGE_ipv4_literal", email: "a@[1.2.3.4]", wantGo: true, zodAccept: false}, // zod: reject (brackets outside classes)
		{name: "DIVERGE_underscore_domain", email: "a@b_c.com", wantGo: true, zodAccept: false}, // zod: reject ('_' outside domain class)
		{name: "DIVERGE_unicode_local", email: "töst@example.com", wantGo: true, zodAccept: false}, // zod: reject (non-ASCII outside classes)
		{name: "DIVERGE_unicode_domain", email: "test@münchen.de", wantGo: true, zodAccept: false}, // zod: reject (non-ASCII in domain)

		{name: "DIVERGE_trailing_hyphen_label", email: "a@example-.com", wantGo: false, zodAccept: true}, // zod: accept ([A-Za-z0-9-]* swallows '-'); Go: trailing-hyphen rule
		{name: "DIVERGE_overlong_label_64", email: overlongLabel, wantGo: false, zodAccept: true},        // zod: accept (no length cap); Go: 64 > 63
		{name: "DIVERGE_total_length_255", email: total255, wantGo: false, zodAccept: true},              // zod: accept (no length cap); Go: 255 > 254
	}

	agree, diverge := 0, 0
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isValidSignInEmail(tc.email); got != tc.wantGo {
				t.Errorf("isValidSignInEmail(%q) = %v, want %v", tc.email, got, tc.wantGo)
			}
			zodVerdict := "reject"
			if tc.zodAccept {
				zodVerdict = "accept"
			}
			table := "AGREE"
			if tc.wantGo != tc.zodAccept {
				table = "DIVERGE"
			}
			t.Logf("C1TABLE %-32s go=%-5v zod=%-6s %s", tc.name, tc.wantGo, zodVerdict, table)
		})
		if tc.wantGo != tc.zodAccept {
			diverge++
		} else {
			agree++
		}
	}
	t.Logf("C1SUMMARY vectors=%d agree=%d diverge=%d (Go stricter=3, Go looser=10)", len(cases), agree, diverge)
}
