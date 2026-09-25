package routes

// C1 email-validator characterization (PARITY_V2.md P02, second-pass note:
// "Email-validator strictness — DEVIATION (hardened, delta unverified)".
//
// Go under test: isValidSignInEmail (auth/src/api/routes/sign-in.go:55-90):
// 254-byte cap, whitespace (" \t\r\n") reject, exactly one "@", non-empty
// local/domain, no leading/trailing/double dot in local, domain with >= 2
// labels each 1-63 bytes and without leading/trailing "-", then a
// net/mail.ParseAddress round-trip (parsed.Address == input).
//
// Upstream: z.email().safeParse(email) (vendor/better-auth
// packages/better-auth/src/api/routes/sign-in.ts:522-525). The zod pin for
// the vendored Better Auth (1.7.5 @ 5468e6bf) resolves via the
// pnpm-workspace catalog ("zod@>=4: 4.5.4") to zod 4.5.4, whose DEFAULT
// email pattern (packages/zod/src/v4/core/regexes.ts @ v4.5.4) is:
//
//	/^(?!\.)(?!.*\.\.)([A-Za-z0-9_'+\-\.]*)[A-Za-z0-9_+-]@([A-Za-z0-9][A-Za-z0-9\-]*\.)+[A-Za-z]{2,}$/
//
// i.e. ASCII-only local of [A-Za-z0-9_'+\-.] with no leading dot, no "..",
// no trailing dot; domain of >= 1 dotted labels (leading alnum, interior
// alnum/hyphen — note: a trailing hyphen BEFORE a dot is allowed) plus a
// final TLD of >= 2 ASCII letters. No length caps of any kind.
//
// Method: BOTH sides executed, nothing hand-derived. Go verdicts run the
// real isValidSignInEmail; zod verdicts were executed with node against
// zod@4.5.4 (z.email().safeParse) and are pinned per row below as
// "zod: accept|reject". Pure characterization: the test asserts ONLY the Go
// verdict and PASSES regardless of divergence — the deliverable is the
// divergence table itself (row names + zod comments + -v log lines).
//
// Result: 13/35 diverge. Go is STRICTER on: trailing-hyphen labels,
// >63-byte labels, >254-byte totals (zod caps nothing). Go is LOOSER on:
// single-char/numeric/alphanumeric TLDs, all-numeric dotted domains,
// RFC-special local chars (! # / etc.), bracketed IPv4 literals,
// underscore domains, and all Unicode local/domain forms (net/mail
// accepts them; the zod ASCII class rejects them).

import (
	"strings"
	"testing"
)

func TestC1_SignInEmailValidatorDivergence(t *testing.T) {
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
		// AGREE-accept: valid shape under both validators.
		{name: "simple_valid", email: "test@example.com", wantGo: true, zodAccept: true},                 // zod: accept (canonical shape)
		{name: "plus_tag", email: "plus+tag@example.com", wantGo: true, zodAccept: true},                 // zod: accept ('+' in local class)
		{name: "apostrophe_local", email: "o'brien@example.com", wantGo: true, zodAccept: true},          // zod: accept ('\'' in local class)
		{name: "punycode_domain", email: "test@xn--mnchen-3ya.de", wantGo: true, zodAccept: true},        // zod: accept (punycode is ASCII alnum/hyphen)
		{name: "multi_subdomain", email: "user@sub.domain.example.com", wantGo: true, zodAccept: true},   // zod: accept (repeated label group)

		// AGREE-reject: quoted-local forms (RFC-valid, rejected by both).
		{name: "quoted_local_space", email: `"a b"@x.com`, wantGo: false, zodAccept: false}, // zod: reject (no quote/space in local class; Go: Split("@")+ParseAddress round-trip)
		{name: "quoted_local_plain", email: `"abc"@example.com`, wantGo: false, zodAccept: false}, // zod: reject (quotes outside local class)

		// AGREE-reject: single-label hosts and empty parts.
		{name: "single_label_host", email: "a@localhost", wantGo: false, zodAccept: false}, // zod: reject (domain group needs >= 1 dot); Go: < 2 labels
		{name: "empty_local", email: "@missing-local.com", wantGo: false, zodAccept: false}, // zod: reject (local needs trailing [A-Za-z0-9_+-]); Go: empty local
		{name: "empty_domain", email: "a@", wantGo: false, zodAccept: false},                 // zod: reject (no domain); Go: empty domain
		{name: "double_at", email: "a@@b.com", wantGo: false, zodAccept: false},              // zod: reject ('@' outside classes); Go: Split gives 3 parts

		// AGREE-reject: dotless-excepted/dot-rule locals and domains.
		{name: "leading_dot_local", email: ".a@example.com", wantGo: false, zodAccept: false},   // zod: reject ((?!\.)); Go: leading-dot rule
		{name: "trailing_dot_local", email: "a.@example.com", wantGo: false, zodAccept: false}, // zod: reject (local must end [A-Za-z0-9_+-]); Go: trailing-dot rule
		{name: "double_dot_local", email: "a..b@example.com", wantGo: false, zodAccept: false}, // zod: reject ((?!.*\.\.)); Go: double-dot rule
		{name: "double_dot_domain", email: "a@b..com", wantGo: false, zodAccept: false},         // zod: reject (empty label can't match); Go: empty label
		{name: "trailing_dot_fqdn", email: "a@b.com.", wantGo: false, zodAccept: false},         // zod: reject (trailing dot breaks TLD anchor); Go: empty final label
		{name: "leading_hyphen_label", email: "a@-example.com", wantGo: false, zodAccept: false}, // zod: reject (label must open alnum); Go: leading-hyphen rule

		// AGREE-reject: IPv6 literal and whitespace variants.
		{name: "ipv6_literal", email: "a@[IPv6:2001:db8::1]", wantGo: false, zodAccept: false}, // zod: reject (brackets/colons outside classes); Go: no dot => single label
		{name: "ws_space_middle", email: "a b@example.com", wantGo: false, zodAccept: false},   // zod: reject (space outside classes); Go: whitespace gate
		{name: "ws_leading_space", email: " a@example.com", wantGo: false, zodAccept: false},   // zod: reject; Go: whitespace gate
		{name: "ws_trailing_space", email: "a@example.com ", wantGo: false, zodAccept: false},  // zod: reject; Go: whitespace gate (+ParseAddress mismatch)
		{name: "ws_tab", email: "a\tb@example.com", wantGo: false, zodAccept: false},           // zod: reject; Go: whitespace gate

		// DIVERGE (Go looser): TLD rules. Go's label loop has no TLD-alpha
		// requirement and net/mail accepts these; zod needs [A-Za-z]{2,}.
		{name: "DIVERGE_single_char_tld", email: "a@b.c", wantGo: true, zodAccept: false}, // zod: reject (TLD needs >= 2 letters)
		{name: "DIVERGE_numeric_tld", email: "a@b.12", wantGo: true, zodAccept: false},    // zod: reject (TLD letters-only)
		{name: "DIVERGE_dotted_quad", email: "a@1.2.3.4", wantGo: true, zodAccept: false}, // zod: reject (final "4" not [A-Za-z]{2,})

		// DIVERGE (Go looser): RFC-special local chars. net/mail accepts
		// them; zod's local class ([A-Za-z0-9_'+\-.]) does not.
		{name: "DIVERGE_bang_local", email: "a!b@example.com", wantGo: true, zodAccept: false},  // zod: reject ('!' outside class)
		{name: "DIVERGE_hash_local", email: "a#b@example.com", wantGo: true, zodAccept: false},  // zod: reject ('#' outside class)
		{name: "DIVERGE_slash_local", email: "a/b@example.com", wantGo: true, zodAccept: false}, // zod: reject ('/' outside class)

		// DIVERGE (Go looser): IP-literal / underscore domains and Unicode.
		// Go's label loop permits brackets/underscores/non-ASCII and
		// net/mail round-trips them; zod is ASCII-alnum/hyphen only.
		{name: "DIVERGE_ipv4_literal", email: "a@[1.2.3.4]", wantGo: true, zodAccept: false}, // zod: reject (brackets outside classes)
		{name: "DIVERGE_underscore_domain", email: "a@b_c.com", wantGo: true, zodAccept: false}, // zod: reject ('_' outside domain class)
		{name: "DIVERGE_unicode_local", email: "töst@example.com", wantGo: true, zodAccept: false}, // zod: reject (non-ASCII outside classes)
		{name: "DIVERGE_unicode_domain", email: "test@münchen.de", wantGo: true, zodAccept: false}, // zod: reject (non-ASCII in domain)

		// DIVERGE (Go stricter): trailing-hyphen labels, >63 labels, >254 totals.
		// zod's domain group allows "label-." and caps nothing.
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
