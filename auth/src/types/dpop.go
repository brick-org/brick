package types

// DPoP (RFC 9449) integrator-facing option surface.
//
// The proof-verification runtime lives in auth/oauth2 (see VerifyDpopProof
// there, mirroring vendor/better-auth/packages/core/src/oauth2/dpop.ts) and
// the sender-constraint enforcement lives in the OAuth Provider plugin. This
// file carries only the pure, dependency-free surface integrators configure:
// the plugin `dpop` option bag, its upstream defaults, and the `dpop_jkt`
// shape validator. Nothing here performs I/O.

// DPoPSigningAlgorithm is an accepted JWS algorithm for DPoP proof JWTs.
//
// Upstream: DpopSigningAlgorithm in
// vendor/better-auth/packages/core/src/oauth2/dpop.ts
// (DPOP_SIGNING_ALGORITHMS). Symmetric and `none` algorithms are never
// accepted.
type DPoPSigningAlgorithm string

const (
	DPoPSigningEdDSA DPoPSigningAlgorithm = "EdDSA"
	DPoPSigningES256 DPoPSigningAlgorithm = "ES256"
	DPoPSigningES512 DPoPSigningAlgorithm = "ES512"
	DPoPSigningPS256 DPoPSigningAlgorithm = "PS256"
	DPoPSigningRS256 DPoPSigningAlgorithm = "RS256"
)

// DefaultDPoPSigningAlgorithms lists the DPoP proof JWS algorithms accepted
// when DPoPOptions.SigningAlgorithms is nil.
//
// Upstream: DPOP_SIGNING_ALGORITHMS in
// vendor/better-auth/packages/core/src/oauth2/dpop.ts, advertised as the
// default for `dpop.signingAlgorithms` in
// vendor/better-auth/packages/oauth-provider/src/types/index.ts.
var DefaultDPoPSigningAlgorithms = []string{"EdDSA", "ES256", "ES512", "PS256", "RS256"}

// DefaultDPoPProofMaxAgeSeconds bounds the accepted age of a DPoP proof JWT
// in seconds when DPoPOptions.ProofMaxAgeSeconds is unset.
//
// Upstream: the `dpop.proofMaxAgeSeconds` default (300) in
// vendor/better-auth/packages/oauth-provider/src/types/index.ts, matching
// DEFAULT_DPOP_PROOF_MAX_AGE_SECONDS in core/src/oauth2/dpop.ts.
const DefaultDPoPProofMaxAgeSeconds = 300

// DPoPOptions tunes DPoP proof validation without changing the enablement
// contract: DPoP is enforced when a client or resource asks for DPoP-bound
// access tokens.
//
// Upstream: the `dpop?: { proofMaxAgeSeconds?, signingAlgorithms? }` option
// bag in vendor/better-auth/packages/oauth-provider/src/types/index.ts.
// Pure option surface; the OAuth Provider plugin owns the runtime
// consumption (its flat DPoPProofMaxAgeSeconds/DPoPSigningAlgorithms fields
// predate this bag — future wiring may resolve them through it).
type DPoPOptions struct {
	// ProofMaxAgeSeconds is the accepted age of a DPoP proof JWT in
	// seconds. Zero or negative selects DefaultDPoPProofMaxAgeSeconds via
	// EffectiveProofMaxAgeSeconds.
	ProofMaxAgeSeconds int64
	// SigningAlgorithms lists the supported JWS algorithms for DPoP proof
	// JWTs. Nil selects DefaultDPoPSigningAlgorithms via
	// EffectiveSigningAlgorithms; an explicit (even empty) list is kept
	// as-is, mirroring upstream `??` semantics (empty accepts nothing and
	// fails closed).
	SigningAlgorithms []string
}

// EffectiveProofMaxAgeSeconds reports the accepted proof age in seconds,
// defaulting to DefaultDPoPProofMaxAgeSeconds when unset. Pure helper.
func (o DPoPOptions) EffectiveProofMaxAgeSeconds() int64 {
	if o.ProofMaxAgeSeconds <= 0 {
		return DefaultDPoPProofMaxAgeSeconds
	}
	return o.ProofMaxAgeSeconds
}

// EffectiveSigningAlgorithms reports the accepted proof JWS algorithms,
// defaulting to DefaultDPoPSigningAlgorithms when nil. An explicit empty
// list is preserved (accepts nothing). Pure helper; the returned default
// slice must not be mutated by callers.
func (o DPoPOptions) EffectiveSigningAlgorithms() []string {
	if o.SigningAlgorithms == nil {
		return DefaultDPoPSigningAlgorithms
	}
	return o.SigningAlgorithms
}

// ValidDPoPJkt reports whether jkt has the upstream `dpop_jkt` shape: a
// base64url-encoded SHA-256 JWK thumbprint (RFC 7638), exactly 43 chars from
// [A-Za-z0-9_-] with no padding. Pure validator; no I/O.
//
// Upstream: dpopJktSchema in
// vendor/better-auth/packages/oauth-provider/src/types/zod.ts
// (/^[A-Za-z0-9_-]{43}$/).
func ValidDPoPJkt(jkt string) bool {
	if len(jkt) != 43 {
		return false
	}
	for i := 0; i < len(jkt); i++ {
		c := jkt[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' {
			continue
		}
		return false
	}
	return true
}
