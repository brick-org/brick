// Package utils API-error predicate — IsAPIError parity (PARITY_V3.md gap 15).
//
// Upstream: packages/core/src/utils/is-api-error.ts @ 5468e6bf (re-exported
// by packages/better-auth/src/utils/is-api-error.ts):
//
//	export function isAPIError(error: unknown): error is APIError {
//		return (
//			error instanceof BaseAPIError ||
//			error instanceof APIError ||
//			(error as { name?: string })?.name === "APIError"
//		);
//	}
//
// Go equivalent: report whether err wraps types.HttpError (the Go APIError
// shape: {code, message} + numeric Status). Both value and pointer forms,
// including fmt-wrapped chains, count; nil and unrelated errors do not.
//
// Excluded / by-design (do NOT implement here):
//   - keccak toChecksumAddress (utils/hashing.ts, ERC-55 via @noble/hashes):
//     no v1 email/password+session caller; excluded.
//   - safeCloneRequest (utils/request.ts, Request.clone with bodyless
//     fallback): Go has no Request.clone; the faithful equivalent is the
//     best-effort rebuild in api/requestFromContext and
//     api/routes callbackRequest/mergeVerifyPostStoredRequest (method+URL+
//     headers only, body referenced not cloned). By design, no counterpart
//     in this package.
package utils

import (
	"errors"

	"github.com/brick-org/brick/auth/src/types"
)

// IsAPIError reports whether err is or wraps a types.HttpError,
// mirroring upstream isAPIError for the Go APIError shape.
func IsAPIError(err error) bool {
	if err == nil {
		return false
	}
	var v types.HttpError
	if errors.As(err, &v) {
		return true
	}
	var p *types.HttpError
	if errors.As(err, &p) && p != nil {
		return true
	}
	return false
}
