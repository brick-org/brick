// Package utils API-error predicate.
// Upstream: is-api-error.ts isAPIError.
// Go equivalent: report whether err wraps types.HttpError (the Go APIError
// shape: {code, message} + numeric Status). Both value and pointer forms,
// including fmt-wrapped chains, count; nil and unrelated errors do not.
//
// Excluded / by-design (do NOT implement here):
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
