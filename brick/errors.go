package brick

import (
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
)

// NotFound returns an RFC 9457 error with HTTP 404 status and the given detail.
func NotFound(detail string) huma.StatusError {
	return huma.NewError(http.StatusNotFound, detail)
}

// Unauthorized returns an RFC 9457 error with HTTP 401 status and the given detail.
func Unauthorized(detail string) huma.StatusError {
	return huma.NewError(http.StatusUnauthorized, detail)
}

// Forbidden returns an RFC 9457 error with HTTP 403 status and the given detail.
func Forbidden(detail string) huma.StatusError {
	return huma.NewError(http.StatusForbidden, detail)
}

// BadRequest returns an RFC 9457 error with HTTP 400 status and the given detail.
func BadRequest(detail string) huma.StatusError {
	return huma.NewError(http.StatusBadRequest, detail)
}

// Unprocessable returns an RFC 9457 error with HTTP 422 status carrying
// per-field validation failures. Replaces 500-on-NOT-NULL: input violations
// are client errors with actionable details, never bare 500s.
func Unprocessable(errs []FieldError) huma.StatusError {
	msgs := make([]string, 0, len(errs))
	for _, e := range errs {
		msgs = append(msgs, e.Field+": "+e.Message)
	}
	return huma.NewError(http.StatusUnprocessableEntity, "validation failed: "+strings.Join(msgs, "; "))
}

// Conflict returns an RFC 9457 error with HTTP 409 status. Used for PG
// 23505 unique violations (dup slug, autoname-hash race) detected by
// SQLSTATE code, never by string matching.
func Conflict(detail string) huma.StatusError {
	return huma.NewError(http.StatusConflict, detail)
}

// Internal returns an RFC 9457 error with HTTP 500 status and the given detail.
func Internal(detail string) huma.StatusError {
	return huma.NewError(http.StatusInternalServerError, detail)
}

// internalError maps an unexpected failure to a 500 whose detail carries
// only the request ID plus a generic message — never PG internals. The
// full error goes to the structured log via logExecError.
func internalError(requestID string) huma.StatusError {
	if requestID == "" {
		return huma.NewError(http.StatusInternalServerError, "internal error")
	}
	return huma.NewError(http.StatusInternalServerError, "internal error (request_id "+requestID+")")
}
