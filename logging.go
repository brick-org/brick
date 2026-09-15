package brick

import (
	"context"
	"log/slog"
	"net/http"
)

// requestIDKey carries the per-request ID used to correlate 500 envelopes
// with structured logs.
type requestIDKey struct{}

// requestIDFromCtx returns the request ID stored by the request-ID
// middleware, or "" when absent (non-HTTP exec paths, tests).
func requestIDFromCtx(ctx context.Context) string {
	rid, _ := ctx.Value(requestIDKey{}).(string)
	return rid
}

// requestIDMiddleware assigns a UUID v4 per request unless X-Request-ID is
// present (tests and callers may fix the ID for correlation), stores it in
// the context, and echoes it back as a response header.
func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := r.Header.Get("X-Request-ID")
		if rid == "" {
			rid = newUUID()
		}
		w.Header().Set("X-Request-ID", rid)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, rid)))
	})
}

// logExecError records a storage/runtime failure with the fields needed to
// find it again: request_id (matches the 500 envelope), resource, op.
// Client errors (4xx StatusErrors) never reach here — only genuine 500s.
func logExecError(ctx context.Context, op string, err error) {
	slog.Error("brick exec failed",
		"request_id", requestIDFromCtx(ctx),
		"op", op,
		"error", err,
	)
}
