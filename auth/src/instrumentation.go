package auth

// Instrumentation in this runtime (AUTH-F6-03).
//
// Pinned upstream: createWithSpan/withSpan in
// vendor/better-auth/packages/core/src/instrumentation (tracer.ts, noop.ts,
// pure.index.ts).
//
// Upstream selects the span runner per instance: withSpan (real OpenTelemetry
// tracer, recording exceptions on the span — except 3xx APIError redirects,
// which close as OK) unless experimental.instrumentation.enabled === false,
// in which case noopWithSpan executes the function directly.
//
// EXCLUSION (explicit, platform): the Go runtime vendors no OpenTelemetry
// SDK — the dynamic import in upstream api.ts has no Go equivalent — so both
// paths execute inline. Preserved exactly: name/attribute plumbing in the
// signature (reserved for future OTel wiring), value AND error propagation
// (upstream rethrows after recording; here there is no span to record on),
// and the disable flag (explicit false still executes, mirroring
// noopWithSpan). Instrumentation is enabled by default and when
// Experimental.Instrumentation.Enabled is explicitly true; it is bypassed
// only when explicitly disabled — either way the function runs.
//
// Upstream TypeScript names: createWithSpan, withSpan.
func WithSpan[T any](opts Options, name string, attrs map[string]string, fn func() (T, error)) (T, error) {
	_ = name
	_ = attrs
	return fn()
}
