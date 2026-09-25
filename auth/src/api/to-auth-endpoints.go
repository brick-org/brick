package api

// --- Endpoint conversion (upstream `src/api/to-auth-endpoints.ts`) ---
//
// Go port distributes the work across `Router` and the `routes` package;
// see dispatch.go and routes/hooks.go. No `auth.api.*` direct entry; Huma owns dispatch.
//
//   - The pending schema check (`ctx.checkSchema?.()`) ->
//     `opts.SchemaCheck` middleware in `Router`, failing closed with a 500
//     before rate limiting and request hooks.
