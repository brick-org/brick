package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/netip"
	"net/url"
	stdpath "path"
	"slices"
	"strings"
	"time"

	"github.com/brick-org/brick/auth/src/api/routes"
	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
)

// Router initialises a Huma API on the provided adapter, registers the
// origin-check middleware, and registers all auth routes (core + plugin
// endpoints via types.CollectPluginEndpoints, which merges the legacy slice
// and the named-endpoint map form).
func Router(adapter huma.Adapter, basePath string, opts types.Options) huma.API {
	// Trailing-slash variants mirror upstream's skipTrailingSlashes router
	// normalization (vendor/.../src/api/index.ts:296): when set, every
	// registered route also serves its slash suffixed spelling. The
	// duplicating adapter below keeps this central so core routes (owned by
	// sibling packages), custom OAuth callback mounts, and plugin endpoints
	// all gain variants without touching their registration call sites.
	// Middleware path decisions normalize separately (see
	// middlewareRateLimitPath); this registration is what lets a
	// trailing-slash request actually REACH a handler.
	if opts.Advanced.SkipTrailingSlashes {
		adapter = &slashVariantAdapter{inner: adapter, seen: map[string]struct{}{}}
	}
	cfg := huma.DefaultConfig("Auth API", "1.0.0")
	cfg.CreateHooks = nil // disable $schema property in responses
	api := huma.NewAPI(cfg, adapter)
	enabled := func(path string) bool {
		return !disabledPathMatched(opts.DisabledPaths, path)
	}

	// Endpoint-conflict parity (mirrors checkEndpointConflicts in
	// vendor/.../src/api/index.ts:58-171): plugin endpoint paths sharing a
	// method log an error diagnostic (level-gated, quiet by default).
	// BetterAuth-constructed instances reach this through their Router call;
	// direct Router callers are covered too.
	checkEndpointConflicts(opts)

	// Origin-check middleware — mirrors better-auth's CSRF/origin protection
	// (vendor/.../src/api/middlewares/origin-check.ts: validateOrigin).
	// POST/PUT/PATCH/DELETE requests that carry both an Origin header AND a
	// Cookie header must come from a trusted origin.
	// Requests without cookies (server-to-server) always pass through.
	// Short-circuit errors use the huma {status,title,detail} shape, matching
	// writeHookError below; only the rate limiter intentionally differs (it
	// keeps upstream's {message} body — see writeRateLimitResponse).
	//
	// DisableOriginCheck skips this middleware entirely. Mirroring upstream's
	// backward compatibility (shouldSkipCSRFForBackwardCompat), it also skips
	// the CSRF check unless DisableCSRFCheck is set explicitly; BetterAuth
	// logs a warning when the flag is set (direct Router callers get the
	// same note here when logging is configured).
	//
	// DynamicBaseURL mode installs this middleware even without a static
	// BaseURL: the request origin is checked against the allowedHosts /
	// fallback expansion (see ExpandDynamicBaseURLOrigins), which BetterAuth
	// pre-merges into TrustedOrigins and which is re-derived here so direct
	// Router callers are covered too.
	originCheckSkipped := opts.Advanced.DisableCSRFCheck || opts.Advanced.DisableOriginCheck
	if opts.Advanced.DisableOriginCheck && !opts.Advanced.DisableCSRFCheck {
		apiLogf(opts, "warn", "auth: Advanced.DisableOriginCheck is set: origin validation is skipped in middleware, and CSRF origin checks are skipped as well for backward compatibility with better-auth; set Advanced.DisableCSRFCheck explicitly to silence this note")
	}
	if !originCheckSkipped && (opts.BaseURL != "" || len(opts.TrustedOrigins) > 0 || opts.TrustedOriginsFunc != nil || opts.DynamicBaseURL != nil) {
		api.UseMiddleware(func(ctx huma.Context, next func(huma.Context)) {
			m := ctx.Method()
			mutating := m == http.MethodPost || m == http.MethodPut ||
				m == http.MethodPatch || m == http.MethodDelete
			if mutating {
				origin := ctx.Header("Origin")
				cookie := ctx.Header("Cookie")
				// Only validate when browser-style request (has both Origin + Cookie)
				if origin != "" && cookie != "" {
					// Reconstruct the request so TrustedOriginsFunc receives
					// headers/URL/RemoteAddr; callers must still handle a
					// body-less shallow copy (see requestFromContext limits).
					if !originTrustedForRequest(origin, opts, requestFromContext(ctx)) {
						// Headers before status: adapters flush on WriteHeader.
						ctx.SetHeader("Content-Type", "application/json")
						ctx.SetStatus(http.StatusForbidden)
						_, _ = ctx.BodyWriter().Write([]byte(
							`{"status":403,"title":"Forbidden","detail":"Invalid origin"}`,
						))
						return
					}
				}
			}
			next(ctx)
		})
	}

	if rateLimitNeedsCustomMiddleware(opts) {
		useRateLimitMiddlewareWithStorage(api, basePath, opts)
	} else {
		useRateLimitMiddleware(api, basePath, opts)
	}

	// Schema-check gate (mirrors the checkSchema await at the top of
	// upstream's router onRequest, vendor/.../src/api/index.ts:305-306, and
	// toAuthEndpoints, to-auth-endpoints.ts:94-95). BetterAuth attaches the
	// validator as opts.SchemaCheck (nil when Advanced.Database.ValidateSchema
	// is explicitly false or for direct Router callers); when present it runs
	// before rate limiting and request hooks, failing closed with a 500.
	// Upstream TypeScript name: checkSchema.
	if opts.SchemaCheck != nil {
		check := opts.SchemaCheck
		api.UseMiddleware(func(ctx huma.Context, next func(huma.Context)) {
			if err := check(); err != nil {
				writeHookError(api, ctx, huma.NewError(http.StatusInternalServerError, "schema check failed", err))
				return
			}
			next(ctx)
		})
	}

	needsMiddleware := opts.Hooks.Before != nil || opts.Hooks.After != nil ||
		opts.OnAPIError.OnError != nil || opts.OnAPIError.ErrorURL != "" || opts.OnAPIError.Throw ||
		hasPluginRouteHooks(opts) || hasPluginTSRouteHooks(opts) || hasPluginRequestLifecycle(opts)
	// Always-on request context (upstream toAuthEndpoints per-call work:
	// resolveDynamicContext + runWithRequestState, plus dispatch
	// runWithEndpointContext). This runs for every request so handlers and
	// plugin endpoints see the resolved per-request BaseURL, request state,
	// endpoint metadata, the real request, and the auth-route context whether
	// or not hooks are configured. The hook pipeline below reuses the same
	// stores (same map pointers) so values never fork between layers.
	api.UseMiddleware(func(ctx huma.Context, next func(huma.Context)) {
		reqState := NewRequestState()
		if existing := GetRequestState(ctx); existing != nil {
			reqState = existing
		}
		current := WithRequestState(ctx, reqState)
		current = routes.WithRequestStateStore(current, reqState)
		req := requestFromContext(current)
		if baseURL, err := ResolveDynamicBaseURLForRequest(req, opts); err == nil && baseURL != "" {
			reqState[RequestBaseURLKey] = baseURL
			current = routes.WithRequestFullBaseURL(current, baseURL)
		}
		current = routes.WithStoredRequest(current, req)
		opID := ""
		if op := current.Operation(); op != nil {
			opID = op.OperationID
		}
		current = routes.WithEndpointMetadata(current, routes.EndpointMetadata{
			Method:      current.Method(),
			Path:        current.URL().Path,
			OperationID: opID,
		})
		current = routes.WithAuthRouteContext(current)
		current = WithRequestState(current, reqState)
		current = routes.WithRequestStateStore(current, reqState)
		next(current)
	})
	if needsMiddleware {
		// TypeScript-faithful route hooks (upstream plugin.hooks.before/after
		// over PluginHookContext) run inside the same pipeline as the legacy
		// Huma-shaped RouteHooks: before hooks after the legacy route before
		// hooks, after hooks after the legacy route after hooks, all in
		// plugin declaration order (see types.CollectTSRouteHooks).
		tsRouteHooks := types.CollectTSRouteHooks(opts.Plugins)
		api.UseMiddleware(func(ctx huma.Context, next func(huma.Context)) {
			captured := newCapturedContext(ctx)
			current := huma.Context(captured)
			authCtx := types.AuthContext{Options: opts, AppName: opts.AppName}

			req := requestFromContext(current)
			// Reuse the always-on request state so hooks and handlers share
			// one store (upstream runWithRequestState); only create when
			// direct callers bypass that layer.
			reqState := GetRequestState(ctx)
			if reqState == nil {
				reqState = NewRequestState()
			}
			current = WithRequestState(current, reqState)
			current = routes.WithRequestStateStore(current, reqState)
			if baseURL, err := ResolveDynamicBaseURLForRequest(req, opts); err == nil && baseURL != "" {
				reqState[RequestBaseURLKey] = baseURL
				current = routes.WithRequestFullBaseURL(current, baseURL)
				authCtx.BaseURL = baseURL
			} else if full := routes.RequestFullBaseURLFromHuma(ctx); full != "" {
				authCtx.BaseURL = full
			}
			current = routes.WithStoredRequest(current, req)
			// Refresh endpoint metadata through the capture layer so the
			// operation ID survives to handlers and plugin context.
			opID := ""
			if op := current.Operation(); op != nil {
				opID = op.OperationID
			}
			if opID == "" {
				opID = routes.EndpointMetadataFromStd(ctx.Context()).OperationID
			}
			current = routes.WithEndpointMetadata(current, routes.EndpointMetadata{
				Method:      current.Method(),
				Path:        current.URL().Path,
				OperationID: opID,
			})
			for _, p := range opts.Plugins {
				provider, ok := p.(types.PluginOnRequestProvider)
				if !ok || provider.OnRequest() == nil {
					continue
				}
				// Instrumentation: each onRequest runs in its own span
				// (upstream `onRequest ${plugin.id}`), passthrough here.
				onReq := provider.OnRequest()
				pluginID := p.ID()
				result, err := routes.WithSpan(opts, "onRequest "+pluginID, map[string]string{"hook": "onRequest", "plugin": pluginID}, func() (*types.PluginOnRequestResult, error) {
					return onReq(req, authCtx)
				})
				if err != nil {
					writeHookError(api, current, err)
					callAPIErrorHandler(opts, current)
					captured.Flush()
					return
				}
				if result == nil {
					continue
				}
				if result.Response != nil {
					captured.ApplyHTTPResponse(result.Response)
					captured.Flush()
					return
				}
				if result.Request != nil {
					req = result.Request
					current = &requestOverrideContext{inner: current, request: req}
					// A replaced request re-resolves the per-request baseURL
					// and stored request so downstream trust checks and URL
					// builders see the final request.
					if baseURL, rerr := ResolveDynamicBaseURLForRequest(req, opts); rerr == nil && baseURL != "" {
						reqState[RequestBaseURLKey] = baseURL
						current = routes.WithRequestFullBaseURL(current, baseURL)
						authCtx.BaseURL = baseURL
					}
					current = routes.WithStoredRequest(current, req)
				}
			}

			// Plugin buckets consume atomically through the selected backend
			// (custom → secondary → database → memory,
			// ConsumeResolvedRateLimit): a single pre-handler step, so no
			// post-handler record follows. Storage errors fail the
			// request (500); denial answers 429 with retry-after.
			if pluginRateLimit, ok := resolvePluginRateLimit(current, basePath, opts); ok {
				allowed, retryAfter, cerr := ConsumeResolvedRateLimit(current.Context(), pluginRateLimit, opts)
				if cerr != nil {
					apiLogf(opts, "error", "auth: plugin rate-limit consume failed for key %q: %v", pluginRateLimit.Key, cerr)
					writeHookError(api, current, huma.NewError(http.StatusInternalServerError, "rate limit storage error"))
					captured.Flush()
					return
				}
				if !allowed {
					writeRateLimitResponse(current, retryAfter)
					captured.Flush()
					return
				}
			}

			// User global before hook fires first (mirrors better-auth ordering).
			if opts.Hooks.Before != nil {
				before := opts.Hooks.Before
				nextCtx, err := routes.WithSpan(opts, "hook before user", map[string]string{"hook": "before", "context": "user"}, func() (huma.Context, error) {
					return before(current)
				})
				if err != nil {
					writeHookError(api, current, err)
					callAPIErrorHandler(opts, current)
					captured.Flush()
					return
				}
				if nextCtx != nil {
					current = nextCtx
				}
			}

			for _, p := range opts.Plugins {
				provider, ok := p.(types.PluginMiddlewareProvider)
				if !ok {
					continue
				}
				for _, middleware := range provider.Middlewares() {
					if !pluginMiddlewareMatches(current, middleware.Path, basePath) {
						continue
					}
					nextCtx, err := middleware.Handler(current)
					if err != nil {
						writeHookError(api, current, err)
						callAPIErrorHandler(opts, current)
						captured.Flush()
						return
					}
					if nextCtx != nil {
						current = nextCtx
					}
				}
			}

			// Plugin route before hooks fire after the user global hook, in plugin declaration order.
			for _, p := range opts.Plugins {
				for _, hook := range p.RouteHooks().Before {
					if hook.Matcher(current) {
						nextCtx, err := hook.Handler(current)
						if err != nil {
							writeHookError(api, current, err)
							callAPIErrorHandler(opts, current)
							captured.Flush()
							return
						}
						if nextCtx != nil {
							current = nextCtx
						}
					}
				}
			}

			// TypeScript-faithful before hooks run after the legacy route
			// before hooks, in plugin declaration order (upstream
			// hooks.before). The first handler error aborts the route;
			// ResponseHeaders mutations accumulate with upstream merge
			// semantics (set-cookie appends, everything else replaces).
			if len(tsRouteHooks.Before) > 0 {
				hctx := routes.PluginHookContextFromHuma(current, authCtx)
				_, hookErr := routes.WithSpan(opts, "hook before plugins", map[string]string{"hook": "before"}, func() (struct{}, error) {
					return struct{}{}, routes.RunTSRouteBeforeHooks(hctx, tsRouteHooks.Before)
				})
				if hookErr != nil {
					writeHookError(api, current, hookErr)
					callAPIErrorHandler(opts, current)
					captured.Flush()
					return
				}
				applyTSResponseHeaders(current, hctx.ResponseHeaders)
			}

			current = routes.WithAuthRouteContext(current)
			// Preserve request state across the auth-route context wrap
			// (huma.WithValue layers values; re-attach the same map so hooks
			// and handlers after this point keep seeing the same store).
			current = WithRequestState(current, reqState)
			current = routes.WithRequestStateStore(current, reqState)
			next(current)

			// User global after hook fires before plugin after hooks.
			if opts.Hooks.After != nil {
				opts.Hooks.After(current)
			}

			// Plugin route after hooks fire in plugin declaration order.
			for _, p := range opts.Plugins {
				for _, hook := range p.RouteHooks().After {
					if hook.Matcher(current) {
						hook.Handler(current)
					}
				}
			}

			// TypeScript-faithful after hooks run after the legacy route
			// after hooks. Returned carries the wire serialization
			// approximation (captured body bytes); ResponseHeaders mutations
			// are applied with upstream merge semantics (set-cookie appends,
			// everything else replaces). Handler errors never fail the route
			// — each is reported via Options.Logger when configured.
			if len(tsRouteHooks.After) > 0 {
				hctx := routes.PluginHookContextFromHuma(current, authCtx)
				hctx.Returned = append([]byte(nil), captured.body.Bytes()...)
				routes.RunTSRouteAfterHooks(hctx, tsRouteHooks.After, func(err error) {
					apiLogf(opts, "error", "auth: plugin route after hook failed: %v", err)
				})
				applyTSResponseHeaders(current, hctx.ResponseHeaders)
			}

			response := captured.HTTPResponse()
			for _, p := range opts.Plugins {
				provider, ok := p.(types.PluginOnResponseProvider)
				if !ok || provider.OnResponse() == nil {
					continue
				}
				result, err := provider.OnResponse()(response, authCtx)
				if err != nil {
					writeHookError(api, current, err)
					callAPIErrorHandler(opts, current)
					break
				}
				if result != nil && result.Response != nil {
					response = result.Response
				}
			}
			captured.ApplyHTTPResponse(response)

			callAPIErrorHandler(opts, current)
			// No post-handler plugin-bucket record: the pre-handler
			// ConsumeResolvedRateLimit above already consumed atomically.
			captured.Flush()
		})
	}

	if enabled("/ok") {
		routes.Ok(api, basePath)
	}
	if enabled("/error") {
		routes.Error(api, basePath, opts)
	}
	if enabled("/sign-up/email") {
		routes.SignUpEmail(api, basePath, opts)
	}
	if enabled("/sign-in/email") {
		routes.SignInEmail(api, basePath, opts)
	}
	if enabled("/sign-out") {
		routes.SignOut(api, basePath, opts)
	}
	if enabled("/get-session") {
		routes.GetSession(api, basePath, opts)
	}
	if enabled("/list-sessions") {
		routes.ListSessions(api, basePath, opts)
	}
	if enabled("/revoke-session") {
		routes.RevokeSession(api, basePath, opts)
	}
	if enabled("/send-verification-email") {
		routes.SendVerificationEmail(api, basePath, opts)
	}
	if enabled("/verify-email") {
		routes.VerifyEmail(api, basePath, opts)
	}
	if enabled("/request-password-reset") {
		routes.RequestPasswordReset(api, basePath, opts)
	}
	if enabled("/reset-password") {
		routes.ResetPassword(api, basePath, opts)
	}
	if enabled("/change-password") {
		routes.ChangePassword(api, basePath, opts)
	}
	if enabled("/list-accounts") {
		routes.ListUserAccounts(api, basePath, opts)
	}
	if enabled("/update-user") {
		routes.UpdateUser(api, basePath, opts)
	}
	if enabled("/change-email") {
		routes.ChangeEmail(api, basePath, opts)
	}
	if enabled("/delete-user") {
		routes.DeleteUser(api, basePath, opts)
	}
	if enabled("/delete-user/callback") {
		routes.DeleteUserCallback(api, basePath, opts)
	}
	if enabled("/revoke-sessions") {
		routes.RevokeSessions(api, basePath, opts)
	}
	if enabled("/revoke-other-sessions") {
		routes.RevokeOtherSessions(api, basePath, opts)
	}
	if enabled("/update-session") {
		routes.UpdateSession(api, basePath, opts)
	}
	if enabled("/verify-password") {
		routes.VerifyPassword(api, basePath, opts)
	}
	if enabled("/reset-password/:token") {
		routes.RequestPasswordResetCallback(api, basePath, opts)
	}
	// Plugin endpoints (upstream getEndpoints merges plugin.endpoints over
	// the core set). CollectPluginEndpoints merges the legacy Endpoints()
	// slice and the named-endpoint map form (PluginNamedEndpointsProvider,
	// mirroring upstream's `{ [key]: Endpoint }` map) in plugin declaration
	// order with deterministic key sorting; same-path conflicts across
	// plugins are reported by checkEndpointConflicts at Router start.
	for _, ep := range types.CollectPluginEndpoints(opts.Plugins) {
		ep.Register(api, basePath, opts)
	}
	return api
}

type capturedContext struct {
	inner  huma.Context
	body   bytes.Buffer
	status int
	header http.Header
}

func newCapturedContext(ctx huma.Context) *capturedContext {
	return &capturedContext{inner: ctx, header: make(http.Header)}
}

func (c *capturedContext) Operation() *huma.Operation {
	return c.inner.Operation()
}

func (c *capturedContext) Context() context.Context {
	return c.inner.Context()
}

func (c *capturedContext) TLS() *tls.ConnectionState {
	return c.inner.TLS()
}

func (c *capturedContext) Version() huma.ProtoVersion {
	return c.inner.Version()
}

func (c *capturedContext) Method() string {
	return c.inner.Method()
}

func (c *capturedContext) Host() string {
	return c.inner.Host()
}

func (c *capturedContext) RemoteAddr() string {
	return c.inner.RemoteAddr()
}

func (c *capturedContext) URL() url.URL {
	return c.inner.URL()
}

func (c *capturedContext) Param(name string) string {
	return c.inner.Param(name)
}

func (c *capturedContext) Query(name string) string {
	return c.inner.Query(name)
}

func (c *capturedContext) Header(name string) string {
	return c.inner.Header(name)
}

func (c *capturedContext) EachHeader(cb func(name, value string)) {
	c.inner.EachHeader(cb)
}

func (c *capturedContext) BodyReader() io.Reader {
	return c.inner.BodyReader()
}

func (c *capturedContext) GetMultipartForm() (*multipart.Form, error) {
	return c.inner.GetMultipartForm()
}

func (c *capturedContext) SetReadDeadline(deadline time.Time) error {
	return c.inner.SetReadDeadline(deadline)
}

func (c *capturedContext) SetStatus(code int) {
	c.status = code
}

func (c *capturedContext) Status() int {
	if c.status != 0 {
		return c.status
	}
	return c.inner.Status()
}

func (c *capturedContext) SetHeader(name, value string) {
	c.header.Set(name, value)
}

func (c *capturedContext) AppendHeader(name, value string) {
	c.header.Add(name, value)
}

func (c *capturedContext) BodyWriter() io.Writer {
	return &c.body
}

func (c *capturedContext) Unwrap() huma.Context {
	return c.inner
}

func (c *capturedContext) HTTPResponse() *http.Response {
	header := c.header.Clone()
	if header == nil {
		header = make(http.Header)
	}
	status := c.Status()
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{
		StatusCode: status,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(c.body.Bytes())),
	}
}

func (c *capturedContext) ApplyHTTPResponse(resp *http.Response) {
	if resp == nil {
		return
	}
	c.status = resp.StatusCode
	c.header = resp.Header.Clone()
	c.body.Reset()
	if resp.Body != nil {
		body, _ := io.ReadAll(resp.Body)
		c.body.Write(body)
		resp.Body = io.NopCloser(bytes.NewReader(body))
	}
}

func (c *capturedContext) Flush() {
	// Header merge semantics mirror upstream mergeResponseHeaders
	// (vendor/.../src/api/dispatch.ts:86-100): `set-cookie` appends
	// (multiple cookies are legal) while every other header replaces.
	// Flushing with Append for all names would duplicate a header the
	// handler (or an OnResponse hook) intentionally overwrote.
	for name, values := range c.header {
		if isSetCookieHeader(name) {
			for _, value := range values {
				c.inner.AppendHeader(name, value)
			}
			continue
		}
		for i, value := range values {
			if i == 0 {
				c.inner.SetHeader(name, value)
			} else {
				c.inner.AppendHeader(name, value)
			}
		}
	}
	if c.status != 0 {
		c.inner.SetStatus(c.status)
	}
	if c.body.Len() > 0 {
		_, _ = c.inner.BodyWriter().Write(c.body.Bytes())
	}
}

type requestOverrideContext struct {
	inner   huma.Context
	request *http.Request
}

func (c *requestOverrideContext) Operation() *huma.Operation {
	return c.inner.Operation()
}

func (c *requestOverrideContext) Context() context.Context {
	return c.inner.Context()
}

func (c *requestOverrideContext) TLS() *tls.ConnectionState {
	return c.inner.TLS()
}

func (c *requestOverrideContext) Version() huma.ProtoVersion {
	return c.inner.Version()
}

func (c *requestOverrideContext) Method() string {
	return c.request.Method
}

func (c *requestOverrideContext) Host() string {
	return c.request.Host
}

func (c *requestOverrideContext) RemoteAddr() string {
	return c.request.RemoteAddr
}

func (c *requestOverrideContext) URL() url.URL {
	return *c.request.URL
}

func (c *requestOverrideContext) Param(name string) string {
	return c.inner.Param(name)
}

func (c *requestOverrideContext) Query(name string) string {
	return c.request.URL.Query().Get(name)
}

func (c *requestOverrideContext) Header(name string) string {
	return c.request.Header.Get(name)
}

func (c *requestOverrideContext) EachHeader(cb func(name, value string)) {
	for name, values := range c.request.Header {
		for _, value := range values {
			cb(name, value)
		}
	}
}

func (c *requestOverrideContext) BodyReader() io.Reader {
	if c.request.Body == nil {
		return nil
	}
	return c.request.Body
}

func (c *requestOverrideContext) GetMultipartForm() (*multipart.Form, error) {
	return c.inner.GetMultipartForm()
}

func (c *requestOverrideContext) SetReadDeadline(deadline time.Time) error {
	return c.inner.SetReadDeadline(deadline)
}

func (c *requestOverrideContext) SetStatus(code int) {
	c.inner.SetStatus(code)
}

func (c *requestOverrideContext) Status() int {
	return c.inner.Status()
}

func (c *requestOverrideContext) SetHeader(name, value string) {
	c.inner.SetHeader(name, value)
}

func (c *requestOverrideContext) AppendHeader(name, value string) {
	c.inner.AppendHeader(name, value)
}

func (c *requestOverrideContext) BodyWriter() io.Writer {
	return c.inner.BodyWriter()
}

func (c *requestOverrideContext) Unwrap() huma.Context {
	return c.inner
}

func requestFromContext(ctx huma.Context) *http.Request {
	// requestFromContext rebuilds a best-effort *http.Request from a
	// huma.Context for request-aware callbacks (e.g. TrustedOriginsFunc).
	//
	// Cloning limits vs upstream safeCloneRequest/ctx.request.clone():
	//   - The body is referenced, not cloned: BodyReader is passed through,
	//     so a consumer that reads it drains the handler's stream. There is
	//     no buffering or rewind.
	//   - Only method, URL, Host, RemoteAddr, and headers are carried over.
	//     TLS state, trailers, form/multipart caches, and the request context
	//     values are not propagated (a fresh background context applies).
	//   - Plugin OnRequest replacements are visible only where the middleware
	//     swaps in a requestOverrideContext; Param() still resolves from the
	//     inner route context and GetMultipartForm is not overridden.
	reqURL := ctx.URL()
	var body io.Reader
	if reader := ctx.BodyReader(); reader != nil {
		body = reader
	}
	req, _ := http.NewRequest(ctx.Method(), reqURL.String(), body)
	req.Host = ctx.Host()
	req.RemoteAddr = ctx.RemoteAddr()
	ctx.EachHeader(func(name, value string) {
		req.Header.Add(name, value)
	})
	return req
}

func writeHookError(api huma.API, ctx huma.Context, err error) {
	if statusErr, ok := err.(huma.StatusError); ok {
		_ = huma.WriteErr(api, ctx, statusErr.GetStatus(), statusErr.Error())
		return
	}
	_ = huma.WriteErr(api, ctx, http.StatusInternalServerError, "unexpected error occurred", err)
}

func callAPIErrorHandler(opts types.Options, ctx huma.Context) {
	if routes.APIErrorHandled(ctx) {
		return
	}
	status := ctx.Status()
	if status < http.StatusBadRequest {
		return
	}
	// When Throw=true the error already propagated as a Go error through
	// registerAuthOperation; skip the HTTP-level handler to avoid double handling.
	if opts.OnAPIError.Throw {
		return
	}
	if opts.OnAPIError.ErrorURL != "" {
		statusErr := extractStatusError(ctx)
		redirectURL := opts.OnAPIError.ErrorURL + "?error=" + url.QueryEscape(http.StatusText(statusErr.GetStatus())) + "&message=" + url.QueryEscape(statusErr.Error())
		ctx.SetHeader("Location", redirectURL)
		ctx.SetStatus(http.StatusFound)
		return
	}
	if opts.OnAPIError.OnError == nil {
		return
	}
	opts.OnAPIError.OnError(extractStatusError(ctx), ctx)
}

func extractStatusError(ctx huma.Context) huma.StatusError {
	base := unwrapContext(ctx)
	captured, ok := base.(*capturedContext)
	if !ok {
		return huma.NewError(ctx.Status(), http.StatusText(ctx.Status()))
	}

	var model huma.ErrorModel
	if err := json.Unmarshal(captured.body.Bytes(), &model); err == nil {
		if model.Status == 0 {
			model.Status = ctx.Status()
		}
		if model.Title == "" {
			model.Title = http.StatusText(model.Status)
		}
		if model.Status != 0 || model.Detail != "" || model.Title != "" {
			return &model
		}
	}

	detail := captured.body.String()
	if detail == "" {
		detail = http.StatusText(ctx.Status())
	}
	return huma.NewError(ctx.Status(), detail)
}

func unwrapContext(ctx huma.Context) huma.Context {
	for {
		unwrapper, ok := ctx.(interface{ Unwrap() huma.Context })
		if !ok {
			return ctx
		}
		ctx = unwrapper.Unwrap()
	}
}

func hasPluginRouteHooks(opts types.Options) bool {
	for _, p := range opts.Plugins {
		rh := p.RouteHooks()
		if len(rh.Before) > 0 || len(rh.After) > 0 {
			return true
		}
	}
	return false
}

// hasPluginTSRouteHooks reports whether any plugin declares
// TypeScript-faithful route hooks (PluginTSRouteHooksProvider, mirroring
// upstream's plugin.hooks.before/after). It gates the lifecycle middleware
// alongside the legacy Huma-shaped hooks.
func hasPluginTSRouteHooks(opts types.Options) bool {
	for _, p := range opts.Plugins {
		provider, ok := p.(types.PluginTSRouteHooksProvider)
		if !ok {
			continue
		}
		hooks := provider.TSRouteHooks()
		if len(hooks.Before) > 0 || len(hooks.After) > 0 {
			return true
		}
	}
	return false
}

func hasPluginRequestLifecycle(opts types.Options) bool {
	for _, p := range opts.Plugins {
		if provider, ok := p.(types.PluginOnRequestProvider); ok && provider.OnRequest() != nil {
			return true
		}
		if provider, ok := p.(types.PluginOnResponseProvider); ok && provider.OnResponse() != nil {
			return true
		}
		if provider, ok := p.(types.PluginMiddlewareProvider); ok && len(provider.Middlewares()) > 0 {
			return true
		}
		if provider, ok := p.(types.PluginRateLimitProvider); ok && len(provider.RateLimitRules()) > 0 {
			return true
		}
	}
	return false
}

func pluginMiddlewareMatches(ctx huma.Context, pattern string, basePath string) bool {
	path := normalizeRateLimitPath(ctx.URL().Path, basePath)
	if pattern == "" {
		return false
	}
	if !slices.Contains([]rune(pattern), '*') {
		return path == pattern
	}
	matched, err := stdpath.Match(pattern, path)
	return err == nil && matched
}

// disabledPathMatched reports whether the upstream-style route path is
// disabled. Matching uses the same normalization as the request-path helpers
// above (leading slash, no trailing slash, :param/{param} equivalence) so
// gating in Router and middleware path handling cannot disagree on spelling:
// "/verify-email/", "verify-email", and "/verify-email" all disable the
// route, and "/reset-password/:token" matches Huma's
// "/reset-password/{token}" registration.
func disabledPathMatched(disabled []string, route string) bool {
	want := normalizeDisabledPath(route)
	for _, entry := range disabled {
		if normalizeDisabledPath(entry) == want {
			return true
		}
	}
	return false
}

// normalizeDisabledPath canonicalizes a DisabledPaths entry or route key for
// comparison. It must stay in sync with normalizeRateLimitPath: both strip
// the base-path-relative form down to a leading-slash path.
func normalizeDisabledPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return path
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if len(path) > 1 {
		path = strings.TrimSuffix(path, "/")
	}
	// Treat Huma "{param}" segments and upstream ":param" segments as equal.
	if strings.Contains(path, "{") {
		parts := strings.Split(path, "/")
		for i, part := range parts {
			if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") && len(part) > 2 {
				parts[i] = ":" + part[1:len(part)-1]
			}
		}
		path = strings.Join(parts, "/")
	}
	return path
}

// apiLogf reports a framework parity note via Options.Logger when logging is
// configured, enabled, and the level passes the configured minimum
// (types.ShouldPublishLog, default "warn" — mirroring upstream createLogger
// level filtering in vendor/.../core/src/env/logger.ts:106-112). It stays
// quiet otherwise, preserving the historical quiet default (mirrors
// secretWarnf/loggerFromOptions gating in package auth). Level follows the
// upstream logger levels ("debug", "info", "warn", "error"); "success" is
// normalized to "info" for custom handlers.
func apiLogf(opts types.Options, level, format string, args ...any) {
	if opts.Logger.Disabled || opts.Logger.Log == nil {
		return
	}
	msgLevel := types.LogLevel(level)
	if msgLevel == types.LogLevelSuccess {
		msgLevel = types.LogLevelInfo
	}
	if !types.ShouldPublishLog(opts.Logger.Level, msgLevel) {
		return
	}
	opts.Logger.Log(types.NormalizeLogLevelForHandler(types.LogLevel(level)), fmt.Sprintf(format, args...))
}

// --- Dynamic base URL (upstream baseURL object form) ---

// ExpandDynamicBaseURLOrigins expands a DynamicBaseURLConfig into the static
// trusted-origin patterns upstream derives from it in getTrustedOrigins
// (vendor/.../src/context/helpers.ts:108-160):
//
//   - every allowedHosts entry that already contains "://" is kept as-is;
//   - a bare hostname gains "https://<host>" unless Protocol is "http", and
//     gains "http://<host>" when Protocol is "http" or "auto" or the host is
//     a loopback host (localhost, *.localhost, 127.0.0.0/8, ::1). An empty
//     Protocol behaves like upstream's unset value (https required, http only
//     for loopback), NOT like "auto": this is faithful to the upstream code,
//     which only pushes both schemes for an explicit "auto".
//   - the Fallback origin (scheme://host, default port dropped) is appended
//     when Fallback parses as an absolute http(s) URL.
//
// BetterAuth pre-merges this expansion into Options.TrustedOrigins so the
// whole stack (IsTrustedOrigin, route redirect checks, middleware) honors
// allowed hosts; originTrustedForRequest re-derives it per request so direct
// Router callers are covered too. Static BaseURL behavior is unchanged when
// DynamicBaseURL is nil (returns nil).
//
// Upstream TypeScript names: getTrustedOrigins (dynamic branch),
// matchesHostPattern (allowlist check), getOrigin (fallback origin).
func ExpandDynamicBaseURLOrigins(cfg *types.DynamicBaseURLConfig) []string {
	if cfg == nil {
		return nil
	}
	var out []string
	for _, raw := range cfg.AllowedHosts {
		host := strings.TrimSpace(raw)
		if host == "" {
			continue
		}
		if strings.Contains(host, "://") {
			out = append(out, host)
			continue
		}
		proto := cfg.Protocol
		if proto == "" || proto == types.BaseURLProtocolHTTPS || proto == types.BaseURLProtocolAuto {
			out = append(out, "https://"+host)
		}
		if proto == types.BaseURLProtocolHTTP || proto == types.BaseURLProtocolAuto || isLoopbackHost(host) {
			out = append(out, "http://"+host)
		}
	}
	if strings.TrimSpace(cfg.Fallback) != "" {
		if origin, ok := originOfRawURL(cfg.Fallback); ok {
			out = append(out, origin)
		}
	}
	return out
}

// originOfRawURL returns the canonical "scheme://host[:port]" origin of an
// absolute http(s) URL, dropping explicit default ports and bracketing IPv6
// hosts. It mirrors the webOriginOfURL/getOrigin step upstream applies to
// the dynamic fallback (helpers.ts:131-134).
func originOfRawURL(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	host := strings.ToLower(u.Hostname())
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return "", false
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port := u.Port(); port != "" {
		if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
			return scheme + "://" + host, true
		}
		return scheme + "://" + host + ":" + port, true
	}
	return scheme + "://" + host, true
}

// originTrustedForRequest reports whether origin is trusted for the request,
// covering both the static path (BaseURL origin, TrustedOrigins,
// TrustedOriginsFunc via types.IsTrustedOrigin) and the dynamic path
// (Options.DynamicBaseURL expansion). The dynamic leg makes direct Router
// callers — which bypass BetterAuth's pre-merge — behave the same as
// BetterAuth-constructed instances.
func originTrustedForRequest(origin string, opts types.Options, r *http.Request) bool {
	if types.IsTrustedOrigin(origin, opts, r) {
		return true
	}
	if opts.DynamicBaseURL == nil {
		return false
	}
	for _, pattern := range ExpandDynamicBaseURLOrigins(opts.DynamicBaseURL) {
		if types.MatchesOriginPattern(origin, pattern) {
			return true
		}
	}
	return false
}

// isLoopbackHost reports whether hostport is a loopback host for developer
// ergonomics, mirroring upstream isLoopbackHost
// (vendor/.../core/src/utils/host.ts:390-393): IPv4 127.0.0.0/8, IPv6 ::1
// (including IPv4-mapped forms), the literal "localhost", and RFC 6761
// ".localhost" subdomains. Accepts bare hosts, hosts with ports, and
// bracketed IPv6.
func isLoopbackHost(hostport string) bool {
	h := strings.TrimSpace(hostport)
	if addr, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil {
		return addr.WithZone("").Unmap().IsLoopback()
	}
	name := h
	if host, _, err := splitHostPortLenient(h); err == nil {
		name = host
	}
	name = strings.ToLower(strings.TrimSuffix(strings.Trim(strings.TrimSpace(name), "[]"), "."))
	if idx := strings.Index(name, "%"); idx != -1 {
		name = name[:idx]
	}
	return name == "localhost" || strings.HasSuffix(name, ".localhost")
}

// splitHostPortLenient strips a trailing :port from IPv4/FQDN hosts without
// rejecting bare IPv6 literals (which contain multiple colons and carry no
// port). It returns an error only to signal "no port present".
func splitHostPortLenient(hostport string) (string, string, error) {
	if strings.HasPrefix(hostport, "[") {
		if end := strings.Index(hostport, "]"); end != -1 {
			rest := hostport[end+1:]
			if strings.HasPrefix(rest, ":") && len(rest) > 1 {
				return hostport[1:end], rest[1:], nil
			}
			return hostport[1:end], "", fmt.Errorf("auth: no port in %q", hostport)
		}
	}
	if strings.Count(hostport, ":") != 1 {
		return hostport, "", fmt.Errorf("auth: no port in %q", hostport)
	}
	idx := strings.LastIndex(hostport, ":")
	return hostport[:idx], hostport[idx+1:], nil
}

// stripPort removes a trailing :port from a host for loopback checks,
// tolerating bare IPv6 literals.
func stripPort(host string) string {
	if h, _, err := splitHostPortLenient(strings.TrimSpace(host)); err == nil && h != "" {
		return h
	}
	return strings.Trim(strings.TrimSpace(host), "[]")
}

// --- Trailing-slash handling (Advanced.SkipTrailingSlashes) ---

// middlewareRateLimitPath normalizes the request path for rate-limit keying.
// It always applies normalizeRateLimitPath (base-path-relative,
// leading-slash form); when Advanced.SkipTrailingSlashes is set it
// additionally strips one trailing slash so "/get-session/" keys like
// "/get-session", mirroring upstream's skipTrailingSlashes router
// normalization for the middleware's decisions.
//
// LIMITATION (loud, intentional): huma matches registered route paths
// exactly, so making a trailing-slash request actually REACH a handler still
// requires slash-variant route registration in auth/api/routes (sibling
// owner). This normalization only aligns middleware decisions (rate-limit
// keys) with the canonical spelling.
func middlewareRateLimitPath(requestPath, basePath string, opts types.Options) string {
	path := normalizeRateLimitPath(requestPath, basePath)
	if opts.Advanced.SkipTrailingSlashes && len(path) > 1 {
		path = strings.TrimSuffix(path, "/")
	}
	return path
}

// --- Trusted proxies and IPv6 subnets (Advanced.IPAddress) ---

// RequestClientIP resolves the client IP for a huma request with
// trusted-proxy awareness, mirroring upstream getIP/getIPFromHeader
// (vendor/.../core/src/utils/ip.ts:293-385):
//
//   - Advanced.IPAddress.DisableIPTracking returns "" (caller skips
//     limiting), mirroring upstream's null.
//   - Headers are walked in Advanced.IPAddress.IPAddressHeaders order
//     (default X-Forwarded-For, then X-Real-IP).
//   - With Advanced.IPAddress.TrustedProxies set, an X-Forwarded-For chain is
//     walked right to left, trusted hops (IPs or CIDR ranges, IPv4 and IPv6)
//     are skipped, and the first untrusted hop is the client IP. A malformed
//     hop fails that header closed (falls through to the next header),
//     mirroring upstream's null. Malformed proxy entries are ignored
//     (BetterAuth warns about them at construction, mirroring upstream's
//     "Ignoring invalid trustedProxies" warning); with no valid proxy entry
//     the chain mode does not engage.
//   - Without proxies, behavior is exactly requestIP (single-value XFF
//     trusted, multi-hop chains unresolvable without the TrustedProxyHeaders
//     boolean opt-in, RemoteAddr fallback).
//   - IPv6 results are collapsed to the Advanced.IPAddress.IPv6Subnet prefix
//     (upstream default /64 when the proxy path is active) and IPv4-mapped
//     IPv6 is reported as IPv4, mirroring normalizeIP.
//
// When neither TrustedProxies nor IPv6Subnet is configured this delegates to
// requestIP byte-for-byte, so default deployments are unaffected.
//
// NOTE: plugin rate-limit rule matching (resolvePluginRateLimit in
// rate_limiter.go) still resolves via requestIP; proxy-aware IP applies to
// the global rate-limit middleware selected here.
//
// Upstream TypeScript names: getIP, getIPFromHeader, normalizeIP.
func RequestClientIP(ctx huma.Context, opts types.Options) string {
	if len(opts.Advanced.IPAddress.TrustedProxies) == 0 && opts.Advanced.IPAddress.IPv6Subnet == 0 {
		return requestIP(ctx, opts)
	}
	return requestIPWithProxies(ctx, opts)
}

func requestIPWithProxies(ctx huma.Context, opts types.Options) string {
	if opts.Advanced.IPAddress.DisableIPTracking {
		return ""
	}
	headers := opts.Advanced.IPAddress.IPAddressHeaders
	if len(headers) == 0 {
		headers = defaultIPHeaders
	}
	trustChain := opts.Advanced.TrustedProxyHeaders != nil && *opts.Advanced.TrustedProxyHeaders
	networks := parseTrustedProxies(opts.Advanced.IPAddress.TrustedProxies)
	mask := ipv6MaskBits(opts.Advanced.IPAddress.IPv6Subnet)
	for _, header := range headers {
		value := strings.TrimSpace(ctx.Header(header))
		if value == "" {
			continue
		}
		if strings.EqualFold(header, "X-Forwarded-For") {
			hops := splitIPChain(value)
			if len(hops) == 0 {
				continue
			}
			if len(networks) > 0 {
				if ip, ok := walkProxyChain(hops, networks); ok {
					return normalizeClientIP(ip, mask)
				}
				continue
			}
			if len(hops) > 1 && !trustChain {
				// Multi-hop chain with no trusted-proxy configuration:
				// unresolvable (leftmost token is client-spoofable).
				continue
			}
			if ip := stripPort(hops[0]); ip != "" {
				return normalizeClientIP(ip, mask)
			}
			continue
		}
		// Non-XFF headers carry a single value upstream too; it must parse
		// as an IP to be trusted on the proxy path.
		if ip := strings.Trim(strings.TrimSpace(value), "[]"); ip != "" {
			if _, err := netip.ParseAddr(ip); err != nil {
				continue
			}
			return normalizeClientIP(stripPort(value), mask)
		}
	}
	if ip := stripPort(strings.TrimSpace(ctx.RemoteAddr())); ip != "" {
		return normalizeClientIP(ip, mask)
	}
	return ""
}

// splitIPChain splits an X-Forwarded-For value into trimmed non-empty hops.
func splitIPChain(value string) []string {
	parts := strings.Split(value, ",")
	hops := make([]string, 0, len(parts))
	for _, part := range parts {
		if hop := strings.TrimSpace(part); hop != "" {
			hops = append(hops, hop)
		}
	}
	return hops
}

// walkProxyChain walks hops right to left, skipping hops inside networks,
// and returns the first untrusted hop. A hop that does not parse as an IP
// fails the walk (false), mirroring upstream's fail-closed null. When every
// hop is trusted it returns false so the caller falls through to the next
// header. IPv4-mapped IPv6 hops compare as their underlying IPv4, mirroring
// upstream ipToBytes.
func walkProxyChain(hops []string, networks []netip.Prefix) (string, bool) {
	for i := len(hops) - 1; i >= 0; i-- {
		hop := strings.Trim(strings.TrimSpace(hops[i]), "[]")
		addr, err := netip.ParseAddr(hop)
		if err != nil {
			return "", false
		}
		addr = addr.WithZone("").Unmap()
		trusted := false
		for _, network := range networks {
			base := network.Masked().Addr().WithZone("").Unmap()
			family := base.BitLen()
			if family != addr.BitLen() {
				continue
			}
			if netip.PrefixFrom(base, network.Bits()).Contains(addr) {
				trusted = true
				break
			}
		}
		if !trusted {
			return hop, true
		}
	}
	return "", false
}

// parseTrustedProxies parses trusted-proxy entries into prefixes, dropping
// malformed entries (mirroring upstream: a config typo must not leave chain
// mode enabled-but-empty). Bare IPs become host prefixes (/32, /128).
// Entries are trimmed (additive hardening over upstream's raw split).
func parseTrustedProxies(entries []string) []netip.Prefix {
	var out []netip.Prefix
	for _, entry := range entries {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			continue
		}
		if prefix, err := netip.ParsePrefix(trimmed); err == nil {
			out = append(out, prefix.Masked())
			continue
		}
		if addr, err := netip.ParseAddr(strings.Trim(trimmed, "[]")); err == nil {
			addr = addr.WithZone("").Unmap()
			out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}
	return out
}

// FindInvalidTrustedProxies reports entries that are neither a valid IP
// address nor a valid IP/prefix CIDR range (IPv4 or IPv6), mirroring
// upstream findInvalidTrustedProxies
// (vendor/.../core/src/utils/ip.ts:283-285). BetterAuth warns about the
// returned entries at construction and the resolver ignores them. Empty
// entries are invalid (mirroring upstream, which only filters falsy values
// downstream, not here).
func FindInvalidTrustedProxies(entries []string) []string {
	var invalid []string
	for _, entry := range entries {
		trimmed := strings.TrimSpace(entry)
		valid := false
		if trimmed != "" {
			if _, err := netip.ParsePrefix(trimmed); err == nil {
				valid = true
			} else if _, err := netip.ParseAddr(strings.Trim(trimmed, "[]")); err == nil {
				valid = true
			}
		}
		if !valid {
			invalid = append(invalid, entry)
		}
	}
	return invalid
}

// ipv6MaskBits resolves the IPv6Subnet option to a prefix length for
// collapsing IPv6 rate-limit keys, mirroring upstream normalizeIP's default
// of 64. Values outside 1-128 fall back: unset/invalid (<=0) to the
// upstream default 64, oversized (>128) to 128 (full address, i.e. no
// masking — mirroring upstream, where prefix >= 128 skips masking).
// Callers only reach here on the proxy path (see RequestClientIP); the
// legacy requestIP path never masks.
func ipv6MaskBits(subnet int) int {
	if subnet <= 0 {
		return 64
	}
	if subnet > 128 {
		return 128
	}
	return subnet
}

// normalizeClientIP canonicalizes a resolved client IP: IPv4-mapped IPv6 is
// reported as IPv4, other IPv6 is lowercased and collapsed to the mask
// prefix, IPv4 passes through. Unparseable input passes through lowercased
// (mirroring upstream normalizeIP's as-is fallback and requestIP's
// stripPort-only handling).
func normalizeClientIP(ip string, mask int) string {
	trimmed := strings.Trim(strings.TrimSpace(ip), "[]")
	addr, err := netip.ParseAddr(trimmed)
	if err != nil {
		return strings.ToLower(ip)
	}
	addr = addr.WithZone("").Unmap()
	if addr.Is4() {
		return addr.String()
	}
	return netip.PrefixFrom(addr, mask).Masked().Addr().String()
}

// --- Rate-limit storage-backend selection ---

// rateLimitBackendKind selects the storage primitive behind the rate-limit
// middleware. Memory is the default when no selector is configured; custom,
// secondary, and database honor live backends (see ValidateRateLimitStorage).
type rateLimitBackendKind int

const (
	rateLimitBackendMemory rateLimitBackendKind = iota
	rateLimitBackendCustom
	rateLimitBackendSecondary
	rateLimitBackendDatabase
)

// ValidateRateLimitStorage reports whether Options.RateLimit storage
// selection is routable in this runtime (pure: no I/O):
//
//   - CustomStorage set → routable (Storage is ignored, mirroring upstream
//     getRateLimitStorage's customStorage-first precedence).
//   - Storage "" or "memory" → routable (explicit in-memory backend; see the
//     memoryStoreMaxEntries bound documented in rate_limiter.go — this is the
//     loud, documented default, never a silent fallback).
//   - Storage "" with SecondaryStorage present → routable as
//     secondary-storage, mirroring upstream's default (ctx.rateLimit.storage
//     falls back to "secondary-storage" when secondaryStorage is configured).
//   - Storage "secondary-storage" → routable only with SecondaryStorage
//     present (consumed via SecondaryStorage.Increment, mirroring upstream's
//     secondary-storage consume); without a backend it is a descriptive
//     error.
//   - Storage "database" → routable with Options.DB present (atomically
//     consumed via adapter IncrementOne by DatabaseRateLimitStorage,
//     mirroring upstream's createDatabaseStorageWrapper); without a database
//     it is a descriptive error. The rate-limit table must be migrated
//     (schema owner); a missing table surfaces as request-time 500s, never
//     silent passes.
//   - any other literal → descriptive error (ValidateOptions rejects it too).
//
// BetterAuth calls this and returns the error (signature stays (Auth,
// error)); the Router middleware re-checks for direct callers and degrades
// to the documented in-memory backend with a Logger warning when configured.
func ValidateRateLimitStorage(opts types.Options) error {
	if opts.RateLimit.CustomStorage != nil {
		return nil
	}
	switch opts.RateLimit.Storage {
	case "", types.RateLimitStorageMemory:
		return nil
	case types.RateLimitStorageSecondary:
		if opts.SecondaryStorage == nil {
			return fmt.Errorf("auth: options.RateLimit.Storage=%q requires options.SecondaryStorage (no backend configured; in-memory is the explicit default — leave Storage unset or %q)", types.RateLimitStorageSecondary, types.RateLimitStorageMemory)
		}
		return nil
	case types.RateLimitStorageDatabase:
		if opts.DB == nil {
			return fmt.Errorf("auth: options.RateLimit.Storage=%q requires options.DB (no database configured; in-memory is the explicit default — leave Storage unset or %q)", types.RateLimitStorageDatabase, types.RateLimitStorageMemory)
		}
		return nil
	default:
		return fmt.Errorf("auth: options.RateLimit.Storage must be %q, %q, or %q, got %q", types.RateLimitStorageMemory, types.RateLimitStorageDatabase, types.RateLimitStorageSecondary, opts.RateLimit.Storage)
	}
}

// selectRateLimitBackend maps validated options to the enforcement
// primitive. Callers must consult ValidateRateLimitStorage first; an invalid
// selection degrades to memory here (the middleware logs the downgrade).
func selectRateLimitBackend(opts types.Options) rateLimitBackendKind {
	if opts.RateLimit.CustomStorage != nil {
		return rateLimitBackendCustom
	}
	storage := opts.RateLimit.Storage
	if storage == "" {
		if opts.SecondaryStorage != nil {
			return rateLimitBackendSecondary
		}
		return rateLimitBackendMemory
	}
	if storage == types.RateLimitStorageSecondary && opts.SecondaryStorage != nil {
		return rateLimitBackendSecondary
	}
	if storage == types.RateLimitStorageDatabase && opts.DB != nil {
		return rateLimitBackendDatabase
	}
	return rateLimitBackendMemory
}

// rateLimitNeedsCustomMiddleware reports whether Router must install the
// storage/proxy-aware rate-limit middleware instead of the legacy one. It is
// true exactly when the legacy path cannot honor the configuration: a
// non-default storage backend, trusted-proxy/IPv6-subnet resolution, or
// trailing-slash-tolerant keying. Default configurations keep the legacy
// middleware byte-for-byte, so existing deployments are unaffected.
func rateLimitNeedsCustomMiddleware(opts types.Options) bool {
	if opts.RateLimit.CustomStorage != nil {
		return true
	}
	if storage := opts.RateLimit.Storage; storage != "" && storage != types.RateLimitStorageMemory {
		return true
	}
	if opts.SecondaryStorage != nil {
		// Unset Storage defaults to secondary-storage upstream when a
		// secondary backend is present (see ValidateRateLimitStorage).
		return true
	}
	if len(opts.Advanced.IPAddress.TrustedProxies) > 0 || opts.Advanced.IPAddress.IPv6Subnet != 0 {
		return true
	}
	return opts.Advanced.SkipTrailingSlashes
}

// useRateLimitMiddlewareWithStorage enforces rate limits with the selected
// storage backend and proxy-aware client-IP resolution. Rule resolution
// (enabled gate, special rules, static custom rules, function resolvers, key
// shape) is shared with resolveRateLimit in rate_limiter.go via
// applyRateLimitRules — keep the two call sites in sync; only the IP source
// (RequestClientIP), the path form (middlewareRateLimitPath), and the
// enforcement primitive differ.
//
// Enforcement per backend, mirroring upstream onRequestRateLimit's
// single-step consume (vendor/.../src/api/rate-limiter/index.ts:418-437):
//
//   - custom: one CustomStorage.Consume call in the request phase (no
//     response-phase write-back, so concurrent requests cannot pass a stale
//     read). A backend error fails the request with 500 (mirroring upstream,
//     where a storage throw fails the request) and is reported via
//     Options.Logger when configured; it is deliberately NOT routed through
//     OnAPIError (an operational storage failure must not trigger error-URL
//     redirects).
//   - secondary: one SecondaryStorage.Increment(key, windowSeconds) call;
//     the post-increment count is the window count (mirroring upstream's
//     secondary-storage consume: allowed while count <= max, retryAfter is
//     the window). Increment errors fail the request the same way.
//   - database: one atomic consumeDatabaseRateLimit step (create-guarded
//     open, guarded reset/increment, re-read loop), mirroring upstream's
//     createDatabaseStorageWrapper. Storage errors fail the request the same
//     way.
//   - memory: the legacy two-phase check/record pair (isRateLimited before
//     the handler, recordRateLimit after), identical to the legacy
//     middleware.
//
// Limited responses keep the upstream {"message"} body and X-Retry-After
// header via writeRateLimitResponse.
func useRateLimitMiddlewareWithStorage(api huma.API, basePath string, opts types.Options) {
	api.UseMiddleware(func(ctx huma.Context, next func(huma.Context)) {
		config, ok := resolveRateLimitWithProxies(ctx, basePath, opts)
		if !ok {
			next(ctx)
			return
		}
		backend := selectRateLimitBackend(opts)
		if err := ValidateRateLimitStorage(opts); err != nil {
			// Direct Router use bypasses BetterAuth validation: stay up on
			// the explicit in-memory default and note the downgrade when
			// logging is configured (BetterAuth itself returns this error).
			apiLogf(opts, "warn", "auth: rate-limit storage selection invalid (%v); using the explicit in-memory backend", err)
			backend = rateLimitBackendMemory
		}
		switch backend {
		case rateLimitBackendCustom:
			rule := types.RateLimitRule{Window: int(config.Window / time.Second), Max: config.Max}
			result, err := opts.RateLimit.CustomStorage.Consume(config.Key, rule)
			if err != nil {
				apiLogf(opts, "error", "auth: custom rate-limit storage consume failed for key %q: %v", config.Key, err)
				writeHookError(api, ctx, huma.NewError(http.StatusInternalServerError, "rate limit storage error"))
				return
			}
			if !result.Allowed {
				writeRateLimitResponse(ctx, retryAfterOrWindow(result.RetryAfter, config.Window))
				return
			}
			next(ctx)
		case rateLimitBackendSecondary:
			windowSeconds := int(config.Window / time.Second)
			count, err := opts.SecondaryStorage.Increment(config.Key, windowSeconds)
			if err != nil {
				apiLogf(opts, "error", "auth: secondary-storage rate-limit increment failed for key %q: %v", config.Key, err)
				writeHookError(api, ctx, huma.NewError(http.StatusInternalServerError, "rate limit storage error"))
				return
			}
			if count > int64(config.Max) {
				writeRateLimitResponse(ctx, windowSeconds)
				return
			}
			next(ctx)
		case rateLimitBackendDatabase:
			windowSeconds := int(config.Window / time.Second)
			storage := DatabaseRateLimitStorage{
				DB:                   opts.DB,
				Model:                opts.RateLimit.ModelName,
				LongestWindowSeconds: longestConfiguredRateLimitWindow(opts),
				Background:           databaseRateLimitBackground(opts),
				OnPruneError:         databaseRateLimitPruneLogger(opts),
			}
			allowed, retryAfter, err := consumeDatabaseRateLimit(
				ctx.Context(), storage.DB, storage.modelName(), config.Key,
				windowSeconds, config.Max, storage.LongestWindowSeconds,
				storage.now(), storage.Background, storage.OnPruneError,
			)
			if err != nil {
				apiLogf(opts, "error", "auth: database rate-limit consume failed for key %q: %v", config.Key, err)
				writeHookError(api, ctx, huma.NewError(http.StatusInternalServerError, "rate limit storage error"))
				return
			}
			if !allowed {
				writeRateLimitResponse(ctx, retryAfter)
				return
			}
			next(ctx)
		default:
			if retryAfter, limited := isRateLimited(config); limited {
				writeRateLimitResponse(ctx, retryAfter)
				return
			}
			next(ctx)
			recordRateLimit(config)
		}
	})
}

// databaseRateLimitBackground returns the prune dispatcher for the database
// backend: the configured background-tasks handler when set, nil (run
// synchronously in the request path) otherwise — mirroring upstream
// runInBackgroundOrAwait.
func databaseRateLimitBackground(opts types.Options) func(func()) {
	if handler := opts.Advanced.BackgroundTasks.Handler; handler != nil {
		return handler
	}
	return nil
}

// databaseRateLimitPruneLogger reports database prune failures via
// Options.Logger when configured, mirroring upstream's ctx.logger.error in
// deleteExpiredRows.
func databaseRateLimitPruneLogger(opts types.Options) func(error) {
	if opts.Logger.Disabled || opts.Logger.Log == nil {
		return nil
	}
	return func(err error) {
		opts.Logger.Log("error", fmt.Sprintf("auth: failed to prune expired rate-limit rows: %v", err))
	}
}

// resolveRateLimitWithProxies mirrors resolveRateLimit in rate_limiter.go
// (production-default enabled gate, proxy-aware client IP,
// base-path-relative path, shared rule folding, "ip|path" key) — keep the
// two in sync. Differences: RequestClientIP instead of requestIP (via the
// shared rateLimitClientIP helper), and middlewareRateLimitPath instead of
// normalizeRateLimitPath (trailing-slash tolerance when
// Advanced.SkipTrailingSlashes is set).
func resolveRateLimitWithProxies(ctx huma.Context, basePath string, opts types.Options) (resolvedRateLimit, bool) {
	if !rateLimitEnabled(opts) {
		return resolvedRateLimit{}, false
	}

	clientIP, ok := rateLimitClientIP(ctx, opts, true)
	if !ok {
		return resolvedRateLimit{}, false
	}

	path := middlewareRateLimitPath(ctx.URL().Path, basePath, opts)
	window, max, ok := applyRateLimitRules(ctx, path, opts)
	if !ok {
		return resolvedRateLimit{}, false
	}

	return resolvedRateLimit{
		Key:    clientIP + "|" + path,
		Window: window,
		Max:    max,
	}, true
}

// retryAfterOrWindow resolves an optional custom-storage RetryAfter to the
// X-Retry-After seconds, defaulting to the window (mirroring upstream's
// `retryAfter ?? currentWindow`).
func retryAfterOrWindow(retryAfter *int, window time.Duration) int {
	if retryAfter != nil && *retryAfter > 0 {
		return *retryAfter
	}
	if seconds := int(window / time.Second); seconds > 0 {
		return seconds
	}
	return 1
}

// --- Request state (upstream request-state.ts) ---
//
// Upstream keeps per-request state in an AsyncLocalStorage WeakMap
// (vendor/.../core/src/context/request-state.ts) so endpoint code can share
// values across the hook/handler pipeline without threading arguments. Go
// has no goroutine-local storage; the faithful equivalent here is explicit
// context propagation: the lifecycle middleware installs a fresh map per
// request (huma.WithValue layers it onto the request context) and hooks or
// handlers reach it via GetRequestState. The map itself is not synchronized:
// handlers must not share it across goroutines without their own locking,
// mirroring the single-request ownership upstream.
//
// Upstream TypeScript names: requestStateAsyncStorage (storage),
// runWithRequestState (installation), getCurrentRequestState (lookup).

// RequestBaseURLKey stores the per-request resolved dynamic baseURL (when
// Options.DynamicBaseURL is configured) in the request-state map. Route URL
// builders still use the static BaseURL; this key lets future handler
// adoption read the resolved value without changing handler signatures.
const RequestBaseURLKey = "auth.request.baseURL"

// requestStateKey is the huma context value key carrying the per-request
// state map. Unexported so only these helpers read/write it.
type requestStateKey struct{}

// NewRequestState returns a fresh per-request state store.
func NewRequestState() map[any]any {
	return make(map[any]any)
}

// WithRequestState returns ctx carrying state as its request-state store.
// A nil state installs a fresh map. The same map pointer is shared with the
// caller: mutations via GetRequestState/SetRequestState are visible on both
// sides, mirroring upstream's shared WeakMap store.
func WithRequestState(ctx huma.Context, state map[any]any) huma.Context {
	if state == nil {
		state = NewRequestState()
	}
	return huma.WithValue(ctx, requestStateKey{}, state)
}

// GetRequestState returns the request-state store carried by ctx, or nil
// when none was installed (e.g. outside the lifecycle middleware).
func GetRequestState(ctx huma.Context) map[any]any {
	if ctx == nil {
		return nil
	}
	state, _ := ctx.Context().Value(requestStateKey{}).(map[any]any)
	return state
}

// SetRequestState stores value under key in ctx's request-state store. It is
// a no-op when no store is installed. Values are owned by the request;
// callers must not retain the map past the request.
func SetRequestState(ctx huma.Context, key, value any) {
	if state := GetRequestState(ctx); state != nil {
		state[key] = value
	}
}

// --- Response-header merge ordering (upstream dispatch.ts) ---

// isSetCookieHeader reports whether name is the Set-Cookie header
// (case-insensitive). Only Set-Cookie accumulates across merge sources;
func isSetCookieHeader(name string) bool {
	return strings.EqualFold(strings.TrimSpace(name), "Set-Cookie")
}

// applyTSResponseHeaders copies TypeScript-faithful route-hook response
// headers onto the Huma context with upstream mergeResponseHeaders semantics
// (vendor/.../src/api/dispatch.ts:86-100): `set-cookie` appends (multiple
// cookies are legal) while every other header replaces. Nil contexts and
// empty maps are no-ops.
func applyTSResponseHeaders(ctx huma.Context, headers http.Header) {
	if ctx == nil || len(headers) == 0 {
		return
	}
	for name, values := range headers {
		if isSetCookieHeader(name) {
			for _, value := range values {
				ctx.AppendHeader(name, value)
			}
			continue
		}
		for i, value := range values {
			if i == 0 {
				ctx.SetHeader(name, value)
			} else {
				ctx.AppendHeader(name, value)
			}
		}
	}
}

// --- Trailing-slash registration (upstream skipTrailingSlashes) ---

// slashVariantAdapter wraps a huma.Adapter so every Handle registration also
// serves its trailing-slash spelling when Advanced.SkipTrailingSlashes is
// set, mirroring upstream's skipTrailingSlashes router normalization
// (vendor/.../src/api/index.ts:296). better-call normalizes the pathname
// before routing so one endpoint serves both spellings; Huma matches
// registered paths exactly, so the Go port registers both spellings with the
// same handler. Variant operations get a suffixed OperationID so OpenAPI
// documents stay unique; the canonical registration is untouched.
type slashVariantAdapter struct {
	inner huma.Adapter
	seen  map[string]struct{}
}

func (a *slashVariantAdapter) Handle(op *huma.Operation, h func(huma.Context)) {
	a.inner.Handle(op, h)
	if a == nil || a.inner == nil || op == nil {
		return
	}
	path := op.Path
	if path == "" || path == "/" || strings.HasSuffix(path, "/") {
		return
	}
	variant := path + "/"
	if a.seen == nil {
		a.seen = map[string]struct{}{}
	}
	if _, dup := a.seen[variant]; dup {
		return
	}
	a.seen[variant] = struct{}{}
	cp := *op
	cp.Path = variant
	if cp.OperationID != "" {
		cp.OperationID += "_trailingSlash"
	}
	a.inner.Handle(&cp, h)
}

func (a *slashVariantAdapter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.inner.ServeHTTP(w, r)
}

// --- Endpoint-conflict detection (upstream checkEndpointConflicts) ---

// EndpointConflict describes one path shared by multiple plugin endpoints
// with overlapping HTTP methods, mirroring the conflict entries upstream
// collects in checkEndpointConflicts
// (vendor/.../src/api/index.ts:58-171).
type EndpointConflict struct {
	// Path is the conflicting full endpoint path (basePath-joined).
	Path string
	// Plugins lists the conflicting plugin IDs in first-seen order.
	Plugins []string
	// ConflictingMethods lists the overlapping methods ("*" is upstream's
	// wildcard for endpoints without a declared method).
	ConflictingMethods []string
}

// FindEndpointConflicts collects plugin endpoint-path conflicts without
// logging, in plugin declaration order. Only plugin endpoints participate
// (upstream never compares core routes); endpoints without a path are
// skipped, and endpoints without a declared method count as "*".
func FindEndpointConflicts(basePath string, plugins []types.Plugin) []EndpointConflict {
	type entry struct {
		pluginID string
		methods  []string
	}
	registry := map[string][]entry{}
	var pathOrder []string
	add := func(path, pluginID string, methods []string) {
		if _, ok := registry[path]; !ok {
			pathOrder = append(pathOrder, path)
		}
		registry[path] = append(registry[path], entry{pluginID: pluginID, methods: methods})
	}
	for _, p := range plugins {
		if p == nil {
			continue
		}
		id := p.ID()
		for _, ep := range types.CollectPluginEndpoints([]types.Plugin{p}) {
			if ep.Path == "" {
				continue
			}
			full := joinEndpointPath(basePath, ep.Path)
			methods := endpointMethods(ep.Method)
			add(full, id, methods)
		}
	}
	var out []EndpointConflict
	for _, path := range pathOrder {
		entries := registry[path]
		if len(entries) < 2 {
			continue
		}
		methodOwners := map[string][]string{}
		var methodOrder []string
		hasConflict := false
		for _, e := range entries {
			for _, m := range e.methods {
				if _, ok := methodOwners[m]; !ok {
					methodOrder = append(methodOrder, m)
				}
				owners := append(methodOwners[m], e.pluginID)
				methodOwners[m] = owners
				if len(owners) > 1 {
					hasConflict = true
				}
				if m == "*" && len(entries) > 1 {
					hasConflict = true
				} else if m != "*" {
					if _, wildcard := methodOwners["*"]; wildcard {
						hasConflict = true
					}
				}
			}
			if _, wildcard := methodOwners["*"]; wildcard && len(entries) > 1 {
				hasConflict = true
			}
		}
		if !hasConflict {
			continue
		}
		seenPlugins := map[string]struct{}{}
		var pluginIDs []string
		for _, e := range entries {
			if _, ok := seenPlugins[e.pluginID]; !ok {
				seenPlugins[e.pluginID] = struct{}{}
				pluginIDs = append(pluginIDs, e.pluginID)
			}
		}
		var conflicting []string
		for _, m := range methodOrder {
			owners := methodOwners[m]
			if len(owners) > 1 || (m == "*" && len(entries) > 1) || (m != "*" && len(methodOwners["*"]) > 0) {
				conflicting = append(conflicting, m)
			}
		}
		out = append(out, EndpointConflict{Path: path, Plugins: pluginIDs, ConflictingMethods: conflicting})
	}
	return out
}

// CheckEndpointConflicts reports plugin endpoint-path conflicts found by
// FindEndpointConflicts, mirroring upstream's logger.error diagnostic. It
// returns the conflicts for tests and direct callers. The report receives
// the fully formatted message (upstream logs one string).
func CheckEndpointConflicts(basePath string, plugins []types.Plugin, report func(msg string, args ...any)) []EndpointConflict {
	conflicts := FindEndpointConflicts(basePath, plugins)
	if len(conflicts) == 0 || report == nil {
		return conflicts
	}
	lines := make([]string, 0, len(conflicts))
	for _, c := range conflicts {
		lines = append(lines, fmt.Sprintf("  - %q [%s] used by plugins: %s", c.Path, strings.Join(c.ConflictingMethods, ", "), strings.Join(c.Plugins, ", ")))
	}
	report(fmt.Sprintf("Endpoint path conflicts detected! Multiple plugins are trying to use the same endpoint paths with conflicting HTTP methods:\n%s\n\nTo resolve this, you can:\n\t1. Use only one of the conflicting plugins\n\t2. Configure the plugins to use different paths (if supported)\n\t3. Ensure plugins use different HTTP methods for the same path\n", strings.Join(lines, "\n")))
	return conflicts
}

// checkEndpointConflicts logs plugin endpoint-path conflicts via
// Options.Logger (level-gated error, quiet by default), mirroring upstream
// checkEndpointConflicts' logger.error call.
func checkEndpointConflicts(opts types.Options) {
	CheckEndpointConflicts(opts.BasePath, opts.Plugins, func(msg string, args ...any) {
		apiLogf(opts, "error", msg, args...)
	})
}

// joinEndpointPath joins the router basePath and a plugin endpoint suffix
// into the full registered path.
func joinEndpointPath(basePath, suffix string) string {
	if suffix == "" {
		return basePath
	}
	if basePath == "" {
		return suffix
	}
	return strings.TrimSuffix(basePath, "/") + "/" + strings.TrimPrefix(suffix, "/")
}

// endpointMethods normalizes a plugin endpoint method into upstream's method
// list form: empty means wildcard "*", otherwise the uppercased method.
func endpointMethods(method string) []string {
	if strings.TrimSpace(method) == "" {
		return []string{"*"}
	}
	return []string{strings.ToUpper(strings.TrimSpace(method))}
}

// --- Per-request dynamic baseURL (upstream resolveDynamicBaseURL) ---

// ResolveDynamicBaseURLForRequest resolves the full baseURL
// (origin + basePath) for the incoming request under a dynamic
// (allowedHosts) configuration, mirroring upstream resolveDynamicBaseURL
// (vendor/.../src/utils/url.ts:398-438):
//
//   - the host comes from x-forwarded-host only when
//     Advanced.TrustedProxyHeaders opts in, else the Host header, else the
//     request URL host;
//   - the host must match an allowedHosts pattern (see
//     types.MatchesHostPattern) or the Fallback is used when configured;
//     otherwise resolution fails;
//   - without a host the Fallback is used when configured, else resolution
//     fails;
//   - the scheme follows the configured Protocol, else x-forwarded-proto
//     (trusted-proxy opt-in only), else the request URL scheme, else https
//     (http for loopback hosts, mirroring upstream dev ergonomics).
//
// A nil DynamicBaseURL returns ("", nil): static mode has nothing to
// resolve. Static configurations never call this (the middleware only calls
// it to stash the value for future handler adoption; trust decisions keep
// using the ExpandDynamicBaseURLOrigins expansion).
//
// Upstream TypeScript names: resolveDynamicBaseURL, getHostFromSource,
// getProtocolFromSource.
func ResolveDynamicBaseURLForRequest(r *http.Request, opts types.Options) (string, error) {
	cfg := opts.DynamicBaseURL
	if cfg == nil {
		return "", nil
	}
	basePath := opts.BasePath
	if basePath == "" {
		basePath = "/api/auth"
	}
	trustedProxies := opts.Advanced.TrustedProxyHeaders != nil && *opts.Advanced.TrustedProxyHeaders
	host := dynamicRequestHost(r, trustedProxies)
	if host == "" {
		if cfg.Fallback != "" {
			return withBasePath(cfg.Fallback, basePath), nil
		}
		return "", fmt.Errorf("auth: could not determine host from request headers: provide a fallback URL in the dynamic baseURL config")
	}
	allowed := false
	for _, pattern := range cfg.AllowedHosts {
		if types.MatchesHostPattern(host, pattern) {
			allowed = true
			break
		}
	}
	// Port-agnostic fallback: allowedHosts entries are usually bare
	// hostnames while request hosts carry ports (Host header, request URL).
	// When the full host:port form does not match, retry with the hostname
	// alone so "localhost:3000" matches "localhost". The resolved URL below
	// still carries the request's full host (port preserved).
	if !allowed {
		if hostname := stripHostPort(host); hostname != host {
			for _, pattern := range cfg.AllowedHosts {
				if types.MatchesHostPattern(hostname, pattern) {
					allowed = true
					break
				}
			}
		}
	}
	if allowed {
		return withBasePath(dynamicRequestProtocol(r, cfg.Protocol, trustedProxies)+"://"+host, basePath), nil
	}
	if cfg.Fallback != "" {
		return withBasePath(cfg.Fallback, basePath), nil
	}
	return "", fmt.Errorf("auth: host %q is not in the allowed hosts list", host)
}

// dynamicRequestHost extracts the request host, honoring x-forwarded-host
// only under the trusted-proxy opt-in, then the Host header (or r.Host),
// then the request URL host. Invalid proxy values fail closed to the next
// source, mirroring upstream validateProxyHeader gating.
func dynamicRequestHost(r *http.Request, trustedProxies bool) string {
	if r == nil {
		return ""
	}
	if trustedProxies {
		if forwarded := r.Header.Get("X-Forwarded-Host"); isValidProxyHost(forwarded) {
			return strings.TrimSpace(forwarded)
		}
	}
	if host := strings.TrimSpace(r.Host); host != "" {
		return host
	}
	if r.URL != nil && r.URL.Host != "" {
		return r.URL.Host
	}
	return ""
}

// dynamicRequestProtocol resolves the request scheme, mirroring upstream
// getProtocolFromSource: the configured protocol wins when it pins http or
// https; otherwise x-forwarded-proto applies only under the trusted-proxy
// opt-in, then the request URL scheme, then http for loopback hosts, else
// https.
func dynamicRequestProtocol(r *http.Request, configured types.BaseURLProtocol, trustedProxies bool) string {
	if configured == types.BaseURLProtocolHTTP || configured == types.BaseURLProtocolHTTPS {
		return string(configured)
	}
	if r != nil {
		if trustedProxies {
			if proto := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))); proto == "http" || proto == "https" {
				return proto
			}
		}
		if r.URL != nil && (r.URL.Scheme == "http" || r.URL.Scheme == "https") {
			return r.URL.Scheme
		}
		if host := dynamicRequestHost(r, trustedProxies); host != "" && isLoopbackHost(stripHostPort(host)) {
			return "http"
		}
	}
	return "https"
}

// isValidProxyHost gates proxy-supplied hosts the way upstream
// validateProxyHeader does for the resolution path: non-empty, no
// whitespace, no path traversal, no injection characters.
func isValidProxyHost(host string) bool {
	trimmed := strings.TrimSpace(host)
	if trimmed == "" || strings.ContainsAny(trimmed, " \t\n\r") {
		return false
	}
	for _, bad := range []string{"..", "<", ">", "'", "\"", "javascript:", "file:", "data:"} {
		if strings.Contains(strings.ToLower(trimmed), bad) {
			return false
		}
	}
	if strings.HasPrefix(trimmed, ".") {
		return false
	}
	return true
}

// stripHostPort removes a trailing :port from a host for loopback checks,
// tolerating bare IPv6 literals.
func stripHostPort(host string) string {
	if h, _, err := splitHostPortLenient(strings.TrimSpace(host)); err == nil && h != "" {
		return h
	}
	return strings.Trim(strings.TrimSpace(host), "[]")
}

// withBasePath appends basePath to an origin unless the origin already
// carries a non-root path, mirroring upstream withPath.
func withBasePath(origin, basePath string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(origin), "/")
	if basePath == "" || basePath == "/" {
		return trimmed
	}
	if !strings.HasPrefix(basePath, "/") {
		basePath = "/" + basePath
	}
	return trimmed + basePath
}
