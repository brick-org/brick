package routes

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
)

type oauthServerContextKey struct{}

type humaContextKey struct{}
type apiErrorHandledKey struct{}

func WithAuthRouteContext(ctx huma.Context) huma.Context {
	handled := false
	ctx = huma.WithValue(ctx, apiErrorHandledKey{}, &handled)
	return huma.WithValue(ctx, humaContextKey{}, ctx)
}

func APIErrorHandled(ctx huma.Context) bool {
	handled, _ := ctx.Context().Value(apiErrorHandledKey{}).(*bool)
	return handled != nil && *handled
}

// NewPluginHookContext builds a TypeScript-faithful route-hook context
// (types.PluginHookContext, mirroring upstream's HookEndpointContext in
// vendor/better-auth/packages/core/src/types/plugin.ts) from an HTTP
// request and the resolved auth context. Method and Path default to the
// request's values when empty; Headers aliases the request headers.
// ResponseHeaders must be non-nil when after-hooks mutate response headers
// (a nil map is replaced with an empty one); Returned carries the
// endpoint's returned value for after hooks (upstream context.returned).
// A nil request leaves Request/Headers unset, mirroring upstream hooks
// invoked without one.
func NewPluginHookContext(r *http.Request, authCtx types.AuthContext, returned any, responseHeaders http.Header) types.PluginHookContext {
	out := types.PluginHookContext{
		Request:         r,
		AuthContext:     authCtx,
		Returned:        returned,
		ResponseHeaders: responseHeaders,
	}
	if out.ResponseHeaders == nil {
		out.ResponseHeaders = http.Header{}
	}
	if r != nil {
		if out.Method == "" {
			out.Method = r.Method
		}
		if out.Path == "" && r.URL != nil {
			out.Path = r.URL.Path
		}
		out.Headers = r.Header
	}
	return out
}

// PluginHookContextFromHuma builds a TypeScript-faithful route-hook context
// from a Huma request context. Method, path, and headers come from the
// wire; Request is nil (huma.Context does not expose the underlying
// *http.Request — call sites with one should use NewPluginHookContext);
// ResponseHeaders is a fresh mutable map for after-hook mutation (apply it
// with ApplyPluginResponseHeaders); Returned is unset (before-hook shape).
func PluginHookContextFromHuma(ctx huma.Context, authCtx types.AuthContext) types.PluginHookContext {
	out := types.PluginHookContext{
		AuthContext:     authCtx,
		ResponseHeaders: http.Header{},
	}
	if ctx == nil {
		return out
	}
	out.Method = ctx.Method()
	if url := ctx.URL(); url.Path != "" {
		out.Path = url.Path
	}
	headers := http.Header{}
	ctx.EachHeader(func(name, value string) {
		headers.Add(name, value)
	})
	out.Headers = headers
	return out
}

// ApplyPluginResponseHeaders copies mutated plugin response headers onto
// the Huma context (upstream responseHeaders). Nil values are skipped.
func ApplyPluginResponseHeaders(ctx huma.Context, headers http.Header) {
	if ctx == nil {
		return
	}
	for name, values := range headers {
		for _, value := range values {
			ctx.AppendHeader(name, value)
		}
	}
}

// RunTSRouteBeforeHooks runs TypeScript-faithful route before hooks
// (upstream `hooks.before`: { matcher, handler }) in order over hctx. A nil
// matcher always runs; a nil handler is a no-op. The first handler error
// aborts the chain and the route (returned as-is for errors.Is/As).
func RunTSRouteBeforeHooks(hctx types.PluginHookContext, before []types.PluginTSRouteBeforeHook) error {
	for _, hook := range before {
		if hook.Matcher != nil && !hook.Matcher(hctx) {
			continue
		}
		if hook.Handler == nil {
			continue
		}
		if err := hook.Handler(hctx); err != nil {
			return err
		}
	}
	return nil
}

// RunTSRouteAfterHooks runs TypeScript-faithful route after hooks
// (upstream `hooks.after`) in order over hctx. All matching hooks run;
// handler errors never fail the route — each is passed to report (nil
// report discards, mirroring the quiet default elsewhere).
func RunTSRouteAfterHooks(hctx types.PluginHookContext, after []types.PluginTSRouteAfterHook, report func(error)) {
	for _, hook := range after {
		if hook.Matcher != nil && !hook.Matcher(hctx) {
			continue
		}
		if hook.Handler == nil {
			continue
		}
		if err := hook.Handler(hctx); err != nil && report != nil {
			report(err)
		}
	}
}

func registerAuthOperation[I any, O any](
	api huma.API,
	op huma.Operation,
	opts types.Options,
	handler func(context.Context, *I) (*O, error),
) {
	huma.Register(api, op, func(ctx context.Context, input *I) (*O, error) {
		out, err := handler(ctx, input)
		if err != nil {
			callRouteAPIErrorHandler(ctx, opts, err)
		}
		return out, err
	})
}

func callRouteAPIErrorHandler(ctx context.Context, opts types.Options, err error) {
	if opts.OnAPIError.OnError == nil {
		return
	}
	handled, _ := ctx.Value(apiErrorHandledKey{}).(*bool)
	if handled != nil && *handled {
		return
	}

	var statusErr huma.StatusError
	if !errors.As(err, &statusErr) {
		return
	}

	humaCtx, _ := ctx.Value(humaContextKey{}).(huma.Context)
	if humaCtx == nil {
		return
	}

	if handled != nil {
		*handled = true
	}
	opts.OnAPIError.OnError(statusErr, humaCtx)
}

// --- AUTH-F6-01 request context and dynamic BaseURL ---
//
// Upstream resolves the per-request BaseURL from the incoming request under a
// dynamic (allowedHosts) configuration and makes it authoritative for
// downstream handlers (vendor/.../src/utils/url.ts resolveDynamicBaseURL,
// context/helpers.ts resolveRequestContext, api/to-auth-endpoints.ts
// resolveDynamicContext). Static configurations keep the configured BaseURL.
//
// Go has no AsyncLocalStorage; the faithful equivalent is explicit context
// propagation through huma.WithValue (which layers onto the underlying
// context.Context, so std handlers see the same values). The api middleware
// stores the resolved full baseURL (origin + basePath) under these keys;
// route handlers read it via EffectiveBaseURL/EffectiveFullBaseURL with a
// static fallback, so concurrent hosts never leak into each other (the shared
// Options stay untouched, mirroring upstream's per-call clone).

type requestFullBaseURLKey struct{}
type requestStateStdKey struct{}
type endpointMetadataKey struct{}
type storedRequestKey struct{}

// EndpointMetadata carries the matched endpoint identity through the
// middleware pipeline (upstream dispatch.ts operationId/route/method used for
// spans and hook matchers). The middleware stores it; handlers and plugin
// endpoints read it via EndpointMetadataFromStd.
type EndpointMetadata struct {
	Method      string
	Path        string
	OperationID string
}

// WithRequestFullBaseURL stores the resolved full baseURL (origin + basePath)
// on a huma request context.
func WithRequestFullBaseURL(ctx huma.Context, full string) huma.Context {
	if ctx == nil || full == "" {
		return ctx
	}
	return huma.WithValue(ctx, requestFullBaseURLKey{}, full)
}

// WithRequestFullBaseURLValue stores the resolved full baseURL on a std
// context (tests and non-huma producers).
func WithRequestFullBaseURLValue(ctx context.Context, full string) context.Context {
	if ctx == nil || full == "" {
		return ctx
	}
	return context.WithValue(ctx, requestFullBaseURLKey{}, full)
}

// RequestFullBaseURLFromHuma returns the request-scoped full baseURL, or ""
// when none was installed.
func RequestFullBaseURLFromHuma(ctx huma.Context) string {
	if ctx == nil {
		return ""
	}
	return RequestFullBaseURLFromStd(ctx.Context())
}

// RequestFullBaseURLFromStd returns the request-scoped full baseURL, or ""
// when none was installed.
func RequestFullBaseURLFromStd(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	full, _ := ctx.Value(requestFullBaseURLKey{}).(string)
	return full
}

// WithRequestStateStore shares the per-request state map under the routes
// readable key. The api middleware calls this with the same map pointer it
// installs under its own key, so huma and std readers see one store.
func WithRequestStateStore(ctx huma.Context, state map[any]any) huma.Context {
	if ctx == nil {
		return ctx
	}
	if state == nil {
		state = make(map[any]any)
	}
	return huma.WithValue(ctx, requestStateStdKey{}, state)
}

// RequestStateFromStd returns the per-request state store, or nil when none
// was installed (outside the middleware pipeline).
func RequestStateFromStd(ctx context.Context) map[any]any {
	if ctx == nil {
		return nil
	}
	state, _ := ctx.Value(requestStateStdKey{}).(map[any]any)
	return state
}

// RequestStateFromHuma returns the per-request state store for a huma
// context, or nil when none was installed.
func RequestStateFromHuma(ctx huma.Context) map[any]any {
	if ctx == nil {
		return nil
	}
	return RequestStateFromStd(ctx.Context())
}

// WithEndpointMetadata stores the matched endpoint identity on a huma
// context.
func WithEndpointMetadata(ctx huma.Context, md EndpointMetadata) huma.Context {
	if ctx == nil {
		return ctx
	}
	return huma.WithValue(ctx, endpointMetadataKey{}, md)
}

// EndpointMetadataFromStd returns the endpoint identity carried by the
// middleware, or the zero value when none was installed.
func EndpointMetadataFromStd(ctx context.Context) EndpointMetadata {
	if ctx == nil {
		return EndpointMetadata{}
	}
	md, _ := ctx.Value(endpointMetadataKey{}).(EndpointMetadata)
	return md
}

// EndpointMetadataFromHuma returns the endpoint identity for a huma context.
func EndpointMetadataFromHuma(ctx huma.Context) EndpointMetadata {
	if ctx == nil {
		return EndpointMetadata{}
	}
	return EndpointMetadataFromStd(ctx.Context())
}

// WithStoredRequest stores the reconstructed *http.Request for request-aware
// trust callbacks (TrustedOriginsFunc, IsTrustedRedirect) so std handlers
// without wire access still validate against the real request.
func WithStoredRequest(ctx huma.Context, r *http.Request) huma.Context {
	if ctx == nil || r == nil {
		return ctx
	}
	return huma.WithValue(ctx, storedRequestKey{}, r)
}

// StoredRequestFromStd returns the middleware-reconstructed request, or nil.
func StoredRequestFromStd(ctx context.Context) *http.Request {
	if ctx == nil {
		return nil
	}
	r, _ := ctx.Value(storedRequestKey{}).(*http.Request)
	return r
}

// RequestFromHuma rebuilds a best-effort *http.Request from a huma context
// for request-aware trust callbacks. It carries method, URL, Host,
// RemoteAddr, and headers; the body is referenced, not cloned.
func RequestFromHuma(ctx huma.Context) *http.Request {
	if ctx == nil {
		return nil
	}
	reqURL := ctx.URL()
	req, _ := http.NewRequest(ctx.Method(), reqURL.String(), nil)
	if req == nil {
		return nil
	}
	req.Host = ctx.Host()
	req.RemoteAddr = ctx.RemoteAddr()
	ctx.EachHeader(func(name, value string) {
		req.Header.Add(name, value)
	})
	return req
}

// joinBasePathWithCheck appends basePath to an origin unless the origin
// already carries a non-root path, mirroring upstream withPath
// (utils/url.ts:73-89).
func joinBasePathWithCheck(origin, basePath string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(origin), "/")
	if trimmed == "" {
		return trimmed
	}
	if basePath == "" || basePath == "/" {
		return trimmed
	}
	if !strings.HasPrefix(basePath, "/") {
		basePath = "/" + basePath
	}
	if u, err := url.Parse(trimmed); err == nil && u.Host != "" {
		if p := strings.TrimSuffix(u.Path, "/"); p != "" && p != "/" {
			return trimmed
		}
	}
	return trimmed + basePath
}

// staticFullBaseURL returns the static full baseURL (origin + basePath), or
// "" when no static BaseURL is configured.
func staticFullBaseURL(opts types.Options) string {
	if strings.TrimSpace(opts.BaseURL) == "" {
		return ""
	}
	basePath := opts.BasePath
	if basePath == "" {
		basePath = "/api/auth"
	}
	return joinBasePathWithCheck(opts.BaseURL, basePath)
}

// EffectiveFullBaseURL returns the authoritative full baseURL for a request:
// the middleware-resolved per-request value wins; otherwise the static
// origin + basePath; otherwise the dynamic fallback + basePath; otherwise "".
// It never mutates shared state, so concurrent hosts stay isolated.
func EffectiveFullBaseURL(ctx context.Context, opts types.Options) string {
	if full := RequestFullBaseURLFromStd(ctx); full != "" {
		return full
	}
	if full := staticFullBaseURL(opts); full != "" {
		return full
	}
	if cfg := opts.DynamicBaseURL; cfg != nil && strings.TrimSpace(cfg.Fallback) != "" {
		basePath := opts.BasePath
		if basePath == "" {
			basePath = "/api/auth"
		}
		return joinBasePathWithCheck(cfg.Fallback, basePath)
	}
	return ""
}

// EffectiveFullBaseURLFromHuma is the huma variant of EffectiveFullBaseURL.
func EffectiveFullBaseURLFromHuma(ctx huma.Context, opts types.Options) string {
	if ctx == nil {
		return EffectiveFullBaseURL(context.Background(), opts)
	}
	return EffectiveFullBaseURL(ctx.Context(), opts)
}

// originOfFull returns the scheme://host origin of a full baseURL.
func originOfFull(full string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(full))
	if err != nil || u.Host == "" {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	return scheme + "://" + u.Host, true
}

// EffectiveBaseURL returns the authoritative origin for a request (upstream
// c.context.options.baseURL after resolveRequestContext: the origin of the
// resolved full baseURL). Static fallback is opts.BaseURL; dynamic fallback
// is the fallback origin. Callbacks and cookie domains use this; redirect
// URIs and error URLs use EffectiveFullBaseURL.
func EffectiveBaseURL(ctx context.Context, opts types.Options) string {
	if full := RequestFullBaseURLFromStd(ctx); full != "" {
		if origin, ok := originOfFull(full); ok {
			return origin
		}
		return full
	}
	if strings.TrimSpace(opts.BaseURL) != "" {
		return strings.TrimRight(strings.TrimSpace(opts.BaseURL), "/")
	}
	if cfg := opts.DynamicBaseURL; cfg != nil && strings.TrimSpace(cfg.Fallback) != "" {
		if origin, ok := originOfFull(strings.TrimSpace(cfg.Fallback)); ok {
			return origin
		}
		return strings.TrimRight(strings.TrimSpace(cfg.Fallback), "/")
	}
	return ""
}

// EffectiveBaseURLFromHuma is the huma variant of EffectiveBaseURL.
func EffectiveBaseURLFromHuma(ctx huma.Context, opts types.Options) string {
	if ctx == nil {
		return EffectiveBaseURL(context.Background(), opts)
	}
	return EffectiveBaseURL(ctx.Context(), opts)
}

// DefaultErrorURLWithContext returns the OAuth error base URL using the
// authoritative per-request baseURL (upstream parseState:
// options.onAPIError?.errorURL || `${c.context.baseURL}/error`).
func DefaultErrorURLWithContext(ctx context.Context, opts types.Options) string {
	if opts.OnAPIError.ErrorURL != "" {
		return opts.OnAPIError.ErrorURL
	}
	if full := EffectiveFullBaseURL(ctx, opts); full != "" {
		return strings.TrimSuffix(full, "/") + "/error"
	}
	return "/error"
}

// DefaultErrorURLWithHuma is the huma variant of DefaultErrorURLWithContext.
func DefaultErrorURLWithHuma(ctx huma.Context, opts types.Options) string {
	if opts.OnAPIError.ErrorURL != "" {
		return opts.OnAPIError.ErrorURL
	}
	if full := EffectiveFullBaseURLFromHuma(ctx, opts); full != "" {
		return strings.TrimSuffix(full, "/") + "/error"
	}
	return "/error"
}

// AddOAuthServerContextValue accumulates server-trusted flow values onto a
// std context. Multiple calls merge with later keys winning. A nil or empty
// values map leaves ctx unchanged.
func AddOAuthServerContextValue(ctx context.Context, values map[string]any) context.Context {
	if len(values) == 0 {
		return ctx
	}
	merged := map[string]any{}
	for k, v := range ServerContextFromHooks(ctx) {
		merged[k] = v
	}
	for k, v := range values {
		merged[k] = v
	}
	return context.WithValue(ctx, oauthServerContextKey{}, merged)
}

// AddOAuthServerContextToHuma accumulates server-trusted flow values onto a
// huma request context so they reach std handlers via context propagation.
func AddOAuthServerContextToHuma(ctx huma.Context, values map[string]any) huma.Context {
	if ctx == nil || len(values) == 0 {
		return ctx
	}
	return huma.WithContext(ctx, AddOAuthServerContextValue(ctx.Context(), values))
}

// ServerContextFromHooks returns server-trusted flow values accumulated on
// ctx, or nil when none were added.
func ServerContextFromHooks(ctx context.Context) map[string]any {
	if v, _ := ctx.Value(oauthServerContextKey{}).(map[string]any); len(v) > 0 {
		return v
	}
	return nil
}

// ResolveOAuthServerContext merges the context-carried accumulation with the
// explicit trusted argument winning. It returns nil when every layer is
// empty so the stored payload omits the key.
func ResolveOAuthServerContext(ctx context.Context, explicit map[string]any) map[string]any {
	base := ServerContextFromHooks(ctx)
	if len(base) == 0 && len(explicit) == 0 {
		return nil
	}
	merged := map[string]any{}
	for k, v := range base {
		merged[k] = v
	}
	for k, v := range explicit {
		merged[k] = v
	}
	return merged
}

// ResolveSecureCookiesWithContext reports whether cookies must carry Secure
// using the authoritative request origin (upstream: https baseURL). Explicit
// UseSecureCookies wins, then trusted-proxy proto, then the effective origin
// scheme; static behavior is unchanged when no request value is present.
func ResolveSecureCookiesWithContext(ctx context.Context, opts types.Options, headers CookieRequestHeaders) bool {
	if opts.Advanced.UseSecureCookies != nil {
		return *opts.Advanced.UseSecureCookies
	}
	if trustedProxyHeadersEnabled(opts) {
		switch trustedProxyProto(headers.XForwardedProto) {
		case "https":
			return true
		case "http":
			return false
		}
	}
	return strings.HasPrefix(strings.ToLower(EffectiveBaseURL(ctx, opts)), "https://")
}

// ResolveCrossSubDomainCookieDomainWithContext returns the cross-subdomain
// cookie domain using the authoritative request origin: explicit Domain wins,
// then trusted-proxy host, then the effective origin hostname, then the Host
// header. Static behavior is unchanged when no request value is present.
func ResolveCrossSubDomainCookieDomainWithContext(ctx context.Context, opts types.Options, headers CookieRequestHeaders) string {
	if opts.Advanced.CrossSubDomainCookies.Domain != "" {
		return opts.Advanced.CrossSubDomainCookies.Domain
	}
	if trustedProxyHeadersEnabled(opts) {
		if host, ok := trustedProxyHost(headers.XForwardedHost); ok {
			return host
		}
	}
	if origin := EffectiveBaseURL(ctx, opts); origin != "" {
		if parsed, err := url.Parse(origin); err == nil {
			if host := parsed.Hostname(); host != "" {
				return host
			}
		}
	}
	if host, ok := trustedProxyHost(headers.Host); ok {
		return host
	}
	return ""
}

// RunInBackground dispatches deferred work after the response, mirroring
// upstream ctx.runInBackground: the configured Handler receives the thunk,
// otherwise the task runs fire-and-forget with panics contained. A nil task
// is a no-op. Routes call this instead of importing the root package (which
// would cycle); behavior matches auth.RunInBackground.
func RunInBackground(opts types.Options, task func()) {
	if task == nil {
		return
	}
	if handler := opts.Advanced.BackgroundTasks.Handler; handler != nil {
		handler(task)
		return
	}
	go func() {
		defer func() { _ = recover() }()
		task()
	}()
}

// Logf reports a route-level diagnostic via Options.Logger when logging is
// configured and the level passes (types.ShouldPublishLog, default "warn").
// It stays quiet otherwise, preserving the historical quiet default.
func Logf(opts types.Options, level, format string, args ...any) {
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

// WithSpan executes fn directly while preserving upstream span name/attribute
// plumbing (upstream createWithSpan; instrumentation is enabled by default).
// The Go runtime has no tracer, so both paths execute inline.
func WithSpan[T any](opts types.Options, name string, attrs map[string]string, fn func() (T, error)) (T, error) {
	_ = opts
	_ = name
	_ = attrs
	return fn()
}

// isLoopbackHostPort reports whether a Host-header value is a loopback host
// for cookie-secure inference (localhost, *.localhost, 127.0.0.0/8, ::1),
// tolerating ports and brackets. It mirrors the api-layer classifier without
// importing it (routes cannot import api).
func isLoopbackHostPort(hostport string) bool {
	h := strings.TrimSpace(hostport)
	// Strip a single trailing :port for IPv4/FQDN hosts; bare IPv6 literals
	// carry no port.
	name := h
	if strings.HasPrefix(h, "[") {
		if end := strings.Index(h, "]"); end != -1 {
			name = h[1:end]
		}
	} else if strings.Count(h, ":") == 1 {
		if idx := strings.LastIndex(h, ":"); idx != -1 {
			name = h[:idx]
		}
	}
	name = strings.ToLower(strings.TrimSuffix(strings.Trim(name, "[]"), "."))
	if idx := strings.Index(name, "%"); idx != -1 {
		name = name[:idx]
	}
	if name == "localhost" || strings.HasSuffix(name, ".localhost") {
		return true
	}
	if name == "::1" {
		return true
	}
	if strings.HasPrefix(name, "127.") {
		return true
	}
	return false
}
