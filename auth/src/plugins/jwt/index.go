package jwt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	auth "github.com/brick-org/brick/auth/src"
	"github.com/brick-org/brick/auth/src/api/routes"
	authtypes "github.com/brick-org/brick/auth/src/types"
	"github.com/danielgtaylor/huma/v2"
)

const (
	pluginID            = "jwt"
	defaultJWKSPath     = "/jwks"
	getSessionPath      = "/get-session"
	accessTokenHeader   = "set-auth-jwt"
	exposeHeadersHeader = "Access-Control-Expose-Headers"
	defaultGracePeriod  = 30 * 24 * time.Hour
)

var publicJWKFields = []string{
	"kty", "use", "key_ops", "alg", "kid", "x5u", "x5c", "x5t", "x5t#S256",
	"crv", "x", "y", "n", "e",
}

// Plugin provides JWT signing, verification, and the public JWKS/token routes.
type Plugin struct {
	mu          sync.RWMutex
	opts        Options
	authCtx     authtypes.AuthContext
	store       jwksStore
	initialized bool
}

var (
	_ authtypes.Plugin = (*Plugin)(nil)
	_ Signer           = (*Plugin)(nil)
	_ Verifier         = (*Plugin)(nil)
)

// New constructs the JWT plugin. Configuration errors are returned from Init.
func New(opts Options) *Plugin {
	return &Plugin{opts: cloneOptions(opts)}
}

func cloneOptions(opts Options) Options {
	if opts.JWKS != nil {
		jwks := *opts.JWKS
		jwks.KeyPairConfigs = slices.Clone(opts.JWKS.KeyPairConfigs)
		opts.JWKS = &jwks
	}
	if opts.JWT != nil {
		jwtOptions := *opts.JWT
		jwtOptions.Audience = slices.Clone(opts.JWT.Audience)
		if opts.JWT.ExpirationTime != nil {
			expiration := *opts.JWT.ExpirationTime
			if expiration.At != nil {
				at := *expiration.At
				expiration.At = &at
			}
			if expiration.UnixSeconds != nil {
				seconds := *expiration.UnixSeconds
				expiration.UnixSeconds = &seconds
			}
			jwtOptions.ExpirationTime = &expiration
		}
		opts.JWT = &jwtOptions
	}
	return opts
}

func (p *Plugin) ID() string { return pluginID }

// Init validates configuration and prepares database-backed local key storage.
func (p *Plugin) Init(authCtx authtypes.AuthContext) error {
	if authCtx.BaseURL == "" {
		authCtx.BaseURL = configuredBaseURL(authCtx.Options)
	} else {
		authCtx.BaseURL = urlOrigin(authCtx.BaseURL)
	}
	p.mu.Lock()
	p.initialized = false
	p.authCtx = authtypes.AuthContext{}
	p.store = nil
	opts := cloneOptions(p.opts)
	p.mu.Unlock()

	if err := validateOptions(opts, authCtx.Options); err != nil {
		return err
	}
	if !usesRemoteSigner(opts) {
		if authCtx.Options.DB == nil {
			return errors.New("jwt: local signing requires a configured database adapter")
		}
		jwksOptions := effectiveJWKSOptions(opts)
		store, err := newDatabaseJWKSStore(
			authCtx.Options.DB,
			authCtx.SecretConfig,
			jwksOptions.DisablePrivateKeyEncryption,
		)
		if err != nil {
			return fmt.Errorf("jwt: initialize JWKS store: %w", err)
		}
		p.mu.Lock()
		p.authCtx = authCtx
		p.store = store
		p.initialized = true
		p.mu.Unlock()
		return nil
	}

	p.mu.Lock()
	p.authCtx = authCtx
	p.initialized = true
	p.mu.Unlock()
	return nil
}

func validateOptions(opts Options, authOptions authtypes.Options) error {
	jwks := effectiveJWKSOptions(opts)
	if jwks.JWKSPath != "" {
		if !strings.HasPrefix(jwks.JWKSPath, "/") || strings.Contains(jwks.JWKSPath, "..") ||
			strings.HasPrefix(jwks.JWKSPath, "//") || strings.ContainsAny(jwks.JWKSPath, "?#") ||
			path.Clean(jwks.JWKSPath) != jwks.JWKSPath {
			return fmt.Errorf("jwt: invalid JWKS path %q", jwks.JWKSPath)
		}
		if jwks.JWKSPath == "/token" {
			return errors.New("jwt: JWKS path must not conflict with /token")
		}
	}
	if jwks.RemoteURL != "" {
		remoteURL, err := url.ParseRequestURI(jwks.RemoteURL)
		if err != nil || remoteURL.Host == "" || (remoteURL.Scheme != "http" && remoteURL.Scheme != "https") {
			return fmt.Errorf("jwt: invalid remote JWKS URL %q", jwks.RemoteURL)
		}
		if opts.JWKS == nil || opts.JWKS.KeyPairConfig.Alg == "" {
			return errors.New("jwt: remote JWKS requires an explicitly configured primary algorithm")
		}
		if opts.JWT == nil || opts.JWT.Sign == nil {
			return errors.New("jwt: remote JWKS requires a configured remote signer; local keys cannot be published at JWKS.RemoteURL")
		}
	}
	if opts.JWT != nil && opts.JWT.Sign != nil && jwks.RemoteURL == "" {
		return errors.New("jwt: JWT.Sign requires JWKS.RemoteURL")
	}
	if jwks.RotationInterval < 0 {
		return errors.New("jwt: JWKS rotation interval must not be negative")
	}
	if jwks.GracePeriod < 0 {
		return errors.New("jwt: JWKS grace period must not be negative")
	}
	if _, err := ResolveKeyPairConfig(jwks.KeyPairConfig); err != nil {
		return fmt.Errorf("jwt: invalid primary key-pair config: %w", err)
	}
	seenAlgorithms := make(map[JWSAlgorithm]struct{}, len(jwks.KeyPairConfigs)+1)
	primary, _ := ResolveKeyPairConfig(jwks.KeyPairConfig)
	seenAlgorithms[primary.Alg] = struct{}{}
	for _, config := range jwks.KeyPairConfigs {
		resolved, err := ResolveKeyPairConfig(config)
		if err != nil {
			return fmt.Errorf("jwt: invalid additional key-pair config: %w", err)
		}
		if _, duplicate := seenAlgorithms[resolved.Alg]; duplicate {
			return fmt.Errorf("jwt: duplicate key-pair algorithm %q", resolved.Alg)
		}
		seenAlgorithms[resolved.Alg] = struct{}{}
	}
	if opts.JWT != nil {
		if opts.JWT.ExpirationTime != nil {
			if _, err := toExpJWT(*opts.JWT.ExpirationTime, 1); err != nil {
				return fmt.Errorf("jwt: invalid expiration time: %w", err)
			}
		}
		for i, audience := range opts.JWT.Audience {
			if strings.TrimSpace(audience) == "" || slices.Contains(opts.JWT.Audience[:i], audience) {
				return errors.New("jwt: JWT audience contains an empty or duplicate value")
			}
		}
	}
	if opts.SessionCookieCache && authOptions.Session.CookieCache.Strategy != authtypes.SessionCookieCacheJWT {
		return fmt.Errorf("jwt: session cookie-cache signing requires strategy %q", authtypes.SessionCookieCacheJWT)
	}
	if opts.SessionCookieCache && usesRemoteSigner(opts) {
		return errors.New("jwt: session cookie-cache signing requires locally managed keys")
	}
	if authOptions.Session.CookieCache.Strategy == authtypes.SessionCookieCacheJWT && !opts.SessionCookieCache {
		return errors.New("jwt: JWT session cookie-cache strategy requires SessionCookieCache to be enabled")
	}
	return nil
}

func effectiveJWKSOptions(opts Options) JWKSOptions {
	if opts.JWKS == nil {
		return JWKSOptions{KeyPairConfig: DefaultKeyPairConfig()}
	}
	return *opts.JWKS
}

func usesRemoteSigner(opts Options) bool {
	return opts.JWT != nil && opts.JWT.Sign != nil
}

func (p *Plugin) snapshot() (Options, authtypes.AuthContext, jwksStore, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.opts, p.authCtx, p.store, p.initialized
}

func (p *Plugin) Endpoints() []authtypes.Endpoint {
	opts, _, _, _ := p.snapshot()
	jwksPath := effectiveJWKSOptions(opts).JWKSPath
	if jwksPath == "" {
		jwksPath = defaultJWKSPath
	}
	return []authtypes.Endpoint{
		{
			Method:      http.MethodGet,
			Path:        jwksPath,
			OperationID: "getJWKS",
			Summary:     "Get public JSON Web Key Set",
			Register:    p.registerJWKS,
		},
		{
			Method:      http.MethodGet,
			Path:        "/token",
			OperationID: "getToken",
			Summary:     "Get a JWT for the current session",
			Register:    p.registerToken,
		},
	}
}

func (p *Plugin) registerJWKS(api any, basePath string, _ authtypes.Options) {
	registerAPI := api.(huma.API)
	path := effectiveJWKSPath(p)
	huma.Register(registerAPI, huma.Operation{
		Method:      http.MethodGet,
		Path:        joinBasePath(basePath, path),
		OperationID: "getJWKS",
		Summary:     "Get public JSON Web Key Set",
	}, func(ctx context.Context, _ *struct{}) (*jwksOutput, error) {
		return p.getJWKS(ctx)
	})
}

func (p *Plugin) registerToken(api any, basePath string, _ authtypes.Options) {
	registerAPI := api.(huma.API)
	huma.Register(registerAPI, huma.Operation{
		Method:      http.MethodGet,
		Path:        joinBasePath(basePath, "/token"),
		OperationID: "getToken",
		Summary:     "Get a JWT for the current session",
	}, func(ctx context.Context, _ *struct{}) (*tokenOutput, error) {
		token, err := p.getToken(ctx)
		if err != nil {
			return nil, err
		}
		return &tokenOutput{Body: tokenBody{Token: token}}, nil
	})
}

func joinBasePath(basePath, endpointPath string) string {
	return strings.TrimRight(basePath, "/") + "/" + strings.TrimLeft(endpointPath, "/")
}

func effectiveJWKSPath(p *Plugin) string {
	opts, _, _, _ := p.snapshot()
	if path := effectiveJWKSOptions(opts).JWKSPath; path != "" {
		return path
	}
	return defaultJWKSPath
}

type jwksOutput struct {
	Body struct {
		Keys []json.RawMessage `json:"keys"`
	}
}

type tokenOutput struct {
	Body tokenBody
}

type tokenBody struct {
	Token string `json:"token"`
}

func (p *Plugin) getJWKS(ctx context.Context) (*jwksOutput, error) {
	opts, _, store, initialized := p.snapshot()
	if !initialized {
		return nil, huma.Error500InternalServerError("JWT plugin is not initialized")
	}
	if effectiveJWKSOptions(opts).RemoteURL != "" {
		return nil, huma.Error404NotFound("JWKS is not served in remote mode")
	}
	if store == nil {
		return nil, huma.Error500InternalServerError("JWKS store is unavailable")
	}
	keys, err := store.getPublicAll(ctx)
	if err != nil {
		return nil, huma.Error500InternalServerError("failed to load JWKS")
	}
	if len(keys) == 0 {
		jwksOptions := effectiveJWKSOptions(opts)
		if _, err := createJWK(ctx, store, jwksOptions.KeyPairConfig, jwksOptions.RotationInterval); err != nil {
			return nil, huma.Error500InternalServerError("failed to create initial JWKS key")
		}
		keys, err = store.getPublicAll(ctx)
		if err != nil {
			return nil, huma.Error500InternalServerError("failed to load initial JWKS key")
		}
	}
	keys = publishedJWKs(keys, time.Now(), gracePeriod(opts))
	out := &jwksOutput{}
	out.Body.Keys = make([]json.RawMessage, 0, len(keys))
	defaultKeyConfig, err := ResolveKeyPairConfig(effectiveJWKSOptions(opts).KeyPairConfig)
	if err != nil {
		return nil, huma.Error500InternalServerError("invalid default JWKS key configuration")
	}
	for _, key := range keys {
		public, err := publicJWK(key, defaultKeyConfig)
		if err != nil {
			return nil, huma.Error500InternalServerError("failed to encode public JWKS")
		}
		out.Body.Keys = append(out.Body.Keys, public)
	}
	return out, nil
}

func publicJWK(key JWK, defaults KeyPairConfig) (json.RawMessage, error) {
	if key.ID == "" {
		return nil, errors.New("jwt: public key id is required")
	}
	var stored map[string]json.RawMessage
	if err := json.Unmarshal([]byte(key.PublicKeyJSON), &stored); err != nil || stored == nil {
		return nil, fmt.Errorf("jwt: invalid public key JSON for %q", key.ID)
	}
	public := make(map[string]json.RawMessage, len(publicJWKFields))
	for _, name := range publicJWKFields {
		if value, ok := stored[name]; ok {
			public[name] = value
		}
	}
	if _, exists := public["alg"]; !exists {
		algorithm := defaults.Alg
		if key.Alg != nil {
			algorithm = *key.Alg
		}
		if algorithm != "" {
			public["alg"], _ = json.Marshal(algorithm)
		}
	}
	if _, exists := public["crv"]; !exists {
		curve := defaults.Crv
		if key.Crv != nil {
			curve = *key.Crv
		}
		if curve != "" {
			public["crv"], _ = json.Marshal(curve)
		}
	}
	kid, err := json.Marshal(key.ID)
	if err != nil {
		return nil, err
	}
	public["kid"] = kid
	return json.Marshal(public)
}

func gracePeriod(options Options) time.Duration {
	if options.JWKS == nil || options.JWKS.GracePeriod == 0 {
		return defaultGracePeriod
	}
	return options.JWKS.GracePeriod
}

func publishedJWKs(keys []JWK, now time.Time, grace time.Duration) []JWK {
	return slices.DeleteFunc(slices.Clone(keys), func(key JWK) bool {
		return key.ExpiresAt != nil && !key.ExpiresAt.Add(grace).After(now)
	})
}

func (p *Plugin) getToken(ctx context.Context) (string, error) {
	_, authCtx, _, initialized := p.snapshot()
	if !initialized {
		return "", huma.Error500InternalServerError("JWT plugin is not initialized")
	}
	request := routes.StoredRequestFromStd(ctx)
	if request == nil {
		return "", huma.Error401Unauthorized("authentication is required")
	}
	session, user, _, err := auth.GetSessionFromRequest(request, authCtx.Options)
	if err != nil {
		return "", err
	}
	if session == nil || user == nil {
		return "", huma.Error401Unauthorized("authentication is required")
	}
	opts, _, store, _ := p.snapshot()
	token, err := sessionJWT(ctx, store, opts, requestBaseURL(ctx, authCtx.BaseURL), *session, *user)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (p *Plugin) Schema() authtypes.PluginSchema { return Schema() }

func (p *Plugin) Hooks() authtypes.DBHooks { return authtypes.DBHooks{} }

func (p *Plugin) RouteHooks() authtypes.PluginRouteHooks {
	opts, authCtx, _, initialized := p.snapshot()
	if !initialized || opts.DisableSettingJWTHeader {
		return authtypes.PluginRouteHooks{}
	}
	basePath := strings.TrimRight(authCtx.Options.BasePath, "/")
	if basePath == "" {
		basePath = "/api/auth"
	}
	getSessionRoute := basePath + getSessionPath
	return authtypes.PluginRouteHooks{After: []authtypes.PluginRouteAfterHook{{
		Matcher: func(ctx huma.Context) bool {
			return ctx != nil && ctx.URL().Path == getSessionRoute
		},
		Handler: p.setSessionJWTHeader,
	}}}
}

func (p *Plugin) setSessionJWTHeader(ctx huma.Context) {
	if ctx == nil {
		return
	}
	opts, authCtx, store, initialized := p.snapshot()
	if !initialized {
		return
	}
	request := routes.RequestFromHuma(ctx)
	if request == nil {
		return
	}
	session, user, _, err := auth.GetSessionFromRequest(request, authCtx.Options)
	if err != nil || session == nil || user == nil {
		return
	}
	token, err := sessionJWT(request.Context(), store, opts, requestBaseURL(ctx.Context(), authCtx.BaseURL), *session, *user)
	if err != nil {
		return
	}
	ctx.SetHeader(accessTokenHeader, token)
	ctx.AppendHeader(exposeHeadersHeader, accessTokenHeader)
}

func (p *Plugin) ErrorCodes() map[string]string { return map[string]string{} }

// ResolveSigningKey selects the local or configured remote signing identity.
func (p *Plugin) ResolveSigningKey(ctx context.Context, overrides SigningKeyOverrides) (ResolvedSigningKey, error) {
	opts, _, store, initialized := p.snapshot()
	if !initialized {
		return ResolvedSigningKey{}, errors.New("jwt: plugin is not initialized")
	}
	return resolveSigningKey(ctx, store, opts, overrides)
}

// SignJWT signs a server-side payload without exposing an HTTP signing route.
func (p *Plugin) SignJWT(ctx context.Context, payload Payload, overrides SigningKeyOverrides) (string, error) {
	opts, authCtx, store, initialized := p.snapshot()
	if !initialized {
		return "", errors.New("jwt: plugin is not initialized")
	}
	opts = withBaseURLDefaults(opts, requestBaseURL(ctx, authCtx.BaseURL))
	return signJWT(ctx, store, opts, payload, overrides)
}

func withBaseURLDefaults(options Options, baseURL string) Options {
	if baseURL == "" {
		return options
	}
	if options.JWT == nil {
		options.JWT = &JWTOptions{Issuer: baseURL, Audience: []string{baseURL}}
		return options
	}
	jwtOptions := *options.JWT
	if jwtOptions.Issuer == "" {
		jwtOptions.Issuer = baseURL
	}
	if len(jwtOptions.Audience) == 0 {
		jwtOptions.Audience = []string{baseURL}
	} else {
		jwtOptions.Audience = slices.Clone(jwtOptions.Audience)
	}
	options.JWT = &jwtOptions
	return options
}

func requestBaseURL(ctx context.Context, fallback string) string {
	full := routes.RequestFullBaseURLFromStd(ctx)
	if origin := urlOrigin(full); origin != "" {
		return origin
	}
	return fallback
}

func configuredBaseURL(options authtypes.Options) string {
	if options.DynamicBaseURL != nil {
		return ""
	}
	return urlOrigin(options.BaseURL)
}

func urlOrigin(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return ""
	}
	return (&url.URL{Scheme: parsed.Scheme, Host: parsed.Host}).String()
}

// VerifyJWT verifies a token against the plugin's persisted public keys.
func (p *Plugin) VerifyJWT(ctx context.Context, token string, options VerifyOptions) (JWTClaims, error) {
	opts, authCtx, store, initialized := p.snapshot()
	if !initialized {
		return JWTClaims{}, errors.New("jwt: plugin is not initialized")
	}
	if store == nil {
		return JWTClaims{}, errors.New("jwt: local JWKS store is unavailable")
	}
	options = defaultVerifyOptions(opts, requestBaseURL(ctx, authCtx.BaseURL), options)
	keys, err := store.getPublicAll(ctx)
	if err != nil {
		return JWTClaims{}, fmt.Errorf("jwt: load verification keys: %w", err)
	}
	return verifyJWT(token, keys, options)
}

// VerifyAccessToken verifies an RFC 9068-style access-token JWT.
func (p *Plugin) VerifyAccessToken(ctx context.Context, token string, options VerifyOptions) (JWTClaims, error) {
	_, _, store, initialized := p.snapshot()
	if !initialized {
		return JWTClaims{}, errors.New("jwt: plugin is not initialized")
	}
	if store == nil {
		return JWTClaims{}, errors.New("jwt: local JWKS store is unavailable")
	}
	if options.Issuer == "" || len(options.Audience) == 0 || slices.Contains(options.Audience, "") {
		return JWTClaims{}, errors.New("jwt: access-token verification requires an explicit issuer and expected audience")
	}
	keys, err := store.getPublicAll(ctx)
	if err != nil {
		return JWTClaims{}, fmt.Errorf("jwt: load access-token verification keys: %w", err)
	}
	return verifyAccessToken(token, keys, options)
}

func defaultVerifyOptions(pluginOptions Options, baseURL string, verifyOptions VerifyOptions) VerifyOptions {
	if verifyOptions.Issuer == "" {
		if pluginOptions.JWT != nil && pluginOptions.JWT.Issuer != "" {
			verifyOptions.Issuer = pluginOptions.JWT.Issuer
		} else {
			verifyOptions.Issuer = baseURL
		}
	}
	if len(verifyOptions.Audience) == 0 {
		if pluginOptions.JWT != nil && len(pluginOptions.JWT.Audience) > 0 {
			verifyOptions.Audience = slices.Clone(pluginOptions.JWT.Audience)
		} else if baseURL != "" {
			verifyOptions.Audience = []string{baseURL}
		}
	}
	return verifyOptions
}

// SignCookieCache is discovered by auth routes for the JWT cookie-cache strategy.
func (p *Plugin) SignCookieCache(ctx context.Context, opts authtypes.Options, payload cookieCachePayload, maxAge time.Duration) (string, error) {
	signer := newCookieCacheSigner(p, p, p.cookieCacheEnabled())
	return signer.SignCookieCache(ctx, opts, payload, maxAge)
}

// VerifyCookieCache is discovered by auth routes for the JWT cookie-cache strategy.
func (p *Plugin) VerifyCookieCache(ctx context.Context, opts authtypes.Options, token string) (cookieCacheVerified, error) {
	signer := newCookieCacheSigner(p, p, p.cookieCacheEnabled())
	return signer.VerifyCookieCache(ctx, opts, token)
}

func (p *Plugin) cookieCacheEnabled() bool {
	opts, _, _, _ := p.snapshot()
	return opts.SessionCookieCache
}
