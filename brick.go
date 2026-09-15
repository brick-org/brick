package brick

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/bdpiprava/scalar-go"
	"github.com/brick-org/brick/db"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humabunrouter"
	"github.com/uptrace/bun"
	"github.com/uptrace/bunrouter"
)

// Config holds the configuration for creating a Brick instance.
// TCtx is the app-defined context type; use Config[any] when no typed context is needed.
type Config[TCtx any] struct {
	Title   string
	Version string
	DB      *bun.DB

	// API lets callers (typically tests via humatest) supply a pre-built
	// huma.API. When nil, brick creates its own using bunrouter +
	// humabunrouter, and owns the resulting http.Handler. Set this if you
	// need full control over the adapter/router or want to drive routes
	// with humatest.
	API huma.API

	// Resources is the list of resources to register CRUD routes for.
	Resources []ResourceConfig

	// Routes registers custom (non-CRUD) routes on the huma API.
	Routes func(api huma.API, db *db.DB)

	// CtxFromRequest derives the app's context from the request. Brick
	// calls it with a nil base (brick mounts no auth of its own — the app
	// resolves identity upstream, e.g. in wrapping middleware) and stores
	// the result when it implements AppCtxer. Nil result = anonymous;
	// guards treat it as unauthenticated.
	CtxFromRequest func(req *http.Request, base *AppCtx) *TCtx
}

// Brick is the main framework instance, typed on the app's context type.
type Brick[TCtx any] struct {
	config Config[TCtx]
	api    huma.API
	db     *db.DB
	router *bunrouter.Router // nil when API was injected externally
}

// New creates a new Brick instance. When config.API is nil, brick builds
// its own router/adapter/api stack and owns the resulting http.Handler.
// When config.API is non-nil, brick uses it as-is and owns neither the
// router nor the handler (Handler returns nil then). Misconfiguration
// (nil DB) is an error, never a panic.
func New[TCtx any](config Config[TCtx]) (*Brick[TCtx], error) {
	if config.Title == "" {
		config.Title = "Brick API"
	}
	if config.Version == "" {
		config.Version = "1.0.0"
	}
	if config.DB == nil {
		return nil, fmt.Errorf("brick: Config.DB is nil")
	}

	b := &Brick[TCtx]{config: config, db: db.New(config.DB)}

	if config.API != nil {
		// Test / advanced path: caller supplied a pre-built huma.API.
		// Brick won't create a router.
		b.api = config.API
	} else {
		// Production path: brick owns the router stack.
		b.router = bunrouter.New()
		adapter := humabunrouter.NewAdapter(b.router)
		b.api = huma.NewAPI(huma.DefaultConfig(config.Title, config.Version), adapter)
	}

	for i := range config.Resources {
		b.registerRoutes(&config.Resources[i])
	}

	if config.Routes != nil {
		config.Routes(b.api, b.db)
	}

	return b, nil
}

// Huma returns the underlying huma API.
func (b *Brick[TCtx]) Huma() huma.API {
	return b.api
}

// OpenAPISpec returns the serialized OpenAPI 3.1 JSON spec for the app.
// Call after New() to capture the spec without starting a server.
func (b *Brick[TCtx]) OpenAPISpec() ([]byte, error) {
	return json.MarshalIndent(b.api.OpenAPI(), "", "  ")
}

// DB returns the brick database wrapper.
func (b *Brick[TCtx]) DB() *db.DB {
	return b.db
}

// Router returns the brick-owned bunrouter so callers can register
// non-huma routes (e.g. /reference scalar docs HTML). Returns nil when
// config.API was supplied externally — that caller owns their router.
func (b *Brick[TCtx]) Router() *bunrouter.Router {
	return b.router
}

// Handler returns an http.Handler wrapping brick's middleware + router.
// Returns nil when brick doesn't own the router (config.API was supplied).
func (b *Brick[TCtx]) Handler() http.Handler {
	if b.router == nil {
		return nil
	}
	return requestIDMiddleware(b.Middleware()(b.router))
}

// ListenAndServe starts an http server bound to addr serving brick's
// Handler. Returns an error if brick doesn't own the router.
func (b *Brick[TCtx]) ListenAndServe(addr string) error {
	h := b.Handler()
	if h == nil {
		return fmt.Errorf("brick.ListenAndServe: no router (set Config.API to nil to let brick own the router)")
	}
	return http.ListenAndServe(addr, h)
}

// Middleware returns an HTTP middleware that stores the typed app context
// in every request context. Identity is resolved upstream (base is always
// nil — brick mounts no auth); CtxFromRequest maps the request to the
// app's context type, stored via storeAppCtx when it implements AppCtxer.
// No header reads happen here: the app owns headers/crypto in its own
// middleware, brick owns ctx plumbing.
func (b *Brick[TCtx]) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			if b.config.CtxFromRequest != nil {
				if appCtx := b.config.CtxFromRequest(r, nil); appCtx != nil {
					if ac, ok := any(appCtx).(AppCtxer); ok {
						ctx = storeAppCtx(ctx, ac)
					}
				}
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ScalarDocsHTML returns the full HTML page for the Scalar API reference viewer.
func ScalarDocsHTML(specURL string) (string, error) {
	return scalargo.NewV2(
		scalargo.WithSpecURL(specURL),
		scalargo.WithTheme(scalargo.ThemeBluePlanet),
		scalargo.WithDarkMode(),
	)
}
