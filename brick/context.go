package brick

import (
	"context"
	"reflect"
	"strings"
)

// User is brick's minimal identity model. The auth package was cut in the
// rebuild (identity is Frappe's job; brick only carries it) — apps map
// their verified identity onto this struct in CtxFromRequest. JSON tags
// mirror the old auth types so `from: session.*` resolution keeps working.
type User struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// Session is brick's minimal session model. Only the fields the runtime
// resolves (`userId` via `from:`) and the app seam needs are carried.
type Session struct {
	ID                   string  `json:"id"`
	UserID               string  `json:"userId"`
	ActiveOrganizationID *string `json:"activeOrganizationId,omitempty"`
	ActiveTeamID         *string `json:"activeTeamId,omitempty"`
}

// AppCtx is the default per-request context brick stores on every request.
// It carries the authenticated User and Session resolved by the app, when
// present. Apps that need extra context fields embed it:
//
//	type MyCtx struct {
//	    brick.AppCtx
//	    Team string
//	}
//
// Then pass Config[MyCtx] + a CtxFromRequest that derives MyCtx from
// the request.
type AppCtx struct {
	Actor   *User
	Session *Session
}

// BrickActor / BrickSession satisfy AppCtxer so brick.AppCtx (and structs
// that embed it) are storable in the request context for schema.From
// resolution and guards.
func (a AppCtx) BrickActor() any   { return a.Actor }
func (a AppCtx) BrickSession() any { return a.Session }

// AppCtxer is the interface brick stores in the request context. Any type
// that exposes Actor/Session — including the default brick.AppCtx and
// user structs that embed it — satisfies this automatically.
type AppCtxer interface {
	BrickActor() any
	BrickSession() any
}

type appCtxKey struct{}

// storeAppCtx puts the AppCtxer in the request context. Called by Middleware.
func storeAppCtx(ctx context.Context, ac AppCtxer) context.Context {
	return context.WithValue(ctx, appCtxKey{}, ac)
}

// appCtxFromContext retrieves the AppCtxer stored by Middleware. Returns nil
// when the request was unauthenticated.
func appCtxFromContext(ctx context.Context) AppCtxer {
	ac, _ := ctx.Value(appCtxKey{}).(AppCtxer)
	return ac
}

// GetActor returns the authenticated user attached to the request, or
// nil for anonymous requests. Works regardless of which concrete TCtx
// the app uses — relies on the AppCtxer interface, which brick.AppCtx
// (and any struct embedding it) satisfies automatically.
func GetActor(ctx context.Context) *User {
	ac := appCtxFromContext(ctx)
	if ac == nil {
		return nil
	}
	u, _ := ac.BrickActor().(*User)
	return u
}

// GetSession returns the active session attached to the request, or nil
// for anonymous requests. Same TCtx-agnostic shape as GetActor.
func GetSession(ctx context.Context) *Session {
	ac := appCtxFromContext(ctx)
	if ac == nil {
		return nil
	}
	s, _ := ac.BrickSession().(*Session)
	return s
}

// GetAppCtx retrieves the typed app context from a request context.
// Returns nil if the request was unauthenticated or the stored type doesn't match T.
//
//	appCtx := brick.GetAppCtx[MyCtx](ctx)
//	if appCtx == nil { return brick.Unauthorized("sign in required") }
func GetAppCtx[T any](ctx context.Context) *T {
	p, _ := ctx.Value(appCtxKey{}).(*T)
	return p
}

// resolveFromAppCtx resolves a dot-separated path like "session.userId" against
// the AppCtxer's Actor/Session via reflection on JSON-tagged fields.
func resolveFromAppCtx(ac AppCtxer, path string) any {
	if ac == nil {
		return nil
	}
	root, key, ok := strings.Cut(path, ".")
	if !ok {
		return nil
	}
	var target any
	switch root {
	case "actor":
		target = ac.BrickActor()
	case "session":
		target = ac.BrickSession()
	default:
		return nil
	}
	if target == nil {
		return nil
	}
	return resolveJSONField(target, key)
}

// resolveJSONField finds a field on a struct by its JSON tag name. Returns nil if not found.
func resolveJSONField(v any, jsonName string) any {
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Ptr {
		if rv.IsNil() {
			return nil
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return nil
	}
	rt := rv.Type()
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		tag := f.Tag.Get("json")
		if tag == "" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if name == jsonName {
			fv := rv.Field(i)
			if (fv.Kind() == reflect.Ptr || fv.Kind() == reflect.Interface) && fv.IsNil() {
				return nil
			}
			if fv.Kind() == reflect.Ptr {
				return fv.Elem().Interface()
			}
			return fv.Interface()
		}
	}
	return nil
}
