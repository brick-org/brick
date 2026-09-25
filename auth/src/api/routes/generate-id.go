package routes

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/brick-org/brick/auth/src/crypto"
	"github.com/brick-org/brick/auth/src/types"
)

// mintModelID mints a model row ID honoring Advanced.Database.GenerateID via
// the shared context-generator service (types.MintModelID, mirroring upstream
// generateIdFunc in create-context.ts:248-263). Model mints pass no size
// hint, matching upstream's generateId({model}) call sites.
//
// ok=false means "omit the ID and let the database issue it" (upstream
// generateId:false / "serial", or a custom function returning false).
// Random tokens (session tokens, verification tokens, OAuth state) are NOT
// model IDs — upstream mints those with generateId(n) directly — and must
// never flow through here.
func mintModelID(opts types.Options, model string) (string, bool) {
	return types.MintModelID(opts, model, nil)
}

// setRowID sets the create-row ID from a mint result, omitting the key when
// the generator defers to the database. Callers must then consume the
// persisted-row return (see persistedRowID) so adapter/database-issued IDs
// win.
func setRowID(row map[string]any, id string, ok bool) {
	if ok {
		row["id"] = id
	}
}

// persistedRowID returns the persisted "id" from a created row, preferring
// the adapter/database-issued value over the pre-minted fallback (upstream
// create returns the persisted row; numeric serial IDs stringify like the
// factory output transform). A missing/unrecognized ID keeps the fallback so
// echo adapters behave identically to before.
func persistedRowID(row map[string]any, fallback string) string {
	if row == nil {
		return fallback
	}
	switch v := row["id"].(type) {
	case string:
		if v != "" {
			return v
		}
	case int:
		return fmt.Sprintf("%d", v)
	case int32:
		return fmt.Sprintf("%d", v)
	case int64:
		return fmt.Sprintf("%d", v)
	case uint:
		return fmt.Sprintf("%d", v)
	case uint64:
		return fmt.Sprintf("%d", v)
	case float64:
		return fmt.Sprintf("%.0f", v)
	}
	return fallback
}

// createIssuedSession creates the session row for credential/social/verified
// issuance, mirroring upstream createSession (db/internal-adapter.ts:466-603):
//
//   - secondary-only deployments (secondary storage without
//     Session.StoreSessionInDatabase) skip the primary DB entirely
//     (upstream createWithHooks executeMainFn: storeInDb); the session ID is
//     minted in memory via the context generator with a random fallback when
//     it defers to the database (`generatedId !== false ? generatedId :
//     generateId()` — there is no database to issue one);
//   - database deployments persist through opts.DB (hooks included, as with
//     every route-level create) and return the persisted row, so
//     adapter/database-issued IDs win.
//
// The token is caller-minted randomness (upstream token: generateId(32)
// direct, bypassing the context generator) and is never routed through
// mintModelID. A failing create surfaces an error; callers map it to
// ErrFailedToCreateSession.
//
// Upstream TypeScript name: createSession.
func createIssuedSession(ctx context.Context, opts types.Options, userID, token string, expiresAt, now time.Time) (types.Session, error) {
	id, ok := mintModelID(opts, "session")
	// Upstream stamps ipAddress/userAgent before store routing
	// (db/internal-adapter.ts:498-518), so both legs below carry them.
	ip, userAgent := sessionRequestMeta(ctx)
	if opts.SecondaryStorage != nil && !opts.Session.StoreSessionInDatabase {
		if !ok || id == "" {
			id = crypto.GenerateID()
		}
		return types.Session{
			ID:        id,
			UserID:    userID,
			Token:     token,
			ExpiresAt: expiresAt,
			CreatedAt: now,
			UpdatedAt: now,
			IPAddress: &ip,
			UserAgent: &userAgent,
		}, nil
	}
	if opts.DB == nil {
		return types.Session{}, errors.New("auth: session persistence requires options.DB")
	}
	row := map[string]any{
		"userId":    userID,
		"token":     token,
		"expiresAt": expiresAt,
		"createdAt": now,
		"updatedAt": now,
		"ipAddress": ip,
		"userAgent": userAgent,
	}
	setRowID(row, id, ok)
	created, err := opts.DB.Create(ctx, "session", row, nil)
	if err != nil {
		return types.Session{}, err
	}
	sess := rowToSession(created, opts)
	// rowToSession only sets the pointers for non-empty cells, but upstream
	// returns the created object with the fields always present ("", never
	// null). Fill from the resolved values written above so the return
	// matches the row on both legs.
	if sess.IPAddress == nil {
		sess.IPAddress = &ip
	}
	if sess.UserAgent == nil {
		sess.UserAgent = &userAgent
	}
	return sess, nil
}

// sessionRequestMeta resolves the client IP and user agent stamped onto a
// freshly issued session, mirroring upstream createSession
// (db/internal-adapter.ts:500-502):
//
//	ipAddress: headers ? getIP(headers, options) || "" : ""
//	userAgent: headers?.get("user-agent") || ""
//
// The request is the middleware-reconstructed one carried on ctx
// (StoredRequestFromStd, installed by the always-on api middleware),
// falling back to the huma-rebuilt one (callbackRequest). Both are nil
// outside a request (programmatic issuance), which resolves to "" for both
// fields. Resolution order for the IP: X-Forwarded-For leftmost non-empty
// hop, X-Real-IP, RemoteAddr host (port stripped, bare IPv6 tolerated),
// then "". The user agent is the User-Agent header verbatim, then "".
//
// DOCUMENTED DEVIATION (for SCOPE.md): this intentionally does NOT replicate
// the full upstream getIP proxy-chain semantics (trustedProxies CIDR walk,
// ipAddressHeaders ordering, disableIpTracking, IPv6-subnet normalization,
// dev/test localhost fallback) that api/RequestClientIP implements for rate
// limiting. Session issuance stores the directly resolved client address.
func sessionRequestMeta(ctx context.Context) (ip, userAgent string) {
	req := StoredRequestFromStd(ctx)
	if req == nil {
		req = callbackRequest(ctx)
	}
	if req == nil {
		return "", ""
	}
	return clientIPFromRequest(req), req.Header.Get("User-Agent")
}

// clientIPFromRequest resolves the direct client IP from req. A nil request
// resolves to "".
func clientIPFromRequest(req *http.Request) string {
	if req == nil {
		return ""
	}
	if hop := firstForwardedHop(req.Header.Get("X-Forwarded-For")); hop != "" {
		return hop
	}
	if ip := strings.TrimSpace(req.Header.Get("X-Real-IP")); ip != "" {
		return ip
	}
	return remoteAddrHost(req.RemoteAddr)
}

// firstForwardedHop returns the leftmost non-empty X-Forwarded-For hop,
// trimmed. An empty header resolves to "".
func firstForwardedHop(header string) string {
	for _, hop := range strings.Split(header, ",") {
		if hop = strings.TrimSpace(hop); hop != "" {
			return hop
		}
	}
	return ""
}

// remoteAddrHost strips a trailing :port from a RemoteAddr value, tolerating
// bare IPv6 literals (with or without brackets) that carry no port. Empty
// input resolves to "".
func remoteAddrHost(remoteAddr string) string {
	s := strings.TrimSpace(remoteAddr)
	if s == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		return host
	}
	return strings.Trim(s, "[]")
}
