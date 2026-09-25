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

// the shared context-generator service (types.MintModelID, mirroring upstream
// hint, matching upstream's generateId({model}) call sites.
// ok=false means "omit the ID and let the database issue it" (upstream
// model IDs — upstream mints those with generateId(n) directly — and must
// never flow through here.
func mintModelID(opts types.Options, model string) (string, bool) {
	return types.MintModelID(opts, model, nil)
}

// the generator defers to the database. Callers must then consume the
// persisted-row return (see persistedRowID) so adapter/database-issued IDs
func setRowID(row map[string]any, id string, ok bool) {
	if ok {
		row["id"] = id
	}
}

// the adapter/database-issued value over the pre-minted fallback (upstream
// factory output transform). A missing/unrecognized ID keeps the fallback so
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

// issuance, mirroring upstream createSession (db/internal-adapter.ts:466-603):
//     (upstream createWithHooks executeMainFn: storeInDb); the session ID is
//     minted in memory via the context generator with a random fallback when
// The token is caller-minted randomness (upstream token: generateId(32)
// direct, bypassing the context generator) and is never routed through
// ErrFailedToCreateSession.
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
	if sess.IPAddress == nil {
		sess.IPAddress = &ip
	}
	if sess.UserAgent == nil {
		sess.UserAgent = &userAgent
	}
	return sess, nil
}

// freshly issued session, mirroring upstream createSession
// (db/internal-adapter.ts:500-502):
// hop, X-Real-IP, RemoteAddr host (port stripped, bare IPv6 tolerated),
// the full upstream getIP proxy-chain semantics (trustedProxies CIDR walk,
// dev/test localhost fallback) that api/RequestClientIP implements for rate
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

// bare IPv6 literals (with or without brackets) that carry no port. Empty
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
