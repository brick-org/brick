package middlewares

import (
	"context"
	"fmt"
	"strings"

	"github.com/brick-org/brick/auth/src/types"
)

// --- Authorization middlewares (upstream
// `src/api/middlewares/authorization.ts`) ---
//
// Upstream exports two `createAuthMiddleware` factories used after the
// session middleware in an endpoint's `use` array. Both read the session
// from the endpoint context, load the target row through
// `ctx.context.adapter`, and throw `UNAUTHORIZED` (no session),
// `BAD_REQUEST` (missing id param), `NOT_FOUND` (missing resource), or
// `FORBIDDEN` (ownership/role failure). The verified row is returned on the
// context (`verifiedResource` / `verifiedMember`) so the handler skips a
// redundant query.
//
// The Go helpers below implement the same load-and-compare core against the
// `types.Adapter` contract without importing the `api`/`routes` Huma stack
// (which would cycle: enforcement lives in `api`). They return the loaded
// row on success so handlers can reuse it; failures are descriptive errors
// whose messages carry the upstream status code word (`UNAUTHORIZED`,
// `BAD_REQUEST`, `NOT_FOUND`, `FORBIDDEN`) for the caller to map to its
// error shape. A nil adapter fails closed.

// OwnershipConfig configures RequireResourceOwnership.
//
// Upstream TypeScript fields: model, idParam (resolved by the caller here to
// ResourceID from body/query), idSource (see IDSourceBody/IDSourceQuery),
// ownerField (default "userId"), notFoundError/forbiddenError custom error
// overrides, forbiddenStatus ("FORBIDDEN" default, or "UNAUTHORIZED").
type OwnershipConfig struct {
	// Model is the database model name (e.g. "passkey", "apiKey").
	Model string
	// OwnerField holds the owner's user ID on the resource. Default "userId".
	OwnerField string
	// ForbiddenStatus overrides the ownership-failure status word.
	// Default "FORBIDDEN"; upstream also allows "UNAUTHORIZED".
	ForbiddenStatus string
}

// ID source labels mirroring upstream's `idSource: "body" | "query"`. The Go
// helpers take the already-resolved ResourceID; the labels exist so callers
// can attribute where the id came from in logs/diagnostics.
const (
	// IDSourceBody marks ids read from the request body.
	IDSourceBody = "body"
	// IDSourceQuery marks ids read from the query string.
	IDSourceQuery = "query"
)

func ownershipField(cfg OwnershipConfig) string {
	if strings.TrimSpace(cfg.OwnerField) != "" {
		return cfg.OwnerField
	}
	return "userId"
}

func forbiddenStatus(cfg OwnershipConfig) string {
	if cfg.ForbiddenStatus == "UNAUTHORIZED" {
		return "UNAUTHORIZED"
	}
	return "FORBIDDEN"
}

// RequireResourceOwnership verifies the authenticated user owns a resource,
// mirroring upstream `requireResourceOwnership`
// (vendor/.../src/api/middlewares/authorization.ts:42-80). resourceID is the
// already-resolved id param (missing/empty reports BAD_REQUEST, mirroring a
// missing body/query param). It returns the loaded resource row on success
// (upstream `ctx.context.verifiedResource`).
func RequireResourceOwnership(ctx context.Context, db types.Adapter, cfg OwnershipConfig, resourceID, userID string) (map[string]any, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, fmt.Errorf("auth: UNAUTHORIZED")
	}
	if strings.TrimSpace(resourceID) == "" {
		return nil, fmt.Errorf("auth: BAD_REQUEST: missing required resource id")
	}
	if strings.TrimSpace(cfg.Model) == "" {
		return nil, fmt.Errorf("auth: BAD_REQUEST: missing model")
	}
	if db == nil {
		return nil, fmt.Errorf("auth: NOT_FOUND")
	}
	row, err := db.FindOne(ctx, cfg.Model, []types.Where{{Field: "id", Value: resourceID}}, nil)
	if err != nil || row == nil {
		return nil, fmt.Errorf("auth: NOT_FOUND")
	}
	owner, _ := row[ownershipField(cfg)].(string)
	if owner == "" {
		if id, ok := row["userId"].(string); ok && ownershipField(cfg) != "userId" {
			owner = id
		}
	}
	if owner != userID {
		return nil, fmt.Errorf("auth: %s", forbiddenStatus(cfg))
	}
	return row, nil
}

// RequireOrgRole verifies the authenticated user is a member of an
// organization with one of the allowed roles, mirroring upstream
// `requireOrgRole`
// (vendor/.../src/api/middlewares/authorization.ts:102-156).
// organizationID is the already-resolved org id param (missing/empty reports
// BAD_REQUEST). An empty allowedRoles list means any membership suffices
// (upstream: omitted or empty). Member roles stored as a comma-separated
// string all participate in the match. It returns the verified member row on
// success (upstream `ctx.context.verifiedMember`).
//
// The caller owns the "organization plugin required" gate (upstream throws
// BAD_REQUEST without it); pass hasOrganizationPlugin=false to reproduce it.
func RequireOrgRole(ctx context.Context, db types.Adapter, hasOrganizationPlugin bool, organizationID, userID string, allowedRoles []string) (map[string]any, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, fmt.Errorf("auth: UNAUTHORIZED")
	}
	if !hasOrganizationPlugin {
		return nil, fmt.Errorf("auth: BAD_REQUEST: Organization plugin is required for org role authorization")
	}
	if strings.TrimSpace(organizationID) == "" {
		return nil, fmt.Errorf("auth: BAD_REQUEST: missing required organization id")
	}
	if db == nil {
		return nil, fmt.Errorf("auth: FORBIDDEN: Not a member of this organization")
	}
	row, err := db.FindOne(ctx, "member", []types.Where{
		{Field: "userId", Value: userID},
		{Field: "organizationId", Value: organizationID, Connector: "AND"},
	}, nil)
	if err != nil || row == nil {
		return nil, fmt.Errorf("auth: FORBIDDEN: Not a member of this organization")
	}
	if len(allowedRoles) > 0 {
		raw, _ := row["role"].(string)
		memberRoles := parseMemberRoles(raw)
		allowed := make(map[string]struct{}, len(allowedRoles))
		for _, role := range allowedRoles {
			allowed[strings.TrimSpace(role)] = struct{}{}
		}
		matched := false
		for _, role := range memberRoles {
			if _, ok := allowed[role]; ok {
				matched = true
				break
			}
		}
		if !matched {
			return nil, fmt.Errorf("auth: FORBIDDEN: Insufficient role for this operation")
		}
	}
	return row, nil
}

// parseMemberRoles splits a comma-separated role string, mirroring upstream's
// inline `role.split(",").map(trim).filter(Boolean)`.
func parseMemberRoles(role string) []string {
	parts := strings.Split(role, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
