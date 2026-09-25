package types

import (
	"github.com/brick-org/brick/auth/src/crypto"
	"github.com/google/uuid"
)

// File boundary: auth/src/types/helper.go, mirroring the upstream
// src/types/helper.ts boundary.
//
// Content note: upstream helper.ts is type-level only (Prettify,
// UnionToIntersection, ...) with no Go equivalent. This file carries the
// generateId runtime (MintModelID), moved unchanged from the former
// types/generate-id.go per SOURCE_LAYOUT_MOVE_LIST.md
// (types/generate-id.go -> types/helper.go).

// MintModelID mints a model row ID honoring Advanced.Database.GenerateID,
// mirroring upstream generateIdFunc (create-context.ts:248-263) and the
// adapter idField defaultValue (core/src/db/adapter/get-id-field.ts:59-90):
//
//   - a custom Func wins (receives model + optional size hint, may return
//     false for database-issued IDs);
//   - Mode "uuid" mints a random UUID (crypto.randomUUID upstream);
//   - Mode "serial" resolves to ("", false) so the database issues the ID
//     (upstream generateId:false);
//   - otherwise the default random identifier applies (upstream generateId;
//     size hint <= 0 falls back to the 32-character default).
//
// Callers must treat ("", false) as "omit the ID and let the database
// generate it", and must consume the persisted-row return so
// adapter/database-issued IDs win over any pre-minted value. Random tokens
// (session tokens, verification tokens, OAuth state) are NOT model IDs:
// upstream mints those with generateId(n) directly, bypassing the context
// generator, so they must keep crypto randomness and never flow through here.
//
// Upstream TypeScript name: generateId.
func MintModelID(opts Options, model string, size *int) (string, bool) {
	if fn := opts.Advanced.Database.GenerateID.Func; fn != nil {
		return fn(model, size)
	}
	switch opts.Advanced.Database.GenerateID.Mode {
	case GenerateIDModeUUID:
		return newUUID(), true
	case GenerateIDModeSerial:
		return "", false
	default:
		n := 0
		if size != nil {
			n = *size
		}
		if n <= 0 {
			return crypto.GenerateID(), true
		}
		return crypto.GenerateIDWithSize(n), true
	}
}

// newUUID mints an RFC 4122 version-4 UUID (google/uuid, already in the
// module graph via bun — replaces the former hand-rolled crypto/rand port).
func newUUID() string {
	return uuid.NewString()
}
