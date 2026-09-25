// File boundary: auth/src/types/index.go, mirroring the upstream
// src/types/index.ts boundary (which re-exports the adapter, api, auth,
// helper, models, and plugins type surfaces).
//
// Go needs no re-export file: every file in this directory already belongs
// to package types, so the public surface is the union of adapter.go,
// api.go, auth.go, dpop.go, email-password.go, helper.go, models.go,
// oauth.go, plugins.go, and trusted-origins.go. This file exists only to pin
// the upstream boundary.
package types
