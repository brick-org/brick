package types

import "time"

// File boundary: auth/src/types/models.go, mirroring the upstream
// src/types/models.ts boundary (which re-exports the User, Session,
// Account, Verification, and RateLimit models).
//
// Content note: User and Session are moved unchanged from the former
// types/email_password.go tail per SOURCE_LAYOUT_MOVE_LIST.md (public types
// toward the auth.go/models.ts boundary). Account, Verification, and
// RateLimit have no dedicated Go structs; their shapes are covered by the
// adapter row contract and plugin schemas.

// User is the canonical user model returned by auth routes.
type User struct {
	ID               string         `json:"id"`
	Email            string         `json:"email"`
	EmailVerified    bool           `json:"emailVerified"`
	Name             string         `json:"name"`
	Image            *string        `json:"image,omitempty"`
	CreatedAt        time.Time      `json:"createdAt"`
	UpdatedAt        time.Time      `json:"updatedAt"`
	AdditionalFields map[string]any `json:"additionalFields,omitempty"`
}

// Session is the canonical session model returned by auth routes.
type Session struct {
	ID                   string         `json:"id"`
	UserID               string         `json:"userId"`
	Token                string         `json:"token"`
	ExpiresAt            time.Time      `json:"expiresAt"`
	IPAddress            *string        `json:"ipAddress,omitempty"`
	UserAgent            *string        `json:"userAgent,omitempty"`
	ActiveOrganizationID *string        `json:"activeOrganizationId,omitempty"`
	ActiveTeamID         *string        `json:"activeTeamId,omitempty"`
	CreatedAt            time.Time      `json:"createdAt"`
	UpdatedAt            time.Time      `json:"updatedAt"`
	AdditionalFields     map[string]any `json:"additionalFields,omitempty"`
}
