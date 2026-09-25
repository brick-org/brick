package types

import "time"

// Mirrors upstream src/types/models.ts.

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
