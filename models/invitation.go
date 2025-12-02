package models

import "time"

// OrganizationInvitation represents an invitation to join an organization.
type OrganizationInvitation struct {
	ID             string
	OrganizationID string
	Invitee        string // email
	Status         string // "Pending", "Accepted", "Expired", "Revoked"
	InviterID      string
	AcceptedUserID string
	Roles          []OrganizationRole
	ExpiresAt      time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// OneTimeTokenResult holds the result of creating a one-time token.
type OneTimeTokenResult struct {
	Token     string
	ExpiresAt int64 // Unix timestamp (seconds)
}
