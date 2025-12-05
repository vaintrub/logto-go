package models

import "time"

// OrganizationInvitation represents an invitation to join an organization.
type OrganizationInvitation struct {
	ID             string             `json:"id"`
	TenantID       string             `json:"tenantId"`
	OrganizationID string             `json:"organizationId"`
	InviterID      string             `json:"inviterId"`
	Invitee        string             `json:"invitee"` // email
	AcceptedUserID string             `json:"acceptedUserId"`
	Status         string             `json:"status"` // "Pending", "Accepted", "Expired", "Revoked"
	Roles          []OrganizationRole `json:"organizationRoles"`
	ExpiresAt      time.Time          `json:"expiresAt"`
	CreatedAt      time.Time          `json:"createdAt"`
	UpdatedAt      time.Time          `json:"updatedAt"`
}

// OneTimeTokenResult holds the result of creating a one-time token.
type OneTimeTokenResult struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expiresAt"` // Unix timestamp (milliseconds)
}
