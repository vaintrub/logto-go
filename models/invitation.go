package models

import (
	"fmt"
	"strings"
)

// InvitationStatus represents the status of an organization invitation.
type InvitationStatus string

const (
	InvitationStatusPending  InvitationStatus = "Pending"
	InvitationStatusAccepted InvitationStatus = "Accepted"
	InvitationStatusExpired  InvitationStatus = "Expired"
	InvitationStatusRevoked  InvitationStatus = "Revoked"
)

// ToInvitationStatus converts a string to InvitationStatus.
// It normalizes the input by capitalizing the first letter and lowercasing the rest.
// Returns an error if the status is unknown.
func ToInvitationStatus(s string) (InvitationStatus, error) {
	if len(s) == 0 {
		return "", fmt.Errorf("invalid invitation status: empty string")
	}

	normalized := strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
	status := InvitationStatus(normalized)

	switch status {
	case InvitationStatusPending, InvitationStatusAccepted, InvitationStatusExpired, InvitationStatusRevoked:
		return status, nil
	default:
		return "", fmt.Errorf("invalid invitation status: %q", s)
	}
}

// OrganizationInvitation represents an invitation to join an organization.
type OrganizationInvitation struct {
	ID             string             `json:"id"`
	TenantID       string             `json:"tenantId"`
	OrganizationID string             `json:"organizationId"`
	InviterID      string             `json:"inviterId"`
	Invitee        string             `json:"invitee"` // email
	AcceptedUserID string             `json:"acceptedUserId"`
	Status         InvitationStatus   `json:"status"`
	Roles          []OrganizationRole `json:"organizationRoles"`
	ExpiresAt      UnixMilliTime      `json:"expiresAt"`
	CreatedAt      UnixMilliTime      `json:"createdAt"`
	UpdatedAt      UnixMilliTime      `json:"updatedAt"`
}

// OrganizationInvitationCreate represents fields for creating an organization invitation.
type OrganizationInvitationCreate struct {
	OrganizationID      string        `json:"organizationId"`
	InviterID           string        `json:"inviterId"`
	Invitee             string        `json:"invitee"` // email
	OrganizationRoleIDs []string      `json:"organizationRoleIds,omitempty"`
	ExpiresAt           UnixMilliTime `json:"expiresAt"`
}

// OneTimeTokenCreate represents fields for creating a one-time token.
type OneTimeTokenCreate struct {
	Email              string   `json:"email"`
	ExpiresIn          int      `json:"expiresIn,omitempty"` // seconds, default 600
	JitOrganizationIDs []string `json:"jitOrganizationIds,omitempty"`
}

// OneTimeTokenResult holds the result of creating a one-time token.
type OneTimeTokenResult struct {
	Token     string        `json:"token"`
	ExpiresAt UnixMilliTime `json:"expiresAt"`
}
