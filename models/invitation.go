package models

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
