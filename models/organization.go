package models

import "time"

// OrganizationBranding represents branding settings for an organization.
type OrganizationBranding struct {
	LogoURL     string `json:"logoUrl"`
	DarkLogoURL string `json:"darkLogoUrl"`
	Favicon     string `json:"favicon"`
	DarkFavicon string `json:"darkFavicon"`
}

// Organization represents organization details from Logto.
type Organization struct {
	ID            string                 `json:"id"`
	TenantID      string                 `json:"tenantId"`
	Name          string                 `json:"name"`
	Description   string                 `json:"description"`
	CustomData    map[string]interface{} `json:"customData"`
	IsMfaRequired bool                   `json:"isMfaRequired"`
	Branding      *OrganizationBranding  `json:"branding"`
	CreatedAt     time.Time              `json:"createdAt"`
}

// OrganizationMember represents a member in an organization with their roles.
type OrganizationMember struct {
	User  *User
	Roles []OrganizationRole
}

// OrganizationCreate represents fields for creating a new organization.
type OrganizationCreate struct {
	Name          string                 `json:"name"`
	Description   string                 `json:"description,omitempty"`
	CustomData    map[string]interface{} `json:"customData,omitempty"`
	IsMfaRequired *bool                  `json:"isMfaRequired,omitempty"`
	Branding      *OrganizationBranding  `json:"branding,omitempty"`
}

// OrganizationUpdate represents fields for updating an organization.
// Use pointers to distinguish between "not set" and "set to empty".
type OrganizationUpdate struct {
	Name          *string                `json:"name,omitempty"`
	Description   *string                `json:"description,omitempty"`
	CustomData    map[string]interface{} `json:"customData,omitempty"`
	IsMfaRequired *bool                  `json:"isMfaRequired,omitempty"`
	Branding      *OrganizationBranding  `json:"branding,omitempty"`
}

// UserOrganizationRolesUpdate represents fields for replacing user roles in an organization.
type UserOrganizationRolesUpdate struct {
	OrganizationRoleIDs []string `json:"organizationRoleIds"`
}
