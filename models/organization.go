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
