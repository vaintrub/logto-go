package models

import "encoding/json"

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
	CreatedAt     UnixMilliTime          `json:"createdAt"`
}

// UserOrganization represents an organization with the user's roles in it.
// Returned by GET /api/users/{userId}/organizations endpoint.
type UserOrganization struct {
	Organization
	OrganizationRoles []OrganizationRole `json:"organizationRoles"`
}

// OrganizationMember represents a member in an organization with their roles.
type OrganizationMember struct {
	User  *User
	Roles []OrganizationRole
}

// organizationMemberRaw is used for JSON unmarshaling of OrganizationMember.
type organizationMemberRaw struct {
	User
	OrganizationRoles []OrganizationRole `json:"organizationRoles"`
}

// UnmarshalJSON implements custom JSON unmarshaling for OrganizationMember.
// The API returns user fields at the top level with organizationRoles embedded.
func (m *OrganizationMember) UnmarshalJSON(data []byte) error {
	var raw organizationMemberRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	m.User = &raw.User
	m.Roles = raw.OrganizationRoles
	return nil
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
