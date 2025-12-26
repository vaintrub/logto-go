// Package models contains data types for the Logto client.
package models

// UserIdentity represents a user's identity from a social/enterprise provider.
type UserIdentity struct {
	UserID  string                 `json:"userId"`
	Details map[string]interface{} `json:"details"`
}

// UserProfile represents additional user profile information.
type UserProfile struct {
	FamilyName        string         `json:"familyName"`
	GivenName         string         `json:"givenName"`
	MiddleName        string         `json:"middleName"`
	Nickname          string         `json:"nickname"`
	PreferredUsername string         `json:"preferredUsername"`
	Profile           string         `json:"profile"`
	Website           string         `json:"website"`
	Gender            string         `json:"gender"`
	Birthdate         string         `json:"birthdate"`
	Zoneinfo          string         `json:"zoneinfo"`
	Locale            string         `json:"locale"`
	Address           *ProfileAddress `json:"address"`
}

// ProfileAddress represents an address in user profile.
type ProfileAddress struct {
	Formatted     string `json:"formatted"`
	StreetAddress string `json:"streetAddress"`
	Locality      string `json:"locality"`
	Region        string `json:"region"`
	PostalCode    string `json:"postalCode"`
	Country       string `json:"country"`
}

// SSOIdentity represents an SSO identity linked to a user.
type SSOIdentity struct {
	ID             string                 `json:"id"`
	TenantID       string                 `json:"tenantId"`
	UserID         string                 `json:"userId"`
	Issuer         string                 `json:"issuer"`
	IdentityID     string                 `json:"identityId"`
	Detail         map[string]interface{} `json:"detail"`
	CreatedAt      UnixMilliTime          `json:"createdAt"`
	SSOConnectorID string                 `json:"ssoConnectorId"`
}

// UserOrganizationRole represents a user's role assignment in an organization.
// This is returned when fetching user details with organization roles included.
type UserOrganizationRole struct {
	OrganizationID string `json:"organizationId"`
	RoleID         string `json:"roleId"`
	RoleName       string `json:"roleName"`
}

// User represents user data from Logto.
type User struct {
	ID                     string                   `json:"id"`
	TenantID               string                   `json:"tenantId"`
	Username               string                   `json:"username"`
	PrimaryEmail           string                   `json:"primaryEmail"`
	PrimaryPhone           string                   `json:"primaryPhone"`
	Name                   string                   `json:"name"`
	Avatar                 string                   `json:"avatar"`
	CustomData             map[string]interface{}   `json:"customData"`
	Identities             map[string]UserIdentity  `json:"identities"`
	LastSignInAt           *UnixMilliTime           `json:"lastSignInAt"`
	CreatedAt              UnixMilliTime            `json:"createdAt"`
	UpdatedAt              UnixMilliTime            `json:"updatedAt"`
	Profile                *UserProfile             `json:"profile"`
	ApplicationID          string                   `json:"applicationId"`
	IsSuspended            bool                     `json:"isSuspended"`
	HasPassword            bool                     `json:"hasPassword"`
	SSOIdentities          []SSOIdentity            `json:"ssoIdentities"`
	MFAVerificationFactors []string                 `json:"mfaVerificationFactors"`
	// Optional fields returned with expanded queries
	Roles             []Role                 `json:"roles,omitempty"`
	Organizations     []Organization         `json:"organizations,omitempty"`
	OrganizationRoles []UserOrganizationRole `json:"organizationRoles,omitempty"`
}

// UserUpdate represents fields that can be updated for a user.
// Use pointers to distinguish between "not set" and "set to empty".
type UserUpdate struct {
	// Basic profile fields
	Username *string `json:"username,omitempty"`
	Name     *string `json:"name,omitempty"`
	Avatar   *string `json:"avatar,omitempty"`

	// Primary identifiers
	PrimaryEmail *string `json:"primaryEmail,omitempty"`
	PrimaryPhone *string `json:"primaryPhone,omitempty"`

	// Custom data - merged with existing data
	CustomData map[string]interface{} `json:"customData,omitempty"`

	// Profile - detailed user profile fields (familyName, givenName, etc.)
	Profile *UserProfileUpdate `json:"profile,omitempty"`
}

// UserCreate represents fields for creating a new user.
type UserCreate struct {
	Username     string                 `json:"username"`
	Password     string                 `json:"password"`
	Name         string                 `json:"name,omitempty"`
	PrimaryEmail string                 `json:"primaryEmail,omitempty"`
	PrimaryPhone string                 `json:"primaryPhone,omitempty"`
	Avatar       string                 `json:"avatar,omitempty"`
	CustomData   map[string]interface{} `json:"customData,omitempty"`
	Profile      *UserProfileUpdate     `json:"profile,omitempty"`
}

// UserProfileUpdate represents fields for updating user profile.
type UserProfileUpdate struct {
	FamilyName        *string         `json:"familyName,omitempty"`
	GivenName         *string         `json:"givenName,omitempty"`
	MiddleName        *string         `json:"middleName,omitempty"`
	Nickname          *string         `json:"nickname,omitempty"`
	PreferredUsername *string         `json:"preferredUsername,omitempty"`
	Profile           *string         `json:"profile,omitempty"`
	Website           *string         `json:"website,omitempty"`
	Gender            *string         `json:"gender,omitempty"`
	Birthdate         *string         `json:"birthdate,omitempty"`
	Zoneinfo          *string         `json:"zoneinfo,omitempty"`
	Locale            *string         `json:"locale,omitempty"`
	Address           *ProfileAddress `json:"address,omitempty"`
}

// UserPasswordUpdate represents fields for updating a user's password.
type UserPasswordUpdate struct {
	Password string `json:"password"`
}
