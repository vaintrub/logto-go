// Package models contains data types for the Logto client.
package models

import "time"

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
	ID         string                 `json:"id"`
	TenantID   string                 `json:"tenantId"`
	UserID     string                 `json:"userId"`
	Issuer     string                 `json:"issuer"`
	IdentityID string                 `json:"identityId"`
	Detail     map[string]interface{} `json:"detail"`
	CreatedAt  time.Time              `json:"createdAt"`
	SSOCONNID  string                 `json:"ssoConnectorId"`
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
	LastSignInAt           *time.Time               `json:"lastSignInAt"`
	CreatedAt              time.Time                `json:"createdAt"`
	UpdatedAt              time.Time                `json:"updatedAt"`
	Profile                *UserProfile             `json:"profile"`
	ApplicationID          string                   `json:"applicationId"`
	IsSuspended            bool                     `json:"isSuspended"`
	HasPassword            bool                     `json:"hasPassword"`
	SSOIdentities          []SSOIdentity            `json:"ssoIdentities"`
	MFAVerificationFactors []string                 `json:"mfaVerificationFactors"`
}

// UserUpdate represents fields that can be updated for a user.
type UserUpdate struct {
	Name   *string
	Avatar *string
}
