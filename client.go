// Package logto provides a self-contained client for Logto Identity Provider.
// It can be used as a standalone package in other Go projects.
package logto

import (
	"context"
	"time"
)

// Client defines the interface for interacting with Logto Identity Provider.
type Client interface {
	// Health
	Ping(ctx context.Context) error

	// M2M Auth
	AuthenticateM2M(ctx context.Context) (accessToken string, expiresIn int, err error)

	// Users (GET /users, GET /users/{userId}, PATCH /users/{userId})
	GetUser(ctx context.Context, userID string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	ListUsers(ctx context.Context) ([]*User, error)
	UpdateUser(ctx context.Context, userID string, update UserUpdate) error
	UpdateUserCustomData(ctx context.Context, userID string, customData map[string]interface{}) error

	// Organizations (GET /organizations, GET /organizations/{id}, POST/PATCH/DELETE)
	GetOrganization(ctx context.Context, orgID string) (*Organization, error)
	ListOrganizations(ctx context.Context) ([]*Organization, error)
	ListUserOrganizations(ctx context.Context, userID string) ([]*Organization, error)
	CreateOrganization(ctx context.Context, name, description string) (orgID string, err error)
	UpdateOrganization(ctx context.Context, orgID string, name, description string, customData map[string]interface{}) error
	DeleteOrganization(ctx context.Context, orgID string) error

	// Organization Members (GET/POST/DELETE /organizations/{id}/users/*)
	ListOrganizationMembers(ctx context.Context, orgID string) ([]*OrganizationMember, error)
	AddUserToOrganization(ctx context.Context, orgID, userID string, roleIDs []string) error
	RemoveUserFromOrganization(ctx context.Context, orgID, userID string) error
	UpdateUserRoles(ctx context.Context, orgID, userID string, roleIDs []string) error
	GetUserRolesInOrganization(ctx context.Context, orgID, userID string) ([]OrganizationRole, error)

	// Organization Roles (GET/POST/PATCH/DELETE /organization-roles)
	GetOrganizationRole(ctx context.Context, roleID string) (*OrganizationRole, error)
	ListOrganizationRoles(ctx context.Context) ([]OrganizationRole, error)
	CreateOrganizationRole(ctx context.Context, name, description string, scopeIDs []string) (roleID string, err error)
	UpdateOrganizationRole(ctx context.Context, roleID, name, description string) error
	DeleteOrganizationRole(ctx context.Context, roleID string) error

	// Organization Role Scopes (GET/PUT/DELETE /organization-roles/{id}/scopes)
	GetOrganizationRoleScopes(ctx context.Context, roleID string) ([]OrganizationScope, error)
	SetOrganizationRoleScopes(ctx context.Context, roleID string, scopeIDs []string) error
	AddOrganizationRoleScopes(ctx context.Context, roleID string, scopeIDs []string) error
	RemoveOrganizationRoleScope(ctx context.Context, roleID, scopeID string) error

	// Organization Scopes (GET/POST/PATCH/DELETE /organization-scopes)
	GetOrganizationScope(ctx context.Context, scopeID string) (*OrganizationScope, error)
	ListOrganizationScopes(ctx context.Context) ([]OrganizationScope, error)
	CreateOrganizationScope(ctx context.Context, name, description string) (scopeID string, err error)
	UpdateOrganizationScope(ctx context.Context, scopeID, name, description string) error
	DeleteOrganizationScope(ctx context.Context, scopeID string) error

	// API Resources (GET/POST/PATCH/DELETE /resources)
	GetAPIResource(ctx context.Context, resourceID string) (*APIResource, error)
	ListAPIResources(ctx context.Context) ([]*APIResource, error)
	CreateAPIResource(ctx context.Context, name, indicator string) (resourceID string, err error)
	UpdateAPIResource(ctx context.Context, resourceID, name string, accessTokenTTL *int) error
	DeleteAPIResource(ctx context.Context, resourceID string) error

	// API Resource Scopes (GET/POST/PATCH/DELETE /resources/{id}/scopes)
	GetAPIResourceScope(ctx context.Context, resourceID, scopeID string) (*APIResourceScope, error)
	ListAPIResourceScopes(ctx context.Context, resourceID string) ([]*APIResourceScope, error)
	CreateAPIResourceScope(ctx context.Context, resourceID, name, description string) (scopeID string, err error)
	UpdateAPIResourceScope(ctx context.Context, resourceID, scopeID, name, description string) error
	DeleteAPIResourceScope(ctx context.Context, resourceID, scopeID string) error

	// Invitations (GET/POST/DELETE /organization-invitations)
	CreateOrganizationInvitation(ctx context.Context, orgID, inviterID, email string, roleIDs []string, expiresAtMs int64) (invitationID string, err error)
	ListOrganizationInvitations(ctx context.Context, orgID string) ([]*OrganizationInvitation, error)
	GetOrganizationInvitation(ctx context.Context, invitationID string) (*OrganizationInvitation, error)
	DeleteOrganizationInvitation(ctx context.Context, invitationID string) error
	SendInvitationMessage(ctx context.Context, invitationID, magicLink string) error

	// One-Time Tokens (POST /api/one-time-tokens)
	CreateOneTimeToken(ctx context.Context, email string, expiresIn int, jitOrgIDs []string) (*OneTimeTokenResult, error)
}

// User represents user data from Logto
type User struct {
	ID          string
	Name        string
	Email       string // primary_email
	Avatar      string
	IsSuspended bool
	CustomData  map[string]interface{} // For user preferences
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// UserUpdate represents fields that can be updated for a user
type UserUpdate struct {
	Name   *string
	Avatar *string
}

// Organization represents organization details from Logto
type Organization struct {
	ID          string
	Name        string
	Description string
	CustomData  map[string]interface{}
	CreatedAt   time.Time
}

// OrganizationMember represents a member in an organization with their roles
type OrganizationMember struct {
	User  *User
	Roles []OrganizationRole
}

// OrganizationRole represents a role definition in Logto
type OrganizationRole struct {
	ID          string
	Name        string
	Description string
	Scopes      []OrganizationScope
}

// OrganizationScope represents a permission scope in Logto's organization template
type OrganizationScope struct {
	ID          string
	Name        string
	Description string
}

// APIResource represents an API resource in Logto
type APIResource struct {
	ID             string
	Name           string
	Indicator      string // The unique resource identifier (URL)
	AccessTokenTTL int    // Token TTL in seconds
	IsDefault      bool
}

// APIResourceScope represents a permission scope for an API resource
type APIResourceScope struct {
	ID          string
	ResourceID  string
	Name        string
	Description string
}

// OrganizationInvitation represents an invitation to join an organization
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

// m2mTokenCache holds cached M2M access tokens (internal use only)
type m2mTokenCache struct {
	accessToken string
	expiresAt   time.Time
}

// OneTimeTokenResult holds the result of creating a one-time token
type OneTimeTokenResult struct {
	Token     string
	ExpiresAt int64 // Unix timestamp (seconds)
}
