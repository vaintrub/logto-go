// Package client provides a self-contained client for Logto Identity Provider.
package client

import (
	"context"
	"time"

	"github.com/vaintrub/logto-go/models"
)

// Client defines the interface for interacting with Logto Identity Provider.
type Client interface {
	// Health
	Ping(ctx context.Context) error

	// M2M Auth
	AuthenticateM2M(ctx context.Context) (accessToken string, expiresIn int, err error)

	// Users (GET /users, GET /users/{userId}, POST /users, PATCH /users/{userId})
	GetUser(ctx context.Context, userID string) (*models.User, error)
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	ListUsers(ctx context.Context) ([]*models.User, error)
	CreateUser(ctx context.Context, username, password, name, primaryEmail string) (userID string, err error)
	UpdateUser(ctx context.Context, userID string, update models.UserUpdate) error
	UpdateUserCustomData(ctx context.Context, userID string, customData map[string]interface{}) error

	// Organizations (GET /organizations, GET /organizations/{id}, POST/PATCH/DELETE)
	GetOrganization(ctx context.Context, orgID string) (*models.Organization, error)
	ListOrganizations(ctx context.Context) ([]*models.Organization, error)
	ListUserOrganizations(ctx context.Context, userID string) ([]*models.Organization, error)
	CreateOrganization(ctx context.Context, name, description string) (orgID string, err error)
	UpdateOrganization(ctx context.Context, orgID string, name, description string, customData map[string]interface{}) error
	DeleteOrganization(ctx context.Context, orgID string) error

	// Organization Members (GET/POST/DELETE /organizations/{id}/users/*)
	ListOrganizationMembers(ctx context.Context, orgID string) ([]*models.OrganizationMember, error)
	AddUserToOrganization(ctx context.Context, orgID, userID string, roleIDs []string) error
	AddUsersToOrganization(ctx context.Context, orgID string, userIDs []string) error // Batch add
	RemoveUserFromOrganization(ctx context.Context, orgID, userID string) error
	UpdateUserRoles(ctx context.Context, orgID, userID string, roleIDs []string) error
	AssignRolesToOrganizationUsers(ctx context.Context, orgID string, userIDs, roleIDs []string) error // Batch assign roles
	GetUserRolesInOrganization(ctx context.Context, orgID, userID string) ([]models.OrganizationRole, error)

	// Organization Roles (GET/POST/PATCH/DELETE /organization-roles)
	GetOrganizationRole(ctx context.Context, roleID string) (*models.OrganizationRole, error)
	ListOrganizationRoles(ctx context.Context) ([]models.OrganizationRole, error)
	CreateOrganizationRole(ctx context.Context, name, description string, scopeIDs []string) (roleID string, err error)
	UpdateOrganizationRole(ctx context.Context, roleID, name, description string) error
	DeleteOrganizationRole(ctx context.Context, roleID string) error

	// Organization Role Scopes (PUT/POST/DELETE /organization-roles/{id}/scopes)
	// Note: Use GetOrganizationRole().Scopes to get role scopes
	SetOrganizationRoleScopes(ctx context.Context, roleID string, scopeIDs []string) error
	AddOrganizationRoleScopes(ctx context.Context, roleID string, scopeIDs []string) error
	RemoveOrganizationRoleScope(ctx context.Context, roleID, scopeID string) error

	// Organization Role Resource Scopes (POST /organization-roles/{id}/resource-scopes)
	AssignResourceScopesToOrganizationRole(ctx context.Context, roleID string, scopeIDs []string) error

	// Organization Scopes (GET/POST/PATCH/DELETE /organization-scopes)
	GetOrganizationScope(ctx context.Context, scopeID string) (*models.OrganizationScope, error)
	ListOrganizationScopes(ctx context.Context) ([]models.OrganizationScope, error)
	CreateOrganizationScope(ctx context.Context, name, description string) (scopeID string, err error)
	UpdateOrganizationScope(ctx context.Context, scopeID, name, description string) error
	DeleteOrganizationScope(ctx context.Context, scopeID string) error

	// API Resources (GET/POST/PATCH/DELETE /resources)
	GetAPIResource(ctx context.Context, resourceID string) (*models.APIResource, error)
	ListAPIResources(ctx context.Context) ([]*models.APIResource, error)
	CreateAPIResource(ctx context.Context, name, indicator string) (resourceID string, err error)
	UpdateAPIResource(ctx context.Context, resourceID, name string, accessTokenTTL *int) error
	DeleteAPIResource(ctx context.Context, resourceID string) error

	// API Resource Scopes (GET/POST/PATCH/DELETE /resources/{id}/scopes)
	GetAPIResourceScope(ctx context.Context, resourceID, scopeID string) (*models.APIResourceScope, error)
	ListAPIResourceScopes(ctx context.Context, resourceID string) ([]*models.APIResourceScope, error)
	CreateAPIResourceScope(ctx context.Context, resourceID, name, description string) (scopeID string, err error)
	UpdateAPIResourceScope(ctx context.Context, resourceID, scopeID, name, description string) error
	DeleteAPIResourceScope(ctx context.Context, resourceID, scopeID string) error

	// Applications (GET/POST /applications)
	ListApplications(ctx context.Context) ([]*models.Application, error)
	CreateApplication(ctx context.Context, app models.ApplicationCreate) (appID string, err error)

	// Invitations (GET/POST/DELETE /organization-invitations)
	CreateOrganizationInvitation(ctx context.Context, orgID, inviterID, email string, roleIDs []string, expiresAtMs int64) (invitationID string, err error)
	ListOrganizationInvitations(ctx context.Context, orgID string) ([]*models.OrganizationInvitation, error)
	GetOrganizationInvitation(ctx context.Context, invitationID string) (*models.OrganizationInvitation, error)
	DeleteOrganizationInvitation(ctx context.Context, invitationID string) error
	SendInvitationMessage(ctx context.Context, invitationID, magicLink string) error

	// One-Time Tokens (POST /api/one-time-tokens)
	CreateOneTimeToken(ctx context.Context, email string, expiresIn int, jitOrgIDs []string) (*models.OneTimeTokenResult, error)
}

// m2mTokenCache holds cached M2M access tokens (internal use only)
type m2mTokenCache struct {
	accessToken string
	expiresAt   time.Time
}
