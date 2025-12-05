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
	CreateUser(ctx context.Context, username, password, name, primaryEmail string) (*models.User, error)
	UpdateUser(ctx context.Context, userID string, update models.UserUpdate) (*models.User, error)
	UpdateUserCustomData(ctx context.Context, userID string, customData map[string]interface{}) (*models.User, error)

	// Organizations (GET /organizations, GET /organizations/{id}, POST/PATCH/DELETE)
	GetOrganization(ctx context.Context, orgID string) (*models.Organization, error)
	ListOrganizations(ctx context.Context) ([]*models.Organization, error)
	ListUserOrganizations(ctx context.Context, userID string) ([]*models.Organization, error)
	CreateOrganization(ctx context.Context, name, description string) (*models.Organization, error)
	UpdateOrganization(ctx context.Context, orgID string, name, description string, customData map[string]interface{}) (*models.Organization, error)
	DeleteOrganization(ctx context.Context, orgID string) error

	// Organization Members (GET/POST/DELETE /organizations/{id}/users/*)
	ListOrganizationMembers(ctx context.Context, orgID string) ([]*models.OrganizationMember, error)
	AddUserToOrganization(ctx context.Context, orgID, userID string, roleIDs []string) error
	AddUsersToOrganization(ctx context.Context, orgID string, userIDs []string) error // Batch add
	RemoveUserFromOrganization(ctx context.Context, orgID, userID string) error
	UpdateUserRoles(ctx context.Context, orgID, userID string, roleIDs []string) error
	AssignRolesToOrganizationUsers(ctx context.Context, orgID string, userIDs, roleIDs []string) error // Batch assign roles
	GetUserRolesInOrganization(ctx context.Context, orgID, userID string) ([]models.OrganizationRole, error)

	// Organization Applications (GET/POST/DELETE /organizations/{id}/applications/*)
	ListOrganizationApplications(ctx context.Context, orgID string) ([]*models.Application, error)
	AddOrganizationApplications(ctx context.Context, orgID string, applicationIDs []string) error
	RemoveOrganizationApplication(ctx context.Context, orgID, applicationID string) error
	GetOrganizationApplicationRoles(ctx context.Context, orgID, applicationID string) ([]models.OrganizationRole, error)
	AssignOrganizationApplicationRoles(ctx context.Context, orgID, applicationID string, roleIDs []string) error
	RemoveOrganizationApplicationRoles(ctx context.Context, orgID, applicationID string, roleIDs []string) error

	// Organization Roles (GET/POST/PATCH/DELETE /organization-roles)
	GetOrganizationRole(ctx context.Context, roleID string) (*models.OrganizationRole, error)
	ListOrganizationRoles(ctx context.Context) ([]models.OrganizationRole, error)
	CreateOrganizationRole(ctx context.Context, name, description string, roleType models.OrganizationRoleType, scopeIDs []string) (*models.OrganizationRole, error)
	UpdateOrganizationRole(ctx context.Context, roleID, name, description string) (*models.OrganizationRole, error)
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
	CreateOrganizationScope(ctx context.Context, name, description string) (*models.OrganizationScope, error)
	UpdateOrganizationScope(ctx context.Context, scopeID, name, description string) (*models.OrganizationScope, error)
	DeleteOrganizationScope(ctx context.Context, scopeID string) error

	// API Resources (GET/POST/PATCH/DELETE /resources)
	GetAPIResource(ctx context.Context, resourceID string) (*models.APIResource, error)
	ListAPIResources(ctx context.Context) ([]*models.APIResource, error)
	CreateAPIResource(ctx context.Context, name, indicator string) (*models.APIResource, error)
	UpdateAPIResource(ctx context.Context, resourceID, name string, accessTokenTTL *int) (*models.APIResource, error)
	DeleteAPIResource(ctx context.Context, resourceID string) error

	// API Resource Scopes (GET/POST/PATCH/DELETE /resources/{id}/scopes)
	GetAPIResourceScope(ctx context.Context, resourceID, scopeID string) (*models.APIResourceScope, error)
	ListAPIResourceScopes(ctx context.Context, resourceID string) ([]*models.APIResourceScope, error)
	CreateAPIResourceScope(ctx context.Context, resourceID, name, description string) (*models.APIResourceScope, error)
	UpdateAPIResourceScope(ctx context.Context, resourceID, scopeID, name, description string) (*models.APIResourceScope, error)
	DeleteAPIResourceScope(ctx context.Context, resourceID, scopeID string) error

	// Applications (GET/POST /applications)
	ListApplications(ctx context.Context) ([]*models.Application, error)
	CreateApplication(ctx context.Context, app models.ApplicationCreate) (*models.Application, error)

	// Roles - Global/Tenant-level roles (GET/POST/PATCH/DELETE /roles)
	GetRole(ctx context.Context, roleID string) (*models.Role, error)
	ListRoles(ctx context.Context) ([]*models.Role, error)
	CreateRole(ctx context.Context, name, description string, roleType models.RoleType, scopeIDs []string) (*models.Role, error)
	UpdateRole(ctx context.Context, roleID, name, description string, isDefault *bool) (*models.Role, error)
	DeleteRole(ctx context.Context, roleID string) error

	// Role Scopes - API resource scopes assigned to roles (GET/POST/DELETE /roles/{id}/scopes)
	ListRoleScopes(ctx context.Context, roleID string) ([]*models.APIResourceScope, error)
	AssignRoleScopes(ctx context.Context, roleID string, scopeIDs []string) error
	RemoveRoleScope(ctx context.Context, roleID, scopeID string) error

	// Role Users - Users assigned to roles (GET/POST/DELETE /roles/{id}/users)
	ListRoleUsers(ctx context.Context, roleID string) ([]*models.User, error)
	AssignRoleToUsers(ctx context.Context, roleID string, userIDs []string) error
	RemoveRoleFromUser(ctx context.Context, roleID, userID string) error

	// Role Applications - M2M applications assigned to roles (GET/POST/DELETE /roles/{id}/applications)
	ListRoleApplications(ctx context.Context, roleID string) ([]*models.Application, error)
	AssignRoleToApplications(ctx context.Context, roleID string, applicationIDs []string) error
	RemoveRoleFromApplication(ctx context.Context, roleID, applicationID string) error

	// Invitations (GET/POST/DELETE /organization-invitations)
	CreateOrganizationInvitation(ctx context.Context, orgID, inviterID, email string, roleIDs []string, expiresAtMs int64) (*models.OrganizationInvitation, error)
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
