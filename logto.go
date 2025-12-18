// Package logto provides a Go SDK for Logto Identity Provider Management API.
//
// Basic usage:
//
//	import logto "github.com/vaintrub/logto-go"
//
//	client, err := logto.NewClient(endpoint, m2mAppID, m2mAppSecret)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	user, err := client.GetUser(ctx, userID)
package logto

import (
	"net/http"
	"time"

	"github.com/vaintrub/logto-go/client"
	"github.com/vaintrub/logto-go/models"
)

// Re-export client types for convenient access
type (
	// Client defines the interface for interacting with Logto Identity Provider.
	Client = client.Client

	// TokenResult represents an OAuth 2.0 token response.
	TokenResult = client.TokenResult

	// UserIterator provides pagination for listing users.
	UserIterator = client.UserIterator

	// OrganizationIterator provides pagination for listing organizations.
	OrganizationIterator = client.OrganizationIterator

	// APIError represents an error from the Logto API.
	APIError = client.APIError

	// ValidationError represents a client-side validation error.
	ValidationError = client.ValidationError

	// VerificationCodeRequest represents a request to send a verification code.
	VerificationCodeRequest = client.VerificationCodeRequest

	// VerifyCodeRequest represents a request to verify a code.
	VerifyCodeRequest = client.VerifyCodeRequest

	// Option configures the client.
	Option = client.Option
)

// Re-export model types for convenient access
type (
	// User represents a Logto user.
	User = models.User
	// UserCreate represents the data needed to create a user.
	UserCreate = models.UserCreate
	// UserUpdate represents the data needed to update a user.
	UserUpdate = models.UserUpdate
	// UserPasswordUpdate represents the data needed to update a user's password.
	UserPasswordUpdate = models.UserPasswordUpdate

	// Organization represents a Logto organization.
	Organization = models.Organization
	// OrganizationCreate represents the data needed to create an organization.
	OrganizationCreate = models.OrganizationCreate
	// OrganizationUpdate represents the data needed to update an organization.
	OrganizationUpdate = models.OrganizationUpdate
	// OrganizationMember represents a member of an organization.
	OrganizationMember = models.OrganizationMember

	// OrganizationRole represents a role within an organization.
	OrganizationRole = models.OrganizationRole
	// OrganizationRoleCreate represents the data needed to create an organization role.
	OrganizationRoleCreate = models.OrganizationRoleCreate
	// OrganizationRoleUpdate represents the data needed to update an organization role.
	OrganizationRoleUpdate = models.OrganizationRoleUpdate

	// OrganizationScope represents a permission scope within an organization.
	OrganizationScope = models.OrganizationScope
	// OrganizationScopeCreate represents the data needed to create an organization scope.
	OrganizationScopeCreate = models.OrganizationScopeCreate
	// OrganizationScopeUpdate represents the data needed to update an organization scope.
	OrganizationScopeUpdate = models.OrganizationScopeUpdate

	// OrganizationInvitation represents an invitation to join an organization.
	OrganizationInvitation = models.OrganizationInvitation
	// OrganizationInvitationCreate represents the data needed to create an invitation.
	OrganizationInvitationCreate = models.OrganizationInvitationCreate

	// APIResource represents an API resource in Logto.
	APIResource = models.APIResource
	// APIResourceCreate represents the data needed to create an API resource.
	APIResourceCreate = models.APIResourceCreate
	// APIResourceUpdate represents the data needed to update an API resource.
	APIResourceUpdate = models.APIResourceUpdate
	// APIResourceScope represents a scope within an API resource.
	APIResourceScope = models.APIResourceScope
	// APIResourceScopeCreate represents the data needed to create a resource scope.
	APIResourceScopeCreate = models.APIResourceScopeCreate
	// APIResourceScopeUpdate represents the data needed to update a resource scope.
	APIResourceScopeUpdate = models.APIResourceScopeUpdate

	// Application represents a Logto application.
	Application = models.Application
	// ApplicationCreate represents the data needed to create an application.
	ApplicationCreate = models.ApplicationCreate

	// Role represents a global/tenant-level role.
	Role = models.Role
	// RoleCreate represents the data needed to create a role.
	RoleCreate = models.RoleCreate
	// RoleUpdate represents the data needed to update a role.
	RoleUpdate = models.RoleUpdate

	// OneTimeTokenCreate represents the data needed to create a one-time token.
	OneTimeTokenCreate = models.OneTimeTokenCreate
	// OneTimeTokenResult represents the result of creating a one-time token.
	OneTimeTokenResult = models.OneTimeTokenResult

	// UnixMilliTime represents a Unix timestamp in milliseconds.
	UnixMilliTime = models.UnixMilliTime
)

// Re-export sentinel errors
var (
	// ErrBadRequest indicates a 400 Bad Request response.
	ErrBadRequest = client.ErrBadRequest
	// ErrUnauthorized indicates a 401 Unauthorized response.
	ErrUnauthorized = client.ErrUnauthorized
	// ErrForbidden indicates a 403 Forbidden response.
	ErrForbidden = client.ErrForbidden
	// ErrNotFound indicates a 404 Not Found response.
	ErrNotFound = client.ErrNotFound
	// ErrConflict indicates a 409 Conflict response.
	ErrConflict = client.ErrConflict
	// ErrUnprocessableEntity indicates a 422 Unprocessable Entity response.
	ErrUnprocessableEntity = client.ErrUnprocessableEntity
	// ErrRateLimited indicates a 429 Too Many Requests response.
	ErrRateLimited = client.ErrRateLimited
	// ErrServerError indicates a 5xx server error response.
	ErrServerError = client.ErrServerError
	// ErrMembershipRequired indicates the user needs organization membership.
	ErrMembershipRequired = client.ErrMembershipRequired
	// ErrUserNotFound indicates no user was found matching the search criteria.
	ErrUserNotFound = client.ErrUserNotFound
	// ErrInvalidInput indicates invalid input parameters.
	ErrInvalidInput = client.ErrInvalidInput
)

// NewClient creates a new Logto client with the provided options.
//
// Parameters:
//   - endpoint: The Logto API endpoint (e.g., "https://your-tenant.logto.app")
//   - m2mAppID: The M2M application ID
//   - m2mAppSecret: The M2M application secret
//   - opts: Optional configuration options
//
// Returns an error if required parameters are missing.
func NewClient(endpoint, m2mAppID, m2mAppSecret string, opts ...Option) (Client, error) {
	return client.New(endpoint, m2mAppID, m2mAppSecret, opts...)
}

// WithTimeout sets the HTTP client timeout.
// Default: 5s
func WithTimeout(d time.Duration) Option {
	return client.WithTimeout(d)
}

// WithHTTPClient sets a custom HTTP client.
// When set, this overrides the timeout option.
func WithHTTPClient(c *http.Client) Option {
	return client.WithHTTPClient(c)
}

// WithResource sets the M2M resource URL for token requests.
// Default: https://default.logto.app/api
func WithResource(resource string) Option {
	return client.WithResource(resource)
}

// WithScope sets the M2M scope for token requests.
// Default: all
func WithScope(scope string) Option {
	return client.WithScope(scope)
}
