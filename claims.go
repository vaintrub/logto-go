package logto

import (
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// Claims represents JWT token claims from Logto Identity Provider.
// This is used internally for parsing JWT tokens.
type Claims struct {
	jwt.RegisteredClaims
	// Organization context
	OrganizationID string `json:"organization_id,omitempty"` // Current org context
	// Permissions (space-separated string from OIDC provider)
	Scope string `json:"scope,omitempty"` // Space-separated permissions
}

// GetScopes parses the space-separated scope string into a slice
func (c *Claims) GetScopes() []string {
	if c.Scope == "" {
		return []string{}
	}
	// strings.Fields splits on whitespace and removes empty strings
	return strings.Fields(c.Scope)
}
