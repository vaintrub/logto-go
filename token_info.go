package logto

// TokenInfo represents parsed JWT access token information.
// This is NOT a full user - only security context from the token.
// Use Client.GetUser() to get full user profile.
type TokenInfo struct {
	UserID         string   // JWT "sub" claim
	OrganizationID string   // Current organization context
	Scopes         []string // Permissions in this organization
}

// HasScope checks if token has a specific permission
func (t *TokenInfo) HasScope(scope string) bool {
	for _, s := range t.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// HasAnyScope checks if token has any of the specified permissions
func (t *TokenInfo) HasAnyScope(scopes ...string) bool {
	for _, required := range scopes {
		if t.HasScope(required) {
			return true
		}
	}
	return false
}

// HasAllScopes checks if token has all of the specified permissions
func (t *TokenInfo) HasAllScopes(scopes ...string) bool {
	for _, required := range scopes {
		if !t.HasScope(required) {
			return false
		}
	}
	return true
}
