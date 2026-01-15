package validator

import "time"

// Token represents a validated JWT access token.
// Implement this interface to create custom token types with typed claims.
//
// Example of creating a custom token type:
//
//	type MyToken struct {
//	    *validator.TokenInfo
//	    TenantID string
//	    Roles    []string
//	}
//
//	func NewMyToken(info *validator.TokenInfo) *MyToken {
//	    return &MyToken{
//	        TokenInfo: info,
//	        TenantID:  info.GetStringClaim("tenant_id"),
//	        Roles:     info.GetStringSliceClaim("roles"),
//	    }
//	}
type Token interface {
	// GetUserID returns the subject (sub) claim - the user identifier
	GetUserID() string

	// GetOrganizationID returns the organization context (if present)
	GetOrganizationID() string

	// GetScopes returns parsed scope permissions
	GetScopes() []string

	// HasScope checks if token has a specific permission
	HasScope(scope string) bool

	// HasAllScopes checks if token has all specified permissions
	HasAllScopes(scopes ...string) bool

	// HasAnyScope checks if token has any of the specified permissions
	HasAnyScope(scopes ...string) bool

	// GetRawClaims returns all JWT claims for custom claim access
	GetRawClaims() map[string]any
}

// TokenInfo represents a validated Logto JWT access token.
// This is NOT a full user - only security context from the token.
// Use Client.GetUser() to get full user profile.
//
// Implements the Token interface.
//
// See: https://docs.logto.io/authorization/validate-access-tokens
type TokenInfo struct {
	// Standard JWT claims (RFC 7519)
	Issuer    string     // iss - token issuer (Logto endpoint)
	Subject   string     // sub - user ID
	Audience  []string   // aud - API resource(s) token was issued for
	ExpiresAt *time.Time // exp - token expiration time
	IssuedAt  *time.Time // iat - when token was issued
	NotBefore *time.Time // nbf - token not valid before (nil if not set)
	JWTID     string     // jti - unique token identifier

	// Logto-specific claims
	ClientID       string   // client_id - application that requested the token
	OrganizationID string   // organization_id - organization context (for org-scoped tokens)
	Scopes         []string // scope - parsed permissions

	// Convenience alias (for backward compatibility)
	UserID string // Alias for Subject (sub claim)

	// RawClaims contains all JWT claims for access to custom claims
	// configured via Logto Custom JWT feature.
	// See: https://docs.logto.io/developers/custom-token-claims
	RawClaims map[string]any
}

// Ensure TokenInfo implements Token interface
var _ Token = (*TokenInfo)(nil)

// GetUserID returns the subject (sub) claim - the user identifier
func (t *TokenInfo) GetUserID() string {
	return t.UserID
}

// GetOrganizationID returns the organization context (if present)
func (t *TokenInfo) GetOrganizationID() string {
	return t.OrganizationID
}

// GetScopes returns parsed scope permissions
func (t *TokenInfo) GetScopes() []string {
	return t.Scopes
}

// GetRawClaims returns all JWT claims for custom claim access
func (t *TokenInfo) GetRawClaims() map[string]any {
	return t.RawClaims
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

// HasAudience checks if token was issued for the specified audience.
func (t *TokenInfo) HasAudience(audience string) bool {
	for _, aud := range t.Audience {
		if aud == audience {
			return true
		}
	}
	return false
}

// IsExpired checks if the token has expired.
func (t *TokenInfo) IsExpired() bool {
	if t.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*t.ExpiresAt)
}

// GetClaim returns a custom claim value by key.
// Returns nil if the claim doesn't exist or RawClaims is nil.
func (t *TokenInfo) GetClaim(key string) any {
	if t.RawClaims == nil {
		return nil
	}
	return t.RawClaims[key]
}

// GetStringClaim returns a custom claim as string.
// Returns empty string if claim doesn't exist or is not a string.
func (t *TokenInfo) GetStringClaim(key string) string {
	v, _ := t.GetClaim(key).(string)
	return v
}

// GetStringSliceClaim returns a custom claim as []string.
// Handles JSON arrays which are decoded as []any.
// Returns nil if claim doesn't exist or cannot be converted.
func (t *TokenInfo) GetStringSliceClaim(key string) []string {
	v, ok := t.GetClaim(key).([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(v))
	for _, item := range v {
		if s, ok := item.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

// GetBoolClaim returns a custom claim as bool.
// Returns false if claim doesn't exist or is not a bool.
func (t *TokenInfo) GetBoolClaim(key string) bool {
	v, _ := t.GetClaim(key).(bool)
	return v
}

// GetFloat64Claim returns a custom claim as float64.
// JSON numbers are decoded as float64.
// Returns 0 if claim doesn't exist or is not a number.
func (t *TokenInfo) GetFloat64Claim(key string) float64 {
	v, _ := t.GetClaim(key).(float64)
	return v
}

// GetIntClaim returns a custom claim as int.
// Converts from float64 since JSON numbers are decoded as float64.
// Returns 0 if claim doesn't exist or is not a number.
func (t *TokenInfo) GetIntClaim(key string) int {
	v, ok := t.GetClaim(key).(float64)
	if !ok {
		return 0
	}
	return int(v)
}

// GetMapClaim returns a custom claim as map[string]any.
// JSON objects are decoded as map[string]any.
// Returns nil if claim doesn't exist or is not a map.
func (t *TokenInfo) GetMapClaim(key string) map[string]any {
	v, ok := t.GetClaim(key).(map[string]any)
	if !ok {
		return nil
	}
	return v
}

// GetArrayMapClaim returns a custom claim as []map[string]any.
// Handles JSON arrays of objects which are decoded as []any containing map[string]any items.
// Returns nil if claim doesn't exist or cannot be converted.
func (t *TokenInfo) GetArrayMapClaim(key string) []map[string]any {
	v, ok := t.GetClaim(key).([]any)
	if !ok {
		return nil
	}
	result := make([]map[string]any, 0, len(v))
	for _, item := range v {
		if m, ok := item.(map[string]any); ok {
			result = append(result, m)
		}
	}
	return result
}
