package validator

import (
	"encoding/json"
	"strings"
	"time"
)

// Claims represents JWT token claims from Logto Identity Provider.
// This is used internally for parsing JWT tokens.
// See: https://docs.logto.io/authorization/validate-access-tokens
type Claims struct {
	// Standard JWT claims (RFC 7519)
	Issuer    string     `json:"iss,omitempty"` // Token issuer (Logto endpoint)
	Subject   string     `json:"sub,omitempty"` // Subject - user ID
	Audience  []string   `json:"aud,omitempty"` // Intended audience (API resource indicator)
	ExpiresAt *time.Time `json:"exp,omitempty"` // Expiration time
	NotBefore *time.Time `json:"nbf,omitempty"` // Not valid before
	IssuedAt  *time.Time `json:"iat,omitempty"` // Issued at time
	ID        string     `json:"jti,omitempty"` // Unique token identifier

	// Logto-specific claims
	ClientID       string `json:"client_id,omitempty"`       // Application that requested the token
	OrganizationID string `json:"organization_id,omitempty"` // Organization context (for org-scoped tokens)

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

// HasAudience checks if the token was issued for the specified audience.
// The audience claim (aud) can be a single string or an array of strings.
// This is critical for security - tokens should only be accepted if issued
// for the specific API resource (audience) that is validating them.
func (c *Claims) HasAudience(audience string) bool {
	for _, aud := range c.Audience {
		if aud == audience {
			return true
		}
	}
	return false
}

// UnmarshalJSON implements custom JSON unmarshaling to handle:
// - Unix timestamps for time fields (exp, nbf, iat)
// - Audience as either string or array of strings
func (c *Claims) UnmarshalJSON(data []byte) error {
	// Alias to avoid infinite recursion
	type ClaimsAlias Claims
	type ClaimsRaw struct {
		ClaimsAlias
		ExpiresAt *int64          `json:"exp,omitempty"`
		NotBefore *int64          `json:"nbf,omitempty"`
		IssuedAt  *int64          `json:"iat,omitempty"`
		Audience  json.RawMessage `json:"aud,omitempty"` // Can be string or []string
	}

	var raw ClaimsRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	*c = Claims(raw.ClaimsAlias)

	// Convert Unix timestamps to time.Time
	if raw.ExpiresAt != nil {
		t := time.Unix(*raw.ExpiresAt, 0)
		c.ExpiresAt = &t
	}
	if raw.NotBefore != nil {
		t := time.Unix(*raw.NotBefore, 0)
		c.NotBefore = &t
	}
	if raw.IssuedAt != nil {
		t := time.Unix(*raw.IssuedAt, 0)
		c.IssuedAt = &t
	}

	// Parse audience - can be string or array of strings per JWT spec
	if len(raw.Audience) > 0 {
		// Try array first
		var audArray []string
		if err := json.Unmarshal(raw.Audience, &audArray); err == nil {
			c.Audience = audArray
		} else {
			// Try single string
			var audString string
			if err := json.Unmarshal(raw.Audience, &audString); err == nil {
				c.Audience = []string{audString}
			}
		}
	}

	return nil
}
