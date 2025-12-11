package models

import "time"

// APIResource represents an API resource in Logto.
type APIResource struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenantId"`
	Name           string    `json:"name"`
	Indicator      string    `json:"indicator"`      // The unique resource identifier (URL)
	AccessTokenTTL int       `json:"accessTokenTtl"` // Token TTL in seconds
	IsDefault      bool      `json:"isDefault"`
	CreatedAt      time.Time `json:"createdAt"`
}

// APIResourceScope represents a permission scope for an API resource.
type APIResourceScope struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenantId"`
	ResourceID  string    `json:"resourceId"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"createdAt"`
}

// APIResourceCreate represents fields for creating a new API resource.
type APIResourceCreate struct {
	Name           string `json:"name"`
	Indicator      string `json:"indicator"`
	AccessTokenTTL *int   `json:"accessTokenTtl,omitempty"`
}

// APIResourceUpdate represents fields for updating an API resource.
// Use pointers to distinguish between "not set" and "set to empty".
type APIResourceUpdate struct {
	Name           *string `json:"name,omitempty"`
	AccessTokenTTL *int    `json:"accessTokenTtl,omitempty"`
}

// APIResourceScopeCreate represents fields for creating a new API resource scope.
type APIResourceScopeCreate struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// APIResourceScopeUpdate represents fields for updating an API resource scope.
// Use pointers to distinguish between "not set" and "set to empty".
type APIResourceScopeUpdate struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
}
