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
