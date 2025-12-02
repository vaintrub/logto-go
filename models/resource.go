package models

// APIResource represents an API resource in Logto.
type APIResource struct {
	ID             string
	Name           string
	Indicator      string // The unique resource identifier (URL)
	AccessTokenTTL int    // Token TTL in seconds
	IsDefault      bool
}

// APIResourceScope represents a permission scope for an API resource.
type APIResourceScope struct {
	ID          string
	ResourceID  string
	Name        string
	Description string
}
