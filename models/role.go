package models

// OrganizationRole represents a role definition in Logto.
type OrganizationRole struct {
	ID          string
	Name        string
	Description string
	Scopes      []OrganizationScope
}

// OrganizationScope represents a permission scope in Logto's organization template.
type OrganizationScope struct {
	ID          string
	Name        string
	Description string
}
