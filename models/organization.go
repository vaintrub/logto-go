package models

import "time"

// Organization represents organization details from Logto.
type Organization struct {
	ID          string
	Name        string
	Description string
	CustomData  map[string]interface{}
	CreatedAt   time.Time
}

// OrganizationMember represents a member in an organization with their roles.
type OrganizationMember struct {
	User  *User
	Roles []OrganizationRole
}
