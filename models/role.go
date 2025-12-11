package models

import "time"

// RoleType represents the type of role (used for both regular and organization roles).
type RoleType string

const (
	// RoleTypeUser is for user-based roles
	RoleTypeUser RoleType = "User"
	// RoleTypeMachineToMachine is for M2M application roles
	RoleTypeMachineToMachine RoleType = "MachineToMachine"
)

// OrganizationRoleType is an alias for RoleType for backwards compatibility.
type OrganizationRoleType = RoleType

const (
	// OrganizationRoleTypeUser is for user-based roles (alias for RoleTypeUser)
	OrganizationRoleTypeUser = RoleTypeUser
	// OrganizationRoleTypeMachineToMachine is for M2M application roles (alias for RoleTypeMachineToMachine)
	OrganizationRoleTypeMachineToMachine = RoleTypeMachineToMachine
)

// Role represents a global (tenant-level) role in Logto.
type Role struct {
	ID          string   `json:"id"`
	TenantID    string   `json:"tenantId"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Type        RoleType `json:"type"`
	IsDefault   bool     `json:"isDefault"`
}

// OrganizationRole represents a role definition in Logto's organization template.
type OrganizationRole struct {
	ID             string              `json:"id"`
	TenantID       string              `json:"tenantId"`
	Name           string              `json:"name"`
	Description    string              `json:"description"`
	Type           string              `json:"type"`
	Scopes         []OrganizationScope `json:"scopes"`
	ResourceScopes []APIResourceScope  `json:"resourceScopes"`
	CreatedAt      time.Time           `json:"createdAt"`
}

// OrganizationScope represents a permission scope in Logto's organization template.
type OrganizationScope struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenantId"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"createdAt"`
}
