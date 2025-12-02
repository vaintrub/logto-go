package models

import "time"

// ApplicationType represents the type of Logto application.
type ApplicationType string

const (
	ApplicationTypeNative           ApplicationType = "Native"
	ApplicationTypeSPA              ApplicationType = "SPA"
	ApplicationTypeTraditional      ApplicationType = "Traditional"
	ApplicationTypeMachineToMachine ApplicationType = "MachineToMachine"
)

// Application represents a Logto application.
type Application struct {
	ID                     string
	Name                   string
	Description            string
	Type                   ApplicationType
	Secret                 string
	IsThirdParty           bool
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	CustomData             map[string]interface{}
	CreatedAt              time.Time
}

// ApplicationCreate represents fields for creating an application.
type ApplicationCreate struct {
	Name         string
	Type         ApplicationType
	Description  string
	RedirectURIs []string
}
