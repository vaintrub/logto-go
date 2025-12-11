package models

import "time"

// ApplicationType represents the type of Logto application.
type ApplicationType string

const (
	ApplicationTypeNative           ApplicationType = "Native"
	ApplicationTypeSPA              ApplicationType = "SPA"
	ApplicationTypeTraditional      ApplicationType = "Traditional"
	ApplicationTypeMachineToMachine ApplicationType = "MachineToMachine"
	ApplicationTypeProtected        ApplicationType = "Protected"
	ApplicationTypeSAML             ApplicationType = "SAML"
)

// OIDCClientMetadata represents OIDC client metadata for an application.
type OIDCClientMetadata struct {
	RedirectURIs                   []string `json:"redirectUris"`
	PostLogoutRedirectURIs         []string `json:"postLogoutRedirectUris"`
	BackchannelLogoutURI           string   `json:"backchannelLogoutUri"`
	BackchannelLogoutSessionRequired bool   `json:"backchannelLogoutSessionRequired"`
	LogoURI                        string   `json:"logoUri"`
}

// CustomClientMetadata represents custom client metadata for an application.
type CustomClientMetadata struct {
	CORSAllowedOrigins     []string `json:"corsAllowedOrigins"`
	IDTokenTTL             int      `json:"idTokenTtl"`
	RefreshTokenTTL        int      `json:"refreshTokenTtl"`
	RefreshTokenTTLInDays  int      `json:"refreshTokenTtlInDays"`
	TenantID               string   `json:"tenantId"`
	AlwaysIssueRefreshToken bool    `json:"alwaysIssueRefreshToken"`
	RotateRefreshToken     bool     `json:"rotateRefreshToken"`
}

// ProtectedAppMetadata represents protected app metadata.
type ProtectedAppMetadata struct {
	Host            string                 `json:"host"`
	Origin          string                 `json:"origin"`
	SessionDuration int                    `json:"sessionDuration"`
	PageRules       []map[string]interface{} `json:"pageRules"`
	CustomDomains   []map[string]interface{} `json:"customDomains"`
}

// Application represents a Logto application.
type Application struct {
	ID                   string                 `json:"id"`
	TenantID             string                 `json:"tenantId"`
	Name                 string                 `json:"name"`
	Description          string                 `json:"description"`
	Type                 ApplicationType        `json:"type"`
	Secret               string                 `json:"secret"`
	OIDCClientMetadata   *OIDCClientMetadata    `json:"oidcClientMetadata"`
	CustomClientMetadata *CustomClientMetadata  `json:"customClientMetadata"`
	ProtectedAppMetadata *ProtectedAppMetadata  `json:"protectedAppMetadata"`
	CustomData           map[string]interface{} `json:"customData"`
	IsThirdParty         bool                   `json:"isThirdParty"`
	IsAdmin              bool                   `json:"isAdmin"`
	CreatedAt            time.Time              `json:"createdAt"`
}

// ApplicationCreate represents fields for creating an application.
type ApplicationCreate struct {
	Name         string          `json:"name"`
	Type         ApplicationType `json:"type"`
	Description  string          `json:"description,omitempty"`
	RedirectURIs []string        `json:"redirectUris,omitempty"`
}
