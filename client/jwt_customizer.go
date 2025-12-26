package client

import (
	"context"
	"net/http"
)

// JWT token types for customizer.
const (
	TokenTypeAccessToken       = "access-token"
	TokenTypeClientCredentials = "client-credentials"
)

// JWTCustomizerConfig represents the JWT customizer configuration.
// See: https://openapi.logto.io/operation/operation-upsertjwtcustomizer
type JWTCustomizerConfig struct {
	// Script is the JavaScript function that returns custom claims.
	// Format: const getCustomJwtClaims = async ({ token, context, environmentVariables }) => { return {}; };
	Script string `json:"script"`

	// EnvironmentVariables are key-value pairs accessible in the script.
	EnvironmentVariables map[string]string `json:"environmentVariables,omitempty"`

	// ContextSample is sample context for testing the script (optional).
	ContextSample map[string]interface{} `json:"contextSample,omitempty"`

	// TokenSample is sample token payload for testing (optional).
	TokenSample map[string]interface{} `json:"tokenSample,omitempty"`
}

// UpsertJWTCustomizer creates or updates a JWT customizer for the given token type.
// tokenType must be either "access-token" or "client-credentials".
//
// Example script to add organization_roles claim:
//
//	const getCustomJwtClaims = async ({ token, context }) => {
//	    const { user } = context;
//	    if (!user || !user.organizationRoles) return {};
//	    const organization_roles = user.organizationRoles.map(r =>
//	        r.organizationId + ':' + r.roleId
//	    );
//	    return { organization_roles };
//	};
func (a *Adapter) UpsertJWTCustomizer(ctx context.Context, tokenType string, config JWTCustomizerConfig) error {
	if tokenType != TokenTypeAccessToken && tokenType != TokenTypeClientCredentials {
		return &ValidationError{Field: "tokenType", Message: "must be 'access-token' or 'client-credentials'"}
	}
	return a.doNoContent(ctx, requestConfig{
		method:      http.MethodPut,
		path:        "/api/configs/jwt-customizer/%s",
		pathParams:  []string{tokenType},
		body:        config,
		expectCodes: []int{http.StatusOK, http.StatusCreated},
	})
}

// GetJWTCustomizer retrieves the JWT customizer configuration for the given token type.
// Returns nil if no customizer is configured.
func (a *Adapter) GetJWTCustomizer(ctx context.Context, tokenType string) (*JWTCustomizerConfig, error) {
	if tokenType != TokenTypeAccessToken && tokenType != TokenTypeClientCredentials {
		return nil, &ValidationError{Field: "tokenType", Message: "must be 'access-token' or 'client-credentials'"}
	}
	var config JWTCustomizerConfig
	err := a.doJSON(ctx, requestConfig{
		method:      http.MethodGet,
		path:        "/api/configs/jwt-customizer/%s",
		pathParams:  []string{tokenType},
		expectCodes: []int{http.StatusOK},
	}, &config)
	if err != nil {
		// Check if it's a 404 (no customizer configured)
		if apiErr, ok := err.(*APIError); ok && apiErr.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &config, nil
}

// DeleteJWTCustomizer removes the JWT customizer for the given token type.
func (a *Adapter) DeleteJWTCustomizer(ctx context.Context, tokenType string) error {
	if tokenType != TokenTypeAccessToken && tokenType != TokenTypeClientCredentials {
		return &ValidationError{Field: "tokenType", Message: "must be 'access-token' or 'client-credentials'"}
	}
	return a.doNoContent(ctx, requestConfig{
		method:      http.MethodDelete,
		path:        "/api/configs/jwt-customizer/%s",
		pathParams:  []string{tokenType},
		expectCodes: []int{http.StatusNoContent, http.StatusOK},
	})
}
