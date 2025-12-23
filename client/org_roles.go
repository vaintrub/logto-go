package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/vaintrub/logto-go/models"
)

// ListOrganizationRoles lists all organization roles with their scopes
func (a *Adapter) ListOrganizationRoles(ctx context.Context) ([]models.OrganizationRole, error) {
	body, _, err := a.doRequest(ctx, requestConfig{
		method: http.MethodGet,
		path:   "/api/organization-roles",
	})
	if err != nil {
		return nil, err
	}

	var roles []models.OrganizationRole
	if err := json.Unmarshal(body, &roles); err != nil {
		return nil, fmt.Errorf("unmarshal organization roles: %w", err)
	}

	return roles, nil
}

// GetOrganizationRole retrieves a single organization role by ID with its scopes
func (a *Adapter) GetOrganizationRole(ctx context.Context, roleID string) (*models.OrganizationRole, error) {
	if roleID == "" {
		return nil, &ValidationError{Field: "roleID", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodGet,
		path:       "/api/organization-roles/%s",
		pathParams: []string{roleID},
	})
	if err != nil {
		return nil, err
	}

	var role models.OrganizationRole
	if err := json.Unmarshal(body, &role); err != nil {
		return nil, fmt.Errorf("unmarshal organization role: %w", err)
	}

	// Get role scopes (separate endpoint in Logto API)
	scopes, err := a.GetOrganizationRoleScopes(ctx, roleID)
	if err != nil {
		return nil, err
	}
	role.Scopes = scopes

	return &role, nil
}

// GetOrganizationRoleScopes retrieves scopes assigned to an organization role
func (a *Adapter) GetOrganizationRoleScopes(ctx context.Context, roleID string) ([]models.OrganizationScope, error) {
	if roleID == "" {
		return nil, &ValidationError{Field: "roleID", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodGet,
		path:       "/api/organization-roles/%s/scopes",
		pathParams: []string{roleID},
	})
	if err != nil {
		return nil, err
	}

	var scopes []models.OrganizationScope
	if err := json.Unmarshal(body, &scopes); err != nil {
		return nil, fmt.Errorf("unmarshal organization role scopes: %w", err)
	}

	return scopes, nil
}

// CreateOrganizationRole creates a new organization role
func (a *Adapter) CreateOrganizationRole(ctx context.Context, role models.OrganizationRoleCreate) (*models.OrganizationRole, error) {
	if role.Name == "" {
		return nil, &ValidationError{Field: "name", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:      http.MethodPost,
		path:        "/api/organization-roles",
		body:        role,
		expectCodes: []int{http.StatusOK, http.StatusCreated},
	})
	if err != nil {
		return nil, err
	}

	return parseOrganizationRoleResponse(body)
}

// UpdateOrganizationRole updates an organization role
func (a *Adapter) UpdateOrganizationRole(ctx context.Context, roleID string, update models.OrganizationRoleUpdate) (*models.OrganizationRole, error) {
	if roleID == "" {
		return nil, &ValidationError{Field: "roleID", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:      http.MethodPatch,
		path:        "/api/organization-roles/%s",
		pathParams:  []string{roleID},
		body:        update,
		expectCodes: []int{http.StatusOK},
	})
	if err != nil {
		return nil, err
	}

	return parseOrganizationRoleResponse(body)
}

// DeleteOrganizationRole deletes an organization role
func (a *Adapter) DeleteOrganizationRole(ctx context.Context, roleID string) error {
	if roleID == "" {
		return &ValidationError{Field: "roleID", Message: "cannot be empty"}
	}

	return a.doNoContent(ctx, requestConfig{
		method:      http.MethodDelete,
		path:        "/api/organization-roles/%s",
		pathParams:  []string{roleID},
		expectCodes: []int{http.StatusOK, http.StatusNoContent},
	})
}

// SetOrganizationRoleScopes replaces all scopes for an organization role
func (a *Adapter) SetOrganizationRoleScopes(ctx context.Context, roleID string, scopeIDs []string) error {
	if roleID == "" {
		return &ValidationError{Field: "roleID", Message: "cannot be empty"}
	}

	return a.doNoContent(ctx, requestConfig{
		method:      http.MethodPut,
		path:        "/api/organization-roles/%s/scopes",
		pathParams:  []string{roleID},
		body:        map[string][]string{"organizationScopeIds": scopeIDs},
		expectCodes: []int{http.StatusOK, http.StatusNoContent},
	})
}

// AddOrganizationRoleScopes adds scopes to an organization role
func (a *Adapter) AddOrganizationRoleScopes(ctx context.Context, roleID string, scopeIDs []string) error {
	if roleID == "" {
		return &ValidationError{Field: "roleID", Message: "cannot be empty"}
	}
	if len(scopeIDs) == 0 {
		return &ValidationError{Field: "scopeIDs", Message: "cannot be empty"}
	}

	return a.doNoContent(ctx, requestConfig{
		method:      http.MethodPost,
		path:        "/api/organization-roles/%s/scopes",
		pathParams:  []string{roleID},
		body:        map[string][]string{"organizationScopeIds": scopeIDs},
		expectCodes: []int{http.StatusOK, http.StatusCreated, http.StatusNoContent},
	})
}

// RemoveScopeFromOrganizationRole removes a scope from an organization role
func (a *Adapter) RemoveScopeFromOrganizationRole(ctx context.Context, roleID, scopeID string) error {
	if roleID == "" {
		return &ValidationError{Field: "roleID", Message: "cannot be empty"}
	}
	if scopeID == "" {
		return &ValidationError{Field: "scopeID", Message: "cannot be empty"}
	}

	return a.doNoContent(ctx, requestConfig{
		method:      http.MethodDelete,
		path:        "/api/organization-roles/%s/scopes/%s",
		pathParams:  []string{roleID, scopeID},
		expectCodes: []int{http.StatusOK, http.StatusNoContent},
	})
}

// GetOrganizationRoleResourceScopes retrieves API resource scopes assigned to an organization role.
func (a *Adapter) GetOrganizationRoleResourceScopes(ctx context.Context, roleID string) ([]models.APIResourceScope, error) {
	if roleID == "" {
		return nil, &ValidationError{Field: "roleID", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodGet,
		path:       "/api/organization-roles/%s/resource-scopes",
		pathParams: []string{roleID},
	})
	if err != nil {
		return nil, err
	}

	var scopes []models.APIResourceScope
	if err := json.Unmarshal(body, &scopes); err != nil {
		return nil, fmt.Errorf("unmarshal organization role resource scopes: %w", err)
	}

	return scopes, nil
}

// AssignResourceScopesToOrganizationRole assigns API resource scopes to an organization role
func (a *Adapter) AssignResourceScopesToOrganizationRole(ctx context.Context, roleID string, scopeIDs []string) error {
	if roleID == "" {
		return &ValidationError{Field: "roleID", Message: "cannot be empty"}
	}
	if len(scopeIDs) == 0 {
		return &ValidationError{Field: "scopeIDs", Message: "cannot be empty"}
	}

	return a.doNoContent(ctx, requestConfig{
		method:      http.MethodPost,
		path:        "/api/organization-roles/%s/resource-scopes",
		pathParams:  []string{roleID},
		body:        map[string][]string{"scopeIds": scopeIDs},
		expectCodes: []int{http.StatusOK, http.StatusCreated, http.StatusNoContent},
	})
}

// GetOrganizationScope retrieves a single organization scope by ID
func (a *Adapter) GetOrganizationScope(ctx context.Context, scopeID string) (*models.OrganizationScope, error) {
	if scopeID == "" {
		return nil, &ValidationError{Field: "scopeID", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodGet,
		path:       "/api/organization-scopes/%s",
		pathParams: []string{scopeID},
	})
	if err != nil {
		return nil, err
	}

	return parseOrganizationScopeResponse(body)
}

// ListOrganizationScopes lists all organization scopes
func (a *Adapter) ListOrganizationScopes(ctx context.Context) ([]models.OrganizationScope, error) {
	body, _, err := a.doRequest(ctx, requestConfig{
		method: http.MethodGet,
		path:   "/api/organization-scopes",
	})
	if err != nil {
		return nil, err
	}

	var scopes []models.OrganizationScope
	if err := json.Unmarshal(body, &scopes); err != nil {
		return nil, fmt.Errorf("unmarshal organization scopes: %w", err)
	}

	return scopes, nil
}

// CreateOrganizationScope creates a new organization scope
func (a *Adapter) CreateOrganizationScope(ctx context.Context, scope models.OrganizationScopeCreate) (*models.OrganizationScope, error) {
	if scope.Name == "" {
		return nil, &ValidationError{Field: "name", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:      http.MethodPost,
		path:        "/api/organization-scopes",
		body:        scope,
		expectCodes: []int{http.StatusOK, http.StatusCreated},
	})
	if err != nil {
		return nil, err
	}

	return parseOrganizationScopeResponse(body)
}

// UpdateOrganizationScope updates an organization scope
func (a *Adapter) UpdateOrganizationScope(ctx context.Context, scopeID string, update models.OrganizationScopeUpdate) (*models.OrganizationScope, error) {
	if scopeID == "" {
		return nil, &ValidationError{Field: "scopeID", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodPatch,
		path:       "/api/organization-scopes/%s",
		pathParams: []string{scopeID},
		body:       update,
	})
	if err != nil {
		return nil, err
	}

	return parseOrganizationScopeResponse(body)
}

// DeleteOrganizationScope deletes an organization scope
func (a *Adapter) DeleteOrganizationScope(ctx context.Context, scopeID string) error {
	if scopeID == "" {
		return &ValidationError{Field: "scopeID", Message: "cannot be empty"}
	}

	return a.doNoContent(ctx, requestConfig{
		method:      http.MethodDelete,
		path:        "/api/organization-scopes/%s",
		pathParams:  []string{scopeID},
		expectCodes: []int{http.StatusOK, http.StatusNoContent},
	})
}

// parseOrganizationRolesSlice parses array of organization roles from API response
func parseOrganizationRolesSlice(data []byte) ([]models.OrganizationRole, error) {
	var roles []models.OrganizationRole
	if err := json.Unmarshal(data, &roles); err != nil {
		return nil, fmt.Errorf("unmarshal organization roles: %w", err)
	}
	return roles, nil
}

// parseOrganizationRoleResponse parses organization role from API response
func parseOrganizationRoleResponse(data []byte) (*models.OrganizationRole, error) {
	var role models.OrganizationRole
	if err := json.Unmarshal(data, &role); err != nil {
		return nil, fmt.Errorf("parse organization role: %w", err)
	}
	return &role, nil
}

// parseOrganizationScopeResponse parses organization scope from API response
func parseOrganizationScopeResponse(data []byte) (*models.OrganizationScope, error) {
	var scope models.OrganizationScope
	if err := json.Unmarshal(data, &scope); err != nil {
		return nil, fmt.Errorf("parse organization scope: %w", err)
	}
	return &scope, nil
}
