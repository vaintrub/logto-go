package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

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

	var rolesResp []struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Scopes      []struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"scopes"`
	}

	if err := json.Unmarshal(body, &rolesResp); err != nil {
		return nil, fmt.Errorf("unmarshal organization roles response: %w", err)
	}

	roles := make([]models.OrganizationRole, len(rolesResp))
	for i, r := range rolesResp {
		scopes := make([]models.OrganizationScope, len(r.Scopes))
		for j, s := range r.Scopes {
			scopes[j] = models.OrganizationScope{
				ID:          s.ID,
				Name:        s.Name,
				Description: s.Description,
			}
		}
		roles[i] = models.OrganizationRole{
			ID:          r.ID,
			Name:        r.Name,
			Description: r.Description,
			Scopes:      scopes,
		}
	}

	return roles, nil
}

// GetOrganizationRole retrieves a single organization role by ID with its scopes
func (a *Adapter) GetOrganizationRole(ctx context.Context, roleID string) (*models.OrganizationRole, error) {
	if roleID == "" {
		return nil, &ValidationError{Field: "roleID", Message: "cannot be empty"}
	}

	// Get role details
	body, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodGet,
		path:       "/api/organization-roles/%s",
		pathParams: []string{roleID},
	})
	if err != nil {
		return nil, err
	}

	var roleResp struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}

	if err := json.Unmarshal(body, &roleResp); err != nil {
		return nil, fmt.Errorf("unmarshal organization role response: %w", err)
	}

	// Get role scopes (separate endpoint in Logto API)
	scopes, err := a.GetOrganizationRoleScopes(ctx, roleID)
	if err != nil {
		return nil, err
	}

	return &models.OrganizationRole{
		ID:          roleResp.ID,
		Name:        roleResp.Name,
		Description: roleResp.Description,
		Scopes:      scopes,
	}, nil
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

	var scopesResp []struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}

	if err := json.Unmarshal(body, &scopesResp); err != nil {
		return nil, fmt.Errorf("unmarshal organization role scopes response: %w", err)
	}

	scopes := make([]models.OrganizationScope, len(scopesResp))
	for i, s := range scopesResp {
		scopes[i] = models.OrganizationScope{
			ID:          s.ID,
			Name:        s.Name,
			Description: s.Description,
		}
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
		expectCodes: []int{http.StatusCreated, http.StatusOK},
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
		expectCodes: []int{http.StatusNoContent, http.StatusOK},
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

	return a.doNoContent(ctx, requestConfig{
		method:      http.MethodPost,
		path:        "/api/organization-roles/%s/scopes",
		pathParams:  []string{roleID},
		body:        map[string][]string{"organizationScopeIds": scopeIDs},
		expectCodes: []int{http.StatusCreated, http.StatusOK, http.StatusNoContent},
	})
}

// RemoveOrganizationRoleScope removes a scope from an organization role
func (a *Adapter) RemoveOrganizationRoleScope(ctx context.Context, roleID, scopeID string) error {
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
		expectCodes: []int{http.StatusNoContent, http.StatusOK},
	})
}

// AssignResourceScopesToOrganizationRole assigns API resource scopes to an organization role
func (a *Adapter) AssignResourceScopesToOrganizationRole(ctx context.Context, roleID string, scopeIDs []string) error {
	if roleID == "" {
		return &ValidationError{Field: "roleID", Message: "cannot be empty"}
	}

	return a.doNoContent(ctx, requestConfig{
		method:      http.MethodPost,
		path:        "/api/organization-roles/%s/resource-scopes",
		pathParams:  []string{roleID},
		body:        map[string][]string{"scopeIds": scopeIDs},
		expectCodes: []int{http.StatusCreated, http.StatusOK, http.StatusNoContent},
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

	var scopesData []json.RawMessage
	if err := json.Unmarshal(body, &scopesData); err != nil {
		return nil, fmt.Errorf("unmarshal organization scopes response: %w", err)
	}

	scopes := make([]models.OrganizationScope, 0, len(scopesData))
	for _, data := range scopesData {
		scope, err := parseOrganizationScopeResponse(data)
		if err != nil {
			return nil, err
		}
		scopes = append(scopes, *scope)
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
		expectCodes: []int{http.StatusCreated, http.StatusOK},
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
		expectCodes: []int{http.StatusNoContent, http.StatusOK},
	})
}

// parseOrganizationRolesSlice parses array of organization roles from API response
func parseOrganizationRolesSlice(data []byte) ([]models.OrganizationRole, error) {
	var rolesData []json.RawMessage
	if err := json.Unmarshal(data, &rolesData); err != nil {
		return nil, fmt.Errorf("unmarshal organization roles: %w", err)
	}

	roles := make([]models.OrganizationRole, 0, len(rolesData))
	for _, raw := range rolesData {
		role, err := parseOrganizationRoleResponse(raw)
		if err != nil {
			return nil, err
		}
		roles = append(roles, *role)
	}
	return roles, nil
}

// parseOrganizationRoleResponse parses organization role from API response
func parseOrganizationRoleResponse(data []byte) (*models.OrganizationRole, error) {
	var raw struct {
		ID          string `json:"id"`
		TenantID    string `json:"tenantId"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Type        string `json:"type"`
		CreatedAt   int64  `json:"createdAt"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse organization role: %w", err)
	}

	return &models.OrganizationRole{
		ID:          raw.ID,
		TenantID:    raw.TenantID,
		Name:        raw.Name,
		Description: raw.Description,
		Type:        raw.Type,
		CreatedAt:   time.UnixMilli(raw.CreatedAt),
	}, nil
}

// parseOrganizationScopeResponse parses organization scope from API response
func parseOrganizationScopeResponse(data []byte) (*models.OrganizationScope, error) {
	var raw struct {
		ID          string `json:"id"`
		TenantID    string `json:"tenantId"`
		Name        string `json:"name"`
		Description string `json:"description"`
		CreatedAt   int64  `json:"createdAt"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse organization scope: %w", err)
	}

	return &models.OrganizationScope{
		ID:          raw.ID,
		TenantID:    raw.TenantID,
		Name:        raw.Name,
		Description: raw.Description,
		CreatedAt:   time.UnixMilli(raw.CreatedAt),
	}, nil
}
