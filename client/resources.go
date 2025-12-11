package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/vaintrub/logto-go/models"
)

// GetAPIResource retrieves a single API resource by ID
func (a *Adapter) GetAPIResource(ctx context.Context, resourceID string) (*models.APIResource, error) {
	if resourceID == "" {
		return nil, &ValidationError{Field: "resourceID", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodGet,
		path:       "/api/resources/%s",
		pathParams: []string{resourceID},
	})
	if err != nil {
		return nil, err
	}

	return parseAPIResourceResponse(body)
}

// ListAPIResources lists all API resources.
// Returns resources and any error. If some items failed to parse, returns partial results
// with a combined error containing all parse failures.
func (a *Adapter) ListAPIResources(ctx context.Context) ([]models.APIResource, error) {
	body, _, err := a.doRequest(ctx, requestConfig{
		method: http.MethodGet,
		path:   "/api/resources",
	})
	if err != nil {
		return nil, err
	}

	var resourcesData []json.RawMessage
	if err := json.Unmarshal(body, &resourcesData); err != nil {
		return nil, fmt.Errorf("unmarshal API resources response: %w", err)
	}

	resources := make([]models.APIResource, 0, len(resourcesData))
	var parseErrs []error
	for _, data := range resourcesData {
		resource, err := parseAPIResourceResponse(data)
		if err != nil {
			parseErrs = append(parseErrs, err)
			continue
		}
		resources = append(resources, *resource)
	}

	if len(parseErrs) > 0 {
		return resources, fmt.Errorf("failed to parse %d resource(s): %w", len(parseErrs), errors.Join(parseErrs...))
	}
	return resources, nil
}

// CreateAPIResource creates a new API resource
func (a *Adapter) CreateAPIResource(ctx context.Context, name, indicator string) (*models.APIResource, error) {
	if name == "" {
		return nil, &ValidationError{Field: "name", Message: "cannot be empty"}
	}
	if indicator == "" {
		return nil, &ValidationError{Field: "indicator", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method: http.MethodPost,
		path:   "/api/resources",
		body: map[string]interface{}{
			"name":      name,
			"indicator": indicator,
		},
		expectCodes: []int{http.StatusCreated, http.StatusOK},
	})
	if err != nil {
		return nil, err
	}

	return parseAPIResourceResponse(body)
}

// UpdateAPIResource updates an API resource
func (a *Adapter) UpdateAPIResource(ctx context.Context, resourceID, name string, accessTokenTTL *int) (*models.APIResource, error) {
	if resourceID == "" {
		return nil, &ValidationError{Field: "resourceID", Message: "cannot be empty"}
	}

	payload := make(map[string]interface{})
	if name != "" {
		payload["name"] = name
	}
	if accessTokenTTL != nil {
		payload["accessTokenTtl"] = *accessTokenTTL
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodPatch,
		path:       "/api/resources/%s",
		pathParams: []string{resourceID},
		body:       payload,
	})
	if err != nil {
		return nil, err
	}

	return parseAPIResourceResponse(body)
}

// DeleteAPIResource deletes an API resource
func (a *Adapter) DeleteAPIResource(ctx context.Context, resourceID string) error {
	if resourceID == "" {
		return &ValidationError{Field: "resourceID", Message: "cannot be empty"}
	}

	return a.doNoContent(ctx, requestConfig{
		method:      http.MethodDelete,
		path:        "/api/resources/%s",
		pathParams:  []string{resourceID},
		expectCodes: []int{http.StatusNoContent, http.StatusOK},
	})
}

// GetAPIResourceScope retrieves a single scope for an API resource
func (a *Adapter) GetAPIResourceScope(ctx context.Context, resourceID, scopeID string) (*models.APIResourceScope, error) {
	// Logto API doesn't have a direct GET endpoint for individual scopes,
	// so we list all scopes and find the one we need
	scopes, err := a.ListAPIResourceScopes(ctx, resourceID)
	if err != nil {
		return nil, err
	}

	for _, scope := range scopes {
		if scope.ID == scopeID {
			return &scope, nil
		}
	}

	return nil, &APIError{StatusCode: 404, Message: fmt.Sprintf("API resource scope not found: %s", scopeID)}
}

// ListAPIResourceScopes lists all scopes for an API resource
func (a *Adapter) ListAPIResourceScopes(ctx context.Context, resourceID string) ([]models.APIResourceScope, error) {
	if resourceID == "" {
		return nil, &ValidationError{Field: "resourceID", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodGet,
		path:       "/api/resources/%s/scopes",
		pathParams: []string{resourceID},
	})
	if err != nil {
		return nil, err
	}

	var scopesData []json.RawMessage
	if err := json.Unmarshal(body, &scopesData); err != nil {
		return nil, fmt.Errorf("unmarshal API resource scopes response: %w", err)
	}

	scopes := make([]models.APIResourceScope, 0, len(scopesData))
	for _, data := range scopesData {
		scope, err := parseAPIResourceScopeResponse(data)
		if err != nil {
			return nil, err
		}
		scopes = append(scopes, *scope)
	}

	return scopes, nil
}

// CreateAPIResourceScope creates a new scope for an API resource
func (a *Adapter) CreateAPIResourceScope(ctx context.Context, resourceID, name, description string) (*models.APIResourceScope, error) {
	if resourceID == "" {
		return nil, &ValidationError{Field: "resourceID", Message: "cannot be empty"}
	}
	if name == "" {
		return nil, &ValidationError{Field: "name", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodPost,
		path:       "/api/resources/%s/scopes",
		pathParams: []string{resourceID},
		body: map[string]interface{}{
			"name":        name,
			"description": description,
		},
		expectCodes: []int{http.StatusCreated, http.StatusOK},
	})
	if err != nil {
		return nil, err
	}

	return parseAPIResourceScopeResponse(body)
}

// UpdateAPIResourceScope updates a scope for an API resource
func (a *Adapter) UpdateAPIResourceScope(ctx context.Context, resourceID, scopeID, name, description string) (*models.APIResourceScope, error) {
	if resourceID == "" {
		return nil, &ValidationError{Field: "resourceID", Message: "cannot be empty"}
	}
	if scopeID == "" {
		return nil, &ValidationError{Field: "scopeID", Message: "cannot be empty"}
	}

	payload := make(map[string]interface{})
	if name != "" {
		payload["name"] = name
	}
	if description != "" {
		payload["description"] = description
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodPatch,
		path:       "/api/resources/%s/scopes/%s",
		pathParams: []string{resourceID, scopeID},
		body:       payload,
	})
	if err != nil {
		return nil, err
	}

	return parseAPIResourceScopeResponse(body)
}

// DeleteAPIResourceScope deletes a scope from an API resource
func (a *Adapter) DeleteAPIResourceScope(ctx context.Context, resourceID, scopeID string) error {
	if resourceID == "" {
		return &ValidationError{Field: "resourceID", Message: "cannot be empty"}
	}
	if scopeID == "" {
		return &ValidationError{Field: "scopeID", Message: "cannot be empty"}
	}

	return a.doNoContent(ctx, requestConfig{
		method:      http.MethodDelete,
		path:        "/api/resources/%s/scopes/%s",
		pathParams:  []string{resourceID, scopeID},
		expectCodes: []int{http.StatusNoContent, http.StatusOK},
	})
}

// parseAPIResourceScopeResponse parses API resource scope from API response
func parseAPIResourceScopeResponse(data []byte) (*models.APIResourceScope, error) {
	var raw struct {
		ID          string `json:"id"`
		TenantID    string `json:"tenantId"`
		ResourceID  string `json:"resourceId"`
		Name        string `json:"name"`
		Description string `json:"description"`
		CreatedAt   int64  `json:"createdAt"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse API resource scope: %w", err)
	}

	return &models.APIResourceScope{
		ID:          raw.ID,
		TenantID:    raw.TenantID,
		ResourceID:  raw.ResourceID,
		Name:        raw.Name,
		Description: raw.Description,
		CreatedAt:   time.UnixMilli(raw.CreatedAt),
	}, nil
}

// parseAPIResourceResponse parses API resource from API response
func parseAPIResourceResponse(data []byte) (*models.APIResource, error) {
	var raw struct {
		ID             string `json:"id"`
		TenantID       string `json:"tenantId"`
		Name           string `json:"name"`
		Indicator      string `json:"indicator"`
		AccessTokenTTL int    `json:"accessTokenTtl"`
		IsDefault      bool   `json:"isDefault"`
		CreatedAt      int64  `json:"createdAt"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse API resource: %w", err)
	}

	return &models.APIResource{
		ID:             raw.ID,
		TenantID:       raw.TenantID,
		Name:           raw.Name,
		Indicator:      raw.Indicator,
		AccessTokenTTL: raw.AccessTokenTTL,
		IsDefault:      raw.IsDefault,
		CreatedAt:      time.UnixMilli(raw.CreatedAt),
	}, nil
}
