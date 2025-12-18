package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

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
func (a *Adapter) ListAPIResources(ctx context.Context) ([]models.APIResource, error) {
	body, _, err := a.doRequest(ctx, requestConfig{
		method: http.MethodGet,
		path:   "/api/resources",
	})
	if err != nil {
		return nil, err
	}

	var resources []models.APIResource
	if err := json.Unmarshal(body, &resources); err != nil {
		return nil, fmt.Errorf("unmarshal API resources: %w", err)
	}

	return resources, nil
}

// CreateAPIResource creates a new API resource
func (a *Adapter) CreateAPIResource(ctx context.Context, resource models.APIResourceCreate) (*models.APIResource, error) {
	if resource.Name == "" {
		return nil, &ValidationError{Field: "name", Message: "cannot be empty"}
	}
	if resource.Indicator == "" {
		return nil, &ValidationError{Field: "indicator", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:      http.MethodPost,
		path:        "/api/resources",
		body:        resource,
		expectCodes: []int{http.StatusOK, http.StatusCreated},
	})
	if err != nil {
		return nil, err
	}

	return parseAPIResourceResponse(body)
}

// UpdateAPIResource updates an API resource
func (a *Adapter) UpdateAPIResource(ctx context.Context, resourceID string, update models.APIResourceUpdate) (*models.APIResource, error) {
	if resourceID == "" {
		return nil, &ValidationError{Field: "resourceID", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodPatch,
		path:       "/api/resources/%s",
		pathParams: []string{resourceID},
		body:       update,
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
		expectCodes: []int{http.StatusOK, http.StatusNoContent},
	})
}

// GetAPIResourceScope retrieves a single scope for an API resource
func (a *Adapter) GetAPIResourceScope(ctx context.Context, resourceID, scopeID string) (*models.APIResourceScope, error) {
	if scopeID == "" {
		return nil, &ValidationError{Field: "scopeID", Message: "cannot be empty"}
	}
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

	var scopes []models.APIResourceScope
	if err := json.Unmarshal(body, &scopes); err != nil {
		return nil, fmt.Errorf("unmarshal API resource scopes: %w", err)
	}

	return scopes, nil
}

// CreateAPIResourceScope creates a new scope for an API resource
func (a *Adapter) CreateAPIResourceScope(ctx context.Context, resourceID string, scope models.APIResourceScopeCreate) (*models.APIResourceScope, error) {
	if resourceID == "" {
		return nil, &ValidationError{Field: "resourceID", Message: "cannot be empty"}
	}
	if scope.Name == "" {
		return nil, &ValidationError{Field: "name", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:      http.MethodPost,
		path:        "/api/resources/%s/scopes",
		pathParams:  []string{resourceID},
		body:        scope,
		expectCodes: []int{http.StatusOK, http.StatusCreated},
	})
	if err != nil {
		return nil, err
	}

	return parseAPIResourceScopeResponse(body)
}

// UpdateAPIResourceScope updates a scope for an API resource
func (a *Adapter) UpdateAPIResourceScope(ctx context.Context, resourceID, scopeID string, update models.APIResourceScopeUpdate) (*models.APIResourceScope, error) {
	if resourceID == "" {
		return nil, &ValidationError{Field: "resourceID", Message: "cannot be empty"}
	}
	if scopeID == "" {
		return nil, &ValidationError{Field: "scopeID", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodPatch,
		path:       "/api/resources/%s/scopes/%s",
		pathParams: []string{resourceID, scopeID},
		body:       update,
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
		expectCodes: []int{http.StatusOK, http.StatusNoContent},
	})
}

// parseAPIResourceScopeResponse parses API resource scope from API response
func parseAPIResourceScopeResponse(data []byte) (*models.APIResourceScope, error) {
	var scope models.APIResourceScope
	if err := json.Unmarshal(data, &scope); err != nil {
		return nil, fmt.Errorf("parse API resource scope: %w", err)
	}
	return &scope, nil
}

// parseAPIResourceResponse parses API resource from API response
func parseAPIResourceResponse(data []byte) (*models.APIResource, error) {
	var resource models.APIResource
	if err := json.Unmarshal(data, &resource); err != nil {
		return nil, fmt.Errorf("parse API resource: %w", err)
	}
	return &resource, nil
}
