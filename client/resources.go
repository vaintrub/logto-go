package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

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

// ListAPIResources returns an iterator for all API resources.
func (a *Adapter) ListAPIResources(config IteratorConfig) *Iterator[models.APIResource] {
	return NewIterator(a.listAPIResourcesPaginated, config)
}

// listAPIResourcesPaginated returns API resources with pagination support
func (a *Adapter) listAPIResourcesPaginated(ctx context.Context, page, pageSize int) (PageResult[models.APIResource], error) {
	result, err := a.doRequestFull(ctx, requestConfig{
		method: http.MethodGet,
		path:   "/api/resources",
		query: url.Values{
			"page":      {fmt.Sprintf("%d", page)},
			"page_size": {fmt.Sprintf("%d", pageSize)},
		},
	})
	if err != nil {
		return PageResult[models.APIResource]{}, err
	}

	var resources []models.APIResource
	if err := json.Unmarshal(result.Body, &resources); err != nil {
		return PageResult[models.APIResource]{}, fmt.Errorf("unmarshal API resources: %w", err)
	}

	return PageResult[models.APIResource]{
		Items: resources,
		Total: getTotalFromHeaders(result.Headers),
	}, nil
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
	if resourceID == "" {
		return nil, &ValidationError{Field: "resourceID", Message: "cannot be empty"}
	}
	if scopeID == "" {
		return nil, &ValidationError{Field: "scopeID", Message: "cannot be empty"}
	}
	// Logto API doesn't have a direct GET endpoint for individual scopes,
	// so we list all scopes and find the one we need
	iter := a.ListAPIResourceScopes(resourceID, DefaultIteratorConfig())
	for iter.Next(ctx) {
		scope := iter.Item()
		if scope.ID == scopeID {
			return scope, nil
		}
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}

	return nil, &APIError{StatusCode: 404, Message: fmt.Sprintf("API resource scope not found: %s", scopeID)}
}

// ListAPIResourceScopes returns an iterator for all scopes for an API resource.
func (a *Adapter) ListAPIResourceScopes(resourceID string, config IteratorConfig) *Iterator[models.APIResourceScope] {
	fetcher := func(ctx context.Context, page, pageSize int) (PageResult[models.APIResourceScope], error) {
		if resourceID == "" {
			return PageResult[models.APIResourceScope]{}, &ValidationError{Field: "resourceID", Message: "cannot be empty"}
		}
		return a.listAPIResourceScopesPaginated(ctx, resourceID, page, pageSize)
	}
	return NewIterator(fetcher, config)
}

// listAPIResourceScopesPaginated returns API resource scopes with pagination support
func (a *Adapter) listAPIResourceScopesPaginated(ctx context.Context, resourceID string, page, pageSize int) (PageResult[models.APIResourceScope], error) {
	result, err := a.doRequestFull(ctx, requestConfig{
		method:     http.MethodGet,
		path:       "/api/resources/%s/scopes",
		pathParams: []string{resourceID},
		query: url.Values{
			"page":      {fmt.Sprintf("%d", page)},
			"page_size": {fmt.Sprintf("%d", pageSize)},
		},
	})
	if err != nil {
		return PageResult[models.APIResourceScope]{}, err
	}

	var scopes []models.APIResourceScope
	if err := json.Unmarshal(result.Body, &scopes); err != nil {
		return PageResult[models.APIResourceScope]{}, fmt.Errorf("unmarshal API resource scopes: %w", err)
	}

	return PageResult[models.APIResourceScope]{
		Items: scopes,
		Total: getTotalFromHeaders(result.Headers),
	}, nil
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
