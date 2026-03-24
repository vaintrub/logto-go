package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/vaintrub/logto-go/models"
)

// ListOrganizationsRequest defines parameters for listing organizations with pagination and filtering options.
type ListOrganizationsRequest struct {
	IteratorConfig
	Page         int
	Q            string
	ShowFeatured bool
}

// GetOrganization retrieves organization details
func (a *Adapter) GetOrganization(ctx context.Context, orgID string) (*models.Organization, error) {
	if orgID == "" {
		return nil, &ValidationError{Field: "orgID", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodGet,
		path:       "/api/organizations/%s",
		pathParams: []string{orgID},
	})
	if err != nil {
		return nil, err
	}

	return parseOrganizationResponse(body)
}

// ListOrganizations returns an iterator for paginating through all organizations.
func (a *Adapter) ListOrganizations(config ListOrganizationsRequest) *Iterator[models.Organization] {
	fetcher := func(ctx context.Context, page, pageSize int) (PageResult[models.Organization], error) {
		req := config
		req.Page = page
		req.PageSize = pageSize
		return a.listOrganizationsPaginated(ctx, req)
	}
	return NewIterator(fetcher, config.IteratorConfig)
}

// ListUserOrganizations returns all organizations a user belongs to,
// including the user's roles in each organization.
// Note: The Logto API does not support pagination for this endpoint.
func (a *Adapter) ListUserOrganizations(ctx context.Context, userID string) ([]models.UserOrganization, error) {
	if userID == "" {
		return nil, &ValidationError{Field: "userID", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodGet,
		path:       "/api/users/%s/organizations",
		pathParams: []string{userID},
	})
	if err != nil {
		return nil, err
	}

	var orgs []models.UserOrganization
	if err := json.Unmarshal(body, &orgs); err != nil {
		return nil, fmt.Errorf("unmarshal user organizations: %w", err)
	}
	return orgs, nil
}

// CreateOrganization creates a new organization in Logto
func (a *Adapter) CreateOrganization(ctx context.Context, org models.OrganizationCreate) (*models.Organization, error) {
	if org.Name == "" {
		return nil, &ValidationError{Field: "name", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:      http.MethodPost,
		path:        "/api/organizations",
		body:        org,
		expectCodes: []int{http.StatusOK, http.StatusCreated},
	})
	if err != nil {
		return nil, err
	}

	return parseOrganizationResponse(body)
}

// UpdateOrganization updates organization details
func (a *Adapter) UpdateOrganization(ctx context.Context, orgID string, update models.OrganizationUpdate) (*models.Organization, error) {
	if orgID == "" {
		return nil, &ValidationError{Field: "orgID", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:      http.MethodPatch,
		path:        "/api/organizations/%s",
		pathParams:  []string{orgID},
		body:        update,
		expectCodes: []int{http.StatusOK},
	})
	if err != nil {
		return nil, err
	}

	return parseOrganizationResponse(body)
}

// DeleteOrganization removes an organization from Logto
func (a *Adapter) DeleteOrganization(ctx context.Context, orgID string) error {
	if orgID == "" {
		return &ValidationError{Field: "orgID", Message: "cannot be empty"}
	}

	return a.doNoContent(ctx, requestConfig{
		method:      http.MethodDelete,
		path:        "/api/organizations/%s",
		pathParams:  []string{orgID},
		expectCodes: []int{http.StatusOK, http.StatusNoContent},
	})
}

// listOrganizationsPaginated returns organizations with pagination support
func (a *Adapter) listOrganizationsPaginated(ctx context.Context, request ListOrganizationsRequest) (PageResult[models.Organization], error) {
	query := url.Values{
		"page":      {fmt.Sprintf("%d", request.Page)},
		"page_size": {fmt.Sprintf("%d", request.PageSize)},
	}
	if request.Q != "" {
		query.Set("q", request.Q)
	}
	if request.ShowFeatured {
		query.Set("showFeatured", fmt.Sprintf("%t", request.ShowFeatured))
	}

	result, err := a.doRequestFull(ctx, requestConfig{
		method: http.MethodGet,
		path:   "/api/organizations",
		query:  query,
	})
	if err != nil {
		return PageResult[models.Organization]{}, err
	}

	var orgs []models.Organization
	if err := json.Unmarshal(result.Body, &orgs); err != nil {
		return PageResult[models.Organization]{}, fmt.Errorf("unmarshal paginated organizations: %w", err)
	}

	return PageResult[models.Organization]{
		Items: orgs,
		Total: getTotalFromHeaders(result.Headers),
	}, nil
}

// parseOrganizationResponse parses organization from API response
func parseOrganizationResponse(data []byte) (*models.Organization, error) {
	var org models.Organization
	if err := json.Unmarshal(data, &org); err != nil {
		return nil, fmt.Errorf("parse organization: %w", err)
	}
	if org.CustomData == nil {
		org.CustomData = make(map[string]interface{})
	}
	return &org, nil
}
