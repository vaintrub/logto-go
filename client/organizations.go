package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/vaintrub/logto-go/models"
)

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
func (a *Adapter) ListOrganizations(config IteratorConfig) *Iterator[models.Organization] {
	return NewIterator(a.listOrganizationsPaginated, config)
}

// ListUserOrganizations returns an iterator for organizations where the user is a member,
// including the user's roles in each organization.
func (a *Adapter) ListUserOrganizations(userID string, config IteratorConfig) *Iterator[models.UserOrganization] {
	fetcher := func(ctx context.Context, page, pageSize int) (PageResult[models.UserOrganization], error) {
		if userID == "" {
			return PageResult[models.UserOrganization]{}, &ValidationError{Field: "userID", Message: "cannot be empty"}
		}
		return a.listUserOrganizationsPaginated(ctx, userID, page, pageSize)
	}
	return NewIterator(fetcher, config)
}

// listUserOrganizationsPaginated returns user organizations with pagination support
func (a *Adapter) listUserOrganizationsPaginated(ctx context.Context, userID string, page, pageSize int) (PageResult[models.UserOrganization], error) {
	result, err := a.doRequestFull(ctx, requestConfig{
		method:     http.MethodGet,
		path:       "/api/users/%s/organizations",
		pathParams: []string{userID},
		query: url.Values{
			"page":      {fmt.Sprintf("%d", page)},
			"page_size": {fmt.Sprintf("%d", pageSize)},
		},
	})
	if err != nil {
		return PageResult[models.UserOrganization]{}, err
	}

	var orgs []models.UserOrganization
	if err := json.Unmarshal(result.Body, &orgs); err != nil {
		return PageResult[models.UserOrganization]{}, fmt.Errorf("unmarshal user organizations: %w", err)
	}

	return PageResult[models.UserOrganization]{
		Items: orgs,
		Total: getTotalFromHeaders(result.Headers),
	}, nil
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
func (a *Adapter) listOrganizationsPaginated(ctx context.Context, page, pageSize int) (PageResult[models.Organization], error) {
	result, err := a.doRequestFull(ctx, requestConfig{
		method: http.MethodGet,
		path:   "/api/organizations",
		query: url.Values{
			"page":      {fmt.Sprintf("%d", page)},
			"page_size": {fmt.Sprintf("%d", pageSize)},
		},
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
