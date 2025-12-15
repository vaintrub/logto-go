package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

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

// ListOrganizations retrieves all organizations.
// Returns organizations and any error. If some items failed to parse, returns partial results
// with a combined error containing all parse failures.
func (a *Adapter) ListOrganizations(ctx context.Context) ([]models.Organization, error) {
	body, _, err := a.doRequest(ctx, requestConfig{
		method: http.MethodGet,
		path:   "/api/organizations",
	})
	if err != nil {
		return nil, err
	}

	var orgsData []json.RawMessage
	if err := json.Unmarshal(body, &orgsData); err != nil {
		return nil, fmt.Errorf("unmarshal organizations response: %w", err)
	}

	orgs := make([]models.Organization, 0, len(orgsData))
	var parseErrs []error
	for _, orgData := range orgsData {
		org, err := parseOrganizationResponse(orgData)
		if err != nil {
			parseErrs = append(parseErrs, err)
			continue
		}
		orgs = append(orgs, *org)
	}

	if len(parseErrs) > 0 {
		return orgs, fmt.Errorf("failed to parse %d organization(s): %w", len(parseErrs), errors.Join(parseErrs...))
	}
	return orgs, nil
}

// ListUserOrganizations retrieves organizations where the user is a member.
// Returns organizations and any error. If some items failed to parse, returns partial results
// with a combined error containing all parse failures.
func (a *Adapter) ListUserOrganizations(ctx context.Context, userID string) ([]models.Organization, error) {
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

	var orgsData []json.RawMessage
	if err := json.Unmarshal(body, &orgsData); err != nil {
		return nil, fmt.Errorf("unmarshal user organizations response: %w", err)
	}

	orgs := make([]models.Organization, 0, len(orgsData))
	var parseErrs []error
	for _, orgData := range orgsData {
		org, err := parseOrganizationResponse(orgData)
		if err != nil {
			parseErrs = append(parseErrs, err)
			continue
		}
		orgs = append(orgs, *org)
	}

	if len(parseErrs) > 0 {
		return orgs, fmt.Errorf("failed to parse %d organization(s): %w", len(parseErrs), errors.Join(parseErrs...))
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
func (a *Adapter) listOrganizationsPaginated(ctx context.Context, page, pageSize int) ([]models.Organization, error) {
	body, _, err := a.doRequest(ctx, requestConfig{
		method: http.MethodGet,
		path:   "/api/organizations",
		query: url.Values{
			"page":      {fmt.Sprintf("%d", page)},
			"page_size": {fmt.Sprintf("%d", pageSize)},
		},
	})
	if err != nil {
		return nil, err
	}

	var orgsData []json.RawMessage
	if err := json.Unmarshal(body, &orgsData); err != nil {
		return nil, fmt.Errorf("unmarshal paginated organizations response: %w", err)
	}

	orgs := make([]models.Organization, 0, len(orgsData))
	for _, orgData := range orgsData {
		org, err := parseOrganizationResponse(orgData)
		if err != nil {
			// Skip invalid items in pagination
			continue
		}
		orgs = append(orgs, *org)
	}

	return orgs, nil
}

// parseOrganizationResponse parses organization from API response
func parseOrganizationResponse(data []byte) (*models.Organization, error) {
	var raw struct {
		ID            string                       `json:"id"`
		TenantID      string                       `json:"tenantId"`
		Name          string                       `json:"name"`
		Description   string                       `json:"description"`
		CustomData    map[string]interface{}       `json:"customData"`
		IsMfaRequired bool                         `json:"isMfaRequired"`
		Branding      *models.OrganizationBranding `json:"branding"`
		CreatedAt     int64                        `json:"createdAt"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse organization: %w", err)
	}

	customData := raw.CustomData
	if customData == nil {
		customData = make(map[string]interface{})
	}

	return &models.Organization{
		ID:            raw.ID,
		TenantID:      raw.TenantID,
		Name:          raw.Name,
		Description:   raw.Description,
		CustomData:    customData,
		IsMfaRequired: raw.IsMfaRequired,
		Branding:      raw.Branding,
		CreatedAt:     time.UnixMilli(raw.CreatedAt),
	}, nil
}
