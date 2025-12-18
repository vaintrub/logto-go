package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/vaintrub/logto-go/models"
)

// ListOrganizationMembers lists all members of an organization with their roles.
func (a *Adapter) ListOrganizationMembers(ctx context.Context, orgID string) ([]models.OrganizationMember, error) {
	if orgID == "" {
		return nil, &ValidationError{Field: "orgID", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodGet,
		path:       "/api/organizations/%s/users",
		pathParams: []string{orgID},
	})
	if err != nil {
		return nil, err
	}

	var members []models.OrganizationMember
	if err := json.Unmarshal(body, &members); err != nil {
		return nil, fmt.Errorf("unmarshal organization members: %w", err)
	}

	return members, nil
}

// AddUserToOrganization adds a user to an organization with specified roles
func (a *Adapter) AddUserToOrganization(ctx context.Context, orgID, userID string, roleIDs []string) error {
	if orgID == "" {
		return &ValidationError{Field: "orgID", Message: "cannot be empty"}
	}
	if userID == "" {
		return &ValidationError{Field: "userID", Message: "cannot be empty"}
	}

	err := a.doNoContent(ctx, requestConfig{
		method:      http.MethodPost,
		path:        "/api/organizations/%s/users",
		pathParams:  []string{orgID},
		body:        map[string][]string{"userIds": {userID}},
		expectCodes: []int{http.StatusOK, http.StatusCreated, http.StatusNoContent},
	})
	if err != nil {
		return err
	}

	// Assign roles if provided
	if len(roleIDs) > 0 {
		return a.UpdateUserRoles(ctx, orgID, userID, models.UserOrganizationRolesUpdate{
			OrganizationRoleIDs: roleIDs,
		})
	}

	return nil
}

// AddUsersToOrganization adds multiple users to an organization (batch operation)
func (a *Adapter) AddUsersToOrganization(ctx context.Context, orgID string, userIDs []string) error {
	if orgID == "" {
		return &ValidationError{Field: "orgID", Message: "cannot be empty"}
	}
	if len(userIDs) == 0 {
		return &ValidationError{Field: "userIDs", Message: "cannot be empty"}
	}

	return a.doNoContent(ctx, requestConfig{
		method:      http.MethodPost,
		path:        "/api/organizations/%s/users",
		pathParams:  []string{orgID},
		body:        map[string][]string{"userIds": userIDs},
		expectCodes: []int{http.StatusOK, http.StatusCreated, http.StatusNoContent},
	})
}

// RemoveUserFromOrganization removes a user from an organization
func (a *Adapter) RemoveUserFromOrganization(ctx context.Context, orgID, userID string) error {
	if orgID == "" {
		return &ValidationError{Field: "orgID", Message: "cannot be empty"}
	}
	if userID == "" {
		return &ValidationError{Field: "userID", Message: "cannot be empty"}
	}

	return a.doNoContent(ctx, requestConfig{
		method:      http.MethodDelete,
		path:        "/api/organizations/%s/users/%s",
		pathParams:  []string{orgID, userID},
		expectCodes: []int{http.StatusOK, http.StatusNoContent},
	})
}

// UpdateUserRoles updates a user's roles in an organization
func (a *Adapter) UpdateUserRoles(ctx context.Context, orgID, userID string, update models.UserOrganizationRolesUpdate) error {
	if orgID == "" {
		return &ValidationError{Field: "orgID", Message: "cannot be empty"}
	}
	if userID == "" {
		return &ValidationError{Field: "userID", Message: "cannot be empty"}
	}

	return a.doNoContent(ctx, requestConfig{
		method:      http.MethodPut,
		path:        "/api/organizations/%s/users/%s/roles",
		pathParams:  []string{orgID, userID},
		body:        update,
		expectCodes: []int{http.StatusOK, http.StatusNoContent},
	})
}

// AssignRolesToOrganizationUsers assigns roles to multiple users in an organization (batch operation)
func (a *Adapter) AssignRolesToOrganizationUsers(ctx context.Context, orgID string, userIDs, roleIDs []string) error {
	if orgID == "" {
		return &ValidationError{Field: "orgID", Message: "cannot be empty"}
	}
	if len(userIDs) == 0 {
		return &ValidationError{Field: "userIDs", Message: "cannot be empty"}
	}
	if len(roleIDs) == 0 {
		return &ValidationError{Field: "roleIDs", Message: "cannot be empty"}
	}

	return a.doNoContent(ctx, requestConfig{
		method:     http.MethodPost,
		path:       "/api/organizations/%s/users/roles",
		pathParams: []string{orgID},
		body: map[string][]string{
			"userIds":             userIDs,
			"organizationRoleIds": roleIDs,
		},
		expectCodes: []int{http.StatusOK, http.StatusCreated, http.StatusNoContent},
	})
}

// GetUserRolesInOrganization gets a user's roles in an organization
func (a *Adapter) GetUserRolesInOrganization(ctx context.Context, orgID, userID string) ([]models.OrganizationRole, error) {
	if orgID == "" {
		return nil, &ValidationError{Field: "orgID", Message: "cannot be empty"}
	}
	if userID == "" {
		return nil, &ValidationError{Field: "userID", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodGet,
		path:       "/api/organizations/%s/users/%s/roles",
		pathParams: []string{orgID, userID},
	})
	if err != nil {
		return nil, err
	}

	return parseOrganizationRolesSlice(body)
}

// GetUserScopesInOrganization gets a user's scopes in an organization
func (a *Adapter) GetUserScopesInOrganization(ctx context.Context, orgID, userID string) ([]models.OrganizationScope, error) {
	if orgID == "" {
		return nil, &ValidationError{Field: "orgID", Message: "cannot be empty"}
	}
	if userID == "" {
		return nil, &ValidationError{Field: "userID", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodGet,
		path:       "/api/organizations/%s/users/%s/scopes",
		pathParams: []string{orgID, userID},
	})
	if err != nil {
		return nil, err
	}

	var scopes []models.OrganizationScope
	if err := json.Unmarshal(body, &scopes); err != nil {
		return nil, fmt.Errorf("unmarshal user organization scopes: %w", err)
	}

	return scopes, nil
}
