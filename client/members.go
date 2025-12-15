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

// ListOrganizationMembers lists all members of an organization with their roles.
// Returns members and any error. If some items failed to parse, returns partial results
// with a combined error containing all parse failures.
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

	var membersData []json.RawMessage
	if err := json.Unmarshal(body, &membersData); err != nil {
		return nil, fmt.Errorf("unmarshal organization members response: %w", err)
	}

	members := make([]models.OrganizationMember, 0, len(membersData))
	var parseErrs []error
	for _, memberData := range membersData {
		member, err := parseOrganizationMemberResponse(memberData)
		if err != nil {
			parseErrs = append(parseErrs, err)
			continue
		}
		members = append(members, *member)
	}

	if len(parseErrs) > 0 {
		return members, fmt.Errorf("failed to parse %d member(s): %w", len(parseErrs), errors.Join(parseErrs...))
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

// parseOrganizationMemberResponse parses user with their organization roles from API response
func parseOrganizationMemberResponse(data []byte) (*models.OrganizationMember, error) {
	var raw struct {
		ID                     string                         `json:"id"`
		TenantID               string                         `json:"tenantId"`
		Username               string                         `json:"username"`
		PrimaryEmail           string                         `json:"primaryEmail"`
		PrimaryPhone           string                         `json:"primaryPhone"`
		Name                   string                         `json:"name"`
		Avatar                 string                         `json:"avatar"`
		CustomData             map[string]interface{}         `json:"customData"`
		Identities             map[string]models.UserIdentity `json:"identities"`
		LastSignInAt           *int64                         `json:"lastSignInAt"`
		CreatedAt              int64                          `json:"createdAt"`
		UpdatedAt              int64                          `json:"updatedAt"`
		Profile                *models.UserProfile            `json:"profile"`
		ApplicationID          string                         `json:"applicationId"`
		IsSuspended            bool                           `json:"isSuspended"`
		HasPassword            bool                           `json:"hasPassword"`
		SSOIdentities          []models.SSOIdentity           `json:"ssoIdentities"`
		MFAVerificationFactors []string                       `json:"mfaVerificationFactors"`
		OrganizationRoles      []struct {
			ID          string `json:"id"`
			TenantID    string `json:"tenantId"`
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"organizationRoles"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse organization member: %w", err)
	}

	customData := raw.CustomData
	if customData == nil {
		customData = make(map[string]interface{})
	}

	identities := raw.Identities
	if identities == nil {
		identities = make(map[string]models.UserIdentity)
	}

	var lastSignInAt *time.Time
	if raw.LastSignInAt != nil {
		t := time.UnixMilli(*raw.LastSignInAt)
		lastSignInAt = &t
	}

	user := &models.User{
		ID:                     raw.ID,
		TenantID:               raw.TenantID,
		Username:               raw.Username,
		PrimaryEmail:           raw.PrimaryEmail,
		PrimaryPhone:           raw.PrimaryPhone,
		Name:                   raw.Name,
		Avatar:                 raw.Avatar,
		CustomData:             customData,
		Identities:             identities,
		LastSignInAt:           lastSignInAt,
		CreatedAt:              time.UnixMilli(raw.CreatedAt),
		UpdatedAt:              time.UnixMilli(raw.UpdatedAt),
		Profile:                raw.Profile,
		ApplicationID:          raw.ApplicationID,
		IsSuspended:            raw.IsSuspended,
		HasPassword:            raw.HasPassword,
		SSOIdentities:          raw.SSOIdentities,
		MFAVerificationFactors: raw.MFAVerificationFactors,
	}

	roles := make([]models.OrganizationRole, len(raw.OrganizationRoles))
	for i, r := range raw.OrganizationRoles {
		roles[i] = models.OrganizationRole{
			ID:          r.ID,
			TenantID:    r.TenantID,
			Name:        r.Name,
			Description: r.Description,
		}
	}

	return &models.OrganizationMember{
		User:  user,
		Roles: roles,
	}, nil
}
