package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/vaintrub/logto-go/models"
)

// Adapter implements the Client interface for Logto IDP
type Adapter struct {
	endpoint     string
	m2mAppID     string
	m2mAppSecret string
	httpClient   *http.Client
	opts         *options

	tokenMu     sync.RWMutex
	cachedToken *m2mTokenCache
}

// New creates a new Logto client with the provided options.
// Returns an error if required parameters are missing.
func New(endpoint, m2mAppID, m2mAppSecret string, opts ...Option) (*Adapter, error) {
	if endpoint == "" {
		return nil, &ValidationError{Field: "endpoint", Message: "cannot be empty"}
	}
	if m2mAppID == "" {
		return nil, &ValidationError{Field: "m2mAppID", Message: "cannot be empty"}
	}
	if m2mAppSecret == "" {
		return nil, &ValidationError{Field: "m2mAppSecret", Message: "cannot be empty"}
	}

	// Apply options
	o := defaultOptions()
	for _, opt := range opts {
		opt(o)
	}

	// Create HTTP client
	httpClient := o.httpClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: o.timeout}
	}

	return &Adapter{
		endpoint:     endpoint,
		m2mAppID:     m2mAppID,
		m2mAppSecret: m2mAppSecret,
		httpClient:   httpClient,
		opts:         o,
	}, nil
}

// Ping checks if the Logto IDP is reachable and healthy
func (a *Adapter) Ping(ctx context.Context) error {
	statusURL := fmt.Sprintf("%s/api/status", a.endpoint)

	req, err := http.NewRequestWithContext(ctx, "GET", statusURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create ping request: %w", err)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("IDP ping failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("IDP returned unhealthy status: %d", resp.StatusCode)
	}

	return nil
}

// AuthenticateM2M obtains a machine-to-machine access token
func (a *Adapter) AuthenticateM2M(ctx context.Context) (string, int, error) {
	// Fast path: check cached token with read lock
	a.tokenMu.RLock()
	if a.cachedToken != nil && time.Now().Add(tokenExpiryBuffer).Before(a.cachedToken.expiresAt) {
		token := a.cachedToken.accessToken
		expiresIn := int(time.Until(a.cachedToken.expiresAt).Seconds())
		a.tokenMu.RUnlock()
		return token, expiresIn, nil
	}
	a.tokenMu.RUnlock()

	// Slow path: acquire write lock and double-check (prevents race condition)
	a.tokenMu.Lock()
	defer a.tokenMu.Unlock()

	// Double-check after acquiring write lock
	if a.cachedToken != nil && time.Now().Add(tokenExpiryBuffer).Before(a.cachedToken.expiresAt) {
		return a.cachedToken.accessToken, int(time.Until(a.cachedToken.expiresAt).Seconds()), nil
	}

	// Request new token
	tokenURL := fmt.Sprintf("%s/oidc/token", a.endpoint)

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("resource", a.opts.resource)
	data.Set("scope", a.opts.scope)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", 0, err
	}

	// Use Basic Auth with M2M credentials
	credentials := base64.StdEncoding.EncodeToString([]byte(a.m2mAppID + ":" + a.m2mAppSecret))
	req.Header.Set("Authorization", "Basic "+credentials)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("M2M auth request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, fmt.Errorf("failed to read M2M auth response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("M2M auth failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}

	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", 0, fmt.Errorf("unmarshal token response: %w", err)
	}

	// Cache token (already holding write lock from defer above)
	a.cachedToken = &m2mTokenCache{
		accessToken: tokenResp.AccessToken,
		expiresAt:   time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
	}

	return tokenResp.AccessToken, tokenResp.ExpiresIn, nil
}

// ListOrganizationApplications lists all applications in an organization
func (a *Adapter) ListOrganizationApplications(ctx context.Context, orgID string) ([]models.Application, error) {
	if orgID == "" {
		return nil, &ValidationError{Field: "orgID", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodGet,
		path:       "/api/organizations/%s/applications",
		pathParams: []string{orgID},
	})
	if err != nil {
		return nil, err
	}

	var appsData []json.RawMessage
	if err := json.Unmarshal(body, &appsData); err != nil {
		return nil, fmt.Errorf("unmarshal applications list: %w", err)
	}

	apps := make([]models.Application, 0, len(appsData))
	for _, appData := range appsData {
		app, err := parseApplicationResponse(appData)
		if err != nil {
			return nil, err
		}
		apps = append(apps, *app)
	}

	return apps, nil
}

// AddOrganizationApplications adds applications to an organization
func (a *Adapter) AddOrganizationApplications(ctx context.Context, orgID string, applicationIDs []string) error {
	if orgID == "" {
		return &ValidationError{Field: "orgID", Message: "cannot be empty"}
	}
	if len(applicationIDs) == 0 {
		return &ValidationError{Field: "applicationIDs", Message: "cannot be empty"}
	}

	_, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodPost,
		path:       "/api/organizations/%s/applications",
		pathParams: []string{orgID},
		body: map[string]interface{}{
			"applicationIds": applicationIDs,
		},
		expectCodes: []int{http.StatusOK, http.StatusCreated, http.StatusNoContent},
	})
	return err
}

// RemoveOrganizationApplication removes an application from an organization
func (a *Adapter) RemoveOrganizationApplication(ctx context.Context, orgID, applicationID string) error {
	if orgID == "" {
		return &ValidationError{Field: "orgID", Message: "cannot be empty"}
	}
	if applicationID == "" {
		return &ValidationError{Field: "applicationID", Message: "cannot be empty"}
	}

	_, _, err := a.doRequest(ctx, requestConfig{
		method:      http.MethodDelete,
		path:        "/api/organizations/%s/applications/%s",
		pathParams:  []string{orgID, applicationID},
		expectCodes: []int{http.StatusOK, http.StatusNoContent},
	})
	return err
}

// GetOrganizationApplicationRoles gets the roles assigned to an application in an organization
func (a *Adapter) GetOrganizationApplicationRoles(ctx context.Context, orgID, applicationID string) ([]models.OrganizationRole, error) {
	if orgID == "" {
		return nil, &ValidationError{Field: "orgID", Message: "cannot be empty"}
	}
	if applicationID == "" {
		return nil, &ValidationError{Field: "applicationID", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodGet,
		path:       "/api/organizations/%s/applications/%s/roles",
		pathParams: []string{orgID, applicationID},
	})
	if err != nil {
		return nil, err
	}

	return parseOrganizationRolesSlice(body)
}

// AssignOrganizationApplicationRoles assigns roles to an application in an organization
func (a *Adapter) AssignOrganizationApplicationRoles(ctx context.Context, orgID, applicationID string, roleIDs []string) error {
	if orgID == "" {
		return &ValidationError{Field: "orgID", Message: "cannot be empty"}
	}
	if applicationID == "" {
		return &ValidationError{Field: "applicationID", Message: "cannot be empty"}
	}
	if len(roleIDs) == 0 {
		return &ValidationError{Field: "roleIDs", Message: "cannot be empty"}
	}

	_, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodPost,
		path:       "/api/organizations/%s/applications/%s/roles",
		pathParams: []string{orgID, applicationID},
		body: map[string]interface{}{
			"organizationRoleIds": roleIDs,
		},
		expectCodes: []int{http.StatusOK, http.StatusCreated, http.StatusNoContent},
	})
	return err
}

// RemoveOrganizationApplicationRoles removes roles from an application in an organization
func (a *Adapter) RemoveOrganizationApplicationRoles(ctx context.Context, orgID, applicationID string, roleIDs []string) error {
	if orgID == "" {
		return &ValidationError{Field: "orgID", Message: "cannot be empty"}
	}
	if applicationID == "" {
		return &ValidationError{Field: "applicationID", Message: "cannot be empty"}
	}
	if len(roleIDs) == 0 {
		return &ValidationError{Field: "roleIDs", Message: "cannot be empty"}
	}

	// Logto API requires deleting roles one at a time
	for _, roleID := range roleIDs {
		_, _, err := a.doRequest(ctx, requestConfig{
			method:      http.MethodDelete,
			path:        "/api/organizations/%s/applications/%s/roles/%s",
			pathParams:  []string{orgID, applicationID, roleID},
			expectCodes: []int{http.StatusOK, http.StatusNoContent},
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// ListApplications retrieves all applications.
// Returns applications and any error. If some items failed to parse, returns partial results
// with a combined error containing all parse failures.
func (a *Adapter) ListApplications(ctx context.Context) ([]models.Application, error) {
	body, _, err := a.doRequest(ctx, requestConfig{
		method: http.MethodGet,
		path:   "/api/applications",
	})
	if err != nil {
		return nil, err
	}

	var appsData []json.RawMessage
	if err := json.Unmarshal(body, &appsData); err != nil {
		return nil, fmt.Errorf("unmarshal applications response: %w", err)
	}

	apps := make([]models.Application, 0, len(appsData))
	var parseErrs []error
	for _, appData := range appsData {
		app, err := parseApplicationResponse(appData)
		if err != nil {
			parseErrs = append(parseErrs, err)
			continue
		}
		apps = append(apps, *app)
	}

	if len(parseErrs) > 0 {
		return apps, fmt.Errorf("failed to parse %d application(s): %w", len(parseErrs), errors.Join(parseErrs...))
	}
	return apps, nil
}

// CreateApplication creates a new application in Logto
func (a *Adapter) CreateApplication(ctx context.Context, app models.ApplicationCreate) (*models.Application, error) {
	if app.Name == "" {
		return nil, &ValidationError{Field: "name", Message: "cannot be empty"}
	}
	if app.Type == "" {
		return nil, &ValidationError{Field: "type", Message: "cannot be empty"}
	}

	payload := map[string]interface{}{
		"name": app.Name,
		"type": app.Type,
	}
	if app.Description != "" {
		payload["description"] = app.Description
	}

	// Only set oidcClientMetadata for non-M2M apps
	if app.Type != models.ApplicationTypeMachineToMachine {
		oidcMetadata := map[string]interface{}{
			"postLogoutRedirectUris": []string{},
		}
		if len(app.RedirectURIs) > 0 {
			oidcMetadata["redirectUris"] = app.RedirectURIs
		}
		payload["oidcClientMetadata"] = oidcMetadata
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:      http.MethodPost,
		path:        "/api/applications",
		body:        payload,
		expectCodes: []int{http.StatusCreated, http.StatusOK},
	})
	if err != nil {
		return nil, err
	}

	return parseApplicationResponse(body)
}

// ========== Global Roles (Tenant-level) ==========

// GetRole retrieves a role by ID
func (a *Adapter) GetRole(ctx context.Context, roleID string) (*models.Role, error) {
	if roleID == "" {
		return nil, &ValidationError{Field: "roleID", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodGet,
		path:       "/api/roles/%s",
		pathParams: []string{roleID},
	})
	if err != nil {
		return nil, err
	}

	return parseRoleResponse(body)
}

// ListRoles lists all global roles
func (a *Adapter) ListRoles(ctx context.Context) ([]models.Role, error) {
	body, _, err := a.doRequest(ctx, requestConfig{
		method: http.MethodGet,
		path:   "/api/roles",
	})
	if err != nil {
		return nil, err
	}

	var rolesData []json.RawMessage
	if err := json.Unmarshal(body, &rolesData); err != nil {
		return nil, fmt.Errorf("unmarshal roles list: %w", err)
	}

	roles := make([]models.Role, 0, len(rolesData))
	for _, roleData := range rolesData {
		role, err := parseRoleResponse(roleData)
		if err != nil {
			return nil, err
		}
		roles = append(roles, *role)
	}

	return roles, nil
}

// CreateRole creates a new global role
func (a *Adapter) CreateRole(ctx context.Context, name, description string, roleType models.RoleType, scopeIDs []string) (*models.Role, error) {
	if name == "" {
		return nil, &ValidationError{Field: "name", Message: "cannot be empty"}
	}

	payload := map[string]interface{}{
		"name":        name,
		"description": description,
	}
	if roleType != "" {
		payload["type"] = roleType
	}
	if len(scopeIDs) > 0 {
		payload["scopeIds"] = scopeIDs
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:      http.MethodPost,
		path:        "/api/roles",
		body:        payload,
		expectCodes: []int{http.StatusOK, http.StatusCreated},
	})
	if err != nil {
		return nil, err
	}

	return parseRoleResponse(body)
}

// UpdateRole updates a global role
func (a *Adapter) UpdateRole(ctx context.Context, roleID, name, description string, isDefault *bool) (*models.Role, error) {
	if roleID == "" {
		return nil, &ValidationError{Field: "roleID", Message: "cannot be empty"}
	}

	payload := make(map[string]interface{})
	if name != "" {
		payload["name"] = name
	}
	if description != "" {
		payload["description"] = description
	}
	if isDefault != nil {
		payload["isDefault"] = *isDefault
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodPatch,
		path:       "/api/roles/%s",
		pathParams: []string{roleID},
		body:       payload,
	})
	if err != nil {
		return nil, err
	}

	return parseRoleResponse(body)
}

// DeleteRole deletes a global role
func (a *Adapter) DeleteRole(ctx context.Context, roleID string) error {
	if roleID == "" {
		return &ValidationError{Field: "roleID", Message: "cannot be empty"}
	}

	_, _, err := a.doRequest(ctx, requestConfig{
		method:      http.MethodDelete,
		path:        "/api/roles/%s",
		pathParams:  []string{roleID},
		expectCodes: []int{http.StatusOK, http.StatusNoContent},
	})
	return err
}

// ListRoleScopes lists API resource scopes assigned to a role
func (a *Adapter) ListRoleScopes(ctx context.Context, roleID string) ([]models.APIResourceScope, error) {
	if roleID == "" {
		return nil, &ValidationError{Field: "roleID", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodGet,
		path:       "/api/roles/%s/scopes",
		pathParams: []string{roleID},
	})
	if err != nil {
		return nil, err
	}

	var scopesData []json.RawMessage
	if err := json.Unmarshal(body, &scopesData); err != nil {
		return nil, fmt.Errorf("unmarshal role scopes response: %w", err)
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

// AssignRoleScopes assigns API resource scopes to a role
func (a *Adapter) AssignRoleScopes(ctx context.Context, roleID string, scopeIDs []string) error {
	if roleID == "" {
		return &ValidationError{Field: "roleID", Message: "cannot be empty"}
	}
	if len(scopeIDs) == 0 {
		return &ValidationError{Field: "scopeIDs", Message: "cannot be empty"}
	}

	_, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodPost,
		path:       "/api/roles/%s/scopes",
		pathParams: []string{roleID},
		body: map[string]interface{}{
			"scopeIds": scopeIDs,
		},
		expectCodes: []int{http.StatusOK, http.StatusCreated},
	})
	return err
}

// RemoveRoleScope removes an API resource scope from a role
func (a *Adapter) RemoveRoleScope(ctx context.Context, roleID, scopeID string) error {
	if roleID == "" {
		return &ValidationError{Field: "roleID", Message: "cannot be empty"}
	}
	if scopeID == "" {
		return &ValidationError{Field: "scopeID", Message: "cannot be empty"}
	}

	_, _, err := a.doRequest(ctx, requestConfig{
		method:      http.MethodDelete,
		path:        "/api/roles/%s/scopes/%s",
		pathParams:  []string{roleID, scopeID},
		expectCodes: []int{http.StatusOK, http.StatusNoContent},
	})
	return err
}

// ListRoleUsers lists users assigned to a role
func (a *Adapter) ListRoleUsers(ctx context.Context, roleID string) ([]models.User, error) {
	if roleID == "" {
		return nil, &ValidationError{Field: "roleID", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodGet,
		path:       "/api/roles/%s/users",
		pathParams: []string{roleID},
	})
	if err != nil {
		return nil, err
	}

	var usersData []json.RawMessage
	if err := json.Unmarshal(body, &usersData); err != nil {
		return nil, fmt.Errorf("unmarshal role users: %w", err)
	}

	users := make([]models.User, 0, len(usersData))
	for _, userData := range usersData {
		user, err := parseUserResponse(userData)
		if err != nil {
			return nil, err
		}
		users = append(users, *user)
	}

	return users, nil
}

// AssignRoleToUsers assigns a role to users
func (a *Adapter) AssignRoleToUsers(ctx context.Context, roleID string, userIDs []string) error {
	if roleID == "" {
		return &ValidationError{Field: "roleID", Message: "cannot be empty"}
	}
	if len(userIDs) == 0 {
		return &ValidationError{Field: "userIDs", Message: "cannot be empty"}
	}

	_, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodPost,
		path:       "/api/roles/%s/users",
		pathParams: []string{roleID},
		body: map[string]interface{}{
			"userIds": userIDs,
		},
		expectCodes: []int{http.StatusOK, http.StatusCreated},
	})
	return err
}

// RemoveRoleFromUser removes a role from a user
func (a *Adapter) RemoveRoleFromUser(ctx context.Context, roleID, userID string) error {
	if roleID == "" {
		return &ValidationError{Field: "roleID", Message: "cannot be empty"}
	}
	if userID == "" {
		return &ValidationError{Field: "userID", Message: "cannot be empty"}
	}

	_, _, err := a.doRequest(ctx, requestConfig{
		method:      http.MethodDelete,
		path:        "/api/roles/%s/users/%s",
		pathParams:  []string{roleID, userID},
		expectCodes: []int{http.StatusOK, http.StatusNoContent},
	})
	return err
}

// ListRoleApplications lists M2M applications assigned to a role
func (a *Adapter) ListRoleApplications(ctx context.Context, roleID string) ([]models.Application, error) {
	if roleID == "" {
		return nil, &ValidationError{Field: "roleID", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodGet,
		path:       "/api/roles/%s/applications",
		pathParams: []string{roleID},
	})
	if err != nil {
		return nil, err
	}

	var appsData []json.RawMessage
	if err := json.Unmarshal(body, &appsData); err != nil {
		return nil, fmt.Errorf("unmarshal role applications: %w", err)
	}

	apps := make([]models.Application, 0, len(appsData))
	for _, appData := range appsData {
		app, err := parseApplicationResponse(appData)
		if err != nil {
			return nil, err
		}
		apps = append(apps, *app)
	}

	return apps, nil
}

// AssignRoleToApplications assigns a role to M2M applications
func (a *Adapter) AssignRoleToApplications(ctx context.Context, roleID string, applicationIDs []string) error {
	if roleID == "" {
		return &ValidationError{Field: "roleID", Message: "cannot be empty"}
	}
	if len(applicationIDs) == 0 {
		return &ValidationError{Field: "applicationIDs", Message: "cannot be empty"}
	}

	_, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodPost,
		path:       "/api/roles/%s/applications",
		pathParams: []string{roleID},
		body: map[string]interface{}{
			"applicationIds": applicationIDs,
		},
		expectCodes: []int{http.StatusOK, http.StatusCreated},
	})
	return err
}

// RemoveRoleFromApplication removes a role from an M2M application
func (a *Adapter) RemoveRoleFromApplication(ctx context.Context, roleID, applicationID string) error {
	if roleID == "" {
		return &ValidationError{Field: "roleID", Message: "cannot be empty"}
	}
	if applicationID == "" {
		return &ValidationError{Field: "applicationID", Message: "cannot be empty"}
	}

	_, _, err := a.doRequest(ctx, requestConfig{
		method:      http.MethodDelete,
		path:        "/api/roles/%s/applications/%s",
		pathParams:  []string{roleID, applicationID},
		expectCodes: []int{http.StatusOK, http.StatusNoContent},
	})
	return err
}

// parseRoleResponse parses a global role from API response
func parseRoleResponse(data []byte) (*models.Role, error) {
	var role models.Role
	if err := json.Unmarshal(data, &role); err != nil {
		return nil, fmt.Errorf("parse role: %w", err)
	}
	return &role, nil
}

// CreateOrganizationInvitation creates an invitation for a user to join an organization
func (a *Adapter) CreateOrganizationInvitation(ctx context.Context, orgID, inviterID, email string, roleIDs []string, expiresAtMs int64) (*models.OrganizationInvitation, error) {
	if orgID == "" {
		return nil, &ValidationError{Field: "orgID", Message: "cannot be empty"}
	}
	if email == "" {
		return nil, &ValidationError{Field: "email", Message: "cannot be empty"}
	}

	payload := map[string]interface{}{
		"organizationId": orgID,
		"invitee":        email,
		"expiresAt":      float64(expiresAtMs),
		"messagePayload": false, // We'll send our own emails
	}

	if inviterID != "" {
		payload["inviterId"] = inviterID
	}

	if len(roleIDs) > 0 {
		payload["organizationRoleIds"] = roleIDs
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:      http.MethodPost,
		path:        "/api/organization-invitations",
		body:        payload,
		expectCodes: []int{http.StatusCreated, http.StatusOK},
	})
	if err != nil {
		return nil, err
	}

	return parseInvitationResponse(body)
}

// ListOrganizationInvitations lists invitations for an organization.
// Returns invitations and any error. If some items failed to parse, returns partial results
// with a combined error containing all parse failures.
func (a *Adapter) ListOrganizationInvitations(ctx context.Context, orgID string) ([]models.OrganizationInvitation, error) {
	if orgID == "" {
		return nil, &ValidationError{Field: "orgID", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method: http.MethodGet,
		path:   "/api/organization-invitations",
		query:  url.Values{"organizationId": {orgID}},
	})
	if err != nil {
		return nil, err
	}

	var invitationsData []json.RawMessage
	if err := json.Unmarshal(body, &invitationsData); err != nil {
		return nil, fmt.Errorf("unmarshal invitations response: %w", err)
	}

	invitations := make([]models.OrganizationInvitation, 0, len(invitationsData))
	var parseErrs []error
	for _, data := range invitationsData {
		inv, err := parseInvitationResponse(data)
		if err != nil {
			parseErrs = append(parseErrs, err)
			continue
		}
		invitations = append(invitations, *inv)
	}

	if len(parseErrs) > 0 {
		return invitations, fmt.Errorf("failed to parse %d invitation(s): %w", len(parseErrs), errors.Join(parseErrs...))
	}
	return invitations, nil
}

// GetOrganizationInvitation retrieves a single invitation by ID
func (a *Adapter) GetOrganizationInvitation(ctx context.Context, invitationID string) (*models.OrganizationInvitation, error) {
	if invitationID == "" {
		return nil, &ValidationError{Field: "invitationID", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodGet,
		path:       "/api/organization-invitations/%s",
		pathParams: []string{invitationID},
	})
	if err != nil {
		return nil, err
	}

	return parseInvitationResponse(body)
}

// DeleteOrganizationInvitation deletes an invitation
func (a *Adapter) DeleteOrganizationInvitation(ctx context.Context, invitationID string) error {
	if invitationID == "" {
		return &ValidationError{Field: "invitationID", Message: "cannot be empty"}
	}

	return a.doNoContent(ctx, requestConfig{
		method:      http.MethodDelete,
		path:        "/api/organization-invitations/%s",
		pathParams:  []string{invitationID},
		expectCodes: []int{http.StatusNoContent, http.StatusOK},
	})
}

// SendInvitationMessage sends the invitation email with a magic link
func (a *Adapter) SendInvitationMessage(ctx context.Context, invitationID, magicLink string) error {
	if invitationID == "" {
		return &ValidationError{Field: "invitationID", Message: "cannot be empty"}
	}

	return a.doNoContent(ctx, requestConfig{
		method:     http.MethodPost,
		path:       "/api/organization-invitations/%s/message",
		pathParams: []string{invitationID},
		body: map[string]interface{}{
			"link": magicLink,
		},
		expectCodes: []int{http.StatusNoContent, http.StatusOK},
	})
}

// CreateOneTimeToken creates a one-time token for magic link authentication
func (a *Adapter) CreateOneTimeToken(ctx context.Context, email string, expiresIn int, jitOrgIDs []string) (*models.OneTimeTokenResult, error) {
	if email == "" {
		return nil, &ValidationError{Field: "email", Message: "cannot be empty"}
	}

	payload := map[string]interface{}{
		"email":     email,
		"expiresIn": expiresIn,
	}

	if len(jitOrgIDs) > 0 {
		payload["context"] = map[string]interface{}{
			"jitOrganizationIds": jitOrgIDs,
		}
	}

	var result struct {
		Token     string `json:"token"`
		ExpiresAt int64  `json:"expiresAt"`
	}
	err := a.doJSON(ctx, requestConfig{
		method:      http.MethodPost,
		path:        "/api/one-time-tokens",
		body:        payload,
		expectCodes: []int{http.StatusCreated, http.StatusOK},
	}, &result)
	if err != nil {
		return nil, err
	}

	return &models.OneTimeTokenResult{
		Token:     result.Token,
		ExpiresAt: result.ExpiresAt,
	}, nil
}

// Helper functions

func parseInvitationResponse(data []byte) (*models.OrganizationInvitation, error) {
	var raw struct {
		ID                string `json:"id"`
		TenantID          string `json:"tenantId"`
		InviterID         string `json:"inviterId"`
		Invitee           string `json:"invitee"`
		AcceptedUserID    string `json:"acceptedUserId"`
		OrganizationID    string `json:"organizationId"`
		Status            string `json:"status"`
		CreatedAt         int64  `json:"createdAt"`
		UpdatedAt         int64  `json:"updatedAt"`
		ExpiresAt         int64  `json:"expiresAt"`
		OrganizationRoles []struct {
			ID          string `json:"id"`
			TenantID    string `json:"tenantId"`
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"organizationRoles"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse invitation: %w", err)
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

	return &models.OrganizationInvitation{
		ID:             raw.ID,
		TenantID:       raw.TenantID,
		OrganizationID: raw.OrganizationID,
		Invitee:        raw.Invitee,
		Status:         raw.Status,
		InviterID:      raw.InviterID,
		AcceptedUserID: raw.AcceptedUserID,
		Roles:          roles,
		ExpiresAt:      time.UnixMilli(raw.ExpiresAt),
		CreatedAt:      time.UnixMilli(raw.CreatedAt),
		UpdatedAt:      time.UnixMilli(raw.UpdatedAt),
	}, nil
}

func parseApplicationResponse(data []byte) (*models.Application, error) {
	var raw struct {
		ID                   string                       `json:"id"`
		TenantID             string                       `json:"tenantId"`
		Name                 string                       `json:"name"`
		Description          string                       `json:"description"`
		Type                 string                       `json:"type"`
		Secret               string                       `json:"secret"`
		OIDCClientMetadata   *models.OIDCClientMetadata   `json:"oidcClientMetadata"`
		CustomClientMetadata *models.CustomClientMetadata `json:"customClientMetadata"`
		ProtectedAppMetadata *models.ProtectedAppMetadata `json:"protectedAppMetadata"`
		CustomData           map[string]interface{}       `json:"customData"`
		IsThirdParty         bool                         `json:"isThirdParty"`
		IsAdmin              bool                         `json:"isAdmin"`
		CreatedAt            int64                        `json:"createdAt"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse application: %w", err)
	}

	customData := raw.CustomData
	if customData == nil {
		customData = make(map[string]interface{})
	}

	return &models.Application{
		ID:                   raw.ID,
		TenantID:             raw.TenantID,
		Name:                 raw.Name,
		Description:          raw.Description,
		Type:                 models.ApplicationType(raw.Type),
		Secret:               raw.Secret,
		OIDCClientMetadata:   raw.OIDCClientMetadata,
		CustomClientMetadata: raw.CustomClientMetadata,
		ProtectedAppMetadata: raw.ProtectedAppMetadata,
		CustomData:           customData,
		IsThirdParty:         raw.IsThirdParty,
		IsAdmin:              raw.IsAdmin,
		CreatedAt:            time.UnixMilli(raw.CreatedAt),
	}, nil
}

// Iterator factory methods

// ListUsersIter returns an iterator for paginating through users.
func (a *Adapter) ListUsersIter(ctx context.Context, pageSize int) *UserIterator {
	return &UserIterator{
		adapter:  a,
		ctx:      ctx,
		pageSize: pageSize,
		page:     0,
		index:    -1,
	}
}

// ListOrganizationsIter returns an iterator for paginating through organizations.
func (a *Adapter) ListOrganizationsIter(ctx context.Context, pageSize int) *OrganizationIterator {
	return &OrganizationIterator{
		adapter:  a,
		ctx:      ctx,
		pageSize: pageSize,
		page:     0,
		index:    -1,
	}
}
