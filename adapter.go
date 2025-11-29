package logto

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
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
		return "", 0, err
	}

	// Cache token (already holding write lock from defer above)
	a.cachedToken = &m2mTokenCache{
		accessToken: tokenResp.AccessToken,
		expiresAt:   time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
	}

	return tokenResp.AccessToken, tokenResp.ExpiresIn, nil
}

// GetUser retrieves user information from Logto
func (a *Adapter) GetUser(ctx context.Context, userID string) (*User, error) {
	if userID == "" {
		return nil, &ValidationError{Field: "userID", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodGet,
		path:       "/api/users/%s",
		pathParams: []string{userID},
	})
	if err != nil {
		return nil, err
	}

	return parseUserResponse(body)
}

// GetUserByEmail retrieves user information by email
func (a *Adapter) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	if email == "" {
		return nil, &ValidationError{Field: "email", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method: http.MethodGet,
		path:   "/api/users",
		query:  url.Values{"search": {email}},
	})
	if err != nil {
		return nil, err
	}

	var users []json.RawMessage
	if err := json.Unmarshal(body, &users); err != nil {
		return nil, err
	}

	// Find user with exact email match
	for _, userData := range users {
		user, err := parseUserResponse(userData)
		if err != nil {
			continue
		}
		if user.Email == email {
			return user, nil
		}
	}

	return nil, &APIError{StatusCode: 404, Message: fmt.Sprintf("user not found with email: %s", email)}
}

// ListUsers retrieves all users
func (a *Adapter) ListUsers(ctx context.Context) ([]*User, error) {
	body, _, err := a.doRequest(ctx, requestConfig{
		method: http.MethodGet,
		path:   "/api/users",
	})
	if err != nil {
		return nil, err
	}

	var usersData []json.RawMessage
	if err := json.Unmarshal(body, &usersData); err != nil {
		return nil, err
	}

	users := make([]*User, 0, len(usersData))
	for _, userData := range usersData {
		user, err := parseUserResponse(userData)
		if err != nil {
			continue
		}
		users = append(users, user)
	}

	return users, nil
}

// GetOrganization retrieves organization details
func (a *Adapter) GetOrganization(ctx context.Context, orgID string) (*Organization, error) {
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

// ListOrganizations retrieves all organizations
func (a *Adapter) ListOrganizations(ctx context.Context) ([]*Organization, error) {
	body, _, err := a.doRequest(ctx, requestConfig{
		method: http.MethodGet,
		path:   "/api/organizations",
	})
	if err != nil {
		return nil, err
	}

	var orgsData []json.RawMessage
	if err := json.Unmarshal(body, &orgsData); err != nil {
		return nil, err
	}

	orgs := make([]*Organization, 0, len(orgsData))
	for _, orgData := range orgsData {
		org, err := parseOrganizationResponse(orgData)
		if err != nil {
			continue
		}
		orgs = append(orgs, org)
	}

	return orgs, nil
}

// ListUserOrganizations retrieves organizations where the user is a member
func (a *Adapter) ListUserOrganizations(ctx context.Context, userID string) ([]*Organization, error) {
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
		return nil, err
	}

	orgs := make([]*Organization, 0, len(orgsData))
	for _, orgData := range orgsData {
		org, err := parseOrganizationResponse(orgData)
		if err != nil {
			continue
		}
		orgs = append(orgs, org)
	}

	return orgs, nil
}

// CreateOrganization creates a new organization in Logto
func (a *Adapter) CreateOrganization(ctx context.Context, name, description string) (string, error) {
	if name == "" {
		return "", &ValidationError{Field: "name", Message: "cannot be empty"}
	}

	var result struct {
		ID string `json:"id"`
	}

	err := a.doJSON(ctx, requestConfig{
		method:      http.MethodPost,
		path:        "/api/organizations",
		body:        map[string]string{"name": name, "description": description},
		expectCodes: []int{http.StatusCreated, http.StatusOK},
	}, &result)
	if err != nil {
		return "", err
	}

	return result.ID, nil
}

// UpdateOrganization updates organization details
func (a *Adapter) UpdateOrganization(ctx context.Context, orgID string, name, description string, customData map[string]interface{}) error {
	if orgID == "" {
		return &ValidationError{Field: "orgID", Message: "cannot be empty"}
	}

	payload := make(map[string]interface{})
	if name != "" {
		payload["name"] = name
	}
	if description != "" {
		payload["description"] = description
	}
	if customData != nil {
		payload["customData"] = customData
	}

	return a.doNoContent(ctx, requestConfig{
		method:      http.MethodPatch,
		path:        "/api/organizations/%s",
		pathParams:  []string{orgID},
		body:        payload,
		expectCodes: []int{http.StatusOK},
	})
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
		expectCodes: []int{http.StatusNoContent, http.StatusOK},
	})
}

// ListOrganizationMembers lists all members of an organization with their roles
func (a *Adapter) ListOrganizationMembers(ctx context.Context, orgID string) ([]*OrganizationMember, error) {
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
		return nil, err
	}

	members := make([]*OrganizationMember, 0, len(membersData))
	for _, memberData := range membersData {
		user, err := parseUserResponse(memberData)
		if err != nil {
			continue
		}

		// Get roles for this user
		roles, err := a.GetUserRolesInOrganization(ctx, orgID, user.ID)
		if err != nil && a.opts.logger != nil {
			a.opts.logger.WarnContext(ctx, "Failed to get user roles in organization",
				slog.String("orgID", orgID),
				slog.String("userID", user.ID),
				slog.Any("error", err))
		}

		members = append(members, &OrganizationMember{
			User:  user,
			Roles: roles,
		})
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
		expectCodes: []int{http.StatusCreated, http.StatusOK, http.StatusNoContent},
	})
	if err != nil {
		return err
	}

	// Assign roles if provided
	if len(roleIDs) > 0 {
		return a.UpdateUserRoles(ctx, orgID, userID, roleIDs)
	}

	return nil
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
		expectCodes: []int{http.StatusNoContent, http.StatusOK},
	})
}

// UpdateUserRoles updates a user's roles in an organization
func (a *Adapter) UpdateUserRoles(ctx context.Context, orgID, userID string, roleIDs []string) error {
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
		body:        map[string][]string{"organizationRoleIds": roleIDs},
		expectCodes: []int{http.StatusOK, http.StatusNoContent},
	})
}

// GetUserRolesInOrganization gets a user's roles in an organization
func (a *Adapter) GetUserRolesInOrganization(ctx context.Context, orgID, userID string) ([]OrganizationRole, error) {
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

	var rolesResp []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}

	if err := json.Unmarshal(body, &rolesResp); err != nil {
		return nil, err
	}

	roles := make([]OrganizationRole, len(rolesResp))
	for i, r := range rolesResp {
		roles[i] = OrganizationRole{
			ID:   r.ID,
			Name: r.Name,
		}
	}

	return roles, nil
}

// ListOrganizationRoles lists all organization roles
func (a *Adapter) ListOrganizationRoles(ctx context.Context) ([]OrganizationRole, error) {
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
	}

	if err := json.Unmarshal(body, &rolesResp); err != nil {
		return nil, err
	}

	roles := make([]OrganizationRole, len(rolesResp))
	for i, r := range rolesResp {
		roles[i] = OrganizationRole{
			ID:          r.ID,
			Name:        r.Name,
			Description: r.Description,
		}
	}

	return roles, nil
}

// GetOrganizationRole retrieves a single organization role by ID
func (a *Adapter) GetOrganizationRole(ctx context.Context, roleID string) (*OrganizationRole, error) {
	if roleID == "" {
		return nil, &ValidationError{Field: "roleID", Message: "cannot be empty"}
	}

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
		Scopes      []struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"scopes"`
	}

	if err := json.Unmarshal(body, &roleResp); err != nil {
		return nil, err
	}

	scopes := make([]OrganizationScope, len(roleResp.Scopes))
	for i, s := range roleResp.Scopes {
		scopes[i] = OrganizationScope{
			ID:          s.ID,
			Name:        s.Name,
			Description: s.Description,
		}
	}

	return &OrganizationRole{
		ID:          roleResp.ID,
		Name:        roleResp.Name,
		Description: roleResp.Description,
		Scopes:      scopes,
	}, nil
}

// CreateOrganizationRole creates a new organization role
func (a *Adapter) CreateOrganizationRole(ctx context.Context, name, description string, scopeIDs []string) (string, error) {
	if name == "" {
		return "", &ValidationError{Field: "name", Message: "cannot be empty"}
	}

	payload := map[string]interface{}{
		"name":        name,
		"description": description,
	}
	if len(scopeIDs) > 0 {
		payload["organizationScopeIds"] = scopeIDs
	}

	var result struct {
		ID string `json:"id"`
	}

	err := a.doJSON(ctx, requestConfig{
		method:      http.MethodPost,
		path:        "/api/organization-roles",
		body:        payload,
		expectCodes: []int{http.StatusCreated, http.StatusOK},
	}, &result)
	if err != nil {
		return "", err
	}

	return result.ID, nil
}

// UpdateOrganizationRole updates an organization role
func (a *Adapter) UpdateOrganizationRole(ctx context.Context, roleID, name, description string) error {
	if roleID == "" {
		return &ValidationError{Field: "roleID", Message: "cannot be empty"}
	}

	payload := make(map[string]interface{})
	if name != "" {
		payload["name"] = name
	}
	if description != "" {
		payload["description"] = description
	}

	return a.doNoContent(ctx, requestConfig{
		method:      http.MethodPatch,
		path:        "/api/organization-roles/%s",
		pathParams:  []string{roleID},
		body:        payload,
		expectCodes: []int{http.StatusOK},
	})
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

// GetOrganizationRoleScopes retrieves scopes assigned to an organization role
func (a *Adapter) GetOrganizationRoleScopes(ctx context.Context, roleID string) ([]OrganizationScope, error) {
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
		return nil, err
	}

	scopes := make([]OrganizationScope, len(scopesResp))
	for i, s := range scopesResp {
		scopes[i] = OrganizationScope{
			ID:          s.ID,
			Name:        s.Name,
			Description: s.Description,
		}
	}

	return scopes, nil
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

// GetOrganizationScope retrieves a single organization scope by ID
func (a *Adapter) GetOrganizationScope(ctx context.Context, scopeID string) (*OrganizationScope, error) {
	if scopeID == "" {
		return nil, &ValidationError{Field: "scopeID", Message: "cannot be empty"}
	}

	var result OrganizationScope
	err := a.doJSON(ctx, requestConfig{
		method:     http.MethodGet,
		path:       "/api/organization-scopes/%s",
		pathParams: []string{scopeID},
	}, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// ListOrganizationScopes lists all organization scopes
func (a *Adapter) ListOrganizationScopes(ctx context.Context) ([]OrganizationScope, error) {
	var result []OrganizationScope
	err := a.doJSON(ctx, requestConfig{
		method: http.MethodGet,
		path:   "/api/organization-scopes",
	}, &result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// CreateOrganizationScope creates a new organization scope
func (a *Adapter) CreateOrganizationScope(ctx context.Context, name, description string) (string, error) {
	if name == "" {
		return "", &ValidationError{Field: "name", Message: "cannot be empty"}
	}

	var result struct {
		ID string `json:"id"`
	}
	err := a.doJSON(ctx, requestConfig{
		method: http.MethodPost,
		path:   "/api/organization-scopes",
		body: map[string]interface{}{
			"name":        name,
			"description": description,
		},
		expectCodes: []int{http.StatusCreated, http.StatusOK},
	}, &result)
	if err != nil {
		return "", err
	}

	return result.ID, nil
}

// UpdateOrganizationScope updates an organization scope
func (a *Adapter) UpdateOrganizationScope(ctx context.Context, scopeID, name, description string) error {
	if scopeID == "" {
		return &ValidationError{Field: "scopeID", Message: "cannot be empty"}
	}

	payload := make(map[string]interface{})
	if name != "" {
		payload["name"] = name
	}
	if description != "" {
		payload["description"] = description
	}

	return a.doNoContent(ctx, requestConfig{
		method:     http.MethodPatch,
		path:       "/api/organization-scopes/%s",
		pathParams: []string{scopeID},
		body:       payload,
	})
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

// GetAPIResource retrieves a single API resource by ID
func (a *Adapter) GetAPIResource(ctx context.Context, resourceID string) (*APIResource, error) {
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

// ListAPIResources lists all API resources
func (a *Adapter) ListAPIResources(ctx context.Context) ([]*APIResource, error) {
	body, _, err := a.doRequest(ctx, requestConfig{
		method: http.MethodGet,
		path:   "/api/resources",
	})
	if err != nil {
		return nil, err
	}

	var resourcesData []json.RawMessage
	if err := json.Unmarshal(body, &resourcesData); err != nil {
		return nil, err
	}

	resources := make([]*APIResource, 0, len(resourcesData))
	for _, data := range resourcesData {
		resource, err := parseAPIResourceResponse(data)
		if err != nil {
			continue
		}
		resources = append(resources, resource)
	}

	return resources, nil
}

// CreateAPIResource creates a new API resource
func (a *Adapter) CreateAPIResource(ctx context.Context, name, indicator string) (string, error) {
	if name == "" {
		return "", &ValidationError{Field: "name", Message: "cannot be empty"}
	}
	if indicator == "" {
		return "", &ValidationError{Field: "indicator", Message: "cannot be empty"}
	}

	var result struct {
		ID string `json:"id"`
	}
	err := a.doJSON(ctx, requestConfig{
		method: http.MethodPost,
		path:   "/api/resources",
		body: map[string]interface{}{
			"name":      name,
			"indicator": indicator,
		},
		expectCodes: []int{http.StatusCreated, http.StatusOK},
	}, &result)
	if err != nil {
		return "", err
	}

	return result.ID, nil
}

// UpdateAPIResource updates an API resource
func (a *Adapter) UpdateAPIResource(ctx context.Context, resourceID, name string, accessTokenTTL *int) error {
	if resourceID == "" {
		return &ValidationError{Field: "resourceID", Message: "cannot be empty"}
	}

	payload := make(map[string]interface{})
	if name != "" {
		payload["name"] = name
	}
	if accessTokenTTL != nil {
		payload["accessTokenTtl"] = *accessTokenTTL
	}

	return a.doNoContent(ctx, requestConfig{
		method:     http.MethodPatch,
		path:       "/api/resources/%s",
		pathParams: []string{resourceID},
		body:       payload,
	})
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
func (a *Adapter) GetAPIResourceScope(ctx context.Context, resourceID, scopeID string) (*APIResourceScope, error) {
	// Logto API doesn't have a direct GET endpoint for individual scopes,
	// so we list all scopes and find the one we need
	scopes, err := a.ListAPIResourceScopes(ctx, resourceID)
	if err != nil {
		return nil, err
	}

	for _, scope := range scopes {
		if scope.ID == scopeID {
			return scope, nil
		}
	}

	return nil, &APIError{StatusCode: 404, Message: fmt.Sprintf("API resource scope not found: %s", scopeID)}
}

// ListAPIResourceScopes lists all scopes for an API resource
func (a *Adapter) ListAPIResourceScopes(ctx context.Context, resourceID string) ([]*APIResourceScope, error) {
	if resourceID == "" {
		return nil, &ValidationError{Field: "resourceID", Message: "cannot be empty"}
	}

	var result []*APIResourceScope
	err := a.doJSON(ctx, requestConfig{
		method:     http.MethodGet,
		path:       "/api/resources/%s/scopes",
		pathParams: []string{resourceID},
	}, &result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// CreateAPIResourceScope creates a new scope for an API resource
func (a *Adapter) CreateAPIResourceScope(ctx context.Context, resourceID, name, description string) (string, error) {
	if resourceID == "" {
		return "", &ValidationError{Field: "resourceID", Message: "cannot be empty"}
	}
	if name == "" {
		return "", &ValidationError{Field: "name", Message: "cannot be empty"}
	}

	var result struct {
		ID string `json:"id"`
	}
	err := a.doJSON(ctx, requestConfig{
		method:     http.MethodPost,
		path:       "/api/resources/%s/scopes",
		pathParams: []string{resourceID},
		body: map[string]interface{}{
			"name":        name,
			"description": description,
		},
		expectCodes: []int{http.StatusCreated, http.StatusOK},
	}, &result)
	if err != nil {
		return "", err
	}

	return result.ID, nil
}

// UpdateAPIResourceScope updates a scope for an API resource
func (a *Adapter) UpdateAPIResourceScope(ctx context.Context, resourceID, scopeID, name, description string) error {
	if resourceID == "" {
		return &ValidationError{Field: "resourceID", Message: "cannot be empty"}
	}
	if scopeID == "" {
		return &ValidationError{Field: "scopeID", Message: "cannot be empty"}
	}

	payload := make(map[string]interface{})
	if name != "" {
		payload["name"] = name
	}
	if description != "" {
		payload["description"] = description
	}

	return a.doNoContent(ctx, requestConfig{
		method:     http.MethodPatch,
		path:       "/api/resources/%s/scopes/%s",
		pathParams: []string{resourceID, scopeID},
		body:       payload,
	})
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

// Helper function to parse API resource response
func parseAPIResourceResponse(data []byte) (*APIResource, error) {
	var resourceResp struct {
		ID             string `json:"id"`
		Name           string `json:"name"`
		Indicator      string `json:"indicator"`
		AccessTokenTTL int    `json:"accessTokenTtl"`
		IsDefault      bool   `json:"isDefault"`
	}

	if err := json.Unmarshal(data, &resourceResp); err != nil {
		return nil, err
	}

	return &APIResource{
		ID:             resourceResp.ID,
		Name:           resourceResp.Name,
		Indicator:      resourceResp.Indicator,
		AccessTokenTTL: resourceResp.AccessTokenTTL,
		IsDefault:      resourceResp.IsDefault,
	}, nil
}

// CreateOrganizationInvitation creates an invitation for a user to join an organization
func (a *Adapter) CreateOrganizationInvitation(ctx context.Context, orgID, inviterID, email string, roleIDs []string, expiresAtMs int64) (string, error) {
	if orgID == "" {
		return "", &ValidationError{Field: "orgID", Message: "cannot be empty"}
	}
	if email == "" {
		return "", &ValidationError{Field: "email", Message: "cannot be empty"}
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

	var result struct {
		ID string `json:"id"`
	}
	err := a.doJSON(ctx, requestConfig{
		method:      http.MethodPost,
		path:        "/api/organization-invitations",
		body:        payload,
		expectCodes: []int{http.StatusCreated, http.StatusOK},
	}, &result)
	if err != nil {
		return "", err
	}

	return result.ID, nil
}

// UpdateUser updates user profile fields
func (a *Adapter) UpdateUser(ctx context.Context, userID string, update UserUpdate) error {
	if userID == "" {
		return &ValidationError{Field: "userID", Message: "cannot be empty"}
	}

	payload := make(map[string]interface{})
	if update.Name != nil {
		payload["name"] = *update.Name
	}
	if update.Avatar != nil {
		payload["avatar"] = *update.Avatar
	}

	return a.doNoContent(ctx, requestConfig{
		method:     http.MethodPatch,
		path:       "/api/users/%s",
		pathParams: []string{userID},
		body:       payload,
	})
}

// UpdateUserCustomData performs a partial update of user's customData (merge mode)
func (a *Adapter) UpdateUserCustomData(ctx context.Context, userID string, customData map[string]interface{}) error {
	if userID == "" {
		return &ValidationError{Field: "userID", Message: "cannot be empty"}
	}

	return a.doNoContent(ctx, requestConfig{
		method:     http.MethodPatch,
		path:       "/api/users/%s/custom-data",
		pathParams: []string{userID},
		body: map[string]interface{}{
			"customData": customData,
		},
	})
}

// ListOrganizationInvitations lists invitations for an organization
func (a *Adapter) ListOrganizationInvitations(ctx context.Context, orgID string) ([]*OrganizationInvitation, error) {
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
		return nil, err
	}

	invitations := make([]*OrganizationInvitation, 0, len(invitationsData))
	for _, data := range invitationsData {
		inv, err := parseInvitationResponse(data)
		if err != nil {
			continue
		}
		invitations = append(invitations, inv)
	}

	return invitations, nil
}

// GetOrganizationInvitation retrieves a single invitation by ID
func (a *Adapter) GetOrganizationInvitation(ctx context.Context, invitationID string) (*OrganizationInvitation, error) {
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
func (a *Adapter) CreateOneTimeToken(ctx context.Context, email string, expiresIn int, jitOrgIDs []string) (*OneTimeTokenResult, error) {
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

	return &OneTimeTokenResult{
		Token:     result.Token,
		ExpiresAt: result.ExpiresAt,
	}, nil
}

// Helper functions

func parseUserResponse(data []byte) (*User, error) {
	var userResp struct {
		ID           string                 `json:"id"`
		Name         string                 `json:"name"`
		Username     string                 `json:"username"`
		PrimaryEmail string                 `json:"primaryEmail"`
		Avatar       string                 `json:"avatar"`
		IsSuspended  bool                   `json:"isSuspended"`
		CustomData   map[string]interface{} `json:"customData"`
		CreatedAt    int64                  `json:"createdAt"`
		UpdatedAt    int64                  `json:"updatedAt"`
	}

	if err := json.Unmarshal(data, &userResp); err != nil {
		return nil, err
	}

	email := userResp.PrimaryEmail
	if email == "" {
		email = userResp.Username // Fallback
	}

	customData := userResp.CustomData
	if customData == nil {
		customData = make(map[string]interface{})
	}

	return &User{
		ID:          userResp.ID,
		Name:        userResp.Name,
		Email:       email,
		Avatar:      userResp.Avatar,
		IsSuspended: userResp.IsSuspended,
		CustomData:  customData,
		CreatedAt:   time.UnixMilli(userResp.CreatedAt),
		UpdatedAt:   time.UnixMilli(userResp.UpdatedAt),
	}, nil
}

func parseOrganizationResponse(data []byte) (*Organization, error) {
	var orgResp struct {
		ID          string                 `json:"id"`
		Name        string                 `json:"name"`
		Description string                 `json:"description"`
		CustomData  map[string]interface{} `json:"customData"`
		CreatedAt   int64                  `json:"createdAt"`
	}

	if err := json.Unmarshal(data, &orgResp); err != nil {
		return nil, err
	}

	customData := orgResp.CustomData
	if customData == nil {
		customData = make(map[string]interface{})
	}

	return &Organization{
		ID:          orgResp.ID,
		Name:        orgResp.Name,
		Description: orgResp.Description,
		CustomData:  customData,
		CreatedAt:   time.UnixMilli(orgResp.CreatedAt),
	}, nil
}

func parseInvitationResponse(data []byte) (*OrganizationInvitation, error) {
	var invResp struct {
		ID                string `json:"id"`
		InviterID         string `json:"inviterId"`
		Invitee           string `json:"invitee"`
		AcceptedUserID    string `json:"acceptedUserId"`
		OrganizationID    string `json:"organizationId"`
		Status            string `json:"status"`
		CreatedAt         int64  `json:"createdAt"`
		UpdatedAt         int64  `json:"updatedAt"`
		ExpiresAt         int64  `json:"expiresAt"`
		OrganizationRoles []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"organizationRoles"`
	}

	if err := json.Unmarshal(data, &invResp); err != nil {
		return nil, err
	}

	roles := make([]OrganizationRole, len(invResp.OrganizationRoles))
	for i, r := range invResp.OrganizationRoles {
		roles[i] = OrganizationRole{
			ID:   r.ID,
			Name: r.Name,
		}
	}

	return &OrganizationInvitation{
		ID:             invResp.ID,
		OrganizationID: invResp.OrganizationID,
		Invitee:        invResp.Invitee,
		Status:         invResp.Status,
		InviterID:      invResp.InviterID,
		AcceptedUserID: invResp.AcceptedUserID,
		Roles:          roles,
		ExpiresAt:      time.UnixMilli(invResp.ExpiresAt),
		CreatedAt:      time.UnixMilli(invResp.CreatedAt),
		UpdatedAt:      time.UnixMilli(invResp.UpdatedAt),
	}, nil
}

// Paginated list methods for iterators

func (a *Adapter) listUsersPaginated(ctx context.Context, page, pageSize int) ([]*User, error) {
	body, _, err := a.doRequest(ctx, requestConfig{
		method: http.MethodGet,
		path:   "/api/users",
		query: url.Values{
			"page":      {fmt.Sprintf("%d", page)},
			"page_size": {fmt.Sprintf("%d", pageSize)},
		},
	})
	if err != nil {
		return nil, err
	}

	var usersData []json.RawMessage
	if err := json.Unmarshal(body, &usersData); err != nil {
		return nil, err
	}

	users := make([]*User, 0, len(usersData))
	for _, userData := range usersData {
		user, err := parseUserResponse(userData)
		if err != nil {
			continue
		}
		users = append(users, user)
	}

	return users, nil
}

func (a *Adapter) listOrganizationsPaginated(ctx context.Context, page, pageSize int) ([]*Organization, error) {
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
		return nil, err
	}

	orgs := make([]*Organization, 0, len(orgsData))
	for _, orgData := range orgsData {
		org, err := parseOrganizationResponse(orgData)
		if err != nil {
			continue
		}
		orgs = append(orgs, org)
	}

	return orgs, nil
}

func (a *Adapter) listInvitationsPaginated(ctx context.Context, orgID string, page, pageSize int) ([]*OrganizationInvitation, error) {
	body, _, err := a.doRequest(ctx, requestConfig{
		method: http.MethodGet,
		path:   "/api/organization-invitations",
		query: url.Values{
			"organizationId": {orgID},
			"page":           {fmt.Sprintf("%d", page)},
			"page_size":      {fmt.Sprintf("%d", pageSize)},
		},
	})
	if err != nil {
		return nil, err
	}

	var invitationsData []json.RawMessage
	if err := json.Unmarshal(body, &invitationsData); err != nil {
		return nil, err
	}

	invitations := make([]*OrganizationInvitation, 0, len(invitationsData))
	for _, data := range invitationsData {
		inv, err := parseInvitationResponse(data)
		if err != nil {
			continue
		}
		invitations = append(invitations, inv)
	}

	return invitations, nil
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

// ListInvitationsIter returns an iterator for paginating through invitations.
func (a *Adapter) ListInvitationsIter(ctx context.Context, orgID string, pageSize int) *InvitationIterator {
	return &InvitationIterator{
		adapter:  a,
		ctx:      ctx,
		orgID:    orgID,
		pageSize: pageSize,
		page:     0,
		index:    -1,
	}
}
