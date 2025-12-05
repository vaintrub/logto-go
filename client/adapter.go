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

	bodyBytes := []byte(data.Encode())
	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", 0, err
	}

	// Use Basic Auth with M2M credentials
	credentials := base64.StdEncoding.EncodeToString([]byte(a.m2mAppID + ":" + a.m2mAppSecret))
	req.Header.Set("Authorization", "Basic "+credentials)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Set GetBody for retry support
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(data.Encode())), nil
	}

	resp, err := a.doWithRetry(ctx, req, bodyBytes)
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

// GetUser retrieves user information from Logto
func (a *Adapter) GetUser(ctx context.Context, userID string) (*models.User, error) {
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
func (a *Adapter) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
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
		return nil, fmt.Errorf("unmarshal users search response: %w", err)
	}

	// Find user with exact email match
	for _, userData := range users {
		user, err := parseUserResponse(userData)
		if err != nil {
			continue
		}
		if user.PrimaryEmail == email {
			return user, nil
		}
	}

	return nil, &APIError{StatusCode: 404, Message: fmt.Sprintf("user not found with email: %s", email)}
}

// ListUsers retrieves all users.
// Returns users and any error. If some items failed to parse, returns partial results
// with a combined error containing all parse failures.
func (a *Adapter) ListUsers(ctx context.Context) ([]*models.User, error) {
	body, _, err := a.doRequest(ctx, requestConfig{
		method: http.MethodGet,
		path:   "/api/users",
	})
	if err != nil {
		return nil, err
	}

	var usersData []json.RawMessage
	if err := json.Unmarshal(body, &usersData); err != nil {
		return nil, fmt.Errorf("unmarshal users response: %w", err)
	}

	users := make([]*models.User, 0, len(usersData))
	var parseErrs []error
	for _, userData := range usersData {
		user, err := parseUserResponse(userData)
		if err != nil {
			parseErrs = append(parseErrs, err)
			continue
		}
		users = append(users, user)
	}

	if len(parseErrs) > 0 {
		return users, fmt.Errorf("failed to parse %d user(s): %w", len(parseErrs), errors.Join(parseErrs...))
	}
	return users, nil
}

// CreateUser creates a new user in Logto
func (a *Adapter) CreateUser(ctx context.Context, username, password, name, primaryEmail string) (*models.User, error) {
	if username == "" {
		return nil, &ValidationError{Field: "username", Message: "cannot be empty"}
	}
	if password == "" {
		return nil, &ValidationError{Field: "password", Message: "cannot be empty"}
	}

	payload := map[string]interface{}{
		"username": username,
		"password": password,
		"name":     name,
	}
	if primaryEmail != "" {
		payload["primaryEmail"] = primaryEmail
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:      http.MethodPost,
		path:        "/api/users",
		body:        payload,
		expectCodes: []int{http.StatusCreated, http.StatusOK},
	})
	if err != nil {
		return nil, err
	}

	return parseUserResponse(body)
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

// ListOrganizations retrieves all organizations.
// Returns organizations and any error. If some items failed to parse, returns partial results
// with a combined error containing all parse failures.
func (a *Adapter) ListOrganizations(ctx context.Context) ([]*models.Organization, error) {
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

	orgs := make([]*models.Organization, 0, len(orgsData))
	var parseErrs []error
	for _, orgData := range orgsData {
		org, err := parseOrganizationResponse(orgData)
		if err != nil {
			parseErrs = append(parseErrs, err)
			continue
		}
		orgs = append(orgs, org)
	}

	if len(parseErrs) > 0 {
		return orgs, fmt.Errorf("failed to parse %d organization(s): %w", len(parseErrs), errors.Join(parseErrs...))
	}
	return orgs, nil
}

// ListUserOrganizations retrieves organizations where the user is a member.
// Returns organizations and any error. If some items failed to parse, returns partial results
// with a combined error containing all parse failures.
func (a *Adapter) ListUserOrganizations(ctx context.Context, userID string) ([]*models.Organization, error) {
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

	orgs := make([]*models.Organization, 0, len(orgsData))
	var parseErrs []error
	for _, orgData := range orgsData {
		org, err := parseOrganizationResponse(orgData)
		if err != nil {
			parseErrs = append(parseErrs, err)
			continue
		}
		orgs = append(orgs, org)
	}

	if len(parseErrs) > 0 {
		return orgs, fmt.Errorf("failed to parse %d organization(s): %w", len(parseErrs), errors.Join(parseErrs...))
	}
	return orgs, nil
}

// CreateOrganization creates a new organization in Logto
func (a *Adapter) CreateOrganization(ctx context.Context, name, description string) (*models.Organization, error) {
	if name == "" {
		return nil, &ValidationError{Field: "name", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:      http.MethodPost,
		path:        "/api/organizations",
		body:        map[string]string{"name": name, "description": description},
		expectCodes: []int{http.StatusCreated, http.StatusOK},
	})
	if err != nil {
		return nil, err
	}

	return parseOrganizationResponse(body)
}

// UpdateOrganization updates organization details
func (a *Adapter) UpdateOrganization(ctx context.Context, orgID string, name, description string, customData map[string]interface{}) (*models.Organization, error) {
	if orgID == "" {
		return nil, &ValidationError{Field: "orgID", Message: "cannot be empty"}
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

	body, _, err := a.doRequest(ctx, requestConfig{
		method:      http.MethodPatch,
		path:        "/api/organizations/%s",
		pathParams:  []string{orgID},
		body:        payload,
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
		expectCodes: []int{http.StatusNoContent, http.StatusOK},
	})
}

// ListOrganizationMembers lists all members of an organization with their roles.
// Returns members and any error. If some items failed to parse, returns partial results
// with a combined error containing all parse failures.
func (a *Adapter) ListOrganizationMembers(ctx context.Context, orgID string) ([]*models.OrganizationMember, error) {
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

	members := make([]*models.OrganizationMember, 0, len(membersData))
	var parseErrs []error
	for _, memberData := range membersData {
		member, err := parseOrganizationMemberResponse(memberData)
		if err != nil {
			parseErrs = append(parseErrs, err)
			continue
		}
		members = append(members, member)
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
		expectCodes: []int{http.StatusCreated, http.StatusOK, http.StatusNoContent},
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
		expectCodes: []int{http.StatusCreated, http.StatusOK, http.StatusNoContent},
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

	var rolesResp []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}

	if err := json.Unmarshal(body, &rolesResp); err != nil {
		return nil, fmt.Errorf("unmarshal user roles response: %w", err)
	}

	roles := make([]models.OrganizationRole, len(rolesResp))
	for i, r := range rolesResp {
		roles[i] = models.OrganizationRole{
			ID:   r.ID,
			Name: r.Name,
		}
	}

	return roles, nil
}

// ListOrganizationApplications lists all applications in an organization
func (a *Adapter) ListOrganizationApplications(ctx context.Context, orgID string) ([]*models.Application, error) {
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

	apps := make([]*models.Application, 0, len(appsData))
	for _, appData := range appsData {
		app, err := parseApplicationResponse(appData)
		if err != nil {
			return nil, err
		}
		apps = append(apps, app)
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

	var rolesResp []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}

	if err := json.Unmarshal(body, &rolesResp); err != nil {
		return nil, fmt.Errorf("unmarshal application roles response: %w", err)
	}

	roles := make([]models.OrganizationRole, len(rolesResp))
	for i, r := range rolesResp {
		roles[i] = models.OrganizationRole{
			ID:   r.ID,
			Name: r.Name,
		}
	}

	return roles, nil
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

// ListOrganizationRoles lists all organization roles with their scopes
func (a *Adapter) ListOrganizationRoles(ctx context.Context) ([]models.OrganizationRole, error) {
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
		Scopes      []struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"scopes"`
	}

	if err := json.Unmarshal(body, &rolesResp); err != nil {
		return nil, fmt.Errorf("unmarshal organization roles response: %w", err)
	}

	roles := make([]models.OrganizationRole, len(rolesResp))
	for i, r := range rolesResp {
		scopes := make([]models.OrganizationScope, len(r.Scopes))
		for j, s := range r.Scopes {
			scopes[j] = models.OrganizationScope{
				ID:          s.ID,
				Name:        s.Name,
				Description: s.Description,
			}
		}
		roles[i] = models.OrganizationRole{
			ID:          r.ID,
			Name:        r.Name,
			Description: r.Description,
			Scopes:      scopes,
		}
	}

	return roles, nil
}

// GetOrganizationRole retrieves a single organization role by ID with its scopes
func (a *Adapter) GetOrganizationRole(ctx context.Context, roleID string) (*models.OrganizationRole, error) {
	if roleID == "" {
		return nil, &ValidationError{Field: "roleID", Message: "cannot be empty"}
	}

	// Get role details
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
	}

	if err := json.Unmarshal(body, &roleResp); err != nil {
		return nil, fmt.Errorf("unmarshal organization role response: %w", err)
	}

	// Get role scopes (separate endpoint in Logto API)
	scopes, err := a.GetOrganizationRoleScopes(ctx, roleID)
	if err != nil {
		return nil, err
	}

	return &models.OrganizationRole{
		ID:          roleResp.ID,
		Name:        roleResp.Name,
		Description: roleResp.Description,
		Scopes:      scopes,
	}, nil
}

// GetOrganizationRoleScopes retrieves scopes assigned to an organization role
func (a *Adapter) GetOrganizationRoleScopes(ctx context.Context, roleID string) ([]models.OrganizationScope, error) {
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
		return nil, fmt.Errorf("unmarshal organization role scopes response: %w", err)
	}

	scopes := make([]models.OrganizationScope, len(scopesResp))
	for i, s := range scopesResp {
		scopes[i] = models.OrganizationScope{
			ID:          s.ID,
			Name:        s.Name,
			Description: s.Description,
		}
	}

	return scopes, nil
}

// CreateOrganizationRole creates a new organization role
func (a *Adapter) CreateOrganizationRole(ctx context.Context, name, description string, roleType models.OrganizationRoleType, scopeIDs []string) (*models.OrganizationRole, error) {
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
		payload["organizationScopeIds"] = scopeIDs
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:      http.MethodPost,
		path:        "/api/organization-roles",
		body:        payload,
		expectCodes: []int{http.StatusCreated, http.StatusOK},
	})
	if err != nil {
		return nil, err
	}

	return parseOrganizationRoleResponse(body)
}

// UpdateOrganizationRole updates an organization role
func (a *Adapter) UpdateOrganizationRole(ctx context.Context, roleID, name, description string) (*models.OrganizationRole, error) {
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

	body, _, err := a.doRequest(ctx, requestConfig{
		method:      http.MethodPatch,
		path:        "/api/organization-roles/%s",
		pathParams:  []string{roleID},
		body:        payload,
		expectCodes: []int{http.StatusOK},
	})
	if err != nil {
		return nil, err
	}

	return parseOrganizationRoleResponse(body)
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

// AssignResourceScopesToOrganizationRole assigns API resource scopes to an organization role
func (a *Adapter) AssignResourceScopesToOrganizationRole(ctx context.Context, roleID string, scopeIDs []string) error {
	if roleID == "" {
		return &ValidationError{Field: "roleID", Message: "cannot be empty"}
	}

	return a.doNoContent(ctx, requestConfig{
		method:      http.MethodPost,
		path:        "/api/organization-roles/%s/resource-scopes",
		pathParams:  []string{roleID},
		body:        map[string][]string{"scopeIds": scopeIDs},
		expectCodes: []int{http.StatusCreated, http.StatusOK, http.StatusNoContent},
	})
}

// GetOrganizationScope retrieves a single organization scope by ID
func (a *Adapter) GetOrganizationScope(ctx context.Context, scopeID string) (*models.OrganizationScope, error) {
	if scopeID == "" {
		return nil, &ValidationError{Field: "scopeID", Message: "cannot be empty"}
	}

	var result models.OrganizationScope
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
func (a *Adapter) ListOrganizationScopes(ctx context.Context) ([]models.OrganizationScope, error) {
	var result []models.OrganizationScope
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
func (a *Adapter) CreateOrganizationScope(ctx context.Context, name, description string) (*models.OrganizationScope, error) {
	if name == "" {
		return nil, &ValidationError{Field: "name", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method: http.MethodPost,
		path:   "/api/organization-scopes",
		body: map[string]interface{}{
			"name":        name,
			"description": description,
		},
		expectCodes: []int{http.StatusCreated, http.StatusOK},
	})
	if err != nil {
		return nil, err
	}

	return parseOrganizationScopeResponse(body)
}

// UpdateOrganizationScope updates an organization scope
func (a *Adapter) UpdateOrganizationScope(ctx context.Context, scopeID, name, description string) (*models.OrganizationScope, error) {
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
		path:       "/api/organization-scopes/%s",
		pathParams: []string{scopeID},
		body:       payload,
	})
	if err != nil {
		return nil, err
	}

	return parseOrganizationScopeResponse(body)
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
func (a *Adapter) ListAPIResources(ctx context.Context) ([]*models.APIResource, error) {
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

	resources := make([]*models.APIResource, 0, len(resourcesData))
	var parseErrs []error
	for _, data := range resourcesData {
		resource, err := parseAPIResourceResponse(data)
		if err != nil {
			parseErrs = append(parseErrs, err)
			continue
		}
		resources = append(resources, resource)
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
			return scope, nil
		}
	}

	return nil, &APIError{StatusCode: 404, Message: fmt.Sprintf("API resource scope not found: %s", scopeID)}
}

// ListAPIResourceScopes lists all scopes for an API resource
func (a *Adapter) ListAPIResourceScopes(ctx context.Context, resourceID string) ([]*models.APIResourceScope, error) {
	if resourceID == "" {
		return nil, &ValidationError{Field: "resourceID", Message: "cannot be empty"}
	}

	var result []*models.APIResourceScope
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

// ListApplications retrieves all applications.
// Returns applications and any error. If some items failed to parse, returns partial results
// with a combined error containing all parse failures.
func (a *Adapter) ListApplications(ctx context.Context) ([]*models.Application, error) {
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

	apps := make([]*models.Application, 0, len(appsData))
	var parseErrs []error
	for _, appData := range appsData {
		app, err := parseApplicationResponse(appData)
		if err != nil {
			parseErrs = append(parseErrs, err)
			continue
		}
		apps = append(apps, app)
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
func (a *Adapter) ListRoles(ctx context.Context) ([]*models.Role, error) {
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

	roles := make([]*models.Role, 0, len(rolesData))
	for _, roleData := range rolesData {
		role, err := parseRoleResponse(roleData)
		if err != nil {
			return nil, err
		}
		roles = append(roles, role)
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
func (a *Adapter) ListRoleScopes(ctx context.Context, roleID string) ([]*models.APIResourceScope, error) {
	if roleID == "" {
		return nil, &ValidationError{Field: "roleID", Message: "cannot be empty"}
	}

	var result []*models.APIResourceScope
	err := a.doJSON(ctx, requestConfig{
		method:     http.MethodGet,
		path:       "/api/roles/%s/scopes",
		pathParams: []string{roleID},
	}, &result)
	if err != nil {
		return nil, err
	}

	return result, nil
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
func (a *Adapter) ListRoleUsers(ctx context.Context, roleID string) ([]*models.User, error) {
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

	users := make([]*models.User, 0, len(usersData))
	for _, userData := range usersData {
		user, err := parseUserResponse(userData)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
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
func (a *Adapter) ListRoleApplications(ctx context.Context, roleID string) ([]*models.Application, error) {
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

	apps := make([]*models.Application, 0, len(appsData))
	for _, appData := range appsData {
		app, err := parseApplicationResponse(appData)
		if err != nil {
			return nil, err
		}
		apps = append(apps, app)
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

// parseOrganizationRoleResponse parses organization role from API response
func parseOrganizationRoleResponse(data []byte) (*models.OrganizationRole, error) {
	var raw struct {
		ID          string `json:"id"`
		TenantID    string `json:"tenantId"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Type        string `json:"type"`
		CreatedAt   int64  `json:"createdAt"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse organization role: %w", err)
	}

	return &models.OrganizationRole{
		ID:          raw.ID,
		TenantID:    raw.TenantID,
		Name:        raw.Name,
		Description: raw.Description,
		Type:        raw.Type,
		CreatedAt:   models.UnixMilliTime{Time: time.UnixMilli(raw.CreatedAt)},
	}, nil
}

// parseOrganizationScopeResponse parses organization scope from API response
func parseOrganizationScopeResponse(data []byte) (*models.OrganizationScope, error) {
	var raw struct {
		ID          string `json:"id"`
		TenantID    string `json:"tenantId"`
		Name        string `json:"name"`
		Description string `json:"description"`
		CreatedAt   int64  `json:"createdAt"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse organization scope: %w", err)
	}

	return &models.OrganizationScope{
		ID:          raw.ID,
		TenantID:    raw.TenantID,
		Name:        raw.Name,
		Description: raw.Description,
		CreatedAt:   models.UnixMilliTime{Time: time.UnixMilli(raw.CreatedAt)},
	}, nil
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
		CreatedAt:   models.UnixMilliTime{Time: time.UnixMilli(raw.CreatedAt)},
	}, nil
}

// Helper function to parse API resource response
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
		CreatedAt:      models.UnixMilliTime{Time: time.UnixMilli(raw.CreatedAt)},
	}, nil
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

// UpdateUser updates user profile fields
func (a *Adapter) UpdateUser(ctx context.Context, userID string, update models.UserUpdate) (*models.User, error) {
	if userID == "" {
		return nil, &ValidationError{Field: "userID", Message: "cannot be empty"}
	}

	payload := make(map[string]interface{})
	if update.Name != nil {
		payload["name"] = *update.Name
	}
	if update.Avatar != nil {
		payload["avatar"] = *update.Avatar
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodPatch,
		path:       "/api/users/%s",
		pathParams: []string{userID},
		body:       payload,
	})
	if err != nil {
		return nil, err
	}

	return parseUserResponse(body)
}

// UpdateUserCustomData performs a partial update of user's customData (merge mode)
func (a *Adapter) UpdateUserCustomData(ctx context.Context, userID string, customData map[string]interface{}) (*models.User, error) {
	if userID == "" {
		return nil, &ValidationError{Field: "userID", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodPatch,
		path:       "/api/users/%s/custom-data",
		pathParams: []string{userID},
		body: map[string]interface{}{
			"customData": customData,
		},
	})
	if err != nil {
		return nil, err
	}

	return parseUserResponse(body)
}

// ListOrganizationInvitations lists invitations for an organization.
// Returns invitations and any error. If some items failed to parse, returns partial results
// with a combined error containing all parse failures.
func (a *Adapter) ListOrganizationInvitations(ctx context.Context, orgID string) ([]*models.OrganizationInvitation, error) {
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

	invitations := make([]*models.OrganizationInvitation, 0, len(invitationsData))
	var parseErrs []error
	for _, data := range invitationsData {
		inv, err := parseInvitationResponse(data)
		if err != nil {
			parseErrs = append(parseErrs, err)
			continue
		}
		invitations = append(invitations, inv)
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

// parseOrganizationMemberResponse parses user with their organization roles from API response
// The /api/organizations/{id}/users endpoint returns users with their organizationRoles
func parseOrganizationMemberResponse(data []byte) (*models.OrganizationMember, error) {
	var raw struct {
		ID                     string                            `json:"id"`
		TenantID               string                            `json:"tenantId"`
		Username               string                            `json:"username"`
		PrimaryEmail           string                            `json:"primaryEmail"`
		PrimaryPhone           string                            `json:"primaryPhone"`
		Name                   string                            `json:"name"`
		Avatar                 string                            `json:"avatar"`
		CustomData             map[string]interface{}            `json:"customData"`
		Identities             map[string]models.UserIdentity    `json:"identities"`
		LastSignInAt           *int64                            `json:"lastSignInAt"`
		CreatedAt              int64                             `json:"createdAt"`
		UpdatedAt              int64                             `json:"updatedAt"`
		Profile                *models.UserProfile               `json:"profile"`
		ApplicationID          string                            `json:"applicationId"`
		IsSuspended            bool                              `json:"isSuspended"`
		HasPassword            bool                              `json:"hasPassword"`
		SSOIdentities          []models.SSOIdentity              `json:"ssoIdentities"`
		MFAVerificationFactors []string                          `json:"mfaVerificationFactors"`
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

func parseUserResponse(data []byte) (*models.User, error) {
	// Parse with intermediate struct to handle timestamp conversion
	var raw struct {
		ID                     string                            `json:"id"`
		TenantID               string                            `json:"tenantId"`
		Username               string                            `json:"username"`
		PrimaryEmail           string                            `json:"primaryEmail"`
		PrimaryPhone           string                            `json:"primaryPhone"`
		Name                   string                            `json:"name"`
		Avatar                 string                            `json:"avatar"`
		CustomData             map[string]interface{}            `json:"customData"`
		Identities             map[string]models.UserIdentity    `json:"identities"`
		LastSignInAt           *int64                            `json:"lastSignInAt"`
		CreatedAt              int64                             `json:"createdAt"`
		UpdatedAt              int64                             `json:"updatedAt"`
		Profile                *models.UserProfile               `json:"profile"`
		ApplicationID          string                            `json:"applicationId"`
		IsSuspended            bool                              `json:"isSuspended"`
		HasPassword            bool                              `json:"hasPassword"`
		SSOIdentities          []models.SSOIdentity              `json:"ssoIdentities"`
		MFAVerificationFactors []string                          `json:"mfaVerificationFactors"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse user: %w", err)
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

	return &models.User{
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
	}, nil
}

func parseOrganizationResponse(data []byte) (*models.Organization, error) {
	var raw struct {
		ID            string                        `json:"id"`
		TenantID      string                        `json:"tenantId"`
		Name          string                        `json:"name"`
		Description   string                        `json:"description"`
		CustomData    map[string]interface{}        `json:"customData"`
		IsMfaRequired bool                          `json:"isMfaRequired"`
		Branding      *models.OrganizationBranding  `json:"branding"`
		CreatedAt     int64                         `json:"createdAt"`
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
		ID                   string                        `json:"id"`
		TenantID             string                        `json:"tenantId"`
		Name                 string                        `json:"name"`
		Description          string                        `json:"description"`
		Type                 string                        `json:"type"`
		Secret               string                        `json:"secret"`
		OIDCClientMetadata   *models.OIDCClientMetadata    `json:"oidcClientMetadata"`
		CustomClientMetadata *models.CustomClientMetadata  `json:"customClientMetadata"`
		ProtectedAppMetadata *models.ProtectedAppMetadata  `json:"protectedAppMetadata"`
		CustomData           map[string]interface{}        `json:"customData"`
		IsThirdParty         bool                          `json:"isThirdParty"`
		IsAdmin              bool                          `json:"isAdmin"`
		CreatedAt            int64                         `json:"createdAt"`
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

// Paginated list methods for iterators

func (a *Adapter) listUsersPaginated(ctx context.Context, page, pageSize int) ([]*models.User, error) {
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
		return nil, fmt.Errorf("unmarshal paginated users response: %w", err)
	}

	users := make([]*models.User, 0, len(usersData))
	for _, userData := range usersData {
		user, err := parseUserResponse(userData)
		if err != nil {
			// Skip invalid items in pagination - errors are less critical here
			continue
		}
		users = append(users, user)
	}

	return users, nil
}

func (a *Adapter) listOrganizationsPaginated(ctx context.Context, page, pageSize int) ([]*models.Organization, error) {
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

	orgs := make([]*models.Organization, 0, len(orgsData))
	for _, orgData := range orgsData {
		org, err := parseOrganizationResponse(orgData)
		if err != nil {
			// Skip invalid items in pagination - errors are less critical here
			continue
		}
		orgs = append(orgs, org)
	}

	return orgs, nil
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
