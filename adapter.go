package logto

import (
	"bytes"
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
	// Check cached token (with 60s buffer before expiry)
	a.tokenMu.RLock()
	if a.cachedToken != nil && time.Now().Add(60*time.Second).Before(a.cachedToken.expiresAt) {
		token := a.cachedToken.accessToken
		expiresIn := int(time.Until(a.cachedToken.expiresAt).Seconds())
		a.tokenMu.RUnlock()
		return token, expiresIn, nil
	}
	a.tokenMu.RUnlock()

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

	// Cache token
	a.tokenMu.Lock()
	a.cachedToken = &m2mTokenCache{
		accessToken: tokenResp.AccessToken,
		expiresAt:   time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
	}
	a.tokenMu.Unlock()

	return tokenResp.AccessToken, tokenResp.ExpiresIn, nil
}

// GetUser retrieves user information from Logto
func (a *Adapter) GetUser(ctx context.Context, userID string) (*User, error) {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("%s/api/users/%s", a.endpoint, userID)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get user request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read get user response body: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, &APIError{StatusCode: 404, Message: fmt.Sprintf("user not found: %s", userID)}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get user failed with status %d: %s", resp.StatusCode, string(body))
	}

	return a.parseUserResponse(body)
}

// GetUserByEmail retrieves user information by email
func (a *Adapter) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("%s/api/users?search=%s", a.endpoint, url.QueryEscape(email))

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get user by email request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get user by email failed with status %d: %s", resp.StatusCode, string(body))
	}

	var users []json.RawMessage
	if err := json.Unmarshal(body, &users); err != nil {
		return nil, err
	}

	// Find user with exact email match
	for _, userData := range users {
		user, err := a.parseUserResponse(userData)
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
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("%s/api/users", a.endpoint)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list users request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list users failed with status %d: %s", resp.StatusCode, string(body))
	}

	var usersData []json.RawMessage
	if err := json.Unmarshal(body, &usersData); err != nil {
		return nil, err
	}

	users := make([]*User, 0, len(usersData))
	for _, userData := range usersData {
		user, err := a.parseUserResponse(userData)
		if err != nil {
			continue
		}
		users = append(users, user)
	}

	return users, nil
}

// GetOrganization retrieves organization details
func (a *Adapter) GetOrganization(ctx context.Context, orgID string) (*Organization, error) {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("%s/api/organizations/%s", a.endpoint, orgID)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get organization request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, &APIError{StatusCode: 404, Message: fmt.Sprintf("organization not found: %s", orgID)}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get organization failed with status %d: %s", resp.StatusCode, string(body))
	}

	return a.parseOrganizationResponse(body)
}

// ListOrganizations retrieves all organizations
func (a *Adapter) ListOrganizations(ctx context.Context) ([]*Organization, error) {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("%s/api/organizations", a.endpoint)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list organizations request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list organizations failed with status %d: %s", resp.StatusCode, string(body))
	}

	var orgsData []json.RawMessage
	if err := json.Unmarshal(body, &orgsData); err != nil {
		return nil, err
	}

	orgs := make([]*Organization, 0, len(orgsData))
	for _, orgData := range orgsData {
		org, err := a.parseOrganizationResponse(orgData)
		if err != nil {
			continue
		}
		orgs = append(orgs, org)
	}

	return orgs, nil
}

// ListUserOrganizations retrieves organizations where the user is a member
func (a *Adapter) ListUserOrganizations(ctx context.Context, userID string) ([]*Organization, error) {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("%s/api/users/%s/organizations", a.endpoint, userID)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list user organizations request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list user organizations failed with status %d: %s", resp.StatusCode, string(body))
	}

	var orgsData []json.RawMessage
	if err := json.Unmarshal(body, &orgsData); err != nil {
		return nil, err
	}

	orgs := make([]*Organization, 0, len(orgsData))
	for _, orgData := range orgsData {
		org, err := a.parseOrganizationResponse(orgData)
		if err != nil {
			continue
		}
		orgs = append(orgs, org)
	}

	return orgs, nil
}

// CreateOrganization creates a new organization in Logto
func (a *Adapter) CreateOrganization(ctx context.Context, name, description string) (string, error) {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return "", err
	}

	apiURL := fmt.Sprintf("%s/api/organizations", a.endpoint)

	payload := map[string]interface{}{
		"name":        name,
		"description": description,
	}

	jsonData, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(jsonData))
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("create organization request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("create organization failed with status %d: %s", resp.StatusCode, string(body))
	}

	var orgResp struct {
		ID string `json:"id"`
	}

	if err := json.Unmarshal(body, &orgResp); err != nil {
		return "", err
	}

	return orgResp.ID, nil
}

// UpdateOrganization updates organization details
func (a *Adapter) UpdateOrganization(ctx context.Context, orgID string, name, description string, customData map[string]interface{}) error {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return err
	}

	apiURL := fmt.Sprintf("%s/api/organizations/%s", a.endpoint, orgID)

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

	jsonData, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "PATCH", apiURL, bytes.NewReader(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("update organization request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update organization failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// DeleteOrganization removes an organization from Logto
func (a *Adapter) DeleteOrganization(ctx context.Context, orgID string) error {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return err
	}

	apiURL := fmt.Sprintf("%s/api/organizations/%s", a.endpoint, orgID)

	req, err := http.NewRequestWithContext(ctx, "DELETE", apiURL, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("delete organization request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete organization failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// ListOrganizationMembers lists all members of an organization with their roles
func (a *Adapter) ListOrganizationMembers(ctx context.Context, orgID string) ([]*OrganizationMember, error) {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("%s/api/organizations/%s/users", a.endpoint, orgID)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list organization members request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list organization members failed with status %d: %s", resp.StatusCode, string(body))
	}

	var membersData []json.RawMessage
	if err := json.Unmarshal(body, &membersData); err != nil {
		return nil, err
	}

	members := make([]*OrganizationMember, 0, len(membersData))
	for _, memberData := range membersData {
		user, err := a.parseUserResponse(memberData)
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
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return err
	}

	// Add user as member
	apiURL := fmt.Sprintf("%s/api/organizations/%s/users", a.endpoint, orgID)

	payload := map[string]interface{}{
		"userIds": []string{userID},
	}

	jsonData, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("add user to organization request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("add user to organization failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Assign roles if provided
	if len(roleIDs) > 0 {
		return a.UpdateUserRoles(ctx, orgID, userID, roleIDs)
	}

	return nil
}

// RemoveUserFromOrganization removes a user from an organization
func (a *Adapter) RemoveUserFromOrganization(ctx context.Context, orgID, userID string) error {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return err
	}

	apiURL := fmt.Sprintf("%s/api/organizations/%s/users/%s", a.endpoint, orgID, userID)

	req, err := http.NewRequestWithContext(ctx, "DELETE", apiURL, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("remove user from organization request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("remove user from organization failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// UpdateUserRoles updates a user's roles in an organization
func (a *Adapter) UpdateUserRoles(ctx context.Context, orgID, userID string, roleIDs []string) error {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return err
	}

	apiURL := fmt.Sprintf("%s/api/organizations/%s/users/%s/roles", a.endpoint, orgID, userID)

	payload := map[string]interface{}{
		"organizationRoleIds": roleIDs,
	}

	jsonData, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "PUT", apiURL, bytes.NewReader(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("update user roles request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update user roles failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetUserRolesInOrganization gets a user's roles in an organization
func (a *Adapter) GetUserRolesInOrganization(ctx context.Context, orgID, userID string) ([]OrganizationRole, error) {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("%s/api/organizations/%s/users/%s/roles", a.endpoint, orgID, userID)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get user roles request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get user roles failed with status %d: %s", resp.StatusCode, string(body))
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
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("%s/api/organization-roles", a.endpoint)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list roles request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list roles failed with status %d: %s", resp.StatusCode, string(body))
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
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("%s/api/organization-roles/%s", a.endpoint, roleID)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get organization role request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, &APIError{StatusCode: 404, Message: fmt.Sprintf("organization role not found: %s", roleID)}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get organization role failed with status %d: %s", resp.StatusCode, string(body))
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
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return "", err
	}

	apiURL := fmt.Sprintf("%s/api/organization-roles", a.endpoint)

	payload := map[string]interface{}{
		"name":        name,
		"description": description,
	}
	if len(scopeIDs) > 0 {
		payload["organizationScopeIds"] = scopeIDs
	}

	jsonData, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(jsonData))
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("create organization role request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("create organization role failed with status %d: %s", resp.StatusCode, string(body))
	}

	var roleResp struct {
		ID string `json:"id"`
	}

	if err := json.Unmarshal(body, &roleResp); err != nil {
		return "", err
	}

	return roleResp.ID, nil
}

// UpdateOrganizationRole updates an organization role
func (a *Adapter) UpdateOrganizationRole(ctx context.Context, roleID, name, description string) error {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return err
	}

	apiURL := fmt.Sprintf("%s/api/organization-roles/%s", a.endpoint, roleID)

	payload := make(map[string]interface{})
	if name != "" {
		payload["name"] = name
	}
	if description != "" {
		payload["description"] = description
	}

	jsonData, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "PATCH", apiURL, bytes.NewReader(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("update organization role request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update organization role failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// DeleteOrganizationRole deletes an organization role
func (a *Adapter) DeleteOrganizationRole(ctx context.Context, roleID string) error {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return err
	}

	apiURL := fmt.Sprintf("%s/api/organization-roles/%s", a.endpoint, roleID)

	req, err := http.NewRequestWithContext(ctx, "DELETE", apiURL, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("delete organization role request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete organization role failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetOrganizationRoleScopes retrieves scopes assigned to an organization role
func (a *Adapter) GetOrganizationRoleScopes(ctx context.Context, roleID string) ([]OrganizationScope, error) {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("%s/api/organization-roles/%s/scopes", a.endpoint, roleID)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get organization role scopes request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get organization role scopes failed with status %d: %s", resp.StatusCode, string(body))
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
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return err
	}

	apiURL := fmt.Sprintf("%s/api/organization-roles/%s/scopes", a.endpoint, roleID)

	payload := map[string]interface{}{
		"organizationScopeIds": scopeIDs,
	}

	jsonData, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "PUT", apiURL, bytes.NewReader(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("set organization role scopes request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("set organization role scopes failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// AddOrganizationRoleScopes adds scopes to an organization role
func (a *Adapter) AddOrganizationRoleScopes(ctx context.Context, roleID string, scopeIDs []string) error {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return err
	}

	apiURL := fmt.Sprintf("%s/api/organization-roles/%s/scopes", a.endpoint, roleID)

	payload := map[string]interface{}{
		"organizationScopeIds": scopeIDs,
	}

	jsonData, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("add organization role scopes request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("add organization role scopes failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// RemoveOrganizationRoleScope removes a scope from an organization role
func (a *Adapter) RemoveOrganizationRoleScope(ctx context.Context, roleID, scopeID string) error {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return err
	}

	apiURL := fmt.Sprintf("%s/api/organization-roles/%s/scopes/%s", a.endpoint, roleID, scopeID)

	req, err := http.NewRequestWithContext(ctx, "DELETE", apiURL, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("remove organization role scope request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("remove organization role scope failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetOrganizationScope retrieves a single organization scope by ID
func (a *Adapter) GetOrganizationScope(ctx context.Context, scopeID string) (*OrganizationScope, error) {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("%s/api/organization-scopes/%s", a.endpoint, scopeID)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get organization scope request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, &APIError{StatusCode: 404, Message: fmt.Sprintf("organization scope not found: %s", scopeID)}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get organization scope failed with status %d: %s", resp.StatusCode, string(body))
	}

	var scopeResp struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}

	if err := json.Unmarshal(body, &scopeResp); err != nil {
		return nil, err
	}

	return &OrganizationScope{
		ID:          scopeResp.ID,
		Name:        scopeResp.Name,
		Description: scopeResp.Description,
	}, nil
}

// ListOrganizationScopes lists all organization scopes
func (a *Adapter) ListOrganizationScopes(ctx context.Context) ([]OrganizationScope, error) {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("%s/api/organization-scopes", a.endpoint)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list organization scopes request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list organization scopes failed with status %d: %s", resp.StatusCode, string(body))
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

// CreateOrganizationScope creates a new organization scope
func (a *Adapter) CreateOrganizationScope(ctx context.Context, name, description string) (string, error) {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return "", err
	}

	apiURL := fmt.Sprintf("%s/api/organization-scopes", a.endpoint)

	payload := map[string]interface{}{
		"name":        name,
		"description": description,
	}

	jsonData, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(jsonData))
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("create organization scope request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("create organization scope failed with status %d: %s", resp.StatusCode, string(body))
	}

	var scopeResp struct {
		ID string `json:"id"`
	}

	if err := json.Unmarshal(body, &scopeResp); err != nil {
		return "", err
	}

	return scopeResp.ID, nil
}

// UpdateOrganizationScope updates an organization scope
func (a *Adapter) UpdateOrganizationScope(ctx context.Context, scopeID, name, description string) error {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return err
	}

	apiURL := fmt.Sprintf("%s/api/organization-scopes/%s", a.endpoint, scopeID)

	payload := make(map[string]interface{})
	if name != "" {
		payload["name"] = name
	}
	if description != "" {
		payload["description"] = description
	}

	jsonData, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "PATCH", apiURL, bytes.NewReader(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("update organization scope request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update organization scope failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// DeleteOrganizationScope deletes an organization scope
func (a *Adapter) DeleteOrganizationScope(ctx context.Context, scopeID string) error {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return err
	}

	apiURL := fmt.Sprintf("%s/api/organization-scopes/%s", a.endpoint, scopeID)

	req, err := http.NewRequestWithContext(ctx, "DELETE", apiURL, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("delete organization scope request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete organization scope failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetAPIResource retrieves a single API resource by ID
func (a *Adapter) GetAPIResource(ctx context.Context, resourceID string) (*APIResource, error) {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("%s/api/resources/%s", a.endpoint, resourceID)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get API resource request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, &APIError{StatusCode: 404, Message: fmt.Sprintf("API resource not found: %s", resourceID)}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get API resource failed with status %d: %s", resp.StatusCode, string(body))
	}

	return a.parseAPIResourceResponse(body)
}

// ListAPIResources lists all API resources
func (a *Adapter) ListAPIResources(ctx context.Context) ([]*APIResource, error) {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("%s/api/resources", a.endpoint)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list API resources request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list API resources failed with status %d: %s", resp.StatusCode, string(body))
	}

	var resourcesData []json.RawMessage
	if err := json.Unmarshal(body, &resourcesData); err != nil {
		return nil, err
	}

	resources := make([]*APIResource, 0, len(resourcesData))
	for _, data := range resourcesData {
		resource, err := a.parseAPIResourceResponse(data)
		if err != nil {
			continue
		}
		resources = append(resources, resource)
	}

	return resources, nil
}

// CreateAPIResource creates a new API resource
func (a *Adapter) CreateAPIResource(ctx context.Context, name, indicator string) (string, error) {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return "", err
	}

	apiURL := fmt.Sprintf("%s/api/resources", a.endpoint)

	payload := map[string]interface{}{
		"name":      name,
		"indicator": indicator,
	}

	jsonData, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(jsonData))
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("create API resource request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("create API resource failed with status %d: %s", resp.StatusCode, string(body))
	}

	var resourceResp struct {
		ID string `json:"id"`
	}

	if err := json.Unmarshal(body, &resourceResp); err != nil {
		return "", err
	}

	return resourceResp.ID, nil
}

// UpdateAPIResource updates an API resource
func (a *Adapter) UpdateAPIResource(ctx context.Context, resourceID, name string, accessTokenTTL *int) error {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return err
	}

	apiURL := fmt.Sprintf("%s/api/resources/%s", a.endpoint, resourceID)

	payload := make(map[string]interface{})
	if name != "" {
		payload["name"] = name
	}
	if accessTokenTTL != nil {
		payload["accessTokenTtl"] = *accessTokenTTL
	}

	jsonData, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "PATCH", apiURL, bytes.NewReader(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("update API resource request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update API resource failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// DeleteAPIResource deletes an API resource
func (a *Adapter) DeleteAPIResource(ctx context.Context, resourceID string) error {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return err
	}

	apiURL := fmt.Sprintf("%s/api/resources/%s", a.endpoint, resourceID)

	req, err := http.NewRequestWithContext(ctx, "DELETE", apiURL, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("delete API resource request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete API resource failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
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
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("%s/api/resources/%s/scopes", a.endpoint, resourceID)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list API resource scopes request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list API resource scopes failed with status %d: %s", resp.StatusCode, string(body))
	}

	var scopesResp []struct {
		ID          string `json:"id"`
		ResourceID  string `json:"resourceId"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}

	if err := json.Unmarshal(body, &scopesResp); err != nil {
		return nil, err
	}

	scopes := make([]*APIResourceScope, len(scopesResp))
	for i, s := range scopesResp {
		scopes[i] = &APIResourceScope{
			ID:          s.ID,
			ResourceID:  s.ResourceID,
			Name:        s.Name,
			Description: s.Description,
		}
	}

	return scopes, nil
}

// CreateAPIResourceScope creates a new scope for an API resource
func (a *Adapter) CreateAPIResourceScope(ctx context.Context, resourceID, name, description string) (string, error) {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return "", err
	}

	apiURL := fmt.Sprintf("%s/api/resources/%s/scopes", a.endpoint, resourceID)

	payload := map[string]interface{}{
		"name":        name,
		"description": description,
	}

	jsonData, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(jsonData))
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("create API resource scope request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("create API resource scope failed with status %d: %s", resp.StatusCode, string(body))
	}

	var scopeResp struct {
		ID string `json:"id"`
	}

	if err := json.Unmarshal(body, &scopeResp); err != nil {
		return "", err
	}

	return scopeResp.ID, nil
}

// UpdateAPIResourceScope updates a scope for an API resource
func (a *Adapter) UpdateAPIResourceScope(ctx context.Context, resourceID, scopeID, name, description string) error {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return err
	}

	apiURL := fmt.Sprintf("%s/api/resources/%s/scopes/%s", a.endpoint, resourceID, scopeID)

	payload := make(map[string]interface{})
	if name != "" {
		payload["name"] = name
	}
	if description != "" {
		payload["description"] = description
	}

	jsonData, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "PATCH", apiURL, bytes.NewReader(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("update API resource scope request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update API resource scope failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// DeleteAPIResourceScope deletes a scope from an API resource
func (a *Adapter) DeleteAPIResourceScope(ctx context.Context, resourceID, scopeID string) error {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return err
	}

	apiURL := fmt.Sprintf("%s/api/resources/%s/scopes/%s", a.endpoint, resourceID, scopeID)

	req, err := http.NewRequestWithContext(ctx, "DELETE", apiURL, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("delete API resource scope request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete API resource scope failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// Helper function to parse API resource response
func (a *Adapter) parseAPIResourceResponse(data []byte) (*APIResource, error) {
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
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return "", err
	}

	apiURL := fmt.Sprintf("%s/api/organization-invitations", a.endpoint)

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

	jsonData, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(jsonData))
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("create invitation request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("create invitation failed with status %d: %s", resp.StatusCode, string(body))
	}

	var invitationResp struct {
		ID string `json:"id"`
	}

	if err := json.Unmarshal(body, &invitationResp); err != nil {
		return "", err
	}

	return invitationResp.ID, nil
}

// UpdateUser updates user profile fields
func (a *Adapter) UpdateUser(ctx context.Context, userID string, update UserUpdate) error {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return err
	}

	apiURL := fmt.Sprintf("%s/api/users/%s", a.endpoint, userID)

	payload := make(map[string]interface{})
	if update.Name != nil {
		payload["name"] = *update.Name
	}
	if update.Avatar != nil {
		payload["avatar"] = *update.Avatar
	}

	jsonData, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "PATCH", apiURL, bytes.NewReader(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("update user request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update user failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// UpdateUserCustomData performs a partial update of user's customData (merge mode)
func (a *Adapter) UpdateUserCustomData(ctx context.Context, userID string, customData map[string]interface{}) error {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return err
	}

	apiURL := fmt.Sprintf("%s/api/users/%s/custom-data", a.endpoint, userID)

	payload := map[string]interface{}{
		"customData": customData,
	}

	jsonData, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "PATCH", apiURL, bytes.NewReader(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("update user custom data request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update user custom data failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// ListOrganizationInvitations lists invitations for an organization
func (a *Adapter) ListOrganizationInvitations(ctx context.Context, orgID string) ([]*OrganizationInvitation, error) {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("%s/api/organization-invitations?organizationId=%s", a.endpoint, url.QueryEscape(orgID))

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list invitations request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list invitations failed with status %d: %s", resp.StatusCode, string(body))
	}

	var invitationsData []json.RawMessage
	if err := json.Unmarshal(body, &invitationsData); err != nil {
		return nil, err
	}

	invitations := make([]*OrganizationInvitation, 0, len(invitationsData))
	for _, data := range invitationsData {
		inv, err := a.parseInvitationResponse(data)
		if err != nil {
			continue
		}
		invitations = append(invitations, inv)
	}

	return invitations, nil
}

// GetOrganizationInvitation retrieves a single invitation by ID
func (a *Adapter) GetOrganizationInvitation(ctx context.Context, invitationID string) (*OrganizationInvitation, error) {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("%s/api/organization-invitations/%s", a.endpoint, invitationID)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get invitation request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, &APIError{StatusCode: 404, Message: fmt.Sprintf("invitation not found: %s", invitationID)}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get invitation failed with status %d: %s", resp.StatusCode, string(body))
	}

	return a.parseInvitationResponse(body)
}

// DeleteOrganizationInvitation deletes an invitation
func (a *Adapter) DeleteOrganizationInvitation(ctx context.Context, invitationID string) error {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return err
	}

	apiURL := fmt.Sprintf("%s/api/organization-invitations/%s", a.endpoint, invitationID)

	req, err := http.NewRequestWithContext(ctx, "DELETE", apiURL, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("delete invitation request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete invitation failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// SendInvitationMessage sends the invitation email with a magic link
func (a *Adapter) SendInvitationMessage(ctx context.Context, invitationID, magicLink string) error {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return err
	}

	apiURL := fmt.Sprintf("%s/api/organization-invitations/%s/message", a.endpoint, invitationID)

	// Send with magic link - Logto email template will use {{link}} variable
	payload := map[string]interface{}{
		"link": magicLink,
	}

	jsonData, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send invitation message request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("send invitation message failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// CreateOneTimeToken creates a one-time token for magic link authentication
func (a *Adapter) CreateOneTimeToken(ctx context.Context, email string, expiresIn int, jitOrgIDs []string) (*OneTimeTokenResult, error) {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("%s/api/one-time-tokens", a.endpoint)

	payload := map[string]interface{}{
		"email":     email,
		"expiresIn": expiresIn,
	}

	if len(jitOrgIDs) > 0 {
		payload["context"] = map[string]interface{}{
			"jitOrganizationIds": jitOrgIDs,
		}
	}

	jsonData, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(jsonData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("create one-time token request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("create one-time token failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		Token     string `json:"token"`
		ExpiresAt int64  `json:"expiresAt"` // Unix timestamp in seconds
	}

	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, err
	}

	return &OneTimeTokenResult{
		Token:     tokenResp.Token,
		ExpiresAt: tokenResp.ExpiresAt,
	}, nil
}

// Helper functions

func (a *Adapter) parseUserResponse(data []byte) (*User, error) {
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

func (a *Adapter) parseOrganizationResponse(data []byte) (*Organization, error) {
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

func (a *Adapter) parseInvitationResponse(data []byte) (*OrganizationInvitation, error) {
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
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("%s/api/users?page=%d&page_size=%d", a.endpoint, page, pageSize)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list users request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, newAPIError(resp.StatusCode, body)
	}

	var usersData []json.RawMessage
	if err := json.Unmarshal(body, &usersData); err != nil {
		return nil, err
	}

	users := make([]*User, 0, len(usersData))
	for _, userData := range usersData {
		user, err := a.parseUserResponse(userData)
		if err != nil {
			continue
		}
		users = append(users, user)
	}

	return users, nil
}

func (a *Adapter) listOrganizationsPaginated(ctx context.Context, page, pageSize int) ([]*Organization, error) {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("%s/api/organizations?page=%d&page_size=%d", a.endpoint, page, pageSize)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list organizations request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, newAPIError(resp.StatusCode, body)
	}

	var orgsData []json.RawMessage
	if err := json.Unmarshal(body, &orgsData); err != nil {
		return nil, err
	}

	orgs := make([]*Organization, 0, len(orgsData))
	for _, orgData := range orgsData {
		org, err := a.parseOrganizationResponse(orgData)
		if err != nil {
			continue
		}
		orgs = append(orgs, org)
	}

	return orgs, nil
}

func (a *Adapter) listInvitationsPaginated(ctx context.Context, orgID string, page, pageSize int) ([]*OrganizationInvitation, error) {
	token, _, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("%s/api/organization-invitations?organizationId=%s&page=%d&page_size=%d",
		a.endpoint, url.QueryEscape(orgID), page, pageSize)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list invitations request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, newAPIError(resp.StatusCode, body)
	}

	var invitationsData []json.RawMessage
	if err := json.Unmarshal(body, &invitationsData); err != nil {
		return nil, err
	}

	invitations := make([]*OrganizationInvitation, 0, len(invitationsData))
	for _, data := range invitationsData {
		inv, err := a.parseInvitationResponse(data)
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
