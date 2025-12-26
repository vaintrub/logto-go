package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
	endpoint          string
	m2mAppID          string
	m2mAppSecret      string
	httpClient        *http.Client
	opts              *options
	cachedCredentials string // Base64 encoded credentials (computed once)

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

	// Create HTTP client with proper connection pooling
	httpClient := o.httpClient
	if httpClient == nil {
		// Clone default transport and increase connection pool limits
		// Default MaxIdleConnsPerHost is 2, which causes excessive TIME_WAIT connections
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.MaxIdleConns = 100
		transport.MaxIdleConnsPerHost = 100
		transport.MaxConnsPerHost = 100
		// Add transport-level timeouts to prevent hanging connections in Docker/CI
		transport.ResponseHeaderTimeout = o.responseHeaderTimeout
		transport.IdleConnTimeout = o.idleConnTimeout
		httpClient = &http.Client{
			Timeout:   o.timeout,
			Transport: transport,
		}
	}

	// Normalize endpoint: remove trailing slash to prevent double slashes in URL concatenation
	endpoint = strings.TrimSuffix(endpoint, "/")

	// Pre-compute base64 credentials to avoid repeated encoding on each request
	credentials := base64.StdEncoding.EncodeToString([]byte(m2mAppID + ":" + m2mAppSecret))

	return &Adapter{
		endpoint:          endpoint,
		m2mAppID:          m2mAppID,
		m2mAppSecret:      m2mAppSecret,
		httpClient:        httpClient,
		opts:              o,
		cachedCredentials: credentials,
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
		// Limit response size to prevent DoS
		const maxErrorResponseSize = 1024 * 1024 // 1MB for error responses
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorResponseSize))
		requestID := resp.Header.Get("X-Request-Id")
		return newAPIErrorFromResponse(resp.StatusCode, body, requestID)
	}

	return nil
}

// AuthenticateM2M obtains a machine-to-machine access token for the Management API.
// The token is cached internally and refreshed automatically when expired.
func (a *Adapter) AuthenticateM2M(ctx context.Context) (*TokenResult, error) {
	// Fast path: check cached token with read lock
	a.tokenMu.RLock()
	if a.cachedToken != nil && time.Now().Add(tokenExpiryBuffer).Before(a.cachedToken.expiresAt) {
		result := &TokenResult{
			AccessToken: a.cachedToken.accessToken,
			TokenType:   "Bearer",
			ExpiresIn:   int(time.Until(a.cachedToken.expiresAt).Seconds()),
			ExpiresAt:   a.cachedToken.expiresAt,
			Scope:       a.opts.scope,
		}
		a.tokenMu.RUnlock()
		return result, nil
	}
	a.tokenMu.RUnlock()

	// Slow path: acquire write lock and double-check (prevents race condition)
	a.tokenMu.Lock()
	defer a.tokenMu.Unlock()

	// Double-check after acquiring write lock
	if a.cachedToken != nil && time.Now().Add(tokenExpiryBuffer).Before(a.cachedToken.expiresAt) {
		return &TokenResult{
			AccessToken: a.cachedToken.accessToken,
			TokenType:   "Bearer",
			ExpiresIn:   int(time.Until(a.cachedToken.expiresAt).Seconds()),
			ExpiresAt:   a.cachedToken.expiresAt,
			Scope:       a.opts.scope,
		}, nil
	}

	// Request new token
	tokenURL := fmt.Sprintf("%s/oidc/token", a.endpoint)

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("resource", a.opts.resource)
	data.Set("scope", a.opts.scope)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	// Use Basic Auth with cached M2M credentials
	req.Header.Set("Authorization", "Basic "+a.cachedCredentials)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("M2M auth request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read M2M auth response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		requestID := resp.Header.Get("X-Request-Id")
		return nil, newAPIErrorFromResponse(resp.StatusCode, body, requestID)
	}

	var result TokenResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("unmarshal token response: %w", err)
	}

	// Compute ExpiresAt
	result.ExpiresAt = time.Now().Add(time.Duration(result.ExpiresIn) * time.Second)

	// Cache token (already holding write lock from defer above)
	a.cachedToken = &m2mTokenCache{
		accessToken: result.AccessToken,
		expiresAt:   result.ExpiresAt,
	}

	return &result, nil
}

// GetOrganizationToken obtains an M2M token scoped to a specific organization.
//
// This method is used when your M2M application needs to access resources
// on behalf of a specific organization. The M2M app must be added to the
// organization first using AddOrganizationApplications.
//
// IMPORTANT: This method does NOT cache tokens internally.
// Caching is the responsibility of the calling code.
// Use TokenResult.ExpiresAt for cache TTL calculations.
//
// Example usage with caching:
//
//	result, err := client.GetOrganizationToken(ctx, orgID)
//	if err != nil {
//	    return err
//	}
//	// Cache result.AccessToken with TTL based on result.ExpiresAt
//	cache.Set(orgID, result.AccessToken, time.Until(result.ExpiresAt))
func (a *Adapter) GetOrganizationToken(ctx context.Context, orgID string) (*TokenResult, error) {
	if orgID == "" {
		return nil, &ValidationError{Field: "orgID", Message: "cannot be empty"}
	}

	tokenURL := fmt.Sprintf("%s/oidc/token", a.endpoint)

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("resource", a.opts.resource)
	data.Set("scope", a.opts.scope)
	data.Set("organization_id", orgID)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	// Use Basic Auth with cached M2M credentials
	req.Header.Set("Authorization", "Basic "+a.cachedCredentials)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("organization token request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read organization token response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		requestID := resp.Header.Get("X-Request-Id")
		return nil, newAPIErrorFromResponse(resp.StatusCode, body, requestID)
	}

	var result TokenResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("unmarshal organization token response: %w", err)
	}

	// Compute ExpiresAt for convenient cache TTL calculation
	result.ExpiresAt = time.Now().Add(time.Duration(result.ExpiresIn) * time.Second)

	return &result, nil
}

// GetResourceToken obtains an M2M token for a specific API resource.
//
// This method is used when your M2M application needs to access external APIs
// that are registered as API Resources in Logto. The M2M app must have a role
// with the required scopes for the target resource.
//
// IMPORTANT: This method does NOT cache tokens internally.
// Caching is the responsibility of the calling code.
// Use TokenResult.ExpiresAt for cache TTL calculations.
//
// Example usage:
//
//	token, err := client.GetResourceToken(ctx, "https://my-api.example.com", "read:data", "write:data")
//	if err != nil {
//	    return err
//	}
//	// Use token.AccessToken in Authorization header
//	req.Header.Set("Authorization", "Bearer " + token.AccessToken)
func (a *Adapter) GetResourceToken(ctx context.Context, resource string, scopes ...string) (*TokenResult, error) {
	if resource == "" {
		return nil, &ValidationError{Field: "resource", Message: "cannot be empty"}
	}

	tokenURL := fmt.Sprintf("%s/oidc/token", a.endpoint)

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("resource", resource)
	if len(scopes) > 0 {
		data.Set("scope", strings.Join(scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	// Use Basic Auth with cached M2M credentials
	req.Header.Set("Authorization", "Basic "+a.cachedCredentials)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("resource token request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read resource token response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		requestID := resp.Header.Get("X-Request-Id")
		return nil, newAPIErrorFromResponse(resp.StatusCode, body, requestID)
	}

	var result TokenResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("unmarshal resource token response: %w", err)
	}

	// Compute ExpiresAt for convenient cache TTL calculation
	result.ExpiresAt = time.Now().Add(time.Duration(result.ExpiresIn) * time.Second)

	return &result, nil
}

// ListOrganizationApplications returns an iterator for all applications in an organization.
func (a *Adapter) ListOrganizationApplications(orgID string, config IteratorConfig) *Iterator[models.Application] {
	fetcher := func(ctx context.Context, page, pageSize int) (PageResult[models.Application], error) {
		if orgID == "" {
			return PageResult[models.Application]{}, &ValidationError{Field: "orgID", Message: "cannot be empty"}
		}
		return a.listOrganizationApplicationsPaginated(ctx, orgID, page, pageSize)
	}
	return NewIterator(fetcher, config)
}

// listOrganizationApplicationsPaginated returns organization applications with pagination support
func (a *Adapter) listOrganizationApplicationsPaginated(ctx context.Context, orgID string, page, pageSize int) (PageResult[models.Application], error) {
	result, err := a.doRequestFull(ctx, requestConfig{
		method:     http.MethodGet,
		path:       "/api/organizations/%s/applications",
		pathParams: []string{orgID},
		query: url.Values{
			"page":      {fmt.Sprintf("%d", page)},
			"page_size": {fmt.Sprintf("%d", pageSize)},
		},
	})
	if err != nil {
		return PageResult[models.Application]{}, err
	}

	var apps []models.Application
	if err := json.Unmarshal(result.Body, &apps); err != nil {
		return PageResult[models.Application]{}, fmt.Errorf("unmarshal applications: %w", err)
	}

	return PageResult[models.Application]{
		Items: apps,
		Total: getTotalFromHeaders(result.Headers),
	}, nil
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

// RemoveApplicationFromOrganization removes an application from an organization
func (a *Adapter) RemoveApplicationFromOrganization(ctx context.Context, orgID, applicationID string) error {
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

// RemoveRolesFromOrganizationApplication removes roles from an application in an organization
func (a *Adapter) RemoveRolesFromOrganizationApplication(ctx context.Context, orgID, applicationID string, roleIDs []string) error {
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

// ListApplications returns an iterator for paginating through all applications.
func (a *Adapter) ListApplications(config IteratorConfig) *Iterator[models.Application] {
	return NewIterator(a.listApplicationsPaginated, config)
}

// listApplicationsPaginated returns applications with pagination support
func (a *Adapter) listApplicationsPaginated(ctx context.Context, page, pageSize int) (PageResult[models.Application], error) {
	result, err := a.doRequestFull(ctx, requestConfig{
		method: http.MethodGet,
		path:   "/api/applications",
		query: url.Values{
			"page":      {fmt.Sprintf("%d", page)},
			"page_size": {fmt.Sprintf("%d", pageSize)},
		},
	})
	if err != nil {
		return PageResult[models.Application]{}, err
	}

	var apps []models.Application
	if err := json.Unmarshal(result.Body, &apps); err != nil {
		return PageResult[models.Application]{}, fmt.Errorf("unmarshal applications: %w", err)
	}

	return PageResult[models.Application]{
		Items: apps,
		Total: getTotalFromHeaders(result.Headers),
	}, nil
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
		expectCodes: []int{http.StatusOK, http.StatusCreated},
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

// ListRoles returns an iterator for paginating through all global roles.
func (a *Adapter) ListRoles(config IteratorConfig) *Iterator[models.Role] {
	return NewIterator(a.listRolesPaginated, config)
}

// listRolesPaginated returns roles with pagination support
func (a *Adapter) listRolesPaginated(ctx context.Context, page, pageSize int) (PageResult[models.Role], error) {
	result, err := a.doRequestFull(ctx, requestConfig{
		method: http.MethodGet,
		path:   "/api/roles",
		query: url.Values{
			"page":      {fmt.Sprintf("%d", page)},
			"page_size": {fmt.Sprintf("%d", pageSize)},
		},
	})
	if err != nil {
		return PageResult[models.Role]{}, err
	}

	var roles []models.Role
	if err := json.Unmarshal(result.Body, &roles); err != nil {
		return PageResult[models.Role]{}, fmt.Errorf("unmarshal roles: %w", err)
	}

	return PageResult[models.Role]{
		Items: roles,
		Total: getTotalFromHeaders(result.Headers),
	}, nil
}

// CreateRole creates a new global role
func (a *Adapter) CreateRole(ctx context.Context, role models.RoleCreate) (*models.Role, error) {
	if role.Name == "" {
		return nil, &ValidationError{Field: "name", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:      http.MethodPost,
		path:        "/api/roles",
		body:        role,
		expectCodes: []int{http.StatusOK, http.StatusCreated},
	})
	if err != nil {
		return nil, err
	}

	return parseRoleResponse(body)
}

// UpdateRole updates a global role
func (a *Adapter) UpdateRole(ctx context.Context, roleID string, update models.RoleUpdate) (*models.Role, error) {
	if roleID == "" {
		return nil, &ValidationError{Field: "roleID", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodPatch,
		path:       "/api/roles/%s",
		pathParams: []string{roleID},
		body:       update,
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

// ListRoleScopes returns an iterator for API resource scopes assigned to a role.
func (a *Adapter) ListRoleScopes(roleID string, config IteratorConfig) *Iterator[models.APIResourceScope] {
	fetcher := func(ctx context.Context, page, pageSize int) (PageResult[models.APIResourceScope], error) {
		if roleID == "" {
			return PageResult[models.APIResourceScope]{}, &ValidationError{Field: "roleID", Message: "cannot be empty"}
		}
		return a.listRoleScopesPaginated(ctx, roleID, page, pageSize)
	}
	return NewIterator(fetcher, config)
}

// listRoleScopesPaginated returns role scopes with pagination support
func (a *Adapter) listRoleScopesPaginated(ctx context.Context, roleID string, page, pageSize int) (PageResult[models.APIResourceScope], error) {
	result, err := a.doRequestFull(ctx, requestConfig{
		method:     http.MethodGet,
		path:       "/api/roles/%s/scopes",
		pathParams: []string{roleID},
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
		return PageResult[models.APIResourceScope]{}, fmt.Errorf("unmarshal role scopes: %w", err)
	}

	return PageResult[models.APIResourceScope]{
		Items: scopes,
		Total: getTotalFromHeaders(result.Headers),
	}, nil
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

// RemoveScopeFromRole removes an API resource scope from a role
func (a *Adapter) RemoveScopeFromRole(ctx context.Context, roleID, scopeID string) error {
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

// ListRoleUsers returns an iterator for users assigned to a role.
func (a *Adapter) ListRoleUsers(roleID string, config IteratorConfig) *Iterator[models.User] {
	fetcher := func(ctx context.Context, page, pageSize int) (PageResult[models.User], error) {
		if roleID == "" {
			return PageResult[models.User]{}, &ValidationError{Field: "roleID", Message: "cannot be empty"}
		}
		return a.listRoleUsersPaginated(ctx, roleID, page, pageSize)
	}
	return NewIterator(fetcher, config)
}

// listRoleUsersPaginated returns role users with pagination support
func (a *Adapter) listRoleUsersPaginated(ctx context.Context, roleID string, page, pageSize int) (PageResult[models.User], error) {
	result, err := a.doRequestFull(ctx, requestConfig{
		method:     http.MethodGet,
		path:       "/api/roles/%s/users",
		pathParams: []string{roleID},
		query: url.Values{
			"page":      {fmt.Sprintf("%d", page)},
			"page_size": {fmt.Sprintf("%d", pageSize)},
		},
	})
	if err != nil {
		return PageResult[models.User]{}, err
	}

	var users []models.User
	if err := json.Unmarshal(result.Body, &users); err != nil {
		return PageResult[models.User]{}, fmt.Errorf("unmarshal role users: %w", err)
	}

	return PageResult[models.User]{
		Items: users,
		Total: getTotalFromHeaders(result.Headers),
	}, nil
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

// ListRoleApplications returns an iterator for M2M applications assigned to a role.
func (a *Adapter) ListRoleApplications(roleID string, config IteratorConfig) *Iterator[models.Application] {
	fetcher := func(ctx context.Context, page, pageSize int) (PageResult[models.Application], error) {
		if roleID == "" {
			return PageResult[models.Application]{}, &ValidationError{Field: "roleID", Message: "cannot be empty"}
		}
		return a.listRoleApplicationsPaginated(ctx, roleID, page, pageSize)
	}
	return NewIterator(fetcher, config)
}

// listRoleApplicationsPaginated returns role applications with pagination support
func (a *Adapter) listRoleApplicationsPaginated(ctx context.Context, roleID string, page, pageSize int) (PageResult[models.Application], error) {
	result, err := a.doRequestFull(ctx, requestConfig{
		method:     http.MethodGet,
		path:       "/api/roles/%s/applications",
		pathParams: []string{roleID},
		query: url.Values{
			"page":      {fmt.Sprintf("%d", page)},
			"page_size": {fmt.Sprintf("%d", pageSize)},
		},
	})
	if err != nil {
		return PageResult[models.Application]{}, err
	}

	var apps []models.Application
	if err := json.Unmarshal(result.Body, &apps); err != nil {
		return PageResult[models.Application]{}, fmt.Errorf("unmarshal role applications: %w", err)
	}

	return PageResult[models.Application]{
		Items: apps,
		Total: getTotalFromHeaders(result.Headers),
	}, nil
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
func (a *Adapter) CreateOrganizationInvitation(ctx context.Context, invitation models.OrganizationInvitationCreate) (*models.OrganizationInvitation, error) {
	if invitation.OrganizationID == "" {
		return nil, &ValidationError{Field: "organizationId", Message: "cannot be empty"}
	}
	if invitation.Invitee == "" {
		return nil, &ValidationError{Field: "invitee", Message: "cannot be empty"}
	}

	payload := map[string]interface{}{
		"organizationId": invitation.OrganizationID,
		"invitee":        invitation.Invitee,
		"expiresAt":      invitation.ExpiresAt.UnixMilli(),
		"messagePayload": false, // We'll send our own emails
	}

	if invitation.InviterID != "" {
		payload["inviterId"] = invitation.InviterID
	}

	if len(invitation.OrganizationRoleIDs) > 0 {
		payload["organizationRoleIds"] = invitation.OrganizationRoleIDs
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:      http.MethodPost,
		path:        "/api/organization-invitations",
		body:        payload,
		expectCodes: []int{http.StatusOK, http.StatusCreated},
	})
	if err != nil {
		return nil, err
	}

	return parseInvitationResponse(body)
}

// ListOrganizationInvitations returns an iterator for invitations for an organization.
func (a *Adapter) ListOrganizationInvitations(orgID string, config IteratorConfig) *Iterator[models.OrganizationInvitation] {
	fetcher := func(ctx context.Context, page, pageSize int) (PageResult[models.OrganizationInvitation], error) {
		if orgID == "" {
			return PageResult[models.OrganizationInvitation]{}, &ValidationError{Field: "orgID", Message: "cannot be empty"}
		}
		return a.listOrganizationInvitationsPaginated(ctx, orgID, page, pageSize)
	}
	return NewIterator(fetcher, config)
}

// listOrganizationInvitationsPaginated returns organization invitations with pagination support
func (a *Adapter) listOrganizationInvitationsPaginated(ctx context.Context, orgID string, page, pageSize int) (PageResult[models.OrganizationInvitation], error) {
	result, err := a.doRequestFull(ctx, requestConfig{
		method: http.MethodGet,
		path:   "/api/organization-invitations",
		query: url.Values{
			"organizationId": {orgID},
			"page":           {fmt.Sprintf("%d", page)},
			"page_size":      {fmt.Sprintf("%d", pageSize)},
		},
	})
	if err != nil {
		return PageResult[models.OrganizationInvitation]{}, err
	}

	var invitations []models.OrganizationInvitation
	if err := json.Unmarshal(result.Body, &invitations); err != nil {
		return PageResult[models.OrganizationInvitation]{}, fmt.Errorf("unmarshal invitations: %w", err)
	}

	return PageResult[models.OrganizationInvitation]{
		Items: invitations,
		Total: getTotalFromHeaders(result.Headers),
	}, nil
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
		expectCodes: []int{http.StatusOK, http.StatusNoContent},
	})
}

// SendInvitationMessage sends the invitation email with a magic link
func (a *Adapter) SendInvitationMessage(ctx context.Context, invitationID, magicLink string) error {
	if invitationID == "" {
		return &ValidationError{Field: "invitationID", Message: "cannot be empty"}
	}
	if magicLink == "" {
		return &ValidationError{Field: "magicLink", Message: "cannot be empty"}
	}

	return a.doNoContent(ctx, requestConfig{
		method:     http.MethodPost,
		path:       "/api/organization-invitations/%s/message",
		pathParams: []string{invitationID},
		body: map[string]interface{}{
			"link": magicLink,
		},
		expectCodes: []int{http.StatusOK, http.StatusNoContent},
	})
}

// CreateOneTimeToken creates a one-time token for magic link authentication
func (a *Adapter) CreateOneTimeToken(ctx context.Context, token models.OneTimeTokenCreate) (*models.OneTimeTokenResult, error) {
	if token.Email == "" {
		return nil, &ValidationError{Field: "email", Message: "cannot be empty"}
	}

	payload := map[string]interface{}{
		"email": token.Email,
	}

	if token.ExpiresIn > 0 {
		payload["expiresIn"] = token.ExpiresIn
	}

	if len(token.JitOrganizationIDs) > 0 {
		payload["context"] = map[string]interface{}{
			"jitOrganizationIds": token.JitOrganizationIDs,
		}
	}

	var result models.OneTimeTokenResult
	err := a.doJSON(ctx, requestConfig{
		method:      http.MethodPost,
		path:        "/api/one-time-tokens",
		body:        payload,
		expectCodes: []int{http.StatusOK, http.StatusCreated},
	}, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// Helper functions

func parseInvitationResponse(data []byte) (*models.OrganizationInvitation, error) {
	var inv models.OrganizationInvitation
	if err := json.Unmarshal(data, &inv); err != nil {
		return nil, fmt.Errorf("parse invitation: %w", err)
	}
	return &inv, nil
}

func parseApplicationResponse(data []byte) (*models.Application, error) {
	var app models.Application
	if err := json.Unmarshal(data, &app); err != nil {
		return nil, fmt.Errorf("parse application: %w", err)
	}
	if app.CustomData == nil {
		app.CustomData = make(map[string]interface{})
	}
	return &app, nil
}

