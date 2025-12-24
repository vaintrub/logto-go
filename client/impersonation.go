package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SubjectTokenResult represents the response from creating a subject token.
type SubjectTokenResult struct {
	// SubjectToken is the token to exchange for an access token
	SubjectToken string `json:"subjectToken"`
	// ExpiresIn is the token lifetime in seconds
	ExpiresIn int `json:"expiresIn"`
}

// SubjectTokenContext contains optional context for subject token creation.
// This context can be used in Custom Token Claims scripts in Logto.
type SubjectTokenContext map[string]any

// TokenExchangeOption configures token exchange behavior.
type TokenExchangeOption func(*tokenExchangeOptions)

type tokenExchangeOptions struct {
	organizationID string
	scopes         []string
	resource       string
}

// WithOrganizationID sets the organization context for the exchanged token.
func WithOrganizationID(orgID string) TokenExchangeOption {
	return func(o *tokenExchangeOptions) {
		o.organizationID = orgID
	}
}

// WithScopes sets the scopes for the exchanged token.
func WithScopes(scopes ...string) TokenExchangeOption {
	return func(o *tokenExchangeOptions) {
		o.scopes = scopes
	}
}

// WithExchangeResource sets the resource (audience) for the exchanged token.
// If not set, uses the default resource from client configuration.
func WithExchangeResource(resource string) TokenExchangeOption {
	return func(o *tokenExchangeOptions) {
		o.resource = resource
	}
}

// CreateSubjectToken creates a subject token for user impersonation.
//
// This is the first step in the token exchange flow for user impersonation.
// The subject token can then be exchanged for an access token using ExchangeSubjectToken.
//
// The context parameter is optional and can be used to pass custom data
// that will be available in Custom Token Claims scripts in Logto.
//
// See: https://docs.logto.io/developers/user-impersonation
func (a *Adapter) CreateSubjectToken(ctx context.Context, userID string, tokenCtx SubjectTokenContext) (*SubjectTokenResult, error) {
	if userID == "" {
		return nil, &ValidationError{Field: "userID", Message: "cannot be empty"}
	}

	payload := map[string]any{
		"userId": userID,
	}

	if len(tokenCtx) > 0 {
		payload["context"] = tokenCtx
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:      http.MethodPost,
		path:        "/api/subject-tokens",
		body:        payload,
		expectCodes: []int{http.StatusOK, http.StatusCreated},
	})
	if err != nil {
		return nil, err
	}

	var result SubjectTokenResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("unmarshal subject token response: %w", err)
	}

	return &result, nil
}

// ExchangeSubjectToken exchanges a subject token for an access token.
//
// This implements RFC 8693 Token Exchange with grant type
// "urn:ietf:params:oauth:grant-type:token-exchange".
//
// Options can be used to specify organization context and scopes for the token.
//
// See: https://docs.logto.io/developers/user-impersonation
func (a *Adapter) ExchangeSubjectToken(ctx context.Context, subjectToken string, opts ...TokenExchangeOption) (*TokenResult, error) {
	if subjectToken == "" {
		return nil, &ValidationError{Field: "subjectToken", Message: "cannot be empty"}
	}

	// Apply options
	var defaultScopes []string
	if a.opts.scope != "" {
		defaultScopes = []string{a.opts.scope}
	}
	o := &tokenExchangeOptions{
		resource: a.opts.resource,
		scopes:   defaultScopes,
	}
	for _, opt := range opts {
		opt(o)
	}

	tokenURL := fmt.Sprintf("%s/oidc/token", a.endpoint)

	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	data.Set("subject_token", subjectToken)
	data.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	data.Set("client_id", a.m2mAppID)

	if o.resource != "" {
		data.Set("resource", o.resource)
	}

	if len(o.scopes) > 0 {
		data.Set("scope", strings.Join(o.scopes, " "))
	}

	if o.organizationID != "" {
		data.Set("organization_id", o.organizationID)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	// Use Basic Auth as required by Logto documentation for token exchange
	req.Header.Set("Authorization", "Basic "+a.cachedCredentials)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	const maxResponseSize = 10 * 1024 * 1024 // 10MB
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		requestID := resp.Header.Get("X-Request-Id")
		return nil, newAPIErrorFromResponse(resp.StatusCode, respBody, requestID)
	}

	var result TokenResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("unmarshal token exchange response: %w", err)
	}

	// Compute ExpiresAt for convenient cache TTL calculation
	result.ExpiresAt = time.Now().Add(time.Duration(result.ExpiresIn) * time.Second)

	return &result, nil
}

// GetUserAccessToken is a convenience method that obtains an access token
// for a specific user using the Subject Token Impersonation flow.
//
// This combines CreateSubjectToken and ExchangeSubjectToken into a single call.
// The returned token can be used to make API calls on behalf of the user.
//
// Options can specify organization context and scopes for the token.
//
// Example usage:
//
//	token, err := client.GetUserAccessToken(ctx, userID,
//	    WithOrganizationID("org_123"),
//	    WithScopes("read:members", "write:members"),
//	)
//	if err != nil {
//	    return err
//	}
//	// Use token.AccessToken in Authorization header
//
// See: https://docs.logto.io/developers/user-impersonation
func (a *Adapter) GetUserAccessToken(ctx context.Context, userID string, opts ...TokenExchangeOption) (*TokenResult, error) {
	// Step 1: Create subject token
	subject, err := a.CreateSubjectToken(ctx, userID, nil)
	if err != nil {
		return nil, fmt.Errorf("create subject token: %w", err)
	}

	// Step 2: Exchange for access token
	return a.ExchangeSubjectToken(ctx, subject.SubjectToken, opts...)
}
