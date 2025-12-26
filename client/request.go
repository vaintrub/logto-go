package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// requestConfig contains parameters for an HTTP request.
type requestConfig struct {
	method      string      // HTTP method (GET, POST, PUT, PATCH, DELETE)
	path        string      // URL path template, e.g. "/api/users/%s"
	pathParams  []string    // Parameters to substitute in path (will be URL-escaped)
	query       url.Values  // Query parameters
	body        interface{} // Request body (will be JSON-encoded)
	expectCodes []int       // Expected HTTP status codes (default: 200)
}

// doRequest executes an API request with authentication, URL building, and error handling.
// Returns response body, status code, and error.
func (a *Adapter) doRequest(ctx context.Context, cfg requestConfig) ([]byte, int, error) {
	// 1. Authenticate
	tokenResult, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("authentication failed: %w", err)
	}
	token := tokenResult.AccessToken

	// 2. Build URL with escaped path parameters
	apiURL := a.buildURL(cfg.path, cfg.pathParams, cfg.query)

	// 3. Serialize body if present
	var bodyReader io.Reader
	var bodyBytes []byte
	if cfg.body != nil {
		bodyBytes, err = json.Marshal(cfg.body)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	// 4. Create request
	req, err := http.NewRequestWithContext(ctx, cfg.method, apiURL, bodyReader)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	// 5. Set headers
	req.Header.Set("Authorization", "Bearer "+token)
	if cfg.body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// 6. Execute request
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	// 8. Read response body (with size limit to prevent DoS)
	const maxResponseSize = 10 * 1024 * 1024 // 10MB
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to read response: %w", err)
	}

	// 9. Check status code
	if !isExpectedStatus(resp.StatusCode, cfg.expectCodes) {
		requestID := resp.Header.Get("X-Request-Id")
		return respBody, resp.StatusCode, newAPIErrorFromResponse(resp.StatusCode, respBody, requestID)
	}

	return respBody, resp.StatusCode, nil
}

// doJSON executes an API request and unmarshals the JSON response into result.
func (a *Adapter) doJSON(ctx context.Context, cfg requestConfig, result interface{}) error {
	body, _, err := a.doRequest(ctx, cfg)
	if err != nil {
		return err
	}

	if result != nil && len(body) > 0 {
		// Validate that body looks like JSON before parsing
		trimmed := bytes.TrimSpace(body)
		if len(trimmed) > 0 && trimmed[0] != '{' && trimmed[0] != '[' {
			// Truncate body for error message if too long
			preview := string(body)
			if len(preview) > 200 {
				preview = preview[:200] + "..."
			}
			return fmt.Errorf("expected JSON response but got: %s", preview)
		}

		if err := json.Unmarshal(body, result); err != nil {
			return fmt.Errorf("failed to unmarshal response: %w", err)
		}
	}

	return nil
}

// doNoContent executes an API request that expects no response body (e.g., DELETE).
func (a *Adapter) doNoContent(ctx context.Context, cfg requestConfig) error {
	_, _, err := a.doRequest(ctx, cfg)
	return err
}

// requestResult contains the full response from an HTTP request.
type requestResult struct {
	Body       []byte
	StatusCode int
	Headers    http.Header
}

// doRequestFull executes an API request and returns full response including headers.
// Used for paginated endpoints that need Total-Number header.
func (a *Adapter) doRequestFull(ctx context.Context, cfg requestConfig) (*requestResult, error) {
	// 1. Authenticate
	tokenResult, err := a.AuthenticateM2M(ctx)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}
	token := tokenResult.AccessToken

	// 2. Build URL with escaped path parameters
	apiURL := a.buildURL(cfg.path, cfg.pathParams, cfg.query)

	// 3. Serialize body if present
	var bodyReader io.Reader
	if cfg.body != nil {
		bodyBytes, err := json.Marshal(cfg.body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	// 4. Create request
	req, err := http.NewRequestWithContext(ctx, cfg.method, apiURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// 5. Set headers
	req.Header.Set("Authorization", "Bearer "+token)
	if cfg.body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// 6. Execute request
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	// 7. Read response body
	const maxResponseSize = 10 * 1024 * 1024 // 10MB
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// 8. Check status code
	if !isExpectedStatus(resp.StatusCode, cfg.expectCodes) {
		requestID := resp.Header.Get("X-Request-Id")
		return nil, newAPIErrorFromResponse(resp.StatusCode, respBody, requestID)
	}

	return &requestResult{
		Body:       respBody,
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
	}, nil
}

// getTotalFromHeaders extracts Total-Number header value.
// Returns -1 if header is not present or invalid.
func getTotalFromHeaders(headers http.Header) int {
	totalStr := headers.Get("Total-Number")
	if totalStr == "" {
		return -1
	}
	total, err := strconv.Atoi(totalStr)
	if err != nil {
		return -1
	}
	return total
}

// buildURL constructs a full URL with escaped path parameters and query string.
func (a *Adapter) buildURL(pathTemplate string, pathParams []string, query url.Values) string {
	// Escape all path parameters
	var path string
	if len(pathParams) > 0 {
		escapedParams := make([]interface{}, len(pathParams))
		for i, p := range pathParams {
			escapedParams[i] = url.PathEscape(p)
		}
		path = fmt.Sprintf(pathTemplate, escapedParams...)
	} else {
		path = pathTemplate
	}

	result := a.endpoint + path

	if len(query) > 0 {
		result += "?" + query.Encode()
	}

	return result
}
