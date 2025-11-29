package logto

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestBuildURL_EscapesPathParams(t *testing.T) {
	adapter, _ := New("https://example.com", "app-id", "secret")

	tests := []struct {
		name       string
		path       string
		pathParams []string
		query      url.Values
		want       string
	}{
		{
			name:       "simple path",
			path:       "/api/users/%s",
			pathParams: []string{"user123"},
			want:       "https://example.com/api/users/user123",
		},
		{
			name:       "path with special characters",
			path:       "/api/users/%s",
			pathParams: []string{"user/with/slash"},
			want:       "https://example.com/api/users/user%2Fwith%2Fslash",
		},
		{
			name:       "path with spaces",
			path:       "/api/users/%s",
			pathParams: []string{"user name"},
			want:       "https://example.com/api/users/user%20name",
		},
		{
			name:       "multiple path params",
			path:       "/api/orgs/%s/users/%s",
			pathParams: []string{"org/id", "user/id"},
			want:       "https://example.com/api/orgs/org%2Fid/users/user%2Fid",
		},
		{
			name:       "with query params",
			path:       "/api/users",
			pathParams: nil,
			query:      url.Values{"page": {"1"}, "size": {"10"}},
			want:       "https://example.com/api/users?page=1&size=10",
		},
		{
			name:       "no path params",
			path:       "/api/users",
			pathParams: nil,
			want:       "https://example.com/api/users",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := adapter.buildURL(tt.path, tt.pathParams, tt.query)
			if got != tt.want {
				t.Errorf("buildURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDoRequest_UsesRetry(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Token endpoint
		if r.URL.Path == "/oidc/token" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "test-token",
				"expires_in":   3600,
			})
			return
		}
		// API endpoint - fail first time, succeed second
		attempts++
		if attempts == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"id": "test"})
	}))
	defer server.Close()

	adapter, _ := New(server.URL, "app-id", "secret",
		WithRetry(3, 10*time.Millisecond))

	ctx := context.Background()
	_, _, err := adapter.doRequest(ctx, requestConfig{
		method: http.MethodGet,
		path:   "/api/users/123",
	})

	if err != nil {
		t.Errorf("doRequest() error = %v, expected success after retry", err)
	}
	if attempts != 2 {
		t.Errorf("expected 2 attempts, got %d", attempts)
	}
}

func TestDoRequest_ReturnsAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Token endpoint
		if r.URL.Path == "/oidc/token" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "test-token",
				"expires_in":   3600,
			})
			return
		}
		// API endpoint returns error
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "User not found",
			"code":    "entity.not_found",
		})
	}))
	defer server.Close()

	adapter, _ := New(server.URL, "app-id", "secret")

	ctx := context.Background()
	_, _, err := adapter.doRequest(ctx, requestConfig{
		method: http.MethodGet,
		path:   "/api/users/123",
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}

	if apiErr.StatusCode != 404 {
		t.Errorf("expected status 404, got %d", apiErr.StatusCode)
	}
	if apiErr.Code != "entity.not_found" {
		t.Errorf("expected code 'entity.not_found', got %q", apiErr.Code)
	}
	if apiErr.Message != "User not found" {
		t.Errorf("expected message 'User not found', got %q", apiErr.Message)
	}
}

func TestDoJSON_UnmarshalSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oidc/token" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "test-token",
				"expires_in":   3600,
			})
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":   "user-123",
			"name": "Test User",
		})
	}))
	defer server.Close()

	adapter, _ := New(server.URL, "app-id", "secret")

	var result struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}

	err := adapter.doJSON(context.Background(), requestConfig{
		method: http.MethodGet,
		path:   "/api/users/123",
	}, &result)

	if err != nil {
		t.Fatalf("doJSON() error = %v", err)
	}
	if result.ID != "user-123" {
		t.Errorf("expected id 'user-123', got %q", result.ID)
	}
	if result.Name != "Test User" {
		t.Errorf("expected name 'Test User', got %q", result.Name)
	}
}

func TestDoNoContent_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oidc/token" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "test-token",
				"expires_in":   3600,
			})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	adapter, _ := New(server.URL, "app-id", "secret")

	err := adapter.doNoContent(context.Background(), requestConfig{
		method:      http.MethodDelete,
		path:        "/api/users/123",
		expectCodes: []int{http.StatusNoContent},
	})

	if err != nil {
		t.Errorf("doNoContent() error = %v", err)
	}
}

func TestIsExpectedStatus(t *testing.T) {
	tests := []struct {
		code     int
		expected []int
		want     bool
	}{
		{200, nil, true},        // default checks for 200
		{201, nil, false},       // default only 200
		{200, []int{200}, true}, // explicit 200
		{201, []int{200, 201}, true},
		{204, []int{200, 201}, false},
		{404, []int{404}, true},
	}

	for _, tt := range tests {
		got := isExpectedStatus(tt.code, tt.expected)
		if got != tt.want {
			t.Errorf("isExpectedStatus(%d, %v) = %v, want %v",
				tt.code, tt.expected, got, tt.want)
		}
	}
}
