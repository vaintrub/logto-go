package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vaintrub/logto-go/models"
)

// === Helper functions ===

// newTestAdapter creates an Adapter pointing to the given test server.
func newTestAdapter(t *testing.T, serverURL string) *Adapter {
	t.Helper()
	adapter, err := New(
		serverURL,
		"test-app-id",
		"test-app-secret",
	)
	if err != nil {
		t.Fatalf("failed to create adapter: %v", err)
	}
	return adapter
}

// mockM2MTokenResponse returns a handler that responds to M2M token requests.
func mockM2MTokenResponse(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == "/oidc/token" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-token",
			"expires_in":   3600,
		})
		return true
	}
	return false
}

// === Constructor and validation tests ===

func TestNew_Validation(t *testing.T) {
	tests := []struct {
		name        string
		endpoint    string
		m2mAppID    string
		m2mSecret   string
		wantErr     bool
		wantErrType error
	}{
		{
			name:        "empty endpoint returns ValidationError",
			endpoint:    "",
			m2mAppID:    "app-id",
			m2mSecret:   "secret",
			wantErr:     true,
			wantErrType: ErrInvalidInput,
		},
		{
			name:        "empty m2mAppID returns ValidationError",
			endpoint:    "http://localhost",
			m2mAppID:    "",
			m2mSecret:   "secret",
			wantErr:     true,
			wantErrType: ErrInvalidInput,
		},
		{
			name:        "empty m2mAppSecret returns ValidationError",
			endpoint:    "http://localhost",
			m2mAppID:    "app-id",
			m2mSecret:   "",
			wantErr:     true,
			wantErrType: ErrInvalidInput,
		},
		{
			name:        "valid params succeeds",
			endpoint:    "http://localhost",
			m2mAppID:    "app-id",
			m2mSecret:   "secret",
			wantErr:     false,
			wantErrType: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.endpoint, tt.m2mAppID, tt.m2mSecret)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if tt.wantErrType != nil && !errors.Is(err, tt.wantErrType) {
					t.Errorf("expected error to be %v, got %v", tt.wantErrType, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestNew_Options(t *testing.T) {
	t.Run("defaults are applied", func(t *testing.T) {
		adapter, err := New("http://localhost", "app-id", "secret")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if adapter.opts.timeout != 5*time.Second {
			t.Errorf("expected default timeout 5s, got %v", adapter.opts.timeout)
		}
		if adapter.opts.resource != "https://default.logto.app/api" {
			t.Errorf("expected default resource, got %s", adapter.opts.resource)
		}
		if adapter.opts.scope != "all" {
			t.Errorf("expected default scope 'all', got %s", adapter.opts.scope)
		}
	})

	t.Run("WithTimeout sets timeout", func(t *testing.T) {
		adapter, _ := New("http://localhost", "app-id", "secret", WithTimeout(60*time.Second))
		if adapter.opts.timeout != 60*time.Second {
			t.Errorf("expected timeout 60s, got %v", adapter.opts.timeout)
		}
	})

	t.Run("WithResource sets resource", func(t *testing.T) {
		adapter, _ := New("http://localhost", "app-id", "secret", WithResource("https://custom.api"))
		if adapter.opts.resource != "https://custom.api" {
			t.Errorf("expected custom resource, got %s", adapter.opts.resource)
		}
	})

	t.Run("WithScope sets scope", func(t *testing.T) {
		adapter, _ := New("http://localhost", "app-id", "secret", WithScope("read write"))
		if adapter.opts.scope != "read write" {
			t.Errorf("expected scope 'read write', got %s", adapter.opts.scope)
		}
	})

	t.Run("WithHTTPClient overrides default client", func(t *testing.T) {
		customClient := &http.Client{Timeout: 120 * time.Second}
		adapter, _ := New("http://localhost", "app-id", "secret", WithHTTPClient(customClient))
		if adapter.httpClient != customClient {
			t.Error("expected custom HTTP client to be used")
		}
	})

	t.Run("WithResponseHeaderTimeout sets responseHeaderTimeout", func(t *testing.T) {
		adapter, _ := New("http://localhost", "app-id", "secret", WithResponseHeaderTimeout(45*time.Second))
		if adapter.opts.responseHeaderTimeout != 45*time.Second {
			t.Errorf("expected responseHeaderTimeout 45s, got %v", adapter.opts.responseHeaderTimeout)
		}
	})

	t.Run("WithIdleConnTimeout sets idleConnTimeout", func(t *testing.T) {
		adapter, _ := New("http://localhost", "app-id", "secret", WithIdleConnTimeout(120*time.Second))
		if adapter.opts.idleConnTimeout != 120*time.Second {
			t.Errorf("expected idleConnTimeout 120s, got %v", adapter.opts.idleConnTimeout)
		}
	})

	t.Run("defaults include transport timeouts", func(t *testing.T) {
		adapter, _ := New("http://localhost", "app-id", "secret")
		if adapter.opts.responseHeaderTimeout != 30*time.Second {
			t.Errorf("expected default responseHeaderTimeout 30s, got %v", adapter.opts.responseHeaderTimeout)
		}
		if adapter.opts.idleConnTimeout != 90*time.Second {
			t.Errorf("expected default idleConnTimeout 90s, got %v", adapter.opts.idleConnTimeout)
		}
	})

	t.Run("zero values are ignored for transport timeouts", func(t *testing.T) {
		adapter, _ := New("http://localhost", "app-id", "secret",
			WithResponseHeaderTimeout(0),
			WithIdleConnTimeout(-1*time.Second),
		)
		// Should keep defaults when invalid values provided
		if adapter.opts.responseHeaderTimeout != 30*time.Second {
			t.Errorf("expected default responseHeaderTimeout 30s, got %v", adapter.opts.responseHeaderTimeout)
		}
		if adapter.opts.idleConnTimeout != 90*time.Second {
			t.Errorf("expected default idleConnTimeout 90s, got %v", adapter.opts.idleConnTimeout)
		}
	})
}

// === Error types tests ===

func TestAPIError_Is(t *testing.T) {
	tests := []struct {
		statusCode int
		target     error
		expected   bool
	}{
		{400, ErrBadRequest, true},
		{401, ErrUnauthorized, true},
		{403, ErrForbidden, true},
		{404, ErrNotFound, true},
		{409, ErrConflict, true},
		{422, ErrUnprocessableEntity, true},
		{429, ErrRateLimited, true},
		{500, ErrServerError, true},
		{502, ErrServerError, true},
		{503, ErrServerError, true},
		{504, ErrServerError, true},
		{200, ErrNotFound, false},
		{400, ErrNotFound, false},
		{404, ErrBadRequest, false},
		{409, ErrNotFound, false},
		{422, ErrBadRequest, false},
	}

	for _, tt := range tests {
		name := fmt.Sprintf("%d→%v=%v", tt.statusCode, tt.target, tt.expected)
		t.Run(name, func(t *testing.T) {
			err := &APIError{StatusCode: tt.statusCode, Message: "test"}
			if got := errors.Is(err, tt.target); got != tt.expected {
				t.Errorf("APIError{StatusCode: %d}.Is(%v) = %v, want %v",
					tt.statusCode, tt.target, got, tt.expected)
			}
		})
	}
}

func TestValidationError_Is(t *testing.T) {
	err := &ValidationError{Field: "test", Message: "error"}
	if !errors.Is(err, ErrInvalidInput) {
		t.Error("ValidationError should match ErrInvalidInput")
	}
}

func TestAPIError_Error(t *testing.T) {
	t.Run("with code", func(t *testing.T) {
		err := &APIError{StatusCode: 404, Message: "not found", Code: "NOT_FOUND"}
		expected := "logto api error (status 404, code NOT_FOUND): not found"
		if err.Error() != expected {
			t.Errorf("got %q, want %q", err.Error(), expected)
		}
	})

	t.Run("without code", func(t *testing.T) {
		err := &APIError{StatusCode: 404, Message: "not found"}
		expected := "logto api error (status 404): not found"
		if err.Error() != expected {
			t.Errorf("got %q, want %q", err.Error(), expected)
		}
	})
}

func TestValidationError_Error(t *testing.T) {
	err := &ValidationError{Field: "name", Message: "cannot be empty"}
	expected := "validation error: name: cannot be empty"
	if err.Error() != expected {
		t.Errorf("got %q, want %q", err.Error(), expected)
	}
}

func TestAPIError_Unwrap(t *testing.T) {
	err := &APIError{StatusCode: 404, Message: "not found"}
	if err.Unwrap() != nil {
		t.Error("APIError.Unwrap() should return nil")
	}
}

func TestValidationError_Unwrap(t *testing.T) {
	err := &ValidationError{Field: "test", Message: "error"}
	if err.Unwrap() != ErrInvalidInput {
		t.Error("ValidationError.Unwrap() should return ErrInvalidInput")
	}
}

func TestNewAPIErrorFromResponse(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		body        string
		requestID   string
		wantMessage string
		wantCode    string
	}{
		{
			name:        "json with message and code",
			statusCode:  400,
			body:        `{"message": "Invalid input", "code": "INVALID_INPUT"}`,
			requestID:   "req-123",
			wantMessage: "Invalid input",
			wantCode:    "INVALID_INPUT",
		},
		{
			name:        "json with only message",
			statusCode:  404,
			body:        `{"message": "User not found"}`,
			requestID:   "",
			wantMessage: "User not found",
			wantCode:    "",
		},
		{
			name:        "plain text",
			statusCode:  500,
			body:        `Internal Server Error`,
			requestID:   "req-456",
			wantMessage: "Internal Server Error",
			wantCode:    "",
		},
		{
			name:        "empty body",
			statusCode:  204,
			body:        "",
			requestID:   "",
			wantMessage: "",
			wantCode:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := newAPIErrorFromResponse(tt.statusCode, []byte(tt.body), tt.requestID)
			if err.StatusCode != tt.statusCode {
				t.Errorf("StatusCode = %d, want %d", err.StatusCode, tt.statusCode)
			}
			if err.Message != tt.wantMessage {
				t.Errorf("Message = %q, want %q", err.Message, tt.wantMessage)
			}
			if err.Code != tt.wantCode {
				t.Errorf("Code = %q, want %q", err.Code, tt.wantCode)
			}
			if err.RequestID != tt.requestID {
				t.Errorf("RequestID = %q, want %q", err.RequestID, tt.requestID)
			}
			if string(err.Body) != tt.body {
				t.Errorf("Body = %q, want %q", string(err.Body), tt.body)
			}
		})
	}
}

// === HTTP API tests ===

func TestGetUser_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mockM2MTokenResponse(w, r) {
			return
		}

		if r.URL.Path == "/api/users/user-123" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id":           "user-123",
				"name":         "Test User",
				"primaryEmail": "test@example.com",
				"avatar":       "https://example.com/avatar.png",
				"isSuspended":  false,
				"customData":   map[string]interface{}{"key": "value"},
				"createdAt":    1700000000000,
				"updatedAt":    1700000001000,
			})
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	adapter := newTestAdapter(t, server.URL)
	user, err := adapter.GetUser(context.Background(), "user-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if user.ID != "user-123" {
		t.Errorf("expected user ID 'user-123', got %q", user.ID)
	}
	if user.Name != "Test User" {
		t.Errorf("expected name 'Test User', got %q", user.Name)
	}
	if user.PrimaryEmail != "test@example.com" {
		t.Errorf("expected email 'test@example.com', got %q", user.PrimaryEmail)
	}
}

func TestGetUser_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mockM2MTokenResponse(w, r) {
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message": "user not found"}`))
	}))
	defer server.Close()

	adapter := newTestAdapter(t, server.URL)
	_, err := adapter.GetUser(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

}

func TestListUsers_EmptyArray(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mockM2MTokenResponse(w, r) {
			return
		}

		if r.URL.Path == "/api/users" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[]`))
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	adapter := newTestAdapter(t, server.URL)
	users, err := adapter.ListUsers(DefaultIteratorConfig()).Collect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(users) != 0 {
		t.Errorf("expected empty slice, got %d users", len(users))
	}
}

// === Iterator tests ===

func TestUserIterator_Collect(t *testing.T) {
	var page int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mockM2MTokenResponse(w, r) {
			return
		}

		if r.URL.Path == "/api/users" {
			page++
			w.Header().Set("Content-Type", "application/json")

			if page == 1 {
				_, _ = w.Write([]byte(`[
					{"id": "user-1", "primaryEmail": "user1@test.com", "createdAt": 1700000000000, "updatedAt": 1700000000000},
					{"id": "user-2", "primaryEmail": "user2@test.com", "createdAt": 1700000000000, "updatedAt": 1700000000000}
				]`))
				return
			}

			// Second page is empty
			_, _ = w.Write([]byte(`[]`))
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	adapter := newTestAdapter(t, server.URL)
	ctx := context.Background()
	iter := adapter.ListUsers(IteratorConfig{PageSize: 10})

	users, err := iter.Collect(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(users) != 2 {
		t.Errorf("expected 2 users, got %d", len(users))
	}
}

func TestUserIterator_Next(t *testing.T) {
	var page int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mockM2MTokenResponse(w, r) {
			return
		}

		if r.URL.Path == "/api/users" {
			page++
			w.Header().Set("Content-Type", "application/json")

			if page == 1 {
				_, _ = w.Write([]byte(`[
					{"id": "user-1", "primaryEmail": "user1@test.com", "createdAt": 1700000000000, "updatedAt": 1700000000000}
				]`))
				return
			}

			_, _ = w.Write([]byte(`[]`))
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	adapter := newTestAdapter(t, server.URL)
	ctx := context.Background()
	iter := adapter.ListUsers(IteratorConfig{PageSize: 10})

	// First call to Next should succeed
	if !iter.Next(ctx) {
		t.Fatal("expected Next() to return true")
	}

	user := iter.Item()
	if user == nil {
		t.Fatal("expected user, got nil")
	}
	if user.ID != "user-1" {
		t.Errorf("expected user-1, got %s", user.ID)
	}

	// Second call should return false (no more users)
	if iter.Next(ctx) {
		t.Error("expected Next() to return false")
	}

	if iter.Err() != nil {
		t.Errorf("unexpected error: %v", iter.Err())
	}
}

func TestUserIterator_Error(t *testing.T) {
	var page int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mockM2MTokenResponse(w, r) {
			return
		}

		if r.URL.Path == "/api/users" {
			page++
			if page == 1 {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`[
					{"id": "user-1", "primaryEmail": "user1@test.com", "createdAt": 1700000000000, "updatedAt": 1700000000000}
				]`))
				return
			}
			// Second request returns error
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	adapter := newTestAdapter(t, server.URL)
	ctx := context.Background()
	iter := adapter.ListUsers(IteratorConfig{PageSize: 1})

	// First page succeeds
	if !iter.Next(ctx) {
		t.Fatal("expected first Next() to return true")
	}

	// Second call should fail
	if iter.Next(ctx) {
		t.Error("expected Next() to return false on error")
	}

	if iter.Err() == nil {
		t.Error("expected error after failed request")
	}
}

// === M2M Authentication tests ===

func TestAuthenticateM2M_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oidc/token" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "test-access-token",
				"expires_in":   3600,
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	adapter := newTestAdapter(t, server.URL)
	result, err := adapter.AuthenticateM2M(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.AccessToken != "test-access-token" {
		t.Errorf("expected token 'test-access-token', got %q", result.AccessToken)
	}
	if result.ExpiresIn != 3600 {
		t.Errorf("expected expiresIn 3600, got %d", result.ExpiresIn)
	}
}

func TestAuthenticateM2M_CachesToken(t *testing.T) {
	var callCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oidc/token" {
			callCount.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "test-access-token",
				"expires_in":   3600,
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	adapter := newTestAdapter(t, server.URL)

	// First call
	_, err := adapter.AuthenticateM2M(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Second call should use cache
	_, err = adapter.AuthenticateM2M(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if callCount.Load() != 1 {
		t.Errorf("expected 1 token request (cached), got %d", callCount.Load())
	}
}

func TestAuthenticateM2M_ConcurrentAccess(t *testing.T) {
	var callCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oidc/token" {
			callCount.Add(1)
			// Simulate some delay to increase chance of race
			time.Sleep(10 * time.Millisecond)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "test-access-token",
				"expires_in":   3600,
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	adapter := newTestAdapter(t, server.URL)

	// Launch 100 concurrent goroutines
	const numGoroutines = 100
	done := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			_, err := adapter.AuthenticateM2M(context.Background())
			done <- err
		}()
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		if err := <-done; err != nil {
			t.Errorf("goroutine %d error: %v", i, err)
		}
	}

	// With proper locking, only 1 token request should be made
	count := callCount.Load()
	if count != 1 {
		t.Errorf("expected 1 token request (race condition protection), got %d", count)
	}
}

// === CRUD Validation tests ===

func TestCRUDValidation_EmptyIDs(t *testing.T) {
	adapter, _ := New("http://localhost", "app-id", "secret")

	tests := []struct {
		name  string
		fn    func() error
		field string
	}{
		{"GetUser empty userID", func() error {
			_, err := adapter.GetUser(context.Background(), "")
			return err
		}, "userID"},
		{"GetOrganization empty orgID", func() error {
			_, err := adapter.GetOrganization(context.Background(), "")
			return err
		}, "orgID"},
		{"GetOrganizationRole empty roleID", func() error {
			_, err := adapter.GetOrganizationRole(context.Background(), "")
			return err
		}, "roleID"},
		{"GetAPIResource empty resourceID", func() error {
			_, err := adapter.GetAPIResource(context.Background(), "")
			return err
		}, "resourceID"},
		{"DeleteOrganization empty orgID", func() error {
			return adapter.DeleteOrganization(context.Background(), "")
		}, "orgID"},
		{"RemoveUserFromOrganization empty orgID", func() error {
			return adapter.RemoveUserFromOrganization(context.Background(), "", "user-123")
		}, "orgID"},
		{"RemoveUserFromOrganization empty userID", func() error {
			return adapter.RemoveUserFromOrganization(context.Background(), "org-123", "")
		}, "userID"},
		{"ListOrganizationMembers empty orgID", func() error {
			iter := adapter.ListOrganizationMembers("", DefaultIteratorConfig())
			iter.Next(context.Background())
			return iter.Err()
		}, "orgID"},
		{"ListAPIResourceScopes empty resourceID", func() error {
			iter := adapter.ListAPIResourceScopes("", DefaultIteratorConfig())
			iter.Next(context.Background())
			return iter.Err()
		}, "resourceID"},
		{"GetOrganizationRoleResourceScopes empty roleID", func() error {
			_, err := adapter.GetOrganizationRoleResourceScopes(context.Background(), "")
			return err
		}, "roleID"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			if err == nil {
				t.Error("expected validation error, got nil")
				return
			}
			if !errors.Is(err, ErrInvalidInput) {
				t.Errorf("expected ErrInvalidInput, got %v", err)
			}
			var valErr *ValidationError
			if errors.As(err, &valErr) {
				if valErr.Field != tt.field {
					t.Errorf("expected field %q, got %q", tt.field, valErr.Field)
				}
			}
		})
	}
}

func TestCRUDValidation_EmptyNames(t *testing.T) {
	adapter, _ := New("http://localhost", "app-id", "secret")

	tests := []struct {
		name  string
		fn    func() error
		field string
	}{
		{"CreateOrganization empty name", func() error {
			_, err := adapter.CreateOrganization(context.Background(), models.OrganizationCreate{Description: "description"})
			return err
		}, "name"},
		{"CreateOrganizationRole empty name", func() error {
			_, err := adapter.CreateOrganizationRole(context.Background(), models.OrganizationRoleCreate{Description: "description"})
			return err
		}, "name"},
		{"CreateOrganizationScope empty name", func() error {
			_, err := adapter.CreateOrganizationScope(context.Background(), models.OrganizationScopeCreate{Description: "description"})
			return err
		}, "name"},
		{"CreateAPIResource empty name", func() error {
			_, err := adapter.CreateAPIResource(context.Background(), models.APIResourceCreate{Indicator: "https://api.example.com"})
			return err
		}, "name"},
		{"CreateAPIResource empty indicator", func() error {
			_, err := adapter.CreateAPIResource(context.Background(), models.APIResourceCreate{Name: "Test API"})
			return err
		}, "indicator"},
		{"CreateAPIResourceScope empty name", func() error {
			_, err := adapter.CreateAPIResourceScope(context.Background(), "resource-123", models.APIResourceScopeCreate{Description: "description"})
			return err
		}, "name"},
		{"CreateAPIResourceScope empty resourceID", func() error {
			_, err := adapter.CreateAPIResourceScope(context.Background(), "", models.APIResourceScopeCreate{Name: "scope", Description: "description"})
			return err
		}, "resourceID"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			if err == nil {
				t.Error("expected validation error, got nil")
				return
			}
			if !errors.Is(err, ErrInvalidInput) {
				t.Errorf("expected ErrInvalidInput, got %v", err)
			}
			var valErr *ValidationError
			if errors.As(err, &valErr) {
				if valErr.Field != tt.field {
					t.Errorf("expected field %q, got %q", tt.field, valErr.Field)
				}
			}
		})
	}
}

// === Verification Code tests ===

func TestRequestVerificationCode_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mockM2MTokenResponse(w, r) {
			return
		}

		if r.URL.Path == "/api/verification-codes" && r.Method == http.MethodPost {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	adapter := newTestAdapter(t, server.URL)

	// Test with email
	err := adapter.RequestVerificationCode(context.Background(), VerificationCodeRequest{
		Email: "test@example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRequestVerificationCode_SuccessWithPhone(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mockM2MTokenResponse(w, r) {
			return
		}

		if r.URL.Path == "/api/verification-codes" && r.Method == http.MethodPost {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	adapter := newTestAdapter(t, server.URL)

	// Test with phone
	err := adapter.RequestVerificationCode(context.Background(), VerificationCodeRequest{
		Phone: "+1234567890",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRequestVerificationCode_Validation(t *testing.T) {
	adapter, _ := New("http://localhost", "app-id", "secret")

	tests := []struct {
		name    string
		req     VerificationCodeRequest
		wantErr string
	}{
		{
			name:    "empty email and phone",
			req:     VerificationCodeRequest{},
			wantErr: "either email or phone must be provided",
		},
		{
			name:    "both email and phone",
			req:     VerificationCodeRequest{Email: "test@example.com", Phone: "+1234567890"},
			wantErr: "only one of email or phone should be provided",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := adapter.RequestVerificationCode(context.Background(), tt.req)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, ErrInvalidInput) {
				t.Errorf("expected ErrInvalidInput, got %v", err)
			}
			var valErr *ValidationError
			if errors.As(err, &valErr) {
				if valErr.Message != tt.wantErr {
					t.Errorf("expected message %q, got %q", tt.wantErr, valErr.Message)
				}
			}
		})
	}
}

func TestVerifyCode_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mockM2MTokenResponse(w, r) {
			return
		}

		if r.URL.Path == "/api/verification-codes/verify" && r.Method == http.MethodPost {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	adapter := newTestAdapter(t, server.URL)

	err := adapter.VerifyCode(context.Background(), VerifyCodeRequest{
		Email:            "test@example.com",
		VerificationCode: "123456",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyCode_SuccessWithPhone(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mockM2MTokenResponse(w, r) {
			return
		}

		if r.URL.Path == "/api/verification-codes/verify" && r.Method == http.MethodPost {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	adapter := newTestAdapter(t, server.URL)

	err := adapter.VerifyCode(context.Background(), VerifyCodeRequest{
		Phone:            "+1234567890",
		VerificationCode: "123456",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyCode_Validation(t *testing.T) {
	adapter, _ := New("http://localhost", "app-id", "secret")

	tests := []struct {
		name    string
		req     VerifyCodeRequest
		field   string
		wantErr string
	}{
		{
			name:    "empty email and phone",
			req:     VerifyCodeRequest{VerificationCode: "123456"},
			field:   "email/phone",
			wantErr: "either email or phone must be provided",
		},
		{
			name:    "empty verification code",
			req:     VerifyCodeRequest{Email: "test@example.com"},
			field:   "verificationCode",
			wantErr: "cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := adapter.VerifyCode(context.Background(), tt.req)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, ErrInvalidInput) {
				t.Errorf("expected ErrInvalidInput, got %v", err)
			}
			var valErr *ValidationError
			if errors.As(err, &valErr) {
				if valErr.Field != tt.field {
					t.Errorf("expected field %q, got %q", tt.field, valErr.Field)
				}
			}
		})
	}
}

// === GetResourceToken tests ===

func TestGetResourceToken_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oidc/token" && r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "resource-access-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
				"scope":        "read:data write:data",
			})
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	adapter := newTestAdapter(t, server.URL)
	result, err := adapter.GetResourceToken(context.Background(), "https://api.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.AccessToken != "resource-access-token" {
		t.Errorf("expected accessToken 'resource-access-token', got %q", result.AccessToken)
	}
	if result.ExpiresIn != 3600 {
		t.Errorf("expected expiresIn 3600, got %d", result.ExpiresIn)
	}
}

func TestGetResourceToken_WithScopes(t *testing.T) {
	var capturedForm map[string]string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oidc/token" {
			_ = r.ParseForm()
			capturedForm = make(map[string]string)
			for key := range r.PostForm {
				capturedForm[key] = r.PostForm.Get(key)
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "test-token",
				"expires_in":   3600,
			})
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	adapter := newTestAdapter(t, server.URL)
	_, err := adapter.GetResourceToken(context.Background(), "https://api.example.com", "read:data", "write:data")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if capturedForm["resource"] != "https://api.example.com" {
		t.Errorf("expected resource 'https://api.example.com', got %q", capturedForm["resource"])
	}

	if capturedForm["scope"] != "read:data write:data" {
		t.Errorf("expected scope 'read:data write:data', got %q", capturedForm["scope"])
	}

	if capturedForm["grant_type"] != "client_credentials" {
		t.Errorf("expected grant_type 'client_credentials', got %q", capturedForm["grant_type"])
	}
}

func TestGetResourceToken_UsesBasicAuth(t *testing.T) {
	var capturedAuthHeader string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oidc/token" {
			capturedAuthHeader = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "test-token",
				"expires_in":   3600,
			})
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	adapter := newTestAdapter(t, server.URL)
	_, err := adapter.GetResourceToken(context.Background(), "https://api.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify Basic Auth header
	if !strings.HasPrefix(capturedAuthHeader, "Basic ") {
		t.Errorf("expected Authorization header to start with 'Basic ', got %q", capturedAuthHeader)
	}
}

func TestGetResourceToken_WithoutScopes(t *testing.T) {
	var capturedForm map[string][]string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oidc/token" {
			_ = r.ParseForm()
			capturedForm = r.PostForm

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "test-token",
				"expires_in":   3600,
			})
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	adapter := newTestAdapter(t, server.URL)
	_, err := adapter.GetResourceToken(context.Background(), "https://api.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify scope is NOT sent when no scopes provided
	if _, exists := capturedForm["scope"]; exists {
		t.Errorf("expected scope to be absent when no scopes provided, but got %q", capturedForm["scope"])
	}
}

func TestGetResourceToken_Validation(t *testing.T) {
	adapter, _ := New("http://localhost", "app-id", "secret")

	_, err := adapter.GetResourceToken(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty resource")
	}

	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}

	var valErr *ValidationError
	if errors.As(err, &valErr) {
		if valErr.Field != "resource" {
			t.Errorf("expected field 'resource', got %q", valErr.Field)
		}
	} else {
		t.Error("expected ValidationError type")
	}
}

func TestGetResourceToken_ExpiresAt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oidc/token" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "test-token",
				"expires_in":   7200,
			})
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	adapter := newTestAdapter(t, server.URL)
	before := time.Now()

	result, err := adapter.GetResourceToken(context.Background(), "https://api.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	after := time.Now()

	// ExpiresAt should be approximately now + 7200 seconds
	expectedMin := before.Add(7200 * time.Second)
	expectedMax := after.Add(7200 * time.Second)

	if result.ExpiresAt.Before(expectedMin) || result.ExpiresAt.After(expectedMax) {
		t.Errorf("ExpiresAt %v not in expected range [%v, %v]", result.ExpiresAt, expectedMin, expectedMax)
	}
}

func TestGetResourceToken_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oidc/token" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message": "Access denied to resource"}`))
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	adapter := newTestAdapter(t, server.URL)
	_, err := adapter.GetResourceToken(context.Background(), "https://api.example.com")
	if err == nil {
		t.Fatal("expected error for forbidden resource")
	}

	if !errors.Is(err, ErrForbidden) {
		t.Errorf("expected ErrForbidden, got %v", err)
	}
}
