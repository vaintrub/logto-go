package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// === CreateSubjectToken tests ===

func TestCreateSubjectToken_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mockM2MTokenResponse(w, r) {
			return
		}

		if r.URL.Path == "/api/subject-tokens" && r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"subjectToken": "test-subject-token-xyz",
				"expiresIn":    600,
			})
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	adapter := newTestAdapter(t, server.URL)
	result, err := adapter.CreateSubjectToken(context.Background(), "user-123", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.SubjectToken != "test-subject-token-xyz" {
		t.Errorf("expected subjectToken 'test-subject-token-xyz', got %q", result.SubjectToken)
	}
	if result.ExpiresIn != 600 {
		t.Errorf("expected expiresIn 600, got %d", result.ExpiresIn)
	}
}

func TestCreateSubjectToken_WithContext(t *testing.T) {
	var capturedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mockM2MTokenResponse(w, r) {
			return
		}

		if r.URL.Path == "/api/subject-tokens" && r.Method == http.MethodPost {
			_ = json.NewDecoder(r.Body).Decode(&capturedBody)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"subjectToken": "test-subject-token",
				"expiresIn":    600,
			})
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	adapter := newTestAdapter(t, server.URL)
	tokenCtx := SubjectTokenContext{
		"ticketId": "TICKET-123",
		"reason":   "customer support",
	}

	_, err := adapter.CreateSubjectToken(context.Background(), "user-456", tokenCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify request body
	if capturedBody["userId"] != "user-456" {
		t.Errorf("expected userId 'user-456', got %v", capturedBody["userId"])
	}

	ctx, ok := capturedBody["context"].(map[string]interface{})
	if !ok {
		t.Fatal("expected context to be present in request body")
	}
	if ctx["ticketId"] != "TICKET-123" {
		t.Errorf("expected ticketId 'TICKET-123', got %v", ctx["ticketId"])
	}
	if ctx["reason"] != "customer support" {
		t.Errorf("expected reason 'customer support', got %v", ctx["reason"])
	}
}

func TestCreateSubjectToken_WithoutContext(t *testing.T) {
	var capturedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mockM2MTokenResponse(w, r) {
			return
		}

		if r.URL.Path == "/api/subject-tokens" && r.Method == http.MethodPost {
			_ = json.NewDecoder(r.Body).Decode(&capturedBody)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"subjectToken": "test-subject-token",
				"expiresIn":    600,
			})
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	adapter := newTestAdapter(t, server.URL)
	_, err := adapter.CreateSubjectToken(context.Background(), "user-789", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify context is NOT in request body when nil
	if _, exists := capturedBody["context"]; exists {
		t.Error("expected context to be absent when nil")
	}
}

func TestCreateSubjectToken_Validation(t *testing.T) {
	adapter, _ := New("http://localhost", "app-id", "secret")

	_, err := adapter.CreateSubjectToken(context.Background(), "", nil)
	if err == nil {
		t.Fatal("expected error for empty userID")
	}

	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}

	var valErr *ValidationError
	if errors.As(err, &valErr) {
		if valErr.Field != "userID" {
			t.Errorf("expected field 'userID', got %q", valErr.Field)
		}
	} else {
		t.Error("expected ValidationError type")
	}
}

func TestCreateSubjectToken_UserNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mockM2MTokenResponse(w, r) {
			return
		}

		if r.URL.Path == "/api/subject-tokens" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message": "User does not exist", "code": "entity.not_exists"}`))
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	adapter := newTestAdapter(t, server.URL)
	_, err := adapter.CreateSubjectToken(context.Background(), "nonexistent-user", nil)
	if err == nil {
		t.Fatal("expected error for nonexistent user")
	}

	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

// === ExchangeSubjectToken tests ===

func TestExchangeSubjectToken_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oidc/token" && r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "exchanged-access-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
				"scope":        "openid profile",
			})
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	adapter := newTestAdapter(t, server.URL)
	result, err := adapter.ExchangeSubjectToken(context.Background(), "subject-token-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.AccessToken != "exchanged-access-token" {
		t.Errorf("expected accessToken 'exchanged-access-token', got %q", result.AccessToken)
	}
	if result.TokenType != "Bearer" {
		t.Errorf("expected tokenType 'Bearer', got %q", result.TokenType)
	}
	if result.ExpiresIn != 3600 {
		t.Errorf("expected expiresIn 3600, got %d", result.ExpiresIn)
	}
	if result.Scope != "openid profile" {
		t.Errorf("expected scope 'openid profile', got %q", result.Scope)
	}
}

func TestExchangeSubjectToken_UsesBasicAuth(t *testing.T) {
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
	_, err := adapter.ExchangeSubjectToken(context.Background(), "subject-token-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify Basic Auth header is present
	if !strings.HasPrefix(capturedAuthHeader, "Basic ") {
		t.Errorf("expected Authorization header to start with 'Basic ', got %q", capturedAuthHeader)
	}
}

func TestExchangeSubjectToken_RequestParameters(t *testing.T) {
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
	_, err := adapter.ExchangeSubjectToken(context.Background(), "my-subject-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify required parameters
	expectedGrantType := "urn:ietf:params:oauth:grant-type:token-exchange"
	if capturedForm["grant_type"] != expectedGrantType {
		t.Errorf("expected grant_type %q, got %q", expectedGrantType, capturedForm["grant_type"])
	}

	if capturedForm["subject_token"] != "my-subject-token" {
		t.Errorf("expected subject_token 'my-subject-token', got %q", capturedForm["subject_token"])
	}

	expectedTokenType := "urn:ietf:params:oauth:token-type:access_token"
	if capturedForm["subject_token_type"] != expectedTokenType {
		t.Errorf("expected subject_token_type %q, got %q", expectedTokenType, capturedForm["subject_token_type"])
	}

	if capturedForm["client_id"] != "test-app-id" {
		t.Errorf("expected client_id 'test-app-id', got %q", capturedForm["client_id"])
	}
}

func TestExchangeSubjectToken_WithOptions(t *testing.T) {
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
	_, err := adapter.ExchangeSubjectToken(
		context.Background(),
		"subject-token",
		WithExchangeResource("https://api.example.com"),
		WithScopes("read:data", "write:data"),
		WithOrganizationID("org-123"),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if capturedForm["resource"] != "https://api.example.com" {
		t.Errorf("expected resource 'https://api.example.com', got %q", capturedForm["resource"])
	}

	if capturedForm["scope"] != "read:data write:data" {
		t.Errorf("expected scope 'read:data write:data', got %q", capturedForm["scope"])
	}

	if capturedForm["organization_id"] != "org-123" {
		t.Errorf("expected organization_id 'org-123', got %q", capturedForm["organization_id"])
	}
}

func TestExchangeSubjectToken_DefaultsFromAdapter(t *testing.T) {
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

	// Create adapter with custom resource and scope
	adapter, _ := New(
		server.URL,
		"test-app-id",
		"test-app-secret",
		WithResource("https://custom-api.example.com"),
		WithScope("custom:scope"),
	)

	_, err := adapter.ExchangeSubjectToken(context.Background(), "subject-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should use adapter defaults
	if capturedForm["resource"] != "https://custom-api.example.com" {
		t.Errorf("expected default resource from adapter, got %q", capturedForm["resource"])
	}

	if capturedForm["scope"] != "custom:scope" {
		t.Errorf("expected default scope from adapter, got %q", capturedForm["scope"])
	}
}

func TestExchangeSubjectToken_Validation(t *testing.T) {
	adapter, _ := New("http://localhost", "app-id", "secret")

	_, err := adapter.ExchangeSubjectToken(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty subjectToken")
	}

	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}

	var valErr *ValidationError
	if errors.As(err, &valErr) {
		if valErr.Field != "subjectToken" {
			t.Errorf("expected field 'subjectToken', got %q", valErr.Field)
		}
	} else {
		t.Error("expected ValidationError type")
	}
}

func TestExchangeSubjectToken_ExpiresAt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oidc/token" {
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
	before := time.Now()

	result, err := adapter.ExchangeSubjectToken(context.Background(), "subject-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	after := time.Now()

	// ExpiresAt should be approximately now + 3600 seconds
	expectedMin := before.Add(3600 * time.Second)
	expectedMax := after.Add(3600 * time.Second)

	if result.ExpiresAt.Before(expectedMin) || result.ExpiresAt.After(expectedMax) {
		t.Errorf("ExpiresAt %v not in expected range [%v, %v]", result.ExpiresAt, expectedMin, expectedMax)
	}
}

func TestExchangeSubjectToken_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oidc/token" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error": "invalid_grant", "error_description": "subject token expired"}`))
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	adapter := newTestAdapter(t, server.URL)
	_, err := adapter.ExchangeSubjectToken(context.Background(), "expired-token")
	if err == nil {
		t.Fatal("expected error for bad request")
	}

	if !errors.Is(err, ErrBadRequest) {
		t.Errorf("expected ErrBadRequest, got %v", err)
	}
}

// === GetUserAccessToken tests ===

func TestGetUserAccessToken_Success(t *testing.T) {
	var capturedSubjectToken string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle /oidc/token - need to check grant_type first
		if r.URL.Path == "/oidc/token" && r.Method == http.MethodPost {
			_ = r.ParseForm()
			grantType := r.PostForm.Get("grant_type")

			// Token exchange for impersonation
			if grantType == "urn:ietf:params:oauth:grant-type:token-exchange" {
				capturedSubjectToken = r.PostForm.Get("subject_token")
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"access_token": "final-user-access-token",
					"token_type":   "Bearer",
					"expires_in":   3600,
				})
				return
			}

			// M2M auth (client_credentials)
			if grantType == "client_credentials" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"access_token": "m2m-token",
					"expires_in":   3600,
				})
				return
			}
		}

		// CreateSubjectToken
		if r.URL.Path == "/api/subject-tokens" && r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"subjectToken": "intermediate-subject-token",
				"expiresIn":    600,
			})
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	adapter := newTestAdapter(t, server.URL)
	result, err := adapter.GetUserAccessToken(context.Background(), "user-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.AccessToken != "final-user-access-token" {
		t.Errorf("expected accessToken 'final-user-access-token', got %q", result.AccessToken)
	}

	// Verify subject_token from CreateSubjectToken is passed to ExchangeSubjectToken
	if capturedSubjectToken != "intermediate-subject-token" {
		t.Errorf("expected subject_token 'intermediate-subject-token', got %q", capturedSubjectToken)
	}
}

func TestGetUserAccessToken_PropagatesCreateSubjectTokenError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mockM2MTokenResponse(w, r) {
			return
		}

		// CreateSubjectToken fails
		if r.URL.Path == "/api/subject-tokens" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message": "User not found"}`))
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	adapter := newTestAdapter(t, server.URL)
	_, err := adapter.GetUserAccessToken(context.Background(), "nonexistent-user")
	if err == nil {
		t.Fatal("expected error when CreateSubjectToken fails")
	}

	// Error should be wrapped
	if !strings.Contains(err.Error(), "create subject token") {
		t.Errorf("expected error to contain 'create subject token', got %v", err)
	}
}

func TestGetUserAccessToken_WithOptions(t *testing.T) {
	var capturedForm map[string]string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle /oidc/token - need to check grant_type first
		if r.URL.Path == "/oidc/token" && r.Method == http.MethodPost {
			_ = r.ParseForm()
			grantType := r.PostForm.Get("grant_type")

			// Token exchange for impersonation
			if grantType == "urn:ietf:params:oauth:grant-type:token-exchange" {
				capturedForm = make(map[string]string)
				for key := range r.PostForm {
					capturedForm[key] = r.PostForm.Get(key)
				}

				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"access_token": "token",
					"expires_in":   3600,
				})
				return
			}

			// M2M auth (client_credentials)
			if grantType == "client_credentials" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"access_token": "m2m-token",
					"expires_in":   3600,
				})
				return
			}
		}

		if r.URL.Path == "/api/subject-tokens" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"subjectToken": "subject-token",
				"expiresIn":    600,
			})
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	adapter := newTestAdapter(t, server.URL)
	_, err := adapter.GetUserAccessToken(
		context.Background(),
		"user-123",
		WithOrganizationID("org-456"),
		WithScopes("read:members"),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify options were passed to ExchangeSubjectToken
	if capturedForm["organization_id"] != "org-456" {
		t.Errorf("expected organization_id 'org-456', got %q", capturedForm["organization_id"])
	}
	if capturedForm["scope"] != "read:members" {
		t.Errorf("expected scope 'read:members', got %q", capturedForm["scope"])
	}
}
