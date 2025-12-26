package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// === UpsertJWTCustomizer tests ===

func TestUpsertJWTCustomizer_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mockM2MTokenResponse(w, r) {
			return
		}

		if r.URL.Path == "/api/configs/jwt-customizer/access-token" && r.Method == http.MethodPut {
			w.WriteHeader(http.StatusOK)
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	adapter := newTestAdapter(t, server.URL)
	err := adapter.UpsertJWTCustomizer(context.Background(), TokenTypeAccessToken, JWTCustomizerConfig{
		Script: "const getCustomJwtClaims = async () => { return {}; };",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpsertJWTCustomizer_WithEnvVars(t *testing.T) {
	var capturedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mockM2MTokenResponse(w, r) {
			return
		}

		if r.URL.Path == "/api/configs/jwt-customizer/client-credentials" && r.Method == http.MethodPut {
			_ = json.NewDecoder(r.Body).Decode(&capturedBody)
			w.WriteHeader(http.StatusCreated)
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	adapter := newTestAdapter(t, server.URL)
	err := adapter.UpsertJWTCustomizer(context.Background(), TokenTypeClientCredentials, JWTCustomizerConfig{
		Script: "const getCustomJwtClaims = async () => { return {}; };",
		EnvironmentVariables: map[string]string{
			"API_KEY": "secret123",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	envVars, ok := capturedBody["environmentVariables"].(map[string]interface{})
	if !ok {
		t.Fatal("expected environmentVariables in request body")
	}
	if envVars["API_KEY"] != "secret123" {
		t.Errorf("expected API_KEY 'secret123', got %v", envVars["API_KEY"])
	}
}

func TestUpsertJWTCustomizer_InvalidTokenType(t *testing.T) {
	adapter, _ := New("http://localhost", "app-id", "secret")

	err := adapter.UpsertJWTCustomizer(context.Background(), "invalid-type", JWTCustomizerConfig{
		Script: "test",
	})
	if err == nil {
		t.Fatal("expected error for invalid token type")
	}

	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}

	var valErr *ValidationError
	if errors.As(err, &valErr) {
		if valErr.Field != "tokenType" {
			t.Errorf("expected field 'tokenType', got %q", valErr.Field)
		}
	} else {
		t.Error("expected ValidationError type")
	}
}

// === GetJWTCustomizer tests ===

func TestGetJWTCustomizer_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mockM2MTokenResponse(w, r) {
			return
		}

		if r.URL.Path == "/api/configs/jwt-customizer/access-token" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"script": "const getCustomJwtClaims = async () => { return { custom: true }; };",
				"environmentVariables": map[string]string{
					"KEY": "value",
				},
			})
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	adapter := newTestAdapter(t, server.URL)
	config, err := adapter.GetJWTCustomizer(context.Background(), TokenTypeAccessToken)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if config == nil {
		t.Fatal("expected config, got nil")
	}
	if config.Script == "" {
		t.Error("expected script to be set")
	}
	if config.EnvironmentVariables["KEY"] != "value" {
		t.Errorf("expected KEY 'value', got %q", config.EnvironmentVariables["KEY"])
	}
}

func TestGetJWTCustomizer_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mockM2MTokenResponse(w, r) {
			return
		}

		if r.URL.Path == "/api/configs/jwt-customizer/access-token" && r.Method == http.MethodGet {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message": "Not found"}`))
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	adapter := newTestAdapter(t, server.URL)
	config, err := adapter.GetJWTCustomizer(context.Background(), TokenTypeAccessToken)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if config != nil {
		t.Errorf("expected nil config for 404, got %+v", config)
	}
}

func TestGetJWTCustomizer_InvalidTokenType(t *testing.T) {
	adapter, _ := New("http://localhost", "app-id", "secret")

	_, err := adapter.GetJWTCustomizer(context.Background(), "bad-type")
	if err == nil {
		t.Fatal("expected error for invalid token type")
	}

	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}

	var valErr *ValidationError
	if errors.As(err, &valErr) {
		if valErr.Field != "tokenType" {
			t.Errorf("expected field 'tokenType', got %q", valErr.Field)
		}
	} else {
		t.Error("expected ValidationError type")
	}
}

// === DeleteJWTCustomizer tests ===

func TestDeleteJWTCustomizer_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mockM2MTokenResponse(w, r) {
			return
		}

		if r.URL.Path == "/api/configs/jwt-customizer/client-credentials" && r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	adapter := newTestAdapter(t, server.URL)
	err := adapter.DeleteJWTCustomizer(context.Background(), TokenTypeClientCredentials)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeleteJWTCustomizer_InvalidTokenType(t *testing.T) {
	adapter, _ := New("http://localhost", "app-id", "secret")

	err := adapter.DeleteJWTCustomizer(context.Background(), "wrong")
	if err == nil {
		t.Fatal("expected error for invalid token type")
	}

	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}

	var valErr *ValidationError
	if errors.As(err, &valErr) {
		if valErr.Field != "tokenType" {
			t.Errorf("expected field 'tokenType', got %q", valErr.Field)
		}
	} else {
		t.Error("expected ValidationError type")
	}
}

// === Constants tests ===

func TestTokenTypeConstants(t *testing.T) {
	if TokenTypeAccessToken != "access-token" {
		t.Errorf("expected TokenTypeAccessToken to be 'access-token', got %q", TokenTypeAccessToken)
	}
	if TokenTypeClientCredentials != "client-credentials" {
		t.Errorf("expected TokenTypeClientCredentials to be 'client-credentials', got %q", TokenTypeClientCredentials)
	}
}
