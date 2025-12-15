package validator

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

func TestTokenInfo_HasScope(t *testing.T) {
	info := &TokenInfo{
		Scopes: []string{"read", "write", "admin"},
	}

	tests := []struct {
		scope string
		want  bool
	}{
		{"read", true},
		{"write", true},
		{"admin", true},
		{"delete", false},
		{"", false},
		{"READ", false}, // case-sensitive
	}

	for _, tt := range tests {
		t.Run(tt.scope, func(t *testing.T) {
			if got := info.HasScope(tt.scope); got != tt.want {
				t.Errorf("HasScope(%q) = %v, want %v", tt.scope, got, tt.want)
			}
		})
	}
}

func TestTokenInfo_HasScope_Empty(t *testing.T) {
	info := &TokenInfo{
		Scopes: []string{},
	}

	if info.HasScope("read") {
		t.Error("HasScope() should return false for empty scopes")
	}
}

func TestTokenInfo_HasAnyScope(t *testing.T) {
	info := &TokenInfo{
		Scopes: []string{"read", "write", "admin"},
	}

	tests := []struct {
		name   string
		scopes []string
		want   bool
	}{
		{"single_match", []string{"read"}, true},
		{"multiple_one_match", []string{"delete", "read"}, true},
		{"none_match", []string{"delete", "create"}, false},
		{"all_match", []string{"read", "write"}, true},
		{"empty_input", []string{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := info.HasAnyScope(tt.scopes...); got != tt.want {
				t.Errorf("HasAnyScope(%v) = %v, want %v", tt.scopes, got, tt.want)
			}
		})
	}
}

func TestTokenInfo_HasAllScopes(t *testing.T) {
	info := &TokenInfo{
		Scopes: []string{"read", "write", "admin"},
	}

	tests := []struct {
		name   string
		scopes []string
		want   bool
	}{
		{"single_match", []string{"read"}, true},
		{"all_match", []string{"read", "write"}, true},
		{"partial_match", []string{"read", "delete"}, false},
		{"none_match", []string{"delete", "create"}, false},
		{"empty_input", []string{}, true}, // vacuously true
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := info.HasAllScopes(tt.scopes...); got != tt.want {
				t.Errorf("HasAllScopes(%v) = %v, want %v", tt.scopes, got, tt.want)
			}
		})
	}
}

func TestTokenInfo_Fields(t *testing.T) {
	info := &TokenInfo{
		UserID:         "user-123",
		OrganizationID: "org-456",
		Scopes:         []string{"read", "write"},
	}

	if info.UserID != "user-123" {
		t.Errorf("UserID = %q, want 'user-123'", info.UserID)
	}
	if info.OrganizationID != "org-456" {
		t.Errorf("OrganizationID = %q, want 'org-456'", info.OrganizationID)
	}
	if len(info.Scopes) != 2 {
		t.Errorf("Scopes len = %d, want 2", len(info.Scopes))
	}
}

func TestTokenInfo_NilScopes(t *testing.T) {
	info := &TokenInfo{
		UserID: "user-123",
		// Scopes is nil
	}

	// Should handle nil scopes gracefully
	if info.HasScope("read") {
		t.Error("HasScope should return false for nil scopes")
	}
	if info.HasAnyScope("read", "write") {
		t.Error("HasAnyScope should return false for nil scopes")
	}
	if !info.HasAllScopes() {
		t.Error("HasAllScopes with empty input should return true")
	}
}

// === Custom Claims tests ===

func TestTokenInfo_GetClaim(t *testing.T) {
	info := &TokenInfo{
		RawClaims: map[string]any{
			"string_claim": "hello",
			"int_claim":    float64(42), // JSON numbers are float64
			"bool_claim":   true,
			"array_claim":  []any{"a", "b", "c"},
			"nested":       map[string]any{"key": "value"},
		},
	}

	// Test existing claims
	if v := info.GetClaim("string_claim"); v != "hello" {
		t.Errorf("GetClaim(string_claim) = %v, want 'hello'", v)
	}
	if v := info.GetClaim("int_claim"); v != float64(42) {
		t.Errorf("GetClaim(int_claim) = %v, want 42", v)
	}

	// Test non-existing claim
	if v := info.GetClaim("nonexistent"); v != nil {
		t.Errorf("GetClaim(nonexistent) = %v, want nil", v)
	}
}

func TestTokenInfo_GetClaim_NilRawClaims(t *testing.T) {
	info := &TokenInfo{
		UserID:    "user-123",
		RawClaims: nil,
	}

	if v := info.GetClaim("anything"); v != nil {
		t.Errorf("GetClaim on nil RawClaims should return nil, got %v", v)
	}
}

func TestTokenInfo_GetStringClaim(t *testing.T) {
	info := &TokenInfo{
		RawClaims: map[string]any{
			"tenant_id": "tenant-123",
			"not_string": 42,
		},
	}

	if v := info.GetStringClaim("tenant_id"); v != "tenant-123" {
		t.Errorf("GetStringClaim(tenant_id) = %q, want 'tenant-123'", v)
	}
	if v := info.GetStringClaim("not_string"); v != "" {
		t.Errorf("GetStringClaim(not_string) = %q, want ''", v)
	}
	if v := info.GetStringClaim("nonexistent"); v != "" {
		t.Errorf("GetStringClaim(nonexistent) = %q, want ''", v)
	}
}

func TestTokenInfo_GetStringSliceClaim(t *testing.T) {
	info := &TokenInfo{
		RawClaims: map[string]any{
			"roles":     []any{"admin", "user", "moderator"},
			"mixed":     []any{"string", 123, true}, // should only include strings
			"not_array": "just a string",
			"empty":     []any{},
		},
	}

	// Test normal string array
	roles := info.GetStringSliceClaim("roles")
	if len(roles) != 3 {
		t.Errorf("GetStringSliceClaim(roles) len = %d, want 3", len(roles))
	}
	if roles[0] != "admin" || roles[1] != "user" || roles[2] != "moderator" {
		t.Errorf("GetStringSliceClaim(roles) = %v, want [admin user moderator]", roles)
	}

	// Test mixed array - should only include strings
	mixed := info.GetStringSliceClaim("mixed")
	if len(mixed) != 1 || mixed[0] != "string" {
		t.Errorf("GetStringSliceClaim(mixed) = %v, want [string]", mixed)
	}

	// Test non-array
	if v := info.GetStringSliceClaim("not_array"); v != nil {
		t.Errorf("GetStringSliceClaim(not_array) = %v, want nil", v)
	}

	// Test empty array
	empty := info.GetStringSliceClaim("empty")
	if len(empty) != 0 {
		t.Errorf("GetStringSliceClaim(empty) = %v, want []", empty)
	}

	// Test nonexistent
	if v := info.GetStringSliceClaim("nonexistent"); v != nil {
		t.Errorf("GetStringSliceClaim(nonexistent) = %v, want nil", v)
	}
}

func TestTokenInfo_GetBoolClaim(t *testing.T) {
	info := &TokenInfo{
		RawClaims: map[string]any{
			"is_admin":  true,
			"is_active": false,
			"not_bool":  "true",
		},
	}

	if v := info.GetBoolClaim("is_admin"); !v {
		t.Error("GetBoolClaim(is_admin) = false, want true")
	}
	if v := info.GetBoolClaim("is_active"); v {
		t.Error("GetBoolClaim(is_active) = true, want false")
	}
	if v := info.GetBoolClaim("not_bool"); v {
		t.Error("GetBoolClaim(not_bool) should return false for non-bool")
	}
	if v := info.GetBoolClaim("nonexistent"); v {
		t.Error("GetBoolClaim(nonexistent) should return false")
	}
}

func TestTokenInfo_GetFloat64Claim(t *testing.T) {
	info := &TokenInfo{
		RawClaims: map[string]any{
			"rate":       3.14,
			"count":      float64(100),
			"not_number": "42",
		},
	}

	if v := info.GetFloat64Claim("rate"); v != 3.14 {
		t.Errorf("GetFloat64Claim(rate) = %v, want 3.14", v)
	}
	if v := info.GetFloat64Claim("count"); v != 100 {
		t.Errorf("GetFloat64Claim(count) = %v, want 100", v)
	}
	if v := info.GetFloat64Claim("not_number"); v != 0 {
		t.Errorf("GetFloat64Claim(not_number) = %v, want 0", v)
	}
}

func TestTokenInfo_GetIntClaim(t *testing.T) {
	info := &TokenInfo{
		RawClaims: map[string]any{
			"count":      float64(42),
			"negative":   float64(-10),
			"not_number": "42",
		},
	}

	if v := info.GetIntClaim("count"); v != 42 {
		t.Errorf("GetIntClaim(count) = %v, want 42", v)
	}
	if v := info.GetIntClaim("negative"); v != -10 {
		t.Errorf("GetIntClaim(negative) = %v, want -10", v)
	}
	if v := info.GetIntClaim("not_number"); v != 0 {
		t.Errorf("GetIntClaim(not_number) = %v, want 0", v)
	}
}

func TestTokenInfo_RawClaims_Integration(t *testing.T) {
	// Simulate what would come from a real JWT with custom claims
	info := &TokenInfo{
		UserID:         "user-123",
		OrganizationID: "org-456",
		Scopes:         []string{"read", "write"},
		RawClaims: map[string]any{
			"sub":             "user-123",
			"organization_id": "org-456",
			"scope":           "read write",
			// Custom claims from Logto Custom JWT
			"roles":     []any{"admin", "editor"},
			"tenant_id": "tenant-abc",
			"features":  map[string]any{"beta": true},
		},
	}

	// Standard claims are still accessible via struct fields
	if info.UserID != "user-123" {
		t.Errorf("UserID = %q, want 'user-123'", info.UserID)
	}

	// Custom claims via RawClaims
	roles := info.GetStringSliceClaim("roles")
	if len(roles) != 2 || roles[0] != "admin" {
		t.Errorf("roles = %v, want [admin editor]", roles)
	}

	tenantID := info.GetStringClaim("tenant_id")
	if tenantID != "tenant-abc" {
		t.Errorf("tenant_id = %q, want 'tenant-abc'", tenantID)
	}

	// Nested claims via GetClaim
	features := info.GetClaim("features")
	if featuresMap, ok := features.(map[string]any); ok {
		if beta, ok := featuresMap["beta"].(bool); !ok || !beta {
			t.Error("features.beta should be true")
		}
	} else {
		t.Error("features should be a map")
	}
}

// === JWKS Validator tests ===

// testClaims is used for creating test JWT tokens
type testClaims struct {
	josejwt.Claims
	OrganizationID string `json:"organization_id,omitempty"`
	ClientID       string `json:"client_id,omitempty"`
	Scope          string `json:"scope,omitempty"`
}

// signRSAToken creates a signed JWT token with RSA key
func signRSAToken(t *testing.T, privateKey *rsa.PrivateKey, kid string, claims testClaims) string {
	t.Helper()

	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
		(&jose.SignerOptions{}).WithHeader("kid", kid),
	)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	token, err := josejwt.Signed(sig).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return token
}

// signECToken creates a signed JWT token with EC key
func signECToken(t *testing.T, privateKey *ecdsa.PrivateKey, kid string, claims testClaims) string {
	t.Helper()

	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: privateKey},
		(&jose.SignerOptions{}).WithHeader("kid", kid),
	)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	token, err := josejwt.Signed(sig).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return token
}

func TestNewJWKSValidator_ValidEndpoint(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{Key: &privateKey.PublicKey, KeyID: "test-kid", Algorithm: "RS256", Use: "sig"},
		},
	}

	// Create mock JWKS server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	validator, err := NewJWKSValidator(server.URL, "https://test.issuer.com", "", 5*time.Minute, nil)
	if err != nil {
		t.Fatalf("NewJWKSValidator failed: %v", err)
	}

	if validator == nil {
		t.Fatal("expected validator, got nil")
	}
	// With lazy loading, keySet is nil until first ValidateToken call
	if validator.keySet != nil {
		t.Error("expected keySet to be nil before first ValidateToken (lazy loading)")
	}
}

func TestNewJWKSValidator_InvalidEndpoint(t *testing.T) {
	// With lazy loading, constructor should succeed even with invalid URL
	// Error will occur on first ValidateToken call
	validator, err := NewJWKSValidator("http://localhost:1", "https://test.issuer.com", "", 5*time.Minute, nil)
	if err != nil {
		t.Errorf("NewJWKSValidator should not fail with lazy loading: %v", err)
	}
	if validator == nil {
		t.Error("expected validator, got nil")
	}
}

func TestNewJWKSValidator_InvalidJWKSResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`invalid json`))
	}))
	defer server.Close()

	// With lazy loading, constructor should succeed
	validator, err := NewJWKSValidator(server.URL, "https://test.issuer.com", "", 5*time.Minute, nil)
	if err != nil {
		t.Errorf("NewJWKSValidator should not fail with lazy loading: %v", err)
	}
	if validator == nil {
		t.Error("expected validator, got nil")
	}
}

func TestNewJWKSValidator_NonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	// With lazy loading, constructor should succeed
	validator, err := NewJWKSValidator(server.URL, "https://test.issuer.com", "", 5*time.Minute, nil)
	if err != nil {
		t.Errorf("NewJWKSValidator should not fail with lazy loading: %v", err)
	}
	if validator == nil {
		t.Error("expected validator, got nil")
	}
}

func TestValidateToken_ValidRSAToken(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	issuer := "https://test.issuer.com"
	kid := "test-kid"

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{Key: &privateKey.PublicKey, KeyID: kid, Algorithm: "RS256", Use: "sig"},
		},
	}

	// Create mock JWKS server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	validator, err := NewJWKSValidator(server.URL, issuer, "", 5*time.Minute, nil)
	if err != nil {
		t.Fatalf("NewJWKSValidator failed: %v", err)
	}

	// Create valid token
	claims := testClaims{
		Claims: josejwt.Claims{
			Issuer:   issuer,
			Subject:  "user-123",
			Expiry:   josejwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt: josejwt.NewNumericDate(time.Now()),
		},
		Scope:          "read write",
		OrganizationID: "org-456",
	}

	tokenString := signRSAToken(t, privateKey, kid, claims)

	// Validate token
	info, err := validator.ValidateToken(context.Background(), tokenString)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}

	if info.UserID != "user-123" {
		t.Errorf("expected UserID 'user-123', got %q", info.UserID)
	}
	if info.OrganizationID != "org-456" {
		t.Errorf("expected OrganizationID 'org-456', got %q", info.OrganizationID)
	}
	if len(info.Scopes) != 2 {
		t.Errorf("expected 2 scopes, got %d", len(info.Scopes))
	}
}

func TestValidateToken_ExpiredToken(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	issuer := "https://test.issuer.com"
	kid := "test-kid"

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{Key: &privateKey.PublicKey, KeyID: kid, Algorithm: "RS256", Use: "sig"},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	validator, err := NewJWKSValidator(server.URL, issuer, "", 5*time.Minute, nil)
	if err != nil {
		t.Fatalf("NewJWKSValidator failed: %v", err)
	}

	// Create expired token
	claims := testClaims{
		Claims: josejwt.Claims{
			Issuer:   issuer,
			Subject:  "user-123",
			Expiry:   josejwt.NewNumericDate(time.Now().Add(-1 * time.Hour)), // expired 1 hour ago
			IssuedAt: josejwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
	}

	tokenString := signRSAToken(t, privateKey, kid, claims)

	_, err = validator.ValidateToken(context.Background(), tokenString)
	if err == nil {
		t.Error("expected error for expired token, got nil")
	}
}

func TestValidateToken_InvalidIssuer(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	kid := "test-kid"

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{Key: &privateKey.PublicKey, KeyID: kid, Algorithm: "RS256", Use: "sig"},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	validator, err := NewJWKSValidator(server.URL, "https://expected.issuer.com", "", 5*time.Minute, nil)
	if err != nil {
		t.Fatalf("NewJWKSValidator failed: %v", err)
	}

	// Create token with wrong issuer
	claims := testClaims{
		Claims: josejwt.Claims{
			Issuer:   "https://wrong.issuer.com",
			Subject:  "user-123",
			Expiry:   josejwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt: josejwt.NewNumericDate(time.Now()),
		},
	}

	tokenString := signRSAToken(t, privateKey, kid, claims)

	_, err = validator.ValidateToken(context.Background(), tokenString)
	if err == nil {
		t.Error("expected error for invalid issuer, got nil")
	}
}

func TestValidateToken_UnknownKid(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	issuer := "https://test.issuer.com"

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{Key: &privateKey.PublicKey, KeyID: "server-kid", Algorithm: "RS256", Use: "sig"},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	validator, err := NewJWKSValidator(server.URL, issuer, "", 5*time.Minute, nil)
	if err != nil {
		t.Fatalf("NewJWKSValidator failed: %v", err)
	}

	// Create token with different kid
	claims := testClaims{
		Claims: josejwt.Claims{
			Issuer:   issuer,
			Subject:  "user-123",
			Expiry:   josejwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt: josejwt.NewNumericDate(time.Now()),
		},
	}

	tokenString := signRSAToken(t, privateKey, "unknown-kid", claims) // different from server-kid

	_, err = validator.ValidateToken(context.Background(), tokenString)
	if err == nil {
		t.Error("expected error for unknown kid, got nil")
	}
}

func TestValidateToken_ValidECToken(t *testing.T) {
	// Generate EC key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}

	issuer := "https://test.issuer.com"
	kid := "ec-kid"

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{Key: &privateKey.PublicKey, KeyID: kid, Algorithm: "ES256", Use: "sig"},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	validator, err := NewJWKSValidator(server.URL, issuer, "", 5*time.Minute, nil)
	if err != nil {
		t.Fatalf("NewJWKSValidator failed: %v", err)
	}

	// Create valid EC token
	claims := testClaims{
		Claims: josejwt.Claims{
			Issuer:   issuer,
			Subject:  "user-ec",
			Expiry:   josejwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt: josejwt.NewNumericDate(time.Now()),
		},
		Scope: "admin",
	}

	tokenString := signECToken(t, privateKey, kid, claims)

	info, err := validator.ValidateToken(context.Background(), tokenString)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}

	if info.UserID != "user-ec" {
		t.Errorf("expected UserID 'user-ec', got %q", info.UserID)
	}
}

func TestValidateToken_MissingKid(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	issuer := "https://test.issuer.com"

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{Key: &privateKey.PublicKey, KeyID: "test-kid", Algorithm: "RS256", Use: "sig"},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	validator, err := NewJWKSValidator(server.URL, issuer, "", 5*time.Minute, nil)
	if err != nil {
		t.Fatalf("NewJWKSValidator failed: %v", err)
	}

	// Create token without kid header
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
		nil, // no options = no kid header
	)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	claims := testClaims{
		Claims: josejwt.Claims{
			Issuer:   issuer,
			Subject:  "user-123",
			Expiry:   josejwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt: josejwt.NewNumericDate(time.Now()),
		},
	}

	tokenString, err := josejwt.Signed(sig).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	_, err = validator.ValidateToken(context.Background(), tokenString)
	if err == nil {
		t.Error("expected error for missing kid, got nil")
	}
}

// === Audience validation tests ===

func TestValidateToken_ValidAudience(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	issuer := "https://test.issuer.com"
	audience := "https://my-api.example.com"
	kid := "test-kid"

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{Key: &privateKey.PublicKey, KeyID: kid, Algorithm: "RS256", Use: "sig"},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	validator, err := NewJWKSValidator(server.URL, issuer, audience, 5*time.Minute, nil)
	if err != nil {
		t.Fatalf("NewJWKSValidator failed: %v", err)
	}

	// Create token with correct audience
	claims := testClaims{
		Claims: josejwt.Claims{
			Issuer:   issuer,
			Subject:  "user-123",
			Audience: josejwt.Audience{audience},
			Expiry:   josejwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt: josejwt.NewNumericDate(time.Now()),
		},
	}

	tokenString := signRSAToken(t, privateKey, kid, claims)

	info, err := validator.ValidateToken(context.Background(), tokenString)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}

	if info.UserID != "user-123" {
		t.Errorf("expected UserID 'user-123', got %q", info.UserID)
	}
}

func TestValidateToken_InvalidAudience(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	issuer := "https://test.issuer.com"
	kid := "test-kid"

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{Key: &privateKey.PublicKey, KeyID: kid, Algorithm: "RS256", Use: "sig"},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	// Validator expects "https://my-api.example.com"
	validator, err := NewJWKSValidator(server.URL, issuer, "https://my-api.example.com", 5*time.Minute, nil)
	if err != nil {
		t.Fatalf("NewJWKSValidator failed: %v", err)
	}

	// Create token with WRONG audience
	claims := testClaims{
		Claims: josejwt.Claims{
			Issuer:   issuer,
			Subject:  "user-123",
			Audience: josejwt.Audience{"https://different-api.example.com"}, // Wrong audience!
			Expiry:   josejwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt: josejwt.NewNumericDate(time.Now()),
		},
	}

	tokenString := signRSAToken(t, privateKey, kid, claims)

	_, err = validator.ValidateToken(context.Background(), tokenString)
	if err == nil {
		t.Error("expected error for invalid audience, got nil")
	}
}

func TestValidateToken_MultipleAudiences(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	issuer := "https://test.issuer.com"
	audience := "https://my-api.example.com"
	kid := "test-kid"

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{Key: &privateKey.PublicKey, KeyID: kid, Algorithm: "RS256", Use: "sig"},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	validator, err := NewJWKSValidator(server.URL, issuer, audience, 5*time.Minute, nil)
	if err != nil {
		t.Fatalf("NewJWKSValidator failed: %v", err)
	}

	// Create token with multiple audiences (one matches)
	claims := testClaims{
		Claims: josejwt.Claims{
			Issuer:   issuer,
			Subject:  "user-123",
			Audience: josejwt.Audience{"https://other-api.com", audience, "https://third-api.com"},
			Expiry:   josejwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt: josejwt.NewNumericDate(time.Now()),
		},
	}

	tokenString := signRSAToken(t, privateKey, kid, claims)

	info, err := validator.ValidateToken(context.Background(), tokenString)
	if err != nil {
		t.Fatalf("ValidateToken should accept token with matching audience in array: %v", err)
	}

	if info.UserID != "user-123" {
		t.Errorf("expected UserID 'user-123', got %q", info.UserID)
	}
}

func TestValidateToken_NotBeforeInFuture(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	issuer := "https://test.issuer.com"
	kid := "test-kid"

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{Key: &privateKey.PublicKey, KeyID: kid, Algorithm: "RS256", Use: "sig"},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	validator, err := NewJWKSValidator(server.URL, issuer, "", 5*time.Minute, nil)
	if err != nil {
		t.Fatalf("NewJWKSValidator failed: %v", err)
	}

	// Create token that is not yet valid (nbf in future)
	claims := testClaims{
		Claims: josejwt.Claims{
			Issuer:    issuer,
			Subject:   "user-123",
			Expiry:    josejwt.NewNumericDate(time.Now().Add(2 * time.Hour)),
			NotBefore: josejwt.NewNumericDate(time.Now().Add(1 * time.Hour)), // Not valid for 1 hour
			IssuedAt:  josejwt.NewNumericDate(time.Now()),
		},
	}

	tokenString := signRSAToken(t, privateKey, kid, claims)

	_, err = validator.ValidateToken(context.Background(), tokenString)
	if err == nil {
		t.Error("expected error for token not yet valid (nbf), got nil")
	}
}

// === Claims tests ===

func TestClaims_HasAudience(t *testing.T) {
	tests := []struct {
		name     string
		audience []string
		check    string
		want     bool
	}{
		{"single match", []string{"https://api.example.com"}, "https://api.example.com", true},
		{"single no match", []string{"https://api.example.com"}, "https://other.com", false},
		{"multiple match first", []string{"https://api.example.com", "https://other.com"}, "https://api.example.com", true},
		{"multiple match second", []string{"https://api.example.com", "https://other.com"}, "https://other.com", true},
		{"multiple no match", []string{"https://api.example.com", "https://other.com"}, "https://third.com", false},
		{"empty audience", []string{}, "https://api.example.com", false},
		{"nil audience", nil, "https://api.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &Claims{Audience: tt.audience}
			if got := claims.HasAudience(tt.check); got != tt.want {
				t.Errorf("HasAudience(%q) = %v, want %v", tt.check, got, tt.want)
			}
		})
	}
}

func TestClaims_UnmarshalJSON_AudienceString(t *testing.T) {
	// Test audience as single string (per JWT spec, can be string or array)
	jsonData := `{
		"iss": "https://test.issuer.com",
		"sub": "user-123",
		"aud": "https://api.example.com",
		"exp": 1700000000
	}`

	var claims Claims
	err := json.Unmarshal([]byte(jsonData), &claims)
	if err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}

	if len(claims.Audience) != 1 {
		t.Errorf("expected 1 audience, got %d", len(claims.Audience))
	}
	if claims.Audience[0] != "https://api.example.com" {
		t.Errorf("Audience[0] = %q, want 'https://api.example.com'", claims.Audience[0])
	}
}

func TestClaims_UnmarshalJSON_AudienceArray(t *testing.T) {
	// Test audience as array
	jsonData := `{
		"iss": "https://test.issuer.com",
		"sub": "user-123",
		"aud": ["https://api1.example.com", "https://api2.example.com"],
		"exp": 1700000000
	}`

	var claims Claims
	err := json.Unmarshal([]byte(jsonData), &claims)
	if err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}

	if len(claims.Audience) != 2 {
		t.Errorf("expected 2 audiences, got %d", len(claims.Audience))
	}
	if claims.Audience[0] != "https://api1.example.com" {
		t.Errorf("Audience[0] = %q, want 'https://api1.example.com'", claims.Audience[0])
	}
	if claims.Audience[1] != "https://api2.example.com" {
		t.Errorf("Audience[1] = %q, want 'https://api2.example.com'", claims.Audience[1])
	}
}

func TestClaims_UnmarshalJSON(t *testing.T) {
	jsonData := `{
		"iss": "https://test.issuer.com",
		"sub": "user-123",
		"exp": 1700000000,
		"iat": 1699990000,
		"organization_id": "org-456",
		"scope": "read write"
	}`

	var claims Claims
	err := json.Unmarshal([]byte(jsonData), &claims)
	if err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}

	if claims.Issuer != "https://test.issuer.com" {
		t.Errorf("Issuer = %q, want 'https://test.issuer.com'", claims.Issuer)
	}
	if claims.Subject != "user-123" {
		t.Errorf("Subject = %q, want 'user-123'", claims.Subject)
	}
	if claims.OrganizationID != "org-456" {
		t.Errorf("OrganizationID = %q, want 'org-456'", claims.OrganizationID)
	}
	if claims.Scope != "read write" {
		t.Errorf("Scope = %q, want 'read write'", claims.Scope)
	}
	if claims.ExpiresAt == nil {
		t.Error("ExpiresAt should not be nil")
	} else if claims.ExpiresAt.Unix() != 1700000000 {
		t.Errorf("ExpiresAt = %d, want 1700000000", claims.ExpiresAt.Unix())
	}
	if claims.IssuedAt == nil {
		t.Error("IssuedAt should not be nil")
	} else if claims.IssuedAt.Unix() != 1699990000 {
		t.Errorf("IssuedAt = %d, want 1699990000", claims.IssuedAt.Unix())
	}
}

func TestClaims_GetScopes(t *testing.T) {
	tests := []struct {
		name     string
		scope    string
		expected []string
	}{
		{"empty", "", []string{}},
		{"single", "read", []string{"read"}},
		{"multiple", "read write delete", []string{"read", "write", "delete"}},
		{"with extra spaces", "read  write   delete", []string{"read", "write", "delete"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &Claims{Scope: tt.scope}
			scopes := claims.GetScopes()
			if len(scopes) != len(tt.expected) {
				t.Errorf("GetScopes() returned %d items, want %d", len(scopes), len(tt.expected))
				return
			}
			for i, s := range tt.expected {
				if scopes[i] != s {
					t.Errorf("scope[%d] = %q, want %q", i, scopes[i], s)
				}
			}
		})
	}
}

// === Token interface tests ===

func TestTokenInfo_ImplementsTokenInterface(t *testing.T) {
	// Compile-time check that TokenInfo implements Token
	var _ Token = (*TokenInfo)(nil)

	// Runtime check
	info := &TokenInfo{
		UserID:         "user-123",
		OrganizationID: "org-456",
		Scopes:         []string{"read", "write"},
		RawClaims:      map[string]any{"custom": "value"},
	}

	var token Token = info

	if token.GetUserID() != "user-123" {
		t.Errorf("GetUserID() = %q, want 'user-123'", token.GetUserID())
	}
	if token.GetOrganizationID() != "org-456" {
		t.Errorf("GetOrganizationID() = %q, want 'org-456'", token.GetOrganizationID())
	}
	if len(token.GetScopes()) != 2 {
		t.Errorf("GetScopes() length = %d, want 2", len(token.GetScopes()))
	}
	if !token.HasScope("read") {
		t.Error("HasScope('read') should return true")
	}
	if !token.HasAllScopes("read", "write") {
		t.Error("HasAllScopes('read', 'write') should return true")
	}
	if token.HasAnyScope("admin", "delete") {
		t.Error("HasAnyScope('admin', 'delete') should return false")
	}
	if token.GetRawClaims()["custom"] != "value" {
		t.Error("GetRawClaims() should return raw claims")
	}
}

// === New TokenInfo fields tests ===

func TestTokenInfo_AllJWTFields(t *testing.T) {
	now := time.Now()
	exp := now.Add(1 * time.Hour)
	nbf := now.Add(-5 * time.Minute)

	info := &TokenInfo{
		// Standard JWT claims
		Issuer:    "https://test.logto.app/oidc",
		Subject:   "user-123",
		Audience:  []string{"https://api.example.com"},
		ExpiresAt: &exp,
		IssuedAt:  &now,
		NotBefore: &nbf,
		JWTID:     "token-id-abc",

		// Logto-specific
		ClientID:       "app-456",
		OrganizationID: "org-789",
		Scopes:         []string{"read", "write"},

		// Alias
		UserID: "user-123",

		RawClaims: map[string]any{},
	}

	// Verify all fields
	if info.Issuer != "https://test.logto.app/oidc" {
		t.Errorf("Issuer = %q, want 'https://test.logto.app/oidc'", info.Issuer)
	}
	if info.Subject != "user-123" {
		t.Errorf("Subject = %q, want 'user-123'", info.Subject)
	}
	if info.UserID != info.Subject {
		t.Errorf("UserID should equal Subject")
	}
	if len(info.Audience) != 1 || info.Audience[0] != "https://api.example.com" {
		t.Errorf("Audience = %v, want ['https://api.example.com']", info.Audience)
	}
	if info.ExpiresAt == nil || info.ExpiresAt.Unix() != exp.Unix() {
		t.Error("ExpiresAt not set correctly")
	}
	if info.IssuedAt == nil || info.IssuedAt.Unix() != now.Unix() {
		t.Error("IssuedAt not set correctly")
	}
	if info.NotBefore == nil || info.NotBefore.Unix() != nbf.Unix() {
		t.Error("NotBefore not set correctly")
	}
	if info.JWTID != "token-id-abc" {
		t.Errorf("JWTID = %q, want 'token-id-abc'", info.JWTID)
	}
	if info.ClientID != "app-456" {
		t.Errorf("ClientID = %q, want 'app-456'", info.ClientID)
	}
	if info.OrganizationID != "org-789" {
		t.Errorf("OrganizationID = %q, want 'org-789'", info.OrganizationID)
	}
}

func TestTokenInfo_HasAudience(t *testing.T) {
	info := &TokenInfo{
		Audience: []string{"https://api1.example.com", "https://api2.example.com"},
	}

	tests := []struct {
		audience string
		want     bool
	}{
		{"https://api1.example.com", true},
		{"https://api2.example.com", true},
		{"https://api3.example.com", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.audience, func(t *testing.T) {
			if got := info.HasAudience(tt.audience); got != tt.want {
				t.Errorf("HasAudience(%q) = %v, want %v", tt.audience, got, tt.want)
			}
		})
	}
}

func TestTokenInfo_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt *time.Time
		want      bool
	}{
		{"nil expiration", nil, false},
		{"future expiration", func() *time.Time { t := time.Now().Add(1 * time.Hour); return &t }(), false},
		{"past expiration", func() *time.Time { t := time.Now().Add(-1 * time.Hour); return &t }(), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &TokenInfo{ExpiresAt: tt.expiresAt}
			if got := info.IsExpired(); got != tt.want {
				t.Errorf("IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

// === ClientID claim tests ===

func TestClaims_ClientID(t *testing.T) {
	jsonData := `{
		"iss": "https://test.issuer.com",
		"sub": "user-123",
		"client_id": "my-app-id",
		"exp": 1700000000
	}`

	var claims Claims
	err := json.Unmarshal([]byte(jsonData), &claims)
	if err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}

	if claims.ClientID != "my-app-id" {
		t.Errorf("ClientID = %q, want 'my-app-id'", claims.ClientID)
	}
}

func TestValidateToken_FillsAllFields(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	issuer := "https://test.issuer.com"
	audience := "https://my-api.example.com"
	kid := "test-kid"

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{Key: &privateKey.PublicKey, KeyID: kid, Algorithm: "RS256", Use: "sig"},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	validator, err := NewJWKSValidator(server.URL, issuer, audience, 5*time.Minute, nil)
	if err != nil {
		t.Fatalf("NewJWKSValidator failed: %v", err)
	}

	// Create token with all claims
	claims := testClaims{
		Claims: josejwt.Claims{
			Issuer:   issuer,
			Subject:  "user-123",
			Audience: josejwt.Audience{audience},
			Expiry:   josejwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt: josejwt.NewNumericDate(time.Now()),
			ID:       "jwt-id-xyz",
		},
		Scope:          "read write",
		OrganizationID: "org-456",
		ClientID:       "app-789",
	}

	tokenString := signRSAToken(t, privateKey, kid, claims)

	info, err := validator.ValidateToken(context.Background(), tokenString)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}

	// Verify all fields are populated
	if info.Issuer != issuer {
		t.Errorf("Issuer = %q, want %q", info.Issuer, issuer)
	}
	if info.Subject != "user-123" {
		t.Errorf("Subject = %q, want 'user-123'", info.Subject)
	}
	if info.UserID != "user-123" {
		t.Errorf("UserID = %q, want 'user-123'", info.UserID)
	}
	if len(info.Audience) != 1 || info.Audience[0] != audience {
		t.Errorf("Audience = %v, want [%q]", info.Audience, audience)
	}
	if info.ExpiresAt == nil {
		t.Error("ExpiresAt should not be nil")
	}
	if info.IssuedAt == nil {
		t.Error("IssuedAt should not be nil")
	}
	if info.JWTID != "jwt-id-xyz" {
		t.Errorf("JWTID = %q, want 'jwt-id-xyz'", info.JWTID)
	}
	if info.ClientID != "app-789" {
		t.Errorf("ClientID = %q, want 'app-789'", info.ClientID)
	}
	if info.OrganizationID != "org-456" {
		t.Errorf("OrganizationID = %q, want 'org-456'", info.OrganizationID)
	}
	if len(info.Scopes) != 2 {
		t.Errorf("Scopes length = %d, want 2", len(info.Scopes))
	}
}
