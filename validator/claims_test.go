package validator

import (
	"testing"
)

func TestClaims_GetScopes_Empty(t *testing.T) {
	claims := &Claims{}
	scopes := claims.GetScopes()

	if len(scopes) != 0 {
		t.Errorf("expected empty scopes, got %v", scopes)
	}
}

func TestClaims_GetScopes_Single(t *testing.T) {
	claims := &Claims{
		Scope: "read",
	}
	scopes := claims.GetScopes()

	if len(scopes) != 1 {
		t.Errorf("expected 1 scope, got %d", len(scopes))
	}
	if scopes[0] != "read" {
		t.Errorf("expected 'read', got %q", scopes[0])
	}
}

func TestClaims_GetScopes_Multiple(t *testing.T) {
	claims := &Claims{
		Scope: "read write delete",
	}
	scopes := claims.GetScopes()

	if len(scopes) != 3 {
		t.Errorf("expected 3 scopes, got %d", len(scopes))
	}
	expected := []string{"read", "write", "delete"}
	for i, s := range expected {
		if scopes[i] != s {
			t.Errorf("scope[%d] = %q, want %q", i, scopes[i], s)
		}
	}
}

func TestClaims_GetScopes_WithExtraSpaces(t *testing.T) {
	claims := &Claims{
		Scope: "read  write   delete",
	}
	scopes := claims.GetScopes()

	// strings.Fields handles multiple spaces correctly
	if len(scopes) != 3 {
		t.Errorf("expected 3 scopes, got %d: %v", len(scopes), scopes)
	}
}

func TestClaims_OrganizationID(t *testing.T) {
	tests := []struct {
		name     string
		orgID    string
		expected string
	}{
		{"empty", "", ""},
		{"with_org_id", "org-123", "org-123"},
		{"with_urn", "urn:logto:organization:abc", "urn:logto:organization:abc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &Claims{OrganizationID: tt.orgID}
			if got := claims.OrganizationID; got != tt.expected {
				t.Errorf("OrganizationID = %q, want %q", got, tt.expected)
			}
		})
	}
}
