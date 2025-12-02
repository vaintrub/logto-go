package client

import (
	"testing"
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
