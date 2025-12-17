package client

import (
	"errors"
	"testing"
)

func TestAPIError_Is_MembershipRequired(t *testing.T) {
	tests := []struct {
		name       string
		apiError   *APIError
		target     error
		wantResult bool
	}{
		{
			name: "422 with membership code matches ErrMembershipRequired",
			apiError: &APIError{
				StatusCode: 422,
				Code:       "organization.require_membership",
				Message:    "User must be a member of the organization",
			},
			target:     ErrMembershipRequired,
			wantResult: true,
		},
		{
			name: "422 with membership code also matches ErrUnprocessableEntity (multiple match)",
			apiError: &APIError{
				StatusCode: 422,
				Code:       "organization.require_membership",
				Message:    "User must be a member of the organization",
			},
			target:     ErrUnprocessableEntity,
			wantResult: true,
		},
		{
			name: "422 without code matches ErrUnprocessableEntity",
			apiError: &APIError{
				StatusCode: 422,
				Message:    "Some validation error",
			},
			target:     ErrUnprocessableEntity,
			wantResult: true,
		},
		{
			name: "422 without code does NOT match ErrMembershipRequired",
			apiError: &APIError{
				StatusCode: 422,
				Message:    "Some validation error",
			},
			target:     ErrMembershipRequired,
			wantResult: false,
		},
		{
			name: "422 with different code does NOT match ErrMembershipRequired",
			apiError: &APIError{
				StatusCode: 422,
				Code:       "entity.invalid",
				Message:    "Invalid entity",
			},
			target:     ErrMembershipRequired,
			wantResult: false,
		},
		{
			name: "422 with different code matches ErrUnprocessableEntity",
			apiError: &APIError{
				StatusCode: 422,
				Code:       "entity.invalid",
				Message:    "Invalid entity",
			},
			target:     ErrUnprocessableEntity,
			wantResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := errors.Is(tt.apiError, tt.target)
			if got != tt.wantResult {
				t.Errorf("errors.Is(apiError, %v) = %v, want %v", tt.target, got, tt.wantResult)
			}
		})
	}
}

func TestAPIError_Is_StandardCases(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		target     error
		wantResult bool
	}{
		{"400 matches ErrBadRequest", 400, ErrBadRequest, true},
		{"401 matches ErrUnauthorized", 401, ErrUnauthorized, true},
		{"403 matches ErrForbidden", 403, ErrForbidden, true},
		{"404 matches ErrNotFound", 404, ErrNotFound, true},
		{"409 matches ErrConflict", 409, ErrConflict, true},
		{"429 matches ErrRateLimited", 429, ErrRateLimited, true},
		{"500 matches ErrServerError", 500, ErrServerError, true},
		{"502 matches ErrServerError", 502, ErrServerError, true},
		{"503 matches ErrServerError", 503, ErrServerError, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiErr := &APIError{StatusCode: tt.statusCode}
			got := errors.Is(apiErr, tt.target)
			if got != tt.wantResult {
				t.Errorf("errors.Is(apiError[%d], %v) = %v, want %v",
					tt.statusCode, tt.target, got, tt.wantResult)
			}
		})
	}
}
