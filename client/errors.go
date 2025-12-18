package client

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Sentinel errors for use with errors.Is()
var (
	// ErrNotFound indicates the requested resource was not found (HTTP 404).
	ErrNotFound = errors.New("resource not found")

	// ErrUnauthorized indicates invalid or missing authentication (HTTP 401).
	ErrUnauthorized = errors.New("unauthorized")

	// ErrForbidden indicates insufficient permissions (HTTP 403).
	ErrForbidden = errors.New("forbidden")

	// ErrBadRequest indicates invalid request parameters (HTTP 400).
	ErrBadRequest = errors.New("bad request")

	// ErrConflict indicates a resource conflict, e.g., duplicate entry (HTTP 409).
	ErrConflict = errors.New("resource conflict")

	// ErrUnprocessableEntity indicates semantic validation failure (HTTP 422).
	ErrUnprocessableEntity = errors.New("unprocessable entity")

	// ErrMembershipRequired indicates the user must be an organization member (HTTP 422, code: organization.require_membership).
	ErrMembershipRequired = errors.New("organization membership required")

	// ErrRateLimited indicates too many requests (HTTP 429).
	ErrRateLimited = errors.New("rate limited")

	// ErrServerError indicates an internal server error (HTTP 5xx).
	ErrServerError = errors.New("server error")

	// ErrInvalidInput indicates validation failure for input parameters.
	ErrInvalidInput = errors.New("invalid input")

	// ErrUserNotFound indicates no user was found matching the search criteria.
	ErrUserNotFound = errors.New("user not found")
)

// APIError represents an error response from the Logto API.
type APIError struct {
	StatusCode int    // HTTP status code
	Message    string // Error message from API
	Code       string // Error code from API (if available)
	RequestID  string // Request ID from X-Request-Id header (for debugging)
	Body       []byte // Raw response body (for debugging)
}

// Error implements the error interface.
func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("logto api error (status %d, code %s): %s", e.StatusCode, e.Code, e.Message)
	}
	return fmt.Sprintf("logto api error (status %d): %s", e.StatusCode, e.Message)
}

// Is implements errors.Is() for comparing with sentinel errors.
func (e *APIError) Is(target error) bool {
	switch e.StatusCode {
	case 400:
		return target == ErrBadRequest
	case 401:
		return target == ErrUnauthorized
	case 403:
		return target == ErrForbidden
	case 404:
		return target == ErrNotFound
	case 409:
		return target == ErrConflict
	case 422:
		if e.Code == "organization.require_membership" {
			return target == ErrMembershipRequired || target == ErrUnprocessableEntity
		}
		return target == ErrUnprocessableEntity
	case 429:
		return target == ErrRateLimited
	}
	if e.StatusCode >= 500 && e.StatusCode < 600 {
		return target == ErrServerError
	}
	return false
}

// Unwrap returns nil as APIError doesn't wrap other errors.
func (e *APIError) Unwrap() error {
	return nil
}

// ValidationError represents an input validation error.
type ValidationError struct {
	Field   string // Field name that failed validation
	Message string // Validation error message
}

// Error implements the error interface.
func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error: %s: %s", e.Field, e.Message)
}

// Is implements errors.Is() for comparing with ErrInvalidInput.
func (e *ValidationError) Is(target error) bool {
	return target == ErrInvalidInput
}

// Unwrap returns ErrInvalidInput for error chain.
func (e *ValidationError) Unwrap() error {
	return ErrInvalidInput
}

// newAPIErrorFromResponse creates an APIError with JSON parsing support.
// It attempts to extract structured error info from the response body.
func newAPIErrorFromResponse(statusCode int, body []byte, requestID string) *APIError {
	apiErr := &APIError{
		StatusCode: statusCode,
		Message:    string(body),
		RequestID:  requestID,
		Body:       body,
	}

	// Try to parse JSON error response from Logto
	var errResp struct {
		Message string `json:"message"`
		Code    string `json:"code"`
	}
	if json.Unmarshal(body, &errResp) == nil {
		if errResp.Message != "" {
			apiErr.Message = errResp.Message
		}
		apiErr.Code = errResp.Code
	}

	return apiErr
}

// isExpectedStatus checks if the status code is in the expected list.
// If expected is empty, it defaults to checking for 200 OK.
func isExpectedStatus(code int, expected []int) bool {
	if len(expected) == 0 {
		return code == 200
	}
	for _, e := range expected {
		if code == e {
			return true
		}
	}
	return false
}
