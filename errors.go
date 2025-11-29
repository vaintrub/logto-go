package logto

import (
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

	// ErrRateLimited indicates too many requests (HTTP 429).
	ErrRateLimited = errors.New("rate limited")

	// ErrServerError indicates an internal server error (HTTP 5xx).
	ErrServerError = errors.New("server error")

	// ErrInvalidInput indicates validation failure for input parameters.
	ErrInvalidInput = errors.New("invalid input")
)

// APIError represents an error response from the Logto API.
type APIError struct {
	StatusCode int    // HTTP status code
	Message    string // Error message from API
	Code       string // Error code from API (if available)
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

// newAPIError creates an APIError from HTTP status and response body.
func newAPIError(statusCode int, body []byte) *APIError {
	return &APIError{
		StatusCode: statusCode,
		Message:    string(body),
	}
}

// isRetryable returns true if the error represents a retryable condition.
func isRetryable(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return isRetryableStatus(apiErr.StatusCode)
	}
	return false
}

// isRetryableStatus returns true if the HTTP status code is retryable.
func isRetryableStatus(statusCode int) bool {
	switch statusCode {
	case 408, // Request Timeout
		429, // Too Many Requests
		500, // Internal Server Error
		502, // Bad Gateway
		503, // Service Unavailable
		504: // Gateway Timeout
		return true
	}
	return false
}
