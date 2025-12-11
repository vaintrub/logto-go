package client

import (
	"context"
	"net/http"
)

// VerificationCodeRequest represents a request to send a verification code.
type VerificationCodeRequest struct {
	// Email to send verification code to (mutually exclusive with Phone)
	Email string `json:"email,omitempty"`
	// Phone to send verification code to (mutually exclusive with Email)
	Phone string `json:"phone,omitempty"`
}

// VerifyCodeRequest represents a request to verify a code.
type VerifyCodeRequest struct {
	// Email that received the verification code (mutually exclusive with Phone)
	Email string `json:"email,omitempty"`
	// Phone that received the verification code (mutually exclusive with Email)
	Phone string `json:"phone,omitempty"`
	// VerificationCode is the code to verify
	VerificationCode string `json:"verificationCode"`
}

// RequestVerificationCode sends a verification code to the specified email or phone.
// Use this before changing a user's primary email or phone.
// POST /api/verification-codes
func (a *Adapter) RequestVerificationCode(ctx context.Context, req VerificationCodeRequest) error {
	if req.Email == "" && req.Phone == "" {
		return &ValidationError{Field: "email/phone", Message: "either email or phone must be provided"}
	}
	if req.Email != "" && req.Phone != "" {
		return &ValidationError{Field: "email/phone", Message: "only one of email or phone should be provided"}
	}

	_, _, err := a.doRequest(ctx, requestConfig{
		method:      http.MethodPost,
		path:        "/api/verification-codes",
		body:        req,
		expectCodes: []int{http.StatusNoContent, http.StatusOK},
	})
	return err
}

// VerifyCode verifies a verification code that was sent via RequestVerificationCode.
// After successful verification, you can update the user's email/phone using UpdateUser.
// POST /api/verification-codes/verify
func (a *Adapter) VerifyCode(ctx context.Context, req VerifyCodeRequest) error {
	if req.Email == "" && req.Phone == "" {
		return &ValidationError{Field: "email/phone", Message: "either email or phone must be provided"}
	}
	if req.VerificationCode == "" {
		return &ValidationError{Field: "verificationCode", Message: "cannot be empty"}
	}

	_, _, err := a.doRequest(ctx, requestConfig{
		method:      http.MethodPost,
		path:        "/api/verification-codes/verify",
		body:        req,
		expectCodes: []int{http.StatusNoContent, http.StatusOK},
	})
	return err
}
