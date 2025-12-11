package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/vaintrub/logto-go/models"
)

// GetUser retrieves user information from Logto
func (a *Adapter) GetUser(ctx context.Context, userID string) (*models.User, error) {
	if userID == "" {
		return nil, &ValidationError{Field: "userID", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodGet,
		path:       "/api/users/%s",
		pathParams: []string{userID},
	})
	if err != nil {
		return nil, err
	}

	return parseUserResponse(body)
}

// GetUserByEmail retrieves user information by email
func (a *Adapter) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	if email == "" {
		return nil, &ValidationError{Field: "email", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method: http.MethodGet,
		path:   "/api/users",
		query:  url.Values{"search": {email}},
	})
	if err != nil {
		return nil, err
	}

	var users []json.RawMessage
	if err := json.Unmarshal(body, &users); err != nil {
		return nil, fmt.Errorf("unmarshal users search response: %w", err)
	}

	// Find user with exact email match
	for _, userData := range users {
		user, err := parseUserResponse(userData)
		if err != nil {
			continue
		}
		if user.PrimaryEmail == email {
			return user, nil
		}
	}

	return nil, &APIError{StatusCode: 404, Message: fmt.Sprintf("user not found with email: %s", email)}
}

// ListUsers retrieves all users.
// Returns users and any error. If some items failed to parse, returns partial results
// with a combined error containing all parse failures.
func (a *Adapter) ListUsers(ctx context.Context) ([]models.User, error) {
	body, _, err := a.doRequest(ctx, requestConfig{
		method: http.MethodGet,
		path:   "/api/users",
	})
	if err != nil {
		return nil, err
	}

	var usersData []json.RawMessage
	if err := json.Unmarshal(body, &usersData); err != nil {
		return nil, fmt.Errorf("unmarshal users response: %w", err)
	}

	users := make([]models.User, 0, len(usersData))
	var parseErrs []error
	for _, userData := range usersData {
		user, err := parseUserResponse(userData)
		if err != nil {
			parseErrs = append(parseErrs, err)
			continue
		}
		users = append(users, *user)
	}

	if len(parseErrs) > 0 {
		return users, fmt.Errorf("failed to parse %d user(s): %w", len(parseErrs), errors.Join(parseErrs...))
	}
	return users, nil
}

// CreateUser creates a new user in Logto
func (a *Adapter) CreateUser(ctx context.Context, user models.UserCreate) (*models.User, error) {
	if user.Username == "" {
		return nil, &ValidationError{Field: "username", Message: "cannot be empty"}
	}
	if user.Password == "" {
		return nil, &ValidationError{Field: "password", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:      http.MethodPost,
		path:        "/api/users",
		body:        user,
		expectCodes: []int{http.StatusCreated, http.StatusOK},
	})
	if err != nil {
		return nil, err
	}

	return parseUserResponse(body)
}

// UpdateUser updates user profile fields.
// Note: For changing email/phone, consider using verification code flow first.
// PATCH /api/users/{userId}
func (a *Adapter) UpdateUser(ctx context.Context, userID string, update models.UserUpdate) (*models.User, error) {
	if userID == "" {
		return nil, &ValidationError{Field: "userID", Message: "cannot be empty"}
	}

	payload := make(map[string]interface{})
	if update.Username != nil {
		payload["username"] = *update.Username
	}
	if update.Name != nil {
		payload["name"] = *update.Name
	}
	if update.Avatar != nil {
		payload["avatar"] = *update.Avatar
	}
	if update.PrimaryEmail != nil {
		payload["primaryEmail"] = *update.PrimaryEmail
	}
	if update.PrimaryPhone != nil {
		payload["primaryPhone"] = *update.PrimaryPhone
	}
	if update.CustomData != nil {
		payload["customData"] = update.CustomData
	}
	if update.Profile != nil {
		payload["profile"] = update.Profile
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodPatch,
		path:       "/api/users/%s",
		pathParams: []string{userID},
		body:       payload,
	})
	if err != nil {
		return nil, err
	}

	return parseUserResponse(body)
}

// DeleteUser deletes a user by ID
// DELETE /api/users/{userId}
func (a *Adapter) DeleteUser(ctx context.Context, userID string) error {
	if userID == "" {
		return &ValidationError{Field: "userID", Message: "cannot be empty"}
	}

	_, _, err := a.doRequest(ctx, requestConfig{
		method:      http.MethodDelete,
		path:        "/api/users/%s",
		pathParams:  []string{userID},
		expectCodes: []int{http.StatusNoContent},
	})
	return err
}

// UpdateUserPassword sets a new password for the user.
// Note: This does not require the old password. Use VerifyUserPassword first
// if you need to verify the current password before changing it.
// PATCH /api/users/{userId}/password
func (a *Adapter) UpdateUserPassword(ctx context.Context, userID string, update models.UserPasswordUpdate) error {
	if userID == "" {
		return &ValidationError{Field: "userID", Message: "cannot be empty"}
	}
	if update.Password == "" {
		return &ValidationError{Field: "password", Message: "cannot be empty"}
	}

	_, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodPatch,
		path:       "/api/users/%s/password",
		pathParams: []string{userID},
		body:       update,
	})
	return err
}

// VerifyUserPassword checks if the provided password matches the user's current password.
// Returns true if password is correct, false otherwise.
// POST /api/users/{userId}/password/verify
func (a *Adapter) VerifyUserPassword(ctx context.Context, userID, password string) (bool, error) {
	if userID == "" {
		return false, &ValidationError{Field: "userID", Message: "cannot be empty"}
	}
	if password == "" {
		return false, &ValidationError{Field: "password", Message: "cannot be empty"}
	}

	_, statusCode, err := a.doRequest(ctx, requestConfig{
		method:      http.MethodPost,
		path:        "/api/users/%s/password/verify",
		pathParams:  []string{userID},
		body:        map[string]interface{}{"password": password},
		expectCodes: []int{http.StatusNoContent, http.StatusUnprocessableEntity, http.StatusBadRequest},
	})
	if err != nil {
		return false, err
	}

	return statusCode == http.StatusNoContent, nil
}

// HasUserPassword checks if the user has a password set.
// GET /api/users/{userId}/has-password
func (a *Adapter) HasUserPassword(ctx context.Context, userID string) (bool, error) {
	if userID == "" {
		return false, &ValidationError{Field: "userID", Message: "cannot be empty"}
	}

	body, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodGet,
		path:       "/api/users/%s/has-password",
		pathParams: []string{userID},
	})
	if err != nil {
		return false, err
	}

	var result struct {
		HasPassword bool `json:"hasPassword"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return false, fmt.Errorf("unmarshal has-password response: %w", err)
	}

	return result.HasPassword, nil
}

// SuspendUser updates the suspension status of a user.
// PATCH /api/users/{userId}/is-suspended
func (a *Adapter) SuspendUser(ctx context.Context, userID string, suspended bool) error {
	if userID == "" {
		return &ValidationError{Field: "userID", Message: "cannot be empty"}
	}

	_, _, err := a.doRequest(ctx, requestConfig{
		method:     http.MethodPatch,
		path:       "/api/users/%s/is-suspended",
		pathParams: []string{userID},
		body: map[string]interface{}{
			"isSuspended": suspended,
		},
	})
	return err
}

// listUsersPaginated returns users with pagination support
func (a *Adapter) listUsersPaginated(ctx context.Context, page, pageSize int) ([]*models.User, error) {
	body, _, err := a.doRequest(ctx, requestConfig{
		method: http.MethodGet,
		path:   "/api/users",
		query: url.Values{
			"page":      {fmt.Sprintf("%d", page)},
			"page_size": {fmt.Sprintf("%d", pageSize)},
		},
	})
	if err != nil {
		return nil, err
	}

	var usersData []json.RawMessage
	if err := json.Unmarshal(body, &usersData); err != nil {
		return nil, fmt.Errorf("unmarshal paginated users response: %w", err)
	}

	users := make([]*models.User, 0, len(usersData))
	for _, userData := range usersData {
		user, err := parseUserResponse(userData)
		if err != nil {
			// Skip invalid items in pagination - errors are less critical here
			continue
		}
		users = append(users, user)
	}

	return users, nil
}

// parseUserResponse parses user from API response
func parseUserResponse(data []byte) (*models.User, error) {
	// Parse with intermediate struct to handle timestamp conversion
	var raw struct {
		ID                     string                         `json:"id"`
		TenantID               string                         `json:"tenantId"`
		Username               string                         `json:"username"`
		PrimaryEmail           string                         `json:"primaryEmail"`
		PrimaryPhone           string                         `json:"primaryPhone"`
		Name                   string                         `json:"name"`
		Avatar                 string                         `json:"avatar"`
		CustomData             map[string]interface{}         `json:"customData"`
		Identities             map[string]models.UserIdentity `json:"identities"`
		LastSignInAt           *int64                         `json:"lastSignInAt"`
		CreatedAt              int64                          `json:"createdAt"`
		UpdatedAt              int64                          `json:"updatedAt"`
		Profile                *models.UserProfile            `json:"profile"`
		ApplicationID          string                         `json:"applicationId"`
		IsSuspended            bool                           `json:"isSuspended"`
		HasPassword            bool                           `json:"hasPassword"`
		SSOIdentities          []models.SSOIdentity           `json:"ssoIdentities"`
		MFAVerificationFactors []string                       `json:"mfaVerificationFactors"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse user: %w", err)
	}

	customData := raw.CustomData
	if customData == nil {
		customData = make(map[string]interface{})
	}

	identities := raw.Identities
	if identities == nil {
		identities = make(map[string]models.UserIdentity)
	}

	var lastSignInAt *time.Time
	if raw.LastSignInAt != nil {
		t := time.UnixMilli(*raw.LastSignInAt)
		lastSignInAt = &t
	}

	return &models.User{
		ID:                     raw.ID,
		TenantID:               raw.TenantID,
		Username:               raw.Username,
		PrimaryEmail:           raw.PrimaryEmail,
		PrimaryPhone:           raw.PrimaryPhone,
		Name:                   raw.Name,
		Avatar:                 raw.Avatar,
		CustomData:             customData,
		Identities:             identities,
		LastSignInAt:           lastSignInAt,
		CreatedAt:              time.UnixMilli(raw.CreatedAt),
		UpdatedAt:              time.UnixMilli(raw.UpdatedAt),
		Profile:                raw.Profile,
		ApplicationID:          raw.ApplicationID,
		IsSuspended:            raw.IsSuspended,
		HasPassword:            raw.HasPassword,
		SSOIdentities:          raw.SSOIdentities,
		MFAVerificationFactors: raw.MFAVerificationFactors,
	}, nil
}
