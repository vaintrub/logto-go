package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

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

	var users []models.User
	if err := json.Unmarshal(body, &users); err != nil {
		return nil, fmt.Errorf("unmarshal users search: %w", err)
	}

	// Find user with exact email match
	for i := range users {
		if users[i].PrimaryEmail == email {
			return &users[i], nil
		}
	}

	return nil, ErrUserNotFound
}

// ListUsers returns an iterator for paginating through all users.
// Use iter.Next(ctx) to iterate, iter.Item() to get current user.
//
// Example:
//
//	iter := client.ListUsers(client.IteratorConfig{PageSize: 50})
//	for iter.Next(ctx) {
//	    user := iter.Item()
//	    fmt.Println(user.ID)
//	}
//	if err := iter.Err(); err != nil {
//	    return err
//	}
func (a *Adapter) ListUsers(config IteratorConfig) *Iterator[models.User] {
	return NewIterator(a.listUsersPaginated, config)
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
		expectCodes: []int{http.StatusOK, http.StatusCreated},
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
		expectCodes: []int{http.StatusOK, http.StatusNoContent},
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
func (a *Adapter) listUsersPaginated(ctx context.Context, page, pageSize int) (PageResult[models.User], error) {
	result, err := a.doRequestFull(ctx, requestConfig{
		method: http.MethodGet,
		path:   "/api/users",
		query: url.Values{
			"page":      {fmt.Sprintf("%d", page)},
			"page_size": {fmt.Sprintf("%d", pageSize)},
		},
	})
	if err != nil {
		return PageResult[models.User]{}, err
	}

	var users []models.User
	if err := json.Unmarshal(result.Body, &users); err != nil {
		return PageResult[models.User]{}, fmt.Errorf("unmarshal paginated users: %w", err)
	}

	return PageResult[models.User]{
		Items: users,
		Total: getTotalFromHeaders(result.Headers),
	}, nil
}

// parseUserResponse parses user from API response
func parseUserResponse(data []byte) (*models.User, error) {
	var user models.User
	if err := json.Unmarshal(data, &user); err != nil {
		return nil, fmt.Errorf("parse user: %w", err)
	}
	if user.CustomData == nil {
		user.CustomData = make(map[string]interface{})
	}
	if user.Identities == nil {
		user.Identities = make(map[string]models.UserIdentity)
	}
	return &user, nil
}
