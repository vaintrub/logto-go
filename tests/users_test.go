package tests

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vaintrub/logto-go/models"
)

// TestUserCRUD tests user creation, retrieval, update, and deletion
func TestUserCRUD(t *testing.T) {
	ctx := context.Background()
	username := fmt.Sprintf("testuser_%d", time.Now().UnixNano())
	email := fmt.Sprintf("testuser%d@test.local", time.Now().UnixNano())

	// Create user
	createdUser, err := testClient.CreateUser(ctx, username, "Password123!", "Test User", email)
	require.NoError(t, err, "CreateUser should succeed")
	assert.NotEmpty(t, createdUser.ID, "User ID should not be empty")
	userID := createdUser.ID

	// Get user
	user, err := testClient.GetUser(ctx, userID)
	require.NoError(t, err, "GetUser should succeed")
	assert.Equal(t, userID, user.ID)
	assert.Equal(t, "Test User", user.Name)
	assert.Equal(t, email, user.PrimaryEmail)

	// Get user by email
	userByEmail, err := testClient.GetUserByEmail(ctx, email)
	require.NoError(t, err, "GetUserByEmail should succeed")
	assert.Equal(t, userID, userByEmail.ID)

	// Update user
	newName := "Updated User"
	updatedUser, err := testClient.UpdateUser(ctx, userID, models.UserUpdate{Name: &newName})
	require.NoError(t, err, "UpdateUser should succeed")
	assert.Equal(t, newName, updatedUser.Name)

	// Verify update
	verifiedUser, err := testClient.GetUser(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, newName, verifiedUser.Name)

	// Update custom data
	_, err = testClient.UpdateUserCustomData(ctx, userID, map[string]interface{}{"key": "value"})
	require.NoError(t, err, "UpdateUserCustomData should succeed")

	// List users
	users, err := testClient.ListUsers(ctx)
	require.NoError(t, err, "ListUsers should succeed")
	assert.NotEmpty(t, users, "Should have at least one user")

	// Verify our user is in the list
	found := false
	for _, u := range users {
		if u.ID == userID {
			found = true
			break
		}
	}
	assert.True(t, found, "Created user should be in the list")
}

// TestUpdateUserProfile tests updating user profile fields (familyName, givenName, etc.)
func TestUpdateUserProfile(t *testing.T) {
	ctx := context.Background()
	username := fmt.Sprintf("profileuser_%d", time.Now().UnixNano())

	// Create user
	createdUser, err := testClient.CreateUser(ctx, username, "Password123!", "", "")
	require.NoError(t, err, "CreateUser should succeed")
	userID := createdUser.ID

	// Update profile
	familyName := "Smith"
	givenName := "John"
	nickname := "Johnny"
	updatedUser, err := testClient.UpdateUserProfile(ctx, userID, models.UserProfileUpdate{
		FamilyName: &familyName,
		GivenName:  &givenName,
		Nickname:   &nickname,
	})
	require.NoError(t, err, "UpdateUserProfile should succeed")

	// Verify profile was updated
	require.NotNil(t, updatedUser.Profile, "Profile should not be nil")
	assert.Equal(t, familyName, updatedUser.Profile.FamilyName)
	assert.Equal(t, givenName, updatedUser.Profile.GivenName)
	assert.Equal(t, nickname, updatedUser.Profile.Nickname)

	// Verify via GetUser
	user, err := testClient.GetUser(ctx, userID)
	require.NoError(t, err)
	require.NotNil(t, user.Profile)
	assert.Equal(t, familyName, user.Profile.FamilyName)
	assert.Equal(t, givenName, user.Profile.GivenName)
}

// TestDeleteUser tests explicit user deletion
func TestDeleteUser(t *testing.T) {
	ctx := context.Background()
	username := fmt.Sprintf("deleteuser_%d", time.Now().UnixNano())

	// Create user
	createdUser, err := testClient.CreateUser(ctx, username, "Password123!", "User to Delete", "")
	require.NoError(t, err)
	userID := createdUser.ID

	// Verify user exists
	_, err = testClient.GetUser(ctx, userID)
	require.NoError(t, err, "User should exist before deletion")

	// Delete user
	err = testClient.DeleteUser(ctx, userID)
	require.NoError(t, err, "DeleteUser should succeed")

	// Verify user no longer exists
	_, err = testClient.GetUser(ctx, userID)
	assert.Error(t, err, "GetUser should fail after deletion")
}

// TestUserPassword tests password-related operations
func TestUserPassword(t *testing.T) {
	ctx := context.Background()
	username := fmt.Sprintf("pwduser_%d", time.Now().UnixNano())
	initialPassword := "Password123!"

	// Create user with password
	createdUser, err := testClient.CreateUser(ctx, username, initialPassword, "", "")
	require.NoError(t, err)
	userID := createdUser.ID

	// Check if user has password
	hasPassword, err := testClient.HasUserPassword(ctx, userID)
	require.NoError(t, err, "HasUserPassword should succeed")
	assert.True(t, hasPassword, "User should have password after creation with password")

	// Verify correct password
	valid, err := testClient.VerifyUserPassword(ctx, userID, initialPassword)
	require.NoError(t, err, "VerifyUserPassword should succeed")
	assert.True(t, valid, "Correct password should be valid")

	// Verify wrong password
	valid, err = testClient.VerifyUserPassword(ctx, userID, "WrongPassword!")
	require.NoError(t, err, "VerifyUserPassword should succeed even with wrong password")
	assert.False(t, valid, "Wrong password should be invalid")

	// Update password
	newPassword := "NewPassword456!"
	err = testClient.UpdateUserPassword(ctx, userID, newPassword)
	require.NoError(t, err, "UpdateUserPassword should succeed")

	// Verify old password no longer works
	valid, err = testClient.VerifyUserPassword(ctx, userID, initialPassword)
	require.NoError(t, err)
	assert.False(t, valid, "Old password should be invalid after change")

	// Verify new password works
	valid, err = testClient.VerifyUserPassword(ctx, userID, newPassword)
	require.NoError(t, err)
	assert.True(t, valid, "New password should be valid")
}

// TestSuspendUser tests user suspension
func TestSuspendUser(t *testing.T) {
	ctx := context.Background()
	username := fmt.Sprintf("suspenduser_%d", time.Now().UnixNano())

	// Create user
	createdUser, err := testClient.CreateUser(ctx, username, "Password123!", "", "")
	require.NoError(t, err)
	userID := createdUser.ID

	// Verify user is not suspended initially
	user, err := testClient.GetUser(ctx, userID)
	require.NoError(t, err)
	assert.False(t, user.IsSuspended, "User should not be suspended initially")

	// Suspend user
	err = testClient.SuspendUser(ctx, userID, true)
	require.NoError(t, err, "SuspendUser(true) should succeed")

	// Verify user is suspended
	user, err = testClient.GetUser(ctx, userID)
	require.NoError(t, err)
	assert.True(t, user.IsSuspended, "User should be suspended")

	// Unsuspend user
	err = testClient.SuspendUser(ctx, userID, false)
	require.NoError(t, err, "SuspendUser(false) should succeed")

	// Verify user is not suspended
	user, err = testClient.GetUser(ctx, userID)
	require.NoError(t, err)
	assert.False(t, user.IsSuspended, "User should not be suspended after unsuspending")
}

// TestValidationErrorsUsers tests that validation errors are properly returned for user operations
func TestValidationErrorsUsers(t *testing.T) {
	ctx := context.Background()

	// Empty userID should fail
	_, err := testClient.GetUser(ctx, "")
	assert.Error(t, err, "GetUser with empty ID should fail")

	// Empty username should fail
	_, err = testClient.CreateUser(ctx, "", "password", "", "")
	assert.Error(t, err, "CreateUser with empty username should fail")
}
