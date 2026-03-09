package tests

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vaintrub/logto-go/client"
	"github.com/vaintrub/logto-go/models"
)

// TestUserCRUD tests user creation, retrieval, update, and deletion
func TestUserCRUD(t *testing.T) {
	ctx := context.Background()
	username := fmt.Sprintf("testuser_%d", time.Now().UnixNano())
	email := fmt.Sprintf("testuser%d@test.local", time.Now().UnixNano())

	// Create user
	createdUser, err := testClient.CreateUser(ctx, models.UserCreate{
		Username:     username,
		Password:     "Password123!",
		Name:         "Test User",
		PrimaryEmail: email,
	})
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
	_, err = testClient.UpdateUser(ctx, userID, models.UserUpdate{
		CustomData: map[string]interface{}{"key": "value"},
	})
	require.NoError(t, err, "UpdateUser with CustomData should succeed")

	// List users
	users, err := testClient.ListUsers(client.DefaultIteratorConfig()).Collect(ctx)
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
	createdUser, err := testClient.CreateUser(ctx, models.UserCreate{
		Username: username,
		Password: "Password123!",
	})
	require.NoError(t, err, "CreateUser should succeed")
	userID := createdUser.ID

	// Update profile using UpdateUser with Profile field
	familyName := "Smith"
	givenName := "John"
	nickname := "Johnny"
	updatedUser, err := testClient.UpdateUser(ctx, userID, models.UserUpdate{
		Profile: &models.UserProfileUpdate{
			FamilyName: &familyName,
			GivenName:  &givenName,
			Nickname:   &nickname,
		},
	})
	require.NoError(t, err, "UpdateUser with Profile should succeed")

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
	createdUser, err := testClient.CreateUser(ctx, models.UserCreate{
		Username: username,
		Password: "Password123!",
		Name:     "User to Delete",
	})
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
	createdUser, err := testClient.CreateUser(ctx, models.UserCreate{
		Username: username,
		Password: initialPassword,
	})
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
	err = testClient.UpdateUserPassword(ctx, userID, models.UserPasswordUpdate{Password: newPassword})
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
	createdUser, err := testClient.CreateUser(ctx, models.UserCreate{
		Username: username,
		Password: "Password123!",
	})
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
	require.Error(t, err, "GetUser with empty ID should fail")
	var validationErr *client.ValidationError
	require.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "userID", validationErr.Field)

	// No identifier should fail
	_, err = testClient.CreateUser(ctx, models.UserCreate{Password: "password"})
	require.Error(t, err, "CreateUser with no identifier should fail")
	require.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "username/primaryEmail/primaryPhone", validationErr.Field)
}

// TestGetUserByEmail_Validation tests validation errors for GetUserByEmail
func TestGetUserByEmail_Validation(t *testing.T) {
	ctx := context.Background()

	_, err := testClient.GetUserByEmail(ctx, "")
	require.Error(t, err, "GetUserByEmail with empty email should fail")
	var validationErr *client.ValidationError
	require.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "email", validationErr.Field)
}

// TestGetUserByEmail_NotFound tests GetUserByEmail with non-existent email
func TestGetUserByEmail_NotFound(t *testing.T) {
	ctx := context.Background()

	_, err := testClient.GetUserByEmail(ctx, "nonexistent-email-12345@test.local")
	assert.Error(t, err, "GetUserByEmail with non-existent email should fail")
}

// TestDeleteUser_Validation tests validation errors for DeleteUser
func TestDeleteUser_Validation(t *testing.T) {
	ctx := context.Background()

	err := testClient.DeleteUser(ctx, "")
	require.Error(t, err, "DeleteUser with empty userID should fail")
	var validationErr *client.ValidationError
	require.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "userID", validationErr.Field)
}

// TestSuspendUser_Validation tests validation errors for SuspendUser
func TestSuspendUser_Validation(t *testing.T) {
	ctx := context.Background()

	err := testClient.SuspendUser(ctx, "", true)
	require.Error(t, err, "SuspendUser with empty userID should fail")
	var validationErr *client.ValidationError
	require.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "userID", validationErr.Field)
}

// TestUpdateUserPassword_Validation tests validation errors for UpdateUserPassword
func TestUpdateUserPassword_Validation(t *testing.T) {
	ctx := context.Background()

	t.Run("empty userID", func(t *testing.T) {
		err := testClient.UpdateUserPassword(ctx, "", models.UserPasswordUpdate{Password: "newpass"})
		require.Error(t, err, "UpdateUserPassword with empty userID should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "userID", validationErr.Field)
	})

	t.Run("empty password", func(t *testing.T) {
		err := testClient.UpdateUserPassword(ctx, "user-123", models.UserPasswordUpdate{Password: ""})
		require.Error(t, err, "UpdateUserPassword with empty password should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "password", validationErr.Field)
	})
}

// TestHasUserPassword_Validation tests validation errors for HasUserPassword
func TestHasUserPassword_Validation(t *testing.T) {
	ctx := context.Background()

	_, err := testClient.HasUserPassword(ctx, "")
	require.Error(t, err, "HasUserPassword with empty userID should fail")
	var validationErr *client.ValidationError
	require.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "userID", validationErr.Field)
}

// TestVerifyUserPassword_Validation tests validation errors for VerifyUserPassword
func TestVerifyUserPassword_Validation(t *testing.T) {
	ctx := context.Background()

	t.Run("empty userID", func(t *testing.T) {
		_, err := testClient.VerifyUserPassword(ctx, "", "password")
		require.Error(t, err, "VerifyUserPassword with empty userID should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "userID", validationErr.Field)
	})

	t.Run("empty password", func(t *testing.T) {
		_, err := testClient.VerifyUserPassword(ctx, "user-123", "")
		require.Error(t, err, "VerifyUserPassword with empty password should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "password", validationErr.Field)
	})
}

// TestUpdateUser_Validation tests validation errors for UpdateUser
func TestUpdateUser_Validation(t *testing.T) {
	ctx := context.Background()

	name := "test"
	_, err := testClient.UpdateUser(ctx, "", models.UserUpdate{Name: &name})
	require.Error(t, err, "UpdateUser with empty userID should fail")
	var validationErr *client.ValidationError
	require.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "userID", validationErr.Field)
}

// TestCreateUserByEmail tests creating a user with only email (no username/password)
func TestCreateUserByEmail(t *testing.T) {
	ctx := context.Background()
	email := fmt.Sprintf("emailonly%d@test.local", time.Now().UnixNano())

	// Create user with email only
	createdUser, err := testClient.CreateUser(ctx, models.UserCreate{
		PrimaryEmail: email,
		Name:         "Email Only User",
	})
	require.NoError(t, err, "CreateUser with email only should succeed")
	t.Cleanup(func() {
		_ = testClient.DeleteUser(context.Background(), createdUser.ID)
	})
	assert.NotEmpty(t, createdUser.ID)
	assert.Equal(t, email, createdUser.PrimaryEmail)
	assert.Equal(t, "Email Only User", createdUser.Name)
	assert.Empty(t, createdUser.Username, "Username should be empty")

	// Verify user has no password
	hasPassword, err := testClient.HasUserPassword(ctx, createdUser.ID)
	require.NoError(t, err)
	assert.False(t, hasPassword, "User created without password should not have one")
}

// TestGetUserRoles tests retrieving user roles
func TestGetUserRoles(t *testing.T) {
	ctx := context.Background()
	username := fmt.Sprintf("roleuser_%d", time.Now().UnixNano())

	// Create user
	createdUser, err := testClient.CreateUser(ctx, models.UserCreate{
		Username: username,
		Password: "Password123!",
	})
	require.NoError(t, err)
	userID := createdUser.ID
	t.Cleanup(func() {
		_ = testClient.DeleteUser(context.Background(), userID)
	})

	// Initially user should have no roles
	roles, err := testClient.GetUserRoles(ctx, userID)
	require.NoError(t, err, "GetUserRoles should succeed")
	assert.Empty(t, roles, "New user should have no roles")

	// Create a role and assign it
	roleName := fmt.Sprintf("Test Role %d", time.Now().UnixNano())
	role, err := testClient.CreateRole(ctx, models.RoleCreate{
		Name:        roleName,
		Description: "Test role for GetUserRoles",
		Type:        models.RoleTypeUser,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = testClient.DeleteRole(context.Background(), role.ID)
	})

	err = testClient.AssignRoleToUsers(ctx, role.ID, []string{userID})
	require.NoError(t, err, "AssignRoleToUsers should succeed")

	// Now GetUserRoles should return the assigned role
	roles, err = testClient.GetUserRoles(ctx, userID)
	require.NoError(t, err, "GetUserRoles should succeed")
	require.Len(t, roles, 1, "User should have exactly one role")
	assert.Equal(t, role.ID, roles[0].ID)
	assert.Equal(t, roleName, roles[0].Name)
}

// TestGetUserRoles_Validation tests validation errors for GetUserRoles
func TestGetUserRoles_Validation(t *testing.T) {
	ctx := context.Background()

	_, err := testClient.GetUserRoles(ctx, "")
	require.Error(t, err, "GetUserRoles with empty userID should fail")
	var validationErr *client.ValidationError
	require.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "userID", validationErr.Field)
}

// TestReplaceUserRoles tests atomically replacing all roles for a user
func TestReplaceUserRoles(t *testing.T) {
	ctx := context.Background()
	username := fmt.Sprintf("replroleuser_%d", time.Now().UnixNano())

	// Create user
	createdUser, err := testClient.CreateUser(ctx, models.UserCreate{
		Username: username,
		Password: "Password123!",
	})
	require.NoError(t, err)
	userID := createdUser.ID
	t.Cleanup(func() {
		_ = testClient.DeleteUser(context.Background(), userID)
	})

	// Create two roles
	role1Name := fmt.Sprintf("ReplRole1 %d", time.Now().UnixNano())
	role1, err := testClient.CreateRole(ctx, models.RoleCreate{
		Name:        role1Name,
		Description: "First role for ReplaceUserRoles test",
		Type:        models.RoleTypeUser,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = testClient.DeleteRole(context.Background(), role1.ID)
	})

	role2Name := fmt.Sprintf("ReplRole2 %d", time.Now().UnixNano())
	role2, err := testClient.CreateRole(ctx, models.RoleCreate{
		Name:        role2Name,
		Description: "Second role for ReplaceUserRoles test",
		Type:        models.RoleTypeUser,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = testClient.DeleteRole(context.Background(), role2.ID)
	})

	// Assign role1 via AssignRoleToUsers
	err = testClient.AssignRoleToUsers(ctx, role1.ID, []string{userID})
	require.NoError(t, err)

	// Verify role1 is assigned
	roles, err := testClient.GetUserRoles(ctx, userID)
	require.NoError(t, err)
	require.Len(t, roles, 1)
	assert.Equal(t, role1.ID, roles[0].ID)

	// Replace with role2
	err = testClient.ReplaceUserRoles(ctx, userID, []string{role2.ID})
	require.NoError(t, err, "ReplaceUserRoles should succeed")

	// Verify only role2 is assigned (replacement, not addition)
	roles, err = testClient.GetUserRoles(ctx, userID)
	require.NoError(t, err)
	require.Len(t, roles, 1, "User should have exactly one role after replacement")
	assert.Equal(t, role2.ID, roles[0].ID)
	assert.Equal(t, role2Name, roles[0].Name)
}

// TestReplaceUserRoles_Validation tests validation errors for ReplaceUserRoles
func TestReplaceUserRoles_Validation(t *testing.T) {
	ctx := context.Background()

	err := testClient.ReplaceUserRoles(ctx, "", []string{"role-123"})
	require.Error(t, err, "ReplaceUserRoles with empty userID should fail")
	var validationErr *client.ValidationError
	require.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "userID", validationErr.Field)
}

// TestPatchCustomData tests shallow-merging custom data for a user
func TestPatchCustomData(t *testing.T) {
	ctx := context.Background()
	username := fmt.Sprintf("customdatauser_%d", time.Now().UnixNano())

	// Create user
	createdUser, err := testClient.CreateUser(ctx, models.UserCreate{
		Username: username,
		Password: "Password123!",
	})
	require.NoError(t, err)
	userID := createdUser.ID
	t.Cleanup(func() {
		_ = testClient.DeleteUser(context.Background(), userID)
	})

	// Set initial custom data
	result, err := testClient.PatchCustomData(ctx, userID, map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
	})
	require.NoError(t, err, "PatchCustomData should succeed")
	assert.Equal(t, "value1", result["key1"])
	assert.Equal(t, "value2", result["key2"])

	// Patch with partial update — key1 should be preserved
	result, err = testClient.PatchCustomData(ctx, userID, map[string]interface{}{
		"key2": "updated",
		"key3": "value3",
	})
	require.NoError(t, err, "PatchCustomData partial update should succeed")
	assert.Equal(t, "value1", result["key1"], "key1 should be preserved")
	assert.Equal(t, "updated", result["key2"], "key2 should be updated")
	assert.Equal(t, "value3", result["key3"], "key3 should be added")

	// Verify via GetUser
	user, err := testClient.GetUser(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, "value1", user.CustomData["key1"])
	assert.Equal(t, "updated", user.CustomData["key2"])
	assert.Equal(t, "value3", user.CustomData["key3"])
}

// TestPatchCustomData_Validation tests validation errors for PatchCustomData
func TestPatchCustomData_Validation(t *testing.T) {
	ctx := context.Background()

	_, err := testClient.PatchCustomData(ctx, "", map[string]interface{}{"key": "value"})
	require.Error(t, err, "PatchCustomData with empty userID should fail")
	var validationErr *client.ValidationError
	require.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "userID", validationErr.Field)
}
