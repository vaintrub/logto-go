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

// TestOrganizationMembership tests adding/removing users from organizations
func TestOrganizationMembership(t *testing.T) {
	ctx := context.Background()

	// Create user
	username := fmt.Sprintf("member_%d", time.Now().UnixNano())
	createdUser, err := testClient.CreateUser(ctx, models.UserCreate{
		Username: username,
		Password: "Password123!",
		Name:     "Member User",
	})
	require.NoError(t, err)
	userID := createdUser.ID

	// Create organization
	orgName := fmt.Sprintf("Membership Org %d", time.Now().UnixNano())
	createdOrg, err := testClient.CreateOrganization(ctx, models.OrganizationCreate{Name: orgName})
	require.NoError(t, err)
	orgID := createdOrg.ID
	t.Cleanup(func() {
		if err := testClient.DeleteOrganization(context.Background(), orgID); err != nil {
			t.Logf("cleanup: failed to delete organization %s: %v", orgID, err)
		}
	})

	// Add user to organization
	err = testClient.AddUserToOrganization(ctx, orgID, userID, nil)
	require.NoError(t, err, "AddUserToOrganization should succeed")

	// List organization members
	members, err := testClient.ListOrganizationMembers(orgID, client.DefaultIteratorConfig()).Collect(ctx)
	require.NoError(t, err, "ListOrganizationMembers should succeed")
	assert.Len(t, members, 1, "Should have one member")
	assert.Equal(t, userID, members[0].User.ID)

	// List user organizations
	userOrgs, err := testClient.ListUserOrganizations(userID, client.DefaultIteratorConfig()).Collect(ctx)
	require.NoError(t, err, "ListUserOrganizations should succeed")
	found := false
	for _, o := range userOrgs {
		if o.ID == orgID {
			found = true
			break
		}
	}
	assert.True(t, found, "User should be member of the organization")

	// Remove user from organization
	err = testClient.RemoveUserFromOrganization(ctx, orgID, userID)
	require.NoError(t, err, "RemoveUserFromOrganization should succeed")

	// Verify removal
	members, err = testClient.ListOrganizationMembers(orgID, client.DefaultIteratorConfig()).Collect(ctx)
	require.NoError(t, err)
	assert.Len(t, members, 0, "Should have no members after removal")
}

// TestBatchOrganizationOperations tests batch operations for organizations
func TestBatchOrganizationOperations(t *testing.T) {
	ctx := context.Background()

	// Create users
	user1Obj, err := testClient.CreateUser(ctx, models.UserCreate{
		Username: fmt.Sprintf("batch1_%d", time.Now().UnixNano()),
		Password: "Password123!",
	})
	require.NoError(t, err)
	user1 := user1Obj.ID
	user2Obj, err := testClient.CreateUser(ctx, models.UserCreate{
		Username: fmt.Sprintf("batch2_%d", time.Now().UnixNano()),
		Password: "Password123!",
	})
	require.NoError(t, err)
	user2 := user2Obj.ID

	// Create organization
	createdOrg, err := testClient.CreateOrganization(ctx, models.OrganizationCreate{
		Name: fmt.Sprintf("Batch Org %d", time.Now().UnixNano()),
	})
	require.NoError(t, err)
	orgID := createdOrg.ID
	t.Cleanup(func() {
		if err := testClient.DeleteOrganization(context.Background(), orgID); err != nil {
			t.Logf("cleanup: failed to delete organization %s: %v", orgID, err)
		}
	})

	// Add multiple users at once
	err = testClient.AddUsersToOrganization(ctx, orgID, []string{user1, user2})
	require.NoError(t, err, "AddUsersToOrganization should succeed")

	// Verify both users are members
	members, err := testClient.ListOrganizationMembers(orgID, client.DefaultIteratorConfig()).Collect(ctx)
	require.NoError(t, err)
	assert.Len(t, members, 2, "Should have two members")

	// Create role for batch assignment
	createdRole, err := testClient.CreateOrganizationRole(ctx, models.OrganizationRoleCreate{
		Name:        fmt.Sprintf("batch-role-%d", time.Now().UnixNano()),
		Description: "Batch role",
	})
	require.NoError(t, err)
	roleID := createdRole.ID
	t.Cleanup(func() {
		if err := testClient.DeleteOrganizationRole(context.Background(), roleID); err != nil {
			t.Logf("cleanup: failed to delete organization role %s: %v", roleID, err)
		}
	})

	// Assign role to multiple users
	err = testClient.AssignRolesToOrganizationUsers(ctx, orgID, []string{user1, user2}, []string{roleID})
	require.NoError(t, err, "AssignRolesToOrganizationUsers should succeed")

	// Verify roles assigned
	roles1, err := testClient.GetUserRolesInOrganization(ctx, orgID, user1)
	require.NoError(t, err)
	assert.Len(t, roles1, 1)
	assert.Equal(t, roleID, roles1[0].ID)
}

// TestUserRolesInOrganization tests user role assignment
func TestUserRolesInOrganization(t *testing.T) {
	ctx := context.Background()

	// Create user
	createdUser, err := testClient.CreateUser(ctx, models.UserCreate{
		Username: fmt.Sprintf("roleuser_%d", time.Now().UnixNano()),
		Password: "Password123!",
	})
	require.NoError(t, err)
	userID := createdUser.ID

	// Create organization
	createdOrg, err := testClient.CreateOrganization(ctx, models.OrganizationCreate{
		Name: fmt.Sprintf("Role Test Org %d", time.Now().UnixNano()),
	})
	require.NoError(t, err)
	orgID := createdOrg.ID
	t.Cleanup(func() {
		if err := testClient.DeleteOrganization(context.Background(), orgID); err != nil {
			t.Logf("cleanup: failed to delete organization %s: %v", orgID, err)
		}
	})

	// Create role
	createdRole, err := testClient.CreateOrganizationRole(ctx, models.OrganizationRoleCreate{
		Name: fmt.Sprintf("user-role-%d", time.Now().UnixNano()),
	})
	require.NoError(t, err)
	roleID := createdRole.ID
	t.Cleanup(func() {
		if err := testClient.DeleteOrganizationRole(context.Background(), roleID); err != nil {
			t.Logf("cleanup: failed to delete organization role %s: %v", roleID, err)
		}
	})

	// Add user to org with role
	err = testClient.AddUserToOrganization(ctx, orgID, userID, []string{roleID})
	require.NoError(t, err, "AddUserToOrganization with roles should succeed")

	// Get user roles
	roles, err := testClient.GetUserRolesInOrganization(ctx, orgID, userID)
	require.NoError(t, err, "GetUserRolesInOrganization should succeed")
	assert.Len(t, roles, 1)
	assert.Equal(t, roleID, roles[0].ID)

	// Update user roles (replace)
	createdRole2, err := testClient.CreateOrganizationRole(ctx, models.OrganizationRoleCreate{
		Name: fmt.Sprintf("user-role2-%d", time.Now().UnixNano()),
	})
	require.NoError(t, err)
	role2ID := createdRole2.ID
	t.Cleanup(func() {
		if err := testClient.DeleteOrganizationRole(context.Background(), role2ID); err != nil {
			t.Logf("cleanup: failed to delete organization role %s: %v", role2ID, err)
		}
	})

	err = testClient.UpdateUserRoles(ctx, orgID, userID, models.UserOrganizationRolesUpdate{
		OrganizationRoleIDs: []string{role2ID},
	})
	require.NoError(t, err, "UpdateUserRoles should succeed")

	// Verify roles updated
	roles, err = testClient.GetUserRolesInOrganization(ctx, orgID, userID)
	require.NoError(t, err)
	assert.Len(t, roles, 1)
	assert.Equal(t, role2ID, roles[0].ID)
}

// TestListOrganizationMembersWithRoles tests that member roles are correctly parsed
func TestListOrganizationMembersWithRoles(t *testing.T) {
	ctx := context.Background()

	// Create user, org, and role
	createdUser, err := testClient.CreateUser(ctx, models.UserCreate{
		Username: fmt.Sprintf("rolemember_%d", time.Now().UnixNano()),
		Password: "Password123!",
	})
	require.NoError(t, err)
	userID := createdUser.ID

	createdOrg, err := testClient.CreateOrganization(ctx, models.OrganizationCreate{
		Name: fmt.Sprintf("MemberRole Org %d", time.Now().UnixNano()),
	})
	require.NoError(t, err)
	orgID := createdOrg.ID
	t.Cleanup(func() {
		if err := testClient.DeleteOrganization(context.Background(), orgID); err != nil {
			t.Logf("cleanup: failed to delete organization %s: %v", orgID, err)
		}
	})

	createdRole, err := testClient.CreateOrganizationRole(ctx, models.OrganizationRoleCreate{
		Name: fmt.Sprintf("member-role-%d", time.Now().UnixNano()),
	})
	require.NoError(t, err)
	roleID := createdRole.ID
	t.Cleanup(func() {
		if err := testClient.DeleteOrganizationRole(context.Background(), roleID); err != nil {
			t.Logf("cleanup: failed to delete organization role %s: %v", roleID, err)
		}
	})

	// Add user with role
	err = testClient.AddUserToOrganization(ctx, orgID, userID, []string{roleID})
	require.NoError(t, err)

	// List members and verify roles are included
	members, err := testClient.ListOrganizationMembers(orgID, client.DefaultIteratorConfig()).Collect(ctx)
	require.NoError(t, err)
	require.Len(t, members, 1)

	member := members[0]
	assert.Equal(t, userID, member.User.ID)
	assert.Len(t, member.Roles, 1, "Member should have one role")
	assert.Equal(t, roleID, member.Roles[0].ID)
}

// TestGetUserScopesInOrganization tests getting user scopes in an organization
func TestGetUserScopesInOrganization(t *testing.T) {
	ctx := context.Background()

	// Create user
	createdUser, err := testClient.CreateUser(ctx, models.UserCreate{
		Username: fmt.Sprintf("scopeuser_%d", time.Now().UnixNano()),
		Password: "Password123!",
	})
	require.NoError(t, err)
	userID := createdUser.ID

	// Create organization
	createdOrg, err := testClient.CreateOrganization(ctx, models.OrganizationCreate{
		Name: fmt.Sprintf("Scope Test Org %d", time.Now().UnixNano()),
	})
	require.NoError(t, err)
	orgID := createdOrg.ID
	t.Cleanup(func() {
		if err := testClient.DeleteOrganization(context.Background(), orgID); err != nil {
			t.Logf("cleanup: failed to delete organization %s: %v", orgID, err)
		}
	})

	// Create organization scope
	createdScope, err := testClient.CreateOrganizationScope(ctx, models.OrganizationScopeCreate{
		Name:        fmt.Sprintf("test:scope:%d", time.Now().UnixNano()),
		Description: "Test scope for user",
	})
	require.NoError(t, err)
	scopeID := createdScope.ID
	t.Cleanup(func() {
		if err := testClient.DeleteOrganizationScope(context.Background(), scopeID); err != nil {
			t.Logf("cleanup: failed to delete organization scope %s: %v", scopeID, err)
		}
	})

	// Create role with scope
	createdRole, err := testClient.CreateOrganizationRole(ctx, models.OrganizationRoleCreate{
		Name:                 fmt.Sprintf("scope-role-%d", time.Now().UnixNano()),
		OrganizationScopeIDs: []string{scopeID},
	})
	require.NoError(t, err)
	roleID := createdRole.ID
	t.Cleanup(func() {
		if err := testClient.DeleteOrganizationRole(context.Background(), roleID); err != nil {
			t.Logf("cleanup: failed to delete organization role %s: %v", roleID, err)
		}
	})

	// Add user to org with role (which has scope)
	err = testClient.AddUserToOrganization(ctx, orgID, userID, []string{roleID})
	require.NoError(t, err)

	// Get user scopes
	scopes, err := testClient.GetUserScopesInOrganization(ctx, orgID, userID)
	require.NoError(t, err, "GetUserScopesInOrganization should succeed")
	require.Len(t, scopes, 1, "User should have one scope")
	assert.Equal(t, scopeID, scopes[0].ID)
}

// TestGetUserScopesInOrganization_Empty tests user with no scopes
func TestGetUserScopesInOrganization_Empty(t *testing.T) {
	ctx := context.Background()

	// Create user
	createdUser, err := testClient.CreateUser(ctx, models.UserCreate{
		Username: fmt.Sprintf("noscopeuser_%d", time.Now().UnixNano()),
		Password: "Password123!",
	})
	require.NoError(t, err)
	userID := createdUser.ID

	// Create organization
	createdOrg, err := testClient.CreateOrganization(ctx, models.OrganizationCreate{
		Name: fmt.Sprintf("NoScope Org %d", time.Now().UnixNano()),
	})
	require.NoError(t, err)
	orgID := createdOrg.ID
	t.Cleanup(func() {
		if err := testClient.DeleteOrganization(context.Background(), orgID); err != nil {
			t.Logf("cleanup: failed to delete organization %s: %v", orgID, err)
		}
	})

	// Add user to org WITHOUT role (no scopes)
	err = testClient.AddUserToOrganization(ctx, orgID, userID, nil)
	require.NoError(t, err)

	// Get user scopes - should be empty
	scopes, err := testClient.GetUserScopesInOrganization(ctx, orgID, userID)
	require.NoError(t, err, "GetUserScopesInOrganization should succeed")
	assert.Empty(t, scopes, "User should have no scopes")
}

// TestGetUserScopesInOrganization_Validation tests validation errors
func TestGetUserScopesInOrganization_Validation(t *testing.T) {
	ctx := context.Background()

	t.Run("empty orgID", func(t *testing.T) {
		_, err := testClient.GetUserScopesInOrganization(ctx, "", "user-123")
		require.Error(t, err, "GetUserScopesInOrganization with empty orgID should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "orgID", validationErr.Field)
	})

	t.Run("empty userID", func(t *testing.T) {
		_, err := testClient.GetUserScopesInOrganization(ctx, "org-123", "")
		require.Error(t, err, "GetUserScopesInOrganization with empty userID should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "userID", validationErr.Field)
	})
}

// TestGetUserScopesInOrganization_MultipleScopes tests user with multiple scopes from multiple roles
func TestGetUserScopesInOrganization_MultipleScopes(t *testing.T) {
	ctx := context.Background()

	// Create user
	createdUser, err := testClient.CreateUser(ctx, models.UserCreate{
		Username: fmt.Sprintf("multiscope_%d", time.Now().UnixNano()),
		Password: "Password123!",
	})
	require.NoError(t, err)
	userID := createdUser.ID

	// Create organization
	createdOrg, err := testClient.CreateOrganization(ctx, models.OrganizationCreate{
		Name: fmt.Sprintf("MultiScope Org %d", time.Now().UnixNano()),
	})
	require.NoError(t, err)
	orgID := createdOrg.ID
	t.Cleanup(func() {
		if err := testClient.DeleteOrganization(context.Background(), orgID); err != nil {
			t.Logf("cleanup: failed to delete organization %s: %v", orgID, err)
		}
	})

	// Create two scopes
	scope1, err := testClient.CreateOrganizationScope(ctx, models.OrganizationScopeCreate{
		Name: fmt.Sprintf("read:%d", time.Now().UnixNano()),
	})
	require.NoError(t, err)
	scope1ID := scope1.ID
	t.Cleanup(func() {
		if err := testClient.DeleteOrganizationScope(context.Background(), scope1ID); err != nil {
			t.Logf("cleanup: failed to delete scope %s: %v", scope1ID, err)
		}
	})

	scope2, err := testClient.CreateOrganizationScope(ctx, models.OrganizationScopeCreate{
		Name: fmt.Sprintf("write:%d", time.Now().UnixNano()),
	})
	require.NoError(t, err)
	scope2ID := scope2.ID
	t.Cleanup(func() {
		if err := testClient.DeleteOrganizationScope(context.Background(), scope2ID); err != nil {
			t.Logf("cleanup: failed to delete scope %s: %v", scope2ID, err)
		}
	})

	// Create role with both scopes
	createdRole, err := testClient.CreateOrganizationRole(ctx, models.OrganizationRoleCreate{
		Name:                 fmt.Sprintf("multi-scope-role-%d", time.Now().UnixNano()),
		OrganizationScopeIDs: []string{scope1ID, scope2ID},
	})
	require.NoError(t, err)
	roleID := createdRole.ID
	t.Cleanup(func() {
		if err := testClient.DeleteOrganizationRole(context.Background(), roleID); err != nil {
			t.Logf("cleanup: failed to delete role %s: %v", roleID, err)
		}
	})

	// Add user to org with role
	err = testClient.AddUserToOrganization(ctx, orgID, userID, []string{roleID})
	require.NoError(t, err)

	// Get user scopes - should have 2
	scopes, err := testClient.GetUserScopesInOrganization(ctx, orgID, userID)
	require.NoError(t, err, "GetUserScopesInOrganization should succeed")
	assert.Len(t, scopes, 2, "User should have two scopes")

	// Verify both scopes are present
	scopeIDs := make(map[string]bool)
	for _, s := range scopes {
		scopeIDs[s.ID] = true
	}
	assert.True(t, scopeIDs[scope1ID], "Scope 1 should be present")
	assert.True(t, scopeIDs[scope2ID], "Scope 2 should be present")
}

// TestAddUsersToOrganization_Validation tests validation errors for AddUsersToOrganization
func TestAddUsersToOrganization_Validation(t *testing.T) {
	ctx := context.Background()

	t.Run("empty orgID", func(t *testing.T) {
		err := testClient.AddUsersToOrganization(ctx, "", []string{"user-1"})
		require.Error(t, err, "AddUsersToOrganization with empty orgID should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "orgID", validationErr.Field)
	})

	t.Run("empty userIDs", func(t *testing.T) {
		err := testClient.AddUsersToOrganization(ctx, "org-123", []string{})
		require.Error(t, err, "AddUsersToOrganization with empty userIDs should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "userIDs", validationErr.Field)
	})

	t.Run("nil userIDs", func(t *testing.T) {
		err := testClient.AddUsersToOrganization(ctx, "org-123", nil)
		require.Error(t, err, "AddUsersToOrganization with nil userIDs should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "userIDs", validationErr.Field)
	})
}

// TestUpdateUserRoles_Validation tests validation errors for UpdateUserRoles
func TestUpdateUserRoles_Validation(t *testing.T) {
	ctx := context.Background()

	t.Run("empty orgID", func(t *testing.T) {
		err := testClient.UpdateUserRoles(ctx, "", "user-123", models.UserOrganizationRolesUpdate{
			OrganizationRoleIDs: []string{"role-1"},
		})
		require.Error(t, err, "UpdateUserRoles with empty orgID should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "orgID", validationErr.Field)
	})

	t.Run("empty userID", func(t *testing.T) {
		err := testClient.UpdateUserRoles(ctx, "org-123", "", models.UserOrganizationRolesUpdate{
			OrganizationRoleIDs: []string{"role-1"},
		})
		require.Error(t, err, "UpdateUserRoles with empty userID should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "userID", validationErr.Field)
	})
}

// TestAssignRolesToOrganizationUsers_Validation tests validation errors
func TestAssignRolesToOrganizationUsers_Validation(t *testing.T) {
	ctx := context.Background()

	t.Run("empty orgID", func(t *testing.T) {
		err := testClient.AssignRolesToOrganizationUsers(ctx, "", []string{"user-1"}, []string{"role-1"})
		require.Error(t, err, "AssignRolesToOrganizationUsers with empty orgID should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "orgID", validationErr.Field)
	})

	t.Run("empty userIDs", func(t *testing.T) {
		err := testClient.AssignRolesToOrganizationUsers(ctx, "org-123", []string{}, []string{"role-1"})
		require.Error(t, err, "AssignRolesToOrganizationUsers with empty userIDs should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "userIDs", validationErr.Field)
	})

	t.Run("empty roleIDs", func(t *testing.T) {
		err := testClient.AssignRolesToOrganizationUsers(ctx, "org-123", []string{"user-1"}, []string{})
		require.Error(t, err, "AssignRolesToOrganizationUsers with empty roleIDs should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "roleIDs", validationErr.Field)
	})
}

// TestAddUserToOrganization_Validation tests validation errors for AddUserToOrganization
func TestAddUserToOrganization_Validation(t *testing.T) {
	ctx := context.Background()

	t.Run("empty orgID", func(t *testing.T) {
		err := testClient.AddUserToOrganization(ctx, "", "user-123", nil)
		require.Error(t, err, "AddUserToOrganization with empty orgID should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "orgID", validationErr.Field)
	})

	t.Run("empty userID", func(t *testing.T) {
		err := testClient.AddUserToOrganization(ctx, "org-123", "", nil)
		require.Error(t, err, "AddUserToOrganization with empty userID should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "userID", validationErr.Field)
	})
}

// TestRemoveUserFromOrganization_Validation tests validation errors
func TestRemoveUserFromOrganization_Validation(t *testing.T) {
	ctx := context.Background()

	t.Run("empty orgID", func(t *testing.T) {
		err := testClient.RemoveUserFromOrganization(ctx, "", "user-123")
		require.Error(t, err, "RemoveUserFromOrganization with empty orgID should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "orgID", validationErr.Field)
	})

	t.Run("empty userID", func(t *testing.T) {
		err := testClient.RemoveUserFromOrganization(ctx, "org-123", "")
		require.Error(t, err, "RemoveUserFromOrganization with empty userID should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "userID", validationErr.Field)
	})
}

// TestGetUserRolesInOrganization_Validation tests validation errors
func TestGetUserRolesInOrganization_Validation(t *testing.T) {
	ctx := context.Background()

	t.Run("empty orgID", func(t *testing.T) {
		_, err := testClient.GetUserRolesInOrganization(ctx, "", "user-123")
		require.Error(t, err, "GetUserRolesInOrganization with empty orgID should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "orgID", validationErr.Field)
	})

	t.Run("empty userID", func(t *testing.T) {
		_, err := testClient.GetUserRolesInOrganization(ctx, "org-123", "")
		require.Error(t, err, "GetUserRolesInOrganization with empty userID should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "userID", validationErr.Field)
	})
}

// TestListOrganizationMembers_Validation tests validation errors
func TestListOrganizationMembers_Validation(t *testing.T) {
	ctx := context.Background()

	iter := testClient.ListOrganizationMembers("", client.DefaultIteratorConfig())
	iter.Next(ctx)
	err := iter.Err()
	require.Error(t, err, "ListOrganizationMembers with empty orgID should fail")
	var validationErr *client.ValidationError
	require.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "orgID", validationErr.Field)
}
