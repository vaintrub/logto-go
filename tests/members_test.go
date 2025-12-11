package tests

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOrganizationMembership tests adding/removing users from organizations
func TestOrganizationMembership(t *testing.T) {
	ctx := context.Background()

	// Create user
	username := fmt.Sprintf("member_%d", time.Now().UnixNano())
	createdUser, err := testClient.CreateUser(ctx, username, "Password123!", "Member User", "")
	require.NoError(t, err)
	userID := createdUser.ID

	// Create organization
	orgName := fmt.Sprintf("Membership Org %d", time.Now().UnixNano())
	createdOrg, err := testClient.CreateOrganization(ctx, orgName, "")
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
	members, err := testClient.ListOrganizationMembers(ctx, orgID)
	require.NoError(t, err, "ListOrganizationMembers should succeed")
	assert.Len(t, members, 1, "Should have one member")
	assert.Equal(t, userID, members[0].User.ID)

	// List user organizations
	userOrgs, err := testClient.ListUserOrganizations(ctx, userID)
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
	members, err = testClient.ListOrganizationMembers(ctx, orgID)
	require.NoError(t, err)
	assert.Len(t, members, 0, "Should have no members after removal")
}

// TestBatchOrganizationOperations tests batch operations for organizations
func TestBatchOrganizationOperations(t *testing.T) {
	ctx := context.Background()

	// Create users
	user1Obj, err := testClient.CreateUser(ctx, fmt.Sprintf("batch1_%d", time.Now().UnixNano()), "Password123!", "", "")
	require.NoError(t, err)
	user1 := user1Obj.ID
	user2Obj, err := testClient.CreateUser(ctx, fmt.Sprintf("batch2_%d", time.Now().UnixNano()), "Password123!", "", "")
	require.NoError(t, err)
	user2 := user2Obj.ID

	// Create organization
	createdOrg, err := testClient.CreateOrganization(ctx, fmt.Sprintf("Batch Org %d", time.Now().UnixNano()), "")
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
	members, err := testClient.ListOrganizationMembers(ctx, orgID)
	require.NoError(t, err)
	assert.Len(t, members, 2, "Should have two members")

	// Create role for batch assignment
	createdRole, err := testClient.CreateOrganizationRole(ctx, fmt.Sprintf("batch-role-%d", time.Now().UnixNano()), "Batch role", "", nil)
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
	createdUser, err := testClient.CreateUser(ctx, fmt.Sprintf("roleuser_%d", time.Now().UnixNano()), "Password123!", "", "")
	require.NoError(t, err)
	userID := createdUser.ID

	// Create organization
	createdOrg, err := testClient.CreateOrganization(ctx, fmt.Sprintf("Role Test Org %d", time.Now().UnixNano()), "")
	require.NoError(t, err)
	orgID := createdOrg.ID
	t.Cleanup(func() {
		if err := testClient.DeleteOrganization(context.Background(), orgID); err != nil {
			t.Logf("cleanup: failed to delete organization %s: %v", orgID, err)
		}
	})

	// Create role
	createdRole, err := testClient.CreateOrganizationRole(ctx, fmt.Sprintf("user-role-%d", time.Now().UnixNano()), "", "", nil)
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
	createdRole2, err := testClient.CreateOrganizationRole(ctx, fmt.Sprintf("user-role2-%d", time.Now().UnixNano()), "", "", nil)
	require.NoError(t, err)
	role2ID := createdRole2.ID
	t.Cleanup(func() {
		if err := testClient.DeleteOrganizationRole(context.Background(), role2ID); err != nil {
			t.Logf("cleanup: failed to delete organization role %s: %v", role2ID, err)
		}
	})

	err = testClient.UpdateUserRoles(ctx, orgID, userID, []string{role2ID})
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
	createdUser, err := testClient.CreateUser(ctx, fmt.Sprintf("rolemember_%d", time.Now().UnixNano()), "Password123!", "", "")
	require.NoError(t, err)
	userID := createdUser.ID

	createdOrg, err := testClient.CreateOrganization(ctx, fmt.Sprintf("MemberRole Org %d", time.Now().UnixNano()), "")
	require.NoError(t, err)
	orgID := createdOrg.ID
	t.Cleanup(func() {
		if err := testClient.DeleteOrganization(context.Background(), orgID); err != nil {
			t.Logf("cleanup: failed to delete organization %s: %v", orgID, err)
		}
	})

	createdRole, err := testClient.CreateOrganizationRole(ctx, fmt.Sprintf("member-role-%d", time.Now().UnixNano()), "", "", nil)
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
	members, err := testClient.ListOrganizationMembers(ctx, orgID)
	require.NoError(t, err)
	require.Len(t, members, 1)

	member := members[0]
	assert.Equal(t, userID, member.User.ID)
	assert.Len(t, member.Roles, 1, "Member should have one role")
	assert.Equal(t, roleID, member.Roles[0].ID)
}
