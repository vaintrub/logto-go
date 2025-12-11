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

// TestRoleCRUD tests global/tenant-level role lifecycle
func TestRoleCRUD(t *testing.T) {
	ctx := context.Background()
	roleName := fmt.Sprintf("Test Global Role %d", time.Now().UnixNano())

	// Create role
	createdRole, err := testClient.CreateRole(ctx, roleName, "Test global role description", models.RoleTypeUser, nil)
	require.NoError(t, err, "CreateRole should succeed")
	assert.NotEmpty(t, createdRole.ID)
	assert.Equal(t, roleName, createdRole.Name)
	assert.Equal(t, models.RoleTypeUser, createdRole.Type)
	roleID := createdRole.ID
	t.Cleanup(func() {
		if err := testClient.DeleteRole(context.Background(), roleID); err != nil {
			t.Logf("cleanup: failed to delete role %s: %v", roleID, err)
		}
	})

	// Get role
	role, err := testClient.GetRole(ctx, roleID)
	require.NoError(t, err, "GetRole should succeed")
	assert.Equal(t, roleID, role.ID)
	assert.Equal(t, roleName, role.Name)
	assert.Equal(t, "Test global role description", role.Description)

	// Update role
	newRoleName := roleName + " Updated"
	updatedRole, err := testClient.UpdateRole(ctx, roleID, newRoleName, "Updated description", nil)
	require.NoError(t, err, "UpdateRole should succeed")
	assert.Equal(t, newRoleName, updatedRole.Name)
	assert.Equal(t, "Updated description", updatedRole.Description)

	// List roles
	roles, err := testClient.ListRoles(ctx)
	require.NoError(t, err, "ListRoles should succeed")
	assert.NotEmpty(t, roles)

	// Verify our role is in the list
	found := false
	for _, r := range roles {
		if r.ID == roleID {
			found = true
			assert.Equal(t, newRoleName, r.Name)
			break
		}
	}
	assert.True(t, found, "Created role should be in the list")

	// Test update with isDefault
	isDefault := true
	_, err = testClient.UpdateRole(ctx, roleID, "", "", &isDefault)
	require.NoError(t, err, "UpdateRole with isDefault should succeed")

	role, err = testClient.GetRole(ctx, roleID)
	require.NoError(t, err)
	assert.True(t, role.IsDefault)
}

// TestRoleScopes tests assigning/removing API resource scopes from global roles
func TestRoleScopes(t *testing.T) {
	ctx := context.Background()

	// Create API resource with scope
	createdResource, err := testClient.CreateAPIResource(ctx,
		fmt.Sprintf("Role Scope Test API %d", time.Now().UnixNano()),
		fmt.Sprintf("https://api.role-scope.test/%d", time.Now().UnixNano()))
	require.NoError(t, err)
	resourceID := createdResource.ID
	t.Cleanup(func() {
		if err := testClient.DeleteAPIResource(context.Background(), resourceID); err != nil {
			t.Logf("cleanup: failed to delete API resource %s: %v", resourceID, err)
		}
	})

	createdScope, err := testClient.CreateAPIResourceScope(ctx, resourceID,
		fmt.Sprintf("read:%d", time.Now().UnixNano()), "Read access")
	require.NoError(t, err)
	scopeID := createdScope.ID

	createdScope2, err := testClient.CreateAPIResourceScope(ctx, resourceID,
		fmt.Sprintf("write:%d", time.Now().UnixNano()), "Write access")
	require.NoError(t, err)
	scope2ID := createdScope2.ID

	// Create role
	createdRole, err := testClient.CreateRole(ctx,
		fmt.Sprintf("scope-test-role-%d", time.Now().UnixNano()), "Role for scope testing", models.RoleTypeUser, nil)
	require.NoError(t, err)
	roleID := createdRole.ID
	t.Cleanup(func() {
		if err := testClient.DeleteRole(context.Background(), roleID); err != nil {
			t.Logf("cleanup: failed to delete role %s: %v", roleID, err)
		}
	})

	// Assign scopes to role
	err = testClient.AssignRoleScopes(ctx, roleID, []string{scopeID})
	require.NoError(t, err, "AssignRoleScopes should succeed")

	// List role scopes
	scopes, err := testClient.ListRoleScopes(ctx, roleID)
	require.NoError(t, err, "ListRoleScopes should succeed")
	assert.Len(t, scopes, 1)
	assert.Equal(t, scopeID, scopes[0].ID)

	// Assign another scope
	err = testClient.AssignRoleScopes(ctx, roleID, []string{scope2ID})
	require.NoError(t, err)

	scopes, err = testClient.ListRoleScopes(ctx, roleID)
	require.NoError(t, err)
	assert.Len(t, scopes, 2)

	// Remove scope from role
	err = testClient.RemoveRoleScope(ctx, roleID, scopeID)
	require.NoError(t, err, "RemoveRoleScope should succeed")

	// Verify removal
	scopes, err = testClient.ListRoleScopes(ctx, roleID)
	require.NoError(t, err)
	assert.Len(t, scopes, 1)
	assert.Equal(t, scope2ID, scopes[0].ID)
}

// TestRoleUsers tests assigning/removing users from global roles
func TestRoleUsers(t *testing.T) {
	ctx := context.Background()

	// Create users
	createdUser1, err := testClient.CreateUser(ctx, fmt.Sprintf("roleuser1_%d", time.Now().UnixNano()), "Password123!", "Role User 1", "")
	require.NoError(t, err)
	user1ID := createdUser1.ID

	createdUser2, err := testClient.CreateUser(ctx, fmt.Sprintf("roleuser2_%d", time.Now().UnixNano()), "Password123!", "Role User 2", "")
	require.NoError(t, err)
	user2ID := createdUser2.ID

	// Create role
	createdRole, err := testClient.CreateRole(ctx,
		fmt.Sprintf("user-test-role-%d", time.Now().UnixNano()), "Role for user testing", models.RoleTypeUser, nil)
	require.NoError(t, err)
	roleID := createdRole.ID
	t.Cleanup(func() {
		if err := testClient.DeleteRole(context.Background(), roleID); err != nil {
			t.Logf("cleanup: failed to delete role %s: %v", roleID, err)
		}
	})

	// Assign role to users
	err = testClient.AssignRoleToUsers(ctx, roleID, []string{user1ID, user2ID})
	require.NoError(t, err, "AssignRoleToUsers should succeed")

	// List role users
	users, err := testClient.ListRoleUsers(ctx, roleID)
	require.NoError(t, err, "ListRoleUsers should succeed")
	assert.Len(t, users, 2)

	// Verify both users are in the list
	userIDs := make(map[string]bool)
	for _, u := range users {
		userIDs[u.ID] = true
	}
	assert.True(t, userIDs[user1ID], "User 1 should be in the list")
	assert.True(t, userIDs[user2ID], "User 2 should be in the list")

	// Remove user from role
	err = testClient.RemoveRoleFromUser(ctx, roleID, user1ID)
	require.NoError(t, err, "RemoveRoleFromUser should succeed")

	// Verify removal
	users, err = testClient.ListRoleUsers(ctx, roleID)
	require.NoError(t, err)
	assert.Len(t, users, 1)
	assert.Equal(t, user2ID, users[0].ID)
}

// TestRoleApplications tests assigning/removing M2M applications from global roles
func TestRoleApplications(t *testing.T) {
	ctx := context.Background()

	// Create M2M applications
	createdApp1, err := testClient.CreateApplication(ctx, models.ApplicationCreate{
		Name:        fmt.Sprintf("Role Test M2M App 1 %d", time.Now().UnixNano()),
		Description: "Test M2M app 1 for role testing",
		Type:        models.ApplicationTypeMachineToMachine,
	})
	require.NoError(t, err)
	app1ID := createdApp1.ID

	createdApp2, err := testClient.CreateApplication(ctx, models.ApplicationCreate{
		Name:        fmt.Sprintf("Role Test M2M App 2 %d", time.Now().UnixNano()),
		Description: "Test M2M app 2 for role testing",
		Type:        models.ApplicationTypeMachineToMachine,
	})
	require.NoError(t, err)
	app2ID := createdApp2.ID

	// Create M2M role (must be MachineToMachine type to assign to M2M apps)
	createdRole, err := testClient.CreateRole(ctx,
		fmt.Sprintf("m2m-app-test-role-%d", time.Now().UnixNano()), "M2M Role for app testing", models.RoleTypeMachineToMachine, nil)
	require.NoError(t, err)
	roleID := createdRole.ID
	t.Cleanup(func() {
		if err := testClient.DeleteRole(context.Background(), roleID); err != nil {
			t.Logf("cleanup: failed to delete role %s: %v", roleID, err)
		}
	})

	// Assign role to applications
	err = testClient.AssignRoleToApplications(ctx, roleID, []string{app1ID, app2ID})
	require.NoError(t, err, "AssignRoleToApplications should succeed")

	// List role applications
	apps, err := testClient.ListRoleApplications(ctx, roleID)
	require.NoError(t, err, "ListRoleApplications should succeed")
	assert.Len(t, apps, 2)

	// Verify both apps are in the list
	appIDs := make(map[string]bool)
	for _, a := range apps {
		appIDs[a.ID] = true
	}
	assert.True(t, appIDs[app1ID], "App 1 should be in the list")
	assert.True(t, appIDs[app2ID], "App 2 should be in the list")

	// Remove application from role
	err = testClient.RemoveRoleFromApplication(ctx, roleID, app1ID)
	require.NoError(t, err, "RemoveRoleFromApplication should succeed")

	// Verify removal
	apps, err = testClient.ListRoleApplications(ctx, roleID)
	require.NoError(t, err)
	assert.Len(t, apps, 1)
	assert.Equal(t, app2ID, apps[0].ID)
}

// TestCreateRoleWithScopes tests creating a role with scopes assigned at creation time
func TestCreateRoleWithScopes(t *testing.T) {
	ctx := context.Background()

	// Create API resource with scope
	createdResource, err := testClient.CreateAPIResource(ctx,
		fmt.Sprintf("Role Create Scope Test %d", time.Now().UnixNano()),
		fmt.Sprintf("https://api.role-create-scope.test/%d", time.Now().UnixNano()))
	require.NoError(t, err)
	resourceID := createdResource.ID
	t.Cleanup(func() {
		if err := testClient.DeleteAPIResource(context.Background(), resourceID); err != nil {
			t.Logf("cleanup: failed to delete API resource %s: %v", resourceID, err)
		}
	})

	createdScope, err := testClient.CreateAPIResourceScope(ctx, resourceID,
		fmt.Sprintf("manage:%d", time.Now().UnixNano()), "Manage access")
	require.NoError(t, err)
	scopeID := createdScope.ID

	// Create role with scope
	createdRole, err := testClient.CreateRole(ctx,
		fmt.Sprintf("scope-at-create-role-%d", time.Now().UnixNano()),
		"Role with scope at creation",
		models.RoleTypeUser,
		[]string{scopeID})
	require.NoError(t, err, "CreateRole with scopes should succeed")
	roleID := createdRole.ID
	t.Cleanup(func() {
		if err := testClient.DeleteRole(context.Background(), roleID); err != nil {
			t.Logf("cleanup: failed to delete role %s: %v", roleID, err)
		}
	})

	// Verify scope is assigned
	scopes, err := testClient.ListRoleScopes(ctx, roleID)
	require.NoError(t, err)
	assert.Len(t, scopes, 1)
	assert.Equal(t, scopeID, scopes[0].ID)
}
