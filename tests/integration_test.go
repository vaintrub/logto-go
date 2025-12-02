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

// TestPing tests the Ping endpoint
func TestPing(t *testing.T) {
	ctx := context.Background()
	err := testClient.Ping(ctx)
	require.NoError(t, err, "Ping should succeed")
}

// TestAuthenticateM2M tests M2M authentication
func TestAuthenticateM2M(t *testing.T) {
	ctx := context.Background()
	token, expiresIn, err := testClient.AuthenticateM2M(ctx)
	require.NoError(t, err, "AuthenticateM2M should succeed")
	assert.NotEmpty(t, token, "Token should not be empty")
	assert.Greater(t, expiresIn, 0, "ExpiresIn should be positive")

	// Test token caching - second call should return same token
	token2, _, err := testClient.AuthenticateM2M(ctx)
	require.NoError(t, err)
	assert.Equal(t, token, token2, "Cached token should be returned")
}

// TestUserCRUD tests user creation, retrieval, update, and deletion
func TestUserCRUD(t *testing.T) {
	ctx := context.Background()
	username := fmt.Sprintf("testuser_%d", time.Now().UnixNano())
	email := fmt.Sprintf("testuser%d@test.local", time.Now().UnixNano())

	// Create user
	userID, err := testClient.CreateUser(ctx, username, "Password123!", "Test User", email)
	require.NoError(t, err, "CreateUser should succeed")
	assert.NotEmpty(t, userID, "User ID should not be empty")

	// Get user
	user, err := testClient.GetUser(ctx, userID)
	require.NoError(t, err, "GetUser should succeed")
	assert.Equal(t, userID, user.ID)
	assert.Equal(t, "Test User", user.Name)
	assert.Equal(t, email, user.Email)

	// Get user by email
	userByEmail, err := testClient.GetUserByEmail(ctx, email)
	require.NoError(t, err, "GetUserByEmail should succeed")
	assert.Equal(t, userID, userByEmail.ID)

	// Update user
	newName := "Updated User"
	err = testClient.UpdateUser(ctx, userID, models.UserUpdate{Name: &newName})
	require.NoError(t, err, "UpdateUser should succeed")

	// Verify update
	updatedUser, err := testClient.GetUser(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, newName, updatedUser.Name)

	// Update custom data
	err = testClient.UpdateUserCustomData(ctx, userID, map[string]interface{}{"key": "value"})
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

// TestOrganizationCRUD tests organization lifecycle
func TestOrganizationCRUD(t *testing.T) {
	ctx := context.Background()
	orgName := fmt.Sprintf("Test Org %d", time.Now().UnixNano())

	// Create organization
	orgID, err := testClient.CreateOrganization(ctx, orgName, "Test description")
	require.NoError(t, err, "CreateOrganization should succeed")
	assert.NotEmpty(t, orgID, "Org ID should not be empty")

	// Get organization
	org, err := testClient.GetOrganization(ctx, orgID)
	require.NoError(t, err, "GetOrganization should succeed")
	assert.Equal(t, orgID, org.ID)
	assert.Equal(t, orgName, org.Name)
	assert.Equal(t, "Test description", org.Description)

	// Update organization
	newName := orgName + " Updated"
	err = testClient.UpdateOrganization(ctx, orgID, newName, "Updated description", nil)
	require.NoError(t, err, "UpdateOrganization should succeed")

	// Verify update
	updatedOrg, err := testClient.GetOrganization(ctx, orgID)
	require.NoError(t, err)
	assert.Equal(t, newName, updatedOrg.Name)

	// List organizations
	orgs, err := testClient.ListOrganizations(ctx)
	require.NoError(t, err, "ListOrganizations should succeed")
	assert.NotEmpty(t, orgs)

	// Delete organization
	err = testClient.DeleteOrganization(ctx, orgID)
	require.NoError(t, err, "DeleteOrganization should succeed")

	// Verify deletion
	_, err = testClient.GetOrganization(ctx, orgID)
	assert.Error(t, err, "GetOrganization should fail after deletion")
}

// TestOrganizationMembership tests adding/removing users from organizations
func TestOrganizationMembership(t *testing.T) {
	ctx := context.Background()

	// Create user
	username := fmt.Sprintf("member_%d", time.Now().UnixNano())
	userID, err := testClient.CreateUser(ctx, username, "Password123!", "Member User", "")
	require.NoError(t, err)

	// Create organization
	orgName := fmt.Sprintf("Membership Org %d", time.Now().UnixNano())
	orgID, err := testClient.CreateOrganization(ctx, orgName, "")
	require.NoError(t, err)
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
	user1, err := testClient.CreateUser(ctx, fmt.Sprintf("batch1_%d", time.Now().UnixNano()), "Password123!", "", "")
	require.NoError(t, err)
	user2, err := testClient.CreateUser(ctx, fmt.Sprintf("batch2_%d", time.Now().UnixNano()), "Password123!", "", "")
	require.NoError(t, err)

	// Create organization
	orgID, err := testClient.CreateOrganization(ctx, fmt.Sprintf("Batch Org %d", time.Now().UnixNano()), "")
	require.NoError(t, err)
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
	roleID, err := testClient.CreateOrganizationRole(ctx, fmt.Sprintf("batch-role-%d", time.Now().UnixNano()), "Batch role", nil)
	require.NoError(t, err)
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

// TestOrganizationRoleCRUD tests organization role lifecycle
func TestOrganizationRoleCRUD(t *testing.T) {
	ctx := context.Background()
	roleName := fmt.Sprintf("Test Role %d", time.Now().UnixNano())

	// Create role
	roleID, err := testClient.CreateOrganizationRole(ctx, roleName, "Test role description", nil)
	require.NoError(t, err, "CreateOrganizationRole should succeed")
	assert.NotEmpty(t, roleID)

	// Get role
	role, err := testClient.GetOrganizationRole(ctx, roleID)
	require.NoError(t, err, "GetOrganizationRole should succeed")
	assert.Equal(t, roleID, role.ID)
	assert.Equal(t, roleName, role.Name)

	// Update role
	newRoleName := roleName + " Updated"
	err = testClient.UpdateOrganizationRole(ctx, roleID, newRoleName, "Updated description")
	require.NoError(t, err, "UpdateOrganizationRole should succeed")

	// List roles
	roles, err := testClient.ListOrganizationRoles(ctx)
	require.NoError(t, err, "ListOrganizationRoles should succeed")
	assert.NotEmpty(t, roles)

	// Delete role
	err = testClient.DeleteOrganizationRole(ctx, roleID)
	require.NoError(t, err, "DeleteOrganizationRole should succeed")
}

// TestOrganizationScopeCRUD tests organization scope lifecycle
func TestOrganizationScopeCRUD(t *testing.T) {
	ctx := context.Background()
	scopeName := fmt.Sprintf("test:scope:%d", time.Now().UnixNano())

	// Create scope
	scopeID, err := testClient.CreateOrganizationScope(ctx, scopeName, "Test scope")
	require.NoError(t, err, "CreateOrganizationScope should succeed")
	assert.NotEmpty(t, scopeID)

	// Get scope
	scope, err := testClient.GetOrganizationScope(ctx, scopeID)
	require.NoError(t, err, "GetOrganizationScope should succeed")
	assert.Equal(t, scopeID, scope.ID)
	assert.Equal(t, scopeName, scope.Name)

	// Update scope
	err = testClient.UpdateOrganizationScope(ctx, scopeID, "", "Updated description")
	require.NoError(t, err, "UpdateOrganizationScope should succeed")

	// List scopes
	scopes, err := testClient.ListOrganizationScopes(ctx)
	require.NoError(t, err, "ListOrganizationScopes should succeed")
	assert.NotEmpty(t, scopes)

	// Delete scope
	err = testClient.DeleteOrganizationScope(ctx, scopeID)
	require.NoError(t, err, "DeleteOrganizationScope should succeed")
}

// TestRoleScopeOperations tests assigning/removing scopes from roles
func TestRoleScopeOperations(t *testing.T) {
	ctx := context.Background()

	// Create scope
	scopeID, err := testClient.CreateOrganizationScope(ctx, fmt.Sprintf("role:scope:%d", time.Now().UnixNano()), "")
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := testClient.DeleteOrganizationScope(context.Background(), scopeID); err != nil {
			t.Logf("cleanup: failed to delete organization scope %s: %v", scopeID, err)
		}
	})

	// Create role
	roleID, err := testClient.CreateOrganizationRole(ctx, fmt.Sprintf("scope-role-%d", time.Now().UnixNano()), "", nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := testClient.DeleteOrganizationRole(context.Background(), roleID); err != nil {
			t.Logf("cleanup: failed to delete organization role %s: %v", roleID, err)
		}
	})

	// Add scope to role
	err = testClient.AddOrganizationRoleScopes(ctx, roleID, []string{scopeID})
	require.NoError(t, err, "AddOrganizationRoleScopes should succeed")

	// Verify scope is assigned
	role, err := testClient.GetOrganizationRole(ctx, roleID)
	require.NoError(t, err)
	require.Len(t, role.Scopes, 1, "Role should have 1 scope")
	assert.Equal(t, scopeID, role.Scopes[0].ID)

	// Remove scope from role
	err = testClient.RemoveOrganizationRoleScope(ctx, roleID, scopeID)
	require.NoError(t, err, "RemoveOrganizationRoleScope should succeed")

	// Verify removal
	role, err = testClient.GetOrganizationRole(ctx, roleID)
	require.NoError(t, err)
	assert.Len(t, role.Scopes, 0)

	// Test SetOrganizationRoleScopes (replace all)
	err = testClient.SetOrganizationRoleScopes(ctx, roleID, []string{scopeID})
	require.NoError(t, err, "SetOrganizationRoleScopes should succeed")

	role, err = testClient.GetOrganizationRole(ctx, roleID)
	require.NoError(t, err)
	assert.Len(t, role.Scopes, 1)
}

// TestUserRolesInOrganization tests user role assignment
func TestUserRolesInOrganization(t *testing.T) {
	ctx := context.Background()

	// Create user
	userID, err := testClient.CreateUser(ctx, fmt.Sprintf("roleuser_%d", time.Now().UnixNano()), "Password123!", "", "")
	require.NoError(t, err)

	// Create organization
	orgID, err := testClient.CreateOrganization(ctx, fmt.Sprintf("Role Test Org %d", time.Now().UnixNano()), "")
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := testClient.DeleteOrganization(context.Background(), orgID); err != nil {
			t.Logf("cleanup: failed to delete organization %s: %v", orgID, err)
		}
	})

	// Create role
	roleID, err := testClient.CreateOrganizationRole(ctx, fmt.Sprintf("user-role-%d", time.Now().UnixNano()), "", nil)
	require.NoError(t, err)
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
	role2ID, err := testClient.CreateOrganizationRole(ctx, fmt.Sprintf("user-role2-%d", time.Now().UnixNano()), "", nil)
	require.NoError(t, err)
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

// TestAPIResourceCRUD tests API resource lifecycle
func TestAPIResourceCRUD(t *testing.T) {
	ctx := context.Background()
	resourceName := fmt.Sprintf("Test API %d", time.Now().UnixNano())
	indicator := fmt.Sprintf("https://api.test.local/%d", time.Now().UnixNano())

	// Create resource
	resourceID, err := testClient.CreateAPIResource(ctx, resourceName, indicator)
	require.NoError(t, err, "CreateAPIResource should succeed")
	assert.NotEmpty(t, resourceID)

	// Get resource
	resource, err := testClient.GetAPIResource(ctx, resourceID)
	require.NoError(t, err, "GetAPIResource should succeed")
	assert.Equal(t, resourceID, resource.ID)
	assert.Equal(t, resourceName, resource.Name)
	assert.Equal(t, indicator, resource.Indicator)

	// Update resource
	newName := resourceName + " Updated"
	err = testClient.UpdateAPIResource(ctx, resourceID, newName, nil)
	require.NoError(t, err, "UpdateAPIResource should succeed")

	// List resources
	resources, err := testClient.ListAPIResources(ctx)
	require.NoError(t, err, "ListAPIResources should succeed")
	assert.NotEmpty(t, resources)

	// Delete resource
	err = testClient.DeleteAPIResource(ctx, resourceID)
	require.NoError(t, err, "DeleteAPIResource should succeed")
}

// TestAPIResourceScopeCRUD tests API resource scope lifecycle
func TestAPIResourceScopeCRUD(t *testing.T) {
	ctx := context.Background()

	// Create resource first
	resourceID, err := testClient.CreateAPIResource(ctx, fmt.Sprintf("Scope Test API %d", time.Now().UnixNano()), fmt.Sprintf("https://api.scope.test/%d", time.Now().UnixNano()))
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := testClient.DeleteAPIResource(context.Background(), resourceID); err != nil {
			t.Logf("cleanup: failed to delete API resource %s: %v", resourceID, err)
		}
	})

	scopeName := fmt.Sprintf("read:%d", time.Now().UnixNano())

	// Create scope
	scopeID, err := testClient.CreateAPIResourceScope(ctx, resourceID, scopeName, "Read access")
	require.NoError(t, err, "CreateAPIResourceScope should succeed")
	assert.NotEmpty(t, scopeID)

	// Get scope
	scope, err := testClient.GetAPIResourceScope(ctx, resourceID, scopeID)
	require.NoError(t, err, "GetAPIResourceScope should succeed")
	assert.Equal(t, scopeID, scope.ID)
	assert.Equal(t, scopeName, scope.Name)

	// Update scope
	err = testClient.UpdateAPIResourceScope(ctx, resourceID, scopeID, "", "Updated description")
	require.NoError(t, err, "UpdateAPIResourceScope should succeed")

	// List scopes
	scopes, err := testClient.ListAPIResourceScopes(ctx, resourceID)
	require.NoError(t, err, "ListAPIResourceScopes should succeed")
	assert.NotEmpty(t, scopes)

	// Delete scope
	err = testClient.DeleteAPIResourceScope(ctx, resourceID, scopeID)
	require.NoError(t, err, "DeleteAPIResourceScope should succeed")
}

// TestApplicationOperations tests application listing and creation
func TestApplicationOperations(t *testing.T) {
	ctx := context.Background()

	// List applications (should include our M2M app)
	apps, err := testClient.ListApplications(ctx)
	require.NoError(t, err, "ListApplications should succeed")
	assert.NotEmpty(t, apps, "Should have at least our M2M app")

	// Create SPA application
	appID, err := testClient.CreateApplication(ctx, models.ApplicationCreate{
		Name:         fmt.Sprintf("Test SPA %d", time.Now().UnixNano()),
		Description:  "Test SPA application",
		Type:         models.ApplicationTypeSPA,
		RedirectURIs: []string{"http://localhost:3000/callback"},
	})
	require.NoError(t, err, "CreateApplication should succeed")
	assert.NotEmpty(t, appID)

	// Verify app appears in list
	apps, err = testClient.ListApplications(ctx)
	require.NoError(t, err)
	found := false
	for _, app := range apps {
		if app.ID == appID {
			found = true
			assert.Equal(t, models.ApplicationTypeSPA, app.Type)
			break
		}
	}
	assert.True(t, found, "Created app should be in list")
}

// TestOrganizationInvitations tests invitation lifecycle
func TestOrganizationInvitations(t *testing.T) {
	ctx := context.Background()

	// Create organization
	orgID, err := testClient.CreateOrganization(ctx, fmt.Sprintf("Invite Org %d", time.Now().UnixNano()), "")
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := testClient.DeleteOrganization(context.Background(), orgID); err != nil {
			t.Logf("cleanup: failed to delete organization %s: %v", orgID, err)
		}
	})

	inviteeEmail := fmt.Sprintf("invitee-%d@test.local", time.Now().UnixNano())
	expiresAt := time.Now().Add(24 * time.Hour).UnixMilli()

	// Create invitation
	invitationID, err := testClient.CreateOrganizationInvitation(ctx, orgID, "", inviteeEmail, nil, expiresAt)
	require.NoError(t, err, "CreateOrganizationInvitation should succeed")
	assert.NotEmpty(t, invitationID)

	// Get invitation
	invitation, err := testClient.GetOrganizationInvitation(ctx, invitationID)
	require.NoError(t, err, "GetOrganizationInvitation should succeed")
	assert.Equal(t, invitationID, invitation.ID)
	assert.Equal(t, inviteeEmail, invitation.Invitee)
	assert.Equal(t, "Pending", invitation.Status)

	// List invitations
	invitations, err := testClient.ListOrganizationInvitations(ctx, orgID)
	require.NoError(t, err, "ListOrganizationInvitations should succeed")
	assert.Len(t, invitations, 1)

	// Delete invitation
	err = testClient.DeleteOrganizationInvitation(ctx, invitationID)
	require.NoError(t, err, "DeleteOrganizationInvitation should succeed")

	// Verify deletion
	invitations, err = testClient.ListOrganizationInvitations(ctx, orgID)
	require.NoError(t, err)
	assert.Len(t, invitations, 0)
}

// TestOneTimeToken tests one-time token creation
func TestOneTimeToken(t *testing.T) {
	ctx := context.Background()
	email := fmt.Sprintf("ott-%d@test.local", time.Now().UnixNano())

	result, err := testClient.CreateOneTimeToken(ctx, email, 600, nil)
	require.NoError(t, err, "CreateOneTimeToken should succeed")
	assert.NotEmpty(t, result.Token)
	assert.Greater(t, result.ExpiresAt, time.Now().UnixMilli())
}

// TestIterators tests paginated iterators
func TestIterators(t *testing.T) {
	ctx := context.Background()

	// Test UserIterator
	t.Run("UserIterator", func(t *testing.T) {
		iter := testClient.ListUsersIter(ctx, 10)
		count := 0
		for iter.Next() {
			user := iter.User()
			assert.NotEmpty(t, user.ID)
			count++
			if count >= 3 {
				break
			}
		}
		// Error check at the end
		assert.NoError(t, iter.Err())
	})

	// Test OrganizationIterator
	t.Run("OrganizationIterator", func(t *testing.T) {
		// Create a few orgs first
		for i := 0; i < 3; i++ {
			_, _ = testClient.CreateOrganization(ctx, fmt.Sprintf("Iter Org %d-%d", time.Now().UnixNano(), i), "")
		}

		iter := testClient.ListOrganizationsIter(ctx, 10)
		count := 0
		for iter.Next() {
			org := iter.Organization()
			assert.NotEmpty(t, org.ID)
			count++
		}
		assert.NoError(t, iter.Err())
		assert.GreaterOrEqual(t, count, 3)
	})
}

// TestValidationErrors tests that validation errors are properly returned
func TestValidationErrors(t *testing.T) {
	ctx := context.Background()

	// Empty userID should fail
	_, err := testClient.GetUser(ctx, "")
	assert.Error(t, err, "GetUser with empty ID should fail")

	// Empty orgID should fail
	_, err = testClient.GetOrganization(ctx, "")
	assert.Error(t, err, "GetOrganization with empty ID should fail")

	// Empty name should fail
	_, err = testClient.CreateOrganization(ctx, "", "")
	assert.Error(t, err, "CreateOrganization with empty name should fail")

	// Empty username should fail
	_, err = testClient.CreateUser(ctx, "", "password", "", "")
	assert.Error(t, err, "CreateUser with empty username should fail")
}

// TestListOrganizationMembersWithRoles tests that member roles are correctly parsed
func TestListOrganizationMembersWithRoles(t *testing.T) {
	ctx := context.Background()

	// Create user, org, and role
	userID, err := testClient.CreateUser(ctx, fmt.Sprintf("rolemember_%d", time.Now().UnixNano()), "Password123!", "", "")
	require.NoError(t, err)

	orgID, err := testClient.CreateOrganization(ctx, fmt.Sprintf("MemberRole Org %d", time.Now().UnixNano()), "")
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := testClient.DeleteOrganization(context.Background(), orgID); err != nil {
			t.Logf("cleanup: failed to delete organization %s: %v", orgID, err)
		}
	})

	roleID, err := testClient.CreateOrganizationRole(ctx, fmt.Sprintf("member-role-%d", time.Now().UnixNano()), "", nil)
	require.NoError(t, err)
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

// TestAssignResourceScopesToOrganizationRole tests assigning API resource scopes to org roles
func TestAssignResourceScopesToOrganizationRole(t *testing.T) {
	ctx := context.Background()

	// Create API resource with scope
	resourceID, err := testClient.CreateAPIResource(ctx,
		fmt.Sprintf("Resource Scope Test %d", time.Now().UnixNano()),
		fmt.Sprintf("https://api.resource-scope.test/%d", time.Now().UnixNano()))
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := testClient.DeleteAPIResource(context.Background(), resourceID); err != nil {
			t.Logf("cleanup: failed to delete API resource %s: %v", resourceID, err)
		}
	})

	scopeID, err := testClient.CreateAPIResourceScope(ctx, resourceID,
		fmt.Sprintf("read:%d", time.Now().UnixNano()), "Read access")
	require.NoError(t, err)

	// Create organization role
	roleID, err := testClient.CreateOrganizationRole(ctx,
		fmt.Sprintf("resource-scope-role-%d", time.Now().UnixNano()), "", nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := testClient.DeleteOrganizationRole(context.Background(), roleID); err != nil {
			t.Logf("cleanup: failed to delete organization role %s: %v", roleID, err)
		}
	})

	// Assign resource scope to organization role
	err = testClient.AssignResourceScopesToOrganizationRole(ctx, roleID, []string{scopeID})
	require.NoError(t, err, "AssignResourceScopesToOrganizationRole should succeed")
}

// TestSendInvitationMessage tests sending invitation email
func TestSendInvitationMessage(t *testing.T) {
	ctx := context.Background()

	// Create organization
	orgID, err := testClient.CreateOrganization(ctx,
		fmt.Sprintf("Invite Message Org %d", time.Now().UnixNano()), "")
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := testClient.DeleteOrganization(context.Background(), orgID); err != nil {
			t.Logf("cleanup: failed to delete organization %s: %v", orgID, err)
		}
	})

	// Create invitation
	inviteeEmail := fmt.Sprintf("invite_msg_%d@test.local", time.Now().UnixNano())
	expiresAt := time.Now().Add(24 * time.Hour).UnixMilli()

	invitationID, err := testClient.CreateOrganizationInvitation(ctx, orgID, "", inviteeEmail, nil, expiresAt)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := testClient.DeleteOrganizationInvitation(context.Background(), invitationID); err != nil {
			t.Logf("cleanup: failed to delete invitation %s: %v", invitationID, err)
		}
	})

	// Send invitation message with magic link
	// Note: This may fail in test environment without email connector configured,
	// but we're testing the API call works
	err = testClient.SendInvitationMessage(ctx, invitationID, "https://example.com/invite?token=test123")
	// Accept either success or specific error (email not configured)
	if err != nil {
		assert.Contains(t, err.Error(), "connector", "Error should be about email connector if it fails")
	}
}

// TestGetOrganizationRoleScopes tests getting scopes for a role directly
func TestGetOrganizationRoleScopes(t *testing.T) {
	ctx := context.Background()

	// Create scope
	scopeID, err := testClient.CreateOrganizationScope(ctx,
		fmt.Sprintf("direct:scope:%d", time.Now().UnixNano()), "Direct scope test")
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := testClient.DeleteOrganizationScope(context.Background(), scopeID); err != nil {
			t.Logf("cleanup: failed to delete organization scope %s: %v", scopeID, err)
		}
	})

	// Create role with scope
	roleID, err := testClient.CreateOrganizationRole(ctx,
		fmt.Sprintf("direct-scope-role-%d", time.Now().UnixNano()), "", []string{scopeID})
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := testClient.DeleteOrganizationRole(context.Background(), roleID); err != nil {
			t.Logf("cleanup: failed to delete organization role %s: %v", roleID, err)
		}
	})

	// Get scopes directly
	scopes, err := testClient.GetOrganizationRoleScopes(ctx, roleID)
	require.NoError(t, err, "GetOrganizationRoleScopes should succeed")
	assert.Len(t, scopes, 1)
	assert.Equal(t, scopeID, scopes[0].ID)
}
