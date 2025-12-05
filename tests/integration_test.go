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

// TestOrganizationCRUD tests organization lifecycle
func TestOrganizationCRUD(t *testing.T) {
	ctx := context.Background()
	orgName := fmt.Sprintf("Test Org %d", time.Now().UnixNano())

	// Create organization
	createdOrg, err := testClient.CreateOrganization(ctx, orgName, "Test description")
	require.NoError(t, err, "CreateOrganization should succeed")
	assert.NotEmpty(t, createdOrg.ID, "Org ID should not be empty")
	orgID := createdOrg.ID

	// Get organization
	org, err := testClient.GetOrganization(ctx, orgID)
	require.NoError(t, err, "GetOrganization should succeed")
	assert.Equal(t, orgID, org.ID)
	assert.Equal(t, orgName, org.Name)
	assert.Equal(t, "Test description", org.Description)

	// Update organization
	newName := orgName + " Updated"
	updatedOrg, err := testClient.UpdateOrganization(ctx, orgID, newName, "Updated description", nil)
	require.NoError(t, err, "UpdateOrganization should succeed")
	assert.Equal(t, newName, updatedOrg.Name)

	// Verify update
	verifiedOrg, err := testClient.GetOrganization(ctx, orgID)
	require.NoError(t, err)
	assert.Equal(t, newName, verifiedOrg.Name)

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

// TestOrganizationRoleCRUD tests organization role lifecycle
func TestOrganizationRoleCRUD(t *testing.T) {
	ctx := context.Background()
	roleName := fmt.Sprintf("Test Role %d", time.Now().UnixNano())

	// Create role
	createdRole, err := testClient.CreateOrganizationRole(ctx, roleName, "Test role description", "", nil)
	require.NoError(t, err, "CreateOrganizationRole should succeed")
	assert.NotEmpty(t, createdRole.ID)
	roleID := createdRole.ID

	// Get role
	role, err := testClient.GetOrganizationRole(ctx, roleID)
	require.NoError(t, err, "GetOrganizationRole should succeed")
	assert.Equal(t, roleID, role.ID)
	assert.Equal(t, roleName, role.Name)

	// Update role
	newRoleName := roleName + " Updated"
	_, err = testClient.UpdateOrganizationRole(ctx, roleID, newRoleName, "Updated description")
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
	createdScope, err := testClient.CreateOrganizationScope(ctx, scopeName, "Test scope")
	require.NoError(t, err, "CreateOrganizationScope should succeed")
	assert.NotEmpty(t, createdScope.ID)
	scopeID := createdScope.ID

	// Get scope
	scope, err := testClient.GetOrganizationScope(ctx, scopeID)
	require.NoError(t, err, "GetOrganizationScope should succeed")
	assert.Equal(t, scopeID, scope.ID)
	assert.Equal(t, scopeName, scope.Name)

	// Update scope
	_, err = testClient.UpdateOrganizationScope(ctx, scopeID, "", "Updated description")
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
	createdScope, err := testClient.CreateOrganizationScope(ctx, fmt.Sprintf("role:scope:%d", time.Now().UnixNano()), "")
	require.NoError(t, err)
	scopeID := createdScope.ID
	t.Cleanup(func() {
		if err := testClient.DeleteOrganizationScope(context.Background(), scopeID); err != nil {
			t.Logf("cleanup: failed to delete organization scope %s: %v", scopeID, err)
		}
	})

	// Create role
	createdRole, err := testClient.CreateOrganizationRole(ctx, fmt.Sprintf("scope-role-%d", time.Now().UnixNano()), "", "", nil)
	require.NoError(t, err)
	roleID := createdRole.ID
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

// TestAPIResourceCRUD tests API resource lifecycle
func TestAPIResourceCRUD(t *testing.T) {
	ctx := context.Background()
	resourceName := fmt.Sprintf("Test API %d", time.Now().UnixNano())
	indicator := fmt.Sprintf("https://api.test.local/%d", time.Now().UnixNano())

	// Create resource
	createdResource, err := testClient.CreateAPIResource(ctx, resourceName, indicator)
	require.NoError(t, err, "CreateAPIResource should succeed")
	assert.NotEmpty(t, createdResource.ID)
	resourceID := createdResource.ID

	// Get resource
	resource, err := testClient.GetAPIResource(ctx, resourceID)
	require.NoError(t, err, "GetAPIResource should succeed")
	assert.Equal(t, resourceID, resource.ID)
	assert.Equal(t, resourceName, resource.Name)
	assert.Equal(t, indicator, resource.Indicator)

	// Update resource
	newName := resourceName + " Updated"
	_, err = testClient.UpdateAPIResource(ctx, resourceID, newName, nil)
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
	createdResource, err := testClient.CreateAPIResource(ctx, fmt.Sprintf("Scope Test API %d", time.Now().UnixNano()), fmt.Sprintf("https://api.scope.test/%d", time.Now().UnixNano()))
	require.NoError(t, err)
	resourceID := createdResource.ID
	t.Cleanup(func() {
		if err := testClient.DeleteAPIResource(context.Background(), resourceID); err != nil {
			t.Logf("cleanup: failed to delete API resource %s: %v", resourceID, err)
		}
	})

	scopeName := fmt.Sprintf("read:%d", time.Now().UnixNano())

	// Create scope
	createdScope, err := testClient.CreateAPIResourceScope(ctx, resourceID, scopeName, "Read access")
	require.NoError(t, err, "CreateAPIResourceScope should succeed")
	assert.NotEmpty(t, createdScope.ID)
	scopeID := createdScope.ID

	// Get scope
	scope, err := testClient.GetAPIResourceScope(ctx, resourceID, scopeID)
	require.NoError(t, err, "GetAPIResourceScope should succeed")
	assert.Equal(t, scopeID, scope.ID)
	assert.Equal(t, scopeName, scope.Name)

	// Update scope
	_, err = testClient.UpdateAPIResourceScope(ctx, resourceID, scopeID, "", "Updated description")
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
	createdApp, err := testClient.CreateApplication(ctx, models.ApplicationCreate{
		Name:         fmt.Sprintf("Test SPA %d", time.Now().UnixNano()),
		Description:  "Test SPA application",
		Type:         models.ApplicationTypeSPA,
		RedirectURIs: []string{"http://localhost:3000/callback"},
	})
	require.NoError(t, err, "CreateApplication should succeed")
	assert.NotEmpty(t, createdApp.ID)
	appID := createdApp.ID

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
	createdOrg, err := testClient.CreateOrganization(ctx, fmt.Sprintf("Invite Org %d", time.Now().UnixNano()), "")
	require.NoError(t, err)
	orgID := createdOrg.ID
	t.Cleanup(func() {
		if err := testClient.DeleteOrganization(context.Background(), orgID); err != nil {
			t.Logf("cleanup: failed to delete organization %s: %v", orgID, err)
		}
	})

	inviteeEmail := fmt.Sprintf("invitee-%d@test.local", time.Now().UnixNano())
	expiresAt := time.Now().Add(24 * time.Hour).UnixMilli()

	// Create invitation
	createdInvitation, err := testClient.CreateOrganizationInvitation(ctx, orgID, "", inviteeEmail, nil, expiresAt)
	require.NoError(t, err, "CreateOrganizationInvitation should succeed")
	assert.NotEmpty(t, createdInvitation.ID)
	invitationID := createdInvitation.ID

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

// TestAssignResourceScopesToOrganizationRole tests assigning API resource scopes to org roles
func TestAssignResourceScopesToOrganizationRole(t *testing.T) {
	ctx := context.Background()

	// Create API resource with scope
	createdResource, err := testClient.CreateAPIResource(ctx,
		fmt.Sprintf("Resource Scope Test %d", time.Now().UnixNano()),
		fmt.Sprintf("https://api.resource-scope.test/%d", time.Now().UnixNano()))
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

	// Create organization role
	createdRole, err := testClient.CreateOrganizationRole(ctx,
		fmt.Sprintf("resource-scope-role-%d", time.Now().UnixNano()), "", "", nil)
	require.NoError(t, err)
	roleID := createdRole.ID
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
	createdOrg, err := testClient.CreateOrganization(ctx,
		fmt.Sprintf("Invite Message Org %d", time.Now().UnixNano()), "")
	require.NoError(t, err)
	orgID := createdOrg.ID
	t.Cleanup(func() {
		if err := testClient.DeleteOrganization(context.Background(), orgID); err != nil {
			t.Logf("cleanup: failed to delete organization %s: %v", orgID, err)
		}
	})

	// Create invitation
	inviteeEmail := fmt.Sprintf("invite_msg_%d@test.local", time.Now().UnixNano())
	expiresAt := time.Now().Add(24 * time.Hour).UnixMilli()

	createdInvitation, err := testClient.CreateOrganizationInvitation(ctx, orgID, "", inviteeEmail, nil, expiresAt)
	require.NoError(t, err)
	invitationID := createdInvitation.ID
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
	createdScope, err := testClient.CreateOrganizationScope(ctx,
		fmt.Sprintf("direct:scope:%d", time.Now().UnixNano()), "Direct scope test")
	require.NoError(t, err)
	scopeID := createdScope.ID
	t.Cleanup(func() {
		if err := testClient.DeleteOrganizationScope(context.Background(), scopeID); err != nil {
			t.Logf("cleanup: failed to delete organization scope %s: %v", scopeID, err)
		}
	})

	// Create role with scope
	createdRole, err := testClient.CreateOrganizationRole(ctx,
		fmt.Sprintf("direct-scope-role-%d", time.Now().UnixNano()), "", "", []string{scopeID})
	require.NoError(t, err)
	roleID := createdRole.ID
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

// TestOrganizationApplications tests organization application operations (M2M apps in orgs)
func TestOrganizationApplications(t *testing.T) {
	ctx := context.Background()

	// Create organization
	createdOrg, err := testClient.CreateOrganization(ctx,
		fmt.Sprintf("App Test Org %d", time.Now().UnixNano()), "Organization for app testing")
	require.NoError(t, err)
	orgID := createdOrg.ID
	t.Cleanup(func() {
		if err := testClient.DeleteOrganization(context.Background(), orgID); err != nil {
			t.Logf("cleanup: failed to delete organization %s: %v", orgID, err)
		}
	})

	// Create M2M application (only M2M apps can be added to organizations)
	createdApp, err := testClient.CreateApplication(ctx, models.ApplicationCreate{
		Name:        fmt.Sprintf("Test M2M App %d", time.Now().UnixNano()),
		Description: "Test M2M application for org",
		Type:        models.ApplicationTypeMachineToMachine,
	})
	require.NoError(t, err, "CreateApplication should succeed")
	appID := createdApp.ID

	// Create M2M organization role (only M2M roles can be assigned to M2M apps)
	createdRole, err := testClient.CreateOrganizationRole(ctx,
		fmt.Sprintf("app-test-role-%d", time.Now().UnixNano()), "Role for M2M app", models.OrganizationRoleTypeMachineToMachine, nil)
	require.NoError(t, err)
	roleID := createdRole.ID
	t.Cleanup(func() {
		if err := testClient.DeleteOrganizationRole(context.Background(), roleID); err != nil {
			t.Logf("cleanup: failed to delete organization role %s: %v", roleID, err)
		}
	})

	// Add application to organization
	err = testClient.AddOrganizationApplications(ctx, orgID, []string{appID})
	require.NoError(t, err, "AddOrganizationApplications should succeed")

	// List organization applications
	apps, err := testClient.ListOrganizationApplications(ctx, orgID)
	require.NoError(t, err, "ListOrganizationApplications should succeed")
	assert.Len(t, apps, 1)
	assert.Equal(t, appID, apps[0].ID)

	// Assign roles to application
	err = testClient.AssignOrganizationApplicationRoles(ctx, orgID, appID, []string{roleID})
	require.NoError(t, err, "AssignOrganizationApplicationRoles should succeed")

	// Get application roles
	roles, err := testClient.GetOrganizationApplicationRoles(ctx, orgID, appID)
	require.NoError(t, err, "GetOrganizationApplicationRoles should succeed")
	assert.Len(t, roles, 1)
	assert.Equal(t, roleID, roles[0].ID)

	// Remove roles from application
	err = testClient.RemoveOrganizationApplicationRoles(ctx, orgID, appID, []string{roleID})
	require.NoError(t, err, "RemoveOrganizationApplicationRoles should succeed")

	// Verify roles removed
	roles, err = testClient.GetOrganizationApplicationRoles(ctx, orgID, appID)
	require.NoError(t, err)
	assert.Len(t, roles, 0)

	// Remove application from organization
	err = testClient.RemoveOrganizationApplication(ctx, orgID, appID)
	require.NoError(t, err, "RemoveOrganizationApplication should succeed")

	// Verify application removed
	apps, err = testClient.ListOrganizationApplications(ctx, orgID)
	require.NoError(t, err)
	assert.Len(t, apps, 0)
}

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
