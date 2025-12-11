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

// TestOrganizationRoleCRUD tests organization role lifecycle
func TestOrganizationRoleCRUD(t *testing.T) {
	ctx := context.Background()
	roleName := fmt.Sprintf("Test Role %d", time.Now().UnixNano())

	// Create role
	createdRole, err := testClient.CreateOrganizationRole(ctx, models.OrganizationRoleCreate{
		Name:        roleName,
		Description: "Test role description",
	})
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
	updatedRoleDesc := "Updated description"
	_, err = testClient.UpdateOrganizationRole(ctx, roleID, models.OrganizationRoleUpdate{
		Name:        &newRoleName,
		Description: &updatedRoleDesc,
	})
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
	createdScope, err := testClient.CreateOrganizationScope(ctx, models.OrganizationScopeCreate{
		Name:        scopeName,
		Description: "Test scope",
	})
	require.NoError(t, err, "CreateOrganizationScope should succeed")
	assert.NotEmpty(t, createdScope.ID)
	scopeID := createdScope.ID

	// Get scope
	scope, err := testClient.GetOrganizationScope(ctx, scopeID)
	require.NoError(t, err, "GetOrganizationScope should succeed")
	assert.Equal(t, scopeID, scope.ID)
	assert.Equal(t, scopeName, scope.Name)

	// Update scope
	updatedScopeDesc := "Updated description"
	_, err = testClient.UpdateOrganizationScope(ctx, scopeID, models.OrganizationScopeUpdate{
		Description: &updatedScopeDesc,
	})
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
	createdScope, err := testClient.CreateOrganizationScope(ctx, models.OrganizationScopeCreate{
		Name: fmt.Sprintf("role:scope:%d", time.Now().UnixNano()),
	})
	require.NoError(t, err)
	scopeID := createdScope.ID
	t.Cleanup(func() {
		if err := testClient.DeleteOrganizationScope(context.Background(), scopeID); err != nil {
			t.Logf("cleanup: failed to delete organization scope %s: %v", scopeID, err)
		}
	})

	// Create role
	createdRole, err := testClient.CreateOrganizationRole(ctx, models.OrganizationRoleCreate{
		Name: fmt.Sprintf("scope-role-%d", time.Now().UnixNano()),
	})
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

// TestGetOrganizationRoleScopes tests getting scopes for a role directly
func TestGetOrganizationRoleScopes(t *testing.T) {
	ctx := context.Background()

	// Create scope
	createdScope, err := testClient.CreateOrganizationScope(ctx, models.OrganizationScopeCreate{
		Name:        fmt.Sprintf("direct:scope:%d", time.Now().UnixNano()),
		Description: "Direct scope test",
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
		Name:                 fmt.Sprintf("direct-scope-role-%d", time.Now().UnixNano()),
		OrganizationScopeIDs: []string{scopeID},
	})
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

// TestAssignResourceScopesToOrganizationRole tests assigning API resource scopes to org roles
func TestAssignResourceScopesToOrganizationRole(t *testing.T) {
	ctx := context.Background()

	// Create API resource with scope
	createdResource, err := testClient.CreateAPIResource(ctx, models.APIResourceCreate{
		Name:      fmt.Sprintf("Resource Scope Test %d", time.Now().UnixNano()),
		Indicator: fmt.Sprintf("https://api.resource-scope.test/%d", time.Now().UnixNano()),
	})
	require.NoError(t, err)
	resourceID := createdResource.ID
	t.Cleanup(func() {
		if err := testClient.DeleteAPIResource(context.Background(), resourceID); err != nil {
			t.Logf("cleanup: failed to delete API resource %s: %v", resourceID, err)
		}
	})

	createdScope, err := testClient.CreateAPIResourceScope(ctx, resourceID, models.APIResourceScopeCreate{
		Name:        fmt.Sprintf("read:%d", time.Now().UnixNano()),
		Description: "Read access",
	})
	require.NoError(t, err)
	scopeID := createdScope.ID

	// Create organization role
	createdRole, err := testClient.CreateOrganizationRole(ctx, models.OrganizationRoleCreate{
		Name: fmt.Sprintf("resource-scope-role-%d", time.Now().UnixNano()),
	})
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
