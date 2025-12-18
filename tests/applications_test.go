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

// TestOrganizationApplications tests organization application operations (M2M apps in orgs)
func TestOrganizationApplications(t *testing.T) {
	ctx := context.Background()

	// Create organization
	createdOrg, err := testClient.CreateOrganization(ctx, models.OrganizationCreate{
		Name:        fmt.Sprintf("App Test Org %d", time.Now().UnixNano()),
		Description: "Organization for app testing",
	})
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
	createdRole, err := testClient.CreateOrganizationRole(ctx, models.OrganizationRoleCreate{
		Name:        fmt.Sprintf("app-test-role-%d", time.Now().UnixNano()),
		Description: "Role for M2M app",
		Type:        models.OrganizationRoleTypeMachineToMachine,
	})
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
	err = testClient.RemoveRolesFromOrganizationApplication(ctx, orgID, appID, []string{roleID})
	require.NoError(t, err, "RemoveRolesFromOrganizationApplication should succeed")

	// Verify roles removed
	roles, err = testClient.GetOrganizationApplicationRoles(ctx, orgID, appID)
	require.NoError(t, err)
	assert.Len(t, roles, 0)

	// Remove application from organization
	err = testClient.RemoveApplicationFromOrganization(ctx, orgID, appID)
	require.NoError(t, err, "RemoveApplicationFromOrganization should succeed")

	// Verify application removed
	apps, err = testClient.ListOrganizationApplications(ctx, orgID)
	require.NoError(t, err)
	assert.Len(t, apps, 0)
}

// === Validation Tests ===

// TestListOrganizationApplications_Validation tests validation errors
func TestListOrganizationApplications_Validation(t *testing.T) {
	ctx := context.Background()

	_, err := testClient.ListOrganizationApplications(ctx, "")
	require.Error(t, err, "ListOrganizationApplications with empty orgID should fail")
	var validationErr *client.ValidationError
	require.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "orgID", validationErr.Field)
}

// TestAddOrganizationApplications_Validation tests validation errors
func TestAddOrganizationApplications_Validation(t *testing.T) {
	ctx := context.Background()

	t.Run("empty orgID", func(t *testing.T) {
		err := testClient.AddOrganizationApplications(ctx, "", []string{"app-1"})
		require.Error(t, err, "AddOrganizationApplications with empty orgID should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "orgID", validationErr.Field)
	})

	t.Run("empty applicationIDs", func(t *testing.T) {
		err := testClient.AddOrganizationApplications(ctx, "org-123", []string{})
		require.Error(t, err, "AddOrganizationApplications with empty applicationIDs should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "applicationIDs", validationErr.Field)
	})
}

// TestRemoveApplicationFromOrganization_Validation tests validation errors
func TestRemoveApplicationFromOrganization_Validation(t *testing.T) {
	ctx := context.Background()

	t.Run("empty orgID", func(t *testing.T) {
		err := testClient.RemoveApplicationFromOrganization(ctx, "", "app-123")
		require.Error(t, err, "RemoveApplicationFromOrganization with empty orgID should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "orgID", validationErr.Field)
	})

	t.Run("empty applicationID", func(t *testing.T) {
		err := testClient.RemoveApplicationFromOrganization(ctx, "org-123", "")
		require.Error(t, err, "RemoveApplicationFromOrganization with empty applicationID should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "applicationID", validationErr.Field)
	})
}

// TestGetOrganizationApplicationRoles_Validation tests validation errors
func TestGetOrganizationApplicationRoles_Validation(t *testing.T) {
	ctx := context.Background()

	t.Run("empty orgID", func(t *testing.T) {
		_, err := testClient.GetOrganizationApplicationRoles(ctx, "", "app-123")
		require.Error(t, err, "GetOrganizationApplicationRoles with empty orgID should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "orgID", validationErr.Field)
	})

	t.Run("empty applicationID", func(t *testing.T) {
		_, err := testClient.GetOrganizationApplicationRoles(ctx, "org-123", "")
		require.Error(t, err, "GetOrganizationApplicationRoles with empty applicationID should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "applicationID", validationErr.Field)
	})
}

// TestAssignOrganizationApplicationRoles_Validation tests validation errors
func TestAssignOrganizationApplicationRoles_Validation(t *testing.T) {
	ctx := context.Background()

	t.Run("empty orgID", func(t *testing.T) {
		err := testClient.AssignOrganizationApplicationRoles(ctx, "", "app-123", []string{"role-1"})
		require.Error(t, err, "AssignOrganizationApplicationRoles with empty orgID should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "orgID", validationErr.Field)
	})

	t.Run("empty applicationID", func(t *testing.T) {
		err := testClient.AssignOrganizationApplicationRoles(ctx, "org-123", "", []string{"role-1"})
		require.Error(t, err, "AssignOrganizationApplicationRoles with empty applicationID should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "applicationID", validationErr.Field)
	})

	t.Run("empty roleIDs", func(t *testing.T) {
		err := testClient.AssignOrganizationApplicationRoles(ctx, "org-123", "app-123", []string{})
		require.Error(t, err, "AssignOrganizationApplicationRoles with empty roleIDs should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "roleIDs", validationErr.Field)
	})
}

// TestRemoveRolesFromOrganizationApplication_Validation tests validation errors
func TestRemoveRolesFromOrganizationApplication_Validation(t *testing.T) {
	ctx := context.Background()

	t.Run("empty orgID", func(t *testing.T) {
		err := testClient.RemoveRolesFromOrganizationApplication(ctx, "", "app-123", []string{"role-1"})
		require.Error(t, err, "RemoveRolesFromOrganizationApplication with empty orgID should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "orgID", validationErr.Field)
	})

	t.Run("empty applicationID", func(t *testing.T) {
		err := testClient.RemoveRolesFromOrganizationApplication(ctx, "org-123", "", []string{"role-1"})
		require.Error(t, err, "RemoveRolesFromOrganizationApplication with empty applicationID should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "applicationID", validationErr.Field)
	})

	t.Run("empty roleIDs", func(t *testing.T) {
		err := testClient.RemoveRolesFromOrganizationApplication(ctx, "org-123", "app-123", []string{})
		require.Error(t, err, "RemoveRolesFromOrganizationApplication with empty roleIDs should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "roleIDs", validationErr.Field)
	})
}

// TestCreateApplication_Validation tests validation errors
func TestCreateApplication_Validation(t *testing.T) {
	ctx := context.Background()

	t.Run("empty name", func(t *testing.T) {
		_, err := testClient.CreateApplication(ctx, models.ApplicationCreate{
			Name: "",
			Type: models.ApplicationTypeSPA,
		})
		require.Error(t, err, "CreateApplication with empty name should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "name", validationErr.Field)
	})

	t.Run("empty type", func(t *testing.T) {
		_, err := testClient.CreateApplication(ctx, models.ApplicationCreate{
			Name: "Test App",
			Type: "",
		})
		require.Error(t, err, "CreateApplication with empty type should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "type", validationErr.Field)
	})
}
