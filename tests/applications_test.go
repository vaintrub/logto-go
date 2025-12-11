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
