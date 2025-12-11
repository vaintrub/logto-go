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

// TestOrganizationCRUD tests organization lifecycle
func TestOrganizationCRUD(t *testing.T) {
	ctx := context.Background()
	orgName := fmt.Sprintf("Test Org %d", time.Now().UnixNano())

	// Create organization
	createdOrg, err := testClient.CreateOrganization(ctx, models.OrganizationCreate{
		Name:        orgName,
		Description: "Test description",
	})
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
	updatedDesc := "Updated description"
	updatedOrg, err := testClient.UpdateOrganization(ctx, orgID, models.OrganizationUpdate{
		Name:        &newName,
		Description: &updatedDesc,
	})
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

// TestValidationErrorsOrganizations tests that validation errors are properly returned for organization operations
func TestValidationErrorsOrganizations(t *testing.T) {
	ctx := context.Background()

	// Empty orgID should fail
	_, err := testClient.GetOrganization(ctx, "")
	assert.Error(t, err, "GetOrganization with empty ID should fail")

	// Empty name should fail
	_, err = testClient.CreateOrganization(ctx, models.OrganizationCreate{})
	assert.Error(t, err, "CreateOrganization with empty name should fail")
}
