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
	require.Error(t, err, "GetOrganization with empty ID should fail")
	var validationErr *client.ValidationError
	require.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "orgID", validationErr.Field)

	// Empty name should fail
	_, err = testClient.CreateOrganization(ctx, models.OrganizationCreate{})
	require.Error(t, err, "CreateOrganization with empty name should fail")
	require.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "name", validationErr.Field)
}

// TestUpdateOrganization_Validation tests validation errors for UpdateOrganization
func TestUpdateOrganization_Validation(t *testing.T) {
	ctx := context.Background()

	name := "test"
	_, err := testClient.UpdateOrganization(ctx, "", models.OrganizationUpdate{Name: &name})
	require.Error(t, err, "UpdateOrganization with empty orgID should fail")
	var validationErr *client.ValidationError
	require.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "orgID", validationErr.Field)
}

// TestDeleteOrganization_Validation tests validation errors for DeleteOrganization
func TestDeleteOrganization_Validation(t *testing.T) {
	ctx := context.Background()

	err := testClient.DeleteOrganization(ctx, "")
	require.Error(t, err, "DeleteOrganization with empty orgID should fail")
	var validationErr *client.ValidationError
	require.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "orgID", validationErr.Field)
}

// TestListUserOrganizations_Validation tests validation errors for ListUserOrganizations
func TestListUserOrganizations_Validation(t *testing.T) {
	ctx := context.Background()

	_, err := testClient.ListUserOrganizations(ctx, "")
	require.Error(t, err, "ListUserOrganizations with empty userID should fail")
	var validationErr *client.ValidationError
	require.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "userID", validationErr.Field)
}

// TestListOrganizations_Empty tests that ListOrganizations returns empty list when no orgs match
func TestListOrganizations_Success(t *testing.T) {
	ctx := context.Background()

	// This test just verifies the method works
	orgs, err := testClient.ListOrganizations(ctx)
	require.NoError(t, err, "ListOrganizations should succeed")
	// orgs may be empty or non-empty depending on test state
	_ = orgs
}

// TestOrganizationsIter_Success tests organization iterator
func TestOrganizationsIter_Success(t *testing.T) {
	ctx := context.Background()

	// Create a test org to ensure we have at least one
	createdOrg, err := testClient.CreateOrganization(ctx, models.OrganizationCreate{
		Name: fmt.Sprintf("Iter Test Org %d", time.Now().UnixNano()),
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := testClient.DeleteOrganization(context.Background(), createdOrg.ID); err != nil {
			t.Logf("cleanup: failed to delete org %s: %v", createdOrg.ID, err)
		}
	})

	iter := testClient.ListOrganizationsIter(ctx, 10)
	count := 0
	for iter.Next() {
		org := iter.Organization()
		assert.NotEmpty(t, org.ID)
		count++
		if count >= 3 {
			break
		}
	}
	assert.NoError(t, iter.Err())
	assert.GreaterOrEqual(t, count, 1, "Should have at least one organization")
}
