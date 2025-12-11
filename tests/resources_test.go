package tests

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
