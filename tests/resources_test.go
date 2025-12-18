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

// TestAPIResourceCRUD tests API resource lifecycle
func TestAPIResourceCRUD(t *testing.T) {
	ctx := context.Background()
	resourceName := fmt.Sprintf("Test API %d", time.Now().UnixNano())
	indicator := fmt.Sprintf("https://api.test.local/%d", time.Now().UnixNano())

	// Create resource
	createdResource, err := testClient.CreateAPIResource(ctx, models.APIResourceCreate{
		Name:      resourceName,
		Indicator: indicator,
	})
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
	_, err = testClient.UpdateAPIResource(ctx, resourceID, models.APIResourceUpdate{
		Name: &newName,
	})
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
	createdResource, err := testClient.CreateAPIResource(ctx, models.APIResourceCreate{
		Name:      fmt.Sprintf("Scope Test API %d", time.Now().UnixNano()),
		Indicator: fmt.Sprintf("https://api.scope.test/%d", time.Now().UnixNano()),
	})
	require.NoError(t, err)
	resourceID := createdResource.ID
	t.Cleanup(func() {
		if err := testClient.DeleteAPIResource(context.Background(), resourceID); err != nil {
			t.Logf("cleanup: failed to delete API resource %s: %v", resourceID, err)
		}
	})

	scopeName := fmt.Sprintf("read:%d", time.Now().UnixNano())

	// Create scope
	createdScope, err := testClient.CreateAPIResourceScope(ctx, resourceID, models.APIResourceScopeCreate{
		Name:        scopeName,
		Description: "Read access",
	})
	require.NoError(t, err, "CreateAPIResourceScope should succeed")
	assert.NotEmpty(t, createdScope.ID)
	scopeID := createdScope.ID

	// Get scope
	scope, err := testClient.GetAPIResourceScope(ctx, resourceID, scopeID)
	require.NoError(t, err, "GetAPIResourceScope should succeed")
	assert.Equal(t, scopeID, scope.ID)
	assert.Equal(t, scopeName, scope.Name)

	// Update scope
	updatedScopeDesc := "Updated description"
	_, err = testClient.UpdateAPIResourceScope(ctx, resourceID, scopeID, models.APIResourceScopeUpdate{
		Description: &updatedScopeDesc,
	})
	require.NoError(t, err, "UpdateAPIResourceScope should succeed")

	// List scopes
	scopes, err := testClient.ListAPIResourceScopes(ctx, resourceID)
	require.NoError(t, err, "ListAPIResourceScopes should succeed")
	assert.NotEmpty(t, scopes)

	// Delete scope
	err = testClient.DeleteAPIResourceScope(ctx, resourceID, scopeID)
	require.NoError(t, err, "DeleteAPIResourceScope should succeed")
}

// === Validation Tests ===

// TestGetAPIResource_Validation tests validation errors
func TestGetAPIResource_Validation(t *testing.T) {
	ctx := context.Background()

	_, err := testClient.GetAPIResource(ctx, "")
	require.Error(t, err, "GetAPIResource with empty resourceID should fail")
	var validationErr *client.ValidationError
	require.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "resourceID", validationErr.Field)
}

// TestUpdateAPIResource_Validation tests validation errors
func TestUpdateAPIResource_Validation(t *testing.T) {
	ctx := context.Background()

	name := "test"
	_, err := testClient.UpdateAPIResource(ctx, "", models.APIResourceUpdate{Name: &name})
	require.Error(t, err, "UpdateAPIResource with empty resourceID should fail")
	var validationErr *client.ValidationError
	require.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "resourceID", validationErr.Field)
}

// TestDeleteAPIResource_Validation tests validation errors
func TestDeleteAPIResource_Validation(t *testing.T) {
	ctx := context.Background()

	err := testClient.DeleteAPIResource(ctx, "")
	require.Error(t, err, "DeleteAPIResource with empty resourceID should fail")
	var validationErr *client.ValidationError
	require.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "resourceID", validationErr.Field)
}

// TestCreateAPIResource_Validation tests validation errors
func TestCreateAPIResource_Validation(t *testing.T) {
	ctx := context.Background()

	t.Run("empty name", func(t *testing.T) {
		_, err := testClient.CreateAPIResource(ctx, models.APIResourceCreate{
			Name:      "",
			Indicator: "https://api.test.com",
		})
		require.Error(t, err, "CreateAPIResource with empty name should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "name", validationErr.Field)
	})

	t.Run("empty indicator", func(t *testing.T) {
		_, err := testClient.CreateAPIResource(ctx, models.APIResourceCreate{
			Name:      "Test API",
			Indicator: "",
		})
		require.Error(t, err, "CreateAPIResource with empty indicator should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "indicator", validationErr.Field)
	})
}

// TestGetAPIResourceScope_Validation tests validation errors
func TestGetAPIResourceScope_Validation(t *testing.T) {
	ctx := context.Background()

	t.Run("empty resourceID", func(t *testing.T) {
		_, err := testClient.GetAPIResourceScope(ctx, "", "scope-123")
		require.Error(t, err, "GetAPIResourceScope with empty resourceID should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "resourceID", validationErr.Field)
	})

	t.Run("empty scopeID", func(t *testing.T) {
		_, err := testClient.GetAPIResourceScope(ctx, "resource-123", "")
		require.Error(t, err, "GetAPIResourceScope with empty scopeID should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "scopeID", validationErr.Field)
	})
}

// TestUpdateAPIResourceScope_Validation tests validation errors
func TestUpdateAPIResourceScope_Validation(t *testing.T) {
	ctx := context.Background()
	desc := "test"

	t.Run("empty resourceID", func(t *testing.T) {
		_, err := testClient.UpdateAPIResourceScope(ctx, "", "scope-123", models.APIResourceScopeUpdate{Description: &desc})
		require.Error(t, err, "UpdateAPIResourceScope with empty resourceID should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "resourceID", validationErr.Field)
	})

	t.Run("empty scopeID", func(t *testing.T) {
		_, err := testClient.UpdateAPIResourceScope(ctx, "resource-123", "", models.APIResourceScopeUpdate{Description: &desc})
		require.Error(t, err, "UpdateAPIResourceScope with empty scopeID should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "scopeID", validationErr.Field)
	})
}

// TestDeleteAPIResourceScope_Validation tests validation errors
func TestDeleteAPIResourceScope_Validation(t *testing.T) {
	ctx := context.Background()

	t.Run("empty resourceID", func(t *testing.T) {
		err := testClient.DeleteAPIResourceScope(ctx, "", "scope-123")
		require.Error(t, err, "DeleteAPIResourceScope with empty resourceID should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "resourceID", validationErr.Field)
	})

	t.Run("empty scopeID", func(t *testing.T) {
		err := testClient.DeleteAPIResourceScope(ctx, "resource-123", "")
		require.Error(t, err, "DeleteAPIResourceScope with empty scopeID should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "scopeID", validationErr.Field)
	})
}

// TestCreateAPIResourceScope_Validation tests validation errors
func TestCreateAPIResourceScope_Validation(t *testing.T) {
	ctx := context.Background()

	t.Run("empty resourceID", func(t *testing.T) {
		_, err := testClient.CreateAPIResourceScope(ctx, "", models.APIResourceScopeCreate{Name: "scope"})
		require.Error(t, err, "CreateAPIResourceScope with empty resourceID should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "resourceID", validationErr.Field)
	})

	t.Run("empty name", func(t *testing.T) {
		_, err := testClient.CreateAPIResourceScope(ctx, "resource-123", models.APIResourceScopeCreate{Name: ""})
		require.Error(t, err, "CreateAPIResourceScope with empty name should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "name", validationErr.Field)
	})
}

// TestListAPIResourceScopes_Validation tests validation errors
func TestListAPIResourceScopes_Validation(t *testing.T) {
	ctx := context.Background()

	_, err := testClient.ListAPIResourceScopes(ctx, "")
	require.Error(t, err, "ListAPIResourceScopes with empty resourceID should fail")
	var validationErr *client.ValidationError
	require.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "resourceID", validationErr.Field)
}
