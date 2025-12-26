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

const (
	paginationTestPageSize  = 2
	paginationTestItemCount = 5
	paginationTestTimeout   = 2 * time.Minute
)

// countFoundIDs counts how many IDs from createdIDs are present in allIDs
func countFoundIDs(createdIDs, allIDs []string) int {
	allSet := make(map[string]bool)
	for _, id := range allIDs {
		allSet[id] = true
	}
	count := 0
	for _, id := range createdIDs {
		if allSet[id] {
			count++
		}
	}
	return count
}

// ============================================================================
// Simple pagination tests (no dependencies)
// ============================================================================

func TestPagination_ListUsers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), paginationTestTimeout)
	defer cancel()
	ts := time.Now().UnixNano()

	// Create 5 users
	var createdIDs []string
	for i := 0; i < paginationTestItemCount; i++ {
		user, err := testClient.CreateUser(ctx, models.UserCreate{
			Username: fmt.Sprintf("paguser_%d_%d", ts, i),
			Password: "Password123!",
		})
		require.NoError(t, err, "CreateUser should succeed")
		createdIDs = append(createdIDs, user.ID)
	}
	// Note: Users are intentionally not deleted to avoid breaking other tests
	// that may reference them. Logto handles user cleanup separately.

	// Collect all via iterator with small page size
	iter := testClient.ListUsers(client.IteratorConfig{PageSize: paginationTestPageSize})
	allUsers, err := iter.Collect(ctx)
	require.NoError(t, err, "ListUsers should succeed")

	// Extract IDs
	var allIDs []string
	for _, u := range allUsers {
		allIDs = append(allIDs, u.ID)
	}

	// Verify all created users are found
	foundCount := countFoundIDs(createdIDs, allIDs)
	assert.Equal(t, paginationTestItemCount, foundCount,
		"All %d created users should be found through pagination", paginationTestItemCount)

	// Verify pagination actually happened (we should have more items than page size)
	assert.GreaterOrEqual(t, len(allUsers), paginationTestItemCount,
		"Should have at least %d users total", paginationTestItemCount)
}

func TestPagination_ListOrganizations(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), paginationTestTimeout)
	defer cancel()
	ts := time.Now().UnixNano()

	// Create 5 organizations
	var createdIDs []string
	for i := 0; i < paginationTestItemCount; i++ {
		org, err := testClient.CreateOrganization(ctx, models.OrganizationCreate{
			Name: fmt.Sprintf("pagorg_%d_%d", ts, i),
		})
		require.NoError(t, err, "CreateOrganization should succeed")
		createdIDs = append(createdIDs, org.ID)
	}
	t.Cleanup(func() {
		for _, id := range createdIDs {
			if err := testClient.DeleteOrganization(context.Background(), id); err != nil {
				t.Logf("cleanup: failed to delete organization %s: %v", id, err)
			}
		}
	})

	// Collect via iterator
	iter := testClient.ListOrganizations(client.IteratorConfig{PageSize: paginationTestPageSize})
	allOrgs, err := iter.Collect(ctx)
	require.NoError(t, err, "ListOrganizations should succeed")

	// Extract IDs
	var allIDs []string
	for _, o := range allOrgs {
		allIDs = append(allIDs, o.ID)
	}

	// Verify all created orgs are found
	foundCount := countFoundIDs(createdIDs, allIDs)
	assert.Equal(t, paginationTestItemCount, foundCount,
		"All %d created organizations should be found through pagination", paginationTestItemCount)
}

func TestPagination_ListRoles(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), paginationTestTimeout)
	defer cancel()
	ts := time.Now().UnixNano()

	// Create 5 global roles
	var createdIDs []string
	for i := 0; i < paginationTestItemCount; i++ {
		role, err := testClient.CreateRole(ctx, models.RoleCreate{
			Name:        fmt.Sprintf("pagrole_%d_%d", ts, i),
			Description: "Pagination test role",
			Type:        models.RoleTypeUser,
		})
		require.NoError(t, err, "CreateRole should succeed")
		createdIDs = append(createdIDs, role.ID)
	}
	t.Cleanup(func() {
		for _, id := range createdIDs {
			if err := testClient.DeleteRole(context.Background(), id); err != nil {
				t.Logf("cleanup: failed to delete role %s: %v", id, err)
			}
		}
	})

	// Collect via iterator
	iter := testClient.ListRoles(client.IteratorConfig{PageSize: paginationTestPageSize})
	allRoles, err := iter.Collect(ctx)
	require.NoError(t, err, "ListRoles should succeed")

	// Extract IDs
	var allIDs []string
	for _, r := range allRoles {
		allIDs = append(allIDs, r.ID)
	}

	// Verify
	foundCount := countFoundIDs(createdIDs, allIDs)
	assert.Equal(t, paginationTestItemCount, foundCount,
		"All %d created roles should be found through pagination", paginationTestItemCount)
}

func TestPagination_ListOrganizationRoles(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), paginationTestTimeout)
	defer cancel()
	ts := time.Now().UnixNano()

	// Create 5 organization roles
	var createdIDs []string
	for i := 0; i < paginationTestItemCount; i++ {
		role, err := testClient.CreateOrganizationRole(ctx, models.OrganizationRoleCreate{
			Name:        fmt.Sprintf("pagorgrole_%d_%d", ts, i),
			Description: "Pagination test org role",
		})
		require.NoError(t, err, "CreateOrganizationRole should succeed")
		createdIDs = append(createdIDs, role.ID)
	}
	t.Cleanup(func() {
		for _, id := range createdIDs {
			if err := testClient.DeleteOrganizationRole(context.Background(), id); err != nil {
				t.Logf("cleanup: failed to delete organization role %s: %v", id, err)
			}
		}
	})

	// Collect via iterator
	iter := testClient.ListOrganizationRoles(client.IteratorConfig{PageSize: paginationTestPageSize})
	allRoles, err := iter.Collect(ctx)
	require.NoError(t, err, "ListOrganizationRoles should succeed")

	// Extract IDs
	var allIDs []string
	for _, r := range allRoles {
		allIDs = append(allIDs, r.ID)
	}

	// Verify
	foundCount := countFoundIDs(createdIDs, allIDs)
	assert.Equal(t, paginationTestItemCount, foundCount,
		"All %d created organization roles should be found through pagination", paginationTestItemCount)
}

func TestPagination_ListOrganizationScopes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), paginationTestTimeout)
	defer cancel()
	ts := time.Now().UnixNano()

	// Create 5 organization scopes
	var createdIDs []string
	for i := 0; i < paginationTestItemCount; i++ {
		scope, err := testClient.CreateOrganizationScope(ctx, models.OrganizationScopeCreate{
			Name:        fmt.Sprintf("pagorgscope_%d_%d", ts, i),
			Description: "Pagination test org scope",
		})
		require.NoError(t, err, "CreateOrganizationScope should succeed")
		createdIDs = append(createdIDs, scope.ID)
	}
	t.Cleanup(func() {
		for _, id := range createdIDs {
			if err := testClient.DeleteOrganizationScope(context.Background(), id); err != nil {
				t.Logf("cleanup: failed to delete organization scope %s: %v", id, err)
			}
		}
	})

	// Collect via iterator
	iter := testClient.ListOrganizationScopes(client.IteratorConfig{PageSize: paginationTestPageSize})
	allScopes, err := iter.Collect(ctx)
	require.NoError(t, err, "ListOrganizationScopes should succeed")

	// Extract IDs
	var allIDs []string
	for _, s := range allScopes {
		allIDs = append(allIDs, s.ID)
	}

	// Verify
	foundCount := countFoundIDs(createdIDs, allIDs)
	assert.Equal(t, paginationTestItemCount, foundCount,
		"All %d created organization scopes should be found through pagination", paginationTestItemCount)
}

func TestPagination_ListAPIResources(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), paginationTestTimeout)
	defer cancel()
	ts := time.Now().UnixNano()

	// Create 5 API resources
	var createdIDs []string
	for i := 0; i < paginationTestItemCount; i++ {
		resource, err := testClient.CreateAPIResource(ctx, models.APIResourceCreate{
			Name:      fmt.Sprintf("pagresource_%d_%d", ts, i),
			Indicator: fmt.Sprintf("https://api.pagination.test/%d/%d", ts, i),
		})
		require.NoError(t, err, "CreateAPIResource should succeed")
		createdIDs = append(createdIDs, resource.ID)
	}
	t.Cleanup(func() {
		for _, id := range createdIDs {
			if err := testClient.DeleteAPIResource(context.Background(), id); err != nil {
				t.Logf("cleanup: failed to delete API resource %s: %v", id, err)
			}
		}
	})

	// Collect via iterator
	iter := testClient.ListAPIResources(client.IteratorConfig{PageSize: paginationTestPageSize})
	allResources, err := iter.Collect(ctx)
	require.NoError(t, err, "ListAPIResources should succeed")

	// Extract IDs
	var allIDs []string
	for _, r := range allResources {
		allIDs = append(allIDs, r.ID)
	}

	// Verify
	foundCount := countFoundIDs(createdIDs, allIDs)
	assert.Equal(t, paginationTestItemCount, foundCount,
		"All %d created API resources should be found through pagination", paginationTestItemCount)
}

func TestPagination_ListApplications(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), paginationTestTimeout)
	defer cancel()
	ts := time.Now().UnixNano()

	// Create 5 M2M applications
	// Note: Logto API does not support deleting applications, so we just create them
	var createdIDs []string
	for i := 0; i < paginationTestItemCount; i++ {
		app, err := testClient.CreateApplication(ctx, models.ApplicationCreate{
			Name:        fmt.Sprintf("pagapp_%d_%d", ts, i),
			Description: "Pagination test app",
			Type:        models.ApplicationTypeMachineToMachine,
		})
		require.NoError(t, err, "CreateApplication should succeed")
		createdIDs = append(createdIDs, app.ID)
	}

	// Collect via iterator
	iter := testClient.ListApplications(client.IteratorConfig{PageSize: paginationTestPageSize})
	allApps, err := iter.Collect(ctx)
	require.NoError(t, err, "ListApplications should succeed")

	// Extract IDs
	var allIDs []string
	for _, a := range allApps {
		allIDs = append(allIDs, a.ID)
	}

	// Verify
	foundCount := countFoundIDs(createdIDs, allIDs)
	assert.Equal(t, paginationTestItemCount, foundCount,
		"All %d created applications should be found through pagination", paginationTestItemCount)
}

// ============================================================================
// Medium pagination tests (one dependency)
// ============================================================================

func TestPagination_ListOrganizationMembers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), paginationTestTimeout)
	defer cancel()
	ts := time.Now().UnixNano()

	// Create organization
	org, err := testClient.CreateOrganization(ctx, models.OrganizationCreate{
		Name: fmt.Sprintf("pagmembers_org_%d", ts),
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := testClient.DeleteOrganization(context.Background(), org.ID); err != nil {
			t.Logf("cleanup: failed to delete organization %s: %v", org.ID, err)
		}
	})

	// Create and add 5 users to organization
	// Note: Users are not deleted in cleanup to avoid breaking other tests
	var createdUserIDs []string
	for i := 0; i < paginationTestItemCount; i++ {
		user, err := testClient.CreateUser(ctx, models.UserCreate{
			Username: fmt.Sprintf("pagmember_%d_%d", ts, i),
			Password: "Password123!",
		})
		require.NoError(t, err)
		createdUserIDs = append(createdUserIDs, user.ID)

		err = testClient.AddUserToOrganization(ctx, org.ID, user.ID, nil)
		require.NoError(t, err)
	}

	// Collect via iterator
	iter := testClient.ListOrganizationMembers(org.ID, client.IteratorConfig{PageSize: paginationTestPageSize})
	members, err := iter.Collect(ctx)
	require.NoError(t, err, "ListOrganizationMembers should succeed")

	// Extract user IDs from members
	var memberUserIDs []string
	for _, m := range members {
		memberUserIDs = append(memberUserIDs, m.User.ID)
	}

	// Verify
	foundCount := countFoundIDs(createdUserIDs, memberUserIDs)
	assert.Equal(t, paginationTestItemCount, foundCount,
		"All %d created members should be found through pagination", paginationTestItemCount)
}

func TestPagination_ListAPIResourceScopes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), paginationTestTimeout)
	defer cancel()
	ts := time.Now().UnixNano()

	// Create API resource
	resource, err := testClient.CreateAPIResource(ctx, models.APIResourceCreate{
		Name:      fmt.Sprintf("pagscopes_resource_%d", ts),
		Indicator: fmt.Sprintf("https://api.pagscopes.test/%d", ts),
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := testClient.DeleteAPIResource(context.Background(), resource.ID); err != nil {
			t.Logf("cleanup: failed to delete API resource %s: %v", resource.ID, err)
		}
	})

	// Create 5 scopes for the resource
	var createdIDs []string
	for i := 0; i < paginationTestItemCount; i++ {
		scope, err := testClient.CreateAPIResourceScope(ctx, resource.ID, models.APIResourceScopeCreate{
			Name:        fmt.Sprintf("pagscope_%d_%d", ts, i),
			Description: "Pagination test scope",
		})
		require.NoError(t, err, "CreateAPIResourceScope should succeed")
		createdIDs = append(createdIDs, scope.ID)
	}

	// Collect via iterator
	iter := testClient.ListAPIResourceScopes(resource.ID, client.IteratorConfig{PageSize: paginationTestPageSize})
	allScopes, err := iter.Collect(ctx)
	require.NoError(t, err, "ListAPIResourceScopes should succeed")

	// Extract IDs
	var allIDs []string
	for _, s := range allScopes {
		allIDs = append(allIDs, s.ID)
	}

	// Verify
	foundCount := countFoundIDs(createdIDs, allIDs)
	assert.Equal(t, paginationTestItemCount, foundCount,
		"All %d created API resource scopes should be found through pagination", paginationTestItemCount)
}

func TestPagination_ListOrganizationApplications(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), paginationTestTimeout)
	defer cancel()
	ts := time.Now().UnixNano()

	// Create organization
	org, err := testClient.CreateOrganization(ctx, models.OrganizationCreate{
		Name: fmt.Sprintf("pagorgapps_org_%d", ts),
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := testClient.DeleteOrganization(context.Background(), org.ID); err != nil {
			t.Logf("cleanup: failed to delete organization %s: %v", org.ID, err)
		}
	})

	// Create 5 M2M applications and add to organization
	var createdAppIDs []string
	for i := 0; i < paginationTestItemCount; i++ {
		app, err := testClient.CreateApplication(ctx, models.ApplicationCreate{
			Name:        fmt.Sprintf("pagorgapp_%d_%d", ts, i),
			Description: "Pagination test org app",
			Type:        models.ApplicationTypeMachineToMachine,
		})
		require.NoError(t, err)
		createdAppIDs = append(createdAppIDs, app.ID)
	}

	// Add all apps to organization
	err = testClient.AddOrganizationApplications(ctx, org.ID, createdAppIDs)
	require.NoError(t, err, "AddOrganizationApplications should succeed")

	// Collect via iterator
	iter := testClient.ListOrganizationApplications(org.ID, client.IteratorConfig{PageSize: paginationTestPageSize})
	allApps, err := iter.Collect(ctx)
	require.NoError(t, err, "ListOrganizationApplications should succeed")

	// Extract IDs
	var allIDs []string
	for _, a := range allApps {
		allIDs = append(allIDs, a.ID)
	}

	// Verify
	foundCount := countFoundIDs(createdAppIDs, allIDs)
	assert.Equal(t, paginationTestItemCount, foundCount,
		"All %d organization applications should be found through pagination", paginationTestItemCount)
}

// ============================================================================
// Complex pagination tests (multiple dependencies)
// ============================================================================

func TestPagination_ListRoleScopes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), paginationTestTimeout)
	defer cancel()
	ts := time.Now().UnixNano()

	// Create API resource
	resource, err := testClient.CreateAPIResource(ctx, models.APIResourceCreate{
		Name:      fmt.Sprintf("pagrolescopes_resource_%d", ts),
		Indicator: fmt.Sprintf("https://api.pagrolescopes.test/%d", ts),
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := testClient.DeleteAPIResource(context.Background(), resource.ID); err != nil {
			t.Logf("cleanup: failed to delete API resource %s: %v", resource.ID, err)
		}
	})

	// Create 5 scopes
	var scopeIDs []string
	for i := 0; i < paginationTestItemCount; i++ {
		scope, err := testClient.CreateAPIResourceScope(ctx, resource.ID, models.APIResourceScopeCreate{
			Name:        fmt.Sprintf("pagrolescope_%d_%d", ts, i),
			Description: "Pagination test role scope",
		})
		require.NoError(t, err)
		scopeIDs = append(scopeIDs, scope.ID)
	}

	// Create role and assign all scopes
	role, err := testClient.CreateRole(ctx, models.RoleCreate{
		Name:        fmt.Sprintf("pagrolescopes_role_%d", ts),
		Description: "Role for pagination test",
		Type:        models.RoleTypeUser,
		ScopeIDs:    scopeIDs,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := testClient.DeleteRole(context.Background(), role.ID); err != nil {
			t.Logf("cleanup: failed to delete role %s: %v", role.ID, err)
		}
	})

	// Collect via iterator
	iter := testClient.ListRoleScopes(role.ID, client.IteratorConfig{PageSize: paginationTestPageSize})
	allScopes, err := iter.Collect(ctx)
	require.NoError(t, err, "ListRoleScopes should succeed")

	// Extract IDs
	var allIDs []string
	for _, s := range allScopes {
		allIDs = append(allIDs, s.ID)
	}

	// Verify
	foundCount := countFoundIDs(scopeIDs, allIDs)
	assert.Equal(t, paginationTestItemCount, foundCount,
		"All %d role scopes should be found through pagination", paginationTestItemCount)
}

func TestPagination_ListRoleUsers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), paginationTestTimeout)
	defer cancel()
	ts := time.Now().UnixNano()

	// Create role
	role, err := testClient.CreateRole(ctx, models.RoleCreate{
		Name:        fmt.Sprintf("pagroleusers_role_%d", ts),
		Description: "Role for pagination test",
		Type:        models.RoleTypeUser,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := testClient.DeleteRole(context.Background(), role.ID); err != nil {
			t.Logf("cleanup: failed to delete role %s: %v", role.ID, err)
		}
	})

	// Create 5 users
	var userIDs []string
	for i := 0; i < paginationTestItemCount; i++ {
		user, err := testClient.CreateUser(ctx, models.UserCreate{
			Username: fmt.Sprintf("pagroleuser_%d_%d", ts, i),
			Password: "Password123!",
		})
		require.NoError(t, err)
		userIDs = append(userIDs, user.ID)
	}

	// Assign role to all users
	err = testClient.AssignRoleToUsers(ctx, role.ID, userIDs)
	require.NoError(t, err, "AssignRoleToUsers should succeed")

	// Collect via iterator
	iter := testClient.ListRoleUsers(role.ID, client.IteratorConfig{PageSize: paginationTestPageSize})
	allUsers, err := iter.Collect(ctx)
	require.NoError(t, err, "ListRoleUsers should succeed")

	// Extract IDs
	var allIDs []string
	for _, u := range allUsers {
		allIDs = append(allIDs, u.ID)
	}

	// Verify
	foundCount := countFoundIDs(userIDs, allIDs)
	assert.Equal(t, paginationTestItemCount, foundCount,
		"All %d role users should be found through pagination", paginationTestItemCount)
}

func TestPagination_ListRoleApplications(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), paginationTestTimeout)
	defer cancel()
	ts := time.Now().UnixNano()

	// Create M2M role (required for assigning to M2M apps)
	role, err := testClient.CreateRole(ctx, models.RoleCreate{
		Name:        fmt.Sprintf("pagroleapps_role_%d", ts),
		Description: "M2M Role for pagination test",
		Type:        models.RoleTypeMachineToMachine,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := testClient.DeleteRole(context.Background(), role.ID); err != nil {
			t.Logf("cleanup: failed to delete role %s: %v", role.ID, err)
		}
	})

	// Create 5 M2M applications
	var appIDs []string
	for i := 0; i < paginationTestItemCount; i++ {
		app, err := testClient.CreateApplication(ctx, models.ApplicationCreate{
			Name:        fmt.Sprintf("pagroleapp_%d_%d", ts, i),
			Description: "Pagination test role app",
			Type:        models.ApplicationTypeMachineToMachine,
		})
		require.NoError(t, err)
		appIDs = append(appIDs, app.ID)
	}

	// Assign role to all applications
	err = testClient.AssignRoleToApplications(ctx, role.ID, appIDs)
	require.NoError(t, err, "AssignRoleToApplications should succeed")

	// Collect via iterator
	iter := testClient.ListRoleApplications(role.ID, client.IteratorConfig{PageSize: paginationTestPageSize})
	allApps, err := iter.Collect(ctx)
	require.NoError(t, err, "ListRoleApplications should succeed")

	// Extract IDs
	var allIDs []string
	for _, a := range allApps {
		allIDs = append(allIDs, a.ID)
	}

	// Verify
	foundCount := countFoundIDs(appIDs, allIDs)
	assert.Equal(t, paginationTestItemCount, foundCount,
		"All %d role applications should be found through pagination", paginationTestItemCount)
}
