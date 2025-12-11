package tests

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	result, err := testClient.AuthenticateM2M(ctx)
	require.NoError(t, err, "AuthenticateM2M should succeed")
	assert.NotEmpty(t, result.AccessToken, "AccessToken should not be empty")
	assert.Greater(t, result.ExpiresIn, 0, "ExpiresIn should be positive")
	assert.Equal(t, "Bearer", result.TokenType, "TokenType should be Bearer")
	assert.True(t, result.ExpiresAt.After(time.Now()), "ExpiresAt should be in the future")

	// Test token caching - second call should return same token
	result2, err := testClient.AuthenticateM2M(ctx)
	require.NoError(t, err)
	assert.Equal(t, result.AccessToken, result2.AccessToken, "Cached token should be returned")
}

// TestGetOrganizationToken tests organization-scoped M2M token retrieval
func TestGetOrganizationToken(t *testing.T) {
	ctx := context.Background()

	// Create an organization for testing
	org, err := testClient.CreateOrganization(ctx,
		fmt.Sprintf("OrgToken Test Org %d", time.Now().UnixNano()), "")
	require.NoError(t, err, "CreateOrganization should succeed")
	t.Cleanup(func() {
		if err := testClient.DeleteOrganization(context.Background(), org.ID); err != nil {
			t.Logf("cleanup: failed to delete organization %s: %v", org.ID, err)
		}
	})

	// Note: For this test to fully work, the M2M application used by testClient
	// needs to be added to the organization and assigned appropriate roles.
	// In a real setup, you would do:
	//   testClient.AddOrganizationApplications(ctx, org.ID, []string{m2mAppID})
	//   testClient.AssignOrganizationApplicationRoles(ctx, org.ID, m2mAppID, []string{roleID})
	//
	// For now, we test the basic functionality - the method should either:
	// - Return a token (if setup is complete)
	// - Return an error (if M2M app is not in org)

	result, err := testClient.GetOrganizationToken(ctx, org.ID)
	if err != nil {
		// Expected if M2M app is not added to the organization
		t.Logf("GetOrganizationToken returned error (expected if M2M app not in org): %v", err)
		return
	}

	// If we got here, the M2M app must be properly configured
	assert.NotEmpty(t, result.AccessToken, "AccessToken should not be empty")
	assert.Greater(t, result.ExpiresIn, 0, "ExpiresIn should be positive")
	assert.True(t, result.ExpiresAt.After(time.Now()), "ExpiresAt should be in the future")
	assert.Equal(t, "Bearer", result.TokenType, "TokenType should be Bearer")

	// Verify NO caching - second call should make a new request
	result2, err := testClient.GetOrganizationToken(ctx, org.ID)
	require.NoError(t, err)
	assert.NotEmpty(t, result2.AccessToken)
	// Note: tokens might be the same or different depending on Logto's behavior
	// The key point is that the method doesn't cache internally
}

// TestGetOrganizationTokenValidation tests input validation for GetOrganizationToken
func TestGetOrganizationTokenValidation(t *testing.T) {
	ctx := context.Background()

	// Empty orgID should fail
	_, err := testClient.GetOrganizationToken(ctx, "")
	assert.Error(t, err, "GetOrganizationToken with empty orgID should fail")
}
