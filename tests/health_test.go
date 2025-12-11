package tests

import (
	"context"
	"testing"

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
	token, expiresIn, err := testClient.AuthenticateM2M(ctx)
	require.NoError(t, err, "AuthenticateM2M should succeed")
	assert.NotEmpty(t, token, "Token should not be empty")
	assert.Greater(t, expiresIn, 0, "ExpiresIn should be positive")

	// Test token caching - second call should return same token
	token2, _, err := testClient.AuthenticateM2M(ctx)
	require.NoError(t, err)
	assert.Equal(t, token, token2, "Cached token should be returned")
}
