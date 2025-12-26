package tests

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vaintrub/logto-go/client"
)

// TestJWTCustomizerCRUD tests the full JWT customizer lifecycle
func TestJWTCustomizerCRUD(t *testing.T) {
	ctx := context.Background()

	// Test with access-token type
	t.Run("AccessToken", func(t *testing.T) {
		tokenType := client.TokenTypeAccessToken

		// Clean up any existing customizer first
		_ = testClient.DeleteJWTCustomizer(ctx, tokenType)

		// Initially should be nil/not found
		existing, err := testClient.GetJWTCustomizer(ctx, tokenType)
		if err == nil && existing != nil {
			// Clean it up first
			err = testClient.DeleteJWTCustomizer(ctx, tokenType)
			require.NoError(t, err)
		}

		// Create JWT customizer
		config := client.JWTCustomizerConfig{
			Script: `api.accessToken.payload.custom_claim = "test_value";`,
		}

		err = testClient.UpsertJWTCustomizer(ctx, tokenType, config)
		require.NoError(t, err, "UpsertJWTCustomizer should succeed")

		// Get and verify
		retrieved, err := testClient.GetJWTCustomizer(ctx, tokenType)
		require.NoError(t, err, "GetJWTCustomizer should succeed")
		require.NotNil(t, retrieved, "Retrieved config should not be nil")
		assert.Contains(t, retrieved.Script, "custom_claim", "Script should contain our claim")

		// Update
		config.Script = `api.accessToken.payload.updated_claim = "new_value";`
		err = testClient.UpsertJWTCustomizer(ctx, tokenType, config)
		require.NoError(t, err, "UpsertJWTCustomizer (update) should succeed")

		// Verify update
		retrieved, err = testClient.GetJWTCustomizer(ctx, tokenType)
		require.NoError(t, err)
		assert.Contains(t, retrieved.Script, "updated_claim")

		// Delete
		err = testClient.DeleteJWTCustomizer(ctx, tokenType)
		require.NoError(t, err, "DeleteJWTCustomizer should succeed")

		// Verify deletion
		retrieved, err = testClient.GetJWTCustomizer(ctx, tokenType)
		if err == nil {
			assert.Nil(t, retrieved, "After deletion, should return nil")
		}
		// It's also acceptable to get a 404/not found error
	})

	// Test with client-credentials type
	t.Run("ClientCredentials", func(t *testing.T) {
		tokenType := client.TokenTypeClientCredentials

		// Clean up any existing customizer first
		_ = testClient.DeleteJWTCustomizer(ctx, tokenType)

		// Create
		config := client.JWTCustomizerConfig{
			Script: `api.accessToken.payload.m2m_custom = "m2m_value";`,
		}

		err := testClient.UpsertJWTCustomizer(ctx, tokenType, config)
		require.NoError(t, err, "UpsertJWTCustomizer for client-credentials should succeed")

		// Get and verify
		retrieved, err := testClient.GetJWTCustomizer(ctx, tokenType)
		require.NoError(t, err)
		require.NotNil(t, retrieved)
		assert.Contains(t, retrieved.Script, "m2m_custom")

		// Cleanup
		err = testClient.DeleteJWTCustomizer(ctx, tokenType)
		require.NoError(t, err)
	})
}

// TestJWTCustomizerWithEnvVariables tests JWT customizer with environment variables
func TestJWTCustomizerWithEnvVariables(t *testing.T) {
	ctx := context.Background()
	tokenType := client.TokenTypeAccessToken

	// Clean up first
	_ = testClient.DeleteJWTCustomizer(ctx, tokenType)

	config := client.JWTCustomizerConfig{
		Script: `
			const apiKey = envVars.API_KEY || "default";
			api.accessToken.payload.api_key = apiKey;
		`,
		EnvironmentVariables: map[string]string{
			"API_KEY":     "test-api-key-12345",
			"FEATURE_FLAG": "enabled",
		},
	}

	err := testClient.UpsertJWTCustomizer(ctx, tokenType, config)
	require.NoError(t, err, "UpsertJWTCustomizer with env vars should succeed")

	// Verify
	retrieved, err := testClient.GetJWTCustomizer(ctx, tokenType)
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	assert.Contains(t, retrieved.Script, "envVars")

	// Check environment variables were stored
	if retrieved.EnvironmentVariables != nil {
		assert.Equal(t, "test-api-key-12345", retrieved.EnvironmentVariables["API_KEY"])
	}

	// Cleanup
	_ = testClient.DeleteJWTCustomizer(ctx, tokenType)
}

// === Validation Tests ===

// TestUpsertJWTCustomizer_Validation tests input validation
func TestUpsertJWTCustomizer_Validation(t *testing.T) {
	ctx := context.Background()

	// Invalid token type
	err := testClient.UpsertJWTCustomizer(ctx, "invalid-type", client.JWTCustomizerConfig{
		Script: "test",
	})
	require.Error(t, err, "UpsertJWTCustomizer with invalid token type should fail")

	// Empty token type
	err = testClient.UpsertJWTCustomizer(ctx, "", client.JWTCustomizerConfig{
		Script: "test",
	})
	require.Error(t, err, "UpsertJWTCustomizer with empty token type should fail")
}

// TestGetJWTCustomizer_Validation tests input validation
func TestGetJWTCustomizer_Validation(t *testing.T) {
	ctx := context.Background()

	// Invalid token type
	_, err := testClient.GetJWTCustomizer(ctx, "invalid-type")
	require.Error(t, err, "GetJWTCustomizer with invalid token type should fail")

	// Empty token type
	_, err = testClient.GetJWTCustomizer(ctx, "")
	require.Error(t, err, "GetJWTCustomizer with empty token type should fail")
}

// TestDeleteJWTCustomizer_Validation tests input validation
func TestDeleteJWTCustomizer_Validation(t *testing.T) {
	ctx := context.Background()

	// Invalid token type
	err := testClient.DeleteJWTCustomizer(ctx, "invalid-type")
	require.Error(t, err, "DeleteJWTCustomizer with invalid token type should fail")

	// Empty token type
	err = testClient.DeleteJWTCustomizer(ctx, "")
	require.Error(t, err, "DeleteJWTCustomizer with empty token type should fail")
}
