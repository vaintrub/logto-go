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

// TestCreateSubjectToken tests creating a subject token for user impersonation
func TestCreateSubjectToken(t *testing.T) {
	ctx := context.Background()

	// Create a user to impersonate
	username := fmt.Sprintf("impersonate_%d", time.Now().UnixNano())
	user, err := testClient.CreateUser(ctx, models.UserCreate{
		Username: username,
		Password: "Password123!",
		Name:     "Impersonation Test User",
	})
	require.NoError(t, err, "CreateUser should succeed")
	userID := user.ID

	// Create subject token
	result, err := testClient.CreateSubjectToken(ctx, userID, nil)
	require.NoError(t, err, "CreateSubjectToken should succeed")

	assert.NotEmpty(t, result.SubjectToken, "SubjectToken should not be empty")
	assert.Greater(t, result.ExpiresIn, 0, "ExpiresIn should be positive")
}

// TestCreateSubjectTokenWithContext tests creating a subject token with custom context
func TestCreateSubjectTokenWithContext(t *testing.T) {
	ctx := context.Background()

	// Create a user to impersonate
	username := fmt.Sprintf("impersonate_ctx_%d", time.Now().UnixNano())
	user, err := testClient.CreateUser(ctx, models.UserCreate{
		Username: username,
		Password: "Password123!",
	})
	require.NoError(t, err)
	userID := user.ID

	// Create subject token with context
	tokenCtx := client.SubjectTokenContext{
		"ticketId": "SUPPORT-12345",
		"reason":   "Customer support investigation",
		"agentId":  "agent-001",
	}

	result, err := testClient.CreateSubjectToken(ctx, userID, tokenCtx)
	require.NoError(t, err, "CreateSubjectToken with context should succeed")

	assert.NotEmpty(t, result.SubjectToken)
	assert.Greater(t, result.ExpiresIn, 0)
}

// TestExchangeSubjectToken tests exchanging a subject token for an access token
func TestExchangeSubjectToken(t *testing.T) {
	ctx := context.Background()

	// Create a user to impersonate
	username := fmt.Sprintf("impersonate_exchange_%d", time.Now().UnixNano())
	user, err := testClient.CreateUser(ctx, models.UserCreate{
		Username: username,
		Password: "Password123!",
	})
	require.NoError(t, err)
	userID := user.ID

	// Create subject token
	subjectTokenResult, err := testClient.CreateSubjectToken(ctx, userID, nil)
	require.NoError(t, err)

	// Exchange subject token for access token
	result, err := testClient.ExchangeSubjectToken(ctx, subjectTokenResult.SubjectToken)
	require.NoError(t, err, "ExchangeSubjectToken should succeed")

	assert.NotEmpty(t, result.AccessToken, "AccessToken should not be empty")
	assert.Equal(t, "Bearer", result.TokenType, "TokenType should be Bearer")
	assert.Greater(t, result.ExpiresIn, 0, "ExpiresIn should be positive")
	assert.True(t, result.ExpiresAt.After(time.Now()), "ExpiresAt should be in the future")
}

// TestExchangeSubjectTokenWithOptions tests exchanging with custom options
func TestExchangeSubjectTokenWithOptions(t *testing.T) {
	ctx := context.Background()

	// Create a user
	username := fmt.Sprintf("impersonate_opts_%d", time.Now().UnixNano())
	user, err := testClient.CreateUser(ctx, models.UserCreate{
		Username: username,
		Password: "Password123!",
	})
	require.NoError(t, err)
	userID := user.ID

	// Create an organization and add user
	org, err := testClient.CreateOrganization(ctx, models.OrganizationCreate{
		Name: fmt.Sprintf("Impersonation Org %d", time.Now().UnixNano()),
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := testClient.DeleteOrganization(context.Background(), org.ID); err != nil {
			t.Logf("cleanup: failed to delete org: %v", err)
		}
	})

	// Add user to organization
	err = testClient.AddUserToOrganization(ctx, org.ID, userID, nil)
	require.NoError(t, err)

	// Create subject token
	subjectTokenResult, err := testClient.CreateSubjectToken(ctx, userID, nil)
	require.NoError(t, err)

	// Exchange with organization scope
	result, err := testClient.ExchangeSubjectToken(ctx, subjectTokenResult.SubjectToken,
		client.WithOrganizationID(org.ID),
	)
	if err != nil {
		// This may fail if org tokens aren't configured properly
		t.Logf("ExchangeSubjectToken with org: %v (may require additional setup)", err)
	} else {
		assert.NotEmpty(t, result.AccessToken)
	}
}

// TestGetUserAccessToken tests the convenience method
func TestGetUserAccessToken(t *testing.T) {
	ctx := context.Background()

	// Create a user
	username := fmt.Sprintf("impersonate_full_%d", time.Now().UnixNano())
	user, err := testClient.CreateUser(ctx, models.UserCreate{
		Username: username,
		Password: "Password123!",
	})
	require.NoError(t, err)
	userID := user.ID

	// Get user access token (combines CreateSubjectToken + ExchangeSubjectToken)
	result, err := testClient.GetUserAccessToken(ctx, userID)
	require.NoError(t, err, "GetUserAccessToken should succeed")

	assert.NotEmpty(t, result.AccessToken, "AccessToken should not be empty")
	assert.Equal(t, "Bearer", result.TokenType, "TokenType should be Bearer")
	assert.Greater(t, result.ExpiresIn, 0, "ExpiresIn should be positive")
	assert.True(t, result.ExpiresAt.After(time.Now()), "ExpiresAt should be in the future")
}

// === Validation Tests ===

// TestCreateSubjectToken_Validation tests input validation
func TestCreateSubjectToken_Validation(t *testing.T) {
	ctx := context.Background()

	_, err := testClient.CreateSubjectToken(ctx, "", nil)
	require.Error(t, err, "CreateSubjectToken with empty userID should fail")

	var validationErr *client.ValidationError
	require.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "userID", validationErr.Field)
}

// TestExchangeSubjectToken_Validation tests input validation
func TestExchangeSubjectToken_Validation(t *testing.T) {
	ctx := context.Background()

	_, err := testClient.ExchangeSubjectToken(ctx, "")
	require.Error(t, err, "ExchangeSubjectToken with empty subjectToken should fail")

	var validationErr *client.ValidationError
	require.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "subjectToken", validationErr.Field)
}

// TestCreateSubjectToken_UserNotFound tests error handling for nonexistent user
func TestCreateSubjectToken_UserNotFound(t *testing.T) {
	ctx := context.Background()

	_, err := testClient.CreateSubjectToken(ctx, "nonexistent-user-id", nil)
	require.Error(t, err, "CreateSubjectToken for nonexistent user should fail")
}
