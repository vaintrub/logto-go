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

// TestOneTimeToken tests one-time token creation
func TestOneTimeToken(t *testing.T) {
	ctx := context.Background()
	email := fmt.Sprintf("ott-%d@test.local", time.Now().UnixNano())

	result, err := testClient.CreateOneTimeToken(ctx, models.OneTimeTokenCreate{
		Email:     email,
		ExpiresIn: 600,
	})
	require.NoError(t, err, "CreateOneTimeToken should succeed")
	assert.NotEmpty(t, result.Token)
	assert.True(t, result.ExpiresAt.After(time.Now()), "ExpiresAt should be in the future")
}

// TestOneTimeTokenWithJITOrgs tests one-time token creation with JIT organization IDs
func TestOneTimeTokenWithJITOrgs(t *testing.T) {
	ctx := context.Background()

	// Create organization for JIT
	createdOrg, err := testClient.CreateOrganization(ctx, models.OrganizationCreate{
		Name: fmt.Sprintf("JIT Org %d", time.Now().UnixNano()),
	})
	require.NoError(t, err)
	orgID := createdOrg.ID
	t.Cleanup(func() {
		if err := testClient.DeleteOrganization(context.Background(), orgID); err != nil {
			t.Logf("cleanup: failed to delete organization %s: %v", orgID, err)
		}
	})

	email := fmt.Sprintf("ott-jit-%d@test.local", time.Now().UnixNano())

	result, err := testClient.CreateOneTimeToken(ctx, models.OneTimeTokenCreate{
		Email:              email,
		ExpiresIn:          600,
		JitOrganizationIDs: []string{orgID},
	})
	require.NoError(t, err, "CreateOneTimeToken with JIT orgs should succeed")
	assert.NotEmpty(t, result.Token)
	assert.True(t, result.ExpiresAt.After(time.Now()), "ExpiresAt should be in the future")
}

// === Validation Tests ===

// TestCreateOneTimeToken_Validation tests validation errors
func TestCreateOneTimeToken_Validation(t *testing.T) {
	ctx := context.Background()

	_, err := testClient.CreateOneTimeToken(ctx, models.OneTimeTokenCreate{Email: ""})
	require.Error(t, err, "CreateOneTimeToken with empty email should fail")
	var validationErr *client.ValidationError
	require.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "email", validationErr.Field)
}
