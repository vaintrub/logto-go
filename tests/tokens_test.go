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
	assert.Greater(t, result.ExpiresAt, time.Now().UnixMilli())
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
	assert.Greater(t, result.ExpiresAt, time.Now().UnixMilli())
}
