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

// TestIterators tests paginated iterators
func TestIterators(t *testing.T) {
	ctx := context.Background()

	// Test UserIterator
	t.Run("UserIterator", func(t *testing.T) {
		iter := testClient.ListUsersIter(10)
		count := 0
		for iter.Next(ctx) {
			user := iter.User()
			assert.NotEmpty(t, user.ID)
			count++
			if count >= 3 {
				break
			}
		}
		// Error check at the end
		assert.NoError(t, iter.Err())
	})

	// Test OrganizationIterator
	t.Run("OrganizationIterator", func(t *testing.T) {
		// Create a few orgs first
		var createdOrgIDs []string
		for i := 0; i < 3; i++ {
			org, err := testClient.CreateOrganization(ctx, models.OrganizationCreate{
				Name: fmt.Sprintf("Iter Org %d-%d", time.Now().UnixNano(), i),
			})
			require.NoError(t, err, "CreateOrganization should succeed")
			createdOrgIDs = append(createdOrgIDs, org.ID)
		}
		t.Cleanup(func() {
			for _, orgID := range createdOrgIDs {
				if err := testClient.DeleteOrganization(context.Background(), orgID); err != nil {
					t.Logf("cleanup: failed to delete organization %s: %v", orgID, err)
				}
			}
		})

		iter := testClient.ListOrganizationsIter(10)
		count := 0
		for iter.Next(ctx) {
			org := iter.Organization()
			assert.NotEmpty(t, org.ID)
			count++
		}
		assert.NoError(t, iter.Err())
		assert.GreaterOrEqual(t, count, 3)
	})
}

// TestValidationErrors tests that validation errors are properly returned
func TestValidationErrors(t *testing.T) {
	ctx := context.Background()

	// Empty userID should fail
	_, err := testClient.GetUser(ctx, "")
	require.Error(t, err, "GetUser with empty ID should fail")
	var validationErr *client.ValidationError
	require.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "userID", validationErr.Field)

	// Empty orgID should fail
	_, err = testClient.GetOrganization(ctx, "")
	require.Error(t, err, "GetOrganization with empty ID should fail")
	require.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "orgID", validationErr.Field)

	// Empty name should fail
	_, err = testClient.CreateOrganization(ctx, models.OrganizationCreate{})
	require.Error(t, err, "CreateOrganization with empty name should fail")
	require.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "name", validationErr.Field)

	// Empty username should fail
	_, err = testClient.CreateUser(ctx, models.UserCreate{Password: "password"})
	require.Error(t, err, "CreateUser with empty username should fail")
	require.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "username", validationErr.Field)
}
