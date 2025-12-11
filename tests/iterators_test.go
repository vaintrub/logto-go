package tests

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/vaintrub/logto-go/models"
)

// TestIterators tests paginated iterators
func TestIterators(t *testing.T) {
	ctx := context.Background()

	// Test UserIterator
	t.Run("UserIterator", func(t *testing.T) {
		iter := testClient.ListUsersIter(ctx, 10)
		count := 0
		for iter.Next() {
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
		for i := 0; i < 3; i++ {
			_, _ = testClient.CreateOrganization(ctx, models.OrganizationCreate{
				Name: fmt.Sprintf("Iter Org %d-%d", time.Now().UnixNano(), i),
			})
		}

		iter := testClient.ListOrganizationsIter(ctx, 10)
		count := 0
		for iter.Next() {
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
	assert.Error(t, err, "GetUser with empty ID should fail")

	// Empty orgID should fail
	_, err = testClient.GetOrganization(ctx, "")
	assert.Error(t, err, "GetOrganization with empty ID should fail")

	// Empty name should fail
	_, err = testClient.CreateOrganization(ctx, models.OrganizationCreate{})
	assert.Error(t, err, "CreateOrganization with empty name should fail")

	// Empty username should fail
	_, err = testClient.CreateUser(ctx, models.UserCreate{Password: "password"})
	assert.Error(t, err, "CreateUser with empty username should fail")
}
