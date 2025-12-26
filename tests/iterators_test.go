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

	// Test ListUsers iterator
	t.Run("ListUsers", func(t *testing.T) {
		iter := testClient.ListUsers(client.IteratorConfig{PageSize: 10})
		count := 0
		for iter.Next(ctx) {
			user := iter.Item()
			assert.NotEmpty(t, user.ID)
			count++
			if count >= 3 {
				break
			}
		}
		// Error check at the end
		assert.NoError(t, iter.Err())
	})

	// Test ListOrganizations iterator
	t.Run("ListOrganizations", func(t *testing.T) {
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

		iter := testClient.ListOrganizations(client.IteratorConfig{PageSize: 10})
		count := 0
		for iter.Next(ctx) {
			org := iter.Item()
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

// ============================================================================
// Unit Tests for Iterator Total(), HasMore(), Reset()
// ============================================================================

// TestIterator_Total tests the Total() method behavior
func TestIterator_Total(t *testing.T) {
	ctx := context.Background()

	t.Run("BeforeFetch_ReturnsNegativeOne", func(t *testing.T) {
		iter := client.NewIterator(
			func(ctx context.Context, page, pageSize int) (client.PageResult[string], error) {
				return client.PageResult[string]{Items: []string{"a"}, Total: 10}, nil
			},
			client.IteratorConfig{PageSize: 5},
		)
		assert.Equal(t, -1, iter.Total(), "Total should be -1 before first fetch")
	})

	t.Run("AfterFetch_ReturnsTotal", func(t *testing.T) {
		iter := client.NewIterator(
			func(ctx context.Context, page, pageSize int) (client.PageResult[string], error) {
				return client.PageResult[string]{Items: []string{"a"}, Total: 42}, nil
			},
			client.IteratorConfig{PageSize: 5},
		)
		iter.Next(ctx)
		assert.Equal(t, 42, iter.Total(), "Total should be updated after fetch")
	})

	t.Run("Consistent_AcrossIteration", func(t *testing.T) {
		iter := client.NewIterator(
			func(ctx context.Context, page, pageSize int) (client.PageResult[string], error) {
				items := []string{"a", "b", "c"}
				if page > 1 {
					items = []string{}
				}
				return client.PageResult[string]{Items: items, Total: 3}, nil
			},
			client.IteratorConfig{PageSize: 10},
		)

		var totals []int
		for iter.Next(ctx) {
			totals = append(totals, iter.Total())
		}
		require.NoError(t, iter.Err())

		// All totals should be the same
		for _, total := range totals {
			assert.Equal(t, 3, total, "Total should remain consistent")
		}
	})
}

// TestIterator_HasMore tests the HasMore() method behavior
func TestIterator_HasMore(t *testing.T) {
	ctx := context.Background()

	t.Run("BeforeFetch_ReturnsTrue", func(t *testing.T) {
		iter := client.NewIterator(
			func(ctx context.Context, page, pageSize int) (client.PageResult[string], error) {
				return client.PageResult[string]{Items: []string{"a"}, Total: 1}, nil
			},
			client.IteratorConfig{PageSize: 5},
		)
		assert.True(t, iter.HasMore(), "HasMore should be true before first fetch")
	})

	t.Run("AfterComplete_ReturnsFalse", func(t *testing.T) {
		iter := client.NewIterator(
			func(ctx context.Context, page, pageSize int) (client.PageResult[string], error) {
				if page == 1 {
					return client.PageResult[string]{Items: []string{"a", "b"}, Total: 2}, nil
				}
				return client.PageResult[string]{Items: []string{}, Total: 2}, nil
			},
			client.IteratorConfig{PageSize: 10},
		)

		// Drain iterator
		for iter.Next(ctx) {
		}
		require.NoError(t, iter.Err())
		assert.False(t, iter.HasMore(), "HasMore should be false after complete iteration")
	})

	t.Run("AfterError_ReturnsFalse", func(t *testing.T) {
		iter := client.NewIterator(
			func(ctx context.Context, page, pageSize int) (client.PageResult[string], error) {
				return client.PageResult[string]{}, fmt.Errorf("fetch error")
			},
			client.IteratorConfig{PageSize: 5},
		)

		iter.Next(ctx)
		assert.Error(t, iter.Err())
		assert.False(t, iter.HasMore(), "HasMore should be false after error")
	})

	t.Run("WithKnownTotal_Precise", func(t *testing.T) {
		iter := client.NewIterator(
			func(ctx context.Context, page, pageSize int) (client.PageResult[string], error) {
				// Return 3 items per page, total 5 items
				if page == 1 {
					return client.PageResult[string]{Items: []string{"a", "b", "c"}, Total: 5}, nil
				}
				return client.PageResult[string]{Items: []string{"d", "e"}, Total: 5}, nil
			},
			client.IteratorConfig{PageSize: 3},
		)

		// After first item (fetched=1, total=5)
		iter.Next(ctx)
		assert.True(t, iter.HasMore(), "Should have more after item 1 of 5")

		// After second item (fetched=2, total=5)
		iter.Next(ctx)
		assert.True(t, iter.HasMore(), "Should have more after item 2 of 5")

		// After third item (fetched=3, total=5)
		iter.Next(ctx)
		assert.True(t, iter.HasMore(), "Should have more after item 3 of 5")

		// After fourth item (fetched=4, total=5)
		iter.Next(ctx)
		assert.True(t, iter.HasMore(), "Should have more after item 4 of 5")

		// After fifth item (fetched=5, total=5)
		iter.Next(ctx)
		assert.False(t, iter.HasMore(), "Should NOT have more after item 5 of 5")
	})

	t.Run("WithUnknownTotal_Conservative", func(t *testing.T) {
		fetchCount := 0
		iter := client.NewIterator(
			func(ctx context.Context, page, pageSize int) (client.PageResult[string], error) {
				fetchCount++
				if page == 1 {
					// Return partial page without total
					return client.PageResult[string]{Items: []string{"a", "b"}, Total: -1}, nil
				}
				return client.PageResult[string]{Items: []string{}, Total: -1}, nil
			},
			client.IteratorConfig{PageSize: 10},
		)

		iter.Next(ctx)
		// Partial page (2 items) with PageSize=10, should indicate no more
		assert.False(t, iter.HasMore(), "Partial page should indicate no more items")
	})
}

// TestIterator_Reset tests the Reset() method behavior
func TestIterator_Reset(t *testing.T) {
	ctx := context.Background()

	t.Run("ClearsState", func(t *testing.T) {
		iter := client.NewIterator(
			func(ctx context.Context, page, pageSize int) (client.PageResult[string], error) {
				return client.PageResult[string]{Items: []string{"a"}, Total: 10}, nil
			},
			client.IteratorConfig{PageSize: 5},
		)

		iter.Next(ctx)
		assert.Equal(t, 10, iter.Total())
		assert.NotNil(t, iter.Item())

		iter.Reset()

		assert.Equal(t, -1, iter.Total(), "Total should be reset to -1")
		assert.Nil(t, iter.Item(), "Item should be nil after reset")
		assert.NoError(t, iter.Err(), "Err should be nil after reset")
		assert.True(t, iter.HasMore(), "HasMore should be true after reset")
	})

	t.Run("AllowsReIteration", func(t *testing.T) {
		fetchCount := 0
		iter := client.NewIterator(
			func(ctx context.Context, page, pageSize int) (client.PageResult[string], error) {
				fetchCount++
				if page == 1 {
					return client.PageResult[string]{Items: []string{"a", "b", "c"}, Total: 3}, nil
				}
				return client.PageResult[string]{Items: []string{}, Total: 3}, nil
			},
			client.IteratorConfig{PageSize: 10},
		)

		// First pass
		firstPass, err := iter.Collect(ctx)
		require.NoError(t, err)
		assert.Len(t, firstPass, 3)
		firstFetchCount := fetchCount

		// Reset and iterate again
		iter.Reset()
		secondPass, err := iter.Collect(ctx)
		require.NoError(t, err)
		assert.Len(t, secondPass, 3)

		// Verify fetcher was called again
		assert.Greater(t, fetchCount, firstFetchCount, "Fetcher should be called again after reset")
	})

	t.Run("AfterError_ClearsError", func(t *testing.T) {
		callCount := 0
		iter := client.NewIterator(
			func(ctx context.Context, page, pageSize int) (client.PageResult[string], error) {
				callCount++
				if callCount == 1 {
					return client.PageResult[string]{}, fmt.Errorf("first call error")
				}
				return client.PageResult[string]{Items: []string{"success"}, Total: 1}, nil
			},
			client.IteratorConfig{PageSize: 5},
		)

		iter.Next(ctx)
		assert.Error(t, iter.Err(), "Should have error after failed fetch")

		iter.Reset()
		assert.NoError(t, iter.Err(), "Err should be cleared after reset")

		// Should be able to iterate successfully now
		assert.True(t, iter.Next(ctx), "Should succeed after reset")
		assert.Equal(t, "success", *iter.Item())
	})
}

// TestIterator_EdgeCases tests edge cases
func TestIterator_EdgeCases(t *testing.T) {
	ctx := context.Background()

	t.Run("EmptyResult", func(t *testing.T) {
		iter := client.NewIterator(
			func(ctx context.Context, page, pageSize int) (client.PageResult[string], error) {
				return client.PageResult[string]{Items: []string{}, Total: 0}, nil
			},
			client.IteratorConfig{PageSize: 20},
		)

		assert.False(t, iter.Next(ctx), "Next should return false for empty result")
		assert.NoError(t, iter.Err())
		assert.False(t, iter.HasMore(), "HasMore should be false for empty result")
		assert.Equal(t, 0, iter.Total())
	})

	t.Run("SingleItem", func(t *testing.T) {
		iter := client.NewIterator(
			func(ctx context.Context, page, pageSize int) (client.PageResult[string], error) {
				if page == 1 {
					return client.PageResult[string]{Items: []string{"only-one"}, Total: 1}, nil
				}
				return client.PageResult[string]{Items: []string{}, Total: 1}, nil
			},
			client.IteratorConfig{PageSize: 20},
		)

		assert.True(t, iter.Next(ctx))
		assert.Equal(t, "only-one", *iter.Item())
		assert.False(t, iter.HasMore(), "HasMore should be false after single item")
		assert.False(t, iter.Next(ctx))
		assert.NoError(t, iter.Err())
	})

	t.Run("ExactPageSize", func(t *testing.T) {
		fetchCount := 0
		iter := client.NewIterator(
			func(ctx context.Context, page, pageSize int) (client.PageResult[string], error) {
				fetchCount++
				if page == 1 {
					// Return exactly pageSize items
					items := make([]string, pageSize)
					for i := 0; i < pageSize; i++ {
						items[i] = fmt.Sprintf("item%d", i)
					}
					return client.PageResult[string]{Items: items, Total: pageSize}, nil
				}
				return client.PageResult[string]{Items: []string{}, Total: pageSize}, nil
			},
			client.IteratorConfig{PageSize: 5},
		)

		items, err := iter.Collect(ctx)
		require.NoError(t, err)
		assert.Len(t, items, 5)
		assert.False(t, iter.HasMore())
		// May fetch page 2 to check for more items (depends on Total)
	})

	t.Run("LargePageSize", func(t *testing.T) {
		iter := client.NewIterator(
			func(ctx context.Context, page, pageSize int) (client.PageResult[string], error) {
				if page == 1 {
					return client.PageResult[string]{Items: []string{"a", "b"}, Total: 2}, nil
				}
				return client.PageResult[string]{Items: []string{}, Total: 2}, nil
			},
			client.IteratorConfig{PageSize: 1000},
		)

		items, err := iter.Collect(ctx)
		require.NoError(t, err)
		assert.Len(t, items, 2)
		assert.False(t, iter.HasMore())
	})
}
