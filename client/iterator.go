package client

import (
	"context"

	"github.com/vaintrub/logto-go/models"
)

// UserIterator provides pagination for listing users.
// Use Next(ctx) to iterate through results.
type UserIterator struct {
	adapter  *Adapter
	pageSize int
	page     int
	users    []models.User
	index    int
	err      error
	done     bool
}

// Next advances the iterator to the next user.
// The context is used for the API call to fetch the next page.
func (it *UserIterator) Next(ctx context.Context) bool {
	if it.err != nil || it.done {
		return false
	}

	if it.index < len(it.users)-1 {
		it.index++
		return true
	}

	it.page++
	users, err := it.adapter.listUsersPaginated(ctx, it.page, it.pageSize)
	if err != nil {
		it.err = err
		return false
	}

	if len(users) == 0 {
		it.done = true
		return false
	}

	it.users = users
	it.index = 0
	return true
}

// User returns the current user.
func (it *UserIterator) User() *models.User {
	if it.index < 0 || it.index >= len(it.users) {
		return nil
	}
	return &it.users[it.index]
}

// Err returns any error that occurred during iteration.
func (it *UserIterator) Err() error {
	return it.err
}

// Collect fetches all remaining users and returns them as a slice.
// Pre-allocates memory for better performance.
func (it *UserIterator) Collect(ctx context.Context) ([]models.User, error) {
	all := make([]models.User, 0, it.pageSize*2)
	for it.Next(ctx) {
		all = append(all, *it.User())
	}
	return all, it.Err()
}

// OrganizationIterator provides pagination for listing organizations.
// Use Next(ctx) to iterate through results.
type OrganizationIterator struct {
	adapter       *Adapter
	pageSize      int
	page          int
	organizations []models.Organization
	index         int
	err           error
	done          bool
}

// Next advances the iterator to the next organization.
// The context is used for the API call to fetch the next page.
func (it *OrganizationIterator) Next(ctx context.Context) bool {
	if it.err != nil || it.done {
		return false
	}

	if it.index < len(it.organizations)-1 {
		it.index++
		return true
	}

	it.page++
	orgs, err := it.adapter.listOrganizationsPaginated(ctx, it.page, it.pageSize)
	if err != nil {
		it.err = err
		return false
	}

	if len(orgs) == 0 {
		it.done = true
		return false
	}

	it.organizations = orgs
	it.index = 0
	return true
}

// Organization returns the current organization.
func (it *OrganizationIterator) Organization() *models.Organization {
	if it.index < 0 || it.index >= len(it.organizations) {
		return nil
	}
	return &it.organizations[it.index]
}

// Err returns any error that occurred during iteration.
func (it *OrganizationIterator) Err() error {
	return it.err
}

// Collect fetches all remaining organizations and returns them as a slice.
// Pre-allocates memory for better performance.
func (it *OrganizationIterator) Collect(ctx context.Context) ([]models.Organization, error) {
	all := make([]models.Organization, 0, it.pageSize*2)
	for it.Next(ctx) {
		all = append(all, *it.Organization())
	}
	return all, it.Err()
}
