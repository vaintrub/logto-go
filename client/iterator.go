package client

import (
	"context"

	"github.com/vaintrub/logto-go/models"
)

// UserIterator provides pagination for listing users.
type UserIterator struct {
	adapter  *Adapter
	ctx      context.Context
	pageSize int
	page     int
	users    []models.User
	index    int
	err      error
	done     bool
}

// Next advances the iterator to the next user.
func (it *UserIterator) Next() bool {
	if it.err != nil || it.done {
		return false
	}

	if it.index < len(it.users)-1 {
		it.index++
		return true
	}

	it.page++
	users, err := it.adapter.listUsersPaginated(it.ctx, it.page, it.pageSize)
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
func (it *UserIterator) Collect() ([]models.User, error) {
	var all []models.User
	for it.Next() {
		all = append(all, *it.User())
	}
	return all, it.Err()
}

// OrganizationIterator provides pagination for listing organizations.
type OrganizationIterator struct {
	adapter       *Adapter
	ctx           context.Context
	pageSize      int
	page          int
	organizations []models.Organization
	index         int
	err           error
	done          bool
}

// Next advances the iterator to the next organization.
func (it *OrganizationIterator) Next() bool {
	if it.err != nil || it.done {
		return false
	}

	if it.index < len(it.organizations)-1 {
		it.index++
		return true
	}

	it.page++
	orgs, err := it.adapter.listOrganizationsPaginated(it.ctx, it.page, it.pageSize)
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
func (it *OrganizationIterator) Collect() ([]models.Organization, error) {
	var all []models.Organization
	for it.Next() {
		all = append(all, *it.Organization())
	}
	return all, it.Err()
}
