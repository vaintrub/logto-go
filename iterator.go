package logto

import (
	"context"
)

// UserIterator provides pagination for listing users.
// Usage:
//
//	iter := client.ListUsersIter(ctx, 100)
//	for iter.Next() {
//	    user := iter.User()
//	    fmt.Println(user.Email)
//	}
//	if err := iter.Err(); err != nil {
//	    log.Fatal(err)
//	}
type UserIterator struct {
	adapter  *Adapter
	ctx      context.Context
	pageSize int
	page     int
	users    []*User
	index    int
	err      error
	done     bool
}

// Next advances the iterator to the next user.
// Returns false when iteration is complete or an error occurred.
func (it *UserIterator) Next() bool {
	if it.err != nil || it.done {
		return false
	}

	// If we have more items in current page
	if it.index < len(it.users)-1 {
		it.index++
		return true
	}

	// Fetch next page
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

// User returns the current user. Must be called after Next() returns true.
func (it *UserIterator) User() *User {
	if it.index < 0 || it.index >= len(it.users) {
		return nil
	}
	return it.users[it.index]
}

// Err returns any error that occurred during iteration.
func (it *UserIterator) Err() error {
	return it.err
}

// Collect fetches all remaining users and returns them as a slice.
// This is a convenience method that consumes the iterator.
func (it *UserIterator) Collect() ([]*User, error) {
	var all []*User
	for it.Next() {
		all = append(all, it.User())
	}
	return all, it.Err()
}

// OrganizationIterator provides pagination for listing organizations.
type OrganizationIterator struct {
	adapter       *Adapter
	ctx           context.Context
	pageSize      int
	page          int
	organizations []*Organization
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
func (it *OrganizationIterator) Organization() *Organization {
	if it.index < 0 || it.index >= len(it.organizations) {
		return nil
	}
	return it.organizations[it.index]
}

// Err returns any error that occurred during iteration.
func (it *OrganizationIterator) Err() error {
	return it.err
}

// Collect fetches all remaining organizations and returns them as a slice.
func (it *OrganizationIterator) Collect() ([]*Organization, error) {
	var all []*Organization
	for it.Next() {
		all = append(all, it.Organization())
	}
	return all, it.Err()
}

// InvitationIterator provides pagination for listing invitations.
type InvitationIterator struct {
	adapter     *Adapter
	ctx         context.Context
	orgID       string
	pageSize    int
	page        int
	invitations []*OrganizationInvitation
	index       int
	err         error
	done        bool
}

// Next advances the iterator to the next invitation.
func (it *InvitationIterator) Next() bool {
	if it.err != nil || it.done {
		return false
	}

	if it.index < len(it.invitations)-1 {
		it.index++
		return true
	}

	it.page++
	invs, err := it.adapter.listInvitationsPaginated(it.ctx, it.orgID, it.page, it.pageSize)
	if err != nil {
		it.err = err
		return false
	}

	if len(invs) == 0 {
		it.done = true
		return false
	}

	it.invitations = invs
	it.index = 0
	return true
}

// Invitation returns the current invitation.
func (it *InvitationIterator) Invitation() *OrganizationInvitation {
	if it.index < 0 || it.index >= len(it.invitations) {
		return nil
	}
	return it.invitations[it.index]
}

// Err returns any error that occurred during iteration.
func (it *InvitationIterator) Err() error {
	return it.err
}

// Collect fetches all remaining invitations and returns them as a slice.
func (it *InvitationIterator) Collect() ([]*OrganizationInvitation, error) {
	var all []*OrganizationInvitation
	for it.Next() {
		all = append(all, it.Invitation())
	}
	return all, it.Err()
}
