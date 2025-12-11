package tests

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOrganizationInvitations tests invitation lifecycle
func TestOrganizationInvitations(t *testing.T) {
	ctx := context.Background()

	// Create organization
	createdOrg, err := testClient.CreateOrganization(ctx, fmt.Sprintf("Invite Org %d", time.Now().UnixNano()), "")
	require.NoError(t, err)
	orgID := createdOrg.ID
	t.Cleanup(func() {
		if err := testClient.DeleteOrganization(context.Background(), orgID); err != nil {
			t.Logf("cleanup: failed to delete organization %s: %v", orgID, err)
		}
	})

	inviteeEmail := fmt.Sprintf("invitee-%d@test.local", time.Now().UnixNano())
	expiresAt := time.Now().Add(24 * time.Hour).UnixMilli()

	// Create invitation
	createdInvitation, err := testClient.CreateOrganizationInvitation(ctx, orgID, "", inviteeEmail, nil, expiresAt)
	require.NoError(t, err, "CreateOrganizationInvitation should succeed")
	assert.NotEmpty(t, createdInvitation.ID)
	invitationID := createdInvitation.ID

	// Get invitation
	invitation, err := testClient.GetOrganizationInvitation(ctx, invitationID)
	require.NoError(t, err, "GetOrganizationInvitation should succeed")
	assert.Equal(t, invitationID, invitation.ID)
	assert.Equal(t, inviteeEmail, invitation.Invitee)
	assert.Equal(t, "Pending", invitation.Status)

	// List invitations
	invitations, err := testClient.ListOrganizationInvitations(ctx, orgID)
	require.NoError(t, err, "ListOrganizationInvitations should succeed")
	assert.Len(t, invitations, 1)

	// Delete invitation
	err = testClient.DeleteOrganizationInvitation(ctx, invitationID)
	require.NoError(t, err, "DeleteOrganizationInvitation should succeed")

	// Verify deletion
	invitations, err = testClient.ListOrganizationInvitations(ctx, orgID)
	require.NoError(t, err)
	assert.Len(t, invitations, 0)
}

// TestSendInvitationMessage tests sending invitation email
func TestSendInvitationMessage(t *testing.T) {
	ctx := context.Background()

	// Create organization
	createdOrg, err := testClient.CreateOrganization(ctx,
		fmt.Sprintf("Invite Message Org %d", time.Now().UnixNano()), "")
	require.NoError(t, err)
	orgID := createdOrg.ID
	t.Cleanup(func() {
		if err := testClient.DeleteOrganization(context.Background(), orgID); err != nil {
			t.Logf("cleanup: failed to delete organization %s: %v", orgID, err)
		}
	})

	// Create invitation
	inviteeEmail := fmt.Sprintf("invite_msg_%d@test.local", time.Now().UnixNano())
	expiresAt := time.Now().Add(24 * time.Hour).UnixMilli()

	createdInvitation, err := testClient.CreateOrganizationInvitation(ctx, orgID, "", inviteeEmail, nil, expiresAt)
	require.NoError(t, err)
	invitationID := createdInvitation.ID
	t.Cleanup(func() {
		if err := testClient.DeleteOrganizationInvitation(context.Background(), invitationID); err != nil {
			t.Logf("cleanup: failed to delete invitation %s: %v", invitationID, err)
		}
	})

	// Send invitation message with magic link
	// Note: This may fail in test environment without email connector configured,
	// but we're testing the API call works
	err = testClient.SendInvitationMessage(ctx, invitationID, "https://example.com/invite?token=test123")
	// Accept either success or specific error (email not configured)
	if err != nil {
		assert.Contains(t, err.Error(), "connector", "Error should be about email connector if it fails")
	}
}
