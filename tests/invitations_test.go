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

// TestOrganizationInvitations tests invitation lifecycle
func TestOrganizationInvitations(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Create organization
	createdOrg, err := testClient.CreateOrganization(ctx, models.OrganizationCreate{
		Name: fmt.Sprintf("Invite Org %d", time.Now().UnixNano()),
	})
	require.NoError(t, err)
	orgID := createdOrg.ID
	t.Cleanup(func() {
		if err := testClient.DeleteOrganization(context.Background(), orgID); err != nil {
			t.Logf("cleanup: failed to delete organization %s: %v", orgID, err)
		}
	})

	inviteeEmail := fmt.Sprintf("invitee-%d@test.local", time.Now().UnixNano())
	expiresAt := models.UnixMilliTime{Time: time.Now().Add(24 * time.Hour)}

	// Create invitation
	createdInvitation, err := testClient.CreateOrganizationInvitation(ctx, models.OrganizationInvitationCreate{
		OrganizationID: orgID,
		Invitee:        inviteeEmail,
		ExpiresAt:      expiresAt,
	})
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
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Create organization
	createdOrg, err := testClient.CreateOrganization(ctx, models.OrganizationCreate{
		Name: fmt.Sprintf("Invite Message Org %d", time.Now().UnixNano()),
	})
	require.NoError(t, err)
	orgID := createdOrg.ID
	t.Cleanup(func() {
		if err := testClient.DeleteOrganization(context.Background(), orgID); err != nil {
			t.Logf("cleanup: failed to delete organization %s: %v", orgID, err)
		}
	})

	// Create invitation
	inviteeEmail := fmt.Sprintf("invite_msg_%d@test.local", time.Now().UnixNano())
	expiresAt := models.UnixMilliTime{Time: time.Now().Add(24 * time.Hour)}

	createdInvitation, err := testClient.CreateOrganizationInvitation(ctx, models.OrganizationInvitationCreate{
		OrganizationID: orgID,
		Invitee:        inviteeEmail,
		ExpiresAt:      expiresAt,
	})
	require.NoError(t, err)
	invitationID := createdInvitation.ID
	t.Cleanup(func() {
		if err := testClient.DeleteOrganizationInvitation(context.Background(), invitationID); err != nil {
			t.Logf("cleanup: failed to delete invitation %s: %v", invitationID, err)
		}
	})

	// Clear any previous emails
	testEnv.EmailMock.Clear()

	// Send invitation message with magic link
	magicLink := "https://example.com/invite?token=test123"
	err = testClient.SendInvitationMessage(ctx, invitationID, magicLink)
	require.NoError(t, err, "SendInvitationMessage should succeed")

	// Verify email was received by mock server
	received := testEnv.EmailMock.Received()
	require.Len(t, received, 1, "Should have received exactly one email")

	email := received[0]
	assert.Equal(t, inviteeEmail, email.To, "Email should be sent to invitee")
	assert.Equal(t, "OrganizationInvitation", email.Type, "Email type should be OrganizationInvitation")
	assert.NotNil(t, email.Payload, "Email payload should not be nil")

	// Verify payload contains the magic link
	if link, ok := email.Payload["link"].(string); ok {
		assert.Equal(t, magicLink, link, "Magic link should be in payload")
	}
}

// === Validation Tests ===

// TestCreateOrganizationInvitation_Validation tests validation errors
func TestCreateOrganizationInvitation_Validation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("empty organizationId", func(t *testing.T) {
		_, err := testClient.CreateOrganizationInvitation(ctx, models.OrganizationInvitationCreate{
			OrganizationID: "",
			Invitee:        "test@test.local",
			ExpiresAt:      models.UnixMilliTime{Time: time.Now().Add(24 * time.Hour)},
		})
		require.Error(t, err, "CreateOrganizationInvitation with empty organizationId should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "organizationId", validationErr.Field)
	})

	t.Run("empty invitee", func(t *testing.T) {
		_, err := testClient.CreateOrganizationInvitation(ctx, models.OrganizationInvitationCreate{
			OrganizationID: "org-123",
			Invitee:        "",
			ExpiresAt:      models.UnixMilliTime{Time: time.Now().Add(24 * time.Hour)},
		})
		require.Error(t, err, "CreateOrganizationInvitation with empty invitee should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "invitee", validationErr.Field)
	})
}

// TestListOrganizationInvitations_Validation tests validation errors
func TestListOrganizationInvitations_Validation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := testClient.ListOrganizationInvitations(ctx, "")
	require.Error(t, err, "ListOrganizationInvitations with empty orgID should fail")
	var validationErr *client.ValidationError
	require.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "orgID", validationErr.Field)
}

// TestGetOrganizationInvitation_Validation tests validation errors
func TestGetOrganizationInvitation_Validation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := testClient.GetOrganizationInvitation(ctx, "")
	require.Error(t, err, "GetOrganizationInvitation with empty invitationID should fail")
	var validationErr *client.ValidationError
	require.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "invitationID", validationErr.Field)
}

// TestDeleteOrganizationInvitation_Validation tests validation errors
func TestDeleteOrganizationInvitation_Validation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := testClient.DeleteOrganizationInvitation(ctx, "")
	require.Error(t, err, "DeleteOrganizationInvitation with empty invitationID should fail")
	var validationErr *client.ValidationError
	require.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "invitationID", validationErr.Field)
}

// TestSendInvitationMessage_Validation tests validation errors
func TestSendInvitationMessage_Validation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("empty invitationID", func(t *testing.T) {
		err := testClient.SendInvitationMessage(ctx, "", "https://example.com/invite")
		require.Error(t, err, "SendInvitationMessage with empty invitationID should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "invitationID", validationErr.Field)
	})

	t.Run("empty magicLink", func(t *testing.T) {
		err := testClient.SendInvitationMessage(ctx, "invitation-123", "")
		require.Error(t, err, "SendInvitationMessage with empty magicLink should fail")
		var validationErr *client.ValidationError
		require.ErrorAs(t, err, &validationErr)
		assert.Equal(t, "magicLink", validationErr.Field)
	})
}
