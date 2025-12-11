package tests

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vaintrub/logto-go/client"
)

// TestVerificationCodeValidation tests input validation for verification code methods
func TestVerificationCodeValidation(t *testing.T) {
	ctx := context.Background()

	t.Run("RequestVerificationCode with empty email and phone fails", func(t *testing.T) {
		err := testClient.RequestVerificationCode(ctx, client.VerificationCodeRequest{})
		assert.Error(t, err, "RequestVerificationCode with empty email/phone should fail")
	})

	t.Run("RequestVerificationCode with both email and phone fails", func(t *testing.T) {
		err := testClient.RequestVerificationCode(ctx, client.VerificationCodeRequest{
			Email: "test@example.com",
			Phone: "+1234567890",
		})
		assert.Error(t, err, "RequestVerificationCode with both email and phone should fail")
	})

	t.Run("VerifyCode with empty email and phone fails", func(t *testing.T) {
		err := testClient.VerifyCode(ctx, client.VerifyCodeRequest{
			VerificationCode: "123456",
		})
		assert.Error(t, err, "VerifyCode with empty email/phone should fail")
	})

	t.Run("VerifyCode with empty verification code fails", func(t *testing.T) {
		err := testClient.VerifyCode(ctx, client.VerifyCodeRequest{
			Email: "test@example.com",
		})
		assert.Error(t, err, "VerifyCode with empty verification code should fail")
	})
}
