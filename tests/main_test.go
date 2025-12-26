// Package tests contains integration tests for the logto-go client.
package tests

import (
	"context"
	"log"
	"os"
	"testing"
	"time"

	"github.com/vaintrub/logto-go/client"
)

var (
	testClient *client.Adapter
	testEnv    *Env
)

func TestMain(m *testing.M) {

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	log.Println("Setting up test environment...")
	var err error
	testEnv, err = Setup(ctx)
	if err != nil {
		log.Fatalf("Failed to setup test environment: %v", err)
	}
	testClient = testEnv.Client

	log.Println("Test environment ready, running tests...")
	code := m.Run()

	log.Println("Tearing down test environment...")
	testEnv.Teardown(context.Background())

	os.Exit(code)
}
