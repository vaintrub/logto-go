// Package tests contains integration tests for the logto-go client.
package tests

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/vaintrub/logto-go/client"
)

func init() {
	// This runs AFTER all imported packages' init() functions
	fmt.Println("[tests] init() - package initialization complete")

	// Start a watchdog goroutine that will dump goroutines if we hang
	go func() {
		time.Sleep(3 * time.Minute)
		fmt.Println("\n\n=== WATCHDOG: Test setup taking too long, dumping goroutines ===")
		buf := make([]byte, 1024*1024)
		n := runtime.Stack(buf, true)
		fmt.Println(string(buf[:n]))
		os.Exit(1)
	}()
}

var (
	testClient *client.Adapter
	testEnv    *Env
)

func TestMain(m *testing.M) {
	fmt.Println("[tests] TestMain() started")

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
