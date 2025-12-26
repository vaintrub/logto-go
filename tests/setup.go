// Package tests provides integration tests for the logto-go client.
package tests

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/vaintrub/logto-go/client"
)

//go:embed bootstrap.sql
var bootstrapSQL string

const (
	testM2MAppID     = "test-m2m-app"
	testM2MAppSecret = "test-m2m-secret-12345"
	testOrgID        = "test-org"

	postgresUser     = "logto"
	postgresPassword = "logto"
	postgresDB       = "logto"
)

// EmailPayload represents an email received by the mock server.
type EmailPayload struct {
	To      string         `json:"to"`
	Type    string         `json:"type"`
	Payload map[string]any `json:"payload"`
}

// EmailMockServer holds received emails for verification in tests.
// It listens on 0.0.0.0 so it's accessible from Docker containers via host.docker.internal.
type EmailMockServer struct {
	server     *http.Server
	listener   net.Listener
	received   []EmailPayload
	mu         sync.Mutex
	port       int
	dockerHost string // hostname for Docker containers to reach this server
}

// NewEmailMockServer creates a new mock email server that listens on all interfaces.
// dockerHost should be "host.docker.internal" for Docker Desktop (macOS/Windows)
// or the host's IP address for Linux.
func NewEmailMockServer(dockerHost string) (*EmailMockServer, error) {
	mock := &EmailMockServer{
		dockerHost: dockerHost,
	}

	// Listen on all interfaces so Docker containers can connect
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return nil, fmt.Errorf("failed to create listener: %w", err)
	}
	mock.listener = listener
	mock.port = listener.Addr().(*net.TCPAddr).Port

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload EmailPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mock.mu.Lock()
		mock.received = append(mock.received, payload)
		mock.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})

	mock.server = &http.Server{Handler: handler}
	go func() {
		_ = mock.server.Serve(listener)
	}()

	return mock, nil
}

// URL returns the server URL for local access.
func (m *EmailMockServer) URL() string {
	return fmt.Sprintf("http://127.0.0.1:%d", m.port)
}

// DockerURL returns the URL that Docker containers should use to reach this server.
func (m *EmailMockServer) DockerURL() string {
	return fmt.Sprintf("http://%s:%d", m.dockerHost, m.port)
}

// Close shuts down the mock server.
func (m *EmailMockServer) Close() {
	if m.server != nil {
		_ = m.server.Close()
	}
	if m.listener != nil {
		_ = m.listener.Close()
	}
}

// Received returns all received email payloads.
func (m *EmailMockServer) Received() []EmailPayload {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]EmailPayload, len(m.received))
	copy(result, m.received)
	return result
}

// Clear clears all received emails.
func (m *EmailMockServer) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.received = nil
}

// Env holds the test environment containers and client.
type Env struct {
	PostgresContainer testcontainers.Container
	SeedContainer     testcontainers.Container
	LogtoContainer    testcontainers.Container
	Client            *client.Adapter
	LogtoEndpoint     string
	PostgresURL       string
	EmailMock         *EmailMockServer
}

// Setup creates a test environment with PostgreSQL and Logto containers.
// It handles the proper initialization order:
// 1. Start PostgreSQL
// 2. Run Logto CLI db seed to create tables
// 3. Bootstrap M2M app via SQL
// 4. Start Logto server
func Setup(ctx context.Context) (*Env, error) {
	env := &Env{}

	// Start email mock server first (needed for bootstrap SQL)
	// Use host.docker.internal for Docker Desktop (macOS/Windows)
	// On Linux, this might need to be the host's IP address
	emailMock, err := NewEmailMockServer("host.docker.internal")
	if err != nil {
		return nil, fmt.Errorf("failed to start email mock server: %w", err)
	}
	env.EmailMock = emailMock
	log.Printf("Email mock server started at %s (Docker: %s)", env.EmailMock.URL(), env.EmailMock.DockerURL())

	log.Println("Step 1/6: Starting PostgreSQL container...")
	// 1. Start PostgreSQL container
	postgresReq := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     postgresUser,
			"POSTGRES_PASSWORD": postgresPassword,
			"POSTGRES_DB":       postgresDB,
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).
			WithStartupTimeout(60 * time.Second),
	}

	postgresContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: postgresReq,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to start PostgreSQL container: %w", err)
	}
	env.PostgresContainer = postgresContainer
	log.Println("Step 1/6: PostgreSQL container started")

	// Get PostgreSQL connection info
	postgresHost, err := postgresContainer.Host(ctx)
	if err != nil {
		env.Teardown(ctx)
		return nil, fmt.Errorf("failed to get PostgreSQL host: %w", err)
	}
	postgresPort, err := postgresContainer.MappedPort(ctx, "5432")
	if err != nil {
		env.Teardown(ctx)
		return nil, fmt.Errorf("failed to get PostgreSQL port: %w", err)
	}

	env.PostgresURL = fmt.Sprintf("postgres://%s:%s@%s:%s/%s",
		postgresUser, postgresPassword, postgresHost, postgresPort.Port(), postgresDB)

	// PostgreSQL internal URL for Logto container (using container network)
	postgresInternalIP, err := postgresContainer.ContainerIP(ctx)
	if err != nil {
		env.Teardown(ctx)
		return nil, fmt.Errorf("failed to get PostgreSQL container IP: %w", err)
	}
	postgresInternalURL := fmt.Sprintf("postgres://%s:%s@%s:5432/%s",
		postgresUser, postgresPassword, postgresInternalIP, postgresDB)

	log.Println("Step 2/6: Running Logto database seed...")
	// 2. Run Logto CLI to seed the database (creates tables)
	// Logto Docker image expects commands passed to its entrypoint
	seedReq := testcontainers.ContainerRequest{
		Image:      "svhd/logto:latest",
		Entrypoint: []string{"/bin/sh", "-c"},
		Cmd:        []string{"cd /etc/logto/packages/cli && npm start -- db seed --swe"},
		Env: map[string]string{
			"DB_URL": postgresInternalURL,
		},
		WaitingFor: wait.ForExit().WithExitTimeout(120 * time.Second),
	}

	seedContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: seedReq,
		Started:          true,
	})
	if err != nil {
		env.Teardown(ctx)
		return nil, fmt.Errorf("failed to seed database: %w", err)
	}
	env.SeedContainer = seedContainer

	// Wait for seed to complete and check exit code
	code, err := seedContainer.State(ctx)
	if err != nil {
		env.Teardown(ctx)
		return nil, fmt.Errorf("failed to get seed container state: %w", err)
	}
	if code.ExitCode != 0 {
		logs, _ := seedContainer.Logs(ctx)
		if logs != nil {
			buf := new(bytes.Buffer)
			_, _ = buf.ReadFrom(logs)
			_ = logs.Close()
			return nil, fmt.Errorf("seed failed with exit code %d: %s", code.ExitCode, buf.String())
		}
		env.Teardown(ctx)
		return nil, fmt.Errorf("seed failed with exit code %d", code.ExitCode)
	}
	log.Println("Step 2/6: Database seed completed")

	log.Println("Step 3/6: Bootstrapping M2M application...")
	// 3. Bootstrap M2M application via direct SQL (tables now exist!)
	// Use DockerURL for email endpoint so Logto container can reach it
	if err := bootstrapM2MApp(ctx, env.PostgresURL, bootstrapParams{
		M2MAppID:      testM2MAppID,
		M2MAppSecret:  testM2MAppSecret,
		EmailEndpoint: env.EmailMock.DockerURL(),
	}); err != nil {
		env.Teardown(ctx)
		return nil, fmt.Errorf("failed to bootstrap M2M app: %w", err)
	}
	log.Println("Step 3/6: M2M application bootstrapped")

	log.Println("Step 4/6: Starting Logto server...")
	// 4. Start Logto server
	logtoReq := testcontainers.ContainerRequest{
		Image:        "svhd/logto:latest",
		ExposedPorts: []string{"3001/tcp", "3002/tcp"},
		Env: map[string]string{
			"DB_URL":         postgresInternalURL,
			"TRUST_PROXY":    "true",
			"ENDPOINT":       "http://localhost:3001",
			"ADMIN_ENDPOINT": "http://localhost:3002",
		},
		WaitingFor: wait.ForHTTP("/api/status").
			WithPort("3001/tcp").
			WithStatusCodeMatcher(func(status int) bool {
				return status == 200 || status == 204
			}).
			WithStartupTimeout(120 * time.Second),
	}

	logtoContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: logtoReq,
		Started:          true,
	})
	if err != nil {
		env.Teardown(ctx)
		return nil, fmt.Errorf("failed to start Logto container: %w", err)
	}
	env.LogtoContainer = logtoContainer

	// Get Logto endpoint
	logtoHost, err := logtoContainer.Host(ctx)
	if err != nil {
		env.Teardown(ctx)
		return nil, fmt.Errorf("failed to get Logto host: %w", err)
	}
	logtoPort, err := logtoContainer.MappedPort(ctx, "3001")
	if err != nil {
		env.Teardown(ctx)
		return nil, fmt.Errorf("failed to get Logto port: %w", err)
	}
	env.LogtoEndpoint = fmt.Sprintf("http://%s:%s", logtoHost, logtoPort.Port())
	log.Printf("Step 4/6: Logto server started at %s", env.LogtoEndpoint)

	log.Println("Step 5/6: Waiting for Logto to be ready...")
	// 5. Wait for Logto to fully initialize
	if err := waitForLogtoReady(ctx, env.LogtoEndpoint, 60*time.Second); err != nil {
		env.Teardown(ctx)
		return nil, fmt.Errorf("logto not ready: %w", err)
	}
	log.Println("Step 5/6: Logto is ready")

	log.Println("Step 6/6: Creating Logto client...")
	// 6. Create Logto client
	c, err := client.New(env.LogtoEndpoint, testM2MAppID, testM2MAppSecret,
		client.WithTimeout(30*time.Second),
	)
	if err != nil {
		env.Teardown(ctx)
		return nil, fmt.Errorf("failed to create Logto client: %w", err)
	}
	env.Client = c

	return env, nil
}

// Teardown cleans up the test environment.
func (env *Env) Teardown(ctx context.Context) {
	if env.LogtoContainer != nil {
		_ = env.LogtoContainer.Terminate(ctx)
	}
	if env.SeedContainer != nil {
		_ = env.SeedContainer.Terminate(ctx)
	}
	if env.PostgresContainer != nil {
		_ = env.PostgresContainer.Terminate(ctx)
	}
	if env.EmailMock != nil {
		env.EmailMock.Close()
	}
}

// waitForLogtoReady waits for Logto to be ready.
func waitForLogtoReady(ctx context.Context, endpoint string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	// Normalize endpoint: remove trailing slash to prevent double slashes
	endpoint = strings.TrimSuffix(endpoint, "/")
	for time.Now().Before(deadline) {
		resp, err := http.Get(endpoint + "/api/status")
		if err == nil && (resp.StatusCode == 200 || resp.StatusCode == 204) {
			_ = resp.Body.Close()
			return nil
		}
		if resp != nil {
			_ = resp.Body.Close()
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("timeout waiting for Logto at %s", endpoint)
}

// bootstrapParams holds parameters for the bootstrap SQL template.
type bootstrapParams struct {
	M2MAppID      string
	M2MAppSecret  string
	EmailEndpoint string
}

// bootstrapM2MApp creates the M2M application directly in the database.
func bootstrapM2MApp(ctx context.Context, postgresURL string, params bootstrapParams) error {
	conn, err := pgx.Connect(ctx, postgresURL)
	if err != nil {
		return fmt.Errorf("connect to postgres: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	// Parse and execute template
	tmpl, err := template.New("bootstrap").Parse(bootstrapSQL)
	if err != nil {
		return fmt.Errorf("parse SQL template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, params); err != nil {
		return fmt.Errorf("execute SQL template: %w", err)
	}

	_, err = conn.Exec(ctx, buf.String())
	if err != nil {
		return fmt.Errorf("execute bootstrap SQL: %w", err)
	}

	return nil
}
