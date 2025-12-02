package client

import (
	"log/slog"
	"net/http"
	"time"
)

// Configuration constants
const (
	// tokenExpiryBuffer is the time before token expiry to trigger a refresh
	tokenExpiryBuffer = 60 * time.Second

	// Default configuration values
	defaultTimeout      = 5 * time.Second
	defaultRetryMax     = 1 // 1 = no retry (single attempt)
	defaultRetryBackoff = 500 * time.Millisecond
	defaultResource     = "https://default.logto.app/api"
	defaultScope        = "all"
)

// Option configures the Adapter.
type Option func(*options)

// options holds the configuration for the Adapter.
type options struct {
	timeout      time.Duration // HTTP client timeout (default: 30s)
	retryMax     int           // Max retry attempts (default: 3)
	retryBackoff time.Duration // Initial backoff duration (default: 500ms)
	httpClient   *http.Client  // Custom HTTP client (overrides timeout if set)
	logger       *slog.Logger  // Optional structured logger
	resource     string        // M2M resource URL (default: https://default.logto.app/api)
	scope        string        // M2M scope (default: all)
}

// defaultOptions returns the default configuration.
// Defaults optimized for frontend response time:
// - No retries (retryMax=1 means single attempt)
// - Short timeout (5s) to fail fast
func defaultOptions() *options {
	return &options{
		timeout:      defaultTimeout,
		retryMax:     defaultRetryMax,
		retryBackoff: defaultRetryBackoff,
		resource:     defaultResource,
		scope:        defaultScope,
	}
}

// WithTimeout sets the HTTP client timeout.
// Default: 5s
func WithTimeout(d time.Duration) Option {
	return func(o *options) {
		o.timeout = d
	}
}

// WithRetry configures retry behavior with exponential backoff.
// maxAttempts is the total number of attempts (including the first one).
// backoff is the initial backoff duration, which doubles after each failed attempt.
// Default: 1 attempt (no retries), 500ms initial backoff
func WithRetry(maxAttempts int, backoff time.Duration) Option {
	return func(o *options) {
		if maxAttempts > 0 {
			o.retryMax = maxAttempts
		}
		if backoff > 0 {
			o.retryBackoff = backoff
		}
	}
}

// WithHTTPClient sets a custom HTTP client.
// When set, this overrides the timeout option.
func WithHTTPClient(c *http.Client) Option {
	return func(o *options) {
		o.httpClient = c
	}
}

// WithLogger sets a structured logger for debug output.
func WithLogger(l *slog.Logger) Option {
	return func(o *options) {
		o.logger = l
	}
}

// WithResource sets the M2M resource URL for token requests.
// Default: https://default.logto.app/api
func WithResource(resource string) Option {
	return func(o *options) {
		if resource != "" {
			o.resource = resource
		}
	}
}

// WithScope sets the M2M scope for token requests.
// Default: all
func WithScope(scope string) Option {
	return func(o *options) {
		if scope != "" {
			o.scope = scope
		}
	}
}
