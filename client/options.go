package client

import (
	"net/http"
	"time"
)

// Configuration constants
const (
	// tokenExpiryBuffer is the time before token expiry to trigger a refresh
	tokenExpiryBuffer = 60 * time.Second

	// Default configuration values
	defaultTimeout               = 5 * time.Second
	defaultResponseHeaderTimeout = 30 * time.Second
	defaultIdleConnTimeout       = 90 * time.Second
	defaultResource              = "https://default.logto.app/api"
	defaultScope                 = "all"
)

// Option configures the Adapter.
type Option func(*options)

// options holds the configuration for the Adapter.
type options struct {
	timeout               time.Duration // HTTP client timeout (default: 5s)
	responseHeaderTimeout time.Duration // Timeout for waiting for response headers (default: 30s)
	idleConnTimeout       time.Duration // How long idle connections stay in pool (default: 90s)
	httpClient            *http.Client  // Custom HTTP client (overrides all timeout options if set)
	resource              string        // M2M resource URL (default: https://default.logto.app/api)
	scope                 string        // M2M scope (default: all)
}

// defaultOptions returns the default configuration.
func defaultOptions() *options {
	return &options{
		timeout:               defaultTimeout,
		responseHeaderTimeout: defaultResponseHeaderTimeout,
		idleConnTimeout:       defaultIdleConnTimeout,
		resource:              defaultResource,
		scope:                 defaultScope,
	}
}

// WithTimeout sets the HTTP client timeout.
// Values <= 0 are ignored (default is used).
// Default: 5s
func WithTimeout(d time.Duration) Option {
	return func(o *options) {
		if d > 0 {
			o.timeout = d
		}
	}
}

// WithResponseHeaderTimeout sets the timeout for waiting for response headers.
// This helps prevent hanging connections in Docker/CI environments.
// Default: 30s. Values <= 0 are ignored.
// Note: This option is ignored when WithHTTPClient is used.
func WithResponseHeaderTimeout(d time.Duration) Option {
	return func(o *options) {
		if d > 0 {
			o.responseHeaderTimeout = d
		}
	}
}

// WithIdleConnTimeout sets how long idle connections stay in the connection pool.
// Default: 90s. Values <= 0 are ignored.
// Note: This option is ignored when WithHTTPClient is used.
func WithIdleConnTimeout(d time.Duration) Option {
	return func(o *options) {
		if d > 0 {
			o.idleConnTimeout = d
		}
	}
}

// WithHTTPClient sets a custom HTTP client.
// When set, this overrides timeout, responseHeaderTimeout, and idleConnTimeout options.
// The caller is responsible for configuring appropriate timeouts on the custom client.
// Nil values are ignored.
func WithHTTPClient(c *http.Client) Option {
	return func(o *options) {
		if c != nil {
			o.httpClient = c
		}
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
