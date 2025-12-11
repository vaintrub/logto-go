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
	defaultTimeout  = 5 * time.Second
	defaultResource = "https://default.logto.app/api"
	defaultScope    = "all"
)

// Option configures the Adapter.
type Option func(*options)

// options holds the configuration for the Adapter.
type options struct {
	timeout    time.Duration // HTTP client timeout (default: 5s)
	httpClient *http.Client  // Custom HTTP client (overrides timeout if set)
	logger     *slog.Logger  // Optional structured logger
	resource   string        // M2M resource URL (default: https://default.logto.app/api)
	scope      string        // M2M scope (default: all)
}

// defaultOptions returns the default configuration.
func defaultOptions() *options {
	return &options{
		timeout:  defaultTimeout,
		resource: defaultResource,
		scope:    defaultScope,
	}
}

// WithTimeout sets the HTTP client timeout.
// Default: 5s
func WithTimeout(d time.Duration) Option {
	return func(o *options) {
		o.timeout = d
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
