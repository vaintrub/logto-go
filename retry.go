package logto

import (
	"context"
	"io"
	"math/rand/v2"
	"net/http"
	"time"
)

// doWithRetry executes an HTTP request with exponential backoff retry.
// It will retry on retryable status codes (408, 429, 500, 502, 503, 504).
// Backoff: initialBackoff -> initialBackoff*2 -> initialBackoff*4 (with jitter)
func (a *Adapter) doWithRetry(ctx context.Context, req *http.Request, body []byte) (*http.Response, error) {
	var lastErr error
	backoff := a.opts.retryBackoff

	for attempt := 0; attempt < a.opts.retryMax; attempt++ {
		// Reset body reader for retries (if body exists)
		if body != nil && req.GetBody != nil {
			newBody, err := req.GetBody()
			if err != nil {
				return nil, err
			}
			req.Body = newBody
		}

		resp, err := a.httpClient.Do(req)
		if err != nil {
			// Network error - retry
			lastErr = err
			if !a.shouldRetry(ctx, attempt, backoff) {
				return nil, lastErr
			}
			backoff = a.nextBackoff(backoff)
			continue
		}

		// Check if we should retry based on status code
		if isRetryableStatus(resp.StatusCode) {
			// Read and discard body before retry
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()

			lastErr = newAPIError(resp.StatusCode, nil)
			if !a.shouldRetry(ctx, attempt, backoff) {
				return nil, lastErr
			}
			backoff = a.nextBackoff(backoff)
			continue
		}

		return resp, nil
	}

	return nil, lastErr
}

// shouldRetry returns true if we should attempt another retry.
// It waits for the backoff duration respecting context cancellation.
func (a *Adapter) shouldRetry(ctx context.Context, attempt int, backoff time.Duration) bool {
	// Don't retry if this is the last attempt
	if attempt >= a.opts.retryMax-1 {
		return false
	}

	// Wait with context cancellation support
	timer := time.NewTimer(backoff)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// nextBackoff calculates the next backoff duration with jitter.
// Formula: currentBackoff * 2 + random(0, currentBackoff/2)
func (a *Adapter) nextBackoff(current time.Duration) time.Duration {
	next := current * 2
	// Add jitter: 0-50% of current backoff
	jitter := time.Duration(rand.Int64N(int64(current / 2)))
	return next + jitter
}
