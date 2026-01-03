package llm

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	// retry configuration
	maxRetries     = 5
	baseDelay      = 2 * time.Second
	maxDelay       = 64 * time.Second
	requestTimeout = 60 * time.Second
)

// retryableError represents an error that can be retried
type retryableError struct {
	statusCode int
	message    string
	retryAfter time.Duration
}

func (e *retryableError) Error() string {
	return fmt.Sprintf("retryable error (status %d): %s", e.statusCode, e.message)
}

// isRetryable determines if an http status code should be retried
func isRetryable(statusCode int) bool {
	// retry on rate limit (429) and server errors (5xx)
	return statusCode == http.StatusTooManyRequests || (statusCode >= 500 && statusCode < 600)
}

// getRetryDelay calculates the delay before the next retry using exponential backoff
// respects retry-after header if present
func getRetryDelay(attempt int, retryAfter time.Duration) time.Duration {
	// if server provided retry-after, use it
	if retryAfter > 0 {
		return retryAfter
	}

	// exponential backoff: 2s, 4s, 8s, 16s, 32s, 64s
	delay := baseDelay * (1 << uint(attempt))
	if delay > maxDelay {
		delay = maxDelay
	}

	return delay
}

// parseRetryAfter extracts retry delay from retry-after header
// supports both delay-seconds and http-date formats
func parseRetryAfter(header string) time.Duration {
	if header == "" {
		return 0
	}

	// try parsing as seconds
	if seconds, err := strconv.Atoi(header); err == nil {
		return time.Duration(seconds) * time.Second
	}

	// try parsing as http-date
	if t, err := http.ParseTime(header); err == nil {
		duration := time.Until(t)
		if duration > 0 {
			return duration
		}
	}

	return 0
}

// withRetry wraps an operation with exponential backoff retry logic
// retries on rate limits (429), server errors (5xx), and network failures
// does not retry on client errors (4xx except 429)
func withRetry(ctx context.Context, operation func(context.Context) error) error {
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		// create context with timeout for this attempt
		attemptCtx, cancel := context.WithTimeout(ctx, requestTimeout)

		// execute operation
		err := operation(attemptCtx)
		cancel()

		// success
		if err == nil {
			if attempt > 0 {
				log.Info().
					Str("component", "llm").
					Int("attempt", attempt+1).
					Msg("request succeeded after retry")
			}
			return nil
		}

		lastErr = err

		// check if context was cancelled
		if ctx.Err() != nil {
			log.Warn().
				Str("component", "llm").
				Err(ctx.Err()).
				Msg("request cancelled by context")
			return ctx.Err()
		}

		// check if this is a retryable error
		retryErr, ok := err.(*retryableError)
		if !ok {
			// not a retryable error, fail immediately
			log.Debug().
				Str("component", "llm").
				Err(err).
				Msg("non-retryable error, failing immediately")
			return err
		}

		// reached max retries
		if attempt == maxRetries {
			log.Error().
				Str("component", "llm").
				Int("max_retries", maxRetries).
				Err(lastErr).
				Msg("max retries exceeded")
			return fmt.Errorf("max retries exceeded: %w", lastErr)
		}

		// calculate delay
		delay := getRetryDelay(attempt, retryErr.retryAfter)

		log.Warn().
			Str("component", "llm").
			Int("attempt", attempt+1).
			Int("status_code", retryErr.statusCode).
			Dur("delay", delay).
			Msg("request failed, retrying")

		// wait before retry
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
			// continue to next attempt
		}
	}

	return lastErr
}
