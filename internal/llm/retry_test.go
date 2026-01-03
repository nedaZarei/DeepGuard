package llm

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestIsRetryable(t *testing.T) {
	tests := []struct {
		statusCode int
		retryable  bool
	}{
		{http.StatusOK, false},                 // 200
		{http.StatusBadRequest, false},         // 400
		{http.StatusUnauthorized, false},       // 401
		{http.StatusForbidden, false},          // 403
		{http.StatusNotFound, false},           // 404
		{http.StatusTooManyRequests, true},     // 429 - rate limit
		{http.StatusInternalServerError, true}, // 500
		{http.StatusBadGateway, true},          // 502
		{http.StatusServiceUnavailable, true},  // 503
		{http.StatusGatewayTimeout, true},      // 504
	}

	for _, tt := range tests {
		t.Run(http.StatusText(tt.statusCode), func(t *testing.T) {
			result := isRetryable(tt.statusCode)
			if result != tt.retryable {
				t.Errorf("status %d: expected retryable=%v, got %v", tt.statusCode, tt.retryable, result)
			}
		})
	}
}

func TestGetRetryDelay(t *testing.T) {
	tests := []struct {
		name        string
		attempt     int
		retryAfter  time.Duration
		expectedMin time.Duration
		expectedMax time.Duration
	}{
		{
			name:        "attempt 0 no retry-after",
			attempt:     0,
			retryAfter:  0,
			expectedMin: 2 * time.Second,
			expectedMax: 2 * time.Second,
		},
		{
			name:        "attempt 1 no retry-after",
			attempt:     1,
			retryAfter:  0,
			expectedMin: 4 * time.Second,
			expectedMax: 4 * time.Second,
		},
		{
			name:        "attempt 2 no retry-after",
			attempt:     2,
			retryAfter:  0,
			expectedMin: 8 * time.Second,
			expectedMax: 8 * time.Second,
		},
		{
			name:        "attempt 5 capped at max",
			attempt:     5,
			retryAfter:  0,
			expectedMin: 64 * time.Second,
			expectedMax: 64 * time.Second,
		},
		{
			name:        "retry-after overrides backoff",
			attempt:     0,
			retryAfter:  10 * time.Second,
			expectedMin: 10 * time.Second,
			expectedMax: 10 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			delay := getRetryDelay(tt.attempt, tt.retryAfter)
			if delay < tt.expectedMin || delay > tt.expectedMax {
				t.Errorf("expected delay between %v and %v, got %v", tt.expectedMin, tt.expectedMax, delay)
			}
		})
	}
}

func TestParseRetryAfter(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected time.Duration
	}{
		{
			name:     "empty header",
			header:   "",
			expected: 0,
		},
		{
			name:     "seconds format",
			header:   "30",
			expected: 30 * time.Second,
		},
		{
			name:     "invalid format",
			header:   "invalid",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			duration := parseRetryAfter(tt.header)
			if duration != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, duration)
			}
		})
	}
}

func TestWithRetry_Success(t *testing.T) {
	ctx := context.Background()
	callCount := 0

	operation := func(ctx context.Context) error {
		callCount++
		return nil // success immediately
	}

	err := withRetry(ctx, operation)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if callCount != 1 {
		t.Errorf("expected 1 call, got %d", callCount)
	}
}

func TestWithRetry_SuccessAfterRetry(t *testing.T) {
	ctx := context.Background()
	callCount := 0

	operation := func(ctx context.Context) error {
		callCount++
		if callCount < 3 {
			return &retryableError{
				statusCode: http.StatusServiceUnavailable,
				message:    "service temporarily unavailable",
			}
		}
		return nil // success on third attempt
	}

	err := withRetry(ctx, operation)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if callCount != 3 {
		t.Errorf("expected 3 calls, got %d", callCount)
	}
}

func TestWithRetry_MaxRetriesExceeded(t *testing.T) {
	ctx := context.Background()
	callCount := 0

	operation := func(ctx context.Context) error {
		callCount++
		return &retryableError{
			statusCode: http.StatusServiceUnavailable,
			message:    "always fails",
		}
	}

	err := withRetry(ctx, operation)
	if err == nil {
		t.Error("expected error, got nil")
	}
	// should try initial + 5 retries = 6 times
	if callCount != 6 {
		t.Errorf("expected 6 calls, got %d", callCount)
	}
}

func TestWithRetry_NonRetryableError(t *testing.T) {
	ctx := context.Background()
	callCount := 0

	operation := func(ctx context.Context) error {
		callCount++
		return errors.New("non-retryable error")
	}

	err := withRetry(ctx, operation)
	if err == nil {
		t.Error("expected error, got nil")
	}
	// should only try once (non-retryable)
	if callCount != 1 {
		t.Errorf("expected 1 call, got %d", callCount)
	}
}

func TestWithRetry_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	callCount := 0

	operation := func(ctx context.Context) error {
		callCount++
		if callCount == 2 {
			cancel() // cancel after second attempt
		}
		return &retryableError{
			statusCode: http.StatusServiceUnavailable,
			message:    "service unavailable",
		}
	}

	err := withRetry(ctx, operation)
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}
	// should try twice before cancellation
	if callCount != 2 {
		t.Errorf("expected 2 calls, got %d", callCount)
	}
}

func TestWithRetry_Timeout(t *testing.T) {
	// skip this test as it takes too long and timing is difficult to control precisely
	t.Skip("skipping timeout test - takes too long and timing is hard to control")
}

func TestRetryableError(t *testing.T) {
	err := &retryableError{
		statusCode: 429,
		message:    "rate limit exceeded",
		retryAfter: 5 * time.Second,
	}

	expectedMsg := "retryable error (status 429): rate limit exceeded"
	if err.Error() != expectedMsg {
		t.Errorf("expected message %q, got %q", expectedMsg, err.Error())
	}
}
