package llm

import (
	"context"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// Free API tiers cap tokens-per-minute, not just requests. With several workers
// in flight the natural request rate overruns that cap and every call comes back
// 429, burning the retry budget. minRequestInterval spaces out API calls across
// all workers so the steady-state rate stays under the quota.
//
// Set DEEPGUARD_MIN_REQUEST_INTERVAL_MS to enable (0 = disabled, the default).
// Example: Groq's free tier allows 8000 tokens/min; at ~1500 tokens per request
// that is ~5.3 requests/min, so an interval of 11500 ms keeps you just under it.
var (
	throttleMu   sync.Mutex
	lastRequest  time.Time
	minInterval  = loadMinInterval()
	throttleOnce sync.Once
)

func loadMinInterval() time.Duration {
	if v := os.Getenv("DEEPGUARD_MIN_REQUEST_INTERVAL_MS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Millisecond
		}
	}
	return 0
}

// throttle blocks until the configured minimum interval has elapsed since the
// previous API call. It is a no-op when the interval is unset. Returns the
// context error if the context is cancelled while waiting.
func throttle(ctx context.Context) error {
	if minInterval <= 0 {
		return nil
	}

	throttleOnce.Do(func() {
		log.Info().
			Str("component", "llm").
			Dur("min_request_interval", minInterval).
			Msg("API request throttling enabled")
	})

	throttleMu.Lock()
	wait := time.Duration(0)
	now := time.Now()
	if !lastRequest.IsZero() {
		if elapsed := now.Sub(lastRequest); elapsed < minInterval {
			wait = minInterval - elapsed
		}
	}
	// Reserve this call's slot before releasing the lock so concurrent workers
	// queue up behind each other instead of all waking at the same instant.
	lastRequest = now.Add(wait)
	throttleMu.Unlock()

	if wait <= 0 {
		return nil
	}

	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
