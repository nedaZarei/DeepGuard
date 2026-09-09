package llm

import (
	"context"
	"sync"
	"testing"
	"time"
)

func withInterval(d time.Duration, fn func()) {
	prev := minInterval
	prevLast := lastRequest
	minInterval = d
	lastRequest = time.Time{}
	defer func() { minInterval = prev; lastRequest = prevLast }()
	fn()
}

func TestThrottle_DisabledIsNoop(t *testing.T) {
	withInterval(0, func() {
		start := time.Now()
		for i := 0; i < 5; i++ {
			if err := throttle(context.Background()); err != nil {
				t.Fatalf("throttle: %v", err)
			}
		}
		if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
			t.Errorf("disabled throttle blocked for %v", elapsed)
		}
	})
}

func TestThrottle_SpacesConcurrentCalls(t *testing.T) {
	withInterval(40*time.Millisecond, func() {
		var wg sync.WaitGroup
		start := time.Now()
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := throttle(context.Background()); err != nil {
					t.Errorf("throttle: %v", err)
				}
			}()
		}
		wg.Wait()
		// 4 calls at 40ms spacing: the last one waits ~120ms.
		if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
			t.Errorf("4 calls finished in %v, expected >=100ms of spacing", elapsed)
		}
	})
}

func TestThrottle_RespectsContextCancellation(t *testing.T) {
	withInterval(10*time.Second, func() {
		_ = throttle(context.Background()) // consume the first (free) slot
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		start := time.Now()
		if err := throttle(ctx); err == nil {
			t.Error("expected context error while waiting on throttle")
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("cancellation took %v, should return promptly", elapsed)
		}
	})
}
