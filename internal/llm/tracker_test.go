package llm

import (
	"sync"
	"testing"
)

func TestTrackerBasicOperations(t *testing.T) {
	tracker := NewTracker()

	// initially everything should be zero
	p, c, total, cost, calls := tracker.GetTotals()
	if p != 0 || c != 0 || total != 0 || cost != 0.0 || calls != 0 {
		t.Errorf("expected initial zeros, got p=%d c=%d total=%d cost=%f calls=%d", p, c, total, cost, calls)
	}

	// record first call
	tracker.Record(1000, 500, 0.0075)

	p, c, total, cost, calls = tracker.GetTotals()
	if p != 1000 {
		t.Errorf("expected 1000 prompt tokens, got %d", p)
	}
	if c != 500 {
		t.Errorf("expected 500 completion tokens, got %d", c)
	}
	if total != 1500 {
		t.Errorf("expected 1500 total tokens, got %d", total)
	}
	if cost != 0.0075 {
		t.Errorf("expected cost 0.0075, got %f", cost)
	}
	if calls != 1 {
		t.Errorf("expected 1 call, got %d", calls)
	}

	// record second call
	tracker.Record(2000, 1000, 0.015)

	p, c, total, cost, calls = tracker.GetTotals()
	if p != 3000 {
		t.Errorf("expected 3000 prompt tokens, got %d", p)
	}
	if c != 1500 {
		t.Errorf("expected 1500 completion tokens, got %d", c)
	}
	if total != 4500 {
		t.Errorf("expected 4500 total tokens, got %d", total)
	}
	if cost < 0.0224 || cost > 0.0226 {
		t.Errorf("expected cost ~0.0225, got %f", cost)
	}
	if calls != 2 {
		t.Errorf("expected 2 calls, got %d", calls)
	}
}

func TestTrackerBudgetChecking(t *testing.T) {
	tracker := NewTracker()

	// initially under any budget
	if tracker.ExceedsBudget(1.0) {
		t.Error("should not exceed budget initially")
	}

	// record calls totaling $0.50
	tracker.Record(10000, 5000, 0.25)
	tracker.Record(10000, 5000, 0.25)

	// should not exceed $1.00 budget
	if tracker.ExceedsBudget(1.0) {
		t.Error("should not exceed $1.00 budget with $0.50 spent")
	}

	// should exceed $0.40 budget
	if !tracker.ExceedsBudget(0.40) {
		t.Error("should exceed $0.40 budget with $0.50 spent")
	}

	// should exactly meet $0.50 budget
	if !tracker.ExceedsBudget(0.50) {
		t.Error("should meet/exceed $0.50 budget with $0.50 spent")
	}
}

func TestTrackerReset(t *testing.T) {
	tracker := NewTracker()

	// record some data
	tracker.Record(1000, 500, 0.0075)
	tracker.Record(2000, 1000, 0.015)

	// verify data is recorded
	_, _, _, cost, calls := tracker.GetTotals()
	if cost == 0.0 || calls == 0 {
		t.Error("expected non-zero values before reset")
	}

	// reset
	tracker.Reset()

	// verify everything is zeroed
	p, c, total, cost, calls := tracker.GetTotals()
	if p != 0 || c != 0 || total != 0 || cost != 0.0 || calls != 0 {
		t.Errorf("expected zeros after reset, got p=%d c=%d total=%d cost=%f calls=%d", p, c, total, cost, calls)
	}
}

func TestTrackerConcurrency(t *testing.T) {
	tracker := NewTracker()
	numGoroutines := 100
	recordsPerGoroutine := 10

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// spawn multiple goroutines recording concurrently
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < recordsPerGoroutine; j++ {
				tracker.Record(100, 50, 0.001)
			}
		}()
	}

	wg.Wait()

	// verify totals
	expectedPrompt := numGoroutines * recordsPerGoroutine * 100
	expectedCompletion := numGoroutines * recordsPerGoroutine * 50
	expectedTotal := expectedPrompt + expectedCompletion
	expectedCost := float64(numGoroutines*recordsPerGoroutine) * 0.001
	expectedCalls := numGoroutines * recordsPerGoroutine

	p, c, total, cost, calls := tracker.GetTotals()

	if p != expectedPrompt {
		t.Errorf("expected %d prompt tokens, got %d", expectedPrompt, p)
	}
	if c != expectedCompletion {
		t.Errorf("expected %d completion tokens, got %d", expectedCompletion, c)
	}
	if total != expectedTotal {
		t.Errorf("expected %d total tokens, got %d", expectedTotal, total)
	}
	if cost < expectedCost-0.01 || cost > expectedCost+0.01 {
		t.Errorf("expected cost ~%f, got %f", expectedCost, cost)
	}
	if calls != expectedCalls {
		t.Errorf("expected %d calls, got %d", expectedCalls, calls)
	}
}

func TestTrackerConcurrentBudgetCheck(t *testing.T) {
	tracker := NewTracker()
	var wg sync.WaitGroup
	wg.Add(2)

	// goroutine 1: records data
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			tracker.Record(100, 50, 0.01)
		}
	}()

	// goroutine 2: checks budget
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			_ = tracker.ExceedsBudget(0.5)
		}
	}()

	wg.Wait()

	// verify final cost
	_, _, _, cost, _ := tracker.GetTotals()
	expectedCost := 1.0 // 100 * 0.01

	if cost < expectedCost-0.01 || cost > expectedCost+0.01 {
		t.Errorf("expected cost ~%f, got %f", expectedCost, cost)
	}
}
