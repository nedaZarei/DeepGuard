package llm

import (
	"sync"
)

// tracker maintains cumulative token usage and cost across multiple api calls
// it is thread-safe and can be safely used by concurrent workers
type Tracker struct {
	mu sync.Mutex

	totalPromptTokens     int
	totalCompletionTokens int
	totalCost             float64
	callCount             int
}

// newTracker creates a new token/cost tracker
func NewTracker() *Tracker {
	return &Tracker{}
}

// record adds the token usage and cost from a single api call to the cumulative totals
func (t *Tracker) Record(promptTokens, completionTokens int, cost float64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.totalPromptTokens += promptTokens
	t.totalCompletionTokens += completionTokens
	t.totalCost += cost
	t.callCount++
}

// getTotals returns the current cumulative totals
// returns: promptTokens, completionTokens, totalTokens, cost, callCount
func (t *Tracker) GetTotals() (int, int, int, float64, int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	totalTokens := t.totalPromptTokens + t.totalCompletionTokens
	return t.totalPromptTokens, t.totalCompletionTokens, totalTokens, t.totalCost, t.callCount
}

// exceedsBudget checks if the cumulative cost exceeds the given budget cap
func (t *Tracker) ExceedsBudget(budgetCap float64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.totalCost >= budgetCap
}

// reset clears all cumulative totals (primarily for testing)
func (t *Tracker) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.totalPromptTokens = 0
	t.totalCompletionTokens = 0
	t.totalCost = 0.0
	t.callCount = 0
}
