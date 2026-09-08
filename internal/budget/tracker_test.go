package budget

import (
	"math"
	"sync"
	"testing"
	"time"
)

// costEqual returns true if two cost values are within 1 nano-dollar of each other.
// Exact float64 equality for computed costs fails across architectures (arm64 vs
// amd64) because compile-time constant folding uses arbitrary precision while
// runtime arithmetic uses IEEE 754 — results can differ by 1 ULP.
func costEqual(a, b float64) bool {
	return math.Abs(a-b) < 1e-9
}

func TestNewBudgetTracker(t *testing.T) {
	tracker := NewBudgetTracker(10.0)

	if tracker == nil {
		t.Fatal("Expected non-nil tracker")
	}

	if tracker.GetBudgetCap() != 10.0 {
		t.Errorf("Expected budget cap 10.0, got %.2f", tracker.GetBudgetCap())
	}

	cost := tracker.GetCumulativeCost()
	if cost != 0.0 {
		t.Errorf("Expected initial cost 0.0, got %.2f", cost)
	}
}

func TestCalculateCost_GPT4o(t *testing.T) {
	// Test gpt-4o pricing
	// Input: $2.50/1M, Output: $10.00/1M
	// 1000 input tokens + 2000 output tokens
	cost := CalculateCost(1000, 2000, "gpt-4o")

	expectedCost := (1000.0/1_000_000.0)*2.50 + (2000.0/1_000_000.0)*10.00
	if !costEqual(cost, expectedCost) {
		t.Errorf("Expected cost %.9f, got %.9f", expectedCost, cost)
	}
}

func TestCalculateCost_GPT4oMini(t *testing.T) {
	// Test gpt-4o-mini pricing
	// Input: $0.15/1M, Output: $0.60/1M
	// 10000 input tokens + 5000 output tokens
	cost := CalculateCost(10000, 5000, "gpt-4o-mini")

	expectedCost := (10000.0/1_000_000.0)*0.150 + (5000.0/1_000_000.0)*0.600
	if !costEqual(cost, expectedCost) {
		t.Errorf("Expected cost %.9f, got %.9f", expectedCost, cost)
	}
}

func TestCalculateCost_GPT45Preview(t *testing.T) {
	// Test gpt-4.5-preview pricing
	// Input: $37.50/1M, Output: $150.00/1M
	cost := CalculateCost(1000, 1000, "gpt-4.5-preview")

	expectedCost := (1000.0/1_000_000.0)*37.50 + (1000.0/1_000_000.0)*150.00
	if !costEqual(cost, expectedCost) {
		t.Errorf("Expected cost %.9f, got %.9f", expectedCost, cost)
	}
}

func TestCalculateCost_GPT41(t *testing.T) {
	// Test gpt-4.1 pricing
	// Input: $0.50/1M, Output: $8.00/1M
	cost := CalculateCost(5000, 3000, "gpt-4.1")

	expectedCost := (5000.0/1_000_000.0)*0.50 + (3000.0/1_000_000.0)*8.00
	if !costEqual(cost, expectedCost) {
		t.Errorf("Expected cost %.9f, got %.9f", expectedCost, cost)
	}
}

func TestCalculateCost_UnknownModel(t *testing.T) {
	// Test unknown model (should use gpt-4o pricing as default)
	cost := CalculateCost(1000, 2000, "unknown-model")

	expectedCost := (1000.0/1_000_000.0)*GPT4oInputPricePer1M + (2000.0/1_000_000.0)*GPT4oOutputPricePer1M
	if !costEqual(cost, expectedCost) {
		t.Errorf("Expected cost %.9f for unknown model, got %.9f", expectedCost, cost)
	}
}

func TestRecordUsage_Basic(t *testing.T) {
	tracker := NewBudgetTracker(10.0)

	usage := UsageMetrics{
		PromptTokens:     1000,
		CompletionTokens: 500,
		Model:            "gpt-4o-mini",
		Cost:             CalculateCost(1000, 500, "gpt-4o-mini"),
		Timestamp:        time.Now(),
	}

	err := tracker.RecordUsage(usage)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	cost := tracker.GetCumulativeCost()
	if cost != usage.Cost {
		t.Errorf("Expected cost %.6f, got %.6f", usage.Cost, cost)
	}

	status := tracker.GetCurrentStatus()
	if status.PromptTokens != 1000 {
		t.Errorf("Expected 1000 prompt tokens, got %d", status.PromptTokens)
	}
	if status.CompletionTokens != 500 {
		t.Errorf("Expected 500 completion tokens, got %d", status.CompletionTokens)
	}
	if status.CallCount != 1 {
		t.Errorf("Expected 1 call, got %d", status.CallCount)
	}
}

func TestRecordUsage_NegativeTokens(t *testing.T) {
	tracker := NewBudgetTracker(10.0)

	usage := UsageMetrics{
		PromptTokens:     -100,
		CompletionTokens: 500,
		Model:            "gpt-4o-mini",
		Cost:             0.001,
		Timestamp:        time.Now(),
	}

	err := tracker.RecordUsage(usage)
	if err == nil {
		t.Error("Expected error for negative prompt tokens")
	}

	// Test negative completion tokens
	usage2 := UsageMetrics{
		PromptTokens:     100,
		CompletionTokens: -500,
		Model:            "gpt-4o-mini",
		Cost:             0.001,
		Timestamp:        time.Now(),
	}

	err2 := tracker.RecordUsage(usage2)
	if err2 == nil {
		t.Error("Expected error for negative completion tokens")
	}
}

func TestGetModelBreakdown(t *testing.T) {
	tracker := NewBudgetTracker(10.0)

	// Record usage for multiple models
	usage1 := UsageMetrics{
		PromptTokens:     1000,
		CompletionTokens: 500,
		Model:            "gpt-4o-mini",
		Cost:             CalculateCost(1000, 500, "gpt-4o-mini"),
		Timestamp:        time.Now(),
	}
	tracker.RecordUsage(usage1)

	usage2 := UsageMetrics{
		PromptTokens:     2000,
		CompletionTokens: 1000,
		Model:            "gpt-4o",
		Cost:             CalculateCost(2000, 1000, "gpt-4o"),
		Timestamp:        time.Now(),
	}
	tracker.RecordUsage(usage2)

	usage3 := UsageMetrics{
		PromptTokens:     500,
		CompletionTokens: 250,
		Model:            "gpt-4o-mini",
		Cost:             CalculateCost(500, 250, "gpt-4o-mini"),
		Timestamp:        time.Now(),
	}
	tracker.RecordUsage(usage3)

	breakdown := tracker.GetModelBreakdown()

	if len(breakdown) != 2 {
		t.Errorf("Expected 2 models in breakdown, got %d", len(breakdown))
	}

	if _, ok := breakdown["gpt-4o-mini"]; !ok {
		t.Error("Expected gpt-4o-mini in breakdown")
	}

	if _, ok := breakdown["gpt-4o"]; !ok {
		t.Error("Expected gpt-4o in breakdown")
	}
}

func TestExceedsBudget(t *testing.T) {
	tracker := NewBudgetTracker(0.001) // Very small budget cap

	if tracker.ExceedsBudget() {
		t.Error("Expected ExceedsBudget to be false initially")
	}

	// Record usage that exceeds budget
	usage := UsageMetrics{
		PromptTokens:     10000,
		CompletionTokens: 5000,
		Model:            "gpt-4o",
		Cost:             CalculateCost(10000, 5000, "gpt-4o"),
		Timestamp:        time.Now(),
	}
	tracker.RecordUsage(usage)

	if !tracker.ExceedsBudget() {
		t.Error("Expected ExceedsBudget to be true after exceeding cap")
	}
}

func TestExceedsBudget_NoCap(t *testing.T) {
	tracker := NewBudgetTracker(0) // No budget cap

	usage := UsageMetrics{
		PromptTokens:     100000,
		CompletionTokens: 50000,
		Model:            "gpt-4o",
		Cost:             CalculateCost(100000, 50000, "gpt-4o"),
		Timestamp:        time.Now(),
	}
	tracker.RecordUsage(usage)

	if tracker.ExceedsBudget() {
		t.Error("Expected ExceedsBudget to be false when no budget cap is set")
	}
}

func TestGetCurrentStatus(t *testing.T) {
	tracker := NewBudgetTracker(10.0)

	usage1 := UsageMetrics{
		PromptTokens:     1000,
		CompletionTokens: 500,
		Model:            "gpt-4o-mini",
		Cost:             CalculateCost(1000, 500, "gpt-4o-mini"),
		Timestamp:        time.Now(),
	}
	tracker.RecordUsage(usage1)

	usage2 := UsageMetrics{
		PromptTokens:     2000,
		CompletionTokens: 1000,
		Model:            "gpt-4o",
		Cost:             CalculateCost(2000, 1000, "gpt-4o"),
		Timestamp:        time.Now(),
	}
	tracker.RecordUsage(usage2)

	status := tracker.GetCurrentStatus()

	expectedTotalTokens := 1000 + 500 + 2000 + 1000
	if status.TotalTokens != expectedTotalTokens {
		t.Errorf("Expected total tokens %d, got %d", expectedTotalTokens, status.TotalTokens)
	}

	if status.CallCount != 2 {
		t.Errorf("Expected 2 calls, got %d", status.CallCount)
	}

	if len(status.ModelBreakdown) != 2 {
		t.Errorf("Expected 2 models in breakdown, got %d", len(status.ModelBreakdown))
	}
}

func TestReset(t *testing.T) {
	tracker := NewBudgetTracker(10.0)

	usage := UsageMetrics{
		PromptTokens:     1000,
		CompletionTokens: 500,
		Model:            "gpt-4o-mini",
		Cost:             CalculateCost(1000, 500, "gpt-4o-mini"),
		Timestamp:        time.Now(),
	}
	tracker.RecordUsage(usage)

	// Verify data is recorded
	if tracker.GetCumulativeCost() == 0.0 {
		t.Error("Expected non-zero cost before reset")
	}

	// Reset
	tracker.Reset()

	// Verify everything is cleared
	if tracker.GetCumulativeCost() != 0.0 {
		t.Error("Expected zero cost after reset")
	}

	status := tracker.GetCurrentStatus()
	if status.CallCount != 0 {
		t.Error("Expected zero calls after reset")
	}
	if status.TotalTokens != 0 {
		t.Error("Expected zero tokens after reset")
	}
	if len(status.ModelBreakdown) != 0 {
		t.Error("Expected empty model breakdown after reset")
	}
}

// TestConcurrentRecording tests thread safety with concurrent access
func TestConcurrentRecording(t *testing.T) {
	tracker := NewBudgetTracker(100.0)

	var wg sync.WaitGroup
	workerCount := 100
	callsPerWorker := 10

	// Launch concurrent workers
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for j := 0; j < callsPerWorker; j++ {
				usage := UsageMetrics{
					PromptTokens:     100,
					CompletionTokens: 50,
					Model:            "gpt-4o-mini",
					Cost:             CalculateCost(100, 50, "gpt-4o-mini"),
					Timestamp:        time.Now(),
				}

				err := tracker.RecordUsage(usage)
				if err != nil {
					t.Errorf("Worker %d: unexpected error: %v", workerID, err)
				}
			}
		}(i)
	}

	// Wait for all workers
	wg.Wait()

	// Verify totals
	status := tracker.GetCurrentStatus()
	expectedCalls := workerCount * callsPerWorker
	if status.CallCount != expectedCalls {
		t.Errorf("Expected %d calls, got %d", expectedCalls, status.CallCount)
	}

	expectedPromptTokens := workerCount * callsPerWorker * 100
	if status.PromptTokens != expectedPromptTokens {
		t.Errorf("Expected %d prompt tokens, got %d", expectedPromptTokens, status.PromptTokens)
	}

	expectedCompletionTokens := workerCount * callsPerWorker * 50
	if status.CompletionTokens != expectedCompletionTokens {
		t.Errorf("Expected %d completion tokens, got %d", expectedCompletionTokens, status.CompletionTokens)
	}
}

// TestCostAccuracy tests that costs are accurate within 0.01% of manual calculation
func TestCostAccuracy(t *testing.T) {
	tests := []struct {
		name             string
		promptTokens     int
		completionTokens int
		model            string
	}{
		{"gpt-4o small", 1000, 500, "gpt-4o"},
		{"gpt-4o large", 100000, 50000, "gpt-4o"},
		{"gpt-4o-mini small", 5000, 2500, "gpt-4o-mini"},
		{"gpt-4o-mini large", 500000, 250000, "gpt-4o-mini"},
		{"gpt-4.5-preview", 1000, 1000, "gpt-4.5-preview"},
		{"gpt-4.1", 10000, 5000, "gpt-4.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cost := CalculateCost(tt.promptTokens, tt.completionTokens, tt.model)

			// Manual calculation
			var inputPrice, outputPrice float64
			switch tt.model {
			case "gpt-4o":
				inputPrice, outputPrice = GPT4oInputPricePer1M, GPT4oOutputPricePer1M
			case "gpt-4o-mini":
				inputPrice, outputPrice = GPT4oMiniInputPricePer1M, GPT4oMiniOutputPricePer1M
			case "gpt-4.5-preview":
				inputPrice, outputPrice = GPT45PreviewInputPricePer1M, GPT45PreviewOutputPricePer1M
			case "gpt-4.1":
				inputPrice, outputPrice = GPT41InputPricePer1M, GPT41OutputPricePer1M
			}

			expectedCost := (float64(tt.promptTokens)/1_000_000.0)*inputPrice +
				(float64(tt.completionTokens)/1_000_000.0)*outputPrice

			// Check accuracy within 0.01%
			diff := (cost - expectedCost) / expectedCost * 100.0
			if diff < -0.01 || diff > 0.01 {
				t.Errorf("Cost accuracy error: %.6f vs %.6f (%.4f%% diff)",
					cost, expectedCost, diff)
			}
		})
	}
}

func TestIsZeroCostModel(t *testing.T) {
	for _, m := range []string{"llama-3.3-70b-versatile", "qwen2.5-coder:7b", "Mistral-7B", "deepseek-coder"} {
		if !IsZeroCostModel(m) {
			t.Errorf("%q should be zero-cost", m)
		}
		if c := CalculateCost(1000, 1000, m); c != 0 {
			t.Errorf("CalculateCost(%q)=%v want 0", m, c)
		}
	}
	for _, m := range []string{"gpt-4o", "gpt-4o-mini", "unknown-model"} {
		if IsZeroCostModel(m) {
			t.Errorf("%q should NOT be zero-cost", m)
		}
	}
}
