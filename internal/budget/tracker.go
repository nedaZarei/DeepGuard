package budget

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// UsageMetrics represents a single API call's token usage and cost
type UsageMetrics struct {
	PromptTokens     int
	CompletionTokens int
	Model            string
	Cost             float64
	Timestamp        time.Time
}

// BudgetStatus represents the current budget status
type BudgetStatus struct {
	CumulativeCost   float64
	TotalTokens      int
	PromptTokens     int
	CompletionTokens int
	CallCount        int
	ModelBreakdown   map[string]ModelCost
}

// ModelCost tracks costs for a specific model
type ModelCost struct {
	PromptTokens     int
	CompletionTokens int
	Cost             float64
	CallCount        int
}

// BudgetTracker tracks API usage, costs, and enforces budget caps with milestone logging
type BudgetTracker struct {
	mu sync.Mutex

	// Budget configuration
	budgetCap float64

	// Cumulative totals
	cumulativeCost        float64
	totalPromptTokens     int
	totalCompletionTokens int
	callCount             int

	// Per-model breakdown
	modelCosts map[string]*ModelCost

	// Per-call history (optional, for debugging)
	callHistory []UsageMetrics

	// Milestone tracking
	milestones map[int]bool // tracks which milestones have been logged
}

// Model pricing constants (per 1M tokens) based on GapGPT pricing
// Source: https://gapgpt.app pricing page
const (
	// gpt-4o pricing (OpenAI via GapGPT)
	// Input: $2.50/1M, Output: $10.00/1M (standard OpenAI pricing)
	GPT4oInputPricePer1M  = 2.50
	GPT4oOutputPricePer1M = 10.00

	// gpt-4o-mini pricing (OpenAI via GapGPT)
	// Input: $0.15/1M, Output: $0.60/1M (standard OpenAI pricing)
	GPT4oMiniInputPricePer1M  = 0.150
	GPT4oMiniOutputPricePer1M = 0.600

	// gpt-4.5-preview pricing (OpenAI via GapGPT)
	// Input: $37.50/1M, Output: $150.00/1M
	GPT45PreviewInputPricePer1M  = 37.50
	GPT45PreviewOutputPricePer1M = 150.00

	// gpt-4.1 pricing (OpenAI via GapGPT)
	// Input: $0.50/1M, Output: $8.00/1M
	GPT41InputPricePer1M  = 0.50
	GPT41OutputPricePer1M = 8.00

	// Default pricing for unknown models (use gpt-4o pricing as fallback)
	DefaultInputPricePer1M  = GPT4oInputPricePer1M
	DefaultOutputPricePer1M = GPT4oOutputPricePer1M
)

// NewBudgetTracker creates a new budget tracker with the specified cap
func NewBudgetTracker(budgetCap float64) *BudgetTracker {
	return &BudgetTracker{
		budgetCap:   budgetCap,
		modelCosts:  make(map[string]*ModelCost),
		callHistory: make([]UsageMetrics, 0),
		milestones:  make(map[int]bool),
	}
}

// zeroCostPrefixes are model-name prefixes for open-weight families that are
// typically served without per-token billing (local Ollama, Groq free tier).
var zeroCostPrefixes = []string{
	"llama", "meta-llama", "qwen", "gemma", "mistral", "mixtral",
	"deepseek", "phi", "codellama", "codestral", "codegemma", "starcoder",
}

// IsZeroCostModel reports whether cost tracking should treat the model as free.
func IsZeroCostModel(model string) bool {
	m := strings.ToLower(model)
	for _, p := range zeroCostPrefixes {
		if strings.HasPrefix(m, p) {
			return true
		}
	}
	return false
}

// CalculateCost computes the cost in USD for a given token usage
func CalculateCost(promptTokens, completionTokens int, model string) float64 {
	var inputPrice, outputPrice float64

	switch model {
	case "gpt-4o":
		inputPrice = GPT4oInputPricePer1M
		outputPrice = GPT4oOutputPricePer1M
	case "gpt-4o-mini":
		inputPrice = GPT4oMiniInputPricePer1M
		outputPrice = GPT4oMiniOutputPricePer1M
	case "gpt-4.5-preview":
		inputPrice = GPT45PreviewInputPricePer1M
		outputPrice = GPT45PreviewOutputPricePer1M
	case "gpt-4.1":
		inputPrice = GPT41InputPricePer1M
		outputPrice = GPT41OutputPricePer1M
	default:
		if IsZeroCostModel(model) {
			// Open-weight models served locally (Ollama) or on free tiers (Groq):
			// no per-token charge, so don't accrue fake gpt-4o cost against the cap.
			return 0
		}
		// Log warning for unknown model
		log.Warn().
			Str("component", "budget").
			Str("model", model).
			Msgf("unknown model '%s', using default pricing (gpt-4o)", model)
		inputPrice = DefaultInputPricePer1M
		outputPrice = DefaultOutputPricePer1M
	}

	// Convert tokens to millions and calculate cost
	inputCost := (float64(promptTokens) / 1_000_000.0) * inputPrice
	outputCost := (float64(completionTokens) / 1_000_000.0) * outputPrice

	return inputCost + outputCost
}

// RecordUsage records a single API call's token usage and cost
func (bt *BudgetTracker) RecordUsage(usage UsageMetrics) error {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	// Validation: reject negative token counts
	if usage.PromptTokens < 0 || usage.CompletionTokens < 0 {
		return fmt.Errorf("invalid token counts: prompt=%d, completion=%d (must be non-negative)",
			usage.PromptTokens, usage.CompletionTokens)
	}

	// Update cumulative totals
	bt.cumulativeCost += usage.Cost
	bt.totalPromptTokens += usage.PromptTokens
	bt.totalCompletionTokens += usage.CompletionTokens
	bt.callCount++

	// Update per-model breakdown
	if _, exists := bt.modelCosts[usage.Model]; !exists {
		bt.modelCosts[usage.Model] = &ModelCost{}
	}
	modelCost := bt.modelCosts[usage.Model]
	modelCost.PromptTokens += usage.PromptTokens
	modelCost.CompletionTokens += usage.CompletionTokens
	modelCost.Cost += usage.Cost
	modelCost.CallCount++

	// Store in history
	bt.callHistory = append(bt.callHistory, usage)

	// Check and log milestones
	bt.checkMilestones()

	return nil
}

// checkMilestones logs when budget milestones are reached (50%, 80%, 100%)
func (bt *BudgetTracker) checkMilestones() {
	if bt.budgetCap <= 0 {
		return // No budget cap set
	}

	percentage := (bt.cumulativeCost / bt.budgetCap) * 100.0

	milestones := []int{50, 80, 100}
	for _, milestone := range milestones {
		if percentage >= float64(milestone) && !bt.milestones[milestone] {
			bt.milestones[milestone] = true

			log.Info().
				Str("component", "budget").
				Int("milestone", milestone).
				Float64("current_cost", bt.cumulativeCost).
				Float64("budget_cap", bt.budgetCap).
				Float64("percentage", percentage).
				Msgf("Budget milestone reached: %.0f%% ($%.2f / $%.2f)",
					percentage, bt.cumulativeCost, bt.budgetCap)
		}
	}
}

// GetCumulativeCost returns the total cost accumulated so far
func (bt *BudgetTracker) GetCumulativeCost() float64 {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	return bt.cumulativeCost
}

// GetModelBreakdown returns per-model cost breakdown
func (bt *BudgetTracker) GetModelBreakdown() map[string]float64 {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	breakdown := make(map[string]float64)
	for model, costs := range bt.modelCosts {
		breakdown[model] = costs.Cost
	}

	return breakdown
}

// GetCurrentStatus returns the current budget status with all metrics
func (bt *BudgetTracker) GetCurrentStatus() BudgetStatus {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	// Copy model breakdown
	modelBreakdown := make(map[string]ModelCost)
	for model, costs := range bt.modelCosts {
		modelBreakdown[model] = *costs
	}

	return BudgetStatus{
		CumulativeCost:   bt.cumulativeCost,
		TotalTokens:      bt.totalPromptTokens + bt.totalCompletionTokens,
		PromptTokens:     bt.totalPromptTokens,
		CompletionTokens: bt.totalCompletionTokens,
		CallCount:        bt.callCount,
		ModelBreakdown:   modelBreakdown,
	}
}

// ExceedsBudget checks if the cumulative cost exceeds the budget cap
func (bt *BudgetTracker) ExceedsBudget() bool {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	if bt.budgetCap <= 0 {
		return false // No budget cap
	}

	return bt.cumulativeCost >= bt.budgetCap
}

// GetBudgetCap returns the configured budget cap
func (bt *BudgetTracker) GetBudgetCap() float64 {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	return bt.budgetCap
}

// Reset clears all cumulative totals (primarily for testing)
func (bt *BudgetTracker) Reset() {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	bt.cumulativeCost = 0.0
	bt.totalPromptTokens = 0
	bt.totalCompletionTokens = 0
	bt.callCount = 0
	bt.modelCosts = make(map[string]*ModelCost)
	bt.callHistory = make([]UsageMetrics, 0)
	bt.milestones = make(map[int]bool)
}
