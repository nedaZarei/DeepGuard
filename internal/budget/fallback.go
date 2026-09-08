package budget

import (
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// ModelTransition represents a single model switch event
type ModelTransition struct {
	FromModel    string
	ToModel      string
	Reason       string
	CostAtSwitch float64
	Timestamp    time.Time
}

// ModelUsageStats tracks usage statistics for a single model
type ModelUsageStats struct {
	Model          string
	ChunksAnalyzed int
	TotalCost      float64
	TokensUsed     int
}

// ModelUsageReport provides a summary of model usage across the scan
type ModelUsageReport struct {
	Transitions []ModelTransition
	ModelStats  map[string]ModelUsageStats
	FinalModel  string
	TotalCost   float64
	TotalChunks int
}

// FallbackManager handles automatic model switching based on budget thresholds
type FallbackManager struct {
	mu sync.Mutex

	// Configuration
	budgetCap        float64
	softCapThreshold float64 // 80% of budget ($2.40 for $3.00 cap)
	switchThreshold  float64 // Model switch threshold ($3.00 default)
	primaryModel     string  // Primary model (gpt-4o)
	fallbackModel    string  // Fallback model (gpt-4o-mini)

	// State tracking
	currentModel         string
	transitions          []ModelTransition
	modelChunkCounts     map[string]int
	softCapWarningLogged bool
}

// FallbackConfig holds configuration for the fallback manager
type FallbackConfig struct {
	BudgetCap       float64
	SwitchThreshold float64
	PrimaryModel    string
	FallbackModel   string
}

// DefaultFallbackConfig returns the default fallback configuration
func DefaultFallbackConfig() *FallbackConfig {
	return &FallbackConfig{
		BudgetCap:       5.0, // $5.00 hard cap
		SwitchThreshold: 3.0, // Switch at $3.00
		PrimaryModel:    "gpt-4o",
		FallbackModel:   "gpt-4o-mini",
	}
}

// ResolveFallbackModel picks the model to switch to when spend crosses the
// switch threshold. An explicit choice always wins. Otherwise gpt-4o keeps its
// historical gpt-4o-mini fallback, and every other model (gpt-4o-mini itself,
// Groq/Ollama/other OpenAI-compatible endpoints) falls back to itself, i.e. no
// switch — the provider may not serve gpt-4o-mini at all.
func ResolveFallbackModel(primary, explicit string) string {
	if explicit != "" {
		return explicit
	}
	if primary == "gpt-4o" {
		return "gpt-4o-mini"
	}
	return primary
}

// NewFallbackManager creates a new fallback manager
func NewFallbackManager(config *FallbackConfig) *FallbackManager {
	if config == nil {
		config = DefaultFallbackConfig()
	}

	// Calculate soft cap threshold (80% of switch threshold)
	softCapThreshold := config.SwitchThreshold * 0.8

	return &FallbackManager{
		budgetCap:            config.BudgetCap,
		softCapThreshold:     softCapThreshold,
		switchThreshold:      config.SwitchThreshold,
		primaryModel:         config.PrimaryModel,
		fallbackModel:        config.FallbackModel,
		currentModel:         config.PrimaryModel,
		transitions:          make([]ModelTransition, 0),
		modelChunkCounts:     make(map[string]int),
		softCapWarningLogged: false,
	}
}

// SelectModel determines which model to use based on current cumulative cost
// Returns the model to use for the next API call
func (fm *FallbackManager) SelectModel(cumulativeCost float64) string {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	// Check if we've reached soft cap threshold (80%)
	if cumulativeCost >= fm.softCapThreshold && cumulativeCost < fm.switchThreshold && !fm.softCapWarningLogged {
		remainingBudget := fm.switchThreshold - cumulativeCost
		percentUsed := (cumulativeCost / fm.switchThreshold) * 100.0

		log.Warn().
			Str("component", "budget").
			Float64("current_cost", cumulativeCost).
			Float64("switch_threshold", fm.switchThreshold).
			Float64("remaining_budget", remainingBudget).
			Float64("percent_used", percentUsed).
			Msgf("Budget warning: %.0f%% of fallback threshold consumed ($%.2f / $%.2f), $%.2f remaining before model switch",
				percentUsed, cumulativeCost, fm.switchThreshold, remainingBudget)

		fm.softCapWarningLogged = true
	}

	// Check if we should switch to fallback model
	if cumulativeCost >= fm.switchThreshold && fm.currentModel != fm.fallbackModel {
		// Record the transition
		transition := ModelTransition{
			FromModel:    fm.currentModel,
			ToModel:      fm.fallbackModel,
			Reason:       "budget threshold exceeded",
			CostAtSwitch: cumulativeCost,
			Timestamp:    time.Now(),
		}
		fm.transitions = append(fm.transitions, transition)

		log.Info().
			Str("component", "budget").
			Str("from_model", fm.currentModel).
			Str("to_model", fm.fallbackModel).
			Float64("cost_at_switch", cumulativeCost).
			Float64("switch_threshold", fm.switchThreshold).
			Msgf("Model fallback triggered: switching from %s to %s (cost $%.2f exceeds threshold $%.2f)",
				fm.currentModel, fm.fallbackModel, cumulativeCost, fm.switchThreshold)

		fm.currentModel = fm.fallbackModel
	}

	// If already on fallback model and budget exceeded, just log at debug level
	if cumulativeCost >= fm.budgetCap && fm.currentModel == fm.fallbackModel {
		log.Debug().
			Str("component", "budget").
			Str("model", fm.currentModel).
			Float64("cumulative_cost", cumulativeCost).
			Float64("budget_cap", fm.budgetCap).
			Msg("budget cap exceeded while on fallback model, continuing with current model")
	}

	return fm.currentModel
}

// RecordModelSwitch manually records a model switch (for external transitions)
func (fm *FallbackManager) RecordModelSwitch(fromModel, toModel, reason string, costAtSwitch float64) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	transition := ModelTransition{
		FromModel:    fromModel,
		ToModel:      toModel,
		Reason:       reason,
		CostAtSwitch: costAtSwitch,
		Timestamp:    time.Now(),
	}
	fm.transitions = append(fm.transitions, transition)

	log.Info().
		Str("component", "budget").
		Str("from_model", fromModel).
		Str("to_model", toModel).
		Str("reason", reason).
		Float64("cost_at_switch", costAtSwitch).
		Msg("model switch recorded")

	fm.currentModel = toModel
}

// RecordChunkAnalyzed records that a chunk was analyzed with the current model
func (fm *FallbackManager) RecordChunkAnalyzed(model string) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	fm.modelChunkCounts[model]++
}

// GetCurrentModel returns the current model being used
func (fm *FallbackManager) GetCurrentModel() string {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	return fm.currentModel
}

// GetModelUsageReport generates a final usage report
func (fm *FallbackManager) GetModelUsageReport(budgetStatus BudgetStatus) ModelUsageReport {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	// Build model stats from budget status
	modelStats := make(map[string]ModelUsageStats)
	for model, modelCost := range budgetStatus.ModelBreakdown {
		chunkCount := fm.modelChunkCounts[model]
		modelStats[model] = ModelUsageStats{
			Model:          model,
			ChunksAnalyzed: chunkCount,
			TotalCost:      modelCost.Cost,
			TokensUsed:     modelCost.PromptTokens + modelCost.CompletionTokens,
		}
	}

	// Calculate total chunks
	totalChunks := 0
	for _, count := range fm.modelChunkCounts {
		totalChunks += count
	}

	return ModelUsageReport{
		Transitions: fm.transitions,
		ModelStats:  modelStats,
		FinalModel:  fm.currentModel,
		TotalCost:   budgetStatus.CumulativeCost,
		TotalChunks: totalChunks,
	}
}

// LogModelUsageReport logs the final model usage report
func LogModelUsageReport(report ModelUsageReport) {
	log.Info().
		Str("component", "budget").
		Int("total_chunks", report.TotalChunks).
		Float64("total_cost", report.TotalCost).
		Str("final_model", report.FinalModel).
		Int("transitions_count", len(report.Transitions)).
		Msg("model usage report")

	// Log per-model statistics
	for model, stats := range report.ModelStats {
		log.Info().
			Str("component", "budget").
			Str("model", model).
			Int("chunks_analyzed", stats.ChunksAnalyzed).
			Float64("cost", stats.TotalCost).
			Int("tokens_used", stats.TokensUsed).
			Msgf("Model %s: analyzed %d chunks, cost $%.2f, used %d tokens",
				model, stats.ChunksAnalyzed, stats.TotalCost, stats.TokensUsed)
	}

	// Log transitions
	for i, transition := range report.Transitions {
		log.Info().
			Str("component", "budget").
			Int("transition_number", i+1).
			Str("from_model", transition.FromModel).
			Str("to_model", transition.ToModel).
			Str("reason", transition.Reason).
			Float64("cost_at_switch", transition.CostAtSwitch).
			Time("timestamp", transition.Timestamp).
			Msgf("Transition %d: %s → %s (reason: %s, cost at switch: $%.2f)",
				i+1, transition.FromModel, transition.ToModel, transition.Reason, transition.CostAtSwitch)
	}
}
