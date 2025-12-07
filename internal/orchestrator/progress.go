package orchestrator

import (
	"github.com/Neda-Zarei/deep-guard/internal/llm"
	"github.com/rs/zerolog/log"
)

// ReportProgress logs the current analysis progress
func ReportProgress(tracker *ProgressTracker, budgetTracker *llm.Tracker, model string) {
	processed, total, findings := tracker.GetStats()
	percentage := tracker.GetPercentage()
	_, _, _, cost, _ := budgetTracker.GetTotals()

	log.Info().
		Str("component", "orchestrator").
		Int("processed", processed).
		Int("total", total).
		Float64("percentage", percentage).
		Int("findings", findings).
		Float64("cost", cost).
		Str("model", model).
		Msgf("Progress: %d/%d chunks (%.1f%%), %d findings, $%.2f spent, model: %s",
			processed, total, percentage, findings, cost, model)

	// Mark that we reported
	tracker.MarkReported()
}

// ReportWorkerMetrics logs per-chunk metrics
func ReportWorkerMetrics(result *WorkResult) {
	if result.Success {
		log.Debug().
			Str("component", "orchestrator").
			Str("chunk_id", result.ChunkID).
			Str("file", result.FilePath).
			Dur("duration", result.Duration).
			Int("tokens", result.TokensUsed).
			Float64("cost", result.Cost).
			Int("findings", len(result.Findings)).
			Msg("chunk analysis completed")
	} else {
		log.Error().
			Str("component", "orchestrator").
			Str("chunk_id", result.ChunkID).
			Str("file", result.FilePath).
			Err(result.Error).
			Msg("chunk analysis failed")
	}
}

// ReportFinalStats logs the final analysis statistics
func ReportFinalStats(
	totalChunks int,
	successfulChunks int,
	totalFindings int,
	budgetTracker *llm.Tracker,
	errorTracker *ErrorTracker,
) {
	promptTokens, completionTokens, totalTokens, cost, callCount := budgetTracker.GetTotals()
	failedCount, _, _ := errorTracker.GetStats()

	log.Info().
		Str("component", "orchestrator").
		Int("total_chunks", totalChunks).
		Int("successful", successfulChunks).
		Int("failed", failedCount).
		Int("total_findings", totalFindings).
		Int("api_calls", callCount).
		Int("prompt_tokens", promptTokens).
		Int("completion_tokens", completionTokens).
		Int("total_tokens", totalTokens).
		Float64("total_cost", cost).
		Msgf("Analysis completed: %d/%d chunks successful, %d findings, $%.2f spent",
			successfulChunks, totalChunks, totalFindings, cost)
}
