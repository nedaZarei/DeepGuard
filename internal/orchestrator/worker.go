package orchestrator

import (
	"context"
	"time"

	"github.com/Neda-Zarei/deep-guard/internal/kb"
	"github.com/Neda-Zarei/deep-guard/internal/llm"
	"github.com/rs/zerolog/log"
)

// analyzeWorker is a worker goroutine that processes code chunks
func analyzeWorker(
	ctx context.Context,
	workerID int,
	client *llm.Client,
	renderer *llm.PromptRenderer,
	kbManager interface{}, // KB manager for retrieving context
	workChan <-chan WorkItem,
	resultsChan chan<- WorkResult,
	budgetCap float64,
	errorTracker *ErrorTracker,
	progressTracker *ProgressTracker,
) {
	log.Debug().
		Str("component", "orchestrator").
		Int("worker_id", workerID).
		Msg("worker started")

	for {
		select {
		case <-ctx.Done():
			// Context cancelled (graceful shutdown)
			log.Debug().
				Str("component", "orchestrator").
				Int("worker_id", workerID).
				Msg("worker shutting down due to context cancellation")
			return

		case work, ok := <-workChan:
			if !ok {
				// Work channel closed, worker done
				log.Debug().
					Str("component", "orchestrator").
					Int("worker_id", workerID).
					Msg("worker finished (work channel closed)")
				return
			}

			// Process the work item
			result := processChunk(ctx, workerID, client, renderer, work, budgetCap)

			// Update trackers
			if result.Success {
				errorTracker.RecordSuccess()
			} else {
				errorTracker.RecordFailure(result.ChunkID)
			}

			progressTracker.RecordChunk(len(result.Findings))

			// Send result
			select {
			case resultsChan <- result:
			case <-ctx.Done():
				log.Warn().
					Str("component", "orchestrator").
					Int("worker_id", workerID).
					Msg("worker shutting down while sending result")
				return
			}

			// Check if we should stop due to error threshold
			if errorTracker.ShouldStop() {
				log.Error().
					Str("component", "orchestrator").
					Int("worker_id", workerID).
					Msg("worker stopping due to error threshold exceeded")
				return
			}
		}
	}
}

// processChunk processes a single code chunk and returns the result
func processChunk(
	ctx context.Context,
	workerID int,
	client *llm.Client,
	renderer *llm.PromptRenderer,
	work WorkItem,
	budgetCap float64,
) WorkResult {
	startTime := time.Now()

	log.Debug().
		Str("component", "orchestrator").
		Int("worker_id", workerID).
		Str("chunk_id", work.Chunk.ID).
		Str("file", work.Chunk.FilePath).
		Str("function", work.Chunk.FunctionName).
		Msg("processing chunk")

	// Check budget before API call
	if client.ExceedsBudget(budgetCap) {
		log.Warn().
			Str("component", "orchestrator").
			Int("worker_id", workerID).
			Str("chunk_id", work.Chunk.ID).
			Float64("budget_cap", budgetCap).
			Msg("budget cap exceeded, skipping chunk")

		return WorkResult{
			ChunkID:  work.Chunk.ID,
			FilePath: work.Chunk.FilePath,
			Findings: nil,
			Duration: time.Since(startTime),
			Success:  false,
			Error:    ErrBudgetExceeded,
		}
	}

	// For now, we'll use empty KB context until KB manager is integrated
	// TODO: Retrieve relevant KB entries based on work.VulnType
	kbContext := []kb.KBEntry{}

	// Render prompt for this chunk
	vulnType := llm.VulnerabilityType(work.VulnType)
	prompt, err := renderer.RenderPrompt(vulnType, work.Chunk, kbContext)
	if err != nil {
		log.Error().
			Str("component", "orchestrator").
			Int("worker_id", workerID).
			Str("chunk_id", work.Chunk.ID).
			Err(err).
			Msg("failed to render prompt")

		return WorkResult{
			ChunkID:  work.Chunk.ID,
			FilePath: work.Chunk.FilePath,
			Findings: nil,
			Duration: time.Since(startTime),
			Success:  false,
			Error:    err,
		}
	}

	// Call API with parsing
	parsedResponse, response, err := client.AnalyzeWithParsing(ctx, work.Chunk, kbContext, prompt)

	duration := time.Since(startTime)

	if err != nil {
		// Analysis failed (could be API error, parsing error, etc.)
		tokensUsed := 0
		cost := 0.0
		if response != nil {
			tokensUsed = response.PromptTokens + response.CompletionTokens
			cost = response.Cost
		}

		return WorkResult{
			ChunkID:    work.Chunk.ID,
			FilePath:   work.Chunk.FilePath,
			Findings:   nil,
			Duration:   duration,
			TokensUsed: tokensUsed,
			Cost:       cost,
			Success:    false,
			Error:      err,
		}
	}

	// Success!
	findings := parsedResponse.Findings
	tokensUsed := response.PromptTokens + response.CompletionTokens

	return WorkResult{
		ChunkID:    work.Chunk.ID,
		FilePath:   work.Chunk.FilePath,
		Findings:   findings,
		Duration:   duration,
		TokensUsed: tokensUsed,
		Cost:       response.Cost,
		Success:    true,
		Error:      nil,
	}
}
