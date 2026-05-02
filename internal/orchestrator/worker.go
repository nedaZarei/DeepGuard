package orchestrator

import (
	"context"
	"time"

	"github.com/Neda-Zarei/deep-guard/internal/budget"
	"github.com/Neda-Zarei/deep-guard/internal/kb"
	"github.com/Neda-Zarei/deep-guard/internal/llm"
	"github.com/Neda-Zarei/deep-guard/internal/rag"
	"github.com/rs/zerolog/log"
)

// analyzeWorker is a worker goroutine that processes code chunks
func analyzeWorker(
	ctx context.Context,
	workerID int,
	client *llm.Client,
	renderer *llm.PromptRenderer,
	retriever *rag.Retriever,
	workChan <-chan WorkItem,
	resultsChan chan<- WorkResult,
	budgetTracker *budget.BudgetTracker,
	fallbackManager *budget.FallbackManager,
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
			result := processChunk(ctx, workerID, client, renderer, retriever, work, budgetTracker, fallbackManager)

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
	retriever *rag.Retriever,
	work WorkItem,
	budgetTracker *budget.BudgetTracker,
	fallbackManager *budget.FallbackManager,
) WorkResult {
	startTime := time.Now()

	log.Debug().
		Str("component", "orchestrator").
		Int("worker_id", workerID).
		Str("chunk_id", work.Chunk.ID).
		Str("file", work.Chunk.FilePath).
		Str("function", work.Chunk.FunctionName).
		Msg("processing chunk")

	// Get current cumulative cost
	cumulativeCost := budgetTracker.GetCumulativeCost()

	// Select model based on current cost (automatic fallback)
	selectedModel := fallbackManager.SelectModel(cumulativeCost)

	// Check if budget exceeded (hard stop)
	if budgetTracker.ExceedsBudget() {
		log.Warn().
			Str("component", "orchestrator").
			Int("worker_id", workerID).
			Str("chunk_id", work.Chunk.ID).
			Float64("budget_cap", budgetTracker.GetBudgetCap()).
			Float64("cumulative_cost", cumulativeCost).
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

	// Retrieve relevant KB entries for this chunk via BM25 RAG
	kbContext := []kb.KBEntry{}
	if retriever != nil {
		if ragResult, err := retriever.Retrieve(work.Chunk); err == nil {
			kbContext = ragResult.Entries
		} else {
			log.Warn().
				Str("component", "orchestrator").
				Int("worker_id", workerID).
				Str("chunk_id", work.Chunk.ID).
				Err(err).
				Msg("KB retrieval failed, continuing without context")
		}
	}

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

	// Set the selected model before API call
	client.SetModel(selectedModel)

	log.Debug().
		Str("component", "orchestrator").
		Int("worker_id", workerID).
		Str("chunk_id", work.Chunk.ID).
		Str("model", selectedModel).
		Float64("cumulative_cost", cumulativeCost).
		Msg("calling API with selected model")

	// Call API with parsing
	parsedResponse, response, err := client.AnalyzeWithParsing(ctx, work.Chunk, kbContext, prompt)

	duration := time.Since(startTime)

	// Record usage in budget tracker if we have response data
	if response != nil {
		usage := budget.UsageMetrics{
			PromptTokens:     response.PromptTokens,
			CompletionTokens: response.CompletionTokens,
			Model:            response.ModelUsed,
			Cost:             response.Cost,
			Timestamp:        time.Now(),
		}
		if recordErr := budgetTracker.RecordUsage(usage); recordErr != nil {
			log.Error().
				Str("component", "orchestrator").
				Int("worker_id", workerID).
				Str("chunk_id", work.Chunk.ID).
				Err(recordErr).
				Msg("failed to record usage in budget tracker")
		}

		// Record chunk analyzed in fallback manager
		fallbackManager.RecordChunkAnalyzed(response.ModelUsed)
	}

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
