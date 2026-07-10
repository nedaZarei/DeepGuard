package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/Neda-Zarei/deep-guard/internal/budget"
	"github.com/Neda-Zarei/deep-guard/internal/chunker"
	"github.com/Neda-Zarei/deep-guard/internal/llm"
	"github.com/Neda-Zarei/deep-guard/internal/rag"
	"github.com/Neda-Zarei/deep-guard/pkg/types"
	"github.com/rs/zerolog/log"
)

var (
	// ErrBudgetExceeded is returned when the budget cap is exceeded
	ErrBudgetExceeded = errors.New("budget cap exceeded")

	// ErrErrorThresholdExceeded is returned when too many consecutive errors occur
	ErrErrorThresholdExceeded = errors.New("error threshold exceeded")

	// ErrContextCancelled is returned when the context is cancelled
	ErrContextCancelled = errors.New("context cancelled")
)

// Orchestrator coordinates concurrent vulnerability analysis across multiple workers
type Orchestrator struct {
	config          *OrchestratorConfig
	client          *llm.Client
	renderer        *llm.PromptRenderer
	model           string // Model name for progress reporting
	budgetTracker   *budget.BudgetTracker
	fallbackManager *budget.FallbackManager
	errorTracker    *ErrorTracker
	progressTracker *ProgressTracker
	retriever       *rag.Retriever
}

// SetRetriever attaches a RAG retriever to the orchestrator for KB context injection.
func (o *Orchestrator) SetRetriever(r *rag.Retriever) {
	o.retriever = r
}

// NewOrchestrator creates a new analysis orchestrator
func NewOrchestrator(config *OrchestratorConfig, client *llm.Client, model string) (*Orchestrator, error) {
	if config == nil {
		config = DefaultConfig()
	}

	// Create prompt renderer
	renderer, err := llm.NewPromptRenderer()
	if err != nil {
		return nil, fmt.Errorf("failed to create prompt renderer: %w", err)
	}

	// Create budget tracker
	budgetTracker := budget.NewBudgetTracker(config.BudgetCap)

	// Create fallback manager with default config
	fallbackConfig := budget.DefaultFallbackConfig()
	fallbackConfig.BudgetCap = config.BudgetCap
	fallbackManager := budget.NewFallbackManager(fallbackConfig)

	return &Orchestrator{
		config:          config,
		client:          client,
		renderer:        renderer,
		model:           model,
		budgetTracker:   budgetTracker,
		fallbackManager: fallbackManager,
	}, nil
}

// AnalyzeRepository analyzes all code chunks concurrently and returns aggregated findings
func (o *Orchestrator) AnalyzeRepository(
	ctx context.Context,
	chunks []chunker.CodeChunk,
	vulnType string,
) ([]types.Finding, error) {
	if len(chunks) == 0 {
		log.Warn().
			Str("component", "orchestrator").
			Msg("no chunks to analyze")
		return []types.Finding{}, nil
	}

	log.Info().
		Str("component", "orchestrator").
		Int("total_chunks", len(chunks)).
		Int("workers", o.config.WorkerCount).
		Float64("budget_cap", o.config.BudgetCap).
		Str("vuln_type", vulnType).
		Msg("starting concurrent analysis")

	// Initialize trackers
	o.errorTracker = NewErrorTracker(o.config.ErrorThreshold)
	o.progressTracker = NewProgressTracker(len(chunks))

	// Create channels
	workChan := make(chan WorkItem, o.config.WorkChannelSize)
	resultsChan := make(chan WorkResult, o.config.ResultChannelSize)

	// Create cancellable context for workers
	workerCtx, cancelWorkers := context.WithCancel(ctx)
	defer cancelWorkers()

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < o.config.WorkerCount; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			analyzeWorker(
				workerCtx,
				workerID,
				o.client,
				o.renderer,
				o.retriever,
				workChan,
				resultsChan,
				o.budgetTracker,
				o.fallbackManager,
				o.errorTracker,
				o.progressTracker,
			)
		}(i)
	}

	// Start result collector
	allFindings := make([]types.Finding, 0)
	var findingsMu sync.Mutex
	var collectorWg sync.WaitGroup
	collectorWg.Add(1)

	go func() {
		defer collectorWg.Done()
		for result := range resultsChan {
			// Report per-chunk metrics
			ReportWorkerMetrics(&result)

			// Aggregate findings
			if result.Success && len(result.Findings) > 0 {
				findingsMu.Lock()
				allFindings = append(allFindings, result.Findings...)
				findingsMu.Unlock()
			}

			// Report progress periodically
			if o.progressTracker.ShouldReport() {
				ReportProgress(o.progressTracker, o.client.GetTracker(), o.model)
			}

			// Check for stop conditions
			if o.errorTracker.ShouldStop() {
				log.Error().
					Str("component", "orchestrator").
					Msg("stopping due to error threshold exceeded")
				cancelWorkers()
				return
			}

			if o.client.ExceedsBudget(o.config.BudgetCap) {
				log.Warn().
					Str("component", "orchestrator").
					Float64("budget_cap", o.config.BudgetCap).
					Msg("stopping due to budget cap exceeded")
				cancelWorkers()
				return
			}
		}
	}()

	// Distribute work to workers
	go func() {
		for _, chunk := range chunks {
			select {
			case <-workerCtx.Done():
				// Context cancelled, stop distributing work
				log.Debug().
					Str("component", "orchestrator").
					Msg("stopping work distribution due to context cancellation")
				close(workChan)
				return
			case workChan <- WorkItem{
				Chunk:    chunk,
				VulnType: vulnType,
			}:
				// Work item sent successfully
			}
		}
		// All work distributed, close channel
		close(workChan)
	}()

	// Wait for all workers to finish
	wg.Wait()

	// Close results channel and wait for collector
	close(resultsChan)
	collectorWg.Wait()

	// Report final statistics
	processed, total, findingsCount := o.progressTracker.GetStats()
	ReportFinalStats(total, processed, findingsCount, o.client.GetTracker(), o.errorTracker)

	// Report model usage
	budgetStatus := o.budgetTracker.GetCurrentStatus()
	modelUsageReport := o.fallbackManager.GetModelUsageReport(budgetStatus)
	budget.LogModelUsageReport(modelUsageReport)

	// Check if we stopped early due to errors
	if o.errorTracker.ShouldStop() {
		return allFindings, ErrErrorThresholdExceeded
	}

	// Check if context was cancelled
	select {
	case <-ctx.Done():
		return allFindings, ErrContextCancelled
	default:
	}

	return allFindings, nil
}

// AnalyzeRepositoryAllTypes analyzes all code chunks for all vulnerability types
func (o *Orchestrator) AnalyzeRepositoryAllTypes(
	ctx context.Context,
	chunks []chunker.CodeChunk,
) ([]types.Finding, error) {
	// Vulnerability types to scan for
	vulnTypes := []string{
		string(llm.VulnTypeSQLInjection),
		string(llm.VulnTypeXSS),
		string(llm.VulnTypePathTraversal),
		string(llm.VulnTypeInsecureDeserialization),
		string(llm.VulnTypeAuthIssue),
		string(llm.VulnTypeCryptoIssue),
		string(llm.VulnTypeCommandInjection),
		string(llm.VulnTypeSSRF),
		string(llm.VulnTypeXXEInjection),
	}

	allFindings := make([]types.Finding, 0)

	for _, vulnType := range vulnTypes {
		log.Info().
			Str("component", "orchestrator").
			Str("vuln_type", vulnType).
			Msg("scanning for vulnerability type")

		findings, err := o.AnalyzeRepository(ctx, chunks, vulnType)
		if err != nil {
			// Continue with other vulnerability types even if one fails
			log.Error().
				Str("component", "orchestrator").
				Str("vuln_type", vulnType).
				Err(err).
				Msg("analysis failed for vulnerability type, continuing with others")
			continue
		}

		allFindings = append(allFindings, findings...)

		// Check budget after each vulnerability type
		if o.client.ExceedsBudget(o.config.BudgetCap) {
			log.Warn().
				Str("component", "orchestrator").
				Float64("budget_cap", o.config.BudgetCap).
				Msg("budget cap exceeded, stopping analysis")
			break
		}
	}

	deduplicated := deduplicateFindings(allFindings)
	log.Info().
		Str("component", "orchestrator").
		Int("before", len(allFindings)).
		Int("after", len(deduplicated)).
		Msg("deduplication complete")

	return deduplicated, nil
}

// deduplicateFindings removes duplicate findings of the same vulnerability type in the same
// file at nearly the same line. Within each (file, type) group, findings whose absolute line
// numbers are within 3 lines of the previous kept finding are merged — keeping the one with
// the highest confidence score. The window is 3 to only collapse findings on the same
// statement (e.g. a multi-line expression). Line attribution is now exact (numbered source),
// so a wide window is no longer needed and would collapse distinct nearby vulnerabilities.
func deduplicateFindings(findings []types.Finding) []types.Finding {
	if len(findings) == 0 {
		return findings
	}

	type groupKey struct {
		file     string
		vulnType string
	}

	groups := make(map[groupKey][]types.Finding)
	for _, f := range findings {
		k := groupKey{file: f.FilePath, vulnType: f.Type}
		groups[k] = append(groups[k], f)
	}

	result := make([]types.Finding, 0, len(findings))
	for _, group := range groups {
		sort.Slice(group, func(i, j int) bool {
			return group[i].AbsoluteLine < group[j].AbsoluteLine
		})

		merged := group[:1]
		for _, f := range group[1:] {
			last := &merged[len(merged)-1]
			if f.AbsoluteLine-last.AbsoluteLine <= 3 {
				if f.Confidence > last.Confidence {
					*last = f
				}
			} else {
				merged = append(merged, f)
			}
		}
		result = append(result, merged...)
	}

	return result
}
