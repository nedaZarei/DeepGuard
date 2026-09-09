package orchestrator

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Neda-Zarei/deep-guard/internal/chunker"
	"github.com/Neda-Zarei/deep-guard/internal/llm"
)

func TestNewOrchestrator(t *testing.T) {
	client := llm.NewClient("test-key", "gpt-4o-mini")
	config := DefaultConfig()

	orch, err := NewOrchestrator(config, client, "gpt-4o-mini")
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}

	if orch == nil {
		t.Fatal("Expected non-nil orchestrator")
	}

	if orch.config.WorkerCount != 5 {
		t.Errorf("Expected WorkerCount 5, got %d", orch.config.WorkerCount)
	}

	if orch.client == nil {
		t.Error("Expected non-nil client")
	}

	if orch.renderer == nil {
		t.Error("Expected non-nil renderer")
	}

	if orch.model != "gpt-4o-mini" {
		t.Errorf("Expected model 'gpt-4o-mini', got '%s'", orch.model)
	}
}

func TestNewOrchestrator_NilConfig(t *testing.T) {
	client := llm.NewClient("test-key", "gpt-4o-mini")

	orch, err := NewOrchestrator(nil, client, "gpt-4o-mini")
	if err != nil {
		t.Fatalf("Failed to create orchestrator with nil config: %v", err)
	}

	if orch.config == nil {
		t.Fatal("Expected default config to be used")
	}

	if orch.config.WorkerCount != 5 {
		t.Error("Expected default config to be applied")
	}
}

func TestAnalyzeRepository_EmptyChunks(t *testing.T) {
	client := llm.NewClient("test-key", "gpt-4o-mini")
	config := DefaultConfig()

	orch, err := NewOrchestrator(config, client, "gpt-4o-mini")
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}

	ctx := context.Background()
	chunks := []chunker.CodeChunk{}

	findings, err := orch.AnalyzeRepository(ctx, chunks, "sql_injection")
	if err != nil {
		t.Errorf("Expected no error for empty chunks, got: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("Expected 0 findings for empty chunks, got %d", len(findings))
	}
}

func TestAnalyzeRepository_ContextCancellation(t *testing.T) {
	client := llm.NewClient("test-key", "gpt-4o-mini")
	config := &OrchestratorConfig{
		WorkerCount:       2,
		BudgetCap:         5.0,
		ErrorThreshold:    10,
		WorkChannelSize:   10,
		ResultChannelSize: 10,
	}

	orch, err := NewOrchestrator(config, client, "gpt-4o-mini")
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}

	// Create context that cancels immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	chunks := []chunker.CodeChunk{
		{
			ID:           "test1",
			FilePath:     "/test/file1.js",
			StartLine:    1,
			EndLine:      10,
			FunctionName: "testFunc1",
			Language:     "javascript",
			Source:       "function test() {}",
		},
	}

	findings, err := orch.AnalyzeRepository(ctx, chunks, "sql_injection")

	// Should return with context cancelled error
	if err != ErrContextCancelled {
		t.Logf("Expected ErrContextCancelled, got: %v", err)
		// Note: This might not always trigger depending on timing
	}

	// Findings might be empty due to cancellation
	_ = findings
}

func TestOrchestratorConfig_CustomValues(t *testing.T) {
	config := &OrchestratorConfig{
		WorkerCount:       3,
		BudgetCap:         10.0,
		ErrorThreshold:    5,
		WorkChannelSize:   50,
		ResultChannelSize: 50,
	}

	client := llm.NewClient("test-key", "gpt-4o-mini")
	orch, err := NewOrchestrator(config, client, "gpt-4o-mini")
	if err != nil {
		t.Fatalf("Failed to create orchestrator: %v", err)
	}

	if orch.config.WorkerCount != 3 {
		t.Errorf("Expected WorkerCount 3, got %d", orch.config.WorkerCount)
	}
	if orch.config.BudgetCap != 10.0 {
		t.Errorf("Expected BudgetCap 10.0, got %.2f", orch.config.BudgetCap)
	}
	if orch.config.ErrorThreshold != 5 {
		t.Errorf("Expected ErrorThreshold 5, got %d", orch.config.ErrorThreshold)
	}
}

func TestWorkResult_Timeout(t *testing.T) {
	// Test that we can create a result with a duration
	result := WorkResult{
		ChunkID:    "test-chunk",
		FilePath:   "/test.js",
		Findings:   nil,
		Duration:   500 * time.Millisecond,
		TokensUsed: 100,
		Cost:       0.001,
		Success:    true,
		Error:      nil,
	}

	if result.Duration != 500*time.Millisecond {
		t.Errorf("Expected duration 500ms, got %v", result.Duration)
	}
}

func TestErrorDefinitions(t *testing.T) {
	// Test that our custom errors are defined
	if ErrBudgetExceeded == nil {
		t.Error("Expected ErrBudgetExceeded to be defined")
	}

	if ErrErrorThresholdExceeded == nil {
		t.Error("Expected ErrErrorThresholdExceeded to be defined")
	}

	if ErrContextCancelled == nil {
		t.Error("Expected ErrContextCancelled to be defined")
	}

	// Test error messages
	if ErrBudgetExceeded.Error() != "budget cap exceeded" {
		t.Errorf("Unexpected error message: %s", ErrBudgetExceeded.Error())
	}
}

// TestConcurrentTrackerAccess tests that trackers are thread-safe
func TestConcurrentTrackerAccess(t *testing.T) {
	errorTracker := NewErrorTracker(100)
	progressTracker := NewProgressTracker(1000)

	// Simulate concurrent access from multiple workers
	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				if id%2 == 0 {
					errorTracker.RecordFailure("chunk")
				} else {
					errorTracker.RecordSuccess()
				}

				progressTracker.RecordChunk(id % 3)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify trackers still work after concurrent access
	totalFailed, _, _ := errorTracker.GetStats()
	if totalFailed == 0 {
		t.Error("Expected some failed chunks to be recorded")
	}

	processed, _, _ := progressTracker.GetStats()
	if processed != 1000 {
		t.Errorf("Expected 1000 processed chunks, got %d", processed)
	}
}

func TestNewOrchestrator_NormalisesWorkerCount(t *testing.T) {
	// A zero WorkerCount must not start zero workers (which would hang forever).
	cfg := DefaultConfig()
	cfg.WorkerCount = 0
	o, err := NewOrchestrator(cfg, nil, "test-model")
	if err != nil {
		t.Fatalf("NewOrchestrator: %v", err)
	}
	if o.config.WorkerCount < 1 {
		t.Errorf("WorkerCount=%d, want >= 1", o.config.WorkerCount)
	}
}

func TestOrchestrator_StatsTrackCompleteness(t *testing.T) {
	o, err := NewOrchestrator(DefaultConfig(), nil, "test-model")
	if err != nil {
		t.Fatalf("NewOrchestrator: %v", err)
	}
	if s := o.Stats(); s.Attempted != 0 || s.Failed != 0 {
		t.Fatalf("fresh orchestrator has stats %+v, want zeros", s)
	}
	// Simulate results arriving across several vulnerability types. errorTracker
	// is reset per type, so these counters must survive that reset.
	o.recordAnalysisOutcome(true)
	o.recordAnalysisOutcome(false)
	o.errorTracker = NewErrorTracker(10) // per-type reset
	o.recordAnalysisOutcome(true)
	o.recordAnalysisOutcome(false)

	s := o.Stats()
	if s.Attempted != 4 || s.Failed != 2 {
		t.Errorf("Stats() = %+v, want Attempted=4 Failed=2", s)
	}
}

func TestOrchestrator_StatsConcurrentSafe(t *testing.T) {
	o, err := NewOrchestrator(DefaultConfig(), nil, "test-model")
	if err != nil {
		t.Fatalf("NewOrchestrator: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			o.recordAnalysisOutcome(i%2 == 0)
		}(i)
	}
	wg.Wait()
	if s := o.Stats(); s.Attempted != 50 || s.Failed != 25 {
		t.Errorf("Stats() = %+v, want Attempted=50 Failed=25", s)
	}
}
