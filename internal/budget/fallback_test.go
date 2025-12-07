package budget

import (
	"testing"
	"time"
)

func TestNewFallbackManager(t *testing.T) {
	config := DefaultFallbackConfig()
	fm := NewFallbackManager(config)

	if fm == nil {
		t.Fatal("Expected non-nil fallback manager")
	}

	if fm.GetCurrentModel() != "gpt-4o" {
		t.Errorf("Expected initial model 'gpt-4o', got '%s'", fm.GetCurrentModel())
	}

	if fm.budgetCap != 5.0 {
		t.Errorf("Expected budget cap 5.0, got %.2f", fm.budgetCap)
	}

	if fm.switchThreshold != 3.0 {
		t.Errorf("Expected switch threshold 3.0, got %.2f", fm.switchThreshold)
	}

	expectedSoftCap := 3.0 * 0.8 // 80% of switch threshold
	// Use tolerance for floating point comparison
	tolerance := 0.0001
	if fm.softCapThreshold < expectedSoftCap-tolerance || fm.softCapThreshold > expectedSoftCap+tolerance {
		t.Errorf("Expected soft cap %.4f, got %.4f", expectedSoftCap, fm.softCapThreshold)
	}
}

func TestNewFallbackManager_NilConfig(t *testing.T) {
	fm := NewFallbackManager(nil)

	if fm == nil {
		t.Fatal("Expected non-nil fallback manager with default config")
	}

	if fm.GetCurrentModel() != "gpt-4o" {
		t.Error("Expected default primary model")
	}
}

func TestSelectModel_BelowSoftCap(t *testing.T) {
	config := DefaultFallbackConfig()
	fm := NewFallbackManager(config)

	// Cost below soft cap (80% of $3.00 = $2.40)
	model := fm.SelectModel(2.0)

	if model != "gpt-4o" {
		t.Errorf("Expected 'gpt-4o' below soft cap, got '%s'", model)
	}

	if fm.GetCurrentModel() != "gpt-4o" {
		t.Error("Expected current model to remain 'gpt-4o'")
	}
}

func TestSelectModel_AtSoftCap(t *testing.T) {
	config := DefaultFallbackConfig()
	fm := NewFallbackManager(config)

	// Cost at soft cap (80% of $3.00 = $2.40)
	// Use the actual calculated soft cap to avoid floating point issues
	model := fm.SelectModel(fm.softCapThreshold)

	// Should still be on primary model
	if model != "gpt-4o" {
		t.Errorf("Expected 'gpt-4o' at soft cap, got '%s'", model)
	}

	// Soft cap warning should be logged (check state)
	if !fm.softCapWarningLogged {
		t.Error("Expected soft cap warning to be logged")
	}
}

func TestSelectModel_BetweenSoftCapAndSwitch(t *testing.T) {
	config := DefaultFallbackConfig()
	fm := NewFallbackManager(config)

	// Cost between soft cap and switch threshold
	model := fm.SelectModel(2.5)

	if model != "gpt-4o" {
		t.Errorf("Expected 'gpt-4o' between soft cap and switch, got '%s'", model)
	}

	if !fm.softCapWarningLogged {
		t.Error("Expected soft cap warning to be logged")
	}
}

func TestSelectModel_AtSwitchThreshold(t *testing.T) {
	config := DefaultFallbackConfig()
	fm := NewFallbackManager(config)

	// Cost at switch threshold ($3.00)
	model := fm.SelectModel(3.0)

	if model != "gpt-4o-mini" {
		t.Errorf("Expected 'gpt-4o-mini' at switch threshold, got '%s'", model)
	}

	if fm.GetCurrentModel() != "gpt-4o-mini" {
		t.Error("Expected current model to switch to 'gpt-4o-mini'")
	}

	// Check that transition was recorded
	fm.mu.Lock()
	transitionCount := len(fm.transitions)
	fm.mu.Unlock()

	if transitionCount != 1 {
		t.Errorf("Expected 1 transition, got %d", transitionCount)
	}
}

func TestSelectModel_AboveSwitchThreshold(t *testing.T) {
	config := DefaultFallbackConfig()
	fm := NewFallbackManager(config)

	// Cost above switch threshold
	model := fm.SelectModel(3.5)

	if model != "gpt-4o-mini" {
		t.Errorf("Expected 'gpt-4o-mini' above switch threshold, got '%s'", model)
	}
}

func TestSelectModel_AlreadyOnFallback(t *testing.T) {
	config := DefaultFallbackConfig()
	fm := NewFallbackManager(config)

	// First call to trigger switch
	fm.SelectModel(3.0)

	// Second call should not create another transition
	fm.SelectModel(3.5)

	fm.mu.Lock()
	transitionCount := len(fm.transitions)
	fm.mu.Unlock()

	if transitionCount != 1 {
		t.Errorf("Expected only 1 transition, got %d", transitionCount)
	}

	if fm.GetCurrentModel() != "gpt-4o-mini" {
		t.Error("Expected to remain on 'gpt-4o-mini'")
	}
}

func TestSelectModel_ProgressiveIncrease(t *testing.T) {
	config := DefaultFallbackConfig()
	fm := NewFallbackManager(config)

	costs := []float64{1.0, 1.5, 2.0, 2.4, 2.8, 3.0, 3.5}
	expectedModels := []string{
		"gpt-4o",      // 1.0
		"gpt-4o",      // 1.5
		"gpt-4o",      // 2.0
		"gpt-4o",      // 2.4 (soft cap)
		"gpt-4o",      // 2.8
		"gpt-4o-mini", // 3.0 (switch)
		"gpt-4o-mini", // 3.5
	}

	for i, cost := range costs {
		model := fm.SelectModel(cost)
		if model != expectedModels[i] {
			t.Errorf("At cost %.2f, expected model '%s', got '%s'",
				cost, expectedModels[i], model)
		}
	}
}

func TestRecordModelSwitch(t *testing.T) {
	config := DefaultFallbackConfig()
	fm := NewFallbackManager(config)

	fm.RecordModelSwitch("gpt-4o", "gpt-4o-mini", "manual switch", 2.5)

	if fm.GetCurrentModel() != "gpt-4o-mini" {
		t.Error("Expected current model to be updated to 'gpt-4o-mini'")
	}

	fm.mu.Lock()
	transitions := fm.transitions
	fm.mu.Unlock()

	if len(transitions) != 1 {
		t.Fatalf("Expected 1 transition, got %d", len(transitions))
	}

	transition := transitions[0]
	if transition.FromModel != "gpt-4o" {
		t.Errorf("Expected FromModel 'gpt-4o', got '%s'", transition.FromModel)
	}
	if transition.ToModel != "gpt-4o-mini" {
		t.Errorf("Expected ToModel 'gpt-4o-mini', got '%s'", transition.ToModel)
	}
	if transition.Reason != "manual switch" {
		t.Errorf("Expected reason 'manual switch', got '%s'", transition.Reason)
	}
	if transition.CostAtSwitch != 2.5 {
		t.Errorf("Expected cost 2.5, got %.2f", transition.CostAtSwitch)
	}
}

func TestRecordChunkAnalyzed(t *testing.T) {
	config := DefaultFallbackConfig()
	fm := NewFallbackManager(config)

	fm.RecordChunkAnalyzed("gpt-4o")
	fm.RecordChunkAnalyzed("gpt-4o")
	fm.RecordChunkAnalyzed("gpt-4o-mini")

	fm.mu.Lock()
	gpt4oCount := fm.modelChunkCounts["gpt-4o"]
	gpt4oMiniCount := fm.modelChunkCounts["gpt-4o-mini"]
	fm.mu.Unlock()

	if gpt4oCount != 2 {
		t.Errorf("Expected 2 chunks for gpt-4o, got %d", gpt4oCount)
	}
	if gpt4oMiniCount != 1 {
		t.Errorf("Expected 1 chunk for gpt-4o-mini, got %d", gpt4oMiniCount)
	}
}

func TestGetModelUsageReport(t *testing.T) {
	config := DefaultFallbackConfig()
	fm := NewFallbackManager(config)

	// Record some usage
	fm.RecordChunkAnalyzed("gpt-4o")
	fm.RecordChunkAnalyzed("gpt-4o")
	fm.SelectModel(3.0) // Trigger switch
	fm.RecordChunkAnalyzed("gpt-4o-mini")

	// Create mock budget status
	budgetStatus := BudgetStatus{
		CumulativeCost: 3.5,
		ModelBreakdown: map[string]ModelCost{
			"gpt-4o": {
				PromptTokens:     2000,
				CompletionTokens: 1000,
				Cost:             0.075,
				CallCount:        2,
			},
			"gpt-4o-mini": {
				PromptTokens:     1000,
				CompletionTokens: 500,
				Cost:             0.005,
				CallCount:        1,
			},
		},
	}

	report := fm.GetModelUsageReport(budgetStatus)

	if report.TotalCost != 3.5 {
		t.Errorf("Expected total cost 3.5, got %.2f", report.TotalCost)
	}

	if report.FinalModel != "gpt-4o-mini" {
		t.Errorf("Expected final model 'gpt-4o-mini', got '%s'", report.FinalModel)
	}

	if report.TotalChunks != 3 {
		t.Errorf("Expected 3 total chunks, got %d", report.TotalChunks)
	}

	if len(report.Transitions) != 1 {
		t.Errorf("Expected 1 transition, got %d", len(report.Transitions))
	}

	if len(report.ModelStats) != 2 {
		t.Errorf("Expected 2 model stats, got %d", len(report.ModelStats))
	}

	// Check model stats
	if stats, ok := report.ModelStats["gpt-4o"]; ok {
		if stats.ChunksAnalyzed != 2 {
			t.Errorf("Expected 2 chunks for gpt-4o, got %d", stats.ChunksAnalyzed)
		}
		if stats.TotalCost != 0.075 {
			t.Errorf("Expected cost 0.075 for gpt-4o, got %.6f", stats.TotalCost)
		}
	} else {
		t.Error("Expected gpt-4o in model stats")
	}
}

func TestCustomFallbackConfig(t *testing.T) {
	config := &FallbackConfig{
		BudgetCap:       10.0,
		SwitchThreshold: 6.0,
		PrimaryModel:    "gpt-4.5-preview",
		FallbackModel:   "gpt-4o",
	}

	fm := NewFallbackManager(config)

	if fm.GetCurrentModel() != "gpt-4.5-preview" {
		t.Errorf("Expected custom primary model 'gpt-4.5-preview', got '%s'", fm.GetCurrentModel())
	}

	if fm.switchThreshold != 6.0 {
		t.Errorf("Expected switch threshold 6.0, got %.2f", fm.switchThreshold)
	}

	// Test switch at custom threshold
	model := fm.SelectModel(6.0)
	if model != "gpt-4o" {
		t.Errorf("Expected switch to custom fallback 'gpt-4o', got '%s'", model)
	}
}

func TestModelTransition_Fields(t *testing.T) {
	config := DefaultFallbackConfig()
	fm := NewFallbackManager(config)

	beforeSwitch := time.Now()
	fm.SelectModel(3.0)
	afterSwitch := time.Now()

	fm.mu.Lock()
	transition := fm.transitions[0]
	fm.mu.Unlock()

	if transition.FromModel != "gpt-4o" {
		t.Error("Expected FromModel to be set correctly")
	}
	if transition.ToModel != "gpt-4o-mini" {
		t.Error("Expected ToModel to be set correctly")
	}
	if transition.Reason != "budget threshold exceeded" {
		t.Error("Expected Reason to be set correctly")
	}
	if transition.CostAtSwitch != 3.0 {
		t.Error("Expected CostAtSwitch to be set correctly")
	}
	if transition.Timestamp.Before(beforeSwitch) || transition.Timestamp.After(afterSwitch) {
		t.Error("Expected Timestamp to be set correctly")
	}
}

func TestSoftCapWarningOnlyOnce(t *testing.T) {
	config := DefaultFallbackConfig()
	fm := NewFallbackManager(config)

	// First call at soft cap
	// Use the actual calculated soft cap to avoid floating point issues
	fm.SelectModel(fm.softCapThreshold)

	if !fm.softCapWarningLogged {
		t.Error("Expected soft cap warning to be logged on first call")
	}

	// Second call at soft cap should not log again
	fm.SelectModel(fm.softCapThreshold + 0.1)

	// Verify warning was only logged once (by checking the flag remains true)
	if !fm.softCapWarningLogged {
		t.Error("Expected soft cap warning flag to remain true")
	}
}

func TestDefaultFallbackConfig_Values(t *testing.T) {
	config := DefaultFallbackConfig()

	if config.BudgetCap != 5.0 {
		t.Errorf("Expected default budget cap 5.0, got %.2f", config.BudgetCap)
	}
	if config.SwitchThreshold != 3.0 {
		t.Errorf("Expected default switch threshold 3.0, got %.2f", config.SwitchThreshold)
	}
	if config.PrimaryModel != "gpt-4o" {
		t.Errorf("Expected default primary model 'gpt-4o', got '%s'", config.PrimaryModel)
	}
	if config.FallbackModel != "gpt-4o-mini" {
		t.Errorf("Expected default fallback model 'gpt-4o-mini', got '%s'", config.FallbackModel)
	}
}
