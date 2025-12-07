package orchestrator

import (
	"testing"
	"time"
)

func TestNewErrorTracker(t *testing.T) {
	tracker := NewErrorTracker(5)

	if tracker == nil {
		t.Fatal("Expected non-nil tracker")
	}

	totalFailed, consecutiveFails, threshold := tracker.GetStats()
	if totalFailed != 0 {
		t.Errorf("Expected 0 failed chunks, got %d", totalFailed)
	}
	if consecutiveFails != 0 {
		t.Errorf("Expected 0 consecutive fails, got %d", consecutiveFails)
	}
	if threshold != 5 {
		t.Errorf("Expected threshold 5, got %d", threshold)
	}
}

func TestNewErrorTracker_DefaultThreshold(t *testing.T) {
	tracker := NewErrorTracker(0)

	_, _, threshold := tracker.GetStats()
	if threshold != 10 {
		t.Errorf("Expected default threshold 10, got %d", threshold)
	}
}

func TestErrorTracker_RecordFailure(t *testing.T) {
	tracker := NewErrorTracker(3)

	tracker.RecordFailure("chunk1")
	tracker.RecordFailure("chunk2")

	totalFailed, consecutiveFails, _ := tracker.GetStats()
	if totalFailed != 2 {
		t.Errorf("Expected 2 failed chunks, got %d", totalFailed)
	}
	if consecutiveFails != 2 {
		t.Errorf("Expected 2 consecutive fails, got %d", consecutiveFails)
	}
}

func TestErrorTracker_RecordSuccess(t *testing.T) {
	tracker := NewErrorTracker(3)

	tracker.RecordFailure("chunk1")
	tracker.RecordFailure("chunk2")
	tracker.RecordSuccess()

	totalFailed, consecutiveFails, _ := tracker.GetStats()
	if totalFailed != 2 {
		t.Errorf("Expected 2 total failed chunks, got %d", totalFailed)
	}
	if consecutiveFails != 0 {
		t.Errorf("Expected 0 consecutive fails after success, got %d", consecutiveFails)
	}
}

func TestErrorTracker_ShouldStop(t *testing.T) {
	tracker := NewErrorTracker(3)

	// Should not stop initially
	if tracker.ShouldStop() {
		t.Error("Expected ShouldStop to be false initially")
	}

	// Record failures up to threshold
	tracker.RecordFailure("chunk1")
	tracker.RecordFailure("chunk2")

	if tracker.ShouldStop() {
		t.Error("Expected ShouldStop to be false before threshold")
	}

	// Exceed threshold
	tracker.RecordFailure("chunk3")

	if !tracker.ShouldStop() {
		t.Error("Expected ShouldStop to be true after threshold exceeded")
	}
}

func TestErrorTracker_ShouldStopResetBySuccess(t *testing.T) {
	tracker := NewErrorTracker(3)

	tracker.RecordFailure("chunk1")
	tracker.RecordFailure("chunk2")
	tracker.RecordSuccess()
	tracker.RecordFailure("chunk3")
	tracker.RecordFailure("chunk4")

	// Should not stop because success reset the consecutive counter
	if tracker.ShouldStop() {
		t.Error("Expected ShouldStop to be false after success reset")
	}
}

func TestNewProgressTracker(t *testing.T) {
	tracker := NewProgressTracker(100)

	if tracker == nil {
		t.Fatal("Expected non-nil tracker")
	}

	processed, total, findings := tracker.GetStats()
	if processed != 0 {
		t.Errorf("Expected 0 processed, got %d", processed)
	}
	if total != 100 {
		t.Errorf("Expected total 100, got %d", total)
	}
	if findings != 0 {
		t.Errorf("Expected 0 findings, got %d", findings)
	}
}

func TestProgressTracker_RecordChunk(t *testing.T) {
	tracker := NewProgressTracker(100)

	tracker.RecordChunk(3)
	tracker.RecordChunk(0)
	tracker.RecordChunk(5)

	processed, _, findings := tracker.GetStats()
	if processed != 3 {
		t.Errorf("Expected 3 processed chunks, got %d", processed)
	}
	if findings != 8 {
		t.Errorf("Expected 8 findings (3+0+5), got %d", findings)
	}
}

func TestProgressTracker_GetPercentage(t *testing.T) {
	tracker := NewProgressTracker(100)

	percentage := tracker.GetPercentage()
	if percentage != 0.0 {
		t.Errorf("Expected 0%% initially, got %.2f%%", percentage)
	}

	for i := 0; i < 50; i++ {
		tracker.RecordChunk(0)
	}

	percentage = tracker.GetPercentage()
	if percentage != 50.0 {
		t.Errorf("Expected 50%%, got %.2f%%", percentage)
	}
}

func TestProgressTracker_GetPercentage_ZeroTotal(t *testing.T) {
	tracker := NewProgressTracker(0)

	percentage := tracker.GetPercentage()
	if percentage != 0.0 {
		t.Errorf("Expected 0%% for zero total, got %.2f%%", percentage)
	}
}

func TestProgressTracker_ShouldReport_ChunkThreshold(t *testing.T) {
	tracker := NewProgressTracker(100)

	// Should not report initially
	if tracker.ShouldReport() {
		t.Error("Expected ShouldReport to be false initially")
	}

	// Process chunks up to threshold (10)
	for i := 0; i < 9; i++ {
		tracker.RecordChunk(0)
	}

	if tracker.ShouldReport() {
		t.Error("Expected ShouldReport to be false before threshold")
	}

	// Reach threshold
	tracker.RecordChunk(0)

	if !tracker.ShouldReport() {
		t.Error("Expected ShouldReport to be true at threshold")
	}

	// Mark as reported and verify it resets
	tracker.MarkReported()

	if tracker.ShouldReport() {
		t.Error("Expected ShouldReport to be false after MarkReported")
	}
}

func TestProgressTracker_ShouldReport_TimeThreshold(t *testing.T) {
	tracker := NewProgressTracker(100)
	tracker.reportInterval = 100 * time.Millisecond

	// Should not report initially
	if tracker.ShouldReport() {
		t.Error("Expected ShouldReport to be false initially")
	}

	// Wait for time interval
	time.Sleep(150 * time.Millisecond)

	if !tracker.ShouldReport() {
		t.Error("Expected ShouldReport to be true after time interval")
	}
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config == nil {
		t.Fatal("Expected non-nil config")
	}

	if config.WorkerCount != 5 {
		t.Errorf("Expected WorkerCount 5, got %d", config.WorkerCount)
	}
	if config.BudgetCap != 5.0 {
		t.Errorf("Expected BudgetCap 5.0, got %.2f", config.BudgetCap)
	}
	if config.ErrorThreshold != 10 {
		t.Errorf("Expected ErrorThreshold 10, got %d", config.ErrorThreshold)
	}
	if config.WorkChannelSize != 100 {
		t.Errorf("Expected WorkChannelSize 100, got %d", config.WorkChannelSize)
	}
	if config.ResultChannelSize != 100 {
		t.Errorf("Expected ResultChannelSize 100, got %d", config.ResultChannelSize)
	}
}

func TestWorkResult_Success(t *testing.T) {
	result := WorkResult{
		ChunkID:    "abc123",
		FilePath:   "/test/file.js",
		Findings:   nil,
		Duration:   100 * time.Millisecond,
		TokensUsed: 500,
		Cost:       0.01,
		Success:    true,
		Error:      nil,
	}

	if !result.Success {
		t.Error("Expected Success to be true")
	}
	if result.Error != nil {
		t.Error("Expected Error to be nil for successful result")
	}
}

func TestWorkResult_Failure(t *testing.T) {
	result := WorkResult{
		ChunkID:  "abc123",
		FilePath: "/test/file.js",
		Findings: nil,
		Duration: 50 * time.Millisecond,
		Success:  false,
		Error:    ErrBudgetExceeded,
	}

	if result.Success {
		t.Error("Expected Success to be false")
	}
	if result.Error == nil {
		t.Error("Expected Error to be non-nil for failed result")
	}
}
