package orchestrator

import (
	"sync"
	"time"

	"github.com/Neda-Zarei/deep-guard/internal/chunker"
	"github.com/Neda-Zarei/deep-guard/pkg/types"
)

// WorkItem represents a code chunk to be analyzed
type WorkItem struct {
	Chunk      chunker.CodeChunk
	VulnType   string // Vulnerability type to scan for
	KBEntries  interface{} // KB context entries (type depends on implementation)
	Prompt     string // Rendered prompt for this chunk
}

// WorkResult represents the result of analyzing a single chunk
type WorkResult struct {
	ChunkID    string
	FilePath   string
	Findings   []types.Finding
	Duration   time.Duration
	TokensUsed int
	Cost       float64
	Success    bool
	Error      error
}

// ErrorTracker tracks failed chunks and determines when to stop due to excessive errors
type ErrorTracker struct {
	mu                sync.Mutex
	failedChunks      []string // IDs of failed chunks
	consecutiveFails  int
	errorThreshold    int // Max consecutive failures before stopping
}

// NewErrorTracker creates a new error tracker with the specified threshold
func NewErrorTracker(threshold int) *ErrorTracker {
	if threshold <= 0 {
		threshold = 10 // Default to 10 consecutive failures
	}
	return &ErrorTracker{
		failedChunks:     make([]string, 0),
		errorThreshold:   threshold,
		consecutiveFails: 0,
	}
}

// RecordFailure records a failed chunk analysis
func (et *ErrorTracker) RecordFailure(chunkID string) {
	et.mu.Lock()
	defer et.mu.Unlock()

	et.failedChunks = append(et.failedChunks, chunkID)
	et.consecutiveFails++
}

// RecordSuccess resets the consecutive failure counter
func (et *ErrorTracker) RecordSuccess() {
	et.mu.Lock()
	defer et.mu.Unlock()

	et.consecutiveFails = 0
}

// ShouldStop returns true if error threshold exceeded
func (et *ErrorTracker) ShouldStop() bool {
	et.mu.Lock()
	defer et.mu.Unlock()

	return et.consecutiveFails >= et.errorThreshold
}

// GetStats returns error statistics
// Returns: totalFailed, consecutiveFails, threshold
func (et *ErrorTracker) GetStats() (int, int, int) {
	et.mu.Lock()
	defer et.mu.Unlock()

	return len(et.failedChunks), et.consecutiveFails, et.errorThreshold
}

// ProgressTracker tracks analysis progress and provides periodic updates
type ProgressTracker struct {
	mu                 sync.Mutex
	totalChunks        int
	processedChunks    int
	findingsCount      int
	lastReportTime     time.Time
	lastReportChunks   int
	reportInterval     time.Duration // Report every N seconds
	reportChunkStep    int           // Report every N chunks
}

// NewProgressTracker creates a new progress tracker
func NewProgressTracker(totalChunks int) *ProgressTracker {
	return &ProgressTracker{
		totalChunks:      totalChunks,
		processedChunks:  0,
		findingsCount:    0,
		lastReportTime:   time.Now(),
		lastReportChunks: 0,
		reportInterval:   30 * time.Second,
		reportChunkStep:  10,
	}
}

// RecordChunk records that a chunk was processed
func (pt *ProgressTracker) RecordChunk(findingsCount int) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	pt.processedChunks++
	pt.findingsCount += findingsCount
}

// ShouldReport returns true if it's time to report progress
func (pt *ProgressTracker) ShouldReport() bool {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	chunksSinceReport := pt.processedChunks - pt.lastReportChunks
	timeSinceReport := time.Since(pt.lastReportTime)

	return chunksSinceReport >= pt.reportChunkStep || timeSinceReport >= pt.reportInterval
}

// MarkReported marks that progress was just reported
func (pt *ProgressTracker) MarkReported() {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	pt.lastReportTime = time.Now()
	pt.lastReportChunks = pt.processedChunks
}

// GetStats returns current progress statistics
// Returns: processed, total, findings
func (pt *ProgressTracker) GetStats() (int, int, int) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	return pt.processedChunks, pt.totalChunks, pt.findingsCount
}

// GetPercentage returns the completion percentage
func (pt *ProgressTracker) GetPercentage() float64 {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	if pt.totalChunks == 0 {
		return 0.0
	}
	return (float64(pt.processedChunks) / float64(pt.totalChunks)) * 100.0
}

// OrchestratorConfig holds configuration for the analysis orchestrator
type OrchestratorConfig struct {
	WorkerCount      int     // Number of concurrent workers (default: 5)
	BudgetCap        float64 // Budget cap in USD (default: 5.0)
	ErrorThreshold   int     // Max consecutive errors before stopping (default: 10)
	WorkChannelSize  int     // Size of work channel buffer (default: 100)
	ResultChannelSize int     // Size of result channel buffer (default: 100)
}

// DefaultConfig returns the default orchestrator configuration
func DefaultConfig() *OrchestratorConfig {
	return &OrchestratorConfig{
		WorkerCount:       5,
		BudgetCap:         5.0,
		ErrorThreshold:    10,
		WorkChannelSize:   100,
		ResultChannelSize: 100,
	}
}
