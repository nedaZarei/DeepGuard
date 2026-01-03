package reporting

import (
	"io"
	"testing"

	"github.com/Neda-Zarei/deep-guard/internal/chunker"
	"github.com/Neda-Zarei/deep-guard/internal/report"
	"github.com/Neda-Zarei/deep-guard/internal/suppression"
	"github.com/rs/zerolog"
)

func TestFilterSuppressedFindings_NoSuppressions(t *testing.T) {
	logger := zerolog.New(io.Discard)

	findings := []report.Finding{
		{ID: "1", Type: "sql_injection", File: "test.js", Line: 10, Message: "test", FunctionName: "testFunc"},
		{ID: "2", Type: "xss", File: "test.js", Line: 20, Message: "test", FunctionName: "testFunc"},
	}

	chunks := map[string]chunker.CodeChunk{
		"testFunc": {
			StartLine:       5,
			EndLine:         25,
			SuppressedLines: []suppression.SuppressionInfo{}, // No suppressions
		},
	}

	filtered, stats := FilterSuppressedFindings(findings, chunks, logger)

	if len(filtered) != 2 {
		t.Errorf("Expected 2 findings, got %d", len(filtered))
	}

	if stats.TotalFindings != 2 {
		t.Errorf("Expected total_findings 2, got %d", stats.TotalFindings)
	}

	if stats.SuppressedFindings != 0 {
		t.Errorf("Expected suppressed_findings 0, got %d", stats.SuppressedFindings)
	}

	if stats.KeptFindings != 2 {
		t.Errorf("Expected kept_findings 2, got %d", stats.KeptFindings)
	}
}

func TestFilterSuppressedFindings_SameLineSuppression(t *testing.T) {
	logger := zerolog.New(io.Discard)

	findings := []report.Finding{
		{ID: "1", Type: "sql_injection", File: "test.js", Line: 10, Message: "test", FunctionName: "testFunc"},
		{ID: "2", Type: "xss", File: "test.js", Line: 20, Message: "test", FunctionName: "testFunc"},
	}

	chunks := map[string]chunker.CodeChunk{
		"testFunc": {
			StartLine: 5,
			EndLine:   25,
			SuppressedLines: []suppression.SuppressionInfo{
				{Line: 10, Type: "all", AppliesTo: "same", SourceLine: 10}, // Suppress line 10
			},
		},
	}

	filtered, stats := FilterSuppressedFindings(findings, chunks, logger)

	// Should keep only the XSS finding (line 20)
	if len(filtered) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(filtered))
	}

	if filtered[0].ID != "2" {
		t.Errorf("Expected finding ID '2', got '%s'", filtered[0].ID)
	}

	if stats.SuppressedFindings != 1 {
		t.Errorf("Expected 1 suppressed finding, got %d", stats.SuppressedFindings)
	}
}

func TestFilterSuppressedFindings_TypeSpecific(t *testing.T) {
	logger := zerolog.New(io.Discard)

	findings := []report.Finding{
		{ID: "1", Type: "sql_injection", File: "test.js", Line: 10, Message: "test", FunctionName: "testFunc"},
		{ID: "2", Type: "xss", File: "test.js", Line: 10, Message: "test", FunctionName: "testFunc"},
	}

	chunks := map[string]chunker.CodeChunk{
		"testFunc": {
			StartLine: 5,
			EndLine:   25,
			SuppressedLines: []suppression.SuppressionInfo{
				{Line: 10, Type: "sql_injection", AppliesTo: "same", SourceLine: 10}, // Only suppress SQL injection
			},
		},
	}

	filtered, stats := FilterSuppressedFindings(findings, chunks, logger)

	// Should keep only the XSS finding
	if len(filtered) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(filtered))
	}

	if filtered[0].Type != "xss" {
		t.Errorf("Expected XSS finding, got '%s'", filtered[0].Type)
	}

	if stats.SuppressedFindings != 1 {
		t.Errorf("Expected 1 suppressed finding, got %d", stats.SuppressedFindings)
	}
}

func TestFilterSuppressedFindings_WithJustification(t *testing.T) {
	logger := zerolog.New(io.Discard)

	findings := []report.Finding{
		{ID: "1", Type: "sql_injection", File: "test.js", Line: 10, Message: "test", FunctionName: "testFunc"},
	}

	chunks := map[string]chunker.CodeChunk{
		"testFunc": {
			StartLine: 5,
			EndLine:   25,
			SuppressedLines: []suppression.SuppressionInfo{
				{
					Line:          10,
					Type:          "all",
					AppliesTo:     "same",
					SourceLine:    10,
					Justification: "false positive: validated upstream",
				},
			},
		},
	}

	filtered, stats := FilterSuppressedFindings(findings, chunks, logger)

	if len(filtered) != 0 {
		t.Errorf("Expected 0 findings, got %d", len(filtered))
	}

	if stats.SuppressedFindings != 1 {
		t.Errorf("Expected 1 suppressed finding, got %d", stats.SuppressedFindings)
	}
}

func TestFilterSuppressedFindings_MultipleChunks(t *testing.T) {
	logger := zerolog.New(io.Discard)

	findings := []report.Finding{
		{ID: "1", Type: "sql_injection", File: "test.js", Line: 10, Message: "test", FunctionName: "func1"},
		{ID: "2", Type: "xss", File: "test.js", Line: 20, Message: "test", FunctionName: "func2"},
		{ID: "3", Type: "sqli", File: "test.js", Line: 30, Message: "test", FunctionName: "func3"},
	}

	chunks := map[string]chunker.CodeChunk{
		"func1": {
			StartLine: 5,
			EndLine:   15,
			SuppressedLines: []suppression.SuppressionInfo{
				{Line: 10, Type: "all", AppliesTo: "same", SourceLine: 10},
			},
		},
		"func2": {
			StartLine:       16,
			EndLine:         25,
			SuppressedLines: []suppression.SuppressionInfo{}, // No suppressions
		},
		"func3": {
			StartLine: 26,
			EndLine:   35,
			SuppressedLines: []suppression.SuppressionInfo{
				{Line: 30, Type: "sqli", AppliesTo: "same", SourceLine: 30},
			},
		},
	}

	filtered, stats := FilterSuppressedFindings(findings, chunks, logger)

	// Should keep only func2's finding
	if len(filtered) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(filtered))
	}

	if filtered[0].FunctionName != "func2" {
		t.Errorf("Expected finding from func2, got '%s'", filtered[0].FunctionName)
	}

	if stats.SuppressedFindings != 2 {
		t.Errorf("Expected 2 suppressed findings, got %d", stats.SuppressedFindings)
	}
}

func TestFilterSuppressedFindings_ChunkNotFound(t *testing.T) {
	logger := zerolog.New(io.Discard)

	findings := []report.Finding{
		{ID: "1", Type: "sql_injection", File: "test.js", Line: 10, Message: "test", FunctionName: "unknownFunc"},
	}

	chunks := map[string]chunker.CodeChunk{
		// Chunk for "unknownFunc" doesn't exist
	}

	filtered, stats := FilterSuppressedFindings(findings, chunks, logger)

	// Should keep the finding when chunk not found
	if len(filtered) != 1 {
		t.Errorf("Expected 1 finding when chunk not found, got %d", len(filtered))
	}

	if stats.SuppressedFindings != 0 {
		t.Errorf("Expected 0 suppressed findings, got %d", stats.SuppressedFindings)
	}
}

func TestFilterSuppressedFindings_NextLineSuppression(t *testing.T) {
	logger := zerolog.New(io.Discard)

	findings := []report.Finding{
		{ID: "1", Type: "sql_injection", File: "test.js", Line: 11, Message: "test", FunctionName: "testFunc"},
		{ID: "2", Type: "xss", File: "test.js", Line: 10, Message: "test", FunctionName: "testFunc"},
	}

	chunks := map[string]chunker.CodeChunk{
		"testFunc": {
			StartLine: 5,
			EndLine:   25,
			SuppressedLines: []suppression.SuppressionInfo{
				{Line: 11, Type: "all", AppliesTo: "next", SourceLine: 10}, // Suppress line 11 (next line after comment on line 10)
			},
		},
	}

	filtered, stats := FilterSuppressedFindings(findings, chunks, logger)

	// Should keep only the XSS finding on line 10
	if len(filtered) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(filtered))
	}

	if filtered[0].Line != 10 {
		t.Errorf("Expected finding on line 10, got line %d", filtered[0].Line)
	}

	if stats.SuppressedFindings != 1 {
		t.Errorf("Expected 1 suppressed finding, got %d", stats.SuppressedFindings)
	}
}

func TestFilterSuppressedFindings_EmptyFindings(t *testing.T) {
	logger := zerolog.New(io.Discard)

	var findings []report.Finding
	chunks := map[string]chunker.CodeChunk{}

	filtered, stats := FilterSuppressedFindings(findings, chunks, logger)

	if len(filtered) != 0 {
		t.Errorf("Expected 0 findings, got %d", len(filtered))
	}

	if stats.TotalFindings != 0 {
		t.Errorf("Expected total_findings 0, got %d", stats.TotalFindings)
	}
}
