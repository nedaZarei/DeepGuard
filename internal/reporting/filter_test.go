package reporting

import (
	"io"
	"testing"

	"github.com/Neda-Zarei/deep-guard/internal/report"
	"github.com/rs/zerolog"
)

func testLogger() zerolog.Logger {
	return zerolog.New(io.Discard)
}

func TestFilterFindingsByConfidence_ZeroThreshold(t *testing.T) {
	logger := testLogger()

	findings := []report.Finding{
		{ID: "1", Confidence: 0.1, Type: "sql_injection", File: "test.js", Line: 10, Message: "test"},
		{ID: "2", Confidence: 0.5, Type: "xss", File: "test.js", Line: 20, Message: "test"},
		{ID: "3", Confidence: 0.9, Type: "sqli", File: "test.js", Line: 30, Message: "test"},
	}

	filtered, stats := FilterFindingsByConfidence(findings, 0.0, logger)

	// All findings should be kept with threshold 0.0
	if len(filtered) != 3 {
		t.Errorf("Expected 3 findings with threshold 0.0, got %d", len(filtered))
	}

	if stats.TotalFindings != 3 {
		t.Errorf("Expected total_findings 3, got %d", stats.TotalFindings)
	}

	if stats.FilteredFindings != 0 {
		t.Errorf("Expected filtered_findings 0, got %d", stats.FilteredFindings)
	}

	if stats.KeptFindings != 3 {
		t.Errorf("Expected kept_findings 3, got %d", stats.KeptFindings)
	}

	if stats.ThresholdUsed != 0.0 {
		t.Errorf("Expected threshold_used 0.0, got %.2f", stats.ThresholdUsed)
	}

	if stats.Enabled {
		t.Error("Expected filtering to be disabled with threshold 0.0")
	}
}

func TestFilterFindingsByConfidence_DefaultThreshold(t *testing.T) {
	logger := testLogger()

	findings := []report.Finding{
		{ID: "1", Confidence: 0.3, Type: "sql_injection", File: "test.js", Line: 10, Message: "low confidence", Severity: "high"},
		{ID: "2", Confidence: 0.5, Type: "xss", File: "test.js", Line: 20, Message: "exact threshold", Severity: "medium"},
		{ID: "3", Confidence: 0.7, Type: "sqli", File: "test.js", Line: 30, Message: "high confidence", Severity: "critical"},
		{ID: "4", Confidence: 0.9, Type: "injection", File: "test.js", Line: 40, Message: "very high", Severity: "critical"},
	}

	filtered, stats := FilterFindingsByConfidence(findings, 0.5, logger)

	// Should keep findings with confidence >= 0.5 (3 findings)
	if len(filtered) != 3 {
		t.Errorf("Expected 3 findings with threshold 0.5, got %d", len(filtered))
	}

	if stats.TotalFindings != 4 {
		t.Errorf("Expected total_findings 4, got %d", stats.TotalFindings)
	}

	if stats.FilteredFindings != 1 {
		t.Errorf("Expected filtered_findings 1, got %d", stats.FilteredFindings)
	}

	if stats.KeptFindings != 3 {
		t.Errorf("Expected kept_findings 3, got %d", stats.KeptFindings)
	}

	if stats.ThresholdUsed != 0.5 {
		t.Errorf("Expected threshold_used 0.5, got %.2f", stats.ThresholdUsed)
	}

	if !stats.Enabled {
		t.Error("Expected filtering to be enabled with threshold 0.5")
	}

	// Verify kept findings have confidence >= 0.5
	for _, finding := range filtered {
		if finding.Confidence < 0.5 {
			t.Errorf("Filtered finding %s has confidence %.2f < 0.5", finding.ID, finding.Confidence)
		}
	}

	// Verify filtered finding was removed
	for _, finding := range filtered {
		if finding.ID == "1" {
			t.Error("Finding with ID '1' (confidence 0.3) should be filtered out")
		}
	}
}

func TestFilterFindingsByConfidence_HighThreshold(t *testing.T) {
	logger := testLogger()

	findings := []report.Finding{
		{ID: "1", Confidence: 0.5, Type: "sql_injection", File: "test.js", Line: 10, Message: "test"},
		{ID: "2", Confidence: 0.7, Type: "xss", File: "test.js", Line: 20, Message: "test"},
		{ID: "3", Confidence: 0.8, Type: "sqli", File: "test.js", Line: 30, Message: "test"},
		{ID: "4", Confidence: 0.9, Type: "injection", File: "test.js", Line: 40, Message: "test"},
	}

	filtered, stats := FilterFindingsByConfidence(findings, 0.75, logger)

	// Should keep only findings with confidence >= 0.75 (2 findings)
	if len(filtered) != 2 {
		t.Errorf("Expected 2 findings with threshold 0.75, got %d", len(filtered))
	}

	if stats.FilteredFindings != 2 {
		t.Errorf("Expected 2 filtered findings, got %d", stats.FilteredFindings)
	}

	// Verify kept findings
	expectedIDs := map[string]bool{"3": true, "4": true}
	for _, finding := range filtered {
		if !expectedIDs[finding.ID] {
			t.Errorf("Unexpected finding %s in filtered results", finding.ID)
		}
	}
}

func TestFilterFindingsByConfidence_MaxThreshold(t *testing.T) {
	logger := testLogger()

	findings := []report.Finding{
		{ID: "1", Confidence: 0.9, Type: "sql_injection", File: "test.js", Line: 10, Message: "test"},
		{ID: "2", Confidence: 0.95, Type: "xss", File: "test.js", Line: 20, Message: "test"},
		{ID: "3", Confidence: 1.0, Type: "sqli", File: "test.js", Line: 30, Message: "test"},
	}

	filtered, stats := FilterFindingsByConfidence(findings, 1.0, logger)

	// Should keep only findings with confidence == 1.0 (1 finding)
	if len(filtered) != 1 {
		t.Errorf("Expected 1 finding with threshold 1.0, got %d", len(filtered))
	}

	if stats.FilteredFindings != 2 {
		t.Errorf("Expected 2 filtered findings, got %d", stats.FilteredFindings)
	}

	if filtered[0].ID != "3" {
		t.Errorf("Expected finding ID '3' to be kept, got '%s'", filtered[0].ID)
	}
}

func TestFilterFindingsByConfidence_EmptyFindings(t *testing.T) {
	logger := testLogger()

	var findings []report.Finding

	filtered, stats := FilterFindingsByConfidence(findings, 0.5, logger)

	if len(filtered) != 0 {
		t.Errorf("Expected 0 findings, got %d", len(filtered))
	}

	if stats.TotalFindings != 0 {
		t.Errorf("Expected total_findings 0, got %d", stats.TotalFindings)
	}

	if stats.FilteredFindings != 0 {
		t.Errorf("Expected filtered_findings 0, got %d", stats.FilteredFindings)
	}
}

func TestFilterFindingsByConfidence_AllPassThreshold(t *testing.T) {
	logger := testLogger()

	findings := []report.Finding{
		{ID: "1", Confidence: 0.8, Type: "sql_injection", File: "test.js", Line: 10, Message: "test"},
		{ID: "2", Confidence: 0.9, Type: "xss", File: "test.js", Line: 20, Message: "test"},
		{ID: "3", Confidence: 1.0, Type: "sqli", File: "test.js", Line: 30, Message: "test"},
	}

	filtered, stats := FilterFindingsByConfidence(findings, 0.5, logger)

	// All findings should pass
	if len(filtered) != 3 {
		t.Errorf("Expected 3 findings, got %d", len(filtered))
	}

	if stats.FilteredFindings != 0 {
		t.Errorf("Expected 0 filtered findings, got %d", stats.FilteredFindings)
	}

	if stats.KeptFindings != 3 {
		t.Errorf("Expected 3 kept findings, got %d", stats.KeptFindings)
	}
}

func TestFilterFindingsByConfidence_AllFilteredOut(t *testing.T) {
	logger := testLogger()

	findings := []report.Finding{
		{ID: "1", Confidence: 0.2, Type: "sql_injection", File: "test.js", Line: 10, Message: "test"},
		{ID: "2", Confidence: 0.3, Type: "xss", File: "test.js", Line: 20, Message: "test"},
		{ID: "3", Confidence: 0.4, Type: "sqli", File: "test.js", Line: 30, Message: "test"},
	}

	filtered, stats := FilterFindingsByConfidence(findings, 0.5, logger)

	// All findings should be filtered out
	if len(filtered) != 0 {
		t.Errorf("Expected 0 findings, got %d", len(filtered))
	}

	if stats.FilteredFindings != 3 {
		t.Errorf("Expected 3 filtered findings, got %d", stats.FilteredFindings)
	}

	if stats.KeptFindings != 0 {
		t.Errorf("Expected 0 kept findings, got %d", stats.KeptFindings)
	}
}

func TestFilterFindingsByConfidence_EdgeCases(t *testing.T) {
	logger := testLogger()

	findings := []report.Finding{
		{ID: "1", Confidence: 0.499999, Type: "sql_injection", File: "test.js", Line: 10, Message: "just below"},
		{ID: "2", Confidence: 0.5, Type: "xss", File: "test.js", Line: 20, Message: "exactly at"},
		{ID: "3", Confidence: 0.500001, Type: "sqli", File: "test.js", Line: 30, Message: "just above"},
	}

	filtered, _ := FilterFindingsByConfidence(findings, 0.5, logger)

	// Should keep findings with confidence >= 0.5 (2 findings)
	if len(filtered) != 2 {
		t.Errorf("Expected 2 findings at threshold 0.5, got %d", len(filtered))
	}

	// Verify IDs
	for _, finding := range filtered {
		if finding.ID == "1" {
			t.Error("Finding '1' (confidence 0.499999) should be filtered out")
		}
	}
}

func TestFilterFindingsByConfidence_StatisticsConsistency(t *testing.T) {
	logger := testLogger()

	findings := []report.Finding{
		{ID: "1", Confidence: 0.3, Type: "sql_injection", File: "test.js", Line: 10, Message: "test"},
		{ID: "2", Confidence: 0.6, Type: "xss", File: "test.js", Line: 20, Message: "test"},
		{ID: "3", Confidence: 0.9, Type: "sqli", File: "test.js", Line: 30, Message: "test"},
	}

	filtered, stats := FilterFindingsByConfidence(findings, 0.5, logger)

	// Verify consistency: total = filtered + kept
	if stats.TotalFindings != stats.FilteredFindings+stats.KeptFindings {
		t.Errorf("Statistics inconsistent: total(%d) != filtered(%d) + kept(%d)",
			stats.TotalFindings, stats.FilteredFindings, stats.KeptFindings)
	}

	// Verify kept matches actual filtered length
	if stats.KeptFindings != len(filtered) {
		t.Errorf("KeptFindings (%d) doesn't match filtered length (%d)",
			stats.KeptFindings, len(filtered))
	}
}
