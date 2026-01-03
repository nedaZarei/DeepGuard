package report

import (
	"bytes"
	"strings"
	"testing"
)

func TestTerminalReporter_WithFiltering(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewTerminalReporterWithWriter(&buf, 80, false)

	report := ScanReport{
		ScanMetadata: ScanMetadata{
			Timestamp:           "2025-01-07T10:30:00+03:30",
			TargetPath:          "/test/project",
			Languages:           []string{"javascript", "typescript"},
			Frameworks:          []string{"express"},
			ModelUsed:           "gpt-4o",
			TotalCost:           2.50,
			ScanDurationSeconds: 180,
			Filtering: &FilteringStats{
				Enabled:          true,
				ThresholdUsed:    0.7,
				TotalFindings:    20,
				FilteredFindings: 5,
				KeptFindings:     15,
			},
		},
		Findings: []Finding{
			{ID: "1", Type: "sql_injection", Severity: SeverityCritical, Confidence: 0.9, File: "test.js", Line: 10, Message: "test"},
			{ID: "2", Type: "xss", Severity: SeverityHigh, Confidence: 0.8, File: "test.js", Line: 20, Message: "test"},
		},
		Summary: Summary{
			TotalFindings: 2,
			BySeverity: map[string]int{
				SeverityCritical: 1,
				SeverityHigh:     1,
			},
			ByType: map[string]int{
				"sql_injection": 1,
				"xss":           1,
			},
		},
	}

	reporter.PrintSummary(report)
	output := buf.String()

	// Check for filtering information in output
	if !strings.Contains(output, "2 (5 filtered)") {
		t.Errorf("Expected '2 (5 filtered)' in output, got:\n%s", output)
	}

	if !strings.Contains(output, "Confidence Threshold") {
		t.Error("Expected 'Confidence Threshold' label in output")
	}

	if !strings.Contains(output, "0.70") {
		t.Error("Expected threshold value '0.70' in output")
	}
}

func TestTerminalReporter_WithoutFiltering(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewTerminalReporterWithWriter(&buf, 80, false)

	report := ScanReport{
		ScanMetadata: ScanMetadata{
			Timestamp:           "2025-01-07T10:30:00+03:30",
			TargetPath:          "/test/project",
			Languages:           []string{"javascript"},
			Frameworks:          []string{"express"},
			ModelUsed:           "gpt-4o",
			TotalCost:           2.50,
			ScanDurationSeconds: 180,
			Filtering:           nil, // No filtering
		},
		Findings: []Finding{
			{ID: "1", Type: "sql_injection", Severity: SeverityCritical, Confidence: 0.9, File: "test.js", Line: 10, Message: "test"},
		},
		Summary: Summary{
			TotalFindings: 1,
			BySeverity: map[string]int{
				SeverityCritical: 1,
			},
			ByType: map[string]int{
				"sql_injection": 1,
			},
		},
	}

	reporter.PrintSummary(report)
	output := buf.String()

	// Should show simple count without filtering info
	if strings.Contains(output, "filtered") {
		t.Error("Should not contain 'filtered' when filtering is disabled")
	}

	if strings.Contains(output, "Confidence Threshold") {
		t.Error("Should not show confidence threshold when filtering is disabled")
	}
}

func TestTerminalReporter_FilteringDisabled(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewTerminalReporterWithWriter(&buf, 80, false)

	report := ScanReport{
		ScanMetadata: ScanMetadata{
			Timestamp:           "2025-01-07T10:30:00+03:30",
			TargetPath:          "/test/project",
			Languages:           []string{"javascript"},
			Frameworks:          []string{},
			ModelUsed:           "gpt-4o-mini",
			TotalCost:           1.50,
			ScanDurationSeconds: 120,
			Filtering: &FilteringStats{
				Enabled:          false, // Explicitly disabled (threshold 0.0)
				ThresholdUsed:    0.0,
				TotalFindings:    10,
				FilteredFindings: 0,
				KeptFindings:     10,
			},
		},
		Findings: []Finding{
			{ID: "1", Type: "sql_injection", Severity: SeverityHigh, Confidence: 0.5, File: "test.js", Line: 10, Message: "test"},
		},
		Summary: Summary{
			TotalFindings: 1,
			BySeverity: map[string]int{
				SeverityHigh: 1,
			},
			ByType: map[string]int{
				"sql_injection": 1,
			},
		},
	}

	reporter.PrintSummary(report)
	output := buf.String()

	// Should NOT show filtering info when Enabled=false (even if FilteringStats exists)
	if strings.Contains(output, "filtered") {
		t.Error("Should not show filtering info when Enabled=false")
	}

	if strings.Contains(output, "Confidence Threshold") {
		t.Error("Should not show confidence threshold when Enabled=false")
	}
}

func TestTerminalReporter_ZeroFindings(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewTerminalReporterWithWriter(&buf, 80, false)

	report := ScanReport{
		ScanMetadata: ScanMetadata{
			Timestamp:           "2025-01-07T10:30:00+03:30",
			TargetPath:          "/test/project",
			Languages:           []string{"javascript"},
			Frameworks:          []string{},
			ModelUsed:           "gpt-4o",
			TotalCost:           0.50,
			ScanDurationSeconds: 60,
			Filtering: &FilteringStats{
				Enabled:          true,
				ThresholdUsed:    0.8,
				TotalFindings:    5,
				FilteredFindings: 5,
				KeptFindings:     0, // All filtered out
			},
		},
		Findings: []Finding{},
		Summary: Summary{
			TotalFindings: 0,
			BySeverity:    map[string]int{},
			ByType:        map[string]int{},
		},
	}

	reporter.PrintSummary(report)
	output := buf.String()

	// Should show 0 findings with 5 filtered
	if !strings.Contains(output, "0 (5 filtered)") {
		t.Error("Expected '0 (5 filtered)' when all findings are filtered out")
	}
}
