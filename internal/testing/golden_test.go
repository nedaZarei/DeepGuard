package testing

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Neda-Zarei/deep-guard/internal/report"
)

// TestJSTSSQLiGolden is a golden test that validates SQLi detection against expected findings
func TestJSTSSQLiGolden(t *testing.T) {
	// Skip in short mode or if explicitly disabled
	if testing.Short() {
		t.Skip("Skipping golden test in short mode")
	}

	if os.Getenv("SKIP_GOLDEN_TESTS") == "1" {
		t.Skip("Golden tests disabled via SKIP_GOLDEN_TESTS=1")
	}

	// Load golden file
	goldenPath := filepath.Join("..", "..", "test-samples", "js-ts-sqli", "expected-findings.json")
	golden, err := LoadGoldenFile(goldenPath)
	if err != nil {
		t.Fatalf("Failed to load golden file: %v", err)
	}

	t.Logf("Loaded golden file with %d expected findings", len(golden.Expected))

	// For now, we'll create a mock scan report to demonstrate the test structure
	// In the real implementation, this would run: deepguard scan --path test-samples/js-ts-sqli/
	// and load the actual results from the JSON output

	// TODO: Uncomment when scan command is fully integrated
	// scanReport, err := runScan(golden.ScanMetadata.TargetPath)
	// if err != nil {
	// 	t.Fatalf("Failed to run scan: %v", err)
	// }

	// For demonstration, load a sample report or create empty one
	scanReport := loadSampleReport(t)

	// Compare results with ±2 line tolerance for AST changes
	result := CompareResults(golden, scanReport, 2)

	// Print detailed comparison
	t.Log(FormatComparisonResult(result))

	// Assert no false negatives (all expected findings detected)
	if len(result.Missing) > 0 {
		t.Errorf("False negatives detected: %d expected findings not detected", len(result.Missing))
		for _, missing := range result.Missing {
			t.Errorf("  Missing: %s:%d (%s)", missing.File, missing.Line, missing.Pattern)
		}
	}

	// Assert confidence thresholds met
	if len(result.ConfidenceMismatches) > 0 {
		t.Errorf("Confidence threshold failures: %d findings below minimum confidence", len(result.ConfidenceMismatches))
		for _, mismatch := range result.ConfidenceMismatches {
			t.Errorf("  Low confidence: %s:%d (expected >= %.2f, got %.2f)",
				mismatch.Expected.File, mismatch.Expected.Line,
				mismatch.ExpectedConf, mismatch.ActualConf)
		}
	}

	// Warn about unexpected high/critical findings (possible false positives)
	if len(result.Extra) > 0 {
		t.Logf("Warning: %d unexpected high/critical severity findings detected", len(result.Extra))
		for _, extra := range result.Extra {
			t.Logf("  Unexpected: %s:%d (%s, %s, %.2f confidence)",
				extra.File, extra.Line, extra.Type, extra.Severity, extra.Confidence)
		}
		// Don't fail on extra findings, just warn
	}

	// Overall success
	if !result.Success {
		t.Errorf("Golden test failed: not all expected findings were detected with sufficient confidence")
	} else {
		t.Logf("✅ Golden test passed: all %d expected findings detected", result.Matched)
	}
}

// loadSampleReport loads a sample report for testing
// TODO: Replace with actual scan execution when integrated
func loadSampleReport(t *testing.T) report.ScanReport {
	// Try to load an actual report if it exists
	reportPath := filepath.Join("..", "..", "test-samples", "js-ts-sqli", "scan-results.json")
	if data, err := os.ReadFile(reportPath); err == nil {
		var scanReport report.ScanReport
		if err := json.Unmarshal(data, &scanReport); err == nil {
			t.Logf("Loaded actual scan report from %s", reportPath)
			return scanReport
		}
	}

	// Return empty report if no actual results available
	t.Log("No actual scan results found, using empty report")
	return report.ScanReport{
		ScanMetadata: report.ScanMetadata{
			TargetPath: "test-samples/js-ts-sqli/",
			Languages:  []string{"javascript", "typescript"},
		},
		Findings: []report.Finding{},
		Summary: report.Summary{
			TotalFindings: 0,
			BySeverity:    make(map[string]int),
			ByType:        make(map[string]int),
		},
	}
}

// runScan executes DeepGuard scan and returns the report
// TODO: Implement when scan orchestrator is complete
func runScan(targetPath string) (report.ScanReport, error) {
	// This would execute:
	// 1. Discovery (detect frameworks, find files)
	// 2. Parsing (parse files with tree-sitter)
	// 3. Chunking (extract code chunks)
	// 4. Analysis (LLM-based vulnerability detection)
	// 5. Report generation (collect findings into JSON)

	// For now, return empty report
	return report.ScanReport{}, nil
}
