package testing

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Neda-Zarei/deep-guard/internal/report"
)

// GoldenFile represents the expected findings for a test case
type GoldenFile struct {
	Description  string            `json:"description"`
	ScanMetadata GoldenMetadata    `json:"scan_metadata"`
	Expected     []ExpectedFinding `json:"expected_findings"`
	Severity     map[string]int    `json:"severity_breakdown"`
	Framework    map[string]int    `json:"framework_breakdown"`
}

// GoldenMetadata contains metadata about the expected scan
type GoldenMetadata struct {
	TargetPath            string  `json:"target_path"`
	VulnerabilityType     string  `json:"vulnerability_type"`
	ConfidenceThreshold   float64 `json:"confidence_threshold"`
	TotalExpectedFindings int     `json:"total_expected_findings"`
}

// ExpectedFinding represents a single expected vulnerability
type ExpectedFinding struct {
	File          string  `json:"file"`
	Line          int     `json:"line"`
	Type          string  `json:"type"`
	Severity      string  `json:"severity"`
	ConfidenceMin float64 `json:"confidence_min"`
	Pattern       string  `json:"pattern"`
	Description   string  `json:"description"`
	CodePattern   string  `json:"code_pattern"`
}

// ComparisonResult contains the results of comparing actual vs expected findings
type ComparisonResult struct {
	TotalExpected        int
	TotalActual          int
	Matched              int
	Missing              []ExpectedFinding
	Extra                []report.Finding
	ConfidenceMismatches []ConfidenceMismatch
	Success              bool
}

// ConfidenceMismatch represents a finding that was detected but with lower confidence than expected
type ConfidenceMismatch struct {
	Expected     ExpectedFinding
	Actual       report.Finding
	ExpectedConf float64
	ActualConf   float64
}

// LoadGoldenFile loads and parses a golden test file
func LoadGoldenFile(path string) (*GoldenFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read golden file: %w", err)
	}

	var golden GoldenFile
	if err := json.Unmarshal(data, &golden); err != nil {
		return nil, fmt.Errorf("failed to parse golden file: %w", err)
	}

	// Validate
	if len(golden.Expected) == 0 {
		return nil, fmt.Errorf("golden file contains no expected findings")
	}

	if golden.ScanMetadata.TotalExpectedFindings != len(golden.Expected) {
		return nil, fmt.Errorf("metadata total_expected_findings (%d) doesn't match actual count (%d)",
			golden.ScanMetadata.TotalExpectedFindings, len(golden.Expected))
	}

	return &golden, nil
}

// CompareResults compares actual scan results against expected findings
func CompareResults(golden *GoldenFile, actual report.ScanReport, lineTolerance int) *ComparisonResult {
	result := &ComparisonResult{
		TotalExpected:        len(golden.Expected),
		TotalActual:          len(actual.Findings),
		Missing:              []ExpectedFinding{},
		Extra:                []report.Finding{},
		ConfidenceMismatches: []ConfidenceMismatch{},
	}

	// Track which actual findings have been matched
	matched := make(map[int]bool)

	// For each expected finding, try to find a match in actual findings
	for _, expected := range golden.Expected {
		found := false

		for i, actualFinding := range actual.Findings {
			if matched[i] {
				continue // Already matched to another expected finding
			}

			if matchesFinding(expected, actualFinding, lineTolerance) {
				found = true
				matched[i] = true
				result.Matched++

				// Check confidence threshold
				if actualFinding.Confidence < expected.ConfidenceMin {
					result.ConfidenceMismatches = append(result.ConfidenceMismatches, ConfidenceMismatch{
						Expected:     expected,
						Actual:       actualFinding,
						ExpectedConf: expected.ConfidenceMin,
						ActualConf:   actualFinding.Confidence,
					})
				}
				break
			}
		}

		if !found {
			result.Missing = append(result.Missing, expected)
		}
	}

	// Find unexpected high/critical severity findings
	for i, actualFinding := range actual.Findings {
		if matched[i] {
			continue
		}

		// Flag unmatched critical/high severity as potentially problematic
		if actualFinding.Severity == report.SeverityCritical || actualFinding.Severity == report.SeverityHigh {
			result.Extra = append(result.Extra, actualFinding)
		}
	}

	// Success if all expected findings were found and confidence thresholds met
	result.Success = len(result.Missing) == 0 && len(result.ConfidenceMismatches) == 0

	return result
}

// matchesFinding checks if an actual finding matches an expected finding
func matchesFinding(expected ExpectedFinding, actual report.Finding, lineTolerance int) bool {
	// Normalize file paths for comparison (handle relative vs absolute paths)
	expectedFile := normalizeFilePath(expected.File)
	actualFile := normalizeFilePath(actual.File)

	// Check if file names match (allowing for path differences)
	if !strings.HasSuffix(actualFile, expectedFile) && !strings.HasSuffix(expectedFile, actualFile) {
		return false
	}

	// Check type
	if expected.Type != actual.Type {
		return false
	}

	// Severity is intentionally not checked: it measures scoring quality, not detection.
	// A finding classified as "critical" instead of "high" is still a true positive.

	// Check line number with tolerance (±lineTolerance lines)
	lineDiff := abs(expected.Line - actual.Line)
	if lineDiff > lineTolerance {
		return false
	}

	return true
}

// normalizeFilePath normalizes a file path for comparison
func normalizeFilePath(path string) string {
	// Remove leading "./"
	path = strings.TrimPrefix(path, "./")

	// Convert to forward slashes
	path = filepath.ToSlash(path)

	// Get base name for comparison
	return filepath.Base(path)
}

// abs returns the absolute value of an integer
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// FormatComparisonResult formats the comparison result as a human-readable string
func FormatComparisonResult(result *ComparisonResult) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("\n=== Golden Test Comparison Results ===\n"))
	sb.WriteString(fmt.Sprintf("Expected findings: %d\n", result.TotalExpected))
	sb.WriteString(fmt.Sprintf("Actual findings:   %d\n", result.TotalActual))
	sb.WriteString(fmt.Sprintf("Matched:           %d\n", result.Matched))
	sb.WriteString(fmt.Sprintf("Missing:           %d\n", len(result.Missing)))
	sb.WriteString(fmt.Sprintf("Extra (high/crit): %d\n", len(result.Extra)))
	sb.WriteString(fmt.Sprintf("Confidence issues: %d\n", len(result.ConfidenceMismatches)))
	sb.WriteString(fmt.Sprintf("Status:            %s\n", formatStatus(result.Success)))
	sb.WriteString("======================================\n\n")

	// List missing findings
	if len(result.Missing) > 0 {
		sb.WriteString("❌ Missing Expected Findings:\n")
		for i, missing := range result.Missing {
			sb.WriteString(fmt.Sprintf("  %d. %s:%d (%s, %s)\n",
				i+1, missing.File, missing.Line, missing.Type, missing.Severity))
			sb.WriteString(fmt.Sprintf("     Pattern: %s\n", missing.Pattern))
			sb.WriteString(fmt.Sprintf("     Description: %s\n", missing.Description))
		}
		sb.WriteString("\n")
	}

	// List extra high/critical findings
	if len(result.Extra) > 0 {
		sb.WriteString("⚠️  Unexpected High/Critical Findings:\n")
		for i, extra := range result.Extra {
			sb.WriteString(fmt.Sprintf("  %d. %s:%d (%s, %s, confidence: %.2f)\n",
				i+1, extra.File, extra.Line, extra.Type, extra.Severity, extra.Confidence))
			sb.WriteString(fmt.Sprintf("     Message: %s\n", extra.Message))
		}
		sb.WriteString("\n")
	}

	// List confidence mismatches
	if len(result.ConfidenceMismatches) > 0 {
		sb.WriteString("⚠️  Confidence Threshold Mismatches:\n")
		for i, mismatch := range result.ConfidenceMismatches {
			sb.WriteString(fmt.Sprintf("  %d. %s:%d\n",
				i+1, mismatch.Expected.File, mismatch.Expected.Line))
			sb.WriteString(fmt.Sprintf("     Expected confidence: >= %.2f\n", mismatch.ExpectedConf))
			sb.WriteString(fmt.Sprintf("     Actual confidence:   %.2f\n", mismatch.ActualConf))
		}
		sb.WriteString("\n")
	}

	if result.Success {
		sb.WriteString("✅ All expected findings detected with sufficient confidence!\n")
	}

	return sb.String()
}

// formatStatus returns a colored status string
func formatStatus(success bool) string {
	if success {
		return "PASS ✅"
	}
	return "FAIL ❌"
}
