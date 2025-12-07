package report

import (
	"fmt"
	"time"
)

// ScanReport represents the complete scan report structure
type ScanReport struct {
	ScanMetadata ScanMetadata `json:"scan_metadata"`
	Findings     []Finding    `json:"findings"`
	Summary      Summary      `json:"summary"`
}

// ScanMetadata contains metadata about the scan execution
type ScanMetadata struct {
	Timestamp           string   `json:"timestamp"`             // RFC3339 format
	TargetPath          string   `json:"target_path"`
	Languages           []string `json:"languages"`
	Frameworks          []string `json:"frameworks"`
	ModelUsed           string   `json:"model_used"`
	TotalCost           float64  `json:"total_cost"`
	ScanDurationSeconds int      `json:"scan_duration_seconds"`
}

// Finding represents a single vulnerability finding
type Finding struct {
	ID           string  `json:"id"`
	Type         string  `json:"type"`
	Severity     string  `json:"severity"`
	Confidence   float64 `json:"confidence"`
	File         string  `json:"file"`
	Line         int     `json:"line"`
	Column       int     `json:"column,omitempty"`
	FunctionName string  `json:"function_name,omitempty"`
	Message      string  `json:"message"`
	Recommendation string `json:"recommendation"`
	CodeSnippet  string  `json:"code_snippet,omitempty"`
}

// Summary contains aggregate statistics about findings
type Summary struct {
	TotalFindings int            `json:"total_findings"`
	BySeverity    map[string]int `json:"by_severity"`
	ByType        map[string]int `json:"by_type"`
}

// Validation constants
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
)

// Valid severity levels
var validSeverities = map[string]bool{
	SeverityCritical: true,
	SeverityHigh:     true,
	SeverityMedium:   true,
	SeverityLow:      true,
}

// ValidateFinding validates a finding against the schema rules
func ValidateFinding(f Finding) error {
	// Check required fields
	if f.Type == "" {
		return fmt.Errorf("finding type is required")
	}
	if f.Severity == "" {
		return fmt.Errorf("finding severity is required")
	}
	if f.File == "" {
		return fmt.Errorf("finding file is required")
	}
	if f.Line <= 0 {
		return fmt.Errorf("finding line must be positive (got %d)", f.Line)
	}
	if f.Message == "" {
		return fmt.Errorf("finding message is required")
	}

	// Validate severity enum
	if !validSeverities[f.Severity] {
		return fmt.Errorf("invalid severity '%s', must be one of: critical, high, medium, low", f.Severity)
	}

	// Validate confidence range
	if f.Confidence < 0.0 || f.Confidence > 1.0 {
		return fmt.Errorf("confidence must be between 0.0 and 1.0 (got %.2f)", f.Confidence)
	}

	return nil
}

// ValidateReport validates the entire scan report
func ValidateReport(report ScanReport) error {
	// Validate metadata
	if report.ScanMetadata.Timestamp == "" {
		return fmt.Errorf("scan metadata timestamp is required")
	}
	if report.ScanMetadata.TargetPath == "" {
		return fmt.Errorf("scan metadata target_path is required")
	}

	// Validate timestamp format (RFC3339)
	if _, err := time.Parse(time.RFC3339, report.ScanMetadata.Timestamp); err != nil {
		return fmt.Errorf("invalid timestamp format, expected RFC3339: %w", err)
	}

	// Validate each finding
	for i, finding := range report.Findings {
		if err := ValidateFinding(finding); err != nil {
			return fmt.Errorf("finding[%d] validation failed: %w", i, err)
		}
	}

	// Validate summary consistency
	if report.Summary.TotalFindings != len(report.Findings) {
		return fmt.Errorf("summary total_findings (%d) does not match findings count (%d)",
			report.Summary.TotalFindings, len(report.Findings))
	}

	return nil
}

// GenerateSummary creates a summary from a list of findings
func GenerateSummary(findings []Finding) Summary {
	summary := Summary{
		TotalFindings: len(findings),
		BySeverity:    make(map[string]int),
		ByType:        make(map[string]int),
	}

	for _, finding := range findings {
		summary.BySeverity[finding.Severity]++
		summary.ByType[finding.Type]++
	}

	return summary
}
