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
// AnalysisStats records how many chunk analyses were attempted and how many
// failed (API errors, unparseable responses). A scan with a non-zero Failed
// count is incomplete: it produced fewer findings than a clean run would have,
// so its recall is understated and it must not be compared as if complete.
type AnalysisStats struct {
	Attempted int  `json:"attempted"`
	Failed    int  `json:"failed"`
	Complete  bool `json:"complete"`
}

type ScanMetadata struct {
	Timestamp           string            `json:"timestamp"` // RFC3339 format
	TargetPath          string            `json:"target_path"`
	Languages           []string          `json:"languages"`
	Frameworks          []string          `json:"frameworks"`
	ModelUsed           string            `json:"model_used"`
	TotalCost           float64           `json:"total_cost"`
	ScanDurationSeconds int               `json:"scan_duration_seconds"`
	Analysis            *AnalysisStats    `json:"analysis,omitempty"`    // Chunk-analysis completeness
	LineSnap            *LineSnapStats    `json:"line_snap,omitempty"`   // Quote-anchored line correction
	Judge               *JudgeStats       `json:"judge,omitempty"`       // Per-site type adjudication
	Filtering           *FilteringStats   `json:"filtering,omitempty"`   // Optional filtering statistics
	Suppression         *SuppressionStats `json:"suppression,omitempty"` // Optional suppression statistics
}

// LineSnapStats records what the quote-anchored line correction did.
// Every finding falls into exactly one of: WithoutQuote, FileUnreadable,
// QuoteNotFound, Confirmed, Snapped, TooFar.
type LineSnapStats struct {
	Enabled           bool `json:"enabled"`
	MaxDistance       int  `json:"max_distance"`
	TotalFindings     int  `json:"total_findings"`
	WithQuote         int  `json:"with_quote"`
	WithoutQuote      int  `json:"without_quote"`
	FileUnreadable    int  `json:"file_unreadable"`
	Confirmed         int  `json:"confirmed"`          // quote found at the reported line
	Snapped           int  `json:"snapped"`            // line moved to the quote's location
	TooFar            int  `json:"too_far"`            // quote found only beyond max_distance; left as reported
	QuoteNotFound     int  `json:"quote_not_found"`    // quote absent from the file
	Dropped           int  `json:"dropped"`            // removed under the strict policy (subset of quote_not_found)
	DuplicatesRemoved int  `json:"duplicates_removed"` // same file+line+type collapsed after snapping
	KeptFindings      int  `json:"kept_findings"`
}

// JudgeStats records the per-site type adjudication.
type JudgeStats struct {
	Enabled          bool `json:"enabled"`
	TotalFindings    int  `json:"total_findings"`
	SitesUncontested int  `json:"sites_uncontested"`
	SitesContested   int  `json:"sites_contested"`
	Calls            int  `json:"calls"`
	SelectedOne      int  `json:"selected_one"`
	SelectedNone     int  `json:"selected_none"`
	Removed          int  `json:"removed"`
	Errors           int  `json:"errors"` // failed calls; their sites were kept as reported
	KeptFindings     int  `json:"kept_findings"`
}

// FilteringStats contains statistics about finding filtering
type FilteringStats struct {
	Enabled          bool    `json:"enabled"`
	ThresholdUsed    float64 `json:"threshold_used"`
	TotalFindings    int     `json:"total_findings"`    // Before filtering
	FilteredFindings int     `json:"filtered_findings"` // Number filtered out
	KeptFindings     int     `json:"kept_findings"`     // Number kept (in report)
}

// SuppressionStats contains statistics about suppressed findings
type SuppressionStats struct {
	TotalFindings      int `json:"total_findings"`      // Findings checked for suppression
	SuppressedFindings int `json:"suppressed_findings"` // Number suppressed by inline comments
	KeptFindings       int `json:"kept_findings"`       // Number kept after suppression
}

// Finding represents a single vulnerability finding
type Finding struct {
	ID             string  `json:"id"`
	Type           string  `json:"type"`
	Severity       string  `json:"severity"`
	Confidence     float64 `json:"confidence"`
	File           string  `json:"file"`
	Line           int     `json:"line"`
	Column         int     `json:"column,omitempty"`
	FunctionName   string  `json:"function_name,omitempty"`
	Message        string  `json:"message"`
	Recommendation string  `json:"recommendation"`
	CodeSnippet    string  `json:"code_snippet,omitempty"`
	Quote          string  `json:"quote,omitempty"`
	ReportedLine   int     `json:"reported_line,omitempty"`
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
