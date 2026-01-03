package types

// Finding represents a single security vulnerability detected in code
type Finding struct {
	// Type of vulnerability (sql_injection, xss, etc.)
	Type string `json:"type"`

	// Severity level (low, medium, high, critical)
	Severity string `json:"severity"`

	// Confidence score from 0.0 to 1.0
	Confidence float64 `json:"confidence"`

	// Line number where the issue occurs (relative to chunk start)
	Line int `json:"line"`

	// Message describing the vulnerability
	Message string `json:"message"`

	// Recommendation for fixing the vulnerability
	Recommendation string `json:"recommendation"`

	// --- Context fields (enriched after parsing) ---

	// ChunkID is the SHA256 hash of the code chunk
	ChunkID string `json:"chunk_id,omitempty"`

	// FilePath is the absolute path to the file
	FilePath string `json:"file_path,omitempty"`

	// FunctionName is the name of the function containing the vulnerability
	FunctionName string `json:"function_name,omitempty"`

	// AbsoluteLine is the absolute line number in the file (enriched from Line + chunk.StartLine)
	AbsoluteLine int `json:"absolute_line,omitempty"`

	// LineRangeStart is the starting line of the containing chunk
	LineRangeStart int `json:"line_range_start,omitempty"`

	// LineRangeEnd is the ending line of the containing chunk
	LineRangeEnd int `json:"line_range_end,omitempty"`
}

// VulnerabilityType represents allowed vulnerability types
type VulnerabilityType string

const (
	VulnTypeSQLInjection            VulnerabilityType = "sql_injection"
	VulnTypeXSS                     VulnerabilityType = "xss"
	VulnTypePathTraversal           VulnerabilityType = "path_traversal"
	VulnTypeInsecureDeserialization VulnerabilityType = "insecure_deserialization"
	VulnTypeAuthIssue               VulnerabilityType = "auth_issue"
	VulnTypeCryptoIssue             VulnerabilityType = "crypto_issue"
)

// SeverityLevel represents allowed severity levels
type SeverityLevel string

const (
	SeverityLow      SeverityLevel = "low"
	SeverityMedium   SeverityLevel = "medium"
	SeverityHigh     SeverityLevel = "high"
	SeverityCritical SeverityLevel = "critical"
)

// IsValidVulnerabilityType checks if a string is a valid vulnerability type
func IsValidVulnerabilityType(t string) bool {
	switch VulnerabilityType(t) {
	case VulnTypeSQLInjection, VulnTypeXSS, VulnTypePathTraversal,
		VulnTypeInsecureDeserialization, VulnTypeAuthIssue, VulnTypeCryptoIssue:
		return true
	default:
		return false
	}
}

// IsValidSeverityLevel checks if a string is a valid severity level
func IsValidSeverityLevel(s string) bool {
	switch SeverityLevel(s) {
	case SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	default:
		return false
	}
}
