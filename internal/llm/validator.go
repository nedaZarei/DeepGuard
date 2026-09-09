package llm

import (
	"fmt"

	"github.com/Neda-Zarei/deep-guard/pkg/types"
)

// ValidationError represents a validation error with detailed context
type ValidationError struct {
	Field  string
	Reason string
	Value  interface{}
}

// Error implements the error interface
func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error on field '%s': %s (value: %v)", e.Field, e.Reason, e.Value)
}

// NewValidationError creates a new ValidationError
func NewValidationError(field, reason string, value interface{}) *ValidationError {
	return &ValidationError{
		Field:  field,
		Reason: reason,
		Value:  value,
	}
}

// ValidateFinding validates a single finding according to the schema rules
func ValidateFinding(finding *types.Finding, index int) error {
	// Validate Type field (enum)
	if finding.Type == "" {
		return NewValidationError(
			fmt.Sprintf("findings[%d].type", index),
			"field is required and cannot be empty",
			finding.Type,
		)
	}
	if !types.IsValidVulnerabilityType(finding.Type) {
		return NewValidationError(
			fmt.Sprintf("findings[%d].type", index),
			"must be one of the 13 template vulnerability types (see pkg/types.IsValidVulnerabilityType)",
			finding.Type,
		)
	}

	// Validate Severity field (enum)
	if finding.Severity == "" {
		return NewValidationError(
			fmt.Sprintf("findings[%d].severity", index),
			"field is required and cannot be empty",
			finding.Severity,
		)
	}
	if !types.IsValidSeverityLevel(finding.Severity) {
		return NewValidationError(
			fmt.Sprintf("findings[%d].severity", index),
			"must be one of: low, medium, high, critical",
			finding.Severity,
		)
	}

	// Validate Confidence field (range: 0.0-1.0)
	if finding.Confidence < 0.0 || finding.Confidence > 1.0 {
		return NewValidationError(
			fmt.Sprintf("findings[%d].confidence", index),
			"must be between 0.0 and 1.0 (inclusive)",
			finding.Confidence,
		)
	}

	// Validate Line field (positive integer)
	if finding.Line <= 0 {
		return NewValidationError(
			fmt.Sprintf("findings[%d].line", index),
			"must be a positive integer",
			finding.Line,
		)
	}

	// Validate Message field (non-empty string)
	if finding.Message == "" {
		return NewValidationError(
			fmt.Sprintf("findings[%d].message", index),
			"field is required and cannot be empty",
			finding.Message,
		)
	}

	// Validate Recommendation field (non-empty string)
	if finding.Recommendation == "" {
		return NewValidationError(
			fmt.Sprintf("findings[%d].recommendation", index),
			"field is required and cannot be empty",
			finding.Recommendation,
		)
	}

	return nil
}

// ValidateAPIResponse validates the entire API response
func ValidateAPIResponse(response *APIResponse) error {
	// Findings array can be empty (no vulnerabilities found), but must exist
	if response.Findings == nil {
		return NewValidationError("findings", "field is required (can be empty array)", nil)
	}

	// Validate each finding
	for i, finding := range response.Findings {
		if err := ValidateFinding(&finding, i); err != nil {
			return err
		}
	}

	return nil
}
