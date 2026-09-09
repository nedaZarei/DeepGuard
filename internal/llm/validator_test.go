package llm

import (
	"strings"
	"testing"

	"github.com/Neda-Zarei/deep-guard/pkg/types"
)

func TestValidateFinding_Valid(t *testing.T) {
	finding := types.Finding{
		Type:           "sql_injection",
		Severity:       "high",
		Confidence:     0.9,
		Line:           5,
		Message:        "SQL injection vulnerability",
		Recommendation: "Use parameterized queries",
	}

	err := ValidateFinding(&finding, 0)
	if err != nil {
		t.Errorf("Expected no error for valid finding, got: %v", err)
	}
}

func TestValidateFinding_InvalidType(t *testing.T) {
	tests := []struct {
		name    string
		typeVal string
		wantErr bool
	}{
		{"empty type", "", true},
		{"invalid type", "not_a_vuln_type", true},
		{"valid sql_injection", "sql_injection", false},
		{"valid xss", "xss", false},
		{"valid path_traversal", "path_traversal", false},
		{"valid insecure_deserialization", "insecure_deserialization", false},
		{"valid auth_issue", "auth_issue", false},
		{"valid crypto_issue", "crypto_issue", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := types.Finding{
				Type:           tt.typeVal,
				Severity:       "high",
				Confidence:     0.9,
				Line:           5,
				Message:        "Test",
				Recommendation: "Fix it",
			}

			err := ValidateFinding(&finding, 0)
			if (err != nil) != tt.wantErr {
				t.Errorf("Expected error=%v, got error=%v", tt.wantErr, err)
			}

			if err != nil && !strings.Contains(err.Error(), "type") {
				t.Errorf("Expected error to mention 'type', got: %v", err)
			}
		})
	}
}

func TestValidateFinding_InvalidSeverity(t *testing.T) {
	tests := []struct {
		name     string
		severity string
		wantErr  bool
	}{
		{"empty severity", "", true},
		{"invalid severity", "super_high", true},
		{"valid low", "low", false},
		{"valid medium", "medium", false},
		{"valid high", "high", false},
		{"valid critical", "critical", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := types.Finding{
				Type:           "sql_injection",
				Severity:       tt.severity,
				Confidence:     0.9,
				Line:           5,
				Message:        "Test",
				Recommendation: "Fix it",
			}

			err := ValidateFinding(&finding, 0)
			if (err != nil) != tt.wantErr {
				t.Errorf("Expected error=%v, got error=%v", tt.wantErr, err)
			}

			if err != nil && !strings.Contains(err.Error(), "severity") {
				t.Errorf("Expected error to mention 'severity', got: %v", err)
			}
		})
	}
}

func TestValidateFinding_InvalidConfidence(t *testing.T) {
	tests := []struct {
		name       string
		confidence float64
		wantErr    bool
	}{
		{"negative confidence", -0.1, true},
		{"confidence > 1", 1.5, true},
		{"confidence = 0", 0.0, false},
		{"confidence = 0.5", 0.5, false},
		{"confidence = 1.0", 1.0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := types.Finding{
				Type:           "sql_injection",
				Severity:       "high",
				Confidence:     tt.confidence,
				Line:           5,
				Message:        "Test",
				Recommendation: "Fix it",
			}

			err := ValidateFinding(&finding, 0)
			if (err != nil) != tt.wantErr {
				t.Errorf("Expected error=%v, got error=%v", tt.wantErr, err)
			}

			if err != nil && !strings.Contains(err.Error(), "confidence") {
				t.Errorf("Expected error to mention 'confidence', got: %v", err)
			}
		})
	}
}

func TestValidateFinding_InvalidLine(t *testing.T) {
	tests := []struct {
		name    string
		line    int
		wantErr bool
	}{
		{"negative line", -1, true},
		{"zero line", 0, true},
		{"positive line", 1, false},
		{"large line", 1000, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := types.Finding{
				Type:           "sql_injection",
				Severity:       "high",
				Confidence:     0.9,
				Line:           tt.line,
				Message:        "Test",
				Recommendation: "Fix it",
			}

			err := ValidateFinding(&finding, 0)
			if (err != nil) != tt.wantErr {
				t.Errorf("Expected error=%v, got error=%v", tt.wantErr, err)
			}

			if err != nil && !strings.Contains(err.Error(), "line") {
				t.Errorf("Expected error to mention 'line', got: %v", err)
			}
		})
	}
}

func TestValidateFinding_EmptyMessage(t *testing.T) {
	finding := types.Finding{
		Type:           "sql_injection",
		Severity:       "high",
		Confidence:     0.9,
		Line:           5,
		Message:        "",
		Recommendation: "Fix it",
	}

	err := ValidateFinding(&finding, 0)
	if err == nil {
		t.Error("Expected error for empty message")
	}

	if !strings.Contains(err.Error(), "message") {
		t.Errorf("Expected error to mention 'message', got: %v", err)
	}
}

func TestValidateFinding_EmptyRecommendation(t *testing.T) {
	finding := types.Finding{
		Type:           "sql_injection",
		Severity:       "high",
		Confidence:     0.9,
		Line:           5,
		Message:        "Test",
		Recommendation: "",
	}

	err := ValidateFinding(&finding, 0)
	if err == nil {
		t.Error("Expected error for empty recommendation")
	}

	if !strings.Contains(err.Error(), "recommendation") {
		t.Errorf("Expected error to mention 'recommendation', got: %v", err)
	}
}

func TestValidateAPIResponse_Valid(t *testing.T) {
	response := &APIResponse{
		Findings: []types.Finding{
			{
				Type:           "sql_injection",
				Severity:       "high",
				Confidence:     0.9,
				Line:           5,
				Message:        "Test",
				Recommendation: "Fix it",
			},
		},
	}

	err := ValidateAPIResponse(response)
	if err != nil {
		t.Errorf("Expected no error for valid response, got: %v", err)
	}
}

func TestValidateAPIResponse_EmptyFindings(t *testing.T) {
	response := &APIResponse{
		Findings: []types.Finding{},
	}

	err := ValidateAPIResponse(response)
	if err != nil {
		t.Errorf("Expected no error for empty findings array, got: %v", err)
	}
}

func TestValidateAPIResponse_NilFindings(t *testing.T) {
	response := &APIResponse{
		Findings: nil,
	}

	err := ValidateAPIResponse(response)
	if err == nil {
		t.Error("Expected error for nil findings")
	}

	if !strings.Contains(err.Error(), "findings") {
		t.Errorf("Expected error to mention 'findings', got: %v", err)
	}
}

func TestValidateAPIResponse_MultipleFindings(t *testing.T) {
	response := &APIResponse{
		Findings: []types.Finding{
			{
				Type:           "sql_injection",
				Severity:       "high",
				Confidence:     0.9,
				Line:           5,
				Message:        "Test 1",
				Recommendation: "Fix 1",
			},
			{
				Type:           "xss",
				Severity:       "medium",
				Confidence:     0.7,
				Line:           10,
				Message:        "Test 2",
				Recommendation: "Fix 2",
			},
		},
	}

	err := ValidateAPIResponse(response)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
}

func TestValidateAPIResponse_InvalidFinding(t *testing.T) {
	response := &APIResponse{
		Findings: []types.Finding{
			{
				Type:           "sql_injection",
				Severity:       "high",
				Confidence:     0.9,
				Line:           5,
				Message:        "Test",
				Recommendation: "Fix",
			},
			{
				Type:           "invalid_type", // Invalid
				Severity:       "high",
				Confidence:     0.9,
				Line:           10,
				Message:        "Test",
				Recommendation: "Fix",
			},
		},
	}

	err := ValidateAPIResponse(response)
	if err == nil {
		t.Error("Expected error for invalid finding in array")
	}

	if !strings.Contains(err.Error(), "findings[1]") {
		t.Errorf("Expected error to mention 'findings[1]', got: %v", err)
	}
}

func TestValidationError_Error(t *testing.T) {
	err := NewValidationError("test_field", "must be positive", -1)

	errMsg := err.Error()
	if !strings.Contains(errMsg, "test_field") {
		t.Errorf("Expected error message to contain field name, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "must be positive") {
		t.Errorf("Expected error message to contain reason, got: %s", errMsg)
	}
}
