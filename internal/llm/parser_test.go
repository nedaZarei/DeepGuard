package llm

import (
	"fmt"
	"strings"
	"testing"
)

func TestParseResponse_ValidResponse(t *testing.T) {
	validJSON := `{
		"findings": [
			{
				"type": "sql_injection",
				"severity": "high",
				"confidence": 0.9,
				"line": 5,
				"message": "SQL injection vulnerability",
				"recommendation": "Use parameterized queries"
			}
		]
	}`

	response, err := ParseResponse(validJSON)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if response == nil {
		t.Fatal("Expected non-nil response")
	}

	if len(response.Findings) != 1 {
		t.Fatalf("Expected 1 finding, got %d", len(response.Findings))
	}

	finding := response.Findings[0]
	if finding.Type != "sql_injection" {
		t.Errorf("Expected type 'sql_injection', got '%s'", finding.Type)
	}
	if finding.Severity != "high" {
		t.Errorf("Expected severity 'high', got '%s'", finding.Severity)
	}
	if finding.Confidence != 0.9 {
		t.Errorf("Expected confidence 0.9, got %f", finding.Confidence)
	}
	if finding.Line != 5 {
		t.Errorf("Expected line 5, got %d", finding.Line)
	}
}

func TestParseResponse_EmptyFindings(t *testing.T) {
	validJSON := `{"findings": []}`

	response, err := ParseResponse(validJSON)
	if err != nil {
		t.Fatalf("Expected no error for empty findings, got: %v", err)
	}

	if len(response.Findings) != 0 {
		t.Errorf("Expected 0 findings, got %d", len(response.Findings))
	}
}

func TestParseResponse_InvalidJSON(t *testing.T) {
	invalidJSON := `{"findings": [invalid json]}`

	_, err := ParseResponse(invalidJSON)
	if err == nil {
		t.Fatal("Expected error for invalid JSON")
	}

	if !strings.Contains(err.Error(), "invalid JSON") {
		t.Errorf("Expected 'invalid JSON' error, got: %v", err)
	}
}

func TestParseResponse_MissingFindingsField(t *testing.T) {
	invalidJSON := `{}`

	_, err := ParseResponse(invalidJSON)
	if err == nil {
		t.Fatal("Expected error for missing findings field")
	}
}

func TestParseResponse_InvalidType(t *testing.T) {
	invalidJSON := `{
		"findings": [
			{
				"type": "invalid_type",
				"severity": "high",
				"confidence": 0.9,
				"line": 5,
				"message": "Test",
				"recommendation": "Fix it"
			}
		]
	}`

	_, err := ParseResponse(invalidJSON)
	if err == nil {
		t.Fatal("Expected validation error for invalid type")
	}

	if !strings.Contains(err.Error(), "validation failed") {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

func TestParseResponse_InvalidSeverity(t *testing.T) {
	invalidJSON := `{
		"findings": [
			{
				"type": "sql_injection",
				"severity": "super_critical",
				"confidence": 0.9,
				"line": 5,
				"message": "Test",
				"recommendation": "Fix it"
			}
		]
	}`

	_, err := ParseResponse(invalidJSON)
	if err == nil {
		t.Fatal("Expected validation error for invalid severity")
	}
}

func TestParseResponse_InvalidConfidence(t *testing.T) {
	tests := []struct {
		name       string
		confidence float64
	}{
		{"negative confidence", -0.1},
		{"confidence > 1", 1.5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			invalidJSON := `{
				"findings": [
					{
						"type": "sql_injection",
						"severity": "high",
						"confidence": ` + fmt.Sprintf("%f", tt.confidence) + `,
						"line": 5,
						"message": "Test",
						"recommendation": "Fix it"
					}
				]
			}`

			_, err := ParseResponse(invalidJSON)
			if err == nil {
				t.Fatal("Expected validation error for invalid confidence")
			}
		})
	}
}

func TestParseResponse_InvalidLine(t *testing.T) {
	invalidJSON := `{
		"findings": [
			{
				"type": "sql_injection",
				"severity": "high",
				"confidence": 0.9,
				"line": -1,
				"message": "Test",
				"recommendation": "Fix it"
			}
		]
	}`

	_, err := ParseResponse(invalidJSON)
	if err == nil {
		t.Fatal("Expected validation error for negative line number")
	}
}

func TestParseResponse_EmptyMessage(t *testing.T) {
	invalidJSON := `{
		"findings": [
			{
				"type": "sql_injection",
				"severity": "high",
				"confidence": 0.9,
				"line": 5,
				"message": "",
				"recommendation": "Fix it"
			}
		]
	}`

	_, err := ParseResponse(invalidJSON)
	if err == nil {
		t.Fatal("Expected validation error for empty message")
	}
}

func TestParseResponse_EmptyRecommendation(t *testing.T) {
	invalidJSON := `{
		"findings": [
			{
				"type": "sql_injection",
				"severity": "high",
				"confidence": 0.9,
				"line": 5,
				"message": "Test",
				"recommendation": ""
			}
		]
	}`

	_, err := ParseResponse(invalidJSON)
	if err == nil {
		t.Fatal("Expected validation error for empty recommendation")
	}
}

func TestParseResponse_MultipleFindings(t *testing.T) {
	validJSON := `{
		"findings": [
			{
				"type": "sql_injection",
				"severity": "high",
				"confidence": 0.9,
				"line": 5,
				"message": "SQL injection",
				"recommendation": "Use parameterized queries"
			},
			{
				"type": "xss",
				"severity": "medium",
				"confidence": 0.7,
				"line": 10,
				"message": "XSS vulnerability",
				"recommendation": "Escape user input"
			}
		]
	}`

	response, err := ParseResponse(validJSON)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if len(response.Findings) != 2 {
		t.Fatalf("Expected 2 findings, got %d", len(response.Findings))
	}
}

func TestParseResponseWithRetry_FirstAttemptSuccess(t *testing.T) {
	validJSON := `{"findings": []}`

	response, shouldRetry, err := ParseResponseWithRetry(validJSON, 1)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if shouldRetry {
		t.Error("Expected shouldRetry to be false on success")
	}

	if response == nil {
		t.Fatal("Expected non-nil response")
	}
}

func TestParseResponseWithRetry_FirstAttemptFailure(t *testing.T) {
	invalidJSON := `{"findings": [invalid]}`

	response, shouldRetry, err := ParseResponseWithRetry(invalidJSON, 1)
	if err == nil {
		t.Fatal("Expected error for invalid JSON")
	}

	if !shouldRetry {
		t.Error("Expected shouldRetry to be true on first attempt failure")
	}

	if response != nil {
		t.Error("Expected nil response on failure")
	}
}

func TestParseResponseWithRetry_SecondAttemptFailure(t *testing.T) {
	invalidJSON := `{"findings": [invalid]}`

	response, shouldRetry, err := ParseResponseWithRetry(invalidJSON, 2)
	if err == nil {
		t.Fatal("Expected error for invalid JSON")
	}

	if shouldRetry {
		t.Error("Expected shouldRetry to be false on second attempt failure")
	}

	if response != nil {
		t.Error("Expected nil response on failure")
	}
}

func TestCreateStricterPrompt(t *testing.T) {
	original := "Analyze this code for vulnerabilities"

	stricter := CreateStricterPrompt(original)

	if !strings.Contains(stricter, "CRITICAL INSTRUCTION") {
		t.Error("Expected stricter prompt to contain 'CRITICAL INSTRUCTION'")
	}

	if !strings.Contains(stricter, original) {
		t.Error("Expected stricter prompt to contain original prompt")
	}

	if !strings.Contains(stricter, "ONLY valid JSON") {
		t.Error("Expected stricter prompt to emphasize JSON-only output")
	}
}

func TestExtractJSONFromMarkdown(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name: "JSON in markdown code block",
			input: "Here's the analysis:\n```json\n{\"findings\": []}\n```",
			expected: `{"findings": []}`,
		},
		{
			name: "JSON in code block without language",
			input: "```\n{\"findings\": []}\n```",
			expected: `{"findings": []}`,
		},
		{
			name: "No markdown block",
			input: `{"findings": []}`,
			expected: `{"findings": []}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractJSONFromMarkdown(tt.input)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestParseResponseLenient(t *testing.T) {
	markdownWrapped := "Here's the result:\n```json\n{\"findings\": []}\n```"

	response, err := ParseResponseLenient(markdownWrapped)
	if err != nil {
		t.Fatalf("Expected lenient parser to handle markdown, got error: %v", err)
	}

	if response == nil {
		t.Fatal("Expected non-nil response")
	}

	if len(response.Findings) != 0 {
		t.Errorf("Expected 0 findings, got %d", len(response.Findings))
	}
}

func TestTruncateForLog(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxLen   int
		expected string
	}{
		{
			name:     "Short string",
			input:    "Hello",
			maxLen:   10,
			expected: "Hello",
		},
		{
			name:     "Exact length",
			input:    "Hello",
			maxLen:   5,
			expected: "Hello",
		},
		{
			name:     "Long string",
			input:    "This is a very long string that needs truncation",
			maxLen:   20,
			expected: "This is a very long ... [truncated]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateForLog(tt.input, tt.maxLen)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}
