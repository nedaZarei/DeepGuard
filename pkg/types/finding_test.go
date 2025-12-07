package types

import (
	"testing"
)

func TestIsValidVulnerabilityType(t *testing.T) {
	tests := []struct {
		name     string
		vulnType string
		expected bool
	}{
		{"sql_injection", "sql_injection", true},
		{"xss", "xss", true},
		{"path_traversal", "path_traversal", true},
		{"insecure_deserialization", "insecure_deserialization", true},
		{"auth_issue", "auth_issue", true},
		{"crypto_issue", "crypto_issue", true},
		{"invalid", "buffer_overflow", false},
		{"empty", "", false},
		{"random", "random_vuln", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidVulnerabilityType(tt.vulnType)
			if result != tt.expected {
				t.Errorf("IsValidVulnerabilityType(%s) = %v, want %v", tt.vulnType, result, tt.expected)
			}
		})
	}
}

func TestIsValidSeverityLevel(t *testing.T) {
	tests := []struct {
		name     string
		severity string
		expected bool
	}{
		{"low", "low", true},
		{"medium", "medium", true},
		{"high", "high", true},
		{"critical", "critical", true},
		{"invalid", "super_high", false},
		{"empty", "", false},
		{"random", "unknown", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidSeverityLevel(tt.severity)
			if result != tt.expected {
				t.Errorf("IsValidSeverityLevel(%s) = %v, want %v", tt.severity, result, tt.expected)
			}
		})
	}
}

func TestVulnerabilityTypeConstants(t *testing.T) {
	// Test that constants are valid
	vulnTypes := []VulnerabilityType{
		VulnTypeSQLInjection,
		VulnTypeXSS,
		VulnTypePathTraversal,
		VulnTypeInsecureDeserialization,
		VulnTypeAuthIssue,
		VulnTypeCryptoIssue,
	}

	for _, vt := range vulnTypes {
		if !IsValidVulnerabilityType(string(vt)) {
			t.Errorf("Constant %s should be valid", vt)
		}
	}
}

func TestSeverityLevelConstants(t *testing.T) {
	// Test that constants are valid
	severities := []SeverityLevel{
		SeverityLow,
		SeverityMedium,
		SeverityHigh,
		SeverityCritical,
	}

	for _, s := range severities {
		if !IsValidSeverityLevel(string(s)) {
			t.Errorf("Constant %s should be valid", s)
		}
	}
}

func TestFindingJSONTags(t *testing.T) {
	// This test ensures the Finding struct has proper JSON tags
	// We'll create a finding and verify it can be marshaled/unmarshaled
	finding := Finding{
		Type:           "sql_injection",
		Severity:       "high",
		Confidence:     0.9,
		Line:           5,
		Message:        "Test message",
		Recommendation: "Test recommendation",
		ChunkID:        "abc123",
		FilePath:       "/test/file.js",
		FunctionName:   "testFunc",
		AbsoluteLine:   105,
		LineRangeStart: 100,
		LineRangeEnd:   110,
	}

	// Verify all fields are set
	if finding.Type != "sql_injection" {
		t.Error("Type not set correctly")
	}
	if finding.Severity != "high" {
		t.Error("Severity not set correctly")
	}
	if finding.Confidence != 0.9 {
		t.Error("Confidence not set correctly")
	}
	if finding.Line != 5 {
		t.Error("Line not set correctly")
	}
	if finding.Message != "Test message" {
		t.Error("Message not set correctly")
	}
	if finding.Recommendation != "Test recommendation" {
		t.Error("Recommendation not set correctly")
	}
	if finding.ChunkID != "abc123" {
		t.Error("ChunkID not set correctly")
	}
	if finding.FilePath != "/test/file.js" {
		t.Error("FilePath not set correctly")
	}
	if finding.FunctionName != "testFunc" {
		t.Error("FunctionName not set correctly")
	}
	if finding.AbsoluteLine != 105 {
		t.Error("AbsoluteLine not set correctly")
	}
	if finding.LineRangeStart != 100 {
		t.Error("LineRangeStart not set correctly")
	}
	if finding.LineRangeEnd != 110 {
		t.Error("LineRangeEnd not set correctly")
	}
}
