package report

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

// TestIntegration_FullReportWorkflow is an integration test that verifies
// the complete workflow from creating findings to writing a JSON report
func TestIntegration_FullReportWorkflow(t *testing.T) {
	// Create sample findings from a hypothetical scan
	findings := []Finding{
		{
			ID:             "VULN-001",
			Type:           "sql_injection",
			Severity:       SeverityCritical,
			Confidence:     0.98,
			File:           "app/models/user.go",
			Line:           142,
			Column:         15,
			FunctionName:   "GetUserByID",
			Message:        "SQL injection vulnerability: User input directly concatenated into SQL query",
			Recommendation: "Use parameterized queries or an ORM with prepared statements",
			CodeSnippet:    `query := "SELECT * FROM users WHERE id = " + userID`,
		},
		{
			ID:             "VULN-002",
			Type:           "xss",
			Severity:       SeverityHigh,
			Confidence:     0.92,
			File:           "app/handlers/profile.go",
			Line:           87,
			Column:         22,
			FunctionName:   "RenderProfile",
			Message:        "Cross-site scripting (XSS) vulnerability: Unescaped user input in template",
			Recommendation: "Use proper HTML escaping or a template engine with auto-escaping",
			CodeSnippet:    `html := "<div>" + userBio + "</div>"`,
		},
		{
			ID:             "VULN-003",
			Type:           "path_traversal",
			Severity:       SeverityHigh,
			Confidence:     0.85,
			File:           "app/handlers/files.go",
			Line:           56,
			Column:         10,
			FunctionName:   "DownloadFile",
			Message:        "Path traversal vulnerability: User-controlled file path without validation",
			Recommendation: "Validate and sanitize file paths, use allowlist of permitted directories",
			CodeSnippet:    `filePath := "./uploads/" + filename`,
		},
		{
			ID:             "VULN-004",
			Type:           "auth_issue",
			Severity:       SeverityMedium,
			Confidence:     0.78,
			File:           "app/middleware/auth.go",
			Line:           203,
			Column:         5,
			FunctionName:   "CheckPermissions",
			Message:        "Authorization bypass: Missing permission check for admin actions",
			Recommendation: "Implement proper role-based access control (RBAC)",
		},
	}

	// Generate summary from findings
	summary := GenerateSummary(findings)

	// Create scan metadata
	scanStart := time.Now().Add(-2 * time.Minute)
	metadata := ScanMetadata{
		Timestamp:           scanStart.Format(time.RFC3339),
		TargetPath:          "/Users/test/project",
		Languages:           []string{"go", "javascript"},
		Frameworks:          []string{"gin", "express"},
		ModelUsed:           "gpt-4o",
		TotalCost:           2.47,
		ScanDurationSeconds: 120,
	}

	// Create complete report
	report := ScanReport{
		ScanMetadata: metadata,
		Findings:     findings,
		Summary:      summary,
	}

	// Validate report structure
	if err := ValidateReport(report); err != nil {
		t.Fatalf("Report validation failed: %v", err)
	}

	// Write report to temp directory
	tempDir := t.TempDir()
	outputPath, err := WriteReport(report, tempDir)
	if err != nil {
		t.Fatalf("Failed to write report: %v", err)
	}

	t.Logf("Report written to: %s", outputPath)

	// Read back and verify
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read report file: %v", err)
	}

	// Unmarshal and verify structure
	var loadedReport ScanReport
	if err := json.Unmarshal(data, &loadedReport); err != nil {
		t.Fatalf("Failed to unmarshal report: %v", err)
	}

	// Verify metadata
	if loadedReport.ScanMetadata.TargetPath != "/Users/test/project" {
		t.Errorf("Target path mismatch")
	}
	if loadedReport.ScanMetadata.TotalCost != 2.47 {
		t.Errorf("Total cost mismatch: expected 2.47, got %.2f", loadedReport.ScanMetadata.TotalCost)
	}

	// Verify findings count
	if len(loadedReport.Findings) != 4 {
		t.Errorf("Expected 4 findings, got %d", len(loadedReport.Findings))
	}

	// Verify summary
	if loadedReport.Summary.TotalFindings != 4 {
		t.Errorf("Summary total_findings should be 4, got %d", loadedReport.Summary.TotalFindings)
	}

	// Verify severity breakdown
	if loadedReport.Summary.BySeverity[SeverityCritical] != 1 {
		t.Errorf("Expected 1 critical finding, got %d", loadedReport.Summary.BySeverity[SeverityCritical])
	}
	if loadedReport.Summary.BySeverity[SeverityHigh] != 2 {
		t.Errorf("Expected 2 high findings, got %d", loadedReport.Summary.BySeverity[SeverityHigh])
	}
	if loadedReport.Summary.BySeverity[SeverityMedium] != 1 {
		t.Errorf("Expected 1 medium finding, got %d", loadedReport.Summary.BySeverity[SeverityMedium])
	}

	// Verify type breakdown
	if loadedReport.Summary.ByType["sql_injection"] != 1 {
		t.Errorf("Expected 1 sql_injection finding, got %d", loadedReport.Summary.ByType["sql_injection"])
	}
	if loadedReport.Summary.ByType["xss"] != 1 {
		t.Errorf("Expected 1 xss finding, got %d", loadedReport.Summary.ByType["xss"])
	}

	// Verify first finding details
	firstFinding := loadedReport.Findings[0]
	if firstFinding.ID != "VULN-001" {
		t.Errorf("First finding ID mismatch")
	}
	if firstFinding.Type != "sql_injection" {
		t.Errorf("First finding type mismatch")
	}
	if firstFinding.Severity != SeverityCritical {
		t.Errorf("First finding severity mismatch")
	}
	if firstFinding.Confidence != 0.98 {
		t.Errorf("First finding confidence mismatch")
	}

	// Verify JSON is pretty-printed
	jsonStr := string(data)
	if len(jsonStr) < 100 {
		t.Error("JSON output seems too short")
	}

	// Check for proper indentation (2 spaces)
	if !containsIndentation(jsonStr, "  ") {
		t.Error("JSON should be indented with 2 spaces")
	}

	t.Logf("✓ Integration test passed: Full report workflow works correctly")
	t.Logf("✓ Report contains %d findings", len(loadedReport.Findings))
	t.Logf("✓ Total cost: $%.2f", loadedReport.ScanMetadata.TotalCost)
	t.Logf("✓ Scan duration: %d seconds", loadedReport.ScanMetadata.ScanDurationSeconds)
}

// Helper function to check if JSON contains proper indentation
func containsIndentation(jsonStr, indent string) bool {
	lines := splitLines(jsonStr)
	for _, line := range lines {
		if len(line) > len(indent) && line[:len(indent)] == indent {
			return true
		}
	}
	return false
}

// Helper to split string into lines
func splitLines(s string) []string {
	var lines []string
	var currentLine string
	for _, r := range s {
		if r == '\n' {
			lines = append(lines, currentLine)
			currentLine = ""
		} else {
			currentLine += string(r)
		}
	}
	if currentLine != "" {
		lines = append(lines, currentLine)
	}
	return lines
}
