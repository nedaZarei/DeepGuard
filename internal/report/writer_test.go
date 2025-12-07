package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateFinding_Valid(t *testing.T) {
	finding := Finding{
		ID:             "F001",
		Type:           "sql_injection",
		Severity:       SeverityHigh,
		Confidence:     0.95,
		File:           "app/models/user.go",
		Line:           42,
		Column:         10,
		FunctionName:   "GetUser",
		Message:        "SQL injection vulnerability detected",
		Recommendation: "Use parameterized queries",
		CodeSnippet:    `query := "SELECT * FROM users WHERE id = " + userInput`,
	}

	err := ValidateFinding(finding)
	if err != nil {
		t.Errorf("Expected valid finding to pass validation, got error: %v", err)
	}
}

func TestValidateFinding_MissingRequiredFields(t *testing.T) {
	tests := []struct {
		name    string
		finding Finding
		wantErr string
	}{
		{
			name: "missing type",
			finding: Finding{
				Severity:   SeverityHigh,
				Confidence: 0.9,
				File:       "test.go",
				Line:       1,
				Message:    "test",
			},
			wantErr: "type is required",
		},
		{
			name: "missing severity",
			finding: Finding{
				Type:       "sql_injection",
				Confidence: 0.9,
				File:       "test.go",
				Line:       1,
				Message:    "test",
			},
			wantErr: "severity is required",
		},
		{
			name: "missing file",
			finding: Finding{
				Type:       "sql_injection",
				Severity:   SeverityHigh,
				Confidence: 0.9,
				Line:       1,
				Message:    "test",
			},
			wantErr: "file is required",
		},
		{
			name: "missing message",
			finding: Finding{
				Type:       "sql_injection",
				Severity:   SeverityHigh,
				Confidence: 0.9,
				File:       "test.go",
				Line:       1,
			},
			wantErr: "message is required",
		},
		{
			name: "invalid line number",
			finding: Finding{
				Type:       "sql_injection",
				Severity:   SeverityHigh,
				Confidence: 0.9,
				File:       "test.go",
				Line:       0,
				Message:    "test",
			},
			wantErr: "line must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFinding(tt.finding)
			if err == nil {
				t.Errorf("Expected validation error, got nil")
			} else if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Expected error containing '%s', got '%s'", tt.wantErr, err.Error())
			}
		})
	}
}

func TestValidateFinding_InvalidSeverity(t *testing.T) {
	finding := Finding{
		Type:       "sql_injection",
		Severity:   "super_critical", // Invalid
		Confidence: 0.9,
		File:       "test.go",
		Line:       1,
		Message:    "test",
	}

	err := ValidateFinding(finding)
	if err == nil {
		t.Error("Expected validation error for invalid severity")
	} else if !strings.Contains(err.Error(), "invalid severity") {
		t.Errorf("Expected severity validation error, got: %v", err)
	}
}

func TestValidateFinding_InvalidConfidence(t *testing.T) {
	tests := []struct {
		name       string
		confidence float64
	}{
		{"confidence below 0", -0.1},
		{"confidence above 1", 1.5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := Finding{
				Type:       "sql_injection",
				Severity:   SeverityHigh,
				Confidence: tt.confidence,
				File:       "test.go",
				Line:       1,
				Message:    "test",
			}

			err := ValidateFinding(finding)
			if err == nil {
				t.Error("Expected validation error for invalid confidence")
			} else if !strings.Contains(err.Error(), "confidence must be between") {
				t.Errorf("Expected confidence validation error, got: %v", err)
			}
		})
	}
}

func TestValidateReport_ValidReport(t *testing.T) {
	report := ScanReport{
		ScanMetadata: ScanMetadata{
			Timestamp:           time.Now().Format(time.RFC3339),
			TargetPath:          "/path/to/project",
			Languages:           []string{"go", "javascript"},
			Frameworks:          []string{"express"},
			ModelUsed:           "gpt-4o",
			TotalCost:           2.5,
			ScanDurationSeconds: 120,
		},
		Findings: []Finding{
			{
				Type:       "sql_injection",
				Severity:   SeverityHigh,
				Confidence: 0.95,
				File:       "test.go",
				Line:       10,
				Message:    "SQL injection found",
			},
		},
		Summary: Summary{
			TotalFindings: 1,
			BySeverity: map[string]int{
				SeverityHigh: 1,
			},
			ByType: map[string]int{
				"sql_injection": 1,
			},
		},
	}

	err := ValidateReport(report)
	if err != nil {
		t.Errorf("Expected valid report to pass validation, got error: %v", err)
	}
}

func TestValidateReport_MissingMetadata(t *testing.T) {
	tests := []struct {
		name     string
		metadata ScanMetadata
		wantErr  string
	}{
		{
			name: "missing timestamp",
			metadata: ScanMetadata{
				TargetPath: "/path",
			},
			wantErr: "timestamp is required",
		},
		{
			name: "missing target_path",
			metadata: ScanMetadata{
				Timestamp: time.Now().Format(time.RFC3339),
			},
			wantErr: "target_path is required",
		},
		{
			name: "invalid timestamp format",
			metadata: ScanMetadata{
				Timestamp:  "2024-01-01", // Not RFC3339
				TargetPath: "/path",
			},
			wantErr: "invalid timestamp format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := ScanReport{
				ScanMetadata: tt.metadata,
				Findings:     []Finding{},
				Summary:      Summary{TotalFindings: 0},
			}

			err := ValidateReport(report)
			if err == nil {
				t.Error("Expected validation error, got nil")
			} else if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Expected error containing '%s', got '%s'", tt.wantErr, err.Error())
			}
		})
	}
}

func TestValidateReport_SummaryMismatch(t *testing.T) {
	report := ScanReport{
		ScanMetadata: ScanMetadata{
			Timestamp:  time.Now().Format(time.RFC3339),
			TargetPath: "/path",
		},
		Findings: []Finding{
			{
				Type:       "sql_injection",
				Severity:   SeverityHigh,
				Confidence: 0.9,
				File:       "test.go",
				Line:       1,
				Message:    "test",
			},
		},
		Summary: Summary{
			TotalFindings: 5, // Mismatch!
		},
	}

	err := ValidateReport(report)
	if err == nil {
		t.Error("Expected validation error for summary mismatch")
	} else if !strings.Contains(err.Error(), "does not match findings count") {
		t.Errorf("Expected summary mismatch error, got: %v", err)
	}
}

func TestGenerateSummary(t *testing.T) {
	findings := []Finding{
		{
			Type:       "sql_injection",
			Severity:   SeverityCritical,
			Confidence: 0.95,
			File:       "test1.go",
			Line:       10,
			Message:    "test",
		},
		{
			Type:       "xss",
			Severity:   SeverityHigh,
			Confidence: 0.9,
			File:       "test2.go",
			Line:       20,
			Message:    "test",
		},
		{
			Type:       "sql_injection",
			Severity:   SeverityMedium,
			Confidence: 0.8,
			File:       "test3.go",
			Line:       30,
			Message:    "test",
		},
	}

	summary := GenerateSummary(findings)

	if summary.TotalFindings != 3 {
		t.Errorf("Expected total_findings=3, got %d", summary.TotalFindings)
	}

	if summary.BySeverity[SeverityCritical] != 1 {
		t.Errorf("Expected 1 critical finding, got %d", summary.BySeverity[SeverityCritical])
	}
	if summary.BySeverity[SeverityHigh] != 1 {
		t.Errorf("Expected 1 high finding, got %d", summary.BySeverity[SeverityHigh])
	}
	if summary.BySeverity[SeverityMedium] != 1 {
		t.Errorf("Expected 1 medium finding, got %d", summary.BySeverity[SeverityMedium])
	}

	if summary.ByType["sql_injection"] != 2 {
		t.Errorf("Expected 2 sql_injection findings, got %d", summary.ByType["sql_injection"])
	}
	if summary.ByType["xss"] != 1 {
		t.Errorf("Expected 1 xss finding, got %d", summary.ByType["xss"])
	}
}

func TestGenerateSummary_EmptyFindings(t *testing.T) {
	summary := GenerateSummary([]Finding{})

	if summary.TotalFindings != 0 {
		t.Errorf("Expected total_findings=0, got %d", summary.TotalFindings)
	}

	if len(summary.BySeverity) != 0 {
		t.Errorf("Expected empty severity map, got %v", summary.BySeverity)
	}

	if len(summary.ByType) != 0 {
		t.Errorf("Expected empty type map, got %v", summary.ByType)
	}
}

func TestGenerateFilename(t *testing.T) {
	filename := generateFilename()

	if !strings.HasPrefix(filename, "scan-") {
		t.Errorf("Expected filename to start with 'scan-', got: %s", filename)
	}

	if !strings.HasSuffix(filename, ".json") {
		t.Errorf("Expected filename to end with '.json', got: %s", filename)
	}

	// Check format: scan-YYYYMMDD-HHMMSS.json
	// Should be 24 characters total: "scan-" (5) + "YYYYMMDD-HHMMSS" (15) + ".json" (5) = 25
	if len(filename) != 25 {
		t.Errorf("Expected filename length 25, got %d: %s", len(filename), filename)
	}
}

func TestNormalizeFilePath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"path/to/file.go", "path/to/file.go"},
		{`path\to\file.go`, "path/to/file.go"},
		{`C:\Users\test\file.go`, "C:/Users/test/file.go"},
	}

	for _, tt := range tests {
		result := NormalizeFilePath(tt.input)
		if result != tt.expected {
			t.Errorf("NormalizeFilePath(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestWriteReport_Success(t *testing.T) {
	// Create temp directory for test
	tempDir := t.TempDir()

	report := ScanReport{
		ScanMetadata: ScanMetadata{
			Timestamp:           time.Now().Format(time.RFC3339),
			TargetPath:          "/test/path",
			Languages:           []string{"go"},
			Frameworks:          []string{"gin"},
			ModelUsed:           "gpt-4o-mini",
			TotalCost:           1.5,
			ScanDurationSeconds: 60,
		},
		Findings: []Finding{
			{
				ID:             "F001",
				Type:           "sql_injection",
				Severity:       SeverityHigh,
				Confidence:     0.95,
				File:           "test.go",
				Line:           42,
				FunctionName:   "GetUser",
				Message:        "SQL injection found",
				Recommendation: "Use parameterized queries",
			},
		},
		Summary: Summary{
			TotalFindings: 1,
			BySeverity: map[string]int{
				SeverityHigh: 1,
			},
			ByType: map[string]int{
				"sql_injection": 1,
			},
		},
	}

	outputPath, err := WriteReport(report, tempDir)
	if err != nil {
		t.Fatalf("WriteReport failed: %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Errorf("Report file was not created: %s", outputPath)
	}

	// Read and verify JSON content
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read report file: %v", err)
	}

	var readReport ScanReport
	if err := json.Unmarshal(data, &readReport); err != nil {
		t.Fatalf("Failed to unmarshal report: %v", err)
	}

	// Verify content matches
	if readReport.Summary.TotalFindings != 1 {
		t.Errorf("Expected 1 finding, got %d", readReport.Summary.TotalFindings)
	}

	// Verify pretty-printing (should contain newlines and indentation)
	jsonStr := string(data)
	if !strings.Contains(jsonStr, "\n") {
		t.Error("JSON should be pretty-printed with newlines")
	}
	if !strings.Contains(jsonStr, "  ") {
		t.Error("JSON should be indented with 2 spaces")
	}
}

func TestWriteReport_InvalidReport(t *testing.T) {
	tempDir := t.TempDir()

	invalidReport := ScanReport{
		ScanMetadata: ScanMetadata{
			// Missing required timestamp
			TargetPath: "/test",
		},
		Findings: []Finding{},
		Summary:  Summary{TotalFindings: 0},
	}

	_, err := WriteReport(invalidReport, tempDir)
	if err == nil {
		t.Error("Expected error for invalid report")
	} else if !strings.Contains(err.Error(), "validation failed") {
		t.Errorf("Expected validation error, got: %v", err)
	}
}

func TestWriteReport_DirectoryCreation(t *testing.T) {
	// Use a temp directory that doesn't exist yet
	tempDir := filepath.Join(t.TempDir(), "nested", "reports")

	report := ScanReport{
		ScanMetadata: ScanMetadata{
			Timestamp:  time.Now().Format(time.RFC3339),
			TargetPath: "/test",
		},
		Findings: []Finding{},
		Summary:  Summary{TotalFindings: 0},
	}

	outputPath, err := WriteReport(report, tempDir)
	if err != nil {
		t.Fatalf("WriteReport failed: %v", err)
	}

	// Verify directory was created
	if _, err := os.Stat(tempDir); os.IsNotExist(err) {
		t.Error("Output directory was not created")
	}

	// Verify file exists
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Error("Report file was not created")
	}
}

func TestWriteReport_DefaultOutputDir(t *testing.T) {
	// Clean up default directory if it exists
	defer os.RemoveAll(DefaultOutputDir)

	report := ScanReport{
		ScanMetadata: ScanMetadata{
			Timestamp:  time.Now().Format(time.RFC3339),
			TargetPath: "/test",
		},
		Findings: []Finding{},
		Summary:  Summary{TotalFindings: 0},
	}

	outputPath, err := WriteReport(report, "")
	if err != nil {
		t.Fatalf("WriteReport with default dir failed: %v", err)
	}

	// Verify file is in default directory (may or may not have ./ prefix)
	normalizedPath := strings.TrimPrefix(outputPath, "./")
	expectedPrefix := strings.TrimPrefix(DefaultOutputDir, "./")
	if !strings.HasPrefix(normalizedPath, expectedPrefix) {
		t.Errorf("Expected file in %s, got: %s", DefaultOutputDir, outputPath)
	}
}

func TestWriteReport_ExistingFile(t *testing.T) {
	tempDir := t.TempDir()

	report := ScanReport{
		ScanMetadata: ScanMetadata{
			Timestamp:  time.Now().Format(time.RFC3339),
			TargetPath: "/test",
		},
		Findings: []Finding{},
		Summary:  Summary{TotalFindings: 0},
	}

	// Write first report
	path1, err := WriteReport(report, tempDir)
	if err != nil {
		t.Fatalf("First write failed: %v", err)
	}

	// Wait a second to ensure different timestamp
	time.Sleep(1 * time.Second)

	// Write second report
	path2, err := WriteReport(report, tempDir)
	if err != nil {
		t.Fatalf("Second write failed: %v", err)
	}

	// Verify different filenames (different timestamps)
	if path1 == path2 {
		t.Error("Expected different filenames for reports written at different times")
	}

	// Verify both files exist
	if _, err := os.Stat(path1); os.IsNotExist(err) {
		t.Error("First report file should still exist")
	}
	if _, err := os.Stat(path2); os.IsNotExist(err) {
		t.Error("Second report file should exist")
	}
}

func TestEnsureDirectory_NonWritableDirectory(t *testing.T) {
	// Skip on Windows as permission handling is different
	if os.Getenv("GOOS") == "windows" {
		t.Skip("Skipping permission test on Windows")
	}

	tempDir := t.TempDir()
	testDir := filepath.Join(tempDir, "readonly")

	// Create directory
	if err := os.Mkdir(testDir, 0755); err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	// Make it read-only
	if err := os.Chmod(testDir, 0444); err != nil {
		t.Fatalf("Failed to change permissions: %v", err)
	}
	defer os.Chmod(testDir, 0755) // Restore for cleanup

	// Try to ensure directory (should fail writable check)
	err := ensureDirectory(testDir)
	if err == nil {
		t.Error("Expected error for non-writable directory")
	} else if !strings.Contains(err.Error(), "not writable") {
		t.Errorf("Expected 'not writable' error, got: %v", err)
	}
}

func TestEnsureDirectory_FileExistsWithSameName(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "testfile")

	// Create a file
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Try to ensure directory with same name as file
	err := ensureDirectory(testFile)
	if err == nil {
		t.Error("Expected error when path exists but is not a directory")
	} else if !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("Expected 'not a directory' error, got: %v", err)
	}
}
