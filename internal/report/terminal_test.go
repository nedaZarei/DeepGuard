package report

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestFormatDuration(t *testing.T) {
	tr := NewTerminalReporterWithWriter(&bytes.Buffer{}, 80, false)

	tests := []struct {
		seconds  int
		expected string
	}{
		{0, "0s"},
		{30, "30s"},
		{59, "59s"},
		{60, "1m"},
		{90, "1m 30s"},
		{120, "2m"},
		{125, "2m 5s"},
		{443, "7m 23s"},
		{3600, "60m"},
		{3665, "61m 5s"},
	}

	for _, tt := range tests {
		result := tr.formatDuration(tt.seconds)
		if result != tt.expected {
			t.Errorf("formatDuration(%d) = %q, want %q", tt.seconds, result, tt.expected)
		}
	}
}

func TestFormatCost(t *testing.T) {
	tr := NewTerminalReporterWithWriter(&bytes.Buffer{}, 80, false)

	tests := []struct {
		cost     float64
		expected string
	}{
		{0.0, "$0.00"},
		{0.1, "$0.10"},
		{1.5, "$1.50"},
		{2.45, "$2.45"},
		{10.0, "$10.00"},
		{123.456, "$123.46"}, // Rounds to 2 decimals
	}

	for _, tt := range tests {
		result := tr.formatCost(tt.cost)
		if result != tt.expected {
			t.Errorf("formatCost(%.3f) = %q, want %q", tt.cost, result, tt.expected)
		}
	}
}

func TestFormatTypeName(t *testing.T) {
	tr := NewTerminalReporterWithWriter(&bytes.Buffer{}, 80, false)

	tests := []struct {
		input    string
		expected string
	}{
		{"sql_injection", "Sql Injection"},
		{"xss", "Xss"},
		{"path_traversal", "Path Traversal"},
		{"insecure_deserialization", "Insecure Deserialization"},
		{"auth_issue", "Auth Issue"},
		{"crypto_issue", "Crypto Issue"},
	}

	for _, tt := range tests {
		result := tr.formatTypeName(tt.input)
		if result != tt.expected {
			t.Errorf("formatTypeName(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestStripColors(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"plain text", "plain text"},
		{ColorRed + "red text" + ColorReset, "red text"},
		{ColorBold + ColorYellow + "bold yellow" + ColorReset, "bold yellow"},
		{"before " + ColorCyan + "cyan" + ColorReset + " after", "before cyan after"},
		{"\033[31mRed\033[0m and \033[34mBlue\033[0m", "Red and Blue"},
	}

	for _, tt := range tests {
		result := StripColors(tt.input)
		if result != tt.expected {
			t.Errorf("StripColors(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestColorize_WithColorMode(t *testing.T) {
	tr := NewTerminalReporterWithWriter(&bytes.Buffer{}, 80, true)

	result := tr.colorize("test", ColorRed)
	expected := ColorRed + "test" + ColorReset

	if result != expected {
		t.Errorf("colorize with color mode = %q, want %q", result, expected)
	}
}

func TestColorize_WithoutColorMode(t *testing.T) {
	tr := NewTerminalReporterWithWriter(&bytes.Buffer{}, 80, false)

	result := tr.colorize("test", ColorRed)
	expected := "test"

	if result != expected {
		t.Errorf("colorize without color mode = %q, want %q", result, expected)
	}
}

func TestCenter(t *testing.T) {
	tr := NewTerminalReporterWithWriter(&bytes.Buffer{}, 80, false)

	tests := []struct {
		text     string
		width    int
		expected string
	}{
		{"test", 10, "   test   "},
		{"hello", 11, "   hello   "},
		{"a", 5, "  a  "},
		{"exactly", 7, "exactly"},
		{"toolongtext", 5, "toolo"},
	}

	for _, tt := range tests {
		result := tr.center(tt.text, tt.width)
		if result != tt.expected {
			t.Errorf("center(%q, %d) = %q (len=%d), want %q (len=%d)",
				tt.text, tt.width, result, len(result), tt.expected, len(tt.expected))
		}
	}
}

func TestPrintSummary_EmptyReport(t *testing.T) {
	buf := &bytes.Buffer{}
	tr := NewTerminalReporterWithWriter(buf, 80, false)

	report := ScanReport{
		ScanMetadata: ScanMetadata{
			Timestamp:           time.Now().Format(time.RFC3339),
			TargetPath:          "/test/path",
			Languages:           []string{"go"},
			Frameworks:          []string{},
			ModelUsed:           "gpt-4o-mini",
			TotalCost:           0.0,
			ScanDurationSeconds: 10,
		},
		Findings: []Finding{},
		Summary: Summary{
			TotalFindings: 0,
			BySeverity:    map[string]int{},
			ByType:        map[string]int{},
		},
	}

	tr.PrintSummary(report)

	output := buf.String()

	// Verify key sections are present
	if !strings.Contains(output, "DeepGuard Security Scanner") {
		t.Error("Output should contain header")
	}
	if !strings.Contains(output, "SCAN METADATA") {
		t.Error("Output should contain metadata section")
	}
	if !strings.Contains(output, "SCAN RESULTS") {
		t.Error("Output should contain results section")
	}
	if !strings.Contains(output, "Total Findings") {
		t.Error("Output should contain total findings")
	}
	if !strings.Contains(output, "0") {
		t.Error("Output should show 0 findings")
	}
	if !strings.Contains(output, "$0.00") {
		t.Error("Output should show cost")
	}
	if !strings.Contains(output, "10s") {
		t.Error("Output should show duration")
	}
}

func TestPrintSummary_WithFindings(t *testing.T) {
	buf := &bytes.Buffer{}
	tr := NewTerminalReporterWithWriter(buf, 80, false)

	report := ScanReport{
		ScanMetadata: ScanMetadata{
			Timestamp:           time.Now().Format(time.RFC3339),
			TargetPath:          "/test/project",
			Languages:           []string{"go", "javascript"},
			Frameworks:          []string{"express", "gin"},
			ModelUsed:           "gpt-4o",
			TotalCost:           2.47,
			ScanDurationSeconds: 120,
		},
		Findings: []Finding{
			{Type: "sql_injection", Severity: SeverityCritical, Confidence: 0.95, File: "test.go", Line: 1, Message: "test"},
			{Type: "xss", Severity: SeverityHigh, Confidence: 0.9, File: "test.js", Line: 2, Message: "test"},
			{Type: "xss", Severity: SeverityHigh, Confidence: 0.85, File: "test2.js", Line: 3, Message: "test"},
			{Type: "path_traversal", Severity: SeverityMedium, Confidence: 0.8, File: "test3.go", Line: 4, Message: "test"},
		},
		Summary: Summary{
			TotalFindings: 4,
			BySeverity: map[string]int{
				SeverityCritical: 1,
				SeverityHigh:     2,
				SeverityMedium:   1,
			},
			ByType: map[string]int{
				"sql_injection":  1,
				"xss":            2,
				"path_traversal": 1,
			},
		},
	}

	tr.PrintSummary(report)

	output := buf.String()

	// Verify metadata
	if !strings.Contains(output, "/test/project") {
		t.Error("Output should contain target path")
	}
	if !strings.Contains(output, "go, javascript") {
		t.Error("Output should contain languages")
	}
	if !strings.Contains(output, "express, gin") {
		t.Error("Output should contain frameworks")
	}
	if !strings.Contains(output, "gpt-4o") {
		t.Error("Output should contain model")
	}

	// Verify results
	if !strings.Contains(output, "4") {
		t.Error("Output should show 4 total findings")
	}
	if !strings.Contains(output, "By Severity") {
		t.Error("Output should show severity breakdown")
	}
	if !strings.Contains(output, "Critical") {
		t.Error("Output should show critical severity")
	}
	if !strings.Contains(output, "High") {
		t.Error("Output should show high severity")
	}
	if !strings.Contains(output, "Medium") {
		t.Error("Output should show medium severity")
	}

	// Verify type breakdown
	if !strings.Contains(output, "Top Vulnerability Types") {
		t.Error("Output should show type breakdown header")
	}
	if !strings.Contains(output, "Xss") {
		t.Error("Output should show XSS type")
	}
	if !strings.Contains(output, "Sql Injection") {
		t.Error("Output should show SQL Injection type")
	}

	// Verify footer
	if !strings.Contains(output, "$2.47") {
		t.Error("Output should show cost $2.47")
	}
	if !strings.Contains(output, "2m") {
		t.Error("Output should show duration in minutes")
	}
}

func TestPrintSummary_ColorMode(t *testing.T) {
	buf := &bytes.Buffer{}
	tr := NewTerminalReporterWithWriter(buf, 80, true) // Enable colors

	report := ScanReport{
		ScanMetadata: ScanMetadata{
			Timestamp:           time.Now().Format(time.RFC3339),
			TargetPath:          "/test",
			Languages:           []string{"go"},
			Frameworks:          []string{},
			ModelUsed:           "gpt-4o",
			TotalCost:           1.0,
			ScanDurationSeconds: 60,
		},
		Findings: []Finding{
			{Type: "sql_injection", Severity: SeverityCritical, Confidence: 0.95, File: "test.go", Line: 1, Message: "test"},
			{Type: "xss", Severity: SeverityHigh, Confidence: 0.9, File: "test.js", Line: 2, Message: "test"},
		},
		Summary: Summary{
			TotalFindings: 2,
			BySeverity: map[string]int{
				SeverityCritical: 1,
				SeverityHigh:     1,
			},
			ByType: map[string]int{
				"sql_injection": 1,
				"xss":           1,
			},
		},
	}

	tr.PrintSummary(report)

	output := buf.String()

	// Verify colors are present (ANSI codes)
	if !strings.Contains(output, "\033[") {
		t.Error("Output should contain ANSI color codes when color mode is enabled")
	}

	// Strip colors and verify content is still there
	stripped := StripColors(output)
	if !strings.Contains(stripped, "Critical") {
		t.Error("Stripped output should still contain 'Critical'")
	}
	if !strings.Contains(stripped, "High") {
		t.Error("Stripped output should still contain 'High'")
	}
}

func TestPrintSummary_NoColorMode(t *testing.T) {
	buf := &bytes.Buffer{}
	tr := NewTerminalReporterWithWriter(buf, 80, false) // Disable colors

	report := ScanReport{
		ScanMetadata: ScanMetadata{
			Timestamp:           time.Now().Format(time.RFC3339),
			TargetPath:          "/test",
			Languages:           []string{"go"},
			Frameworks:          []string{},
			ModelUsed:           "gpt-4o",
			TotalCost:           1.0,
			ScanDurationSeconds: 60,
		},
		Findings: []Finding{
			{Type: "sql_injection", Severity: SeverityCritical, Confidence: 0.95, File: "test.go", Line: 1, Message: "test"},
		},
		Summary: Summary{
			TotalFindings: 1,
			BySeverity: map[string]int{
				SeverityCritical: 1,
			},
			ByType: map[string]int{
				"sql_injection": 1,
			},
		},
	}

	tr.PrintSummary(report)

	output := buf.String()

	// Verify no ANSI color codes
	if strings.Contains(output, "\033[") {
		t.Error("Output should NOT contain ANSI color codes when color mode is disabled")
	}

	// Content should still be present
	if !strings.Contains(output, "Critical") {
		t.Error("Output should contain 'Critical'")
	}
}

func TestPrintSummary_TypeBreakdownSorted(t *testing.T) {
	buf := &bytes.Buffer{}
	tr := NewTerminalReporterWithWriter(buf, 80, false)

	// Create report with multiple types to test sorting
	report := ScanReport{
		ScanMetadata: ScanMetadata{
			Timestamp:           time.Now().Format(time.RFC3339),
			TargetPath:          "/test",
			Languages:           []string{"go"},
			Frameworks:          []string{},
			ModelUsed:           "gpt-4o",
			TotalCost:           1.0,
			ScanDurationSeconds: 60,
		},
		Findings: make([]Finding, 0),
		Summary: Summary{
			TotalFindings: 15,
			BySeverity:    map[string]int{SeverityHigh: 15},
			ByType: map[string]int{
				"sql_injection":  5,
				"xss":            8,
				"path_traversal": 2,
			},
		},
	}

	tr.PrintSummary(report)

	output := buf.String()

	// Find positions of type names
	xssPos := strings.Index(output, "Xss")
	sqlPos := strings.Index(output, "Sql Injection")
	pathPos := strings.Index(output, "Path Traversal")

	// Verify XSS (8 findings) appears before SQL Injection (5 findings)
	if xssPos == -1 || sqlPos == -1 {
		t.Fatal("Output should contain both XSS and SQL Injection")
	}
	if xssPos > sqlPos {
		t.Error("XSS (8 findings) should appear before SQL Injection (5 findings) in sorted list")
	}

	// Verify SQL Injection (5) appears before Path Traversal (2)
	if sqlPos == -1 || pathPos == -1 {
		t.Fatal("Output should contain both SQL Injection and Path Traversal")
	}
	if sqlPos > pathPos {
		t.Error("SQL Injection (5) should appear before Path Traversal (2) in sorted list")
	}
}

func TestPrintSummary_SnapshotTest(t *testing.T) {
	buf := &bytes.Buffer{}
	tr := NewTerminalReporterWithWriter(buf, 80, false)

	report := ScanReport{
		ScanMetadata: ScanMetadata{
			Timestamp:           "2025-12-07T20:00:00+03:30",
			TargetPath:          "/home/user/project",
			Languages:           []string{"go", "javascript"},
			Frameworks:          []string{"express", "gin"},
			ModelUsed:           "gpt-4o",
			TotalCost:           2.47,
			ScanDurationSeconds: 443,
		},
		Findings: []Finding{
			{Type: "sql_injection", Severity: SeverityCritical, Confidence: 0.95, File: "test.go", Line: 1, Message: "test"},
			{Type: "xss", Severity: SeverityHigh, Confidence: 0.9, File: "test.js", Line: 2, Message: "test"},
		},
		Summary: Summary{
			TotalFindings: 2,
			BySeverity: map[string]int{
				SeverityCritical: 1,
				SeverityHigh:     1,
			},
			ByType: map[string]int{
				"sql_injection": 1,
				"xss":           1,
			},
		},
	}

	tr.PrintSummary(report)

	output := buf.String()

	// Verify snapshot structure (key elements)
	expectedElements := []string{
		"DeepGuard Security Scanner",
		"v1.0.0",
		"SCAN METADATA",
		"/home/user/project",
		"go, javascript",
		"express, gin",
		"gpt-4o",
		"SCAN RESULTS",
		"Total Findings",
		"2",
		"By Severity",
		"Critical",
		"High",
		"Top Vulnerability Types",
		"SCAN SUMMARY",
		"$2.47",
		"7m 23s",
	}

	for _, elem := range expectedElements {
		if !strings.Contains(output, elem) {
			t.Errorf("Snapshot output should contain %q", elem)
		}
	}

	// Verify box drawing characters are used
	if !strings.Contains(output, BoxHorizontal) {
		t.Error("Output should use box drawing characters")
	}
}
