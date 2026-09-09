package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	// DefaultOutputDir is the default directory for scan reports
	DefaultOutputDir = "./reports"

	// DirectoryPermissions for created directories
	DirectoryPermissions = 0755

	// FilePermissions for created report files
	FilePermissions = 0644
)

// WriteReport writes a scan report to a JSON file with atomic operations
// Returns the path to the written file
func WriteReport(report ScanReport, outputDir string) (string, error) {
	// Use default output directory if not specified
	if outputDir == "" {
		outputDir = DefaultOutputDir
	}

	// Validate the report before writing
	if err := ValidateReport(report); err != nil {
		return "", fmt.Errorf("report validation failed: %w", err)
	}

	// Ensure output directory exists
	if err := ensureDirectory(outputDir); err != nil {
		return "", fmt.Errorf("failed to create output directory: %w", err)
	}

	// Generate filename with timestamp
	filename := generateFilename()
	outputPath := filepath.Join(outputDir, filename)

	// Write report atomically
	if err := writeReportAtomic(report, outputPath); err != nil {
		return "", fmt.Errorf("failed to write report: %w", err)
	}

	log.Info().
		Str("component", "report").
		Str("output_path", outputPath).
		Int("findings_count", len(report.Findings)).
		Float64("total_cost", report.ScanMetadata.TotalCost).
		Msg("scan report written successfully")

	return outputPath, nil
}

// ensureDirectory creates the directory if it doesn't exist
func ensureDirectory(dir string) error {
	// Check if directory exists
	info, err := os.Stat(dir)
	if err == nil {
		// Directory exists, verify it's actually a directory
		if !info.IsDir() {
			return fmt.Errorf("path exists but is not a directory: %s", dir)
		}
		// Check if directory is writable
		return checkWritable(dir)
	}

	// Directory doesn't exist, create it
	if os.IsNotExist(err) {
		if err := os.MkdirAll(dir, DirectoryPermissions); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
		log.Debug().
			Str("component", "report").
			Str("directory", dir).
			Msg("created output directory")
		return nil
	}

	// Other error
	return fmt.Errorf("failed to stat directory: %w", err)
}

// checkWritable verifies that a directory is writable
func checkWritable(dir string) error {
	// Try to create a temporary file to test writability
	testFile := filepath.Join(dir, ".write-test")
	f, err := os.Create(testFile)
	if err != nil {
		return fmt.Errorf("directory is not writable: %w", err)
	}
	f.Close()
	os.Remove(testFile)
	return nil
}

// generateFilename creates a timestamped filename
// Format: scan-YYYYMMDD-HHMMSS.json
func generateFilename() string {
	now := time.Now()
	timestamp := now.Format("20060102-150405") // YYYYMMDD-HHMMSS
	return fmt.Sprintf("scan-%s.json", timestamp)
}

// writeReportAtomic writes the report to a file atomically using temp file + rename
func writeReportAtomic(report ScanReport, outputPath string) error {
	// Create temporary file in the same directory as the output
	dir := filepath.Dir(outputPath)
	tempFile, err := os.CreateTemp(dir, ".report-*.json.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tempPath := tempFile.Name()

	// Ensure temp file is cleaned up on error
	var writeErr error
	defer func() {
		tempFile.Close()
		if writeErr != nil {
			os.Remove(tempPath)
		}
	}()

	// A nil Findings slice marshals to JSON null, which breaks consumers that
	// expect an array (a scan with zero findings is valid, not malformed).
	if report.Findings == nil {
		report.Findings = []Finding{}
	}

	// Marshal report to pretty-printed JSON
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		writeErr = fmt.Errorf("failed to marshal report to JSON: %w", err)
		return writeErr
	}

	// Validate UTF-8 encoding
	if !isValidUTF8(jsonData) {
		writeErr = fmt.Errorf("report contains invalid UTF-8 characters")
		return writeErr
	}

	// Write JSON data to temp file
	if _, err := tempFile.Write(jsonData); err != nil {
		writeErr = fmt.Errorf("failed to write to temp file: %w", err)
		return writeErr
	}

	// Ensure data is flushed to disk
	if err := tempFile.Sync(); err != nil {
		writeErr = fmt.Errorf("failed to sync temp file: %w", err)
		return writeErr
	}

	// Close temp file before rename
	if err := tempFile.Close(); err != nil {
		writeErr = fmt.Errorf("failed to close temp file: %w", err)
		return writeErr
	}

	// Atomically rename temp file to final destination
	if err := os.Rename(tempPath, outputPath); err != nil {
		writeErr = fmt.Errorf("failed to rename temp file: %w", err)
		return writeErr
	}

	// Set proper file permissions
	if err := os.Chmod(outputPath, FilePermissions); err != nil {
		// Log warning but don't fail - file is already written
		log.Warn().
			Str("component", "report").
			Str("file", outputPath).
			Err(err).
			Msg("failed to set file permissions")
	}

	return nil
}

// isValidUTF8 checks if byte slice contains valid UTF-8
func isValidUTF8(data []byte) bool {
	// Convert to string and back - if invalid UTF-8 is present,
	// the string conversion will replace it with replacement character
	str := string(data)
	return !strings.Contains(str, "\ufffd") || len(data) == 0
}

// NormalizeFilePath converts file paths to use forward slashes
func NormalizeFilePath(path string) string {
	// Replace all backslashes with forward slashes
	return strings.ReplaceAll(path, "\\", "/")
}
