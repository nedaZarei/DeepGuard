package kb

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestKBEntry_ValidEntry tests loading a valid KB entry
func TestKBEntry_ValidEntry(t *testing.T) {
	yaml := `id: sql-injection
title: SQL Injection Vulnerability
description: |
  SQL injection occurs when user input is directly concatenated
  into SQL queries without proper sanitization.
code_patterns:
  - '"SELECT * FROM users WHERE id = " + userId'
  - 'query = "DELETE FROM " + tableName'
schema_version: 1
`

	entry, err := parseYAML(yaml)
	if err != nil {
		t.Fatalf("failed to parse valid YAML: %v", err)
	}

	validator := NewDefaultValidator()
	err = validator.Validate(entry)
	if err != nil {
		t.Errorf("validation failed for valid entry: %v", err)
	}

	// Verify fields
	if entry.ID != "sql-injection" {
		t.Errorf("expected ID 'sql-injection', got '%s'", entry.ID)
	}
	if entry.Title != "SQL Injection Vulnerability" {
		t.Errorf("expected title 'SQL Injection Vulnerability', got '%s'", entry.Title)
	}
	if !strings.Contains(entry.Description, "SQL injection occurs") {
		t.Errorf("description not parsed correctly: %s", entry.Description)
	}
	if len(entry.CodePatterns) != 2 {
		t.Errorf("expected 2 code patterns, got %d", len(entry.CodePatterns))
	}
	if entry.SchemaVersion != 1 {
		t.Errorf("expected schema_version 1, got %d", entry.SchemaVersion)
	}
}

// TestKBEntry_MissingID tests missing ID field
func TestKBEntry_MissingID(t *testing.T) {
	yaml := `title: Test
description: Test description
code_patterns:
  - pattern1
`

	entry, err := parseYAML(yaml)
	if err != nil {
		t.Fatalf("failed to parse YAML: %v", err)
	}

	validator := NewDefaultValidator()
	err = validator.Validate(entry)
	if err == nil {
		t.Error("expected validation error for missing ID, got nil")
	}

	if !strings.Contains(err.Error(), "id") {
		t.Errorf("error should mention 'id' field: %v", err)
	}
}

// TestKBEntry_EmptyID tests empty ID field
func TestKBEntry_EmptyID(t *testing.T) {
	yaml := `id: ""
title: Test
description: Test description
code_patterns:
  - pattern1
`

	entry, err := parseYAML(yaml)
	if err != nil {
		t.Fatalf("failed to parse YAML: %v", err)
	}

	validator := NewDefaultValidator()
	err = validator.Validate(entry)
	if err == nil {
		t.Error("expected validation error for empty ID, got nil")
	}

	if !strings.Contains(err.Error(), "id") {
		t.Errorf("error should mention 'id' field: %v", err)
	}
}

// TestKBEntry_InvalidIDFormat tests invalid ID formats
func TestKBEntry_InvalidIDFormat(t *testing.T) {
	tests := []struct {
		name        string
		id          string
		shouldFail  bool
		description string
	}{
		{"uppercase letters", "SQL-Injection", true, "uppercase not allowed"},
		{"spaces", "sql injection", true, "spaces not allowed"},
		{"special chars", "sql_injection!", true, "special chars not allowed"},
		{"underscore", "sql_injection", true, "underscore not allowed"},
		{"valid lowercase", "sql-injection", false, "valid format"},
		{"valid with numbers", "sql-injection-123", false, "valid format"},
		{"valid numbers only", "123", false, "valid format"},
		{"valid single char", "a", false, "valid format"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yaml := `id: ` + tt.id + `
title: Test
description: Test description
code_patterns:
  - pattern1
`

			entry, err := parseYAML(yaml)
			if err != nil {
				t.Fatalf("failed to parse YAML: %v", err)
			}

			validator := NewDefaultValidator()
			err = validator.Validate(entry)

			if tt.shouldFail {
				if err == nil {
					t.Errorf("expected validation error for %s, got nil", tt.description)
				} else if !strings.Contains(err.Error(), "id") {
					t.Errorf("error should mention 'id' field: %v", err)
				}
			} else {
				if err != nil {
					t.Errorf("expected no error for %s, got: %v", tt.description, err)
				}
			}
		})
	}
}

// TestKBEntry_MissingTitle tests missing title field
func TestKBEntry_MissingTitle(t *testing.T) {
	yaml := `id: test-id
description: Test description
code_patterns:
  - pattern1
`

	entry, err := parseYAML(yaml)
	if err != nil {
		t.Fatalf("failed to parse YAML: %v", err)
	}

	validator := NewDefaultValidator()
	err = validator.Validate(entry)
	if err == nil {
		t.Error("expected validation error for missing title, got nil")
	}

	if !strings.Contains(err.Error(), "title") {
		t.Errorf("error should mention 'title' field: %v", err)
	}
}

// TestKBEntry_MissingDescription tests missing description field
func TestKBEntry_MissingDescription(t *testing.T) {
	yaml := `id: test-id
title: Test Title
code_patterns:
  - pattern1
`

	entry, err := parseYAML(yaml)
	if err != nil {
		t.Fatalf("failed to parse YAML: %v", err)
	}

	validator := NewDefaultValidator()
	err = validator.Validate(entry)
	if err == nil {
		t.Error("expected validation error for missing description, got nil")
	}

	if !strings.Contains(err.Error(), "description") {
		t.Errorf("error should mention 'description' field: %v", err)
	}
}

// TestKBEntry_EmptyCodePatterns tests empty code_patterns array
func TestKBEntry_EmptyCodePatterns(t *testing.T) {
	yaml := `id: test-id
title: Test Title
description: Test description
code_patterns: []
`

	entry, err := parseYAML(yaml)
	if err != nil {
		t.Fatalf("failed to parse YAML: %v", err)
	}

	validator := NewDefaultValidator()
	err = validator.Validate(entry)
	if err == nil {
		t.Error("expected validation error for empty code_patterns, got nil")
	}

	if !strings.Contains(err.Error(), "code_patterns") {
		t.Errorf("error should mention 'code_patterns' field: %v", err)
	}
}

// TestKBEntry_MissingCodePatterns tests missing code_patterns field
func TestKBEntry_MissingCodePatterns(t *testing.T) {
	yaml := `id: test-id
title: Test Title
description: Test description
`

	entry, err := parseYAML(yaml)
	if err != nil {
		t.Fatalf("failed to parse YAML: %v", err)
	}

	validator := NewDefaultValidator()
	err = validator.Validate(entry)
	if err == nil {
		t.Error("expected validation error for missing code_patterns, got nil")
	}

	if !strings.Contains(err.Error(), "code_patterns") {
		t.Errorf("error should mention 'code_patterns' field: %v", err)
	}
}

// TestKBEntry_DefaultSchemaVersion tests default schema version
func TestKBEntry_DefaultSchemaVersion(t *testing.T) {
	yaml := `id: test-id
title: Test Title
description: Test description
code_patterns:
  - pattern1
`

	entry, err := parseYAML(yaml)
	if err != nil {
		t.Fatalf("failed to parse YAML: %v", err)
	}

	// Schema version should be 0 initially (not set)
	if entry.SchemaVersion != 0 {
		t.Errorf("expected SchemaVersion 0 (not set), got %d", entry.SchemaVersion)
	}

	// After loading with LoadKBFile, it should default to 1
	// We'll test this in the loader tests
}

// TestLoadKBDirectory_ValidFiles tests loading multiple valid files
func TestLoadKBDirectory_ValidFiles(t *testing.T) {
	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "kb-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test files
	file1 := `id: sql-injection
title: SQL Injection
description: SQL injection vulnerability
code_patterns:
  - '"SELECT * FROM users WHERE id = " + userId'
`

	file2 := `id: xss
title: Cross-Site Scripting
description: XSS vulnerability
code_patterns:
  - innerHTML = userInput
`

	err = os.WriteFile(filepath.Join(tmpDir, "sql-injection.yaml"), []byte(file1), 0644)
	if err != nil {
		t.Fatalf("failed to write file1: %v", err)
	}

	err = os.WriteFile(filepath.Join(tmpDir, "xss.yaml"), []byte(file2), 0644)
	if err != nil {
		t.Fatalf("failed to write file2: %v", err)
	}

	// Load directory
	entries, err := LoadKBDirectory(tmpDir)
	if err != nil {
		t.Fatalf("LoadKBDirectory failed: %v", err)
	}

	// Should have 2 entries
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}

	// Verify IDs
	ids := make(map[string]bool)
	for _, entry := range entries {
		ids[entry.ID] = true
		// Schema version should default to 1
		if entry.SchemaVersion != 1 {
			t.Errorf("expected schema_version 1 for entry %s, got %d", entry.ID, entry.SchemaVersion)
		}
	}

	if !ids["sql-injection"] {
		t.Error("sql-injection entry not found")
	}
	if !ids["xss"] {
		t.Error("xss entry not found")
	}
}

// TestLoadKBDirectory_DuplicateIDs tests duplicate ID detection
func TestLoadKBDirectory_DuplicateIDs(t *testing.T) {
	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "kb-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create two files with same ID
	fileContent := `id: duplicate-id
title: Test
description: Test description
code_patterns:
  - pattern1
`

	err = os.WriteFile(filepath.Join(tmpDir, "file1.yaml"), []byte(fileContent), 0644)
	if err != nil {
		t.Fatalf("failed to write file1: %v", err)
	}

	err = os.WriteFile(filepath.Join(tmpDir, "file2.yaml"), []byte(fileContent), 0644)
	if err != nil {
		t.Fatalf("failed to write file2: %v", err)
	}

	// Load directory - should fail
	_, err = LoadKBDirectory(tmpDir)
	if err == nil {
		t.Fatal("expected error for duplicate IDs, got nil")
	}

	// Check error type
	if _, ok := err.(*DuplicateIDError); !ok {
		t.Errorf("expected DuplicateIDError, got %T: %v", err, err)
	}

	// Error should mention duplicate ID
	if !strings.Contains(err.Error(), "duplicate-id") {
		t.Errorf("error should mention duplicate ID: %v", err)
	}
}

// TestLoadKBDirectory_InvalidFile tests loading with invalid file
func TestLoadKBDirectory_InvalidFile(t *testing.T) {
	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "kb-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create invalid file (missing required field)
	invalidContent := `id: test-id
title: Test
code_patterns:
  - pattern1
`

	err = os.WriteFile(filepath.Join(tmpDir, "invalid.yaml"), []byte(invalidContent), 0644)
	if err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	// Load directory - should fail
	_, err = LoadKBDirectory(tmpDir)
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}

	// Error should mention the invalid file and field
	if !strings.Contains(err.Error(), "invalid.yaml") {
		t.Errorf("error should mention filename: %v", err)
	}
	if !strings.Contains(err.Error(), "description") {
		t.Errorf("error should mention missing field: %v", err)
	}
}

// TestLoadKBDirectory_EmptyDirectory tests loading empty directory
func TestLoadKBDirectory_EmptyDirectory(t *testing.T) {
	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "kb-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Load empty directory
	entries, err := LoadKBDirectory(tmpDir)
	if err != nil {
		t.Fatalf("LoadKBDirectory failed: %v", err)
	}

	// Should return empty slice
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for empty directory, got %d", len(entries))
	}
}

// TestLoadKBDirectory_NonexistentDirectory tests loading nonexistent directory
func TestLoadKBDirectory_NonexistentDirectory(t *testing.T) {
	_, err := LoadKBDirectory("/nonexistent/directory/path")
	if err == nil {
		t.Fatal("expected error for nonexistent directory, got nil")
	}

	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("error should mention nonexistent directory: %v", err)
	}
}

// TestLoadKBDirectory_FileNotDirectory tests loading a file instead of directory
func TestLoadKBDirectory_FileNotDirectory(t *testing.T) {
	// Create temporary file
	tmpFile, err := os.CreateTemp("", "kb-test-*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	_, err = LoadKBDirectory(tmpFile.Name())
	if err == nil {
		t.Fatal("expected error for file instead of directory, got nil")
	}

	if !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("error should mention not a directory: %v", err)
	}
}

// TestValidationError_WithFilename tests ValidationError filename context
func TestValidationError_WithFilename(t *testing.T) {
	err := NewValidationError("id", "invalid format")

	// Without filename
	if !strings.Contains(err.Error(), "field 'id'") {
		t.Errorf("error should mention field: %v", err)
	}
	if strings.Contains(err.Error(), "test.yaml") {
		t.Errorf("error should not contain filename yet: %v", err)
	}

	// With filename
	err = err.WithFilename("test.yaml")
	if !strings.Contains(err.Error(), "test.yaml") {
		t.Errorf("error should contain filename: %v", err)
	}
	if !strings.Contains(err.Error(), "field 'id'") {
		t.Errorf("error should still mention field: %v", err)
	}
}

// TestDuplicateIDError tests DuplicateIDError message
func TestDuplicateIDError(t *testing.T) {
	err := NewDuplicateIDError("test-id", "file1.yaml", "file2.yaml")

	errMsg := err.Error()
	if !strings.Contains(errMsg, "test-id") {
		t.Errorf("error should mention ID: %v", err)
	}
	if !strings.Contains(errMsg, "file1.yaml") {
		t.Errorf("error should mention first file: %v", err)
	}
	if !strings.Contains(errMsg, "file2.yaml") {
		t.Errorf("error should mention second file: %v", err)
	}
}

// TestLoadKBDirectory_YmlExtension tests loading .yml files
func TestLoadKBDirectory_YmlExtension(t *testing.T) {
	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "kb-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create .yml file (not .yaml)
	content := `id: test-id
title: Test
description: Test description
code_patterns:
  - pattern1
`

	err = os.WriteFile(filepath.Join(tmpDir, "test.yml"), []byte(content), 0644)
	if err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	// Load directory
	entries, err := LoadKBDirectory(tmpDir)
	if err != nil {
		t.Fatalf("LoadKBDirectory failed: %v", err)
	}

	// Should load .yml file
	if len(entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(entries))
	}
}

// Helper function to parse YAML string into KBEntry
func parseYAML(yamlStr string) (KBEntry, error) {
	// Create temp file
	tmpFile, err := os.CreateTemp("", "kb-test-*.yaml")
	if err != nil {
		return KBEntry{}, err
	}
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(yamlStr)
	if err != nil {
		return KBEntry{}, err
	}
	tmpFile.Close()

	// Use loadKBFile (not LoadKBFile) to avoid validation
	return loadKBFile(tmpFile.Name())
}
