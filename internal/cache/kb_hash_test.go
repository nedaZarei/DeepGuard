package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestComputeKBHash(t *testing.T) {
	// Create temporary test directory
	tmpDir := t.TempDir()

	// Create test KB files
	testFiles := map[string]string{
		"sqli.yaml": "id: sqli-001\nname: SQL Injection",
		"xss.yaml":  "id: xss-001\nname: Cross-Site Scripting",
	}

	for name, content := range testFiles {
		path := filepath.Join(tmpDir, name)
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", name, err)
		}
	}

	// Test 1: Compute hash
	hash1, err := ComputeKBHash(tmpDir)
	if err != nil {
		t.Fatalf("ComputeKBHash failed: %v", err)
	}

	if hash1 == "" {
		t.Error("Expected non-empty hash")
	}

	// Test 2: Same directory should produce same hash
	hash2, err := ComputeKBHash(tmpDir)
	if err != nil {
		t.Fatalf("ComputeKBHash failed on second call: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("Hash not deterministic: %s != %s", hash1, hash2)
	}

	// Test 3: Modified file should change hash
	time.Sleep(10 * time.Millisecond) // Ensure mod time changes
	modPath := filepath.Join(tmpDir, "sqli.yaml")
	if err := os.WriteFile(modPath, []byte("id: sqli-001\nname: SQL Injection v2"), 0644); err != nil {
		t.Fatalf("Failed to modify file: %v", err)
	}

	hash3, err := ComputeKBHash(tmpDir)
	if err != nil {
		t.Fatalf("ComputeKBHash failed after modification: %v", err)
	}

	if hash1 == hash3 {
		t.Error("Hash should change after file modification")
	}

	// Test 4: New file should change hash
	newPath := filepath.Join(tmpDir, "csrf.yaml")
	if err := os.WriteFile(newPath, []byte("id: csrf-001\nname: CSRF"), 0644); err != nil {
		t.Fatalf("Failed to create new file: %v", err)
	}

	hash4, err := ComputeKBHash(tmpDir)
	if err != nil {
		t.Fatalf("ComputeKBHash failed after new file: %v", err)
	}

	if hash3 == hash4 {
		t.Error("Hash should change after adding new file")
	}
}

func TestComputeKBHash_NonExistentDir(t *testing.T) {
	_, err := ComputeKBHash("/nonexistent/directory/path")
	if err == nil {
		t.Error("Expected error for non-existent directory")
	}
}

func TestComputeKBHash_EmptyDir(t *testing.T) {
	tmpDir := t.TempDir()

	hash, err := ComputeKBHash(tmpDir)
	if err != nil {
		t.Fatalf("ComputeKBHash failed for empty directory: %v", err)
	}

	if hash == "" {
		t.Error("Expected non-empty hash even for empty directory")
	}
}

func TestComputeKBHash_Subdirectories(t *testing.T) {
	tmpDir := t.TempDir()

	// Create nested directory structure
	subdir := filepath.Join(tmpDir, "web")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatalf("Failed to create subdirectory: %v", err)
	}

	// Create file in subdirectory
	subFile := filepath.Join(subdir, "xss.yaml")
	if err := os.WriteFile(subFile, []byte("id: xss-001"), 0644); err != nil {
		t.Fatalf("Failed to create file in subdirectory: %v", err)
	}

	// Create file in root
	rootFile := filepath.Join(tmpDir, "sqli.yaml")
	if err := os.WriteFile(rootFile, []byte("id: sqli-001"), 0644); err != nil {
		t.Fatalf("Failed to create file in root: %v", err)
	}

	hash1, err := ComputeKBHash(tmpDir)
	if err != nil {
		t.Fatalf("ComputeKBHash failed: %v", err)
	}

	// Hash should be deterministic even with subdirectories
	hash2, err := ComputeKBHash(tmpDir)
	if err != nil {
		t.Fatalf("ComputeKBHash failed on second call: %v", err)
	}

	if hash1 != hash2 {
		t.Error("Hash not deterministic with subdirectories")
	}
}

func TestComputeKBHash_IgnoresNonYAMLFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create YAML file
	yamlPath := filepath.Join(tmpDir, "test.yaml")
	if err := os.WriteFile(yamlPath, []byte("content"), 0644); err != nil {
		t.Fatalf("Failed to create YAML file: %v", err)
	}

	hash1, err := ComputeKBHash(tmpDir)
	if err != nil {
		t.Fatalf("ComputeKBHash failed: %v", err)
	}

	// Add non-YAML file (should be ignored)
	txtPath := filepath.Join(tmpDir, "readme.txt")
	if err := os.WriteFile(txtPath, []byte("documentation"), 0644); err != nil {
		t.Fatalf("Failed to create TXT file: %v", err)
	}

	hash2, err := ComputeKBHash(tmpDir)
	if err != nil {
		t.Fatalf("ComputeKBHash failed after adding TXT: %v", err)
	}

	if hash1 != hash2 {
		t.Error("Hash should not change when non-YAML files are added")
	}
}
