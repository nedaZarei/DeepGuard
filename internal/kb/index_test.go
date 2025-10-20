package kb

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestNewIndexManager tests index manager creation
func TestNewIndexManager(t *testing.T) {
	im := NewIndexManager("", "")
	if im.indexPath != defaultIndexPath {
		t.Errorf("expected default index path %s, got %s", defaultIndexPath, im.indexPath)
	}
	if im.kbDataPath != defaultKBDataPath {
		t.Errorf("expected default KB data path %s, got %s", defaultKBDataPath, im.kbDataPath)
	}

	customPath := "/custom/index"
	customData := "/custom/data"
	im = NewIndexManager(customPath, customData)
	if im.indexPath != customPath {
		t.Errorf("expected custom index path %s, got %s", customPath, im.indexPath)
	}
	if im.kbDataPath != customData {
		t.Errorf("expected custom KB data path %s, got %s", customData, im.kbDataPath)
	}
}

// TestCalculateKBHash tests KB directory hashing
func TestCalculateKBHash(t *testing.T) {
	// Create temporary KB directory
	tmpDir, err := os.MkdirTemp("", "kb-hash-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test KB files
	file1 := `id: test-001
title: Test Entry 1
description: Test description
code_patterns:
  - pattern1
schema_version: 1
`
	file2 := `id: test-002
title: Test Entry 2
description: Test description
code_patterns:
  - pattern2
schema_version: 1
`

	err = os.WriteFile(filepath.Join(tmpDir, "test-001.yaml"), []byte(file1), 0644)
	if err != nil {
		t.Fatalf("failed to write file1: %v", err)
	}

	err = os.WriteFile(filepath.Join(tmpDir, "test-002.yaml"), []byte(file2), 0644)
	if err != nil {
		t.Fatalf("failed to write file2: %v", err)
	}

	im := NewIndexManager("", tmpDir)

	// Calculate hash
	hash1, err := im.calculateKBHash()
	if err != nil {
		t.Fatalf("calculateKBHash failed: %v", err)
	}

	if len(hash1) != 64 { // SHA256 hex is 64 characters
		t.Errorf("expected hash length 64, got %d", len(hash1))
	}

	// Calculate again - should be same
	hash2, err := im.calculateKBHash()
	if err != nil {
		t.Fatalf("calculateKBHash failed on second call: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("hash should be consistent: %s != %s", hash1, hash2)
	}

	// Modify file - hash should change
	modified := file1 + "\n# comment\n"
	err = os.WriteFile(filepath.Join(tmpDir, "test-001.yaml"), []byte(modified), 0644)
	if err != nil {
		t.Fatalf("failed to write modified file: %v", err)
	}

	hash3, err := im.calculateKBHash()
	if err != nil {
		t.Fatalf("calculateKBHash failed after modification: %v", err)
	}

	if hash1 == hash3 {
		t.Errorf("hash should change when file is modified")
	}
}

// TestIndexBuild tests building an index from KB entries
func TestIndexBuild(t *testing.T) {
	// Create temporary directories
	tmpIndex, err := os.MkdirTemp("", "index-test-*")
	if err != nil {
		t.Fatalf("failed to create temp index dir: %v", err)
	}
	defer os.RemoveAll(tmpIndex)

	tmpData, err := os.MkdirTemp("", "kb-data-test-*")
	if err != nil {
		t.Fatalf("failed to create temp data dir: %v", err)
	}
	defer os.RemoveAll(tmpData)

	// Create test KB files
	testEntries := []string{
		`id: sql-injection
title: SQL Injection
description: SQL injection vulnerability
code_patterns:
  - db.query("SELECT * FROM users WHERE id = " + userId)
schema_version: 1
`,
		`id: xss
title: Cross-Site Scripting
description: XSS vulnerability
code_patterns:
  - innerHTML = userInput
schema_version: 1
`,
	}

	for i, content := range testEntries {
		filename := filepath.Join(tmpData, strings.Split(content, "\n")[0][4:]+".yaml")
		err = os.WriteFile(filename, []byte(content), 0644)
		if err != nil {
			t.Fatalf("failed to write test file %d: %v", i, err)
		}
	}

	// Create and initialize index manager
	im := NewIndexManager(tmpIndex, tmpData)
	err = im.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	defer im.Close()

	// Verify index was created
	if im.index == nil {
		t.Fatal("index should not be nil after initialization")
	}

	// Check document count
	count, err := im.index.DocCount()
	if err != nil {
		t.Fatalf("DocCount failed: %v", err)
	}

	// Expect 2 KB entries + 1 metadata document
	if count != 3 {
		t.Errorf("expected 3 documents (2 entries + metadata), got %d", count)
	}
}

// TestRebuildDetection tests rebuild detection logic
func TestRebuildDetection(t *testing.T) {
	// Create temporary directories
	tmpIndex, err := os.MkdirTemp("", "rebuild-test-*")
	if err != nil {
		t.Fatalf("failed to create temp index dir: %v", err)
	}
	defer os.RemoveAll(tmpIndex)

	tmpData, err := os.MkdirTemp("", "kb-data-test-*")
	if err != nil {
		t.Fatalf("failed to create temp data dir: %v", err)
	}
	defer os.RemoveAll(tmpData)

	// Create initial KB file
	initialContent := `id: test-001
title: Test Entry
description: Test description
code_patterns:
  - pattern1
schema_version: 1
`
	err = os.WriteFile(filepath.Join(tmpData, "test-001.yaml"), []byte(initialContent), 0644)
	if err != nil {
		t.Fatalf("failed to write initial file: %v", err)
	}

	// First initialization - should build index
	im := NewIndexManager(tmpIndex, tmpData)
	err = im.Initialize()
	if err != nil {
		t.Fatalf("first Initialize failed: %v", err)
	}

	firstCount, _ := im.index.DocCount()
	im.Close()

	// Second initialization without changes - should NOT rebuild
	im = NewIndexManager(tmpIndex, tmpData)
	err = im.Initialize()
	if err != nil {
		t.Fatalf("second Initialize failed: %v", err)
	}

	secondCount, _ := im.index.DocCount()
	if firstCount != secondCount {
		t.Errorf("document count changed without KB modification: %d -> %d", firstCount, secondCount)
	}
	im.Close()

	// Modify KB file - should trigger rebuild
	modifiedContent := initialContent + "\n# Modified\n"
	err = os.WriteFile(filepath.Join(tmpData, "test-001.yaml"), []byte(modifiedContent), 0644)
	if err != nil {
		t.Fatalf("failed to write modified file: %v", err)
	}

	// Give filesystem time to update timestamp
	time.Sleep(10 * time.Millisecond)

	im = NewIndexManager(tmpIndex, tmpData)
	err = im.Initialize()
	if err != nil {
		t.Fatalf("third Initialize failed: %v", err)
	}

	// Should still have same number of documents, but hash should be different
	thirdCount, _ := im.index.DocCount()
	if thirdCount != secondCount {
		t.Errorf("document count should remain same: %d != %d", thirdCount, secondCount)
	}
	im.Close()
}

// TestSearch tests BM25 search functionality
func TestSearch(t *testing.T) {
	// Create temporary directories
	tmpIndex, err := os.MkdirTemp("", "search-test-*")
	if err != nil {
		t.Fatalf("failed to create temp index dir: %v", err)
	}
	defer os.RemoveAll(tmpIndex)

	tmpData, err := os.MkdirTemp("", "kb-data-test-*")
	if err != nil {
		t.Fatalf("failed to create temp data dir: %v", err)
	}
	defer os.RemoveAll(tmpData)

	// Create test KB files with distinct content
	testFiles := map[string]string{
		"sql-injection.yaml": `id: sql-injection
title: SQL Injection Vulnerability
description: SQL injection occurs when user input is concatenated into queries
code_patterns:
  - db.query("SELECT * FROM users WHERE id = " + userId)
schema_version: 1
`,
		"xss.yaml": `id: xss
title: Cross-Site Scripting
description: XSS allows injection of malicious scripts
code_patterns:
  - innerHTML = userInput
schema_version: 1
`,
	}

	for filename, content := range testFiles {
		err = os.WriteFile(filepath.Join(tmpData, filename), []byte(content), 0644)
		if err != nil {
			t.Fatalf("failed to write %s: %v", filename, err)
		}
	}

	// Create and initialize index
	im := NewIndexManager(tmpIndex, tmpData)
	err = im.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	defer im.Close()

	// Search for "SQL"
	results, err := im.Search("SQL", 10)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	if results.Total == 0 {
		t.Error("expected at least 1 result for 'SQL' query")
	}

	// First result should be sql-injection
	if len(results.Hits) > 0 {
		firstHit := results.Hits[0]
		if id, ok := firstHit.Fields["id"].(string); ok {
			if id != "sql-injection" {
				t.Errorf("expected first result to be 'sql-injection', got '%s'", id)
			}
		}
	}

	// Search for "innerHTML" - unique to XSS
	results, err = im.Search("innerHTML", 10)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	if results.Total == 0 {
		t.Error("expected at least 1 result for 'innerHTML' query")
	}

	// First result should be xss
	if len(results.Hits) > 0 {
		firstHit := results.Hits[0]
		if id, ok := firstHit.Fields["id"].(string); ok {
			if id != "xss" {
				t.Errorf("expected first result to be 'xss', got '%s'", id)
			}
		}
	}
}

// TestValidate tests index validation
func TestValidate(t *testing.T) {
	// Create temporary directories
	tmpIndex, err := os.MkdirTemp("", "validate-test-*")
	if err != nil {
		t.Fatalf("failed to create temp index dir: %v", err)
	}
	defer os.RemoveAll(tmpIndex)

	tmpData, err := os.MkdirTemp("", "kb-data-test-*")
	if err != nil {
		t.Fatalf("failed to create temp data dir: %v", err)
	}
	defer os.RemoveAll(tmpData)

	// Create minimal KB file
	content := `id: test-001
title: Test Entry
description: Test description
code_patterns:
  - pattern1
schema_version: 1
`
	err = os.WriteFile(filepath.Join(tmpData, "test.yaml"), []byte(content), 0644)
	if err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	// Create and initialize index
	im := NewIndexManager(tmpIndex, tmpData)
	err = im.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	defer im.Close()

	// Validate should succeed
	err = im.Validate()
	if err != nil {
		t.Errorf("Validate failed: %v", err)
	}

	// Close index and validate should fail
	im.Close()
	err = im.Validate()
	if err == nil {
		t.Error("Validate should fail after index is closed")
	}
}

// TestConcurrentAccess tests concurrent read access
func TestConcurrentAccess(t *testing.T) {
	// Create temporary directories
	tmpIndex, err := os.MkdirTemp("", "concurrent-test-*")
	if err != nil {
		t.Fatalf("failed to create temp index dir: %v", err)
	}
	defer os.RemoveAll(tmpIndex)

	tmpData, err := os.MkdirTemp("", "kb-data-test-*")
	if err != nil {
		t.Fatalf("failed to create temp data dir: %v", err)
	}
	defer os.RemoveAll(tmpData)

	// Create test KB file
	content := `id: test-001
title: Test Entry
description: Test description for concurrent access
code_patterns:
  - pattern1
schema_version: 1
`
	err = os.WriteFile(filepath.Join(tmpData, "test.yaml"), []byte(content), 0644)
	if err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	// Create and initialize index
	im := NewIndexManager(tmpIndex, tmpData)
	err = im.Initialize()
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	defer im.Close()

	// Perform concurrent searches
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			_, err := im.Search("concurrent", 10)
			if err != nil {
				t.Errorf("concurrent search failed: %v", err)
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestHashFile tests file hashing
func TestHashFile(t *testing.T) {
	// Create temporary file
	tmpFile, err := os.CreateTemp("", "hash-test-*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	content := "test content for hashing"
	_, err = tmpFile.WriteString(content)
	if err != nil {
		t.Fatalf("failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	// Hash file
	hash1, err := hashFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("hashFile failed: %v", err)
	}

	if len(hash1) != 64 {
		t.Errorf("expected hash length 64, got %d", len(hash1))
	}

	// Hash again - should be same
	hash2, err := hashFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("hashFile failed on second call: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("hash should be consistent: %s != %s", hash1, hash2)
	}
}

// TestIndexedKBEntry tests the indexed entry structure
func TestIndexedKBEntry(t *testing.T) {
	entry := IndexedKBEntry{
		ID:           "test-001",
		Title:        "Test Title",
		Description:  "Test description",
		CodePatterns: "pattern1\npattern2\npattern3",
	}

	if entry.ID != "test-001" {
		t.Errorf("expected ID 'test-001', got '%s'", entry.ID)
	}

	patterns := strings.Split(entry.CodePatterns, "\n")
	if len(patterns) != 3 {
		t.Errorf("expected 3 patterns, got %d", len(patterns))
	}
}
