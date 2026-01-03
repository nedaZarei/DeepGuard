package rag

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Neda-Zarei/deep-guard/internal/chunker"
	"github.com/Neda-Zarei/deep-guard/internal/kb"
)

// Test query construction from CodeChunk
func TestConstructQuery(t *testing.T) {
	tests := []struct {
		name     string
		chunk    chunker.CodeChunk
		expected string
	}{
		{
			name: "full function with all fields",
			chunk: chunker.CodeChunk{
				FunctionName: "validateUser",
				Language:     "javascript",
				Source:       "function validateUser(username, password) {\n  if (!username) return false;\n  if (!password) return false;\n  return true;\n}",
			},
			expected: "validateUser javascript function validateUser(username, password) { if (!username) return false; if (!password) return false; return true; }",
		},
		{
			name: "anonymous function",
			chunk: chunker.CodeChunk{
				FunctionName: "anonymous",
				Language:     "javascript",
				Source:       "() => { console.log('test'); }",
			},
			expected: "javascript () => { console.log('test'); }",
		},
		{
			name: "long source truncated to 200 chars",
			chunk: chunker.CodeChunk{
				FunctionName: "processData",
				Language:     "python",
				Source:       "def processData(data):\n    # This is a very long function with lots of code\n    result = []\n    for item in data:\n        if item.valid:\n            processed = transform(item)\n            result.append(processed)\n    return result that continues for many more lines",
			},
			expected: "processData python def processData(data): # This is a very long function with lots of code result = [] for item in data: if item.valid: processed = transform(item) result.append(processed) retu",
		},
		{
			name: "function with no name",
			chunk: chunker.CodeChunk{
				FunctionName: "unknown",
				Language:     "java",
				Source:       "public void method() { return; }",
			},
			expected: "java public void method() { return; }",
		},
	}

	indexManager := &kb.IndexManager{} // Mock, not used in this test
	retriever := NewRetriever(indexManager, RetrieverConfig{})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := retriever.constructQuery(tt.chunk)
			if query != tt.expected {
				t.Errorf("Expected query:\n%s\nGot:\n%s", tt.expected, query)
			}
		})
	}
}

// Test token budget enforcement
func TestApplyTokenBudget(t *testing.T) {
	tests := []struct {
		name        string
		result      RetrievalResult
		tokenBudget int
		expectTrunc bool
		maxChars    int
	}{
		{
			name: "within budget - no truncation",
			result: RetrievalResult{
				Entries: []kb.KBEntry{
					{
						ID:           "kb-001",
						Title:        "SQL Injection",
						Description:  "A vulnerability where user input is used in SQL queries without sanitization.",
						CodePatterns: []string{"SELECT * FROM users WHERE id = $input"},
					},
				},
			},
			tokenBudget: 1500,
			expectTrunc: false,
			maxChars:    6000,
		},
		{
			name: "exceeds budget - truncation needed",
			result: RetrievalResult{
				Entries: []kb.KBEntry{
					{
						ID:           "kb-001",
						Title:        "Long Entry 1",
						Description:  string(make([]byte, 3000)), // 3000 chars
						CodePatterns: []string{"pattern1", "pattern2"},
					},
					{
						ID:           "kb-002",
						Title:        "Long Entry 2",
						Description:  string(make([]byte, 3000)), // 3000 chars
						CodePatterns: []string{"pattern3", "pattern4"},
					},
				},
			},
			tokenBudget: 1500, // 6000 char budget
			expectTrunc: true,
			maxChars:    6000,
		},
		{
			name: "multiple entries - proportional truncation",
			result: RetrievalResult{
				Entries: []kb.KBEntry{
					{
						ID:           "kb-001",
						Title:        "Entry 1",
						Description:  string(make([]byte, 2000)), // 2000 chars
						CodePatterns: []string{"pattern1"},
					},
					{
						ID:           "kb-002",
						Title:        "Entry 2",
						Description:  string(make([]byte, 4000)), // 4000 chars
						CodePatterns: []string{"pattern2"},
					},
					{
						ID:           "kb-003",
						Title:        "Entry 3",
						Description:  string(make([]byte, 2000)), // 2000 chars
						CodePatterns: []string{"pattern3"},
					},
				},
			},
			tokenBudget: 1500, // 6000 char budget
			expectTrunc: true,
			maxChars:    6000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			indexManager := &kb.IndexManager{} // Mock
			retriever := NewRetriever(indexManager, RetrieverConfig{
				TokenBudget: tt.tokenBudget,
			})

			err := retriever.applyTokenBudget(&tt.result)
			if err != nil {
				t.Fatalf("applyTokenBudget failed: %v", err)
			}

			if tt.result.Truncated != tt.expectTrunc {
				t.Errorf("Expected Truncated=%v, got %v", tt.expectTrunc, tt.result.Truncated)
			}

			if tt.result.TotalChars > tt.maxChars {
				t.Errorf("Expected TotalChars <= %d, got %d", tt.maxChars, tt.result.TotalChars)
			}

			// Verify all entries still have at least 1 code pattern
			for i, entry := range tt.result.Entries {
				if len(entry.CodePatterns) < 1 {
					t.Errorf("Entry %d should have at least 1 code pattern, got %d", i, len(entry.CodePatterns))
				}
			}
		})
	}
}

// Test cache key computation
func TestComputeCacheKey(t *testing.T) {
	indexManager := &kb.IndexManager{} // Mock
	retriever := NewRetriever(indexManager, RetrieverConfig{})

	chunk1 := chunker.CodeChunk{
		ID:       "abc123",
		Language: "javascript",
	}

	chunk2 := chunker.CodeChunk{
		ID:       "abc123",
		Language: "javascript",
	}

	chunk3 := chunker.CodeChunk{
		ID:       "abc123",
		Language: "python", // Different language
	}

	key1 := retriever.computeCacheKey(chunk1)
	key2 := retriever.computeCacheKey(chunk2)
	key3 := retriever.computeCacheKey(chunk3)

	// Same chunk should produce same key
	if key1 != key2 {
		t.Errorf("Same chunk should produce same key: %s != %s", key1, key2)
	}

	// Different language should produce different key
	if key1 == key3 {
		t.Errorf("Different language should produce different key")
	}

	// Keys should be hex strings
	if len(key1) != 64 {
		t.Errorf("Expected key length 64 (SHA256), got %d", len(key1))
	}
}

// Test cache functionality
func TestRetrievalCache(t *testing.T) {
	cache := newRetrievalCache(3) // Small cache for testing

	result1 := &RetrievalResult{
		KBIDs: []string{"kb-001"},
	}
	result2 := &RetrievalResult{
		KBIDs: []string{"kb-002"},
	}
	result3 := &RetrievalResult{
		KBIDs: []string{"kb-003"},
	}
	result4 := &RetrievalResult{
		KBIDs: []string{"kb-004"},
	}

	// Test put and get
	cache.put("key1", result1)
	cached := cache.get("key1")
	if cached == nil {
		t.Fatal("Expected cached result, got nil")
	}
	if len(cached.KBIDs) != 1 || cached.KBIDs[0] != "kb-001" {
		t.Errorf("Expected KBIDs [kb-001], got %v", cached.KBIDs)
	}

	// Test cache miss
	cached = cache.get("nonexistent")
	if cached != nil {
		t.Error("Expected nil for nonexistent key")
	}

	// Test LRU eviction
	cache.put("key2", result2)
	cache.put("key3", result3)
	cache.put("key4", result4) // Should evict key1

	cached = cache.get("key1")
	if cached != nil {
		t.Error("key1 should have been evicted")
	}

	cached = cache.get("key2")
	if cached == nil {
		t.Error("key2 should still exist")
	}

	// Test statistics
	if cache.hits != 2 {
		t.Errorf("Expected 2 hits, got %d", cache.hits)
	}
	if cache.misses != 2 {
		t.Errorf("Expected 2 misses, got %d", cache.misses)
	}

	// Test clear
	cache.clear()
	if len(cache.entries) != 0 {
		t.Errorf("Expected 0 entries after clear, got %d", len(cache.entries))
	}
	if cache.hits != 0 {
		t.Errorf("Expected 0 hits after clear, got %d", cache.hits)
	}
	if cache.misses != 0 {
		t.Errorf("Expected 0 misses after clear, got %d", cache.misses)
	}
}

// Test cache statistics
func TestGetCacheStats(t *testing.T) {
	indexManager := &kb.IndexManager{} // Mock

	// Test without cache
	retriever := NewRetriever(indexManager, RetrieverConfig{
		EnableCache: false,
	})

	hits, misses, size, hitRate := retriever.GetCacheStats()
	if hits != 0 || misses != 0 || size != 0 || hitRate != 0.0 {
		t.Errorf("Expected all zeros without cache, got hits=%d misses=%d size=%d hitRate=%f", hits, misses, size, hitRate)
	}

	// Test with cache
	retriever = NewRetriever(indexManager, RetrieverConfig{
		EnableCache: true,
		CacheSize:   10,
	})

	// Simulate some cache operations
	retriever.cache.put("key1", &RetrievalResult{})
	retriever.cache.get("key1") // hit
	retriever.cache.get("key2") // miss

	hits, misses, size, hitRate = retriever.GetCacheStats()
	if hits != 1 {
		t.Errorf("Expected 1 hit, got %d", hits)
	}
	if misses != 1 {
		t.Errorf("Expected 1 miss, got %d", misses)
	}
	if size != 1 {
		t.Errorf("Expected size 1, got %d", size)
	}
	if hitRate != 0.5 {
		t.Errorf("Expected hit rate 0.5, got %f", hitRate)
	}
}

// Integration test with real Bleve index
func TestRetrievalIntegration(t *testing.T) {
	// Create temporary directory for test index
	tmpDir, err := os.MkdirTemp("", "deepguard-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	indexPath := filepath.Join(tmpDir, "test-index")
	kbDataPath := "../../internal/kb/data" // Use real KB data

	// Skip if KB data doesn't exist
	if _, err := os.Stat(kbDataPath); os.IsNotExist(err) {
		t.Skip("KB data not found, skipping integration test")
	}

	// Create and initialize index manager
	indexManager := kb.NewIndexManager(indexPath, kbDataPath)
	err = indexManager.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize index: %v", err)
	}
	defer indexManager.Close()

	// Create retriever
	retriever := NewRetriever(indexManager, RetrieverConfig{
		TokenBudget: 1500,
		TopK:        3,
		EnableCache: true,
	})

	// Test chunk - SQL injection vulnerable code
	chunk := chunker.CodeChunk{
		ID:           "test-chunk-001",
		FunctionName: "getUserById",
		Language:     "javascript",
		Source:       "function getUserById(id) { return db.query('SELECT * FROM users WHERE id = ' + id); }",
		FilePath:     "/test/example.js",
	}

	// Retrieve KB entries
	result, err := retriever.Retrieve(chunk)
	if err != nil {
		t.Fatalf("Retrieve failed: %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	// Verify results
	if len(result.KBIDs) > 3 {
		t.Errorf("Should return at most 3 entries, got %d", len(result.KBIDs))
	}
	if len(result.KBIDs) != len(result.RelevanceScores) {
		t.Errorf("KBIDs and RelevanceScores length mismatch: %d != %d", len(result.KBIDs), len(result.RelevanceScores))
	}
	if len(result.KBIDs) != len(result.Entries) {
		t.Errorf("KBIDs and Entries length mismatch: %d != %d", len(result.KBIDs), len(result.Entries))
	}

	// Verify token budget
	if result.TotalChars > 6000 {
		t.Errorf("Should stay within char budget of 6000, got %d", result.TotalChars)
	}

	// Verify cache works
	result2, err := retriever.Retrieve(chunk)
	if err != nil {
		t.Fatalf("Second retrieve failed: %v", err)
	}
	if len(result.KBIDs) != len(result2.KBIDs) {
		t.Error("Cached result should match original")
	}

	hits, misses, _, hitRate := retriever.GetCacheStats()
	if hits != 1 {
		t.Errorf("Expected 1 cache hit, got %d", hits)
	}
	if misses != 1 {
		t.Errorf("Expected 1 cache miss, got %d", misses)
	}
	if hitRate != 0.5 {
		t.Errorf("Expected hit rate 0.5, got %f", hitRate)
	}

	// Log retrieved entries for manual inspection
	t.Logf("Retrieved %d KB entries:", len(result.Entries))
	for i, entry := range result.Entries {
		t.Logf("  [%d] %s (score: %.4f): %s", i, entry.ID, result.RelevanceScores[i], entry.Title)
	}
}

// Performance test - 100 retrievals
func TestRetrievalPerformance(t *testing.T) {
	// Create temporary directory for test index
	tmpDir, err := os.MkdirTemp("", "deepguard-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	indexPath := filepath.Join(tmpDir, "test-index")
	kbDataPath := "../../internal/kb/data"

	// Skip if KB data doesn't exist
	if _, err := os.Stat(kbDataPath); os.IsNotExist(err) {
		t.Skip("KB data not found, skipping performance test")
	}

	// Create and initialize index manager
	indexManager := kb.NewIndexManager(indexPath, kbDataPath)
	err = indexManager.Initialize()
	if err != nil {
		t.Fatalf("Failed to initialize index: %v", err)
	}
	defer indexManager.Close()

	// Create retriever with cache
	retriever := NewRetriever(indexManager, RetrieverConfig{
		TokenBudget: 1500,
		TopK:        3,
		EnableCache: true,
		CacheSize:   1000,
	})

	// Create 10 different chunks (will result in cache hits when repeated)
	chunks := []chunker.CodeChunk{
		{ID: "chunk-001", FunctionName: "validateUser", Language: "javascript", Source: "function validateUser(user) { return user.id > 0; }"},
		{ID: "chunk-002", FunctionName: "processData", Language: "python", Source: "def processData(data): return data.upper()"},
		{ID: "chunk-003", FunctionName: "executeQuery", Language: "java", Source: "public void executeQuery(String sql) { stmt.execute(sql); }"},
		{ID: "chunk-004", FunctionName: "hashPassword", Language: "javascript", Source: "function hashPassword(pwd) { return pwd; }"},
		{ID: "chunk-005", FunctionName: "uploadFile", Language: "python", Source: "def uploadFile(path): open(path).read()"},
		{ID: "chunk-006", FunctionName: "serialize", Language: "java", Source: "Object serialize(byte[] data) { return deserialize(data); }"},
		{ID: "chunk-007", FunctionName: "renderHTML", Language: "javascript", Source: "function renderHTML(html) { return html; }"},
		{ID: "chunk-008", FunctionName: "connectDB", Language: "python", Source: "def connectDB(host): return connect(host)"},
		{ID: "chunk-009", FunctionName: "authenticate", Language: "java", Source: "boolean authenticate(String token) { return true; }"},
		{ID: "chunk-010", FunctionName: "decrypt", Language: "javascript", Source: "function decrypt(data) { return data; }"},
	}

	// Perform 100 retrievals (10 chunks x 10 times = lots of cache hits)
	for i := 0; i < 100; i++ {
		chunk := chunks[i%len(chunks)]
		result, err := retriever.Retrieve(chunk)
		if err != nil {
			t.Fatalf("Retrieve failed at iteration %d: %v", i, err)
		}
		if result == nil {
			t.Fatalf("Expected non-nil result at iteration %d", i)
		}
	}

	// Verify cache performance
	hits, misses, size, hitRate := retriever.GetCacheStats()
	t.Logf("Cache stats: hits=%d, misses=%d, size=%d, hitRate=%.2f%%", hits, misses, size, hitRate*100)

	// With warm cache, we should have high hit rate (90% since we have 10 unique chunks)
	if hitRate < 0.8 {
		t.Errorf("Cache hit rate should be at least 80%%, got %.2f%%", hitRate*100)
	}
	if size != 10 {
		t.Errorf("Cache should contain 10 unique entries, got %d", size)
	}
}

// Test truncation preserves critical information
func TestTruncationPreservesCriticalInfo(t *testing.T) {
	indexManager := &kb.IndexManager{} // Mock
	retriever := NewRetriever(indexManager, RetrieverConfig{
		TokenBudget: 100, // Very small budget to force truncation
	})

	result := RetrievalResult{
		Entries: []kb.KBEntry{
			{
				ID:           "kb-001",
				Title:        "Critical Vulnerability",
				Description:  string(make([]byte, 5000)), // Large description
				CodePatterns: []string{"pattern1", "pattern2", "pattern3"},
			},
		},
	}

	err := retriever.applyTokenBudget(&result)
	if err != nil {
		t.Fatalf("applyTokenBudget failed: %v", err)
	}

	// Verify critical fields preserved
	if result.Entries[0].ID != "kb-001" {
		t.Errorf("Expected ID kb-001, got %s", result.Entries[0].ID)
	}
	if result.Entries[0].Title != "Critical Vulnerability" {
		t.Errorf("Expected title 'Critical Vulnerability', got %s", result.Entries[0].Title)
	}
	if len(result.Entries[0].CodePatterns) < 1 {
		t.Errorf("Expected at least 1 code pattern, got %d", len(result.Entries[0].CodePatterns))
	}
	if !result.Truncated {
		t.Error("Result should be marked as truncated")
	}
	if result.TotalChars > 400 {
		t.Errorf("Should be within budget of 400 chars, got %d", result.TotalChars)
	}
}
