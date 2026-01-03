package cache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAPIResponseCache_Disabled(t *testing.T) {
	logger := testLogger()
	cache := NewAPIResponseCache(false, logger)

	// Get should always return not found when disabled
	_, found := cache.Get("chunk123", "sql_injection", "gpt-4o")
	if found {
		t.Error("Expected not found when cache is disabled")
	}

	// Set should be no-op when disabled
	err := cache.Set("chunk123", "sql_injection", "gpt-4o", map[string]interface{}{"test": "data"}, TokenUsage{
		Prompt:     100,
		Completion: 50,
		Total:      150,
	})
	if err != nil {
		t.Errorf("Set should not error when disabled: %v", err)
	}

	// Should still not find anything
	_, found = cache.Get("chunk123", "sql_injection", "gpt-4o")
	if found {
		t.Error("Expected not found after Set when cache is disabled")
	}
}

func TestAPIResponseCache_SetAndGet(t *testing.T) {
	// Clean up any existing cache
	os.RemoveAll(".deepguard/api-cache")
	defer os.RemoveAll(".deepguard/api-cache")

	logger := testLogger()
	cache := NewAPIResponseCache(true, logger)

	chunkHash := "abc123def456"
	promptTemplate := "sql_injection"
	model := "gpt-4o"

	response := map[string]interface{}{
		"choices": []map[string]interface{}{
			{
				"message": map[string]interface{}{
					"content": `{"vulnerability": "sql_injection", "confidence": 0.9}`,
				},
			},
		},
	}

	tokens := TokenUsage{
		Prompt:     1200,
		Completion: 300,
		Total:      1500,
	}

	// Set cache entry
	err := cache.Set(chunkHash, promptTemplate, model, response, tokens)
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// Get cache entry
	entry, found := cache.Get(chunkHash, promptTemplate, model)
	if !found {
		t.Fatal("Expected to find cached entry")
	}

	// Verify response
	if entry.Response == nil {
		t.Fatal("Expected non-nil response")
	}

	// Verify tokens
	if entry.TokensUsed.Prompt != 1200 {
		t.Errorf("Expected prompt tokens 1200, got %d", entry.TokensUsed.Prompt)
	}

	if entry.TokensUsed.Total != 1500 {
		t.Errorf("Expected total tokens 1500, got %d", entry.TokensUsed.Total)
	}

	// Verify metadata
	if entry.ChunkHash != chunkHash {
		t.Errorf("Expected chunk hash %s, got %s", chunkHash, entry.ChunkHash)
	}

	if entry.PromptTemplate != promptTemplate {
		t.Errorf("Expected prompt template %s, got %s", promptTemplate, entry.PromptTemplate)
	}

	if entry.Model != model {
		t.Errorf("Expected model %s, got %s", model, entry.Model)
	}

	// Verify timestamp is recent
	if time.Since(entry.Timestamp) > 10*time.Second {
		t.Error("Timestamp should be recent")
	}
}

func TestAPIResponseCache_DifferentKeys(t *testing.T) {
	os.RemoveAll(".deepguard/api-cache")
	defer os.RemoveAll(".deepguard/api-cache")

	logger := testLogger()
	cache := NewAPIResponseCache(true, logger)

	response1 := map[string]interface{}{"result": "test1"}
	response2 := map[string]interface{}{"result": "test2"}
	tokens := TokenUsage{Prompt: 100, Completion: 50, Total: 150}

	// Set different entries
	cache.Set("chunk1", "sql_injection", "gpt-4o", response1, tokens)
	cache.Set("chunk2", "sql_injection", "gpt-4o", response2, tokens)
	cache.Set("chunk1", "xss", "gpt-4o", response1, tokens)
	cache.Set("chunk1", "sql_injection", "gpt-4o-mini", response2, tokens)

	// Verify each entry is distinct
	entry1, found := cache.Get("chunk1", "sql_injection", "gpt-4o")
	if !found {
		t.Fatal("Expected to find entry 1")
	}

	entry2, found := cache.Get("chunk2", "sql_injection", "gpt-4o")
	if !found {
		t.Fatal("Expected to find entry 2")
	}

	entry3, found := cache.Get("chunk1", "xss", "gpt-4o")
	if !found {
		t.Fatal("Expected to find entry 3")
	}

	entry4, found := cache.Get("chunk1", "sql_injection", "gpt-4o-mini")
	if !found {
		t.Fatal("Expected to find entry 4")
	}

	// Verify they're different
	if entry1.ChunkHash == entry2.ChunkHash {
		t.Error("Entry 1 and 2 should have different chunk hashes")
	}

	if entry1.PromptTemplate == entry3.PromptTemplate {
		t.Error("Entry 1 and 3 should have different prompt templates")
	}

	if entry1.Model == entry4.Model {
		t.Error("Entry 1 and 4 should have different models")
	}
}

func TestAPIResponseCache_NotFound(t *testing.T) {
	os.RemoveAll(".deepguard/api-cache")
	defer os.RemoveAll(".deepguard/api-cache")

	logger := testLogger()
	cache := NewAPIResponseCache(true, logger)

	// Try to get non-existent entry
	_, found := cache.Get("nonexistent", "sql_injection", "gpt-4o")
	if found {
		t.Error("Expected not found for non-existent entry")
	}
}

func TestAPIResponseCache_ExpiredEntry(t *testing.T) {
	os.RemoveAll(".deepguard/api-cache")
	defer os.RemoveAll(".deepguard/api-cache")

	logger := testLogger()
	cache := NewAPIResponseCache(true, logger)

	// Create cache entry with old timestamp
	chunkHash := "oldchunk"
	promptTemplate := "sql_injection"
	model := "gpt-4o"

	// Manually create expired entry
	cacheKey := cache.generateCacheKey(chunkHash, promptTemplate, model)
	cacheDir := filepath.Join(".deepguard", "api-cache", cacheKey[:2])
	cachePath := filepath.Join(cacheDir, cacheKey+".json")

	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		t.Fatalf("Failed to create cache directory: %v", err)
	}

	expiredTime := time.Now().Add(-31 * 24 * time.Hour) // 31 days ago
	expiredEntry := APICacheEntry{
		ChunkHash:      chunkHash,
		PromptTemplate: promptTemplate,
		Model:          model,
		Timestamp:      expiredTime,
		Response:       map[string]interface{}{"old": "data"},
		TokensUsed:     TokenUsage{Total: 100},
	}

	data, err := json.MarshalIndent(expiredEntry, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal expired entry: %v", err)
	}

	if err := os.WriteFile(cachePath, data, 0644); err != nil {
		t.Fatalf("Failed to write expired entry: %v", err)
	}

	// Try to get expired entry (should not be found)
	_, found := cache.Get(chunkHash, promptTemplate, model)
	if found {
		t.Error("Expected not found for expired entry (>30 days old)")
	}
}

func TestAPIResponseCache_Clear(t *testing.T) {
	os.RemoveAll(".deepguard/api-cache")
	defer os.RemoveAll(".deepguard/api-cache")

	logger := testLogger()
	cache := NewAPIResponseCache(true, logger)

	// Add some entries
	tokens := TokenUsage{Prompt: 100, Completion: 50, Total: 150}
	cache.Set("chunk1", "sql_injection", "gpt-4o", map[string]interface{}{"test": "1"}, tokens)
	cache.Set("chunk2", "xss", "gpt-4o", map[string]interface{}{"test": "2"}, tokens)

	// Verify entries exist
	_, found := cache.Get("chunk1", "sql_injection", "gpt-4o")
	if !found {
		t.Fatal("Entry 1 should exist before clear")
	}

	// Clear cache
	err := cache.Clear()
	if err != nil {
		t.Fatalf("Clear failed: %v", err)
	}

	// Verify entries are gone
	_, found = cache.Get("chunk1", "sql_injection", "gpt-4o")
	if found {
		t.Error("Entry 1 should not exist after clear")
	}

	_, found = cache.Get("chunk2", "xss", "gpt-4o")
	if found {
		t.Error("Entry 2 should not exist after clear")
	}
}

func TestAPIResponseCache_CleanOldEntries(t *testing.T) {
	os.RemoveAll(".deepguard/api-cache")
	defer os.RemoveAll(".deepguard/api-cache")

	logger := testLogger()
	cache := NewAPIResponseCache(true, logger)

	// Add fresh entry
	tokens := TokenUsage{Prompt: 100, Completion: 50, Total: 150}
	cache.Set("fresh", "sql_injection", "gpt-4o", map[string]interface{}{"test": "fresh"}, tokens)

	// Manually create old entry
	oldChunk := "oldchunk"
	oldKey := cache.generateCacheKey(oldChunk, "sql_injection", "gpt-4o")
	oldDir := filepath.Join(".deepguard", "api-cache", oldKey[:2])
	oldPath := filepath.Join(oldDir, oldKey+".json")

	if err := os.MkdirAll(oldDir, 0755); err != nil {
		t.Fatalf("Failed to create old entry directory: %v", err)
	}

	oldTime := time.Now().Add(-31 * 24 * time.Hour)
	oldEntry := APICacheEntry{
		ChunkHash:      oldChunk,
		PromptTemplate: "sql_injection",
		Model:          "gpt-4o",
		Timestamp:      oldTime,
		Response:       map[string]interface{}{"old": "data"},
		TokensUsed:     TokenUsage{Total: 100},
	}

	data, err := json.MarshalIndent(oldEntry, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal old entry: %v", err)
	}

	if err := os.WriteFile(oldPath, data, 0644); err != nil {
		t.Fatalf("Failed to write old entry: %v", err)
	}

	// Clean old entries
	err = cache.CleanOld()
	if err != nil {
		t.Fatalf("CleanOld failed: %v", err)
	}

	// Verify old entry was removed (check file doesn't exist)

	// Verify old entry is gone
	_, err = os.Stat(oldPath)
	if !os.IsNotExist(err) {
		t.Error("Old entry file should be deleted")
	}

	// Verify fresh entry still exists
	_, found := cache.Get("fresh", "sql_injection", "gpt-4o")
	if !found {
		t.Error("Fresh entry should still exist after cleanup")
	}
}

func TestAPIResponseCache_GetStats(t *testing.T) {
	os.RemoveAll(".deepguard/api-cache")
	defer os.RemoveAll(".deepguard/api-cache")

	logger := testLogger()

	// Test disabled cache
	disabledCache := NewAPIResponseCache(false, logger)
	stats, err := disabledCache.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}
	if stats.TotalEntries != 0 {
		t.Errorf("Expected total entries 0 for disabled cache, got %d", stats.TotalEntries)
	}

	// Test enabled cache
	enabledCache := NewAPIResponseCache(true, logger)
	stats, err = enabledCache.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}

	// Add some entries
	tokens := TokenUsage{Prompt: 1000, Completion: 500, Total: 1500}
	enabledCache.Set("chunk1", "sql_injection", "gpt-4o", map[string]interface{}{"test": "1"}, tokens)
	enabledCache.Set("chunk2", "xss", "gpt-4o", map[string]interface{}{"test": "2"}, tokens)

	// Get updated stats
	stats, err = enabledCache.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}
	if stats.TotalEntries != 2 {
		t.Errorf("Expected total_entries 2, got %d", stats.TotalEntries)
	}

	// Simulate cache hits
	enabledCache.Get("chunk1", "sql_injection", "gpt-4o") // hit
	enabledCache.Get("chunk1", "sql_injection", "gpt-4o") // hit
	enabledCache.Get("chunk3", "xss", "gpt-4o")           // miss

	stats, err = enabledCache.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}
	if stats.Hits != 2 {
		t.Errorf("Expected cache_hits 2, got %d", stats.Hits)
	}

	if stats.Misses != 1 {
		t.Errorf("Expected cache_misses 1, got %d", stats.Misses)
	}

	hitRate := enabledCache.GetHitRate()
	expectedRate := 66.66666666666666
	if hitRate < expectedRate-0.1 || hitRate > expectedRate+0.1 {
		t.Errorf("Expected hit_rate ~%.1f%%, got %.1f%%", expectedRate, hitRate)
	}
}

func TestAPICacheEntry_JSONRoundTrip(t *testing.T) {
	timestamp, _ := time.Parse(time.RFC3339, "2025-01-07T10:30:00+03:30")
	original := APICacheEntry{
		ChunkHash:      "abc123",
		PromptTemplate: "sql_injection",
		Model:          "gpt-4o",
		Timestamp:      timestamp,
		Response: map[string]interface{}{
			"choices": []interface{}{
				map[string]interface{}{
					"message": map[string]interface{}{
						"content": "test response",
					},
				},
			},
		},
		TokensUsed: TokenUsage{
			Prompt:     1200,
			Completion: 300,
			Total:      1500,
		},
	}

	// Marshal to JSON
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal entry: %v", err)
	}

	// Unmarshal from JSON
	var decoded APICacheEntry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal entry: %v", err)
	}

	// Verify fields
	if decoded.ChunkHash != original.ChunkHash {
		t.Errorf("ChunkHash mismatch: %s != %s", decoded.ChunkHash, original.ChunkHash)
	}

	if decoded.Model != original.Model {
		t.Errorf("Model mismatch: %s != %s", decoded.Model, original.Model)
	}

	if decoded.TokensUsed.Total != original.TokensUsed.Total {
		t.Errorf("Total tokens mismatch: %d != %d", decoded.TokensUsed.Total, original.TokensUsed.Total)
	}
}

func TestAPIResponseCache_ConcurrentAccess(t *testing.T) {
	os.RemoveAll(".deepguard/api-cache")
	defer os.RemoveAll(".deepguard/api-cache")

	logger := testLogger()
	cache := NewAPIResponseCache(true, logger)

	tokens := TokenUsage{Prompt: 100, Completion: 50, Total: 150}

	// Simulate concurrent writes
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			chunkHash := "concurrent_chunk"
			response := map[string]interface{}{"id": id}
			err := cache.Set(chunkHash, "sql_injection", "gpt-4o", response, tokens)
			if err != nil {
				t.Errorf("Concurrent Set failed: %v", err)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify cache entry exists (last write wins)
	_, found := cache.Get("concurrent_chunk", "sql_injection", "gpt-4o")
	if !found {
		t.Error("Expected to find entry after concurrent writes")
	}
}
