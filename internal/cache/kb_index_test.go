package cache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestKBIndexCache_GetIndexPath(t *testing.T) {
	tmpDir := t.TempDir()
	logger := testLogger()

	cache := NewKBIndexCache(tmpDir, logger)
	indexPath := cache.GetIndexPath()

	expected := filepath.Join(".deepguard", "kb-index", "index.bleve")
	if indexPath != expected {
		t.Errorf("Expected index path %s, got %s", expected, indexPath)
	}
}

func TestKBIndexCache_ShouldRebuild_NoCacheExists(t *testing.T) {
	// Clean up any existing cache from previous tests
	os.RemoveAll(".deepguard")
	defer os.RemoveAll(".deepguard")

	tmpDir := t.TempDir()
	logger := testLogger()

	cache := NewKBIndexCache(tmpDir, logger)

	shouldRebuild, reason, err := cache.ShouldRebuild()
	if err != nil {
		t.Fatalf("ShouldRebuild failed: %v", err)
	}

	if !shouldRebuild {
		t.Error("Expected rebuild when no cache exists")
	}

	if reason != "cache directory missing" {
		t.Errorf("Expected reason 'cache directory missing', got '%s'", reason)
	}
}

func TestKBIndexCache_SaveAndLoadMetadata(t *testing.T) {
	tmpDir := t.TempDir()
	logger := testLogger()

	// Create test KB directory with files
	if err := os.WriteFile(filepath.Join(tmpDir, "test.yaml"), []byte("id: test"), 0644); err != nil {
		t.Fatalf("Failed to create test KB file: %v", err)
	}

	cache := NewKBIndexCache(tmpDir, logger)

	// Save metadata
	err := cache.SaveMetadata(156, "bleve-2.3.10")
	if err != nil {
		t.Fatalf("SaveMetadata failed: %v", err)
	}

	// Load metadata
	metadata, err := cache.LoadMetadata()
	if err != nil {
		t.Fatalf("LoadMetadata failed: %v", err)
	}

	// Verify metadata
	if metadata.Version != "1.0.0" {
		t.Errorf("Expected version 1.0.0, got %s", metadata.Version)
	}

	if metadata.EntryCount != 156 {
		t.Errorf("Expected entry count 156, got %d", metadata.EntryCount)
	}

	if metadata.IndexVersion != "bleve-2.3.10" {
		t.Errorf("Expected index version bleve-2.3.10, got %s", metadata.IndexVersion)
	}

	if metadata.KBPath != tmpDir {
		t.Errorf("Expected KB path %s, got %s", tmpDir, metadata.KBPath)
	}

	// Verify KBHash is not empty
	if metadata.KBHash == "" {
		t.Error("Expected non-empty KB hash")
	}

	// Verify BuildTime is recent
	if time.Since(metadata.BuildTime) > 10*time.Second {
		t.Error("Build time should be recent")
	}
}

func TestKBIndexCache_ShouldRebuild_CacheValid(t *testing.T) {
	tmpDir := t.TempDir()
	logger := testLogger()

	// Create test KB file
	if err := os.WriteFile(filepath.Join(tmpDir, "test.yaml"), []byte("id: test"), 0644); err != nil {
		t.Fatalf("Failed to create test KB file: %v", err)
	}

	cache := NewKBIndexCache(tmpDir, logger)

	// Save metadata
	if err := cache.SaveMetadata(100, "bleve-2.3.10"); err != nil {
		t.Fatalf("SaveMetadata failed: %v", err)
	}

	// Check if rebuild needed (should not be needed)
	shouldRebuild, reason, err := cache.ShouldRebuild()
	if err != nil {
		t.Fatalf("ShouldRebuild failed: %v", err)
	}

	if shouldRebuild {
		t.Errorf("Expected no rebuild when cache is valid, but got reason: %s", reason)
	}

	if reason != "" {
		t.Errorf("Expected empty reason, got: %s", reason)
	}
}

func TestKBIndexCache_ShouldRebuild_KBChanged(t *testing.T) {
	tmpDir := t.TempDir()
	logger := testLogger()

	// Create test KB file
	testFile := filepath.Join(tmpDir, "test.yaml")
	if err := os.WriteFile(testFile, []byte("id: test"), 0644); err != nil {
		t.Fatalf("Failed to create test KB file: %v", err)
	}

	cache := NewKBIndexCache(tmpDir, logger)

	// Save metadata
	if err := cache.SaveMetadata(100, "bleve-2.3.10"); err != nil {
		t.Fatalf("SaveMetadata failed: %v", err)
	}

	// Modify KB file
	time.Sleep(10 * time.Millisecond)
	if err := os.WriteFile(testFile, []byte("id: test-modified"), 0644); err != nil {
		t.Fatalf("Failed to modify test KB file: %v", err)
	}

	// Check if rebuild needed (should be needed)
	shouldRebuild, reason, err := cache.ShouldRebuild()
	if err != nil {
		t.Fatalf("ShouldRebuild failed: %v", err)
	}

	if !shouldRebuild {
		t.Error("Expected rebuild when KB content changed")
	}

	if reason != "KB content changed" {
		t.Errorf("Expected reason 'KB content changed', got '%s'", reason)
	}
}

func TestKBIndexCache_ShouldRebuild_IndexMissing(t *testing.T) {
	tmpDir := t.TempDir()
	logger := testLogger()

	// Create test KB file
	if err := os.WriteFile(filepath.Join(tmpDir, "test.yaml"), []byte("id: test"), 0644); err != nil {
		t.Fatalf("Failed to create test KB file: %v", err)
	}

	cache := NewKBIndexCache(tmpDir, logger)

	// Save metadata
	if err := cache.SaveMetadata(100, "bleve-2.3.10"); err != nil {
		t.Fatalf("SaveMetadata failed: %v", err)
	}

	// Note: The index.bleve directory doesn't exist, but ShouldRebuild only checks metadata and hash.
	// Since hash matches, it will say no rebuild needed.
	// The actual index opening would fail and trigger a rebuild at that point.
	shouldRebuild, _, err := cache.ShouldRebuild()
	if err != nil {
		t.Fatalf("ShouldRebuild failed: %v", err)
	}

	// Should NOT rebuild because hash matches - index existence is checked elsewhere
	if shouldRebuild {
		t.Error("Expected no rebuild when metadata and hash match (index existence checked separately)")
	}
}

func TestKBIndexCache_ClearCache(t *testing.T) {
	tmpDir := t.TempDir()
	logger := testLogger()

	// Create test KB file
	if err := os.WriteFile(filepath.Join(tmpDir, "test.yaml"), []byte("id: test"), 0644); err != nil {
		t.Fatalf("Failed to create test KB file: %v", err)
	}

	cache := NewKBIndexCache(tmpDir, logger)

	// Save metadata
	if err := cache.SaveMetadata(100, "bleve-2.3.10"); err != nil {
		t.Fatalf("SaveMetadata failed: %v", err)
	}

	// Verify metadata exists
	if _, err := cache.LoadMetadata(); err != nil {
		t.Fatalf("Metadata should exist before clear: %v", err)
	}

	// Clear cache
	if err := cache.Clear(); err != nil {
		t.Fatalf("Clear failed: %v", err)
	}

	// Verify metadata is gone
	_, err := cache.LoadMetadata()
	if err == nil {
		t.Error("Expected error when loading metadata after clear")
	}

	// Should require rebuild now
	shouldRebuild, _, err := cache.ShouldRebuild()
	if err != nil {
		t.Fatalf("ShouldRebuild failed: %v", err)
	}

	if !shouldRebuild {
		t.Error("Expected rebuild after cache clear")
	}
}

func TestKBIndexCache_GetStats(t *testing.T) {
	tmpDir := t.TempDir()
	logger := testLogger()

	// Create test KB file
	if err := os.WriteFile(filepath.Join(tmpDir, "test.yaml"), []byte("id: test"), 0644); err != nil {
		t.Fatalf("Failed to create test KB file: %v", err)
	}

	cache := NewKBIndexCache(tmpDir, logger)

	// Stats when no cache exists
	stats, err := cache.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}
	if exists, ok := stats["exists"].(bool); !ok || exists {
		t.Error("Expected cache to not exist")
	}

	// Save metadata
	if err := cache.SaveMetadata(156, "bleve-2.3.10"); err != nil {
		t.Fatalf("SaveMetadata failed: %v", err)
	}

	// Stats after caching
	stats, err = cache.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}
	if exists, ok := stats["exists"].(bool); !ok || !exists {
		t.Error("Expected cache to exist after saving metadata")
	}
}

func TestKBIndexMetadata_JSONRoundTrip(t *testing.T) {
	buildTime, _ := time.Parse(time.RFC3339, "2025-01-07T10:30:00+03:30")
	original := KBIndexMetadata{
		Version:      "1.0.0",
		KBHash:       "abc123def456",
		KBPath:       "/path/to/kb",
		BuildTime:    buildTime,
		EntryCount:   156,
		IndexVersion: "bleve-2.3.10",
	}

	// Marshal to JSON
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal metadata: %v", err)
	}

	// Unmarshal from JSON
	var decoded KBIndexMetadata
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal metadata: %v", err)
	}

	// Verify fields
	if decoded.Version != original.Version {
		t.Errorf("Version mismatch: %s != %s", decoded.Version, original.Version)
	}

	if decoded.KBHash != original.KBHash {
		t.Errorf("KBHash mismatch: %s != %s", decoded.KBHash, original.KBHash)
	}

	if decoded.EntryCount != original.EntryCount {
		t.Errorf("EntryCount mismatch: %d != %d", decoded.EntryCount, original.EntryCount)
	}
}
