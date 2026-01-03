package cache

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog"
)

const (
	// DefaultCacheDir is the default location for DeepGuard cache
	DefaultCacheDir = ".deepguard"

	// KBIndexDir is the subdirectory for KB index cache
	KBIndexDir = "kb-index"

	// MetadataFile stores KB index metadata
	MetadataFile = "metadata.json"
)

// KBIndexMetadata stores information about the cached KB index
type KBIndexMetadata struct {
	Version      string    `json:"version"`
	KBHash       string    `json:"kb_hash"`
	KBPath       string    `json:"kb_path"`
	BuildTime    time.Time `json:"build_time"`
	EntryCount   int       `json:"entry_count"`
	IndexVersion string    `json:"index_version"` // Bleve index version
}

// KBIndexCache manages KB index persistence and rebuild detection
type KBIndexCache struct {
	cacheDir string
	kbDir    string
	logger   zerolog.Logger
}

// NewKBIndexCache creates a new KB index cache manager
func NewKBIndexCache(kbDir string, logger zerolog.Logger) *KBIndexCache {
	return &KBIndexCache{
		cacheDir: filepath.Join(DefaultCacheDir, KBIndexDir),
		kbDir:    kbDir,
		logger:   logger,
	}
}

// ShouldRebuild checks if the KB index needs to be rebuilt
// Returns true if index missing, hash mismatch, or metadata invalid
func (c *KBIndexCache) ShouldRebuild() (bool, string, error) {
	// Check if cache directory exists
	if _, err := os.Stat(c.cacheDir); os.IsNotExist(err) {
		c.logger.Debug().
			Str("component", "cache").
			Str("reason", "cache_missing").
			Msg("KB index cache does not exist")
		return true, "cache directory missing", nil
	}

	// Load metadata
	metadata, err := c.LoadMetadata()
	if err != nil {
		c.logger.Debug().
			Str("component", "cache").
			Str("reason", "metadata_error").
			Err(err).
			Msg("Failed to load KB index metadata")
		return true, "metadata error", nil
	}

	// Compute current KB hash
	currentHash, err := ComputeKBHash(c.kbDir)
	if err != nil {
		return false, "", fmt.Errorf("failed to compute KB hash: %w", err)
	}

	// Compare hashes
	if metadata.KBHash != currentHash {
		c.logger.Info().
			Str("component", "cache").
			Str("reason", "kb_changed").
			Str("old_hash", metadata.KBHash[:8]+"...").
			Str("new_hash", currentHash[:8]+"...").
			Msg("KB content changed, index rebuild required")
		return true, "KB content changed", nil
	}

	c.logger.Debug().
		Str("component", "cache").
		Str("kb_hash", currentHash[:8]+"...").
		Time("build_time", metadata.BuildTime).
		Msg("Using cached KB index")

	return false, "", nil
}

// SaveMetadata saves KB index metadata to cache
func (c *KBIndexCache) SaveMetadata(entryCount int, indexVersion string) error {
	// Ensure cache directory exists
	if err := os.MkdirAll(c.cacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Compute KB hash
	kbHash, err := ComputeKBHash(c.kbDir)
	if err != nil {
		return fmt.Errorf("failed to compute KB hash: %w", err)
	}

	metadata := KBIndexMetadata{
		Version:      "1.0.0",
		KBHash:       kbHash,
		KBPath:       c.kbDir,
		BuildTime:    time.Now(),
		EntryCount:   entryCount,
		IndexVersion: indexVersion,
	}

	// Write metadata to file
	metadataPath := filepath.Join(c.cacheDir, MetadataFile)
	file, err := os.Create(metadataPath)
	if err != nil {
		return fmt.Errorf("failed to create metadata file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(metadata); err != nil {
		return fmt.Errorf("failed to encode metadata: %w", err)
	}

	c.logger.Info().
		Str("component", "cache").
		Str("kb_hash", kbHash[:8]+"...").
		Int("entries", entryCount).
		Msg("Saved KB index metadata")

	return nil
}

// LoadMetadata loads KB index metadata from cache
func (c *KBIndexCache) LoadMetadata() (*KBIndexMetadata, error) {
	metadataPath := filepath.Join(c.cacheDir, MetadataFile)

	file, err := os.Open(metadataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open metadata file: %w", err)
	}
	defer file.Close()

	var metadata KBIndexMetadata
	if err := json.NewDecoder(file).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("failed to decode metadata: %w", err)
	}

	return &metadata, nil
}

// GetIndexPath returns the path where the Bleve index should be stored
func (c *KBIndexCache) GetIndexPath() string {
	return filepath.Join(c.cacheDir, "index.bleve")
}

// Clear removes all cached index data
func (c *KBIndexCache) Clear() error {
	if err := os.RemoveAll(c.cacheDir); err != nil {
		return fmt.Errorf("failed to clear KB index cache: %w", err)
	}

	c.logger.Info().
		Str("component", "cache").
		Msg("Cleared KB index cache")

	return nil
}

// GetStats returns cache statistics
func (c *KBIndexCache) GetStats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Check if cache exists
	info, err := os.Stat(c.cacheDir)
	if os.IsNotExist(err) {
		stats["exists"] = false
		return stats, nil
	}
	stats["exists"] = true

	// Get directory size
	var size int64
	err = filepath.Walk(c.cacheDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to calculate cache size: %w", err)
	}
	stats["size_bytes"] = size
	stats["size_mb"] = float64(size) / (1024 * 1024)

	// Load metadata
	metadata, err := c.LoadMetadata()
	if err == nil {
		stats["kb_hash"] = metadata.KBHash[:8] + "..."
		stats["build_time"] = metadata.BuildTime.Format(time.RFC3339)
		stats["entry_count"] = metadata.EntryCount
		stats["index_version"] = metadata.IndexVersion
		stats["age_hours"] = time.Since(metadata.BuildTime).Hours()
	}

	stats["last_modified"] = info.ModTime().Format(time.RFC3339)

	return stats, nil
}
