package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

const (
	// APICacheDir is the subdirectory for API response cache
	APICacheDir = "api-cache"

	// CacheStatsFile stores cache statistics
	CacheStatsFile = "stats.json"

	// MaxCacheAgeD days - auto-clean entries older than this
	MaxCacheAgeDays = 30
)

// APICacheEntry represents a cached API response
type APICacheEntry struct {
	ChunkHash       string                 `json:"chunk_hash"`
	PromptTemplate  string                 `json:"prompt_template"`
	Model           string                 `json:"model"`
	Timestamp       time.Time              `json:"timestamp"`
	Response        map[string]interface{} `json:"response"` // Full OpenAI response
	TokensUsed      TokenUsage             `json:"tokens_used"`
}

// TokenUsage represents token consumption for a cached response
type TokenUsage struct {
	Prompt     int `json:"prompt"`
	Completion int `json:"completion"`
	Total      int `json:"total"`
}

// APICacheStats tracks cache performance metrics
type APICacheStats struct {
	TotalEntries int       `json:"total_entries"`
	Hits         int       `json:"hits"`
	Misses       int       `json:"misses"`
	LastClean    time.Time `json:"last_clean"`
	TotalSaved   float64   `json:"total_saved_usd"` // Estimated cost savings
}

// APIResponseCache manages caching of OpenAI API responses
type APIResponseCache struct {
	cacheDir string
	enabled  bool
	logger   zerolog.Logger
	mu       sync.RWMutex // Protects concurrent access
	stats    *APICacheStats
}

// NewAPIResponseCache creates a new API response cache
func NewAPIResponseCache(enabled bool, logger zerolog.Logger) *APIResponseCache {
	cache := &APIResponseCache{
		cacheDir: filepath.Join(DefaultCacheDir, APICacheDir),
		enabled:  enabled,
		logger:   logger,
		stats:    &APICacheStats{},
	}

	if enabled {
		cache.loadStats()
		cache.logger.Info().
			Str("component", "cache").
			Bool("enabled", true).
			Str("dir", cache.cacheDir).
			Msg("API response cache enabled")
	}

	return cache
}

// IsEnabled returns whether the cache is enabled
func (c *APIResponseCache) IsEnabled() bool {
	return c.enabled
}

// Get retrieves a cached response if available
func (c *APIResponseCache) Get(chunkHash string, promptTemplate string, model string) (*APICacheEntry, bool) {
	if !c.enabled {
		return nil, false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	cacheKey := c.generateCacheKey(chunkHash, promptTemplate, model)
	cachePath := c.getCachePath(cacheKey)

	// Check if cache file exists
	if _, err := os.Stat(cachePath); os.IsNotExist(err) {
		c.stats.Misses++
		return nil, false
	}

	// Load cache entry
	file, err := os.Open(cachePath)
	if err != nil {
		c.logger.Warn().
			Str("component", "cache").
			Err(err).
			Msg("Failed to open cache file")
		c.stats.Misses++
		return nil, false
	}
	defer file.Close()

	var entry APICacheEntry
	if err := json.NewDecoder(file).Decode(&entry); err != nil {
		c.logger.Warn().
			Str("component", "cache").
			Err(err).
			Msg("Failed to decode cache entry")
		c.stats.Misses++
		return nil, false
	}

	// Check if entry is too old (> 30 days)
	if time.Since(entry.Timestamp).Hours() > float64(MaxCacheAgeDays*24) {
		c.logger.Debug().
			Str("component", "cache").
			Str("cache_key", cacheKey[:8]+"...").
			Msg("Cache entry expired")
		os.Remove(cachePath) // Clean up stale entry
		c.stats.Misses++
		return nil, false
	}

	c.stats.Hits++
	c.logger.Debug().
		Str("component", "cache").
		Str("cache_key", cacheKey[:8]+"...").
		Msg("Cache hit")

	return &entry, true
}

// Set stores an API response in the cache
func (c *APIResponseCache) Set(chunkHash string, promptTemplate string, model string, response map[string]interface{}, tokens TokenUsage) error {
	if !c.enabled {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Ensure cache directory exists
	if err := os.MkdirAll(c.cacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	entry := APICacheEntry{
		ChunkHash:      chunkHash,
		PromptTemplate: promptTemplate,
		Model:          model,
		Timestamp:      time.Now(),
		Response:       response,
		TokensUsed:     tokens,
	}

	cacheKey := c.generateCacheKey(chunkHash, promptTemplate, model)
	cachePath := c.getCachePath(cacheKey)

	// Ensure subdirectory exists
	cacheSubdir := filepath.Dir(cachePath)
	if err := os.MkdirAll(cacheSubdir, 0755); err != nil {
		return fmt.Errorf("failed to create cache subdirectory: %w", err)
	}

	// Write to temporary file first (atomic write)
	tempPath := cachePath + ".tmp"
	file, err := os.Create(tempPath)
	if err != nil {
		return fmt.Errorf("failed to create cache file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(entry); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("failed to encode cache entry: %w", err)
	}

	file.Close()

	// Atomic rename
	if err := os.Rename(tempPath, cachePath); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("failed to move cache file: %w", err)
	}

	c.stats.TotalEntries++

	c.logger.Debug().
		Str("component", "cache").
		Str("cache_key", cacheKey[:8]+"...").
		Msg("Cached API response")

	return nil
}

// generateCacheKey creates a unique key for cache lookup
// Format: SHA256(chunk_hash + prompt_template + model)
func (c *APIResponseCache) generateCacheKey(chunkHash string, promptTemplate string, model string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s:%s:%s", chunkHash, promptTemplate, model)
	hashBytes := h.Sum(nil)
	return hex.EncodeToString(hashBytes)
}

// getCachePath returns the file path for a cache key
func (c *APIResponseCache) getCachePath(cacheKey string) string {
	// Use first 2 chars as subdirectory for better file system performance
	subdir := cacheKey[:2]
	return filepath.Join(c.cacheDir, subdir, cacheKey+".json")
}

// Clear removes all cached API responses
func (c *APIResponseCache) Clear() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := os.RemoveAll(c.cacheDir); err != nil {
		return fmt.Errorf("failed to clear API cache: %w", err)
	}

	// Reset stats
	c.stats = &APICacheStats{}
	c.saveStats()

	c.logger.Info().
		Str("component", "cache").
		Msg("Cleared API response cache")

	return nil
}

// CleanOld removes cache entries older than MaxCacheAgeDays
func (c *APIResponseCache) CleanOld() error {
	if !c.enabled {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	var removedCount int
	cutoff := time.Now().Add(-time.Hour * 24 * MaxCacheAgeDays)

	err := filepath.Walk(c.cacheDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories, stats file, and non-JSON files
		if info.IsDir() || filepath.Ext(path) != ".json" || filepath.Base(path) == CacheStatsFile {
			return nil
		}

		// Read and parse the cache entry to check timestamp
		file, err := os.Open(path)
		if err != nil {
			return nil // Skip files we can't read
		}
		defer file.Close()

		var entry APICacheEntry
		if err := json.NewDecoder(file).Decode(&entry); err != nil {
			return nil // Skip invalid JSON files
		}

		// Check if entry is older than cutoff
		if entry.Timestamp.Before(cutoff) {
			if err := os.Remove(path); err != nil {
				c.logger.Warn().
					Str("component", "cache").
					Str("path", path).
					Err(err).
					Msg("Failed to remove old cache entry")
			} else {
				removedCount++
			}
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to clean old cache entries: %w", err)
	}

	c.stats.LastClean = time.Now()
	c.saveStats()

	if removedCount > 0 {
		c.logger.Info().
			Str("component", "cache").
			Int("removed", removedCount).
			Msg("Cleaned old cache entries")
	}

	return nil
}

// GetStats returns cache statistics
func (c *APIResponseCache) GetStats() (*APICacheStats, error) {
	if !c.enabled {
		return &APICacheStats{}, nil
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	// Count actual files
	var fileCount int
	var totalSize int64

	// Check if cache directory exists
	if _, err := os.Stat(c.cacheDir); os.IsNotExist(err) {
		// Cache directory doesn't exist yet, return empty stats
		stats := *c.stats
		stats.TotalEntries = 0
		return &stats, nil
	}

	err := filepath.Walk(c.cacheDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && filepath.Ext(path) == ".json" && filepath.Base(path) != CacheStatsFile {
			fileCount++
			totalSize += info.Size()
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to calculate stats: %w", err)
	}

	stats := *c.stats
	stats.TotalEntries = fileCount

	return &stats, nil
}

// loadStats loads cache statistics from disk
func (c *APIResponseCache) loadStats() {
	statsPath := filepath.Join(c.cacheDir, CacheStatsFile)

	file, err := os.Open(statsPath)
	if err != nil {
		// Stats file doesn't exist yet, use defaults
		return
	}
	defer file.Close()

	if err := json.NewDecoder(file).Decode(c.stats); err != nil {
		c.logger.Warn().
			Str("component", "cache").
			Err(err).
			Msg("Failed to load cache stats")
	}
}

// saveStats saves cache statistics to disk
func (c *APIResponseCache) saveStats() {
	if !c.enabled {
		return
	}

	if err := os.MkdirAll(c.cacheDir, 0755); err != nil {
		return
	}

	statsPath := filepath.Join(c.cacheDir, CacheStatsFile)
	file, err := os.Create(statsPath)
	if err != nil {
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	encoder.Encode(c.stats)
}

// GetHitRate returns the cache hit rate as a percentage
func (c *APIResponseCache) GetHitRate() float64 {
	total := c.stats.Hits + c.stats.Misses
	if total == 0 {
		return 0.0
	}
	return float64(c.stats.Hits) / float64(total) * 100.0
}
