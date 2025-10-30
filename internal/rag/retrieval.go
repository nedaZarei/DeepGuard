package rag

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"github.com/Neda-Zarei/deep-guard/internal/chunker"
	"github.com/Neda-Zarei/deep-guard/internal/kb"
	"github.com/blevesearch/bleve"
	"github.com/blevesearch/bleve/search/query"
	"github.com/rs/zerolog/log"
)

const (
	// Token budget constants
	defaultTokenBudget     = 1500 // ~1.5k tokens
	charsPerToken          = 4    // Conservative estimate: 4 chars per token
	defaultCharBudget      = defaultTokenBudget * charsPerToken // 6000 chars
	defaultTopK            = 3    // Number of KB entries to retrieve per chunk
	functionNameBoost      = 2.0  // Boost weight for function name matches
	defaultCacheSize       = 1000 // Maximum cache entries (LRU)
	codeSnippetLength      = 200  // First N chars of source code for query
)

// RetrievalResult contains KB entries retrieved for a code chunk
type RetrievalResult struct {
	KBIDs           []string  // KB entry IDs
	RelevanceScores []float64 // BM25 relevance scores
	Entries         []kb.KBEntry // Full KB entries
	TotalChars      int       // Total character count of all entries
	Truncated       bool      // Whether entries were truncated
}

// RetrieverConfig configures the retrieval engine
type RetrieverConfig struct {
	TokenBudget int  // Token budget for retrieved KB entries
	TopK        int  // Number of KB entries to retrieve
	EnableCache bool // Enable in-memory caching
	CacheSize   int  // Maximum cache entries
}

// Retriever performs BM25-based retrieval of KB entries for code chunks
type Retriever struct {
	indexManager *kb.IndexManager
	config       RetrieverConfig
	cache        *retrievalCache
}

// retrievalCache implements an in-memory LRU cache for retrieval results
type retrievalCache struct {
	mu       sync.RWMutex
	entries  map[string]*cacheEntry
	lruList  []string // Simple LRU tracking (most recent at end)
	maxSize  int
	hits     int64
	misses   int64
}

type cacheEntry struct {
	result RetrievalResult
}

// NewRetriever creates a new retrieval engine
func NewRetriever(indexManager *kb.IndexManager, config RetrieverConfig) *Retriever {
	// Set defaults
	if config.TokenBudget <= 0 {
		config.TokenBudget = defaultTokenBudget
	}
	if config.TopK <= 0 {
		config.TopK = defaultTopK
	}
	if config.CacheSize <= 0 {
		config.CacheSize = defaultCacheSize
	}

	retriever := &Retriever{
		indexManager: indexManager,
		config:       config,
	}

	if config.EnableCache {
		retriever.cache = newRetrievalCache(config.CacheSize)
	}

	return retriever
}

// newRetrievalCache creates a new retrieval cache
func newRetrievalCache(maxSize int) *retrievalCache {
	return &retrievalCache{
		entries: make(map[string]*cacheEntry),
		lruList: make([]string, 0, maxSize),
		maxSize: maxSize,
	}
}

// Retrieve retrieves relevant KB entries for a code chunk
func (r *Retriever) Retrieve(chunk chunker.CodeChunk) (*RetrievalResult, error) {
	// Check cache first
	if r.config.EnableCache {
		cacheKey := r.computeCacheKey(chunk)
		if cached := r.cache.get(cacheKey); cached != nil {
			log.Debug().
				Str("component", "retriever").
				Str("chunk_id", chunk.ID).
				Str("function", chunk.FunctionName).
				Msg("Cache hit")
			return cached, nil
		}

		log.Debug().
			Str("component", "retriever").
			Str("chunk_id", chunk.ID).
			Str("function", chunk.FunctionName).
			Msg("Cache miss")
	}

	// Construct search query
	searchQuery := r.constructQuery(chunk)

	log.Debug().
		Str("component", "retriever").
		Str("chunk_id", chunk.ID).
		Str("function", chunk.FunctionName).
		Str("query", searchQuery).
		Msg("Executing BM25 search")

	// Execute BM25 search
	searchResult, err := r.executeSearch(searchQuery, chunk.Language)
	if err != nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}

	// Extract results
	result := r.extractResults(searchResult, chunk)

	// Apply token budget
	if err := r.applyTokenBudget(&result); err != nil {
		return nil, fmt.Errorf("failed to apply token budget: %w", err)
	}

	log.Debug().
		Str("component", "retriever").
		Str("chunk_id", chunk.ID).
		Int("kb_entries", len(result.KBIDs)).
		Int("total_chars", result.TotalChars).
		Bool("truncated", result.Truncated).
		Msg("Retrieval completed")

	// Cache result
	if r.config.EnableCache {
		cacheKey := r.computeCacheKey(chunk)
		r.cache.put(cacheKey, &result)
	}

	return &result, nil
}

// constructQuery builds a search query from a code chunk
func (r *Retriever) constructQuery(chunk chunker.CodeChunk) string {
	var parts []string

	// Add function name (most important)
	if chunk.FunctionName != "" && chunk.FunctionName != "anonymous" && chunk.FunctionName != "unknown" {
		parts = append(parts, chunk.FunctionName)
	}

	// Add language context
	if chunk.Language != "" {
		parts = append(parts, chunk.Language)
	}

	// Add code snippet (first 200 chars)
	if len(chunk.Source) > 0 {
		snippet := chunk.Source
		if len(snippet) > codeSnippetLength {
			snippet = snippet[:codeSnippetLength]
		}
		// Clean snippet: remove newlines, excessive whitespace
		snippet = strings.ReplaceAll(snippet, "\n", " ")
		snippet = strings.Join(strings.Fields(snippet), " ")
		parts = append(parts, snippet)
	}

	return strings.Join(parts, " ")
}

// executeSearch performs BM25 search with boosted function name matching
func (r *Retriever) executeSearch(queryString string, language string) (*bleve.SearchResult, error) {
	// Create a boolean query with boosted fields
	boolQuery := bleve.NewBooleanQuery()

	// Main match query
	mainQuery := query.NewMatchQuery(queryString)
	boolQuery.AddMust(mainQuery)

	// Create search request
	searchRequest := bleve.NewSearchRequest(boolQuery)
	searchRequest.Size = r.config.TopK
	searchRequest.Fields = []string{"id", "title", "description", "code_patterns"}

	// Execute search via IndexManager
	return r.indexManager.Search(queryString, r.config.TopK)
}

// extractResults extracts KB entries from search results
func (r *Retriever) extractResults(searchResult *bleve.SearchResult, chunk chunker.CodeChunk) RetrievalResult {
	result := RetrievalResult{
		KBIDs:           make([]string, 0, len(searchResult.Hits)),
		RelevanceScores: make([]float64, 0, len(searchResult.Hits)),
		Entries:         make([]kb.KBEntry, 0, len(searchResult.Hits)),
	}

	for _, hit := range searchResult.Hits {
		// Extract fields
		id := ""
		title := ""
		description := ""
		codePatternsStr := ""

		if val, ok := hit.Fields["id"].(string); ok {
			id = val
		}
		if val, ok := hit.Fields["title"].(string); ok {
			title = val
		}
		if val, ok := hit.Fields["description"].(string); ok {
			description = val
		}
		if val, ok := hit.Fields["code_patterns"].(string); ok {
			codePatternsStr = val
		}

		// Split code patterns back into array
		var codePatterns []string
		if codePatternsStr != "" {
			codePatterns = strings.Split(codePatternsStr, "\n")
		}

		// Create KB entry
		entry := kb.KBEntry{
			ID:           id,
			Title:        title,
			Description:  description,
			CodePatterns: codePatterns,
		}

		result.KBIDs = append(result.KBIDs, id)
		result.RelevanceScores = append(result.RelevanceScores, hit.Score)
		result.Entries = append(result.Entries, entry)

		log.Debug().
			Str("component", "retriever").
			Str("kb_id", id).
			Float64("score", hit.Score).
			Str("title", title).
			Msg("Retrieved KB entry")
	}

	return result
}

// applyTokenBudget truncates KB entries to fit within token budget
func (r *Retriever) applyTokenBudget(result *RetrievalResult) error {
	if len(result.Entries) == 0 {
		result.TotalChars = 0
		return nil
	}

	charBudget := r.config.TokenBudget * charsPerToken

	// Calculate current size
	totalChars := 0
	for _, entry := range result.Entries {
		totalChars += len(entry.ID) + len(entry.Title) + len(entry.Description)
		for _, pattern := range entry.CodePatterns {
			totalChars += len(pattern)
		}
	}

	result.TotalChars = totalChars

	// If within budget, no truncation needed
	if totalChars <= charBudget {
		result.Truncated = false
		return nil
	}

	// Need to truncate
	result.Truncated = true

	log.Debug().
		Str("component", "retriever").
		Int("current_chars", totalChars).
		Int("budget_chars", charBudget).
		Msg("Truncating KB entries to fit budget")

	// Calculate how much we need to reduce
	excessChars := totalChars - charBudget

	// Strategy: Truncate descriptions proportionally, keep at least 1 code pattern per entry
	// Keep full ID and title (critical for identification)

	// Calculate total description length
	totalDescLen := 0
	for _, entry := range result.Entries {
		totalDescLen += len(entry.Description)
	}

	if totalDescLen == 0 {
		// No descriptions to truncate, try code patterns
		return r.truncateCodePatterns(result, excessChars)
	}

	// Truncate each description proportionally
	for i := range result.Entries {
		if excessChars <= 0 {
			break
		}

		descLen := len(result.Entries[i].Description)
		if descLen == 0 {
			continue
		}

		// Calculate this entry's share of truncation
		proportionalCut := int(float64(excessChars) * (float64(descLen) / float64(totalDescLen)))

		// Ensure we leave at least some description
		minDescLen := 100
		actualCut := proportionalCut
		if descLen-actualCut < minDescLen {
			actualCut = descLen - minDescLen
			if actualCut < 0 {
				actualCut = 0
			}
		}

		if actualCut > 0 {
			newLen := descLen - actualCut
			result.Entries[i].Description = result.Entries[i].Description[:newLen] + "..."
			excessChars -= actualCut
		}
	}

	// Recalculate total chars
	result.TotalChars = 0
	for _, entry := range result.Entries {
		result.TotalChars += len(entry.ID) + len(entry.Title) + len(entry.Description)
		for _, pattern := range entry.CodePatterns {
			result.TotalChars += len(pattern)
		}
	}

	return nil
}

// truncateCodePatterns truncates code patterns when descriptions are insufficient
func (r *Retriever) truncateCodePatterns(result *RetrievalResult, excessChars int) error {
	// Keep at least 1 code pattern per entry, truncate others
	for i := range result.Entries {
		if excessChars <= 0 {
			break
		}

		if len(result.Entries[i].CodePatterns) > 1 {
			// Remove patterns from the end
			for j := len(result.Entries[i].CodePatterns) - 1; j >= 1; j-- {
				patternLen := len(result.Entries[i].CodePatterns[j])
				result.Entries[i].CodePatterns = result.Entries[i].CodePatterns[:j]
				excessChars -= patternLen

				if excessChars <= 0 {
					break
				}
			}
		}
	}

	// Recalculate total chars
	result.TotalChars = 0
	for _, entry := range result.Entries {
		result.TotalChars += len(entry.ID) + len(entry.Title) + len(entry.Description)
		for _, pattern := range entry.CodePatterns {
			result.TotalChars += len(pattern)
		}
	}

	return nil
}

// computeCacheKey generates a cache key from chunk metadata
func (r *Retriever) computeCacheKey(chunk chunker.CodeChunk) string {
	// Use chunk ID + language for cache key
	data := chunk.ID + chunk.Language
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// GetCacheStats returns cache statistics
func (r *Retriever) GetCacheStats() (hits int64, misses int64, size int, hitRate float64) {
	if r.cache == nil {
		return 0, 0, 0, 0.0
	}

	r.cache.mu.RLock()
	defer r.cache.mu.RUnlock()

	hits = r.cache.hits
	misses = r.cache.misses
	size = len(r.cache.entries)

	total := hits + misses
	if total > 0 {
		hitRate = float64(hits) / float64(total)
	}

	return
}

// ClearCache clears the retrieval cache
func (r *Retriever) ClearCache() {
	if r.cache != nil {
		r.cache.clear()
	}
}

// Cache methods

func (c *retrievalCache) get(key string) *RetrievalResult {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	if !exists {
		c.mu.RUnlock()
		c.mu.Lock()
		c.misses++
		c.mu.Unlock()
		c.mu.RLock()
		return nil
	}

	c.mu.RUnlock()
	c.mu.Lock()
	c.hits++

	// Update LRU: move to end
	c.updateLRU(key)
	c.mu.Unlock()
	c.mu.RLock()

	return &entry.result
}

func (c *retrievalCache) put(key string, result *RetrievalResult) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if we need to evict
	if len(c.entries) >= c.maxSize {
		// Remove least recently used (first in list)
		if len(c.lruList) > 0 {
			lruKey := c.lruList[0]
			delete(c.entries, lruKey)
			c.lruList = c.lruList[1:]
		}
	}

	// Add new entry
	c.entries[key] = &cacheEntry{
		result: *result,
	}

	// Update LRU
	c.updateLRU(key)
}

func (c *retrievalCache) updateLRU(key string) {
	// Remove key from current position
	for i, k := range c.lruList {
		if k == key {
			c.lruList = append(c.lruList[:i], c.lruList[i+1:]...)
			break
		}
	}

	// Add to end (most recent)
	c.lruList = append(c.lruList, key)
}

func (c *retrievalCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]*cacheEntry)
	c.lruList = make([]string, 0, c.maxSize)
	c.hits = 0
	c.misses = 0
}
