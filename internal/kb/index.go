package kb

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blevesearch/bleve"
	"github.com/blevesearch/bleve/search/query"
	"github.com/rs/zerolog/log"
)

const (
	// Index metadata keys
	metadataKBHash      = "kb_hash"
	metadataBuildTime   = "build_time"
	defaultIndexPath    = ".deepguard/kb-index"
	defaultKBDataPath   = "internal/kb/data"
)

// IndexManager manages the Bleve search index for vulnerability patterns
type IndexManager struct {
	index      bleve.Index
	indexPath  string
	kbDataPath string
	mu         sync.RWMutex
}

// IndexedKBEntry represents a KB entry as stored in the Bleve index
type IndexedKBEntry struct {
	ID           string `json:"id"`
	Title        string `json:"title"`
	Description  string `json:"description"`
	CodePatterns string `json:"code_patterns"` // Concatenated with newlines
}

// NewIndexManager creates a new index manager
func NewIndexManager(indexPath, kbDataPath string) *IndexManager {
	if indexPath == "" {
		indexPath = defaultIndexPath
	}
	if kbDataPath == "" {
		kbDataPath = defaultKBDataPath
	}

	return &IndexManager{
		indexPath:  indexPath,
		kbDataPath: kbDataPath,
	}
}

// Initialize opens or creates the index, rebuilding if necessary
func (im *IndexManager) Initialize() error {
	im.mu.Lock()
	defer im.mu.Unlock()

	log.Info().
		Str("component", "index").
		Str("path", im.indexPath).
		Msg("Initializing KB index")

	// Calculate current KB directory hash
	currentHash, err := im.calculateKBHash()
	if err != nil {
		return fmt.Errorf("failed to calculate KB hash: %w", err)
	}

	// Check if index exists by trying to stat the directory
	var needsRebuild bool
	var rebuildReason string

	if _, err := os.Stat(im.indexPath); os.IsNotExist(err) {
		needsRebuild = true
		rebuildReason = "index does not exist"
	} else {
		// Open existing index to check metadata
		idx, err := bleve.Open(im.indexPath)
		if err != nil {
			needsRebuild = true
			rebuildReason = fmt.Sprintf("failed to open existing index: %v", err)
		} else {
			// Check stored hash
			storedHash, err := im.getMetadata(idx, metadataKBHash)
			if err != nil || storedHash != currentHash {
				needsRebuild = true
				rebuildReason = "KB hash mismatch"
			}
			idx.Close()
		}
	}

	if needsRebuild {
		log.Info().
			Str("component", "index").
			Str("reason", rebuildReason).
			Msg("Rebuilding KB index")

		if err := im.rebuildIndex(currentHash); err != nil {
			return fmt.Errorf("failed to rebuild index: %w", err)
		}
	} else {
		log.Debug().
			Str("component", "index").
			Msg("KB index is up to date, skipping rebuild")

		// Open existing index
		idx, err := bleve.Open(im.indexPath)
		if err != nil {
			return fmt.Errorf("failed to open index: %w", err)
		}
		im.index = idx
	}

	log.Info().
		Str("component", "index").
		Str("path", im.indexPath).
		Msg("KB index initialized successfully")

	return nil
}

// rebuildIndex deletes old index and creates a new one
func (im *IndexManager) rebuildIndex(kbHash string) error {
	// Delete old index if it exists
	if err := os.RemoveAll(im.indexPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete old index: %w", err)
	}

	// Create new index with BM25 scoring
	idx, err := im.createIndex()
	if err != nil {
		return fmt.Errorf("failed to create index: %w", err)
	}

	// Load KB entries
	entries, err := LoadKBDirectory(im.kbDataPath)
	if err != nil {
		idx.Close()
		return fmt.Errorf("failed to load KB entries: %w", err)
	}

	log.Info().
		Str("component", "index").
		Int("count", len(entries)).
		Msg("Indexing KB entries")

	// Index entries in batch
	batch := idx.NewBatch()
	for _, entry := range entries {
		indexedEntry := IndexedKBEntry{
			ID:           entry.ID,
			Title:        entry.Title,
			Description:  entry.Description,
			CodePatterns: strings.Join(entry.CodePatterns, "\n"),
		}

		if err := batch.Index(entry.ID, indexedEntry); err != nil {
			idx.Close()
			return fmt.Errorf("failed to add entry %s to batch: %w", entry.ID, err)
		}
	}

	if err := idx.Batch(batch); err != nil {
		idx.Close()
		return fmt.Errorf("failed to execute batch: %w", err)
	}

	// Store metadata
	if err := im.setMetadata(idx, metadataKBHash, kbHash); err != nil {
		idx.Close()
		return fmt.Errorf("failed to store KB hash: %w", err)
	}

	buildTime := time.Now().UTC().Format(time.RFC3339)
	if err := im.setMetadata(idx, metadataBuildTime, buildTime); err != nil {
		idx.Close()
		return fmt.Errorf("failed to store build time: %w", err)
	}

	im.index = idx

	log.Info().
		Str("component", "index").
		Int("entries", len(entries)).
		Str("hash", kbHash).
		Msg("KB index built successfully")

	return nil
}

// createIndex creates a new Bleve index with BM25 scoring configuration
func (im *IndexManager) createIndex() (bleve.Index, error) {
	// Create index mapping
	indexMapping := bleve.NewIndexMapping()

	// Configure BM25 similarity (default k1=1.2, b=0.75)
	indexMapping.DefaultAnalyzer = "standard"

	// Create document mapping for KB entries
	kbMapping := bleve.NewDocumentMapping()

	// ID field - stored but not indexed
	idField := bleve.NewTextFieldMapping()
	idField.Store = true
	idField.Index = false
	kbMapping.AddFieldMappingsAt("id", idField)

	// Title field - indexed and stored
	titleField := bleve.NewTextFieldMapping()
	titleField.Store = true
	titleField.Index = true
	titleField.Analyzer = "standard"
	kbMapping.AddFieldMappingsAt("title", titleField)

	// Description field - indexed and stored
	descriptionField := bleve.NewTextFieldMapping()
	descriptionField.Store = true
	descriptionField.Index = true
	descriptionField.Analyzer = "standard"
	kbMapping.AddFieldMappingsAt("description", descriptionField)

	// Code patterns field - indexed and stored
	codePatternsField := bleve.NewTextFieldMapping()
	codePatternsField.Store = true
	codePatternsField.Index = true
	codePatternsField.Analyzer = "standard"
	kbMapping.AddFieldMappingsAt("code_patterns", codePatternsField)

	indexMapping.AddDocumentMapping("_default", kbMapping)

	// Create index
	idx, err := bleve.New(im.indexPath, indexMapping)
	if err != nil {
		return nil, err
	}

	return idx, nil
}

// calculateKBHash computes SHA256 hash of KB directory contents
func (im *IndexManager) calculateKBHash() (string, error) {
	var files []string

	// Walk directory to get all YAML files
	err := filepath.WalkDir(im.kbDataPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && (strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return "", err
	}

	// Sort files for consistent hashing
	sort.Strings(files)

	// Compute combined hash
	h := sha256.New()

	for _, filePath := range files {
		// Add filename to hash
		if _, err := h.Write([]byte(filePath)); err != nil {
			return "", err
		}

		// Add file content hash
		fileHash, err := hashFile(filePath)
		if err != nil {
			return "", fmt.Errorf("failed to hash %s: %w", filePath, err)
		}
		if _, err := h.Write([]byte(fileHash)); err != nil {
			return "", err
		}
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// hashFile computes SHA256 hash of a single file
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// Search performs a BM25-scored search query
func (im *IndexManager) Search(queryString string, limit int) (*bleve.SearchResult, error) {
	im.mu.RLock()
	defer im.mu.RUnlock()

	if im.index == nil {
		return nil, fmt.Errorf("index not initialized")
	}

	// Create query
	q := query.NewMatchQuery(queryString)

	// Create search request
	searchRequest := bleve.NewSearchRequest(q)
	searchRequest.Size = limit
	searchRequest.Fields = []string{"id", "title", "description", "code_patterns"}

	// Execute search
	searchResult, err := im.index.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}

	return searchResult, nil
}

// Close closes the index
func (im *IndexManager) Close() error {
	im.mu.Lock()
	defer im.mu.Unlock()

	if im.index != nil {
		log.Info().
			Str("component", "index").
			Msg("Closing KB index")

		if err := im.index.Close(); err != nil {
			return fmt.Errorf("failed to close index: %w", err)
		}
		im.index = nil
	}

	return nil
}

// Validate checks if the index is valid and accessible
func (im *IndexManager) Validate() error {
	im.mu.RLock()
	defer im.mu.RUnlock()

	if im.index == nil {
		return fmt.Errorf("index not initialized")
	}

	// Try to get document count
	count, err := im.index.DocCount()
	if err != nil {
		return fmt.Errorf("index health check failed: %w", err)
	}

	log.Debug().
		Str("component", "index").
		Uint64("doc_count", count).
		Msg("Index validation successful")

	return nil
}

// getMetadata retrieves metadata from index internal document
func (im *IndexManager) getMetadata(idx bleve.Index, key string) (string, error) {
	// Bleve doesn't have built-in metadata storage, so we use a special document
	metadataDoc := "_metadata"

	doc, err := idx.Document(metadataDoc)
	if err != nil {
		return "", err
	}

	if doc == nil {
		return "", fmt.Errorf("metadata document not found")
	}

	for _, field := range doc.Fields {
		if field.Name() == key {
			return string(field.Value()), nil
		}
	}

	return "", fmt.Errorf("metadata key %s not found", key)
}

// setMetadata stores metadata in index internal document
func (im *IndexManager) setMetadata(idx bleve.Index, key, value string) error {
	metadataDoc := "_metadata"

	// Create or update metadata document
	metadata := map[string]string{
		key: value,
	}

	return idx.Index(metadataDoc, metadata)
}
