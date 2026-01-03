package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ComputeKBHash computes a SHA256 hash of the knowledge base directory
// Hash is based on file paths, modification times, and sizes
// Returns empty string on error
func ComputeKBHash(kbDir string) (string, error) {
	var fileInfos []fileInfo

	// Walk the KB directory
	err := filepath.Walk(kbDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Only include YAML files
		if !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml") {
			return nil
		}

		// Get relative path for consistency
		relPath, err := filepath.Rel(kbDir, path)
		if err != nil {
			return err
		}

		fileInfos = append(fileInfos, fileInfo{
			Path:    relPath,
			ModTime: info.ModTime().Unix(),
			Size:    info.Size(),
		})

		return nil
	})

	if err != nil {
		return "", fmt.Errorf("failed to walk KB directory: %w", err)
	}

	// Sort by path for deterministic ordering
	sort.Slice(fileInfos, func(i, j int) bool {
		return fileInfos[i].Path < fileInfos[j].Path
	})

	// Compute hash from file metadata
	h := sha256.New()
	for _, fi := range fileInfos {
		// Write path, mod time, and size to hash
		fmt.Fprintf(h, "%s:%d:%d\n", fi.Path, fi.ModTime, fi.Size)
	}

	hashBytes := h.Sum(nil)
	return hex.EncodeToString(hashBytes), nil
}

// ComputeFileHash computes SHA256 hash of a single file's contents
func ComputeFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	hashBytes := h.Sum(nil)
	return hex.EncodeToString(hashBytes), nil
}

// fileInfo represents metadata about a KB file
type fileInfo struct {
	Path    string
	ModTime int64
	Size    int64
}
