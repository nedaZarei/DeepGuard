package discovery

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
)

// Filter handles file and directory exclusion logic
type Filter struct {
	// patterns contains all exclusion patterns (from .deepguardignore + defaults)
	patterns []string

	// rootPath is the scan root for resolving relative paths
	rootPath string
}

// Default exclusion patterns
var defaultExcludedDirs = []string{
	"node_modules",
	"vendor",
	".git",
	"dist",
	"build",
	"__pycache__",
	".deepguard", // DeepGuard's own runtime directory
}

var defaultExcludedFiles = []string{
	"*.min.js",
	"*.bundle.js",
}

// NewFilter creates a new exclusion filter
// If ignoreFilePath is provided and exists, it will be parsed for additional patterns
func NewFilter(rootPath, ignoreFilePath string) (*Filter, error) {
	filter := &Filter{
		rootPath: rootPath,
		patterns: []string{},
	}

	// Add default exclusions
	filter.patterns = append(filter.patterns, defaultExcludedDirs...)
	filter.patterns = append(filter.patterns, defaultExcludedFiles...)

	log.Debug().
		Str("component", "discovery").
		Str("operation", "filter_init").
		Strs("default_patterns", filter.patterns).
		Msg("Initialized default exclusion patterns")

	// Parse .deepguardignore if it exists
	if ignoreFilePath != "" {
		patterns, err := parseIgnoreFile(ignoreFilePath)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("failed to parse ignore file: %w", err)
			}
			log.Debug().
				Str("component", "discovery").
				Str("ignore_file", ignoreFilePath).
				Msg("Ignore file not found, using defaults only")
		} else {
			filter.patterns = append(filter.patterns, patterns...)
			log.Info().
				Str("component", "discovery").
				Str("ignore_file", ignoreFilePath).
				Int("custom_patterns", len(patterns)).
				Msg("Loaded custom ignore patterns")
		}
	}

	return filter, nil
}

// ShouldExclude determines if a path should be excluded
func (f *Filter) ShouldExclude(relPath string, isDir bool) bool {
	// Normalize path separators for consistent matching
	normalizedPath := filepath.ToSlash(relPath)

	for _, pattern := range f.patterns {
		if f.matchPattern(normalizedPath, pattern, isDir) {
			return true
		}
	}

	return false
}

// matchPattern performs glob-style pattern matching
func (f *Filter) matchPattern(path, pattern string, isDir bool) bool {
	// Normalize pattern separators
	pattern = filepath.ToSlash(pattern)

	// Skip empty patterns and comments
	if pattern == "" || strings.HasPrefix(pattern, "#") {
		return false
	}

	// Handle directory-only patterns (ending with /)
	if strings.HasSuffix(pattern, "/") {
		pattern = strings.TrimSuffix(pattern, "/")
		// For directory patterns, match both the directory itself and files under it
		if isDir {
			// Check if this is the directory or a subdirectory
			if path == pattern || filepath.Base(path) == pattern {
				return true
			}
		}
		// Check if file is under this directory
		if strings.HasPrefix(path, pattern+"/") {
			return true
		}
		// If we're checking a directory and it didn't match above, no match
		if isDir {
			return false
		}
	}

	// Exact directory name match (for patterns like "node_modules")
	if isDir {
		dirName := filepath.Base(path)
		if dirName == pattern {
			return true
		}
		// Also check if any directory in the path matches
		parts := strings.Split(path, "/")
		for _, part := range parts {
			if part == pattern {
				return true
			}
		}
	}

	// Glob pattern matching (e.g., *.min.js)
	if strings.Contains(pattern, "*") {
		matched, err := filepath.Match(pattern, filepath.Base(path))
		if err == nil && matched {
			return true
		}
		// Also try matching against full path for patterns like **/*.min.js
		matched, err = filepath.Match(pattern, path)
		if err == nil && matched {
			return true
		}
	}

	// Full path prefix match (e.g., dist/ matches dist/anything)
	if strings.HasPrefix(path, pattern+"/") {
		return true
	}

	// Exact match
	if path == pattern {
		return true
	}

	return false
}

// parseIgnoreFile reads and parses a .deepguardignore file
// Uses gitignore-style syntax (lines starting with # are comments, blank lines ignored)
func parseIgnoreFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var patterns []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		patterns = append(patterns, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading ignore file: %w", err)
	}

	log.Debug().
		Str("component", "discovery").
		Str("file", filePath).
		Int("patterns", len(patterns)).
		Msg("Parsed ignore file")

	return patterns, nil
}
