package discovery

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// FileInfo represents a discovered source file with its metadata
type FileInfo struct {
	// Path is the relative path from the scan root
	Path string

	// Language identifies the programming language (javascript, typescript, python, java)
	Language string

	// IsTest indicates whether this file matches test file patterns
	IsTest bool
}

// DiscoveryResult contains the results of a file discovery operation
type DiscoveryResult struct {
	// Files is the list of discovered source files
	Files []FileInfo

	// CountsByLanguage maps language names to file counts
	CountsByLanguage map[string]int

	// TotalFiles is the total number of discovered files
	TotalFiles int

	// TotalTestFiles is the number of test files discovered
	TotalTestFiles int

	// SkippedFiles is the number of files skipped due to exclusion patterns
	SkippedFiles int

	// Duration is the time taken for discovery
	Duration time.Duration
}

// WalkerConfig configures the file discovery walker
type WalkerConfig struct {
	// RootPath is the directory to start scanning from
	RootPath string

	// Languages is the list of languages to discover (filters by extension)
	Languages []string

	// IgnoreFile is the path to .deepguardignore (optional)
	IgnoreFile string

	// FollowSymlinks determines whether to follow symbolic links (default: false)
	FollowSymlinks bool
}

// DiscoverFiles walks the directory tree and discovers all relevant source files
func DiscoverFiles(config WalkerConfig) (*DiscoveryResult, error) {
	start := time.Now()

	log.Info().
		Str("component", "discovery").
		Str("operation", "discover_start").
		Str("path", config.RootPath).
		Strs("languages", config.Languages).
		Msg("Starting file discovery")

	// Initialize result
	result := &DiscoveryResult{
		Files:            []FileInfo{},
		CountsByLanguage: make(map[string]int),
	}

	// Load exclusion filters
	filter, err := NewFilter(config.RootPath, config.IgnoreFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create filter: %w", err)
	}

	// Build language filter set, normalizing language names
	langFilter := make(map[string]bool)
	for _, lang := range config.Languages {
		// Normalize language names to match what getLanguageFromPath returns
		normalized := normalizeLangName(strings.ToLower(lang))
		langFilter[normalized] = true
	}

	// Walk directory tree
	err = filepath.WalkDir(config.RootPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Log permission errors but continue
			log.Warn().
				Err(err).
				Str("component", "discovery").
				Str("path", path).
				Msg("Error accessing path, skipping")
			return nil
		}

		// Get relative path from root
		relPath, err := filepath.Rel(config.RootPath, path)
		if err != nil {
			log.Warn().
				Err(err).
				Str("component", "discovery").
				Str("path", path).
				Msg("Failed to get relative path, skipping")
			return nil
		}

		// Handle directories
		if d.IsDir() {
			// Check if directory should be excluded
			if filter.ShouldExclude(relPath, true) {
				log.Debug().
					Str("component", "discovery").
					Str("path", relPath).
					Msg("Skipping excluded directory")
				return filepath.SkipDir
			}
			return nil
		}

		// Handle symlinks
		if !config.FollowSymlinks && isSymlink(d) {
			log.Debug().
				Str("component", "discovery").
				Str("path", relPath).
				Msg("Skipping symlink")
			result.SkippedFiles++
			return nil
		}

		// Check if file should be excluded
		if filter.ShouldExclude(relPath, false) {
			log.Debug().
				Str("component", "discovery").
				Str("path", relPath).
				Msg("Skipping excluded file")
			result.SkippedFiles++
			return nil
		}

		// Determine file language by extension
		language := getLanguageFromPath(relPath)
		if language == "" {
			// Not a supported language file
			return nil
		}

		// Filter by requested languages
		if len(langFilter) > 0 && !langFilter[language] {
			return nil
		}

		// Detect if this is a test file
		isTest := isTestFile(relPath)

		// Add to results
		fileInfo := FileInfo{
			Path:     relPath,
			Language: language,
			IsTest:   isTest,
		}
		result.Files = append(result.Files, fileInfo)
		result.CountsByLanguage[language]++
		result.TotalFiles++
		if isTest {
			result.TotalTestFiles++
		}

		log.Debug().
			Str("component", "discovery").
			Str("path", relPath).
			Str("language", language).
			Bool("is_test", isTest).
			Msg("Discovered file")

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error walking directory: %w", err)
	}

	result.Duration = time.Since(start)

	log.Info().
		Str("component", "discovery").
		Str("operation", "discover_complete").
		Int("total_files", result.TotalFiles).
		Int("test_files", result.TotalTestFiles).
		Int("skipped_files", result.SkippedFiles).
		Int64("duration_ms", result.Duration.Milliseconds()).
		Msg("File discovery completed")

	return result, nil
}

// normalizeLangName converts short language names to full names
// "js" -> "javascript", "ts" -> "typescript", etc.
func normalizeLangName(lang string) string {
	switch lang {
	case "js":
		return "javascript"
	case "ts":
		return "typescript"
	case "py", "python":
		return "python"
	case "java":
		return "java"
	default:
		return lang
	}
}

// getLanguageFromPath determines the programming language from file extension
func getLanguageFromPath(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".js":
		return "javascript"
	case ".ts":
		return "typescript"
	case ".py":
		return "python"
	case ".java":
		return "java"
	default:
		return ""
	}
}

// isTestFile detects if a file is a test file based on naming patterns
// Patterns: _test.|_spec.|.test.|.spec.|\btests?\b|__tests__
func isTestFile(path string) bool {
	// Normalize path separators for consistent matching
	normalizedPath := filepath.ToSlash(strings.ToLower(path))
	base := strings.ToLower(filepath.Base(path))

	// Remove extension for cleaner matching
	baseNoExt := strings.TrimSuffix(base, filepath.Ext(base))

	// Check filename patterns: .test., .spec., _test., _spec.
	if strings.Contains(base, ".test.") || strings.Contains(base, ".spec.") ||
		strings.Contains(base, "_test.") || strings.Contains(base, "_spec.") {
		return true
	}

	// Check if filename ends with test or spec (before extension)
	if strings.HasSuffix(baseNoExt, "test") || strings.HasSuffix(baseNoExt, "spec") ||
		strings.HasSuffix(baseNoExt, "_test") || strings.HasSuffix(baseNoExt, "_spec") {
		return true
	}

	// Check if filename starts with test_
	if strings.HasPrefix(baseNoExt, "test_") {
		return true
	}

	// Check directory patterns: tests/, __tests__/, test/
	if strings.Contains(normalizedPath, "/tests/") ||
		strings.Contains(normalizedPath, "/__tests__/") ||
		strings.Contains(normalizedPath, "/test/") {
		return true
	}

	// Check if path starts with tests/ or __tests__/
	if strings.HasPrefix(normalizedPath, "tests/") ||
		strings.HasPrefix(normalizedPath, "__tests__/") ||
		strings.HasPrefix(normalizedPath, "test/") {
		return true
	}

	return false
}

// isSymlink checks if a directory entry is a symbolic link
func isSymlink(d fs.DirEntry) bool {
	info, err := d.Info()
	if err != nil {
		return false
	}
	return info.Mode()&fs.ModeSymlink != 0
}
