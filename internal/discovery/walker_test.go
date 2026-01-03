package discovery

import (
	"os"
	"path/filepath"
	"testing"
)

// setupTestDirectory creates a temporary directory structure for testing
func setupTestDirectory(t *testing.T) string {
	tmpDir := t.TempDir()

	// Create directory structure with various file types
	dirs := []string{
		"src",
		"src/components",
		"src/__tests__",
		"tests",
		"node_modules",
		"node_modules/library",
		"dist",
		"vendor",
		".git",
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(filepath.Join(tmpDir, dir), 0755); err != nil {
			t.Fatalf("Failed to create dir %s: %v", dir, err)
		}
	}

	// Create test files
	files := map[string]string{
		"src/main.js":                   "console.log('main');",
		"src/app.ts":                    "const app = 'hello';",
		"src/utils.py":                  "def hello(): pass",
		"src/Main.java":                 "public class Main {}",
		"src/components/button.js":      "export const Button = () => {};",
		"src/components/button.test.js": "test('button', () => {});",
		"src/__tests__/app.test.ts":     "describe('app', () => {});",
		"tests/integration.spec.js":     "it('works', () => {});",
		"tests/helper.py":               "# test helper",
		"src/bundle.min.js":             "/* minified */",
		"dist/output.js":                "// compiled output",
		"node_modules/library/index.js": "module.exports = {};",
		"vendor/lib.py":                 "# vendor code",
		".git/config":                   "[core]",
	}

	for path, content := range files {
		fullPath := filepath.Join(tmpDir, path)
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create file %s: %v", path, err)
		}
	}

	return tmpDir
}

func TestDiscoverFiles_Basic(t *testing.T) {
	tmpDir := setupTestDirectory(t)

	config := WalkerConfig{
		RootPath:       tmpDir,
		Languages:      []string{"javascript", "typescript", "python", "java"},
		FollowSymlinks: false,
	}

	result, err := DiscoverFiles(config)
	if err != nil {
		t.Fatalf("DiscoverFiles failed: %v", err)
	}

	// Should find files in src/ and tests/, but not node_modules/, dist/, vendor/, .git/
	// Expected files: main.js, app.ts, utils.py, Main.java, button.js, button.test.js, app.test.ts, integration.spec.js, helper.py
	// Excluded: bundle.min.js (default pattern), dist/, node_modules/, vendor/, .git/
	expectedMinFiles := 8 // Minimum expected (excluding .min.js and excluded dirs)

	if result.TotalFiles < expectedMinFiles {
		t.Errorf("Expected at least %d files, got %d", expectedMinFiles, result.TotalFiles)
	}

	// Verify no files from excluded directories
	for _, file := range result.Files {
		if filepath.HasPrefix(file.Path, "node_modules") ||
			filepath.HasPrefix(file.Path, "dist") ||
			filepath.HasPrefix(file.Path, "vendor") ||
			filepath.HasPrefix(file.Path, ".git") {
			t.Errorf("Found file in excluded directory: %s", file.Path)
		}
	}

	// Verify .min.js files are excluded
	for _, file := range result.Files {
		if filepath.Ext(file.Path) == ".js" && filepath.Base(file.Path) == "bundle.min.js" {
			t.Errorf("Found excluded .min.js file: %s", file.Path)
		}
	}
}

func TestDiscoverFiles_LanguageFiltering(t *testing.T) {
	tmpDir := setupTestDirectory(t)

	// Only discover JavaScript files
	config := WalkerConfig{
		RootPath:  tmpDir,
		Languages: []string{"javascript"},
	}

	result, err := DiscoverFiles(config)
	if err != nil {
		t.Fatalf("DiscoverFiles failed: %v", err)
	}

	// Verify only JavaScript files
	for _, file := range result.Files {
		if file.Language != "javascript" {
			t.Errorf("Expected only javascript files, found: %s (%s)", file.Path, file.Language)
		}
	}

	// Verify count
	if result.CountsByLanguage["javascript"] != result.TotalFiles {
		t.Errorf("JavaScript count mismatch: %d vs total %d",
			result.CountsByLanguage["javascript"], result.TotalFiles)
	}
}

func TestDiscoverFiles_TestDetection(t *testing.T) {
	tmpDir := setupTestDirectory(t)

	config := WalkerConfig{
		RootPath:  tmpDir,
		Languages: []string{"javascript", "typescript", "python"},
	}

	result, err := DiscoverFiles(config)
	if err != nil {
		t.Fatalf("DiscoverFiles failed: %v", err)
	}

	// Check that test files are detected
	testFiles := []string{
		filepath.Join("src", "components", "button.test.js"),
		filepath.Join("src", "__tests__", "app.test.ts"),
		filepath.Join("tests", "integration.spec.js"),
		filepath.Join("tests", "helper.py"), // in tests/ directory
	}

	foundTestFiles := 0
	for _, file := range result.Files {
		normalizedPath := filepath.ToSlash(file.Path)
		for _, expectedTest := range testFiles {
			expectedNormalized := filepath.ToSlash(expectedTest)
			if normalizedPath == expectedNormalized || filepath.Base(normalizedPath) == filepath.Base(expectedNormalized) {
				if !file.IsTest {
					t.Errorf("File %s should be marked as test file", file.Path)
				}
				foundTestFiles++
			}
		}
	}

	if foundTestFiles == 0 {
		t.Error("No test files detected")
	}

	// Verify non-test files are not marked as tests
	nonTestFiles := []string{"main.js", "app.ts", "utils.py", "Main.java"}
	for _, file := range result.Files {
		base := filepath.Base(file.Path)
		for _, nonTest := range nonTestFiles {
			if base == nonTest && file.IsTest {
				t.Errorf("File %s should not be marked as test file", file.Path)
			}
		}
	}
}

func TestGetLanguageFromPath(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"file.js", "javascript"},
		{"file.ts", "typescript"},
		{"file.py", "python"},
		{"file.java", "java"},
		{"file.JS", "javascript"}, // Case insensitive
		{"file.txt", ""},          // Unsupported
		{"file", ""},              // No extension
		{"path/to/file.js", "javascript"},
	}

	for _, tt := range tests {
		result := getLanguageFromPath(tt.path)
		if result != tt.expected {
			t.Errorf("getLanguageFromPath(%q) = %q, want %q", tt.path, result, tt.expected)
		}
	}
}

func TestIsTestFile(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		// Test filenames
		{"file.test.js", true},
		{"file.spec.ts", true},
		{"file_test.py", true},
		{"test_file.py", true},
		{"fileTest.java", true},

		// Test directories
		{"tests/file.js", true},
		{"__tests__/file.ts", true},
		{"src/__tests__/file.js", true},
		{"test/unit.py", true},

		// Non-test files
		{"file.js", false},
		{"main.py", false},
		{"testimony.js", false}, // Contains "test" but not a test file pattern
		{"src/components/button.js", false},
	}

	for _, tt := range tests {
		result := isTestFile(tt.path)
		if result != tt.expected {
			t.Errorf("isTestFile(%q) = %v, want %v", tt.path, result, tt.expected)
		}
	}
}

func TestFilter_DefaultExclusions(t *testing.T) {
	tmpDir := t.TempDir()

	filter, err := NewFilter(tmpDir, "")
	if err != nil {
		t.Fatalf("NewFilter failed: %v", err)
	}

	tests := []struct {
		path          string
		isDir         bool
		shouldExclude bool
	}{
		{"node_modules", true, true},
		{"node_modules/lib", true, true},
		{"vendor", true, true},
		{".git", true, true},
		{"dist", true, true},
		{"build", true, true},
		{"__pycache__", true, true},
		{"bundle.min.js", false, true},
		{"app.min.js", false, true},
		{"src", true, false},
		{"src/main.js", false, false},
		{"app.js", false, false},
	}

	for _, tt := range tests {
		result := filter.ShouldExclude(tt.path, tt.isDir)
		if result != tt.shouldExclude {
			t.Errorf("ShouldExclude(%q, %v) = %v, want %v",
				tt.path, tt.isDir, result, tt.shouldExclude)
		}
	}
}

func TestFilter_CustomIgnoreFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create custom .deepguardignore
	ignoreContent := `# Custom ignore patterns
coverage/
*.log
temp
`
	ignoreFile := filepath.Join(tmpDir, ".deepguardignore")
	if err := os.WriteFile(ignoreFile, []byte(ignoreContent), 0644); err != nil {
		t.Fatalf("Failed to create ignore file: %v", err)
	}

	filter, err := NewFilter(tmpDir, ignoreFile)
	if err != nil {
		t.Fatalf("NewFilter failed: %v", err)
	}

	// Test custom patterns
	tests := []struct {
		path          string
		isDir         bool
		shouldExclude bool
	}{
		// Custom patterns
		{"coverage", true, true},
		{"coverage/report.html", false, true},
		{"debug.log", false, true},
		{"error.log", false, true},
		{"temp", true, true},

		// Default patterns should still work
		{"node_modules", true, true},
		{"bundle.min.js", false, true},

		// Non-excluded
		{"src/main.js", false, false},
		{"app.js", false, false},
	}

	for _, tt := range tests {
		result := filter.ShouldExclude(tt.path, tt.isDir)
		if result != tt.shouldExclude {
			t.Errorf("ShouldExclude(%q, %v) = %v, want %v",
				tt.path, tt.isDir, result, tt.shouldExclude)
		}
	}
}

func TestDiscoverFiles_WithIgnoreFile(t *testing.T) {
	tmpDir := setupTestDirectory(t)

	// Create .deepguardignore to exclude tests
	ignoreContent := `tests/
*test*
*spec*
`
	ignoreFile := filepath.Join(tmpDir, ".deepguardignore")
	if err := os.WriteFile(ignoreFile, []byte(ignoreContent), 0644); err != nil {
		t.Fatalf("Failed to create ignore file: %v", err)
	}

	config := WalkerConfig{
		RootPath:   tmpDir,
		Languages:  []string{"javascript", "typescript", "python", "java"},
		IgnoreFile: ignoreFile,
	}

	result, err := DiscoverFiles(config)
	if err != nil {
		t.Fatalf("DiscoverFiles failed: %v", err)
	}

	// Verify no test files were discovered
	for _, file := range result.Files {
		if file.IsTest {
			t.Errorf("Found test file despite ignore patterns: %s", file.Path)
		}
		if filepath.HasPrefix(file.Path, "tests") {
			t.Errorf("Found file in tests/ directory: %s", file.Path)
		}
	}
}

func TestDiscoverFiles_EmptyDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	config := WalkerConfig{
		RootPath:  tmpDir,
		Languages: []string{"javascript"},
	}

	result, err := DiscoverFiles(config)
	if err != nil {
		t.Fatalf("DiscoverFiles failed: %v", err)
	}

	if result.TotalFiles != 0 {
		t.Errorf("Expected 0 files in empty directory, got %d", result.TotalFiles)
	}
}

func TestDiscoverFiles_CountsByLanguage(t *testing.T) {
	tmpDir := setupTestDirectory(t)

	config := WalkerConfig{
		RootPath:  tmpDir,
		Languages: []string{"javascript", "typescript", "python", "java"},
	}

	result, err := DiscoverFiles(config)
	if err != nil {
		t.Fatalf("DiscoverFiles failed: %v", err)
	}

	// Verify counts
	totalFromCounts := 0
	for _, count := range result.CountsByLanguage {
		totalFromCounts += count
	}

	if totalFromCounts != result.TotalFiles {
		t.Errorf("Sum of language counts (%d) != TotalFiles (%d)",
			totalFromCounts, result.TotalFiles)
	}

	// Verify we found files for multiple languages
	if len(result.CountsByLanguage) == 0 {
		t.Error("Expected files for at least one language")
	}
}
