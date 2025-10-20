package chunker

import (
	"regexp"
	"strings"
)

// normalizeSource normalizes source code for consistent hashing
// This ensures that minor formatting changes don't affect the chunk ID
func normalizeSource(source string, language string) string {
	// Step 1: Normalize line endings
	source = strings.ReplaceAll(source, "\r\n", "\n")
	source = strings.ReplaceAll(source, "\r", "\n")

	// Step 2: Remove comments (language-specific)
	source = removeComments(source, language)

	// Step 3: Normalize whitespace
	source = normalizeWhitespace(source)

	// Step 4: Remove trailing whitespace from each line
	lines := strings.Split(source, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " \t")
	}
	source = strings.Join(lines, "\n")

	// Step 5: Remove leading and trailing empty lines
	source = strings.TrimSpace(source)

	return source
}

// removeComments removes comments from source code based on language
func removeComments(source string, language string) string {
	switch language {
	case "javascript", "typescript", "java":
		return removeJavaStyleComments(source)
	case "python":
		return removePythonComments(source)
	default:
		return source
	}
}

// removeJavaStyleComments removes // and /* */ style comments
func removeJavaStyleComments(source string) string {
	// Remove multi-line comments /* ... */
	multiLineComment := regexp.MustCompile(`(?s)/\*.*?\*/`)
	source = multiLineComment.ReplaceAllString(source, "")

	// Remove single-line comments //
	singleLineComment := regexp.MustCompile(`//.*`)
	source = singleLineComment.ReplaceAllString(source, "")

	return source
}

// removePythonComments removes # comments and """ docstrings
func removePythonComments(source string) string {
	// Remove docstrings (triple quotes)
	tripleDoubleQuote := regexp.MustCompile(`(?s)""".*?"""`)
	source = tripleDoubleQuote.ReplaceAllString(source, "")

	tripleSingleQuote := regexp.MustCompile(`(?s)'''.*?'''`)
	source = tripleSingleQuote.ReplaceAllString(source, "")

	// Remove single-line comments #
	singleLineComment := regexp.MustCompile(`#.*`)
	source = singleLineComment.ReplaceAllString(source, "")

	return source
}

// normalizeWhitespace normalizes whitespace while preserving code structure
func normalizeWhitespace(source string) string {
	// Collapse multiple consecutive blank lines into one
	multipleNewlines := regexp.MustCompile(`\n{3,}`)
	source = multipleNewlines.ReplaceAllString(source, "\n\n")

	// Normalize spaces around operators (simplified for v1)
	// This is conservative to avoid breaking string literals
	// We only normalize common patterns

	// Normalize spaces around = (but not ==, !=, ===, !==, >=, <=)
	source = regexp.MustCompile(`([^=!><])\s*=\s*([^=])`).ReplaceAllString(source, "$1 = $2")

	// Normalize spaces around + - * / % (arithmetic operators)
	source = regexp.MustCompile(`\s*([+\-*/%])\s*`).ReplaceAllString(source, " $1 ")

	// Remove extra spaces (collapse multiple spaces into one)
	multipleSpaces := regexp.MustCompile(`[ \t]+`)
	source = multipleSpaces.ReplaceAllString(source, " ")

	return source
}

// NormalizeLanguageName converts short language names to canonical forms
func NormalizeLanguageName(lang string) string {
	switch strings.ToLower(lang) {
	case "js":
		return "javascript"
	case "ts":
		return "typescript"
	case "py":
		return "python"
	default:
		return strings.ToLower(lang)
	}
}
