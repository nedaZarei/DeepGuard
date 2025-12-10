package redactor

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/rs/zerolog"
)

// RedactionEvent represents a single redaction operation
type RedactionEvent struct {
	File         string     `json:"file"`
	Line         int        `json:"line"`
	Type         SecretType `json:"type"`
	Description  string     `json:"description"`
	OriginalLength int      `json:"original_length"`
}

// RedactionResult contains the redacted source and metadata
type RedactionResult struct {
	RedactedSource string           `json:"redacted_source"`
	Events         []RedactionEvent `json:"events"`
	TotalRedactions int             `json:"total_redactions"`
}

// Redactor handles sensitive data redaction in source code
type Redactor struct {
	patterns []Pattern
	logger   zerolog.Logger
}

// New creates a new Redactor instance
func New(log zerolog.Logger) *Redactor {
	return &Redactor{
		patterns: GetPatterns(),
		logger:   log,
	}
}

// Redact scans source code for sensitive data and replaces it with placeholders
// Language parameter helps avoid false positives in comments
func (r *Redactor) Redact(source string, language string, filePath string) RedactionResult {
	result := RedactionResult{
		RedactedSource: source,
		Events:         []RedactionEvent{},
		TotalRedactions: 0,
	}

	// Remove comments to avoid false positives in documentation
	sourceWithoutComments := r.removeComments(source, language)

	// Track line numbers for each character in original source
	lineMap := r.buildLineMap(source)

	// Apply each pattern
	for _, pattern := range r.patterns {
		matches := pattern.Regex.FindAllStringSubmatchIndex(sourceWithoutComments, -1)

		for _, match := range matches {
			// match[0] is start index, match[1] is end index of full match
			if len(match) < 2 {
				continue
			}

			startIdx := match[0]
			endIdx := match[1]

			// Extract matched text
			matchedText := sourceWithoutComments[startIdx:endIdx]

			// Skip if likely a false positive
			if IsLikelyFalsePositive(matchedText) {
				continue
			}

			// Skip if already redacted
			if strings.Contains(matchedText, "[REDACTED_") {
				continue
			}

				// Redact the entire matched text
			// This is simpler and more robust than trying to parse capture groups
			originalValue := matchedText
			redactStartIdx := startIdx
			redactEndIdx := endIdx

			// Skip very short matches (likely false positives)
			if len(originalValue) < 8 {
				continue
			}

			// Get line number
			lineNum := lineMap[redactStartIdx]

			// Perform redaction in the result string
			before := result.RedactedSource[:redactStartIdx]
			after := result.RedactedSource[redactEndIdx:]
			result.RedactedSource = before + pattern.Placeholder + after

			// Update sourceWithoutComments for subsequent matches
			beforeComment := sourceWithoutComments[:redactStartIdx]
			afterComment := sourceWithoutComments[redactEndIdx:]
			sourceWithoutComments = beforeComment + pattern.Placeholder + afterComment

			// Record event
			event := RedactionEvent{
				File:           filePath,
				Line:           lineNum,
				Type:           pattern.Type,
				Description:    pattern.Description,
				OriginalLength: len(originalValue),
			}

			result.Events = append(result.Events, event)
			result.TotalRedactions++

			// Log redaction
			r.logger.Info().
				Str("component", "redactor").
				Str("file", filePath).
				Int("line", lineNum).
				Str("type", string(pattern.Type)).
				Int("length", len(originalValue)).
				Msg("Redacted sensitive data")
		}
	}

	return result
}

// removeComments removes comments from source code to reduce false positives
func (r *Redactor) removeComments(source string, language string) string {
	switch language {
	case "javascript", "typescript", "java":
		return r.removeJSStyleComments(source)
	case "python":
		return r.removePythonComments(source)
	default:
		// If language unknown, keep original to avoid breaking code
		return source
	}
}

// removeJSStyleComments removes // and /* */ comments
func (r *Redactor) removeJSStyleComments(source string) string {
	// Remove single-line comments: // comment
	singleLinePattern := regexp.MustCompile(`//[^\n]*`)
	source = singleLinePattern.ReplaceAllString(source, "")

	// Remove multi-line comments: /* comment */
	multiLinePattern := regexp.MustCompile(`/\*[\s\S]*?\*/`)
	source = multiLinePattern.ReplaceAllString(source, "")

	return source
}

// removePythonComments removes # comments and docstrings
func (r *Redactor) removePythonComments(source string) string {
	// Remove single-line comments: # comment
	singleLinePattern := regexp.MustCompile(`#[^\n]*`)
	source = singleLinePattern.ReplaceAllString(source, "")

	// Remove docstrings: """...""" or '''...'''
	tripleQuotePattern := regexp.MustCompile(`("""[\s\S]*?"""|'''[\s\S]*?''')`)
	source = tripleQuotePattern.ReplaceAllString(source, "")

	return source
}

// buildLineMap creates a map from character index to line number
func (r *Redactor) buildLineMap(source string) map[int]int {
	lineMap := make(map[int]int)
	lineNum := 1

	for i := 0; i < len(source); i++ {
		lineMap[i] = lineNum
		if source[i] == '\n' {
			lineNum++
		}
	}

	return lineMap
}

// RedactChunk is a convenience method for redacting code chunks
func (r *Redactor) RedactChunk(source string, language string, filePath string, startLine int) RedactionResult {
	result := r.Redact(source, language, filePath)

	// Adjust line numbers relative to chunk start
	for i := range result.Events {
		result.Events[i].Line += startLine - 1
	}

	return result
}

// FormatRedactionSummary returns a human-readable summary of redactions
func FormatRedactionSummary(events []RedactionEvent) string {
	if len(events) == 0 {
		return "No sensitive data redacted"
	}

	typeCounts := make(map[SecretType]int)
	for _, event := range events {
		typeCounts[event.Type]++
	}

	var summary strings.Builder
	summary.WriteString(fmt.Sprintf("Redacted %d sensitive items:\n", len(events)))

	for secretType, count := range typeCounts {
		summary.WriteString(fmt.Sprintf("  - %s: %d\n", secretType, count))
	}

	return summary.String()
}
