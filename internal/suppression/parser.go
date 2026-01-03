package suppression

import (
	"regexp"
	"strings"
)

// SuppressionInfo represents a suppression comment found in code
type SuppressionInfo struct {
	Line          int    `json:"line"`          // Line number where suppression applies
	Type          string `json:"type"`          // "all" or specific type like "sql_injection"
	Justification string `json:"justification"` // Optional text after "-"
	AppliesTo     string `json:"applies_to"`    // "same" or "next"
	SourceLine    int    `json:"source_line"`   // Line where the comment appears
}

// Suppression comment patterns
var (
	// Same-line suppression: // deepguard:ignore [type] [- justification]
	sameLinePattern = regexp.MustCompile(`(?:^|[^a-zA-Z0-9_])deepguard:ignore(?:\s+([a-z_]+))?(?:\s*-\s*(.+))?`)

	// Next-line suppression: // deepguard:ignore-next-line [type] [- justification]
	nextLinePattern = regexp.MustCompile(`(?:^|[^a-zA-Z0-9_])deepguard:ignore-next-line(?:\s+([a-z_]+))?(?:\s*-\s*(.+))?`)
)

// CommentLocation represents a comment's position in source code
type CommentLocation struct {
	Line int
	Text string
}

// ParseComments extracts suppression directives from comment text
func ParseComments(comments []CommentLocation) []SuppressionInfo {
	var suppressions []SuppressionInfo

	for _, comment := range comments {
		// Check for next-line suppression first (more specific pattern)
		if matches := nextLinePattern.FindStringSubmatch(comment.Text); matches != nil {
			suppression := SuppressionInfo{
				Line:       comment.Line + 1, // Applies to next line
				Type:       extractType(matches[1]),
				AppliesTo:  "next",
				SourceLine: comment.Line,
			}

			// Extract justification if present
			if len(matches) > 2 && matches[2] != "" {
				suppression.Justification = strings.TrimSpace(matches[2])
			}

			suppressions = append(suppressions, suppression)
			continue
		}

		// Check for same-line suppression
		if matches := sameLinePattern.FindStringSubmatch(comment.Text); matches != nil {
			suppression := SuppressionInfo{
				Line:       comment.Line, // Applies to same line
				Type:       extractType(matches[1]),
				AppliesTo:  "same",
				SourceLine: comment.Line,
			}

			// Extract justification if present
			if len(matches) > 2 && matches[2] != "" {
				suppression.Justification = strings.TrimSpace(matches[2])
			}

			suppressions = append(suppressions, suppression)
		}
	}

	return suppressions
}

// extractType normalizes the vulnerability type or returns "all" if not specified
func extractType(typeStr string) string {
	typeStr = strings.TrimSpace(typeStr)
	if typeStr == "" {
		return "all"
	}
	return typeStr
}

// IsSuppressed checks if a finding at a given line and type should be suppressed
func IsSuppressed(line int, vulnType string, suppressions []SuppressionInfo) (bool, *SuppressionInfo) {
	for i := range suppressions {
		suppression := &suppressions[i]

		// Check if line matches
		if suppression.Line != line {
			continue
		}

		// Check if type matches (either "all" or specific type)
		if suppression.Type == "all" || suppression.Type == vulnType {
			return true, suppression
		}
	}

	return false, nil
}

// ExtractCommentsFromSource is a helper that language-specific parsers can use
// to build CommentLocation slices from their AST traversal
func ExtractCommentsFromSource(source string, language string) []CommentLocation {
	var comments []CommentLocation
	lines := strings.Split(source, "\n")

	// Simple fallback: scan for comment patterns in source
	// Tree-sitter integration will override this in chunker.go
	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		switch language {
		case "javascript", "typescript", "java":
			// Single-line comments
			if strings.HasPrefix(trimmed, "//") {
				comments = append(comments, CommentLocation{
					Line: lineNum,
					Text: trimmed,
				})
			}

		case "python":
			// Python comments
			if strings.HasPrefix(trimmed, "#") {
				comments = append(comments, CommentLocation{
					Line: lineNum,
					Text: trimmed,
				})
			}
		}
	}

	return comments
}
