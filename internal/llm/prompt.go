package llm

import (
	"bytes"
	"embed"
	"fmt"
	"strings"
	"text/template"

	"github.com/Neda-Zarei/deep-guard/internal/chunker"
	"github.com/Neda-Zarei/deep-guard/internal/kb"
)

//go:embed templates/*.tmpl
var templateFS embed.FS

// TemplateParams holds all parameters needed for prompt template rendering
type TemplateParams struct {
	// Frameworks detected in the file
	Frameworks []string
	// KBEntries from BM25 retrieval (k=3)
	KBEntries []FormattedKBEntry
	// FilePath of the code chunk
	FilePath string
	// LineStart of the code chunk (1-indexed)
	LineStart int
	// LineEnd of the code chunk (1-indexed)
	LineEnd int
	// FunctionName of the code chunk
	FunctionName string
	// Source code of the chunk
	Source string
	// VulnType is the vulnerability type for this template
	VulnType string
	// FrameworkHints are framework-specific hints for this vulnerability type
	FrameworkHints []string
}

// FormattedKBEntry represents a formatted KB entry for template rendering
type FormattedKBEntry struct {
	Title       string
	Description string
}

// PromptRenderer handles template loading and rendering
type PromptRenderer struct {
	templates map[VulnerabilityType]*template.Template
}

// NewPromptRenderer creates a new prompt renderer with all templates loaded
func NewPromptRenderer() (*PromptRenderer, error) {
	renderer := &PromptRenderer{
		templates: make(map[VulnerabilityType]*template.Template),
	}

	// Define template functions
	funcMap := template.FuncMap{
		"add": func(a, b int) int {
			return a + b
		},
	}

	// Load all templates
	vulnTypes := []VulnerabilityType{
		VulnTypeSQLInjection,
		VulnTypeXSS,
		VulnTypePathTraversal,
		VulnTypeInsecureDeserialization,
		VulnTypeAuthIssue,
		VulnTypeCryptoIssue,
	}

	for _, vulnType := range vulnTypes {
		templateName := getTemplateName(vulnType)
		templatePath := fmt.Sprintf("templates/%s.tmpl", templateName)

		tmpl, err := template.New(templateName + ".tmpl").Funcs(funcMap).ParseFS(templateFS, templatePath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse template %s: %w", templatePath, err)
		}

		renderer.templates[vulnType] = tmpl
	}

	return renderer, nil
}

// RenderPrompt renders a prompt for a specific vulnerability type with the given parameters
func (r *PromptRenderer) RenderPrompt(
	vulnType VulnerabilityType,
	chunk chunker.CodeChunk,
	kbEntries []kb.KBEntry,
) (string, error) {
	// Check if template exists
	tmpl, ok := r.templates[vulnType]
	if !ok {
		return "", fmt.Errorf("no template found for vulnerability type: %s", vulnType)
	}

	// Format KB entries (limit to 200 chars per entry)
	formattedKB := make([]FormattedKBEntry, 0, len(kbEntries))
	for _, entry := range kbEntries {
		formatted := FormattedKBEntry{
			Title:       entry.Title,
			Description: truncateString(entry.Description, 200),
		}
		formattedKB = append(formattedKB, formatted)
	}

	// Get framework-specific hints
	frameworkHints := GetAllFrameworkHints(chunk.Frameworks, vulnType)

	// Build template parameters
	params := TemplateParams{
		Frameworks:     chunk.Frameworks,
		KBEntries:      formattedKB,
		FilePath:       chunk.FilePath,
		LineStart:      chunk.StartLine,
		LineEnd:        chunk.EndLine,
		FunctionName:   chunk.FunctionName,
		Source:         chunk.Source,
		VulnType:       string(vulnType),
		FrameworkHints: frameworkHints,
	}

	// Render template
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, params); err != nil {
		return "", fmt.Errorf("failed to render template for %s: %w", vulnType, err)
	}

	return buf.String(), nil
}

// getTemplateName maps vulnerability type to template filename
func getTemplateName(vulnType VulnerabilityType) string {
	switch vulnType {
	case VulnTypeSQLInjection:
		return "sqli"
	case VulnTypeXSS:
		return "xss"
	case VulnTypePathTraversal:
		return "path_traversal"
	case VulnTypeInsecureDeserialization:
		return "insecure_deser"
	case VulnTypeAuthIssue:
		return "auth"
	case VulnTypeCryptoIssue:
		return "crypto"
	default:
		return "unknown"
	}
}

// truncateString truncates a string to maxLen characters
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// FormatFrameworks formats framework list for template display
func FormatFrameworks(frameworks []string) string {
	if len(frameworks) == 0 {
		return "No frameworks detected"
	}
	return strings.Join(frameworks, ", ")
}
