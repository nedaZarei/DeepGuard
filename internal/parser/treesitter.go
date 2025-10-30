package parser

import (
	"fmt"
	"sync"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/java"
	"github.com/smacker/go-tree-sitter/javascript"
	"github.com/smacker/go-tree-sitter/python"
	"github.com/smacker/go-tree-sitter/typescript/typescript"
	"github.com/rs/zerolog/log"
)

// Parser interface defines the contract for parsing source code into ASTs
type Parser interface {
	Parse(content []byte, language string) (*sitter.Tree, error)
}

// TreeSitterParser implements the Parser interface using Tree-sitter
type TreeSitterParser struct {
	parsers map[string]*sitter.Parser
	mu      sync.Mutex
}

// NewTreeSitterParser creates a new Tree-sitter parser with language-specific parsers
func NewTreeSitterParser() (*TreeSitterParser, error) {
	p := &TreeSitterParser{
		parsers: make(map[string]*sitter.Parser),
	}

	// Initialize parsers for each language
	languages := map[string]*sitter.Language{
		"javascript": javascript.GetLanguage(),
		"typescript": typescript.GetLanguage(),
		"python":     python.GetLanguage(),
		"java":       java.GetLanguage(),
	}

	for lang, grammar := range languages {
		parser := sitter.NewParser()
		parser.SetLanguage(grammar)
		p.parsers[lang] = parser

		log.Debug().
			Str("component", "parser").
			Str("language", lang).
			Msg("Initialized Tree-sitter parser")
	}

	return p, nil
}

// Parse parses source code content using the appropriate language parser
// The caller is responsible for calling tree.Close() after use to prevent memory leaks
func (p *TreeSitterParser) Parse(content []byte, language string) (*sitter.Tree, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Get the appropriate parser for the language
	parser, ok := p.parsers[language]
	if !ok {
		return nil, fmt.Errorf("unsupported language: %s", language)
	}

	log.Debug().
		Str("component", "parser").
		Str("language", language).
		Int("content_size", len(content)).
		Msg("Parsing code with Tree-sitter")

	// Parse the content
	tree := parser.Parse(nil, content)
	if tree == nil {
		return nil, fmt.Errorf("failed to parse %s code: parser returned nil", language)
	}

	// Check for syntax errors in the AST
	if tree.RootNode().HasError() {
		errorInfo := findFirstError(tree.RootNode(), content)
		tree.Close() // Clean up before returning error
		return nil, fmt.Errorf("syntax error at %s", errorInfo)
	}

	return tree, nil
}

// findFirstError traverses the AST to find the first error node and returns its location
func findFirstError(node *sitter.Node, content []byte) string {
	if node.IsError() || node.IsMissing() {
		startPoint := node.StartPoint()

		// Extract the problematic code snippet
		startByte := node.StartByte()
		endByte := node.EndByte()

		snippet := ""
		if startByte < uint32(len(content)) && endByte <= uint32(len(content)) {
			snippetBytes := content[startByte:endByte]
			if len(snippetBytes) > 50 {
				snippet = string(snippetBytes[:50]) + "..."
			} else {
				snippet = string(snippetBytes)
			}
		}

		return fmt.Sprintf("line %d, column %d: '%s'",
			startPoint.Row+1, startPoint.Column+1, snippet)
	}

	// Recursively check children
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if errorInfo := findFirstError(child, content); errorInfo != "" {
			return errorInfo
		}
	}

	return ""
}

// Close releases all parser resources
func (p *TreeSitterParser) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for lang, parser := range p.parsers {
		parser.Close()
		log.Debug().
			Str("component", "parser").
			Str("language", lang).
			Msg("Closed Tree-sitter parser")
	}
}
