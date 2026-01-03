package chunker

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/Neda-Zarei/deep-guard/internal/suppression"
	sitter "github.com/smacker/go-tree-sitter"
)

// CodeChunk represents a parsed function or method extracted from source code
type CodeChunk struct {
	ID              string                        // SHA256 hash of normalized source
	FilePath        string                        // Absolute file path
	StartLine       int                           // 1-indexed start line
	EndLine         int                           // 1-indexed end line
	FunctionName    string                        // Function/method name
	Language        string                        // Programming language (javascript, python, java, typescript)
	Source          string                        // Original source code
	Tokens          int                           // Estimated token count (len/4)
	Frameworks      []string                      // Detected frameworks for this file
	NormalizedSrc   string                        // Normalized source for hashing
	SuppressedLines []suppression.SuppressionInfo // Suppression directives found in this chunk
}

// Chunker extracts code chunks from parsed ASTs
type Chunker interface {
	// ChunkFile extracts all functions/methods from a parsed AST
	ChunkFile(tree *sitter.Tree, content []byte, filePath string, language string, frameworks []string) ([]CodeChunk, error)
}

// ASTChunker implements the Chunker interface using Tree-sitter
type ASTChunker struct {
	maxTokens int // Maximum tokens per chunk before splitting (default: 600)
}

// NewASTChunker creates a new AST-based chunker
func NewASTChunker(maxTokens int) *ASTChunker {
	if maxTokens <= 0 {
		maxTokens = 600 // Default max tokens
	}
	return &ASTChunker{
		maxTokens: maxTokens,
	}
}

// ChunkFile extracts all functions/methods from a parsed AST
func (c *ASTChunker) ChunkFile(tree *sitter.Tree, content []byte, filePath string, language string, frameworks []string) ([]CodeChunk, error) {
	if tree == nil {
		return nil, fmt.Errorf("tree cannot be nil")
	}

	rootNode := tree.RootNode()
	if rootNode == nil {
		return nil, fmt.Errorf("tree has no root node")
	}

	var chunks []CodeChunk

	// Extract comments and parse suppression directives
	comments := suppression.ExtractCommentsFromSource(string(content), language)
	allSuppressions := suppression.ParseComments(comments)

	// Extract function nodes based on language
	functionNodes := c.extractFunctionNodes(rootNode, language)

	for _, node := range functionNodes {
		// Extract function name
		functionName := c.extractFunctionName(node, language, content)

		// Extract source code
		source := node.Content(content)
		startLine := int(node.StartPoint().Row) + 1 // Convert to 1-indexed
		endLine := int(node.EndPoint().Row) + 1

		// Normalize source for hashing
		normalized := normalizeSource(source, language)

		// Calculate hash
		hash := sha256.Sum256([]byte(normalized))
		id := hex.EncodeToString(hash[:])

		// Estimate tokens (rough heuristic: 1 token ≈ 4 characters)
		tokens := estimateTokens(source)

		// Filter suppressions that apply to this chunk's line range
		var chunkSuppressions []suppression.SuppressionInfo
		for _, sup := range allSuppressions {
			if sup.Line >= startLine && sup.Line <= endLine {
				chunkSuppressions = append(chunkSuppressions, sup)
			}
		}

		// Create chunk
		chunk := CodeChunk{
			ID:              id,
			FilePath:        filePath,
			StartLine:       startLine,
			EndLine:         endLine,
			FunctionName:    functionName,
			Language:        language,
			Source:          source,
			Tokens:          tokens,
			Frameworks:      frameworks,
			NormalizedSrc:   normalized,
			SuppressedLines: chunkSuppressions,
		}

		// Split large chunks if they exceed maxTokens
		if tokens > c.maxTokens {
			splitChunks := c.splitLargeChunk(chunk)
			chunks = append(chunks, splitChunks...)
		} else {
			chunks = append(chunks, chunk)
		}
	}

	return chunks, nil
}

// extractFunctionNodes extracts all function/method nodes from the AST
func (c *ASTChunker) extractFunctionNodes(rootNode *sitter.Node, language string) []*sitter.Node {
	var nodes []*sitter.Node

	// Language-specific node types for functions/methods
	var functionTypes []string
	switch language {
	case "javascript", "typescript":
		functionTypes = []string{
			"function_declaration",
			"function",
			"arrow_function",
			"method_definition",
			"function_expression",
		}
	case "python":
		functionTypes = []string{
			"function_definition",
		}
	case "java":
		functionTypes = []string{
			"method_declaration",
			"constructor_declaration",
		}
	default:
		return nodes
	}

	// Traverse the AST using cursor
	cursor := sitter.NewTreeCursor(rootNode)
	defer cursor.Close()

	c.traverseForFunctions(cursor, functionTypes, &nodes)

	return nodes
}

// traverseForFunctions recursively traverses the AST to find function nodes
func (c *ASTChunker) traverseForFunctions(cursor *sitter.TreeCursor, functionTypes []string, nodes *[]*sitter.Node) {
	node := cursor.CurrentNode()

	// Check if current node is a function type
	nodeType := node.Type()
	for _, ft := range functionTypes {
		if nodeType == ft {
			*nodes = append(*nodes, node)
			// Don't traverse children of function nodes (avoid nested functions for now)
			return
		}
	}

	// Traverse children
	if cursor.GoToFirstChild() {
		c.traverseForFunctions(cursor, functionTypes, nodes)
		cursor.GoToParent()
	}

	// Traverse siblings
	if cursor.GoToNextSibling() {
		c.traverseForFunctions(cursor, functionTypes, nodes)
	}
}

// extractFunctionName extracts the function/method name from a node
func (c *ASTChunker) extractFunctionName(node *sitter.Node, language string, content []byte) string {
	switch language {
	case "javascript", "typescript":
		return c.extractJSFunctionName(node, content)
	case "python":
		return c.extractPythonFunctionName(node, content)
	case "java":
		return c.extractJavaFunctionName(node, content)
	default:
		return "unknown"
	}
}

// extractJSFunctionName extracts function name from JavaScript/TypeScript node
func (c *ASTChunker) extractJSFunctionName(node *sitter.Node, content []byte) string {
	nodeType := node.Type()

	// Function declaration: look for identifier child
	if nodeType == "function_declaration" || nodeType == "function_expression" {
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child.Type() == "identifier" {
				return child.Content(content)
			}
		}
	}

	// Method definition: look for property_identifier
	if nodeType == "method_definition" {
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child.Type() == "property_identifier" {
				return child.Content(content)
			}
		}
	}

	// Arrow function: try to get name from parent assignment
	if nodeType == "arrow_function" {
		parent := node.Parent()
		if parent != nil && parent.Type() == "variable_declarator" {
			for i := 0; i < int(parent.ChildCount()); i++ {
				child := parent.Child(i)
				if child.Type() == "identifier" {
					return child.Content(content)
				}
			}
		}
	}

	return "anonymous"
}

// extractPythonFunctionName extracts function name from Python node
func (c *ASTChunker) extractPythonFunctionName(node *sitter.Node, content []byte) string {
	// function_definition has an identifier child
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == "identifier" {
			return child.Content(content)
		}
	}
	return "unknown"
}

// extractJavaFunctionName extracts method name from Java node
func (c *ASTChunker) extractJavaFunctionName(node *sitter.Node, content []byte) string {
	// method_declaration and constructor_declaration have identifier child
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == "identifier" {
			return child.Content(content)
		}
	}
	return "unknown"
}

// splitLargeChunk splits a large chunk into smaller chunks
func (c *ASTChunker) splitLargeChunk(chunk CodeChunk) []CodeChunk {
	// For now, we'll split by statement boundaries
	// This is a simple line-based split for v1
	lines := strings.Split(chunk.Source, "\n")

	if len(lines) <= 1 {
		// Can't split further
		return []CodeChunk{chunk}
	}

	var chunks []CodeChunk
	var currentLines []string
	currentTokens := 0
	partNum := 1

	for _, line := range lines {
		lineTokens := estimateTokens(line)

		if currentTokens+lineTokens > c.maxTokens && len(currentLines) > 0 {
			// Create chunk from accumulated lines
			partSource := strings.Join(currentLines, "\n")
			normalized := normalizeSource(partSource, chunk.Language)
			hash := sha256.Sum256([]byte(normalized))

			// Filter suppressions for this part's line range
			partStartLine := chunk.StartLine
			partEndLine := chunk.StartLine + len(currentLines) - 1
			var partSuppressions []suppression.SuppressionInfo
			for _, sup := range chunk.SuppressedLines {
				if sup.Line >= partStartLine && sup.Line <= partEndLine {
					partSuppressions = append(partSuppressions, sup)
				}
			}

			partChunk := CodeChunk{
				ID:              hex.EncodeToString(hash[:]),
				FilePath:        chunk.FilePath,
				StartLine:       partStartLine,
				EndLine:         partEndLine,
				FunctionName:    fmt.Sprintf("%s_part%d", chunk.FunctionName, partNum),
				Language:        chunk.Language,
				Source:          partSource,
				Tokens:          currentTokens,
				Frameworks:      chunk.Frameworks,
				NormalizedSrc:   normalized,
				SuppressedLines: partSuppressions,
			}
			chunks = append(chunks, partChunk)

			// Reset for next part
			currentLines = []string{line}
			currentTokens = lineTokens
			partNum++
		} else {
			currentLines = append(currentLines, line)
			currentTokens += lineTokens
		}
	}

	// Add remaining lines
	if len(currentLines) > 0 {
		partSource := strings.Join(currentLines, "\n")
		normalized := normalizeSource(partSource, chunk.Language)
		hash := sha256.Sum256([]byte(normalized))

		// Filter suppressions for final part's line range
		partStartLine := chunk.StartLine + len(lines) - len(currentLines)
		partEndLine := chunk.EndLine
		var partSuppressions []suppression.SuppressionInfo
		for _, sup := range chunk.SuppressedLines {
			if sup.Line >= partStartLine && sup.Line <= partEndLine {
				partSuppressions = append(partSuppressions, sup)
			}
		}

		partChunk := CodeChunk{
			ID:              hex.EncodeToString(hash[:]),
			FilePath:        chunk.FilePath,
			StartLine:       partStartLine,
			EndLine:         partEndLine,
			FunctionName:    fmt.Sprintf("%s_part%d", chunk.FunctionName, partNum),
			Language:        chunk.Language,
			Source:          partSource,
			Tokens:          currentTokens,
			Frameworks:      chunk.Frameworks,
			NormalizedSrc:   normalized,
			SuppressedLines: partSuppressions,
		}
		chunks = append(chunks, partChunk)
	}

	return chunks
}

// estimateTokens estimates token count using the heuristic: 1 token ≈ 4 characters
func estimateTokens(source string) int {
	return len(source) / 4
}
