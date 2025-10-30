package chunker

import (
	"strings"
	"testing"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/javascript"
	"github.com/smacker/go-tree-sitter/python"
	"github.com/smacker/go-tree-sitter/java"
)

// TestNewASTChunker tests chunker initialization
func TestNewASTChunker(t *testing.T) {
	tests := []struct {
		name           string
		maxTokens      int
		expectedTokens int
	}{
		{"default max tokens", 0, 600},
		{"custom max tokens", 1000, 1000},
		{"negative max tokens (use default)", -100, 600},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chunker := NewASTChunker(tt.maxTokens)
			if chunker.maxTokens != tt.expectedTokens {
				t.Errorf("expected maxTokens=%d, got %d", tt.expectedTokens, chunker.maxTokens)
			}
		})
	}
}

// TestEstimateTokens tests token estimation
func TestEstimateTokens(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected int
	}{
		{"empty string", "", 0},
		{"4 characters", "test", 1},
		{"8 characters", "testtest", 2},
		{"100 characters", strings.Repeat("a", 100), 25},
		{"typical function", "function foo() { return 42; }", 7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := estimateTokens(tt.source)
			if tokens != tt.expected {
				t.Errorf("expected %d tokens, got %d", tt.expected, tokens)
			}
		})
	}
}

// TestNormalizeSource tests source normalization
func TestNormalizeSource(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		language string
		expected string
	}{
		{
			name:     "normalize line endings CRLF",
			source:   "line1\r\nline2\r\nline3",
			language: "javascript",
			expected: "line1\nline2\nline3",
		},
		{
			name:     "remove JS comments",
			source:   "// comment\nconst x = 1; // inline\n/* block */",
			language: "javascript",
			expected: "const x = 1;",
		},
		{
			name:     "remove Python comments",
			source:   "# comment\nx = 1  # inline\n'''docstring'''",
			language: "python",
			expected: "x = 1",
		},
		{
			name:     "normalize whitespace",
			source:   "x   =    1  +  2",
			language: "javascript",
			expected: "x = 1 + 2",
		},
		{
			name:     "collapse multiple blank lines",
			source:   "line1\n\n\n\nline2",
			language: "javascript",
			expected: "line1\n\nline2",
		},
		{
			name:     "trim trailing whitespace",
			source:   "line1   \nline2\t\t\n",
			language: "javascript",
			expected: "line1\nline2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			normalized := normalizeSource(tt.source, tt.language)
			if normalized != tt.expected {
				t.Errorf("expected:\n%q\ngot:\n%q", tt.expected, normalized)
			}
		})
	}
}

// TestNormalizeSource_HashStability tests that normalized source produces stable hashes
func TestNormalizeSource_HashStability(t *testing.T) {
	source1 := `function foo() {
		return 42; // comment
	}`

	source2 := `function foo()   {
		return   42;
	}` // Different whitespace, no comment

	norm1 := normalizeSource(source1, "javascript")
	norm2 := normalizeSource(source2, "javascript")

	if norm1 != norm2 {
		t.Errorf("normalized sources should be equal:\n%q\nvs\n%q", norm1, norm2)
	}
}

// TestChunkFile_JavaScript tests chunking of JavaScript code
func TestChunkFile_JavaScript(t *testing.T) {
	source := `
function add(a, b) {
	return a + b;
}

const multiply = (x, y) => {
	return x * y;
};

class Calculator {
	subtract(a, b) {
		return a - b;
	}
}
`

	parser := sitter.NewParser()
	parser.SetLanguage(javascript.GetLanguage())
	tree := parser.Parse(nil, []byte(source))
	defer tree.Close()

	chunker := NewASTChunker(600)
	chunks, err := chunker.ChunkFile(tree, []byte(source), "test.js", "javascript", []string{"express"})

	if err != nil {
		t.Fatalf("ChunkFile failed: %v", err)
	}

	// Should find 3 functions: add, multiply, subtract
	if len(chunks) != 3 {
		t.Errorf("expected 3 chunks, got %d", len(chunks))
	}

	// Verify function names
	expectedNames := map[string]bool{"add": false, "multiply": false, "subtract": false}
	for _, chunk := range chunks {
		if _, ok := expectedNames[chunk.FunctionName]; ok {
			expectedNames[chunk.FunctionName] = true
		}
	}

	for name, found := range expectedNames {
		if !found {
			t.Errorf("function '%s' not found in chunks", name)
		}
	}

	// Verify all chunks have IDs (SHA256 hashes)
	for _, chunk := range chunks {
		if len(chunk.ID) != 64 { // SHA256 hex is 64 characters
			t.Errorf("chunk '%s' has invalid ID length: %d", chunk.FunctionName, len(chunk.ID))
		}
	}

	// Verify frameworks are passed through
	for _, chunk := range chunks {
		if len(chunk.Frameworks) != 1 || chunk.Frameworks[0] != "express" {
			t.Errorf("chunk '%s' has incorrect frameworks: %v", chunk.FunctionName, chunk.Frameworks)
		}
	}
}

// TestChunkFile_Python tests chunking of Python code
func TestChunkFile_Python(t *testing.T) {
	source := `
def add(a, b):
	"""Add two numbers"""
	return a + b

def multiply(x, y):
	# Multiply two numbers
	return x * y

class Calculator:
	def subtract(self, a, b):
		return a - b
`

	parser := sitter.NewParser()
	parser.SetLanguage(python.GetLanguage())
	tree := parser.Parse(nil, []byte(source))
	defer tree.Close()

	chunker := NewASTChunker(600)
	chunks, err := chunker.ChunkFile(tree, []byte(source), "test.py", "python", []string{"django"})

	if err != nil {
		t.Fatalf("ChunkFile failed: %v", err)
	}

	// Should find 3 functions: add, multiply, subtract
	if len(chunks) != 3 {
		t.Errorf("expected 3 chunks, got %d", len(chunks))
	}

	// Verify function names
	expectedNames := map[string]bool{"add": false, "multiply": false, "subtract": false}
	for _, chunk := range chunks {
		if _, ok := expectedNames[chunk.FunctionName]; ok {
			expectedNames[chunk.FunctionName] = true
		}
	}

	for name, found := range expectedNames {
		if !found {
			t.Errorf("function '%s' not found in chunks", name)
		}
	}

	// Verify language
	for _, chunk := range chunks {
		if chunk.Language != "python" {
			t.Errorf("chunk '%s' has wrong language: %s", chunk.FunctionName, chunk.Language)
		}
	}
}

// TestChunkFile_Java tests chunking of Java code
func TestChunkFile_Java(t *testing.T) {
	source := `
public class Calculator {
	public int add(int a, int b) {
		return a + b;
	}

	public Calculator() {
		// Constructor
	}
}
`

	parser := sitter.NewParser()
	parser.SetLanguage(java.GetLanguage())
	tree := parser.Parse(nil, []byte(source))
	defer tree.Close()

	chunker := NewASTChunker(600)
	chunks, err := chunker.ChunkFile(tree, []byte(source), "Calculator.java", "java", []string{"spring-boot"})

	if err != nil {
		t.Fatalf("ChunkFile failed: %v", err)
	}

	// Should find 2 chunks: add method and constructor
	if len(chunks) != 2 {
		t.Errorf("expected 2 chunks, got %d", len(chunks))
	}

	// Verify we found both the method and constructor
	hasMethod := false
	hasConstructor := false
	for _, chunk := range chunks {
		if chunk.FunctionName == "add" {
			hasMethod = true
		}
		if chunk.FunctionName == "Calculator" {
			hasConstructor = true
		}
	}

	if !hasMethod {
		t.Error("method 'add' not found")
	}
	if !hasConstructor {
		t.Error("constructor 'Calculator' not found")
	}
}

// TestChunkFile_ChunkBoundaries tests that chunk line numbers are correct
func TestChunkFile_ChunkBoundaries(t *testing.T) {
	source := `
function first() {
	return 1;
}

function second() {
	return 2;
}
`

	parser := sitter.NewParser()
	parser.SetLanguage(javascript.GetLanguage())
	tree := parser.Parse(nil, []byte(source))
	defer tree.Close()

	chunker := NewASTChunker(600)
	chunks, err := chunker.ChunkFile(tree, []byte(source), "test.js", "javascript", nil)

	if err != nil {
		t.Fatalf("ChunkFile failed: %v", err)
	}

	if len(chunks) != 2 {
		t.Fatalf("expected 2 chunks, got %d", len(chunks))
	}

	// Verify line numbers (1-indexed)
	// first() should be around lines 2-4
	// second() should be around lines 6-8

	for _, chunk := range chunks {
		if chunk.StartLine < 1 {
			t.Errorf("chunk '%s' has invalid start line: %d", chunk.FunctionName, chunk.StartLine)
		}
		if chunk.EndLine < chunk.StartLine {
			t.Errorf("chunk '%s' has end line before start line: %d < %d",
				chunk.FunctionName, chunk.EndLine, chunk.StartLine)
		}

		// Verify source matches line range
		lines := strings.Split(chunk.Source, "\n")
		expectedLines := chunk.EndLine - chunk.StartLine + 1
		// Allow some tolerance for how tree-sitter counts lines
		if len(lines) != expectedLines && len(lines) != expectedLines+1 {
			t.Errorf("chunk '%s' source has %d lines but line range suggests %d",
				chunk.FunctionName, len(lines), expectedLines)
		}
	}
}

// TestSplitLargeChunk tests splitting of large functions
func TestSplitLargeChunk(t *testing.T) {
	// Create a large function with many lines
	lines := []string{"function large() {"}
	for i := 0; i < 200; i++ {
		lines = append(lines, "	console.log('line');")
	}
	lines = append(lines, "}")

	largeSource := strings.Join(lines, "\n")

	chunker := NewASTChunker(100) // Small max tokens to force splitting

	chunk := CodeChunk{
		FunctionName: "large",
		Language:     "javascript",
		Source:       largeSource,
		Tokens:       estimateTokens(largeSource),
		FilePath:     "test.js",
		StartLine:    1,
		EndLine:      202,
		Frameworks:   []string{"express"},
	}

	splitChunks := chunker.splitLargeChunk(chunk)

	// Should be split into multiple chunks
	if len(splitChunks) < 2 {
		t.Errorf("expected multiple chunks, got %d", len(splitChunks))
	}

	// Verify all split chunks have unique IDs
	ids := make(map[string]bool)
	for _, sc := range splitChunks {
		if ids[sc.ID] {
			t.Errorf("duplicate chunk ID: %s", sc.ID)
		}
		ids[sc.ID] = true
	}

	// Verify function names have part suffixes
	for i, sc := range splitChunks {
		if !strings.HasPrefix(sc.FunctionName, "large_part") {
			t.Errorf("split chunk %d has wrong name: %s", i, sc.FunctionName)
		}
	}

	// Verify all chunks are under maxTokens
	for i, sc := range splitChunks {
		if sc.Tokens > chunker.maxTokens {
			t.Errorf("split chunk %d has %d tokens, exceeds max %d", i, sc.Tokens, chunker.maxTokens)
		}
	}
}

// TestChunkFile_NilTree tests error handling for nil tree
func TestChunkFile_NilTree(t *testing.T) {
	chunker := NewASTChunker(600)
	_, err := chunker.ChunkFile(nil, []byte("test"), "test.js", "javascript", nil)

	if err == nil {
		t.Error("expected error for nil tree, got nil")
	}
}

// TestChunkFile_EmptyFile tests chunking of empty file
func TestChunkFile_EmptyFile(t *testing.T) {
	source := ""

	parser := sitter.NewParser()
	parser.SetLanguage(javascript.GetLanguage())
	tree := parser.Parse(nil, []byte(source))
	defer tree.Close()

	chunker := NewASTChunker(600)
	chunks, err := chunker.ChunkFile(tree, []byte(source), "test.js", "javascript", nil)

	if err != nil {
		t.Fatalf("ChunkFile failed: %v", err)
	}

	if len(chunks) != 0 {
		t.Errorf("expected 0 chunks for empty file, got %d", len(chunks))
	}
}

// TestChunkFile_NoFunctions tests chunking of file with no functions
func TestChunkFile_NoFunctions(t *testing.T) {
	source := `
const x = 1;
const y = 2;
console.log(x + y);
`

	parser := sitter.NewParser()
	parser.SetLanguage(javascript.GetLanguage())
	tree := parser.Parse(nil, []byte(source))
	defer tree.Close()

	chunker := NewASTChunker(600)
	chunks, err := chunker.ChunkFile(tree, []byte(source), "test.js", "javascript", nil)

	if err != nil {
		t.Fatalf("ChunkFile failed: %v", err)
	}

	if len(chunks) != 0 {
		t.Errorf("expected 0 chunks for file with no functions, got %d", len(chunks))
	}
}

// TestRemoveComments tests comment removal for different languages
func TestRemoveComments(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		language string
		expected string
	}{
		{
			name:     "JS single-line comment",
			source:   "const x = 1; // comment",
			language: "javascript",
			expected: "const x = 1; ",
		},
		{
			name:     "JS multi-line comment",
			source:   "const x = 1; /* comment\nmore */ const y = 2;",
			language: "javascript",
			expected: "const x = 1;  const y = 2;",
		},
		{
			name:     "Python single-line comment",
			source:   "x = 1  # comment",
			language: "python",
			expected: "x = 1  ",
		},
		{
			name:     "Python docstring",
			source:   "def foo():\n\t\"\"\"docstring\"\"\"\n\treturn 1",
			language: "python",
			expected: "def foo():\n\t\n\treturn 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := removeComments(tt.source, tt.language)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestNormalizeLanguageName tests language name normalization
func TestNormalizeLanguageName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"js", "javascript"},
		{"JS", "javascript"},
		{"ts", "typescript"},
		{"TS", "typescript"},
		{"py", "python"},
		{"PY", "python"},
		{"javascript", "javascript"},
		{"python", "python"},
		{"java", "java"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := NormalizeLanguageName(tt.input)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestExtractFunctionName_EdgeCases tests function name extraction edge cases
func TestExtractFunctionName_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		language string
		expected string
	}{
		{
			name:     "anonymous arrow function",
			source:   "const fn = () => 42;",
			language: "javascript",
			expected: "fn",
		},
		{
			name:     "anonymous function expression",
			source:   "const fn = function() { return 42; };",
			language: "javascript",
			expected: "fn",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := sitter.NewParser()
			parser.SetLanguage(javascript.GetLanguage())
			tree := parser.Parse(nil, []byte(tt.source))
			defer tree.Close()

			chunker := NewASTChunker(600)
			chunks, err := chunker.ChunkFile(tree, []byte(tt.source), "test.js", tt.language, nil)

			if err != nil {
				t.Fatalf("ChunkFile failed: %v", err)
			}

			if len(chunks) != 1 {
				t.Fatalf("expected 1 chunk, got %d", len(chunks))
			}

			if chunks[0].FunctionName != tt.expected {
				t.Errorf("expected function name %q, got %q", tt.expected, chunks[0].FunctionName)
			}
		})
	}
}
