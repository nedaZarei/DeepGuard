package parser

import (
	"sync"
	"testing"
)

// Sample valid code for each language
var (
	validJSCode = []byte(`
function greet(name) {
    console.log("Hello, " + name);
    return true;
}

greet("World");
`)

	validTSCode = []byte(`
interface User {
    name: string;
    age: number;
}

function createUser(name: string, age: number): User {
    return { name, age };
}

const user = createUser("Alice", 30);
`)

	validPythonCode = []byte(`
def calculate_sum(a, b):
    """Calculate the sum of two numbers"""
    result = a + b
    return result

class Calculator:
    def __init__(self):
        self.history = []

    def add(self, x, y):
        return x + y

calc = Calculator()
print(calc.add(5, 3))
`)

	validJavaCode = []byte(`
public class HelloWorld {
    private String message;

    public HelloWorld(String message) {
        this.message = message;
    }

    public void printMessage() {
        System.out.println(message);
    }

    public static void main(String[] args) {
        HelloWorld hw = new HelloWorld("Hello, World!");
        hw.printMessage();
    }
}
`)

	// Sample invalid code with syntax errors
	invalidJSCode = []byte(`
function broken(
    console.log("missing closing parenthesis"
}
`)

	invalidTSCode = []byte(`
interface User {
    name: string
    age: number
}

function createUser(: string): User {
    return { name };
}
`)

	invalidPythonCode = []byte(`
def broken_function(
    print("missing closing parenthesis"
    return None
`)

	invalidJavaCode = []byte(`
public class Broken {
    public void method( {
        System.out.println("syntax error"
    }
}
`)
)

func TestNewTreeSitterParser(t *testing.T) {
	parser, err := NewTreeSitterParser()
	if err != nil {
		t.Fatalf("NewTreeSitterParser failed: %v", err)
	}
	defer parser.Close()

	// Verify all language parsers are initialized
	expectedLanguages := []string{"javascript", "typescript", "python", "java"}
	for _, lang := range expectedLanguages {
		if _, ok := parser.parsers[lang]; !ok {
			t.Errorf("Expected parser for %s to be initialized", lang)
		}
	}
}

func TestParse_ValidJavaScript(t *testing.T) {
	parser, err := NewTreeSitterParser()
	if err != nil {
		t.Fatalf("NewTreeSitterParser failed: %v", err)
	}
	defer parser.Close()

	tree, err := parser.Parse(validJSCode, "javascript")
	if err != nil {
		t.Fatalf("Parse failed for valid JavaScript: %v", err)
	}
	defer tree.Close()

	if tree.RootNode() == nil {
		t.Error("Expected non-nil root node")
	}

	if tree.RootNode().HasError() {
		t.Error("Expected no errors in valid JavaScript code")
	}
}

func TestParse_ValidTypeScript(t *testing.T) {
	parser, err := NewTreeSitterParser()
	if err != nil {
		t.Fatalf("NewTreeSitterParser failed: %v", err)
	}
	defer parser.Close()

	tree, err := parser.Parse(validTSCode, "typescript")
	if err != nil {
		t.Fatalf("Parse failed for valid TypeScript: %v", err)
	}
	defer tree.Close()

	if tree.RootNode() == nil {
		t.Error("Expected non-nil root node")
	}

	if tree.RootNode().HasError() {
		t.Error("Expected no errors in valid TypeScript code")
	}
}

func TestParse_ValidPython(t *testing.T) {
	parser, err := NewTreeSitterParser()
	if err != nil {
		t.Fatalf("NewTreeSitterParser failed: %v", err)
	}
	defer parser.Close()

	tree, err := parser.Parse(validPythonCode, "python")
	if err != nil {
		t.Fatalf("Parse failed for valid Python: %v", err)
	}
	defer tree.Close()

	if tree.RootNode() == nil {
		t.Error("Expected non-nil root node")
	}

	if tree.RootNode().HasError() {
		t.Error("Expected no errors in valid Python code")
	}
}

func TestParse_ValidJava(t *testing.T) {
	parser, err := NewTreeSitterParser()
	if err != nil {
		t.Fatalf("NewTreeSitterParser failed: %v", err)
	}
	defer parser.Close()

	tree, err := parser.Parse(validJavaCode, "java")
	if err != nil {
		t.Fatalf("Parse failed for valid Java: %v", err)
	}
	defer tree.Close()

	if tree.RootNode() == nil {
		t.Error("Expected non-nil root node")
	}

	if tree.RootNode().HasError() {
		t.Error("Expected no errors in valid Java code")
	}
}

func TestParse_InvalidJavaScript(t *testing.T) {
	parser, err := NewTreeSitterParser()
	if err != nil {
		t.Fatalf("NewTreeSitterParser failed: %v", err)
	}
	defer parser.Close()

	_, err = parser.Parse(invalidJSCode, "javascript")
	if err == nil {
		t.Error("Expected error for invalid JavaScript code")
	}

	if err != nil {
		t.Logf("Got expected error: %v", err)
	}
}

func TestParse_InvalidTypeScript(t *testing.T) {
	parser, err := NewTreeSitterParser()
	if err != nil {
		t.Fatalf("NewTreeSitterParser failed: %v", err)
	}
	defer parser.Close()

	_, err = parser.Parse(invalidTSCode, "typescript")
	if err == nil {
		t.Error("Expected error for invalid TypeScript code")
	}

	if err != nil {
		t.Logf("Got expected error: %v", err)
	}
}

func TestParse_InvalidPython(t *testing.T) {
	parser, err := NewTreeSitterParser()
	if err != nil {
		t.Fatalf("NewTreeSitterParser failed: %v", err)
	}
	defer parser.Close()

	_, err = parser.Parse(invalidPythonCode, "python")
	if err == nil {
		t.Error("Expected error for invalid Python code")
	}

	if err != nil {
		t.Logf("Got expected error: %v", err)
	}
}

func TestParse_InvalidJava(t *testing.T) {
	parser, err := NewTreeSitterParser()
	if err != nil {
		t.Fatalf("NewTreeSitterParser failed: %v", err)
	}
	defer parser.Close()

	_, err = parser.Parse(invalidJavaCode, "java")
	if err == nil {
		t.Error("Expected error for invalid Java code")
	}

	if err != nil {
		t.Logf("Got expected error: %v", err)
	}
}

func TestParse_UnsupportedLanguage(t *testing.T) {
	parser, err := NewTreeSitterParser()
	if err != nil {
		t.Fatalf("NewTreeSitterParser failed: %v", err)
	}
	defer parser.Close()

	_, err = parser.Parse([]byte("code"), "ruby")
	if err == nil {
		t.Error("Expected error for unsupported language")
	}

	expectedMsg := "unsupported language"
	if err != nil && err.Error() != "unsupported language: ruby" {
		t.Errorf("Expected error message to contain '%s', got: %v", expectedMsg, err)
	}
}

func TestParse_EmptyCode(t *testing.T) {
	parser, err := NewTreeSitterParser()
	if err != nil {
		t.Fatalf("NewTreeSitterParser failed: %v", err)
	}
	defer parser.Close()

	tree, err := parser.Parse([]byte(""), "javascript")
	if err != nil {
		t.Fatalf("Parse failed for empty code: %v", err)
	}
	defer tree.Close()

	// Empty code should parse successfully (empty program)
	if tree.RootNode() == nil {
		t.Error("Expected non-nil root node for empty code")
	}
}

func TestParse_ConcurrentParsing(t *testing.T) {
	parser, err := NewTreeSitterParser()
	if err != nil {
		t.Fatalf("NewTreeSitterParser failed: %v", err)
	}
	defer parser.Close()

	// Test concurrent parsing of different languages
	var wg sync.WaitGroup
	numGoroutines := 10

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Parse different languages concurrently
			languages := []struct {
				name string
				code []byte
			}{
				{"javascript", validJSCode},
				{"typescript", validTSCode},
				{"python", validPythonCode},
				{"java", validJavaCode},
			}

			lang := languages[id%len(languages)]
			tree, err := parser.Parse(lang.code, lang.name)
			if err != nil {
				t.Errorf("Concurrent parse failed for %s: %v", lang.name, err)
				return
			}
			tree.Close()
		}(i)
	}

	wg.Wait()
}

func TestParse_MemoryCleanup(t *testing.T) {
	parser, err := NewTreeSitterParser()
	if err != nil {
		t.Fatalf("NewTreeSitterParser failed: %v", err)
	}
	defer parser.Close()

	// Parse and close many trees to test memory cleanup
	for i := 0; i < 100; i++ {
		tree, err := parser.Parse(validJSCode, "javascript")
		if err != nil {
			t.Fatalf("Parse failed on iteration %d: %v", i, err)
		}
		tree.Close() // Should prevent memory leaks
	}
}

func TestParse_MultipleLanguagesSequential(t *testing.T) {
	parser, err := NewTreeSitterParser()
	if err != nil {
		t.Fatalf("NewTreeSitterParser failed: %v", err)
	}
	defer parser.Close()

	tests := []struct {
		name     string
		language string
		code     []byte
	}{
		{"JavaScript", "javascript", validJSCode},
		{"TypeScript", "typescript", validTSCode},
		{"Python", "python", validPythonCode},
		{"Java", "java", validJavaCode},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := parser.Parse(tt.code, tt.language)
			if err != nil {
				t.Errorf("Parse failed for %s: %v", tt.name, err)
				return
			}
			defer tree.Close()

			if tree.RootNode() == nil {
				t.Errorf("Expected non-nil root node for %s", tt.name)
			}
		})
	}
}

func TestFindFirstError(t *testing.T) {
	parser, err := NewTreeSitterParser()
	if err != nil {
		t.Fatalf("NewTreeSitterParser failed: %v", err)
	}
	defer parser.Close()

	// Parse code with error (bypass the Parse method's error checking)
	p := parser.parsers["javascript"]
	tree := p.Parse(nil, invalidJSCode)
	if tree == nil {
		t.Fatal("Parse returned nil")
	}
	defer tree.Close()

	// Find the error location
	errorInfo := findFirstError(tree.RootNode(), invalidJSCode)
	if errorInfo == "" {
		t.Error("Expected error info for invalid code")
	}

	t.Logf("Error info: %s", errorInfo)

	// Verify it contains line information
	if len(errorInfo) < 5 {
		t.Error("Expected detailed error information")
	}
}

func TestParse_LargeFile(t *testing.T) {
	parser, err := NewTreeSitterParser()
	if err != nil {
		t.Fatalf("NewTreeSitterParser failed: %v", err)
	}
	defer parser.Close()

	// Create a large valid JavaScript file
	largeCode := []byte(`
// Large file with many functions
`)
	for i := 0; i < 100; i++ {
		largeCode = append(largeCode, []byte(`
function func`+string(rune('0'+i%10))+`() {
    const x = `+string(rune('0'+i%10))+`;
    return x * 2;
}
`)...)
	}

	tree, err := parser.Parse(largeCode, "javascript")
	if err != nil {
		t.Fatalf("Parse failed for large file: %v", err)
	}
	defer tree.Close()

	if tree.RootNode() == nil {
		t.Error("Expected non-nil root node for large file")
	}
}
