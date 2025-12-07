package llm

import (
	"strings"
	"testing"

	"github.com/Neda-Zarei/deep-guard/internal/chunker"
	"github.com/Neda-Zarei/deep-guard/internal/kb"
)

func TestNewPromptRenderer(t *testing.T) {
	renderer, err := NewPromptRenderer()
	if err != nil {
		t.Fatalf("Failed to create prompt renderer: %v", err)
	}

	if renderer == nil {
		t.Fatal("Expected non-nil renderer")
	}

	// Verify all templates are loaded
	expectedTypes := []VulnerabilityType{
		VulnTypeSQLInjection,
		VulnTypeXSS,
		VulnTypePathTraversal,
		VulnTypeInsecureDeserialization,
		VulnTypeAuthIssue,
		VulnTypeCryptoIssue,
	}

	for _, vulnType := range expectedTypes {
		if _, ok := renderer.templates[vulnType]; !ok {
			t.Errorf("Template not loaded for vulnerability type: %s", vulnType)
		}
	}
}

func TestRenderPrompt_SQLInjection(t *testing.T) {
	renderer, err := NewPromptRenderer()
	if err != nil {
		t.Fatalf("Failed to create renderer: %v", err)
	}

	chunk := chunker.CodeChunk{
		FilePath:     "/app/routes/users.js",
		StartLine:    10,
		EndLine:      15,
		FunctionName: "getUserById",
		Language:     "javascript",
		Source:       "function getUserById(req, res) {\n  const query = `SELECT * FROM users WHERE id = ${req.params.id}`;\n  db.query(query);\n}",
		Frameworks:   []string{"express"},
	}

	kbEntries := []kb.KBEntry{
		{
			ID:          "sqli-concat",
			Title:       "SQL Injection via String Concatenation",
			Description: "User input concatenated directly into SQL queries allows attackers to inject malicious SQL code.",
		},
		{
			ID:          "sqli-parameterized",
			Title:       "Use Parameterized Queries",
			Description: "Always use parameterized queries or prepared statements to prevent SQL injection.",
		},
	}

	prompt, err := renderer.RenderPrompt(VulnTypeSQLInjection, chunk, kbEntries)
	if err != nil {
		t.Fatalf("Failed to render prompt: %v", err)
	}

	// Verify key sections are present
	expectedContents := []string{
		"You are a security analyst specializing in SQL Injection detection",
		"sql_injection",
		"/app/routes/users.js",
		"**Lines:** 10-15",
		"**Function:** getUserById",
		"SQL Injection via String Concatenation",
		"Use Parameterized Queries",
		"Expected JSON Schema",
	}

	for _, expected := range expectedContents {
		if !strings.Contains(prompt, expected) {
			t.Errorf("Expected prompt to contain '%s', but it didn't", expected)
		}
	}
}

func TestRenderPrompt_XSS(t *testing.T) {
	renderer, err := NewPromptRenderer()
	if err != nil {
		t.Fatalf("Failed to create renderer: %v", err)
	}

	chunk := chunker.CodeChunk{
		FilePath:     "/app/views/profile.jsx",
		StartLine:    20,
		EndLine:      25,
		FunctionName: "renderProfile",
		Language:     "javascript",
		Source:       "function renderProfile(user) {\n  return <div dangerouslySetInnerHTML={{__html: user.bio}} />;\n}",
		Frameworks:   []string{"react"},
	}

	kbEntries := []kb.KBEntry{
		{
			ID:          "xss-react-dangerous",
			Title:       "React dangerouslySetInnerHTML XSS",
			Description: "Using dangerouslySetInnerHTML with user-controlled data can lead to XSS vulnerabilities.",
		},
	}

	prompt, err := renderer.RenderPrompt(VulnTypeXSS, chunk, kbEntries)
	if err != nil {
		t.Fatalf("Failed to render prompt: %v", err)
	}

	expectedContents := []string{
		"Cross-Site Scripting (XSS) detection",
		"\"type\": \"xss\"",
		"/app/views/profile.jsx",
		"renderProfile",
		"React dangerouslySetInnerHTML XSS",
	}

	for _, expected := range expectedContents {
		if !strings.Contains(prompt, expected) {
			t.Errorf("Expected prompt to contain '%s'", expected)
		}
	}
}

func TestRenderPrompt_PathTraversal(t *testing.T) {
	renderer, err := NewPromptRenderer()
	if err != nil {
		t.Fatalf("Failed to create renderer: %v", err)
	}

	chunk := chunker.CodeChunk{
		FilePath:     "/app/download.py",
		StartLine:    5,
		EndLine:      10,
		FunctionName: "download_file",
		Language:     "python",
		Source:       "def download_file(request):\n    filename = request.GET['file']\n    with open('/uploads/' + filename) as f:\n        return f.read()",
		Frameworks:   []string{"flask"},
	}

	kbEntries := []kb.KBEntry{
		{
			ID:          "path-traversal-concat",
			Title:       "Path Traversal via String Concatenation",
			Description: "Directly concatenating user input with file paths allows directory traversal attacks using ../ sequences.",
		},
	}

	prompt, err := renderer.RenderPrompt(VulnTypePathTraversal, chunk, kbEntries)
	if err != nil {
		t.Fatalf("Failed to render prompt: %v", err)
	}

	expectedContents := []string{
		"Path Traversal detection",
		"\"type\": \"path_traversal\"",
		"/app/download.py",
		"download_file",
		"Path Traversal via String Concatenation",
	}

	for _, expected := range expectedContents {
		if !strings.Contains(prompt, expected) {
			t.Errorf("Expected prompt to contain '%s'", expected)
		}
	}
}

func TestRenderPrompt_InsecureDeserialization(t *testing.T) {
	renderer, err := NewPromptRenderer()
	if err != nil {
		t.Fatalf("Failed to create renderer: %v", err)
	}

	chunk := chunker.CodeChunk{
		FilePath:     "/app/api/data.py",
		StartLine:    12,
		EndLine:      18,
		FunctionName: "load_user_data",
		Language:     "python",
		Source:       "def load_user_data(data):\n    import pickle\n    return pickle.loads(data)",
		Frameworks:   []string{"django"},
	}

	kbEntries := []kb.KBEntry{
		{
			ID:          "pickle-rce",
			Title:       "Pickle Deserialization RCE",
			Description: "Python's pickle module can execute arbitrary code during deserialization of untrusted data.",
		},
	}

	prompt, err := renderer.RenderPrompt(VulnTypeInsecureDeserialization, chunk, kbEntries)
	if err != nil {
		t.Fatalf("Failed to render prompt: %v", err)
	}

	expectedContents := []string{
		"Insecure Deserialization detection",
		"\"type\": \"insecure_deserialization\"",
		"/app/api/data.py",
		"load_user_data",
		"Pickle Deserialization RCE",
	}

	for _, expected := range expectedContents {
		if !strings.Contains(prompt, expected) {
			t.Errorf("Expected prompt to contain '%s'", expected)
		}
	}
}

func TestRenderPrompt_AuthIssue(t *testing.T) {
	renderer, err := NewPromptRenderer()
	if err != nil {
		t.Fatalf("Failed to create renderer: %v", err)
	}

	chunk := chunker.CodeChunk{
		FilePath:     "/app/auth/jwt.js",
		StartLine:    8,
		EndLine:      12,
		FunctionName: "verifyToken",
		Language:     "javascript",
		Source:       "function verifyToken(token) {\n  return jwt.decode(token);\n}",
		Frameworks:   []string{"express"},
	}

	kbEntries := []kb.KBEntry{
		{
			ID:          "jwt-no-verify",
			Title:       "JWT Decoded Without Verification",
			Description: "Using jwt.decode() without signature verification allows token forgery.",
		},
	}

	prompt, err := renderer.RenderPrompt(VulnTypeAuthIssue, chunk, kbEntries)
	if err != nil {
		t.Fatalf("Failed to render prompt: %v", err)
	}

	expectedContents := []string{
		"Authentication and Authorization vulnerability detection",
		"\"type\": \"auth_issue\"",
		"/app/auth/jwt.js",
		"verifyToken",
		"JWT Decoded Without Verification",
	}

	for _, expected := range expectedContents {
		if !strings.Contains(prompt, expected) {
			t.Errorf("Expected prompt to contain '%s'", expected)
		}
	}
}

func TestRenderPrompt_CryptoIssue(t *testing.T) {
	renderer, err := NewPromptRenderer()
	if err != nil {
		t.Fatalf("Failed to create renderer: %v", err)
	}

	chunk := chunker.CodeChunk{
		FilePath:     "/app/utils/hash.js",
		StartLine:    5,
		EndLine:      9,
		FunctionName: "hashPassword",
		Language:     "javascript",
		Source:       "function hashPassword(password) {\n  return crypto.createHash('md5').update(password).digest('hex');\n}",
		Frameworks:   []string{},
	}

	kbEntries := []kb.KBEntry{
		{
			ID:          "weak-hash-md5",
			Title:       "Weak Hash Algorithm MD5",
			Description: "MD5 is cryptographically broken and should not be used for password hashing.",
		},
	}

	prompt, err := renderer.RenderPrompt(VulnTypeCryptoIssue, chunk, kbEntries)
	if err != nil {
		t.Fatalf("Failed to render prompt: %v", err)
	}

	expectedContents := []string{
		"Cryptography vulnerability detection",
		"\"type\": \"crypto_issue\"",
		"/app/utils/hash.js",
		"hashPassword",
		"Weak Hash Algorithm MD5",
	}

	for _, expected := range expectedContents {
		if !strings.Contains(prompt, expected) {
			t.Errorf("Expected prompt to contain '%s'", expected)
		}
	}
}

func TestRenderPrompt_WithFrameworkHints(t *testing.T) {
	renderer, err := NewPromptRenderer()
	if err != nil {
		t.Fatalf("Failed to create renderer: %v", err)
	}

	chunk := chunker.CodeChunk{
		FilePath:     "/app/db/queries.js",
		StartLine:    1,
		EndLine:      5,
		FunctionName: "getUser",
		Language:     "javascript",
		Source:       "function getUser(id) {\n  return prisma.$queryRaw(`SELECT * FROM users WHERE id = ${id}`);\n}",
		Frameworks:   []string{"express", "prisma"},
	}

	kbEntries := []kb.KBEntry{}

	prompt, err := renderer.RenderPrompt(VulnTypeSQLInjection, chunk, kbEntries)
	if err != nil {
		t.Fatalf("Failed to render prompt: %v", err)
	}

	// Verify framework hints are included
	if !strings.Contains(prompt, "Framework-Specific Guidance:") {
		t.Error("Expected framework-specific guidance section")
	}

	// Check for Express-specific hints
	if !strings.Contains(prompt, "req.query") || !strings.Contains(prompt, "req.params") {
		t.Error("Expected Express-specific hints about request parameters")
	}

	// Check for Prisma-specific hints
	if !strings.Contains(prompt, "$queryRaw") || !strings.Contains(prompt, "$executeRaw") {
		t.Error("Expected Prisma-specific hints about raw query methods")
	}
}

func TestRenderPrompt_NoFrameworks(t *testing.T) {
	renderer, err := NewPromptRenderer()
	if err != nil {
		t.Fatalf("Failed to create renderer: %v", err)
	}

	chunk := chunker.CodeChunk{
		FilePath:     "/app/test.js",
		StartLine:    1,
		EndLine:      3,
		FunctionName: "test",
		Language:     "javascript",
		Source:       "function test() { return 42; }",
		Frameworks:   []string{},
	}

	kbEntries := []kb.KBEntry{}

	prompt, err := renderer.RenderPrompt(VulnTypeSQLInjection, chunk, kbEntries)
	if err != nil {
		t.Fatalf("Failed to render prompt: %v", err)
	}

	if !strings.Contains(prompt, "**Detected Frameworks:** None") {
		t.Errorf("Expected '**Detected Frameworks:** None' for frameworks when no frameworks detected")
	}
}

func TestRenderPrompt_InvalidVulnType(t *testing.T) {
	renderer, err := NewPromptRenderer()
	if err != nil {
		t.Fatalf("Failed to create renderer: %v", err)
	}

	chunk := chunker.CodeChunk{
		FilePath:     "/app/test.js",
		StartLine:    1,
		EndLine:      3,
		FunctionName: "test",
		Language:     "javascript",
		Source:       "function test() {}",
		Frameworks:   []string{},
	}

	kbEntries := []kb.KBEntry{}

	_, err = renderer.RenderPrompt("invalid_type", chunk, kbEntries)
	if err == nil {
		t.Error("Expected error for invalid vulnerability type")
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxLen   int
		expected string
	}{
		{
			name:     "Short string",
			input:    "Hello",
			maxLen:   10,
			expected: "Hello",
		},
		{
			name:     "Exact length",
			input:    "Hello",
			maxLen:   5,
			expected: "Hello",
		},
		{
			name:     "Long string",
			input:    "This is a very long description that needs to be truncated",
			maxLen:   20,
			expected: "This is a very lo...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateString(tt.input, tt.maxLen)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestFormatFrameworks(t *testing.T) {
	tests := []struct {
		name       string
		frameworks []string
		expected   string
	}{
		{
			name:       "Empty list",
			frameworks: []string{},
			expected:   "No frameworks detected",
		},
		{
			name:       "Single framework",
			frameworks: []string{"express"},
			expected:   "express",
		},
		{
			name:       "Multiple frameworks",
			frameworks: []string{"express", "prisma", "react"},
			expected:   "express, prisma, react",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatFrameworks(tt.frameworks)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}
