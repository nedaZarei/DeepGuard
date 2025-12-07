package llm

import (
	"testing"

	"github.com/Neda-Zarei/deep-guard/internal/chunker"
	"github.com/Neda-Zarei/deep-guard/pkg/types"
)

func TestEnrichFinding(t *testing.T) {
	chunk := &chunker.CodeChunk{
		ID:           "abc123",
		FilePath:     "/app/routes/users.js",
		StartLine:    10,
		EndLine:      20,
		FunctionName: "getUserById",
		Language:     "javascript",
		Source:       "function getUserById() { ... }",
		Frameworks:   []string{"express"},
	}

	finding := &types.Finding{
		Type:           "sql_injection",
		Severity:       "high",
		Confidence:     0.9,
		Line:           5, // Relative to chunk (5th line within the function)
		Message:        "SQL injection vulnerability",
		Recommendation: "Use parameterized queries",
	}

	EnrichFinding(finding, chunk)

	// Check chunk context
	if finding.ChunkID != "abc123" {
		t.Errorf("Expected ChunkID 'abc123', got '%s'", finding.ChunkID)
	}
	if finding.FilePath != "/app/routes/users.js" {
		t.Errorf("Expected FilePath '/app/routes/users.js', got '%s'", finding.FilePath)
	}
	if finding.FunctionName != "getUserById" {
		t.Errorf("Expected FunctionName 'getUserById', got '%s'", finding.FunctionName)
	}

	// Check line range context
	if finding.LineRangeStart != 10 {
		t.Errorf("Expected LineRangeStart 10, got %d", finding.LineRangeStart)
	}
	if finding.LineRangeEnd != 20 {
		t.Errorf("Expected LineRangeEnd 20, got %d", finding.LineRangeEnd)
	}

	// Check absolute line calculation
	// Line 5 relative to chunk starting at line 10 = absolute line 14
	expectedAbsoluteLine := 10 + (5 - 1) // 14
	if finding.AbsoluteLine != expectedAbsoluteLine {
		t.Errorf("Expected AbsoluteLine %d, got %d", expectedAbsoluteLine, finding.AbsoluteLine)
	}
}

func TestEnrichFinding_FirstLineOfChunk(t *testing.T) {
	chunk := &chunker.CodeChunk{
		ID:           "def456",
		FilePath:     "/app/db/queries.py",
		StartLine:    50,
		EndLine:      60,
		FunctionName: "execute_query",
		Language:     "python",
	}

	finding := &types.Finding{
		Type:           "sql_injection",
		Severity:       "critical",
		Confidence:     0.95,
		Line:           1, // First line of chunk
		Message:        "Test",
		Recommendation: "Fix",
	}

	EnrichFinding(finding, chunk)

	// Line 1 relative to chunk starting at line 50 = absolute line 50
	expectedAbsoluteLine := 50
	if finding.AbsoluteLine != expectedAbsoluteLine {
		t.Errorf("Expected AbsoluteLine %d, got %d", expectedAbsoluteLine, finding.AbsoluteLine)
	}
}

func TestEnrichFinding_LastLineOfChunk(t *testing.T) {
	chunk := &chunker.CodeChunk{
		ID:           "ghi789",
		FilePath:     "/app/auth.java",
		StartLine:    100,
		EndLine:      110,
		FunctionName: "validateToken",
		Language:     "java",
	}

	finding := &types.Finding{
		Type:           "auth_issue",
		Severity:       "high",
		Confidence:     0.85,
		Line:           11, // Last line of chunk (11 lines total)
		Message:        "Test",
		Recommendation: "Fix",
	}

	EnrichFinding(finding, chunk)

	// Line 11 relative to chunk starting at line 100 = absolute line 110
	expectedAbsoluteLine := 100 + (11 - 1) // 110
	if finding.AbsoluteLine != expectedAbsoluteLine {
		t.Errorf("Expected AbsoluteLine %d, got %d", expectedAbsoluteLine, finding.AbsoluteLine)
	}
}

func TestEnrichFindings_MultipleFindings(t *testing.T) {
	chunk := &chunker.CodeChunk{
		ID:           "jkl012",
		FilePath:     "/app/crypto.js",
		StartLine:    200,
		EndLine:      220,
		FunctionName: "hashPassword",
		Language:     "javascript",
	}

	response := &APIResponse{
		Findings: []types.Finding{
			{
				Type:           "crypto_issue",
				Severity:       "high",
				Confidence:     0.9,
				Line:           3,
				Message:        "Weak hash algorithm",
				Recommendation: "Use bcrypt",
			},
			{
				Type:           "crypto_issue",
				Severity:       "medium",
				Confidence:     0.7,
				Line:           7,
				Message:        "Hardcoded salt",
				Recommendation: "Generate random salt",
			},
		},
	}

	EnrichFindings(response, chunk)

	// Check first finding
	if response.Findings[0].ChunkID != "jkl012" {
		t.Errorf("Expected ChunkID 'jkl012' for first finding")
	}
	if response.Findings[0].AbsoluteLine != 202 { // 200 + (3 - 1)
		t.Errorf("Expected AbsoluteLine 202 for first finding, got %d", response.Findings[0].AbsoluteLine)
	}

	// Check second finding
	if response.Findings[1].ChunkID != "jkl012" {
		t.Errorf("Expected ChunkID 'jkl012' for second finding")
	}
	if response.Findings[1].AbsoluteLine != 206 { // 200 + (7 - 1)
		t.Errorf("Expected AbsoluteLine 206 for second finding, got %d", response.Findings[1].AbsoluteLine)
	}
}

func TestEnrichFindings_EmptyFindings(t *testing.T) {
	chunk := &chunker.CodeChunk{
		ID:           "mno345",
		FilePath:     "/app/test.js",
		StartLine:    1,
		EndLine:      10,
		FunctionName: "test",
	}

	response := &APIResponse{
		Findings: []types.Finding{},
	}

	// Should not panic
	EnrichFindings(response, chunk)

	if len(response.Findings) != 0 {
		t.Errorf("Expected empty findings to remain empty")
	}
}

func TestEnrichFindings_NilResponse(t *testing.T) {
	chunk := &chunker.CodeChunk{
		ID:           "pqr678",
		FilePath:     "/app/test.js",
		StartLine:    1,
		EndLine:      10,
		FunctionName: "test",
	}

	// Should not panic
	EnrichFindings(nil, chunk)
}

func TestEnrichFindings_NilFindings(t *testing.T) {
	chunk := &chunker.CodeChunk{
		ID:           "stu901",
		FilePath:     "/app/test.js",
		StartLine:    1,
		EndLine:      10,
		FunctionName: "test",
	}

	response := &APIResponse{
		Findings: nil,
	}

	// Should not panic
	EnrichFindings(response, chunk)
}

func TestEnrichFinding_PreservesOriginalFields(t *testing.T) {
	chunk := &chunker.CodeChunk{
		ID:           "vwx234",
		FilePath:     "/app/test.py",
		StartLine:    50,
		EndLine:      60,
		FunctionName: "process_input",
	}

	finding := &types.Finding{
		Type:           "xss",
		Severity:       "medium",
		Confidence:     0.75,
		Line:           5,
		Message:        "XSS vulnerability detected",
		Recommendation: "Escape user input before rendering",
	}

	EnrichFinding(finding, chunk)

	// Ensure original fields are preserved
	if finding.Type != "xss" {
		t.Errorf("Type should be preserved")
	}
	if finding.Severity != "medium" {
		t.Errorf("Severity should be preserved")
	}
	if finding.Confidence != 0.75 {
		t.Errorf("Confidence should be preserved")
	}
	if finding.Line != 5 {
		t.Errorf("Line should be preserved")
	}
	if finding.Message != "XSS vulnerability detected" {
		t.Errorf("Message should be preserved")
	}
	if finding.Recommendation != "Escape user input before rendering" {
		t.Errorf("Recommendation should be preserved")
	}
}
