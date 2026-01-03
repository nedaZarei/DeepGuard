package suppression

import (
	"testing"
)

func TestParseComments_SameLine(t *testing.T) {
	comments := []CommentLocation{
		{Line: 10, Text: "// deepguard:ignore"},
		{Line: 20, Text: "# deepguard:ignore"},
	}

	suppressions := ParseComments(comments)

	if len(suppressions) != 2 {
		t.Fatalf("Expected 2 suppressions, got %d", len(suppressions))
	}

	// Check first suppression
	if suppressions[0].Line != 10 {
		t.Errorf("Expected line 10, got %d", suppressions[0].Line)
	}

	if suppressions[0].Type != "all" {
		t.Errorf("Expected type 'all', got '%s'", suppressions[0].Type)
	}

	if suppressions[0].AppliesTo != "same" {
		t.Errorf("Expected applies_to 'same', got '%s'", suppressions[0].AppliesTo)
	}

	if suppressions[0].SourceLine != 10 {
		t.Errorf("Expected source_line 10, got %d", suppressions[0].SourceLine)
	}
}

func TestParseComments_NextLine(t *testing.T) {
	comments := []CommentLocation{
		{Line: 10, Text: "// deepguard:ignore-next-line"},
		{Line: 20, Text: "# deepguard:ignore-next-line"},
	}

	suppressions := ParseComments(comments)

	if len(suppressions) != 2 {
		t.Fatalf("Expected 2 suppressions, got %d", len(suppressions))
	}

	// Check first suppression - should apply to line 11
	if suppressions[0].Line != 11 {
		t.Errorf("Expected line 11, got %d", suppressions[0].Line)
	}

	if suppressions[0].AppliesTo != "next" {
		t.Errorf("Expected applies_to 'next', got '%s'", suppressions[0].AppliesTo)
	}

	if suppressions[0].SourceLine != 10 {
		t.Errorf("Expected source_line 10, got %d", suppressions[0].SourceLine)
	}

	// Check second suppression - should apply to line 21
	if suppressions[1].Line != 21 {
		t.Errorf("Expected line 21, got %d", suppressions[1].Line)
	}
}

func TestParseComments_TypeSpecific(t *testing.T) {
	comments := []CommentLocation{
		{Line: 10, Text: "// deepguard:ignore sql_injection"},
		{Line: 20, Text: "// deepguard:ignore-next-line xss"},
		{Line: 30, Text: "# deepguard:ignore command_injection"},
	}

	suppressions := ParseComments(comments)

	if len(suppressions) != 3 {
		t.Fatalf("Expected 3 suppressions, got %d", len(suppressions))
	}

	if suppressions[0].Type != "sql_injection" {
		t.Errorf("Expected type 'sql_injection', got '%s'", suppressions[0].Type)
	}

	if suppressions[1].Type != "xss" {
		t.Errorf("Expected type 'xss', got '%s'", suppressions[1].Type)
	}

	if suppressions[2].Type != "command_injection" {
		t.Errorf("Expected type 'command_injection', got '%s'", suppressions[2].Type)
	}
}

func TestParseComments_WithJustification(t *testing.T) {
	comments := []CommentLocation{
		{Line: 10, Text: "// deepguard:ignore - false positive: validated upstream"},
		{Line: 20, Text: "// deepguard:ignore sql_injection - input is sanitized"},
		{Line: 30, Text: "# deepguard:ignore-next-line - test code only"},
	}

	suppressions := ParseComments(comments)

	if len(suppressions) != 3 {
		t.Fatalf("Expected 3 suppressions, got %d", len(suppressions))
	}

	if suppressions[0].Justification != "false positive: validated upstream" {
		t.Errorf("Expected justification, got '%s'", suppressions[0].Justification)
	}

	if suppressions[1].Type != "sql_injection" {
		t.Errorf("Expected type 'sql_injection', got '%s'", suppressions[1].Type)
	}

	if suppressions[1].Justification != "input is sanitized" {
		t.Errorf("Expected justification, got '%s'", suppressions[1].Justification)
	}

	if suppressions[2].Line != 31 {
		t.Errorf("Expected line 31 (next line), got %d", suppressions[2].Line)
	}

	if suppressions[2].Justification != "test code only" {
		t.Errorf("Expected justification, got '%s'", suppressions[2].Justification)
	}
}

func TestParseComments_InvalidFormats(t *testing.T) {
	comments := []CommentLocation{
		{Line: 10, Text: "// deep guard:ignore"},        // Space in keyword
		{Line: 20, Text: "// deepguardignore"},          // Missing colon
		{Line: 30, Text: "// some other comment"},       // Not a suppression
		{Line: 40, Text: "// deepguard ignore"},         // Space instead of colon
		{Line: 50, Text: "// adeepguard:ignore"},        // Preceded by letter (should not match)
	}

	suppressions := ParseComments(comments)

	// None of these should be recognized as suppressions
	if len(suppressions) != 0 {
		t.Errorf("Expected 0 suppressions, got %d", len(suppressions))
	}
}

func TestParseComments_MultipleOnSameLine(t *testing.T) {
	comments := []CommentLocation{
		{Line: 10, Text: "// some comment deepguard:ignore extra text"},
	}

	suppressions := ParseComments(comments)

	// Should find the suppression even with surrounding text
	if len(suppressions) != 1 {
		t.Fatalf("Expected 1 suppression, got %d", len(suppressions))
	}

	if suppressions[0].Line != 10 {
		t.Errorf("Expected line 10, got %d", suppressions[0].Line)
	}
}

func TestIsSuppressed_AllTypes(t *testing.T) {
	suppressions := []SuppressionInfo{
		{Line: 10, Type: "all", AppliesTo: "same"},
		{Line: 20, Type: "sql_injection", AppliesTo: "same"},
	}

	// Test line 10 with any type - should be suppressed
	suppressed, info := IsSuppressed(10, "sql_injection", suppressions)
	if !suppressed {
		t.Error("Expected line 10 to be suppressed for sql_injection")
	}
	if info == nil || info.Type != "all" {
		t.Error("Expected suppression info with type 'all'")
	}

	suppressed, _ = IsSuppressed(10, "xss", suppressions)
	if !suppressed {
		t.Error("Expected line 10 to be suppressed for xss")
	}

	// Test line 20 with matching type - should be suppressed
	suppressed, info = IsSuppressed(20, "sql_injection", suppressions)
	if !suppressed {
		t.Error("Expected line 20 to be suppressed for sql_injection")
	}
	if info == nil || info.Type != "sql_injection" {
		t.Error("Expected suppression info with type 'sql_injection'")
	}

	// Test line 20 with non-matching type - should NOT be suppressed
	suppressed, _ = IsSuppressed(20, "xss", suppressions)
	if suppressed {
		t.Error("Expected line 20 NOT to be suppressed for xss")
	}

	// Test line 30 (not suppressed) - should NOT be suppressed
	suppressed, _ = IsSuppressed(30, "sql_injection", suppressions)
	if suppressed {
		t.Error("Expected line 30 NOT to be suppressed")
	}
}

func TestIsSuppressed_TypeSpecific(t *testing.T) {
	suppressions := []SuppressionInfo{
		{Line: 10, Type: "sql_injection", AppliesTo: "same"},
		{Line: 20, Type: "xss", AppliesTo: "next"},
	}

	// Matching type
	suppressed, _ := IsSuppressed(10, "sql_injection", suppressions)
	if !suppressed {
		t.Error("Expected suppression for matching type")
	}

	// Non-matching type
	suppressed, _ = IsSuppressed(10, "xss", suppressions)
	if suppressed {
		t.Error("Expected no suppression for non-matching type")
	}

	// Different vulnerability type
	suppressed, _ = IsSuppressed(10, "command_injection", suppressions)
	if suppressed {
		t.Error("Expected no suppression for different type")
	}
}

func TestIsSuppressed_NoSuppressions(t *testing.T) {
	var suppressions []SuppressionInfo

	suppressed, info := IsSuppressed(10, "sql_injection", suppressions)
	if suppressed {
		t.Error("Expected no suppression with empty list")
	}
	if info != nil {
		t.Error("Expected nil info with no suppressions")
	}
}

func TestExtractCommentsFromSource_JavaScript(t *testing.T) {
	source := `function test() {
  // deepguard:ignore
  const query = buildQuery();

  // deepguard:ignore-next-line
  db.execute(query);
}`

	comments := ExtractCommentsFromSource(source, "javascript")

	if len(comments) != 2 {
		t.Fatalf("Expected 2 comments, got %d", len(comments))
	}

	if comments[0].Line != 2 {
		t.Errorf("Expected line 2, got %d", comments[0].Line)
	}

	if comments[1].Line != 5 {
		t.Errorf("Expected line 5, got %d", comments[1].Line)
	}
}

func TestExtractCommentsFromSource_Python(t *testing.T) {
	source := `def test():
    # deepguard:ignore
    query = build_query()

    # deepguard:ignore-next-line
    cursor.execute(query)
`

	comments := ExtractCommentsFromSource(source, "python")

	if len(comments) != 2 {
		t.Fatalf("Expected 2 comments, got %d", len(comments))
	}

	if comments[0].Line != 2 {
		t.Errorf("Expected line 2, got %d", comments[0].Line)
	}

	if comments[1].Line != 5 {
		t.Errorf("Expected line 5, got %d", comments[1].Line)
	}
}

func TestExtractType(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", "all"},
		{"  ", "all"},
		{"sql_injection", "sql_injection"},
		{"  xss  ", "xss"},
		{"command_injection", "command_injection"},
	}

	for _, test := range tests {
		result := extractType(test.input)
		if result != test.expected {
			t.Errorf("extractType(%q) = %q, expected %q", test.input, result, test.expected)
		}
	}
}

func TestParseComments_RealWorldExamples(t *testing.T) {
	comments := []CommentLocation{
		// JavaScript examples
		{Line: 10, Text: "// deepguard:ignore - userId is validated as integer in middleware"},
		{Line: 20, Text: "    // deepguard:ignore sql_injection - using parameterized query"},
		{Line: 30, Text: "  // deepguard:ignore-next-line - test sample, not production code"},

		// Python examples
		{Line: 40, Text: "# deepguard:ignore - sanitized by custom validator"},
		{Line: 50, Text: "    # deepguard:ignore xss - output is HTML-encoded"},
		{Line: 60, Text: "  # deepguard:ignore-next-line command_injection - input is whitelisted"},
	}

	suppressions := ParseComments(comments)

	if len(suppressions) != 6 {
		t.Fatalf("Expected 6 suppressions, got %d", len(suppressions))
	}

	// Verify justifications are preserved
	if suppressions[0].Justification == "" {
		t.Error("Expected justification to be preserved")
	}

	// Verify types
	if suppressions[1].Type != "sql_injection" {
		t.Errorf("Expected type 'sql_injection', got '%s'", suppressions[1].Type)
	}

	if suppressions[5].Type != "command_injection" {
		t.Errorf("Expected type 'command_injection', got '%s'", suppressions[5].Type)
	}

	// Verify next-line application
	if suppressions[2].Line != 31 {
		t.Errorf("Expected line 31 for next-line suppression, got %d", suppressions[2].Line)
	}
}
