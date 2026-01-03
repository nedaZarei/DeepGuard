package kb

import (
	"testing"
)

func TestValidateID_Valid(t *testing.T) {
	validator := NewDefaultValidator()

	validIDs := []string{
		"sqli-001",
		"xss-002",
		"cmdi-001",
		"a",
		"123",
		"test-case-123",
	}

	for _, id := range validIDs {
		err := validator.validateID(id)
		if err != nil {
			t.Errorf("Expected ID '%s' to be valid, got error: %v", id, err)
		}
	}
}

func TestValidateID_Invalid(t *testing.T) {
	validator := NewDefaultValidator()

	invalidIDs := map[string]string{
		"":              "empty string",
		"   ":           "whitespace only",
		"SQL-001":       "uppercase letters",
		"sqli_001":      "underscore",
		"sqli.001":      "dot",
		"sqli 001":      "space",
		"sqli/001":      "slash",
		"sql@injection": "special character",
	}

	for id, reason := range invalidIDs {
		err := validator.validateID(id)
		if err == nil {
			t.Errorf("Expected ID '%s' (%s) to be invalid, but validation passed", id, reason)
		}
	}
}

func TestValidateTitle_Valid(t *testing.T) {
	validator := NewDefaultValidator()

	validTitles := []string{
		"SQL Injection",
		"Cross-Site Scripting (XSS)",
		"A",
		"Test Title with Numbers 123",
	}

	for _, title := range validTitles {
		err := validator.validateTitle(title)
		if err != nil {
			t.Errorf("Expected title '%s' to be valid, got error: %v", title, err)
		}
	}
}

func TestValidateTitle_Invalid(t *testing.T) {
	validator := NewDefaultValidator()

	invalidTitles := []string{
		"",
		"   ",
		"\t\n",
	}

	for _, title := range invalidTitles {
		err := validator.validateTitle(title)
		if err == nil {
			t.Errorf("Expected empty/whitespace title to be invalid, but validation passed")
		}
	}
}

func TestValidateDescription_Valid(t *testing.T) {
	validator := NewDefaultValidator()

	validDescriptions := []string{
		"SQL injection occurs when...",
		"A",
		"Multi-line\ndescription\nwith details",
	}

	for _, desc := range validDescriptions {
		err := validator.validateDescription(desc)
		if err != nil {
			t.Errorf("Expected description to be valid, got error: %v", err)
		}
	}
}

func TestValidateDescription_Invalid(t *testing.T) {
	validator := NewDefaultValidator()

	invalidDescriptions := []string{
		"",
		"   ",
		"\t\n",
	}

	for _, desc := range invalidDescriptions {
		err := validator.validateDescription(desc)
		if err == nil {
			t.Errorf("Expected empty/whitespace description to be invalid, but validation passed")
		}
	}
}

func TestValidateCodePatterns_Valid(t *testing.T) {
	validator := NewDefaultValidator()

	validPatterns := [][]string{
		{"db.query()"},
		{"pattern1", "pattern2"},
		{"a", "b", "c"},
	}

	for _, patterns := range validPatterns {
		err := validator.validateCodePatterns(patterns)
		if err != nil {
			t.Errorf("Expected patterns %v to be valid, got error: %v", patterns, err)
		}
	}
}

func TestValidateCodePatterns_Invalid(t *testing.T) {
	validator := NewDefaultValidator()

	invalidPatterns := [][]string{
		{},
		nil,
	}

	for _, patterns := range invalidPatterns {
		err := validator.validateCodePatterns(patterns)
		if err == nil {
			t.Errorf("Expected empty/nil patterns to be invalid, but validation passed")
		}
	}
}

func TestValidate_CompleteEntry(t *testing.T) {
	validator := NewDefaultValidator()

	entry := KBEntry{
		ID:           "test-001",
		Title:        "Test Vulnerability",
		Description:  "This is a test description",
		CodePatterns: []string{"pattern1", "pattern2"},
	}

	err := validator.Validate(entry)
	if err != nil {
		t.Errorf("Expected valid entry to pass validation, got error: %v", err)
	}
}

func TestValidate_MissingID(t *testing.T) {
	validator := NewDefaultValidator()

	entry := KBEntry{
		Title:        "Test Vulnerability",
		Description:  "This is a test description",
		CodePatterns: []string{"pattern1"},
	}

	err := validator.Validate(entry)
	if err == nil {
		t.Error("Expected validation to fail for missing ID")
	}

	valErr, ok := err.(*ValidationError)
	if !ok {
		t.Errorf("Expected ValidationError, got %T", err)
	}

	if valErr.Field != "id" {
		t.Errorf("Expected error for 'id' field, got '%s'", valErr.Field)
	}
}

func TestValidate_MissingTitle(t *testing.T) {
	validator := NewDefaultValidator()

	entry := KBEntry{
		ID:           "test-001",
		Description:  "This is a test description",
		CodePatterns: []string{"pattern1"},
	}

	err := validator.Validate(entry)
	if err == nil {
		t.Error("Expected validation to fail for missing title")
	}

	valErr, ok := err.(*ValidationError)
	if !ok {
		t.Errorf("Expected ValidationError, got %T", err)
	}

	if valErr.Field != "title" {
		t.Errorf("Expected error for 'title' field, got '%s'", valErr.Field)
	}
}

func TestValidate_MissingDescription(t *testing.T) {
	validator := NewDefaultValidator()

	entry := KBEntry{
		ID:           "test-001",
		Title:        "Test Vulnerability",
		CodePatterns: []string{"pattern1"},
	}

	err := validator.Validate(entry)
	if err == nil {
		t.Error("Expected validation to fail for missing description")
	}

	valErr, ok := err.(*ValidationError)
	if !ok {
		t.Errorf("Expected ValidationError, got %T", err)
	}

	if valErr.Field != "description" {
		t.Errorf("Expected error for 'description' field, got '%s'", valErr.Field)
	}
}

func TestValidate_MissingCodePatterns(t *testing.T) {
	validator := NewDefaultValidator()

	entry := KBEntry{
		ID:          "test-001",
		Title:       "Test Vulnerability",
		Description: "This is a test description",
	}

	err := validator.Validate(entry)
	if err == nil {
		t.Error("Expected validation to fail for missing code_patterns")
	}

	valErr, ok := err.(*ValidationError)
	if !ok {
		t.Errorf("Expected ValidationError, got %T", err)
	}

	if valErr.Field != "code_patterns" {
		t.Errorf("Expected error for 'code_patterns' field, got '%s'", valErr.Field)
	}
}

func TestValidate_InvalidIDFormat(t *testing.T) {
	validator := NewDefaultValidator()

	entry := KBEntry{
		ID:           "TEST-001", // Uppercase - invalid
		Title:        "Test Vulnerability",
		Description:  "This is a test description",
		CodePatterns: []string{"pattern1"},
	}

	err := validator.Validate(entry)
	if err == nil {
		t.Error("Expected validation to fail for invalid ID format")
	}

	valErr, ok := err.(*ValidationError)
	if !ok {
		t.Errorf("Expected ValidationError, got %T", err)
	}

	if valErr.Field != "id" {
		t.Errorf("Expected error for 'id' field, got '%s'", valErr.Field)
	}
}
