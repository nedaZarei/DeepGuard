package kb

import (
	"fmt"
	"regexp"
	"strings"
)

// KBEntry represents a vulnerability knowledge base entry
type KBEntry struct {
	ID            string   `yaml:"id"`
	Title         string   `yaml:"title"`
	Description   string   `yaml:"description"`
	CodePatterns  []string `yaml:"code_patterns"`
	SchemaVersion int      `yaml:"schema_version"`
}

// KBValidator validates knowledge base entries
type KBValidator interface {
	Validate(entry KBEntry) error
}

// DefaultValidator implements KBValidator with standard validation rules
type DefaultValidator struct{}

// NewDefaultValidator creates a new DefaultValidator
func NewDefaultValidator() *DefaultValidator {
	return &DefaultValidator{}
}

// Validate validates a KB entry according to schema rules
func (v *DefaultValidator) Validate(entry KBEntry) error {
	// Validate ID field
	if err := v.validateID(entry.ID); err != nil {
		return err
	}

	// Validate title field
	if err := v.validateTitle(entry.Title); err != nil {
		return err
	}

	// Validate description field
	if err := v.validateDescription(entry.Description); err != nil {
		return err
	}

	// Validate code_patterns field
	if err := v.validateCodePatterns(entry.CodePatterns); err != nil {
		return err
	}

	// Schema version is optional, defaults to 1 if not set
	// No validation needed for schema_version

	return nil
}

// validateID validates the ID field
func (v *DefaultValidator) validateID(id string) error {
	// Trim whitespace and check if empty
	id = strings.TrimSpace(id)
	if id == "" {
		return NewValidationError("id", "field is required and cannot be empty")
	}

	// Check format: lowercase alphanumeric with hyphens
	validIDPattern := regexp.MustCompile(`^[a-z0-9-]+$`)
	if !validIDPattern.MatchString(id) {
		return NewValidationError("id", "must contain only lowercase letters, numbers, and hyphens (format: ^[a-z0-9-]+$)")
	}

	return nil
}

// validateTitle validates the title field
func (v *DefaultValidator) validateTitle(title string) error {
	// Trim whitespace and check if empty
	title = strings.TrimSpace(title)
	if title == "" {
		return NewValidationError("title", "field is required and cannot be empty")
	}

	return nil
}

// validateDescription validates the description field
func (v *DefaultValidator) validateDescription(description string) error {
	// Trim whitespace and check if empty
	description = strings.TrimSpace(description)
	if description == "" {
		return NewValidationError("description", "field is required and cannot be empty")
	}

	return nil
}

// validateCodePatterns validates the code_patterns field
func (v *DefaultValidator) validateCodePatterns(patterns []string) error {
	// Check if array exists and has at least one entry
	if len(patterns) == 0 {
		return NewValidationError("code_patterns", "must contain at least 1 entry")
	}

	return nil
}

// ValidationError represents a validation error with context
type ValidationError struct {
	Field    string
	Reason   string
	Filename string // Set by loader when loading from file
}

// NewValidationError creates a new ValidationError
func NewValidationError(field, reason string) *ValidationError {
	return &ValidationError{
		Field:  field,
		Reason: reason,
	}
}

// Error implements the error interface
func (e *ValidationError) Error() string {
	if e.Filename != "" {
		return fmt.Sprintf("validation error in %s: field '%s' - %s", e.Filename, e.Field, e.Reason)
	}
	return fmt.Sprintf("validation error: field '%s' - %s", e.Field, e.Reason)
}

// WithFilename adds filename context to the validation error
func (e *ValidationError) WithFilename(filename string) *ValidationError {
	e.Filename = filename
	return e
}

// DuplicateIDError represents a duplicate ID error
type DuplicateIDError struct {
	ID    string
	File1 string
	File2 string
}

// NewDuplicateIDError creates a new DuplicateIDError
func NewDuplicateIDError(id, file1, file2 string) *DuplicateIDError {
	return &DuplicateIDError{
		ID:    id,
		File1: file1,
		File2: file2,
	}
}

// Error implements the error interface
func (e *DuplicateIDError) Error() string {
	return fmt.Sprintf("duplicate ID '%s' found in files: %s and %s", e.ID, e.File1, e.File2)
}
