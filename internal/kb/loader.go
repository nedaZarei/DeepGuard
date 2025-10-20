package kb

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadKBDirectory loads all KB entries from YAML files in a directory
func LoadKBDirectory(path string) ([]KBEntry, error) {
	// Check if directory exists
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("directory does not exist: %s", path)
		}
		return nil, fmt.Errorf("failed to access directory: %w", err)
	}

	if !info.IsDir() {
		return nil, fmt.Errorf("path is not a directory: %s", path)
	}

	// Find all .yaml files in directory
	var yamlFiles []string
	err = filepath.WalkDir(path, func(filePath string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if d.IsDir() {
			return nil
		}

		// Check if file has .yaml or .yml extension
		ext := strings.ToLower(filepath.Ext(filePath))
		if ext == ".yaml" || ext == ".yml" {
			yamlFiles = append(yamlFiles, filePath)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory: %w", err)
	}

	if len(yamlFiles) == 0 {
		return []KBEntry{}, nil // Return empty slice if no YAML files found
	}

	// Load and validate all entries
	var entries []KBEntry
	validator := NewDefaultValidator()
	idMap := make(map[string]string) // id -> filename for duplicate detection

	for _, filePath := range yamlFiles {
		entry, err := loadKBFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to load %s: %w", filePath, err)
		}

		// Set default schema version if not specified
		if entry.SchemaVersion == 0 {
			entry.SchemaVersion = 1
		}

		// Validate entry
		err = validator.Validate(entry)
		if err != nil {
			// Add filename context to validation errors
			if valErr, ok := err.(*ValidationError); ok {
				return nil, valErr.WithFilename(filePath)
			}
			return nil, fmt.Errorf("validation failed for %s: %w", filePath, err)
		}

		// Check for duplicate IDs
		if existingFile, exists := idMap[entry.ID]; exists {
			return nil, NewDuplicateIDError(entry.ID, existingFile, filePath)
		}
		idMap[entry.ID] = filePath

		entries = append(entries, entry)
	}

	return entries, nil
}

// loadKBFile loads a single KB entry from a YAML file
func loadKBFile(filePath string) (KBEntry, error) {
	// Read file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return KBEntry{}, fmt.Errorf("failed to read file: %w", err)
	}

	// Parse YAML
	var entry KBEntry
	err = yaml.Unmarshal(data, &entry)
	if err != nil {
		return KBEntry{}, fmt.Errorf("failed to parse YAML: %w", err)
	}

	return entry, nil
}

// LoadKBFile loads and validates a single KB entry from a file (exported for testing)
func LoadKBFile(filePath string) (KBEntry, error) {
	entry, err := loadKBFile(filePath)
	if err != nil {
		return KBEntry{}, err
	}

	// Set default schema version if not specified
	if entry.SchemaVersion == 0 {
		entry.SchemaVersion = 1
	}

	// Validate entry
	validator := NewDefaultValidator()
	err = validator.Validate(entry)
	if err != nil {
		// Add filename context to validation errors
		if valErr, ok := err.(*ValidationError); ok {
			return KBEntry{}, valErr.WithFilename(filePath)
		}
		return KBEntry{}, fmt.Errorf("validation failed: %w", err)
	}

	return entry, nil
}
