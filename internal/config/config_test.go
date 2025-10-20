package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig_Defaults(t *testing.T) {
	// Change to a temp directory to avoid picking up real config files
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	defer os.Chdir(oldDir)
	os.Chdir(tmpDir)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// Verify default values
	if cfg.ScanPath != "" {
		t.Errorf("Expected empty scan_path, got: %s", cfg.ScanPath)
	}
	if cfg.OutputDir != "./reports/" {
		t.Errorf("Expected output_dir='./reports/', got: %s", cfg.OutputDir)
	}
	if len(cfg.Languages) != 4 {
		t.Errorf("Expected 4 languages, got: %d", len(cfg.Languages))
	}
	expectedLangs := map[string]bool{"js": true, "ts": true, "python": true, "java": true}
	for _, lang := range cfg.Languages {
		if !expectedLangs[lang] {
			t.Errorf("Unexpected language in defaults: %s", lang)
		}
	}
	if cfg.OpenAIModel != "gpt-4o" {
		t.Errorf("Expected openai_model='gpt-4o', got: %s", cfg.OpenAIModel)
	}
	if cfg.BudgetCap != 3.0 {
		t.Errorf("Expected budget_cap=3.0, got: %f", cfg.BudgetCap)
	}
	if cfg.ConfidenceThreshold != 0.5 {
		t.Errorf("Expected confidence_threshold=0.5, got: %f", cfg.ConfidenceThreshold)
	}
	if cfg.Verbose != false {
		t.Errorf("Expected verbose=false, got: %v", cfg.Verbose)
	}
}

func TestLoadConfig_ConfigFile(t *testing.T) {
	// Create temp directory with config file
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	defer os.Chdir(oldDir)
	os.Chdir(tmpDir)

	// Write config file
	configContent := `scan_path: "/test/path"
output_dir: "./custom_reports/"
languages: ["python", "java"]
openai_model: "gpt-4o-mini"
budget_cap: 5.0
confidence_threshold: 0.7
verbose: true
`
	if err := os.WriteFile(".deepguard.yaml", []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// Verify config file values override defaults
	if cfg.ScanPath != "/test/path" {
		t.Errorf("Expected scan_path='/test/path', got: %s", cfg.ScanPath)
	}
	if cfg.OutputDir != "./custom_reports/" {
		t.Errorf("Expected output_dir='./custom_reports/', got: %s", cfg.OutputDir)
	}
	if len(cfg.Languages) != 2 {
		t.Errorf("Expected 2 languages, got: %d", len(cfg.Languages))
	}
	if cfg.OpenAIModel != "gpt-4o-mini" {
		t.Errorf("Expected openai_model='gpt-4o-mini', got: %s", cfg.OpenAIModel)
	}
	if cfg.BudgetCap != 5.0 {
		t.Errorf("Expected budget_cap=5.0, got: %f", cfg.BudgetCap)
	}
	if cfg.ConfidenceThreshold != 0.7 {
		t.Errorf("Expected confidence_threshold=0.7, got: %f", cfg.ConfidenceThreshold)
	}
	if cfg.Verbose != true {
		t.Errorf("Expected verbose=true, got: %v", cfg.Verbose)
	}
}

func TestLoadConfig_EnvironmentVariables(t *testing.T) {
	// Change to temp directory
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	defer os.Chdir(oldDir)
	os.Chdir(tmpDir)

	// Set environment variables
	os.Setenv("DEEPGUARD_OUTPUT_DIR", "/env/output")
	os.Setenv("DEEPGUARD_BUDGET_CAP", "10.5")
	os.Setenv("DEEPGUARD_VERBOSE", "true")
	defer func() {
		os.Unsetenv("DEEPGUARD_OUTPUT_DIR")
		os.Unsetenv("DEEPGUARD_BUDGET_CAP")
		os.Unsetenv("DEEPGUARD_VERBOSE")
	}()

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// Verify environment variables override defaults
	if cfg.OutputDir != "/env/output" {
		t.Errorf("Expected output_dir='/env/output', got: %s", cfg.OutputDir)
	}
	if cfg.BudgetCap != 10.5 {
		t.Errorf("Expected budget_cap=10.5, got: %f", cfg.BudgetCap)
	}
	if cfg.Verbose != true {
		t.Errorf("Expected verbose=true, got: %v", cfg.Verbose)
	}
}

func TestValidate_ValidConfig(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &Config{
		ScanPath:            tmpDir, // Use temp dir as valid path
		OutputDir:           filepath.Join(tmpDir, "reports"),
		Languages:           []string{"js", "python"},
		OpenAIModel:         "gpt-4o",
		BudgetCap:           3.0,
		ConfidenceThreshold: 0.5,
		Verbose:             false,
	}

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate failed for valid config: %v", err)
	}

	// Verify output_dir was created
	if _, err := os.Stat(cfg.OutputDir); os.IsNotExist(err) {
		t.Error("Expected output_dir to be created")
	}
}

func TestValidate_InvalidScanPath(t *testing.T) {
	cfg := &Config{
		ScanPath:            "/nonexistent/path/12345",
		OutputDir:           "./reports/",
		Languages:           []string{"js"},
		OpenAIModel:         "gpt-4o",
		BudgetCap:           3.0,
		ConfidenceThreshold: 0.5,
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected validation error for nonexistent scan_path")
	}
}

func TestValidate_ScanPathIsFile(t *testing.T) {
	// Create a temp file
	tmpFile, err := os.CreateTemp("", "testfile")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	cfg := &Config{
		ScanPath:            tmpFile.Name(),
		OutputDir:           "./reports/",
		Languages:           []string{"js"},
		OpenAIModel:         "gpt-4o",
		BudgetCap:           3.0,
		ConfidenceThreshold: 0.5,
	}

	err = cfg.Validate()
	if err == nil {
		t.Error("Expected validation error when scan_path is a file")
	}
}

func TestValidate_EmptyOutputDir(t *testing.T) {
	cfg := &Config{
		ScanPath:            "",
		OutputDir:           "",
		Languages:           []string{"js"},
		OpenAIModel:         "gpt-4o",
		BudgetCap:           3.0,
		ConfidenceThreshold: 0.5,
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected validation error for empty output_dir")
	}
}

func TestValidate_InvalidLanguage(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &Config{
		ScanPath:            "",
		OutputDir:           tmpDir,
		Languages:           []string{"js", "ruby", "python"}, // ruby is invalid
		OpenAIModel:         "gpt-4o",
		BudgetCap:           3.0,
		ConfidenceThreshold: 0.5,
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected validation error for invalid language")
	}
}

func TestValidate_NoLanguages(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &Config{
		ScanPath:            "",
		OutputDir:           tmpDir,
		Languages:           []string{}, // Empty
		OpenAIModel:         "gpt-4o",
		BudgetCap:           3.0,
		ConfidenceThreshold: 0.5,
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected validation error for empty languages")
	}
}

func TestValidate_InvalidModel(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &Config{
		ScanPath:            "",
		OutputDir:           tmpDir,
		Languages:           []string{"js"},
		OpenAIModel:         "gpt-3.5-turbo", // Invalid
		BudgetCap:           3.0,
		ConfidenceThreshold: 0.5,
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected validation error for invalid model")
	}
}

func TestValidate_NegativeBudgetCap(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &Config{
		ScanPath:            "",
		OutputDir:           tmpDir,
		Languages:           []string{"js"},
		OpenAIModel:         "gpt-4o",
		BudgetCap:           -1.0, // Negative
		ConfidenceThreshold: 0.5,
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected validation error for negative budget_cap")
	}
}

func TestValidate_ZeroBudgetCap(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &Config{
		ScanPath:            "",
		OutputDir:           tmpDir,
		Languages:           []string{"js"},
		OpenAIModel:         "gpt-4o",
		BudgetCap:           0.0, // Zero
		ConfidenceThreshold: 0.5,
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected validation error for zero budget_cap")
	}
}

func TestValidate_ConfidenceThresholdTooLow(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &Config{
		ScanPath:            "",
		OutputDir:           tmpDir,
		Languages:           []string{"js"},
		OpenAIModel:         "gpt-4o",
		BudgetCap:           3.0,
		ConfidenceThreshold: -0.1, // Too low
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected validation error for confidence_threshold < 0")
	}
}

func TestValidate_ConfidenceThresholdTooHigh(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &Config{
		ScanPath:            "",
		OutputDir:           tmpDir,
		Languages:           []string{"js"},
		OpenAIModel:         "gpt-4o",
		BudgetCap:           3.0,
		ConfidenceThreshold: 1.5, // Too high
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected validation error for confidence_threshold > 1.0")
	}
}

func TestValidate_BoundaryValues(t *testing.T) {
	tmpDir := t.TempDir()

	// Test minimum valid confidence_threshold
	cfg := &Config{
		ScanPath:            "",
		OutputDir:           tmpDir,
		Languages:           []string{"js"},
		OpenAIModel:         "gpt-4o",
		BudgetCap:           0.01,
		ConfidenceThreshold: 0.0,
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Confidence 0.0 should be valid: %v", err)
	}

	// Test maximum valid confidence_threshold
	cfg.ConfidenceThreshold = 1.0
	if err := cfg.Validate(); err != nil {
		t.Errorf("Confidence 1.0 should be valid: %v", err)
	}
}

func TestValidate_AllLanguages(t *testing.T) {
	tmpDir := t.TempDir()

	// Test each valid language individually
	validLanguages := []string{"js", "ts", "python", "java"}
	for _, lang := range validLanguages {
		cfg := &Config{
			ScanPath:            "",
			OutputDir:           tmpDir,
			Languages:           []string{lang},
			OpenAIModel:         "gpt-4o",
			BudgetCap:           3.0,
			ConfidenceThreshold: 0.5,
		}
		if err := cfg.Validate(); err != nil {
			t.Errorf("Language '%s' should be valid: %v", lang, err)
		}
	}
}

func TestValidate_BothModels(t *testing.T) {
	tmpDir := t.TempDir()

	// Test gpt-4o
	cfg := &Config{
		ScanPath:            "",
		OutputDir:           tmpDir,
		Languages:           []string{"js"},
		OpenAIModel:         "gpt-4o",
		BudgetCap:           3.0,
		ConfidenceThreshold: 0.5,
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Model 'gpt-4o' should be valid: %v", err)
	}

	// Test gpt-4o-mini
	cfg.OpenAIModel = "gpt-4o-mini"
	if err := cfg.Validate(); err != nil {
		t.Errorf("Model 'gpt-4o-mini' should be valid: %v", err)
	}
}
