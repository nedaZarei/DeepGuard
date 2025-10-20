package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

// Config holds all configuration for DeepGuard scanner.
// Configuration is loaded from multiple sources with the following precedence:
//  1. CLI flags (highest priority) - handled by Cobra
//  2. Config file (.deepguard.yaml)
//  3. Environment variables (DEEPGUARD_ prefix)
//  4. Default values (lowest priority)
type Config struct {
	// ScanPath is the target directory to scan for vulnerabilities
	ScanPath string `mapstructure:"scan_path"`

	// OutputDir is the directory where scan reports will be written
	OutputDir string `mapstructure:"output_dir"`

	// Languages is the list of programming languages to scan
	// Valid values: "js", "ts", "python", "java"
	Languages []string `mapstructure:"languages"`

	// OpenAIModel is the OpenAI model to use for analysis
	// Valid values: "gpt-4o", "gpt-4o-mini"
	OpenAIModel string `mapstructure:"openai_model"`

	// BudgetCap is the maximum cost in USD for a single scan
	// Must be a positive float
	BudgetCap float64 `mapstructure:"budget_cap"`

	// ConfidenceThreshold is the minimum confidence score (0.0-1.0) for reporting findings
	// Findings with lower confidence will be filtered out
	ConfidenceThreshold float64 `mapstructure:"confidence_threshold"`

	// Verbose enables detailed JSON logging to stderr
	Verbose bool `mapstructure:"verbose"`
}

// LoadConfig loads configuration from all sources in order of precedence:
// defaults -> config file -> environment variables -> CLI flags (set by Cobra).
//
// It searches for .deepguard.yaml in:
//  1. Current directory
//  2. Parent directories (walking up the tree)
//  3. User home directory
//
// If no config file is found, it uses default values.
// Environment variables must be prefixed with DEEPGUARD_ (e.g., DEEPGUARD_OUTPUT_DIR).
func LoadConfig() (*Config, error) {
	v := viper.New()

	// Set default values
	setDefaults(v)

	// Configure config file search
	v.SetConfigName(".deepguard")
	v.SetConfigType("yaml")

	// Search in current directory
	v.AddConfigPath(".")

	// Search in parent directories
	currentDir, err := os.Getwd()
	if err == nil {
		dir := currentDir
		for {
			v.AddConfigPath(dir)
			parent := filepath.Dir(dir)
			if parent == dir {
				break // Reached root
			}
			dir = parent
		}
	}

	// Search in user home directory
	if home, err := os.UserHomeDir(); err == nil {
		v.AddConfigPath(home)
	}

	// Read config file (ignore error if not found)
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
		// Config file not found is OK, we'll use defaults
	}

	// Bind environment variables
	v.SetEnvPrefix("DEEPGUARD")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Unmarshal config into struct
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}

// setDefaults sets default values for all configuration fields.
func setDefaults(v *viper.Viper) {
	v.SetDefault("scan_path", "")
	v.SetDefault("output_dir", "./reports/")
	v.SetDefault("languages", []string{"js", "ts", "python", "java"})
	v.SetDefault("openai_model", "gpt-4o")
	v.SetDefault("budget_cap", 3.0)
	v.SetDefault("confidence_threshold", 0.5)
	v.SetDefault("verbose", false)
}

// Validate checks that all configuration values are valid.
// Returns an error describing the first validation failure encountered.
func (c *Config) Validate() error {
	// Validate scan_path if provided
	if c.ScanPath != "" {
		info, err := os.Stat(c.ScanPath)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("scan_path does not exist: %s", c.ScanPath)
			}
			return fmt.Errorf("cannot access scan_path: %w", err)
		}
		if !info.IsDir() {
			return fmt.Errorf("scan_path must be a directory: %s", c.ScanPath)
		}
	}

	// Validate output_dir (create if missing)
	if c.OutputDir == "" {
		return fmt.Errorf("output_dir cannot be empty")
	}
	if err := os.MkdirAll(c.OutputDir, 0755); err != nil {
		return fmt.Errorf("cannot create output_dir: %w", err)
	}

	// Validate languages
	validLanguages := map[string]bool{
		"js":     true,
		"ts":     true,
		"python": true,
		"java":   true,
	}
	if len(c.Languages) == 0 {
		return fmt.Errorf("at least one language must be specified")
	}
	for _, lang := range c.Languages {
		if !validLanguages[lang] {
			return fmt.Errorf("invalid language: %s (must be one of: js, ts, python, java)", lang)
		}
	}

	// Validate openai_model
	if c.OpenAIModel != "gpt-4o" && c.OpenAIModel != "gpt-4o-mini" {
		return fmt.Errorf("invalid openai_model: %s (must be gpt-4o or gpt-4o-mini)", c.OpenAIModel)
	}

	// Validate budget_cap
	if c.BudgetCap <= 0 {
		return fmt.Errorf("budget_cap must be positive, got: %f", c.BudgetCap)
	}

	// Validate confidence_threshold
	if c.ConfidenceThreshold < 0.0 || c.ConfidenceThreshold > 1.0 {
		return fmt.Errorf("confidence_threshold must be between 0.0 and 1.0, got: %f", c.ConfidenceThreshold)
	}

	return nil
}

// GetConfigFilePath returns the path to the config file if one was loaded.
// Returns empty string if no config file was found.
func GetConfigFilePath() string {
	return viper.ConfigFileUsed()
}
