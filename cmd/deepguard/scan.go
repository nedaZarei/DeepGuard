package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/Neda-Zarei/deep-guard/internal/config"
	"github.com/Neda-Zarei/deep-guard/internal/logger"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a directory for security vulnerabilities",
	Long: `Scan analyzes source code in the target directory for security vulnerabilities
using AI-powered analysis with GPT-4o.

The scanner parses code into function-level chunks, retrieves relevant vulnerability
patterns from the knowledge base, and performs intelligent security analysis.`,
	Example: `  # Basic scan
  deepguard scan --path ./my-project

  # Scan with custom output directory
  deepguard scan --path ./my-project --output ./security-reports

  # Scan specific languages only
  deepguard scan --path ./my-project --languages js,ts

  # Scan with verbose logging
  deepguard scan --path ./my-project --verbose`,
	PreRunE: validateScanFlags,
	RunE:    runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)

	// Required flags
	scanCmd.Flags().StringP("path", "p", "", "target directory to scan (required)")
	scanCmd.MarkFlagRequired("path")

	// Optional flags
	scanCmd.Flags().StringP("output", "o", "./reports/", "output directory for scan reports")
	scanCmd.Flags().StringSliceP("languages", "l", []string{"js", "ts", "python", "java"}, "languages to scan (comma-separated)")

	// Bind flags to viper config keys
	viper.BindPFlag("scan_path", scanCmd.Flags().Lookup("path"))
	viper.BindPFlag("output_dir", scanCmd.Flags().Lookup("output"))
	viper.BindPFlag("languages", scanCmd.Flags().Lookup("languages"))
}

// validateScanFlags validates all scan command flags before execution
func validateScanFlags(cmd *cobra.Command, args []string) error {
	// Get values from viper (which has flag bindings from init())
	scanPath := viper.GetString("scan_path")
	outputDir := viper.GetString("output_dir")
	languages := viper.GetStringSlice("languages")
	verbose := viper.GetBool("verbose")

	// Re-initialize logger with updated verbose flag
	logger.InitLogger(verbose)

	log.Debug().
		Str("component", "cli").
		Str("operation", "validate_flags").
		Str("scan_path", scanPath).
		Msg("Validating scan flags")

	// Validate scan_path exists and is a directory
	if scanPath == "" {
		return fmt.Errorf("--path flag is required")
	}

	info, err := os.Stat(scanPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("scan path does not exist: %s", scanPath)
		}
		return fmt.Errorf("cannot access scan path: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("scan path must be a directory: %s", scanPath)
	}

	log.Debug().
		Str("component", "cli").
		Str("path", scanPath).
		Msg("Scan path validated")

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	log.Debug().
		Str("component", "cli").
		Str("output_dir", outputDir).
		Msg("Output directory ready")

	// Validate languages
	validLanguages := map[string]bool{
		"js":     true,
		"ts":     true,
		"python": true,
		"java":   true,
	}

	filteredLanguages := []string{}
	for _, lang := range languages {
		lang = strings.TrimSpace(strings.ToLower(lang))
		if validLanguages[lang] {
			filteredLanguages = append(filteredLanguages, lang)
		} else {
			log.Warn().
				Str("component", "cli").
				Str("language", lang).
				Msg("Skipping invalid language")
		}
	}

	if len(filteredLanguages) == 0 {
		return fmt.Errorf("no valid languages specified (must be one of: js, ts, python, java)")
	}

	log.Debug().
		Str("component", "cli").
		Strs("languages", filteredLanguages).
		Msg("Languages validated")

	// Rebuild config from validated values
	var loadErr error
	cfg, loadErr = config.LoadConfig()
	if loadErr != nil {
		return fmt.Errorf("failed to load configuration: %w", loadErr)
	}

	// Override with validated flag values
	cfg.ScanPath = scanPath
	cfg.OutputDir = outputDir
	cfg.Languages = filteredLanguages
	cfg.Verbose = verbose

	// Run full config validation
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	return nil
}

// runScan executes the vulnerability scan
func runScan(cmd *cobra.Command, args []string) error {
	log.Info().
		Str("component", "scanner").
		Str("operation", "scan_start").
		Str("path", cfg.ScanPath).
		Msg("Starting vulnerability scan")

	log.Info().
		Str("component", "config").
		Str("output_dir", cfg.OutputDir).
		Strs("languages", cfg.Languages).
		Str("model", cfg.OpenAIModel).
		Float64("budget_cap", cfg.BudgetCap).
		Float64("confidence_threshold", cfg.ConfidenceThreshold).
		Msg("Scan configuration")

	// TODO: Wire to scanning pipeline
	// This will be implemented in the File Discovery Engine and subsequent tasks
	log.Info().
		Str("component", "scanner").
		Msg("Scan pipeline not yet implemented - this is a stub")

	log.Info().
		Str("component", "scanner").
		Str("operation", "scan_complete").
		Msg("Scan completed successfully")

	fmt.Printf("\nScan completed! Results will be written to: %s\n", cfg.OutputDir)

	return nil
}
