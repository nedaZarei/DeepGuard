package main

import (
	"fmt"

	"github.com/Neda-Zarei/deep-guard/internal/config"
	"github.com/Neda-Zarei/deep-guard/internal/logger"
	"github.com/rs/zerolog/log"
)

func main() {
	fmt.Println("DeepGuard v1 - AI-Powered Vulnerability Scanner")

	// Load configuration from all sources
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load configuration")
	}

	// Initialize logger based on config
	logger.InitLogger(cfg.Verbose)

	log.Info().
		Str("component", "scanner").
		Str("operation", "startup").
		Msg("DeepGuard initialized")

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		log.Fatal().
			Err(err).
			Str("component", "config").
			Msg("Invalid configuration")
	}

	log.Info().
		Str("component", "config").
		Msg("Configuration loaded and validated")

	// Display configuration summary
	log.Info().
		Str("component", "config").
		Str("output_dir", cfg.OutputDir).
		Strs("languages", cfg.Languages).
		Str("model", cfg.OpenAIModel).
		Float64("budget_cap", cfg.BudgetCap).
		Float64("confidence_threshold", cfg.ConfidenceThreshold).
		Msg("Configuration summary")

	if cfg.ScanPath != "" {
		log.Info().
			Str("component", "scanner").
			Str("path", cfg.ScanPath).
			Msg("Ready to scan")
	} else {
		log.Info().
			Str("component", "scanner").
			Msg("Ready (use --scan-path to specify target)")
	}
}
