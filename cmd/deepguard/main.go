package main

import (
	"fmt"
	"time"

	"github.com/Neda-Zarei/deep-guard/internal/logger"
	"github.com/rs/zerolog/log"
)

func main() {
	// Initialize logger (use --verbose flag in production)
	verbose := false // Set to true to see JSON logs
	logger.InitLogger(verbose)

	fmt.Println("DeepGuard v1 - AI-Powered Vulnerability Scanner")

	// Example: Info-level logging
	log.Info().
		Str("component", "scanner").
		Str("operation", "startup").
		Msg("DeepGuard initialized successfully")

	// Example: Using context helpers
	componentLogger := logger.WithComponent("demo")
	componentLogger.Info().
		Str("status", "ready").
		Msg("Logger system configured")

	// Example: Simulating file processing with timing
	start := time.Now()
	time.Sleep(50 * time.Millisecond) // Simulate work
	duration := time.Since(start).Milliseconds()

	fileLogger := logger.WithContext("parser", "parse_file", "example.js")
	fileLogger.Debug().
		Int64("duration_ms", duration).
		Int("chunks", 3).
		Msg("File parsed successfully")

	log.Info().
		Str("component", "scanner").
		Msg("Ready to scan repositories")
}
