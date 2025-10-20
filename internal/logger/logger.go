package logger

import (
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// InitLogger initializes the global logger with the specified verbosity level.
// In verbose mode, logs are output as JSON to stderr with all context fields.
// In standard mode, logs use a human-friendly console format without timestamps.
//
// All logs are written to stderr to keep stdout clean for terminal reports.
// Debug-level logs are only visible in verbose mode.
func InitLogger(verbose bool) {
	// All logs go to stderr
	zerolog.TimeFieldFormat = time.RFC3339

	if verbose {
		// Verbose mode: JSON-formatted logs with all fields
		log.Logger = zerolog.New(os.Stderr).
			With().
			Timestamp().
			Logger().
			Level(zerolog.DebugLevel)
	} else {
		// Standard mode: Human-friendly console output
		output := zerolog.ConsoleWriter{
			Out:        os.Stderr,
			TimeFormat: "15:04:05",
			NoColor:    false,
		}
		log.Logger = zerolog.New(output).
			With().
			Timestamp().
			Logger().
			Level(zerolog.InfoLevel)
	}
}

// WithComponent returns a logger with the component context field set.
// The component represents the module/package name (e.g., "parser", "analyzer", "reporter").
//
// Example:
//
//	logger := WithComponent("parser")
//	logger.Info().Msg("Starting parse operation")
func WithComponent(component string) *zerolog.Logger {
	logger := log.With().Str("component", component).Logger()
	return &logger
}

// WithFile returns a logger with the file context field set.
// Use this when logging operations related to specific files.
//
// Example:
//
//	logger := WithFile("src/main.js")
//	logger.Debug().Msg("Parsing file")
func WithFile(filePath string) *zerolog.Logger {
	logger := log.With().Str("file", filePath).Logger()
	return &logger
}

// WithOperation returns a logger with the operation context field set.
// The operation represents the specific function/action being performed.
//
// Example:
//
//	logger := WithOperation("analyze_chunk")
//	logger.Info().Msg("Analysis complete")
func WithOperation(operation string) *zerolog.Logger {
	logger := log.With().Str("operation", operation).Logger()
	return &logger
}

// WithDuration returns a logger with the duration context field set.
// Duration should be provided in milliseconds for consistency.
//
// Example:
//
//	start := time.Now()
//	// ... perform operation ...
//	logger := WithDuration(time.Since(start).Milliseconds())
//	logger.Info().Msg("Operation completed")
func WithDuration(durationMs int64) *zerolog.Logger {
	logger := log.With().Int64("duration_ms", durationMs).Logger()
	return &logger
}

// WithContext returns a logger with multiple context fields set at once.
// This is a convenience function for setting component, operation, and file together.
//
// Example:
//
//	logger := WithContext("parser", "parse_file", "src/main.js")
//	logger.Debug().Int("chunks", 5).Msg("File parsed successfully")
func WithContext(component, operation, filePath string) *zerolog.Logger {
	logger := log.With().
		Str("component", component).
		Str("operation", operation).
		Str("file", filePath).
		Logger()
	return &logger
}

// Logging Guidelines:
//
// Log Levels:
// - Debug: Verbose operational details (file processing, chunk creation, API interactions)
//   Only visible in verbose mode (--verbose flag)
// - Info: High-level progress (scan phases, milestones, completion)
//   Visible in both modes
// - Warn: Recoverable issues (skipped files, parsing failures, model fallback)
//   Visible in both modes
// - Error: Critical failures (API exhaustion, unrecoverable errors)
//   Visible in both modes
//
// Required Context Fields:
// - component: Module/package name (e.g., "parser", "analyzer", "reporter")
// - operation: Specific function/action (e.g., "parse_file", "analyze_chunk")
// - file: File path being processed (when applicable)
// - duration_ms: Operation timing in milliseconds (when applicable)
//
// Usage Examples:
//
//	// Info-level: High-level progress
//	log.Info().
//		Str("component", "scanner").
//		Str("operation", "scan_start").
//		Str("path", targetPath).
//		Msg("Starting vulnerability scan")
//
//	// Debug-level: Detailed operation
//	log.Debug().
//		Str("component", "parser").
//		Str("file", filePath).
//		Int("chunks", len(chunks)).
//		Msg("File parsed successfully")
//
//	// Warn-level: Recoverable issue
//	log.Warn().
//		Str("component", "parser").
//		Str("file", filePath).
//		Err(err).
//		Msg("Skipping unparseable file")
//
//	// Error-level: Critical failure
//	log.Error().
//		Str("component", "analyzer").
//		Str("operation", "api_call").
//		Err(err).
//		Msg("OpenAI API call failed after retries")
