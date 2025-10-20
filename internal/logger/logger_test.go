package logger

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func TestInitLogger_VerboseMode(t *testing.T) {
	// Capture stderr output
	var buf bytes.Buffer
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	// Initialize logger in verbose mode
	InitLogger(true)

	// Write a test log message
	log.Debug().
		Str("component", "test").
		Str("operation", "test_operation").
		Msg("Test debug message")

	// Restore stderr and capture output
	w.Close()
	os.Stderr = oldStderr
	buf.ReadFrom(r)
	output := buf.String()

	// Verify JSON format
	var logEntry map[string]interface{}
	if err := json.Unmarshal([]byte(output), &logEntry); err != nil {
		t.Errorf("Expected JSON output in verbose mode, got: %s", output)
	}

	// Verify required fields
	if logEntry["level"] != "debug" {
		t.Errorf("Expected level=debug, got: %v", logEntry["level"])
	}
	if logEntry["component"] != "test" {
		t.Errorf("Expected component=test, got: %v", logEntry["component"])
	}
	if logEntry["operation"] != "test_operation" {
		t.Errorf("Expected operation=test_operation, got: %v", logEntry["operation"])
	}
	if logEntry["message"] != "Test debug message" {
		t.Errorf("Expected message='Test debug message', got: %v", logEntry["message"])
	}
	if _, ok := logEntry["time"]; !ok {
		t.Error("Expected timestamp field in verbose mode")
	}
}

func TestInitLogger_StandardMode(t *testing.T) {
	// Capture stderr output
	var buf bytes.Buffer
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	// Initialize logger in standard mode
	InitLogger(false)

	// Write a test log message
	log.Info().
		Str("component", "scanner").
		Msg("Test info message")

	// Debug should not appear in standard mode
	log.Debug().
		Str("component", "parser").
		Msg("Test debug message")

	// Restore stderr and capture output
	w.Close()
	os.Stderr = oldStderr
	buf.ReadFrom(r)
	output := buf.String()

	// Verify console format (not JSON)
	if strings.Contains(output, "{") && strings.Contains(output, "}") {
		t.Errorf("Expected console format, got JSON: %s", output)
	}

	// Verify info message appears
	if !strings.Contains(output, "Test info message") {
		t.Errorf("Expected 'Test info message' in output, got: %s", output)
	}

	// Verify debug message does NOT appear (info level filters it out)
	if strings.Contains(output, "Test debug message") {
		t.Errorf("Debug message should not appear in standard mode, got: %s", output)
	}
}

func TestWithComponent(t *testing.T) {
	logger := WithComponent("parser")

	// Verify logger has component field
	if logger == nil {
		t.Fatal("WithComponent returned nil logger")
	}

	// Test logging with the component logger
	var buf bytes.Buffer
	testLogger := logger.Output(&buf)
	testLogger.Info().Msg("test")

	output := buf.String()
	if !strings.Contains(output, "parser") {
		t.Errorf("Expected 'parser' component in output, got: %s", output)
	}
}

func TestWithFile(t *testing.T) {
	logger := WithFile("src/main.js")

	// Verify logger has file field
	if logger == nil {
		t.Fatal("WithFile returned nil logger")
	}

	// Test logging with the file logger
	var buf bytes.Buffer
	testLogger := logger.Output(&buf)
	testLogger.Info().Msg("test")

	output := buf.String()
	if !strings.Contains(output, "src/main.js") {
		t.Errorf("Expected 'src/main.js' file in output, got: %s", output)
	}
}

func TestWithOperation(t *testing.T) {
	logger := WithOperation("analyze_chunk")

	// Verify logger has operation field
	if logger == nil {
		t.Fatal("WithOperation returned nil logger")
	}

	// Test logging with the operation logger
	var buf bytes.Buffer
	testLogger := logger.Output(&buf)
	testLogger.Info().Msg("test")

	output := buf.String()
	if !strings.Contains(output, "analyze_chunk") {
		t.Errorf("Expected 'analyze_chunk' operation in output, got: %s", output)
	}
}

func TestWithDuration(t *testing.T) {
	durationMs := int64(150)
	logger := WithDuration(durationMs)

	// Verify logger has duration field
	if logger == nil {
		t.Fatal("WithDuration returned nil logger")
	}

	// Test logging with the duration logger
	var buf bytes.Buffer
	testLogger := logger.Output(&buf)
	testLogger.Info().Msg("test")

	output := buf.String()
	if !strings.Contains(output, "150") {
		t.Errorf("Expected '150' duration in output, got: %s", output)
	}
}

func TestWithContext(t *testing.T) {
	logger := WithContext("parser", "parse_file", "src/app.py")

	// Verify logger has all context fields
	if logger == nil {
		t.Fatal("WithContext returned nil logger")
	}

	// Test logging with full context
	var buf bytes.Buffer
	testLogger := logger.Output(&buf)
	testLogger.Info().Msg("test")

	output := buf.String()
	if !strings.Contains(output, "parser") {
		t.Errorf("Expected 'parser' component in output, got: %s", output)
	}
	if !strings.Contains(output, "parse_file") {
		t.Errorf("Expected 'parse_file' operation in output, got: %s", output)
	}
	if !strings.Contains(output, "src/app.py") {
		t.Errorf("Expected 'src/app.py' file in output, got: %s", output)
	}
}

func TestLogLevels(t *testing.T) {
	// Capture output
	var buf bytes.Buffer
	logger := zerolog.New(&buf).With().Timestamp().Logger()

	// Test all log levels
	logger.Debug().Msg("debug message")
	logger.Info().Msg("info message")
	logger.Warn().Msg("warn message")
	logger.Error().Msg("error message")

	output := buf.String()

	// Verify all levels appear
	if !strings.Contains(output, "debug message") {
		t.Error("Debug message not logged")
	}
	if !strings.Contains(output, "info message") {
		t.Error("Info message not logged")
	}
	if !strings.Contains(output, "warn message") {
		t.Error("Warn message not logged")
	}
	if !strings.Contains(output, "error message") {
		t.Error("Error message not logged")
	}
}

func TestErrorLogging(t *testing.T) {
	// Capture output
	var buf bytes.Buffer
	logger := zerolog.New(&buf).With().Timestamp().Logger()

	// Test error logging
	testErr := os.ErrNotExist
	logger.Error().
		Err(testErr).
		Str("component", "parser").
		Str("file", "missing.js").
		Msg("File not found")

	output := buf.String()

	// Verify error context
	if !strings.Contains(output, "file does not exist") {
		t.Errorf("Expected error message in output, got: %s", output)
	}
	if !strings.Contains(output, "missing.js") {
		t.Errorf("Expected file path in output, got: %s", output)
	}
}

func TestTimingContext(t *testing.T) {
	// Simulate operation timing
	start := time.Now()
	time.Sleep(10 * time.Millisecond)
	duration := time.Since(start).Milliseconds()

	// Create logger with duration
	var buf bytes.Buffer
	logger := zerolog.New(&buf).
		With().
		Int64("duration_ms", duration).
		Logger()

	logger.Info().Msg("Operation completed")

	output := buf.String()

	// Verify duration is logged and reasonable
	if !strings.Contains(output, "duration_ms") {
		t.Error("Expected duration_ms field in output")
	}
	// Duration should be at least 10ms
	if duration < 10 {
		t.Errorf("Expected duration >= 10ms, got: %d", duration)
	}
}
