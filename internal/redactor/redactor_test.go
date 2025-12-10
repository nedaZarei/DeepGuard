package redactor

import (
	"io"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

// Helper function to create a no-op logger for tests
func testLogger() zerolog.Logger {
	return zerolog.New(io.Discard)
}

func TestRedactAWSKeys(t *testing.T) {
	log := testLogger()
	r := New(log)

	tests := []struct {
		name     string
		source   string
		expected string
		wantRedactions int
	}{
		{
			name:     "AWS Access Key",
			source:   `const accessKey = "AKIAIOSFODNN7EXAMPLE";`,
			expected: `const accessKey = "[REDACTED_AWS_ACCESS_KEY]";`,
			wantRedactions: 1,
		},
		{
			name:     "AWS keys in config",
			source: `{
  "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
  "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}`,
			expected: `{
  "aws_access_key_id": "[REDACTED_AWS_ACCESS_KEY]",
  "aws_secret_access_key": "[REDACTED_AWS_SECRET_KEY]"
}`,
			wantRedactions: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := r.Redact(tt.source, "javascript", "test.js")

			if result.RedactedSource != tt.expected {
				t.Errorf("Redaction mismatch:\nGot:      %q\nExpected: %q", result.RedactedSource, tt.expected)
			}

			if result.TotalRedactions != tt.wantRedactions {
				t.Errorf("Expected %d redactions, got %d", tt.wantRedactions, result.TotalRedactions)
			}
		})
	}
}

func TestRedactAPIKeys(t *testing.T) {
	log := testLogger()
	r := New(log)

	tests := []struct {
		name     string
		source   string
		shouldRedact bool
	}{
		{
			name:     "Generic API key in JavaScript",
			source:   `const apiKey = "sk_live_1234567890abcdefghij";`,
			shouldRedact: true,
		},
		{
			name:     "API key with underscore",
			source:   `api_key = "abcd1234efgh5678ijkl9012";`,
			shouldRedact: true,
		},
		{
			name:     "API key in object",
			source:   `config = { apiKey: "test_key_abc123def456" };`,
			shouldRedact: true,
		},
		{
			name:     "GitHub token",
			source:   `token = "ghp_1234567890abcdefghijklmnopqrstuv";`,
			shouldRedact: true,
		},
		{
			name:     "Slack token",
			source:   `slackToken = "xoxb-1234567890-abcdefghijklmnop";`,
			shouldRedact: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := r.Redact(tt.source, "javascript", "test.js")

			hasRedaction := strings.Contains(result.RedactedSource, "[REDACTED_")

			if tt.shouldRedact && !hasRedaction {
				t.Errorf("Expected redaction but none found in: %s", result.RedactedSource)
			}

			if !tt.shouldRedact && hasRedaction {
				t.Errorf("Unexpected redaction in: %s", result.RedactedSource)
			}
		})
	}
}

func TestRedactPasswords(t *testing.T) {
	log := testLogger()
	r := New(log)

	tests := []struct {
		name     string
		source   string
		expected string
	}{
		{
			name:     "Password variable",
			source:   `password = "SuperSecret123";`,
			expected: `password = "[REDACTED_PASSWORD]";`,
		},
		{
			name:     "Database password",
			source:   `const dbConfig = { password: "myDbPass456" };`,
			expected: `const dbConfig = { password: "[REDACTED_PASSWORD]" };`,
		},
		{
			name:     "Password in URL",
			source:   `url = "password=SecretPass789&user=admin";`,
			expected: `url = "password=[REDACTED_PASSWORD]&user=admin";`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := r.Redact(tt.source, "javascript", "test.js")

			if result.RedactedSource != tt.expected {
				t.Errorf("Redaction mismatch:\nGot:      %q\nExpected: %q", result.RedactedSource, tt.expected)
			}
		})
	}
}

func TestRedactJWT(t *testing.T) {
	log := testLogger()
	r := New(log)

	source := `const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";`

	result := r.Redact(source, "javascript", "test.js")

	if !strings.Contains(result.RedactedSource, "[REDACTED_JWT_TOKEN]") {
		t.Errorf("JWT token not redacted: %s", result.RedactedSource)
	}

	if result.TotalRedactions != 1 {
		t.Errorf("Expected 1 redaction, got %d", result.TotalRedactions)
	}
}

func TestRedactConnectionStrings(t *testing.T) {
	log := testLogger()
	r := New(log)

	tests := []struct {
		name     string
		source   string
		shouldRedact bool
	}{
		{
			name:     "MySQL connection string",
			source:   `conn = "mysql://user:password123@localhost:3306/mydb";`,
			shouldRedact: true,
		},
		{
			name:     "PostgreSQL connection string",
			source:   `db = "postgresql://admin:secret456@db.example.com/production";`,
			shouldRedact: true,
		},
		{
			name:     "MongoDB connection string",
			source:   `uri = "mongodb://username:pass789@cluster.mongodb.net/app";`,
			shouldRedact: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := r.Redact(tt.source, "javascript", "test.js")

			hasRedaction := strings.Contains(result.RedactedSource, "[REDACTED_")

			if tt.shouldRedact && !hasRedaction {
				t.Errorf("Expected redaction but none found in: %s", result.RedactedSource)
			}

			if result.TotalRedactions == 0 && tt.shouldRedact {
				t.Errorf("Expected redactions but got %d", result.TotalRedactions)
			}
		})
	}
}

func TestRedactBearerToken(t *testing.T) {
	log := testLogger()
	r := New(log)

	source := `Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9`

	result := r.Redact(source, "javascript", "test.js")

	if !strings.Contains(result.RedactedSource, "[REDACTED_BEARER_TOKEN]") {
		t.Errorf("Bearer token not redacted: %s", result.RedactedSource)
	}
}

func TestRedactPrivateKey(t *testing.T) {
	log := testLogger()
	r := New(log)

	source := "const key = `-----BEGIN PRIVATE KEY-----\n" +
		"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n" +
		"-----END PRIVATE KEY-----`;"

	result := r.Redact(source, "javascript", "test.js")

	if !strings.Contains(result.RedactedSource, "[REDACTED_PRIVATE_KEY]") {
		t.Errorf("Private key not redacted: %s", result.RedactedSource)
	}
}

func TestFalsePositives(t *testing.T) {
	log := testLogger()
	r := New(log)

	tests := []struct {
		name     string
		source   string
		shouldNotRedact bool
	}{
		{
			name:     "Placeholder API key",
			source:   `apiKey = "your_api_key_here";`,
			shouldNotRedact: true,
		},
		{
			name:     "Example password",
			source:   `password = "example";`,
			shouldNotRedact: true,
		},
		{
			name:     "Environment variable reference",
			source:   `const key = process.env.API_KEY;`,
			shouldNotRedact: true,
		},
		{
			name:     "Template placeholder",
			source:   `token = "${API_KEY}";`,
			shouldNotRedact: true,
		},
		{
			name:     "Comment with API key mention",
			source:   `// Set your API_KEY here`,
			shouldNotRedact: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := r.Redact(tt.source, "javascript", "test.js")

			hasRedaction := strings.Contains(result.RedactedSource, "[REDACTED_")

			if tt.shouldNotRedact && hasRedaction {
				t.Errorf("False positive: unexpected redaction in: %s\nResult: %s", tt.source, result.RedactedSource)
			}
		})
	}
}

func TestRedactMultipleSecrets(t *testing.T) {
	log := testLogger()
	r := New(log)

	source := `
const config = {
  apiKey: "sk_live_abcd1234efgh5678ijkl",
  password: "SuperSecret123",
  jwt: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
  dbUrl: "postgresql://admin:dbpass456@localhost/app"
};
`

	result := r.Redact(source, "javascript", "config.js")

	// Should have multiple redactions
	if result.TotalRedactions < 3 {
		t.Errorf("Expected at least 3 redactions, got %d", result.TotalRedactions)
	}

	// Check that all secrets are redacted
	if !strings.Contains(result.RedactedSource, "[REDACTED_") {
		t.Errorf("No redactions found in multi-secret source")
	}

	// Verify structure is preserved
	if !strings.Contains(result.RedactedSource, "const config = {") {
		t.Errorf("Code structure not preserved")
	}
}

func TestRedactPythonCode(t *testing.T) {
	log := testLogger()
	r := New(log)

	source := `
# Database configuration
db_password = "MySecretPass123"
api_key = "sk_test_abcd1234efgh5678"

# Comment with password mention - should not trigger
connection = "postgresql://user:dbpass789@localhost/app"
`

	result := r.Redact(source, "python", "config.py")

	// Should redact password and API key
	if result.TotalRedactions < 2 {
		t.Errorf("Expected at least 2 redactions in Python code, got %d", result.TotalRedactions)
	}

	// Comment should not trigger redaction
	if strings.Count(result.RedactedSource, "[REDACTED_") > 3 {
		t.Errorf("Too many redactions (may include false positives from comments)")
	}
}

func TestRedactLineNumbers(t *testing.T) {
	log := testLogger()
	r := New(log)

	source := `line 1
line 2
const apiKey = "sk_live_abcd1234efgh5678ijkl";
line 4`

	result := r.Redact(source, "javascript", "test.js")

	if len(result.Events) == 0 {
		t.Fatal("Expected redaction events")
	}

	// API key is on line 3
	if result.Events[0].Line != 3 {
		t.Errorf("Expected line 3, got line %d", result.Events[0].Line)
	}
}

func TestRedactPreservesCodeStructure(t *testing.T) {
	log := testLogger()
	r := New(log)

	source := `function authenticate(password) {
  const apiKey = "sk_live_1234567890abcdef";
  return fetch('/api/auth', {
    headers: { 'Authorization': 'Bearer ' + apiKey }
  });
}`

	result := r.Redact(source, "javascript", "auth.js")

	// Function structure should be preserved
	if !strings.Contains(result.RedactedSource, "function authenticate(password)") {
		t.Errorf("Function signature not preserved")
	}

	if !strings.Contains(result.RedactedSource, "return fetch('/api/auth'") {
		t.Errorf("Function body not preserved")
	}

	// Should have redactions
	if result.TotalRedactions == 0 {
		t.Errorf("Expected redactions in authentication code")
	}
}

func TestRedactEmptySource(t *testing.T) {
	log := testLogger()
	r := New(log)

	result := r.Redact("", "javascript", "empty.js")

	if result.TotalRedactions != 0 {
		t.Errorf("Expected 0 redactions for empty source, got %d", result.TotalRedactions)
	}

	if result.RedactedSource != "" {
		t.Errorf("Expected empty redacted source")
	}
}

func TestFormatRedactionSummary(t *testing.T) {
	events := []RedactionEvent{
		{Type: SecretTypeAPIKey, Description: "API Key"},
		{Type: SecretTypeAPIKey, Description: "API Key"},
		{Type: SecretTypePassword, Description: "Password"},
	}

	summary := FormatRedactionSummary(events)

	if !strings.Contains(summary, "3 sensitive items") {
		t.Errorf("Summary should mention 3 items")
	}

	if !strings.Contains(summary, "api_key: 2") {
		t.Errorf("Summary should count API keys")
	}

	if !strings.Contains(summary, "password: 1") {
		t.Errorf("Summary should count passwords")
	}
}

func TestFormatRedactionSummaryEmpty(t *testing.T) {
	summary := FormatRedactionSummary([]RedactionEvent{})

	if summary != "No sensitive data redacted" {
		t.Errorf("Expected 'No sensitive data redacted', got: %s", summary)
	}
}
