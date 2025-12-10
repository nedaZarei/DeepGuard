package redactor

import (
	"regexp"
	"strings"
)

// SecretType represents the category of sensitive data detected
type SecretType string

const (
	SecretTypeAPIKey            SecretType = "api_key"
	SecretTypeAWSKey            SecretType = "aws_key"
	SecretTypePassword          SecretType = "password"
	SecretTypeJWT               SecretType = "jwt_token"
	SecretTypeConnectionString  SecretType = "connection_string"
	SecretTypeBearerToken       SecretType = "bearer_token"
	SecretTypePrivateKey        SecretType = "private_key"
	SecretTypeGenericSecret     SecretType = "generic_secret"
)

// Pattern represents a regex pattern for detecting sensitive data
type Pattern struct {
	Type        SecretType
	Regex       *regexp.Regexp
	Placeholder string
	Description string
}

// All compiled regex patterns for secret detection
var (
	// AWS Access Keys - AKIA[0-9A-Z]{16}
	awsAccessKeyPattern = regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`)

	// AWS Secret Access Keys - 40 characters
	awsSecretKeyPattern = regexp.MustCompile(`\b([A-Za-z0-9/+=]{40})\b`)

	// Generic API keys in assignments (case-insensitive)
	// Matches: api_key = "abc123", apiKey: "xyz789", API_KEY="test123"
	genericAPIKeyPattern = regexp.MustCompile(`(?i)(api[_-]?key|apikey)(['"]?\s*[:=]\s*['"])([a-zA-Z0-9_\-]{16,})(['"])`)

	// Bearer tokens - Authorization: Bearer <token>
	bearerTokenPattern = regexp.MustCompile(`\b(Bearer\s+)([a-zA-Z0-9\-._~+/]+=*)`)

	// JWT tokens - eyJ...eyJ...<signature>
	jwtPattern = regexp.MustCompile(`\b(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\b`)

	// Password in variable assignments
	// Matches: password = "abc", passwd: "xyz", pwd="123"
	passwordVarPattern = regexp.MustCompile(`(?i)(password|passwd|pwd|secret)(['"]?\s*[:=]\s*['"])([^'";\n]{3,})(['"])`)

	// Connection strings with credentials
	// MySQL: mysql://user:pass@host/db
	// PostgreSQL: postgresql://user:pass@host/db
	// MongoDB: mongodb://user:pass@host/db
	connectionStringPattern = regexp.MustCompile(`\b([a-z]+://)([^:]+):([^@]+)@([^\s'"]+)`)

	// Database connection string with password= parameter
	dbPasswordPattern = regexp.MustCompile(`(?i)(password|pwd)=([^\s;'"&]+)`)

	// Private keys (PEM format)
	privateKeyPattern = regexp.MustCompile(`-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----`)

	// Generic secrets in variable names
	// Matches: secret_token = "xyz", secretKey: "abc"
	genericSecretPattern = regexp.MustCompile(`(?i)(secret[_-]?(?:key|token|code))(['"]?\s*[:=]\s*['"])([a-zA-Z0-9_\-]{8,})(['"])`)

	// OAuth tokens and client secrets
	oauthPattern = regexp.MustCompile(`(?i)(client_secret|oauth[_-]?token)(['"]?\s*[:=]\s*['"])([a-zA-Z0-9_\-]{16,})(['"])`)

	// GitHub tokens - ghp_, gho_, ghu_, ghs_, ghr_
	githubTokenPattern = regexp.MustCompile(`\b(gh[pousr]_[a-zA-Z0-9]{36,})\b`)

	// Slack tokens - xox[baprs]-
	slackTokenPattern = regexp.MustCompile(`\b(xox[baprs]-[a-zA-Z0-9-]+)\b`)

	// Environment variable patterns with secrets
	// Matches: process.env.API_KEY, os.getenv("SECRET_KEY")
	envVarSecretPattern = regexp.MustCompile(`(?i)(env|getenv|environ)\[?['"]?(api[_-]?key|secret|token|password)['"]?\]?`)
)

// GetPatterns returns all secret detection patterns
func GetPatterns() []Pattern {
	return []Pattern{
		{
			Type:        SecretTypeAWSKey,
			Regex:       awsAccessKeyPattern,
			Placeholder: "[REDACTED_AWS_ACCESS_KEY]",
			Description: "AWS Access Key ID",
		},
		{
			Type:        SecretTypeAWSKey,
			Regex:       awsSecretKeyPattern,
			Placeholder: "[REDACTED_AWS_SECRET_KEY]",
			Description: "AWS Secret Access Key",
		},
		{
			Type:        SecretTypeAPIKey,
			Regex:       genericAPIKeyPattern,
			Placeholder: "[REDACTED_API_KEY]",
			Description: "Generic API Key",
		},
		{
			Type:        SecretTypeBearerToken,
			Regex:       bearerTokenPattern,
			Placeholder: "[REDACTED_BEARER_TOKEN]",
			Description: "Bearer Token",
		},
		{
			Type:        SecretTypeJWT,
			Regex:       jwtPattern,
			Placeholder: "[REDACTED_JWT_TOKEN]",
			Description: "JWT Token",
		},
		{
			Type:        SecretTypePassword,
			Regex:       passwordVarPattern,
			Placeholder: "[REDACTED_PASSWORD]",
			Description: "Password Variable",
		},
		{
			Type:        SecretTypeConnectionString,
			Regex:       connectionStringPattern,
			Placeholder: "[REDACTED_CONNECTION_STRING]",
			Description: "Database Connection String",
		},
		{
			Type:        SecretTypePassword,
			Regex:       dbPasswordPattern,
			Placeholder: "[REDACTED_PASSWORD]",
			Description: "Database Password Parameter",
		},
		{
			Type:        SecretTypePrivateKey,
			Regex:       privateKeyPattern,
			Placeholder: "[REDACTED_PRIVATE_KEY]",
			Description: "Private Key (PEM)",
		},
		{
			Type:        SecretTypeGenericSecret,
			Regex:       genericSecretPattern,
			Placeholder: "[REDACTED_SECRET]",
			Description: "Generic Secret Variable",
		},
		{
			Type:        SecretTypeAPIKey,
			Regex:       oauthPattern,
			Placeholder: "[REDACTED_OAUTH_TOKEN]",
			Description: "OAuth Token/Client Secret",
		},
		{
			Type:        SecretTypeAPIKey,
			Regex:       githubTokenPattern,
			Placeholder: "[REDACTED_GITHUB_TOKEN]",
			Description: "GitHub Personal Access Token",
		},
		{
			Type:        SecretTypeAPIKey,
			Regex:       slackTokenPattern,
			Placeholder: "[REDACTED_SLACK_TOKEN]",
			Description: "Slack API Token",
		},
	}
}

// IsLikelyFalsePositive checks if a matched string is likely a false positive
func IsLikelyFalsePositive(value string) bool {
	// Common false positive patterns - match whole value only
	falsePositives := []string{
		"your_api_key_here",
		"your-api-key",
		"xxx",
		"placeholder",
		"dummy",
		"test123",
		"password123",
		"changeme",
		"<api_key>",
		"${api_key}",
		"{{api_key}}",
		"$API_KEY",
		"process.env",
		"os.getenv",
	}

	valueLower := strings.ToLower(value)
	for _, fp := range falsePositives {
		if valueLower == strings.ToLower(fp) {
			return true
		}
	}

	// Check for template placeholders
	if strings.HasPrefix(value, "${") || strings.HasPrefix(value, "{{") || strings.HasPrefix(value, "<") {
		return true
	}

	// If value is a short all-uppercase constant name (likely a variable reference, not actual secret)
	// But allow longer ones that might be actual keys
	if regexp.MustCompile(`^[A-Z_]+$`).MatchString(value) && len(value) < 16 {
		return true
	}

	// If value contains only repeated characters (xxx, 111, aaa)
	if len(value) > 0 {
		firstChar := value[0]
		allSame := true
		for i := 1; i < len(value); i++ {
			if value[i] != firstChar {
				allSame = false
				break
			}
		}
		if allSame {
			return true
		}
	}

	return false
}
