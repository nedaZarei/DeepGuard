# Sensitive Data Redaction

This package provides sensitive data redaction for DeepGuard to protect API keys, passwords, and other secrets before sending code to OpenAI's API.

## Overview

The redactor scans source code for common patterns of sensitive data and replaces them with semantic placeholders like `[REDACTED_API_KEY]` or `[REDACTED_PASSWORD]`. This ensures that actual secrets are not transmitted to external APIs while preserving enough context for vulnerability analysis.

## Supported Secret Types

### API Keys & Tokens
- **AWS Access Keys**: `AKIA[0-9A-Z]{16}`
- **AWS Secret Keys**: 40-character base64 strings
- **Generic API Keys**: `api_key = "abc123..."`
- **GitHub Tokens**: `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` prefixes
- **Slack Tokens**: `xox[baprs]-` format
- **OAuth Tokens**: `client_secret`, `oauth_token` assignments

### Passwords & Credentials
- **Password Variables**: `password = "..."`, `passwd: "..."`, `pwd="..."`
- **Database Passwords**: `password=...` in connection strings
- **Generic Secrets**: `secret_key = "..."`, `secret_token: "..."`

### Tokens
- **JWT Tokens**: Standard `eyJ...eyJ...<signature>` format
- **Bearer Tokens**: `Authorization: Bearer <token>`

### Connection Strings
- **MySQL**: `mysql://user:pass@host/db`
- **PostgreSQL**: `postgresql://user:pass@host/db`
- **MongoDB**: `mongodb://user:pass@host/db`

### Private Keys
- **PEM Format**: `-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----`
- **RSA Keys**: `-----BEGIN RSA PRIVATE KEY-----...`

## Usage

```go
import (
    "github.com/Neda-Zarei/deep-guard/internal/redactor"
    "github.com/rs/zerolog"
)

// Create redactor
log := zerolog.New(os.Stderr)
r := redactor.New(log)

// Redact source code
result := r.Redact(sourceCode, "javascript", "app.js")

// Access redacted source
fmt.Println(result.RedactedSource)

// Check redaction statistics
fmt.Printf("Total redactions: %d\n", result.TotalRedactions)

// Review redaction events
for _, event := range result.Events {
    fmt.Printf("%s:%d - %s (%d chars)\n",
        event.File, event.Line, event.Type, event.OriginalLength)
}
```

## Redaction Strategy

### Full Match Replacement

The redactor replaces **entire matched patterns** rather than just the secret value. This is intentional for safety:

```javascript
// Original
const apiKey = "sk_live_1234567890abcdef";

// Redacted
[REDACTED_API_KEY];
```

While this may seem aggressive, it's safer to over-redact than to risk leaking partial secrets or surrounding context that could aid in reconstruction.

### Language-Aware Comment Filtering

To reduce false positives, the redactor removes comments before pattern matching:

- **JavaScript/TypeScript/Java**: `//` and `/* */` comments removed
- **Python**: `#` comments and docstrings removed

This prevents documentation like "Set your API_KEY here" from triggering redactions.

### False Positive Detection

The redactor automatically skips common false positives:

- Placeholder values: `"your_api_key_here"`, `"example"`, `"dummy"`
- Template variables: `"${API_KEY}"`, `"{{api_key}}"`, `"<api_key>"`
- Environment references: `process.env.API_KEY`, `os.getenv("SECRET")`
- Short constant names: `API_KEY` (less than 16 chars, all uppercase)
- Repeated characters: `"xxx"`, `"111"`, `"aaa"`

## Integration with Chunking Pipeline

The redactor is called **before code chunks are sent to the LLM**:

```
1. Parse source code → AST
2. Extract code chunks (functions)
3. **→ Redact sensitive data**
4. Send redacted chunks to OpenAI
5. Analyze for vulnerabilities
6. Generate report
```

## Redaction Events & Logging

Each redaction is logged at INFO level with:

- File path and line number
- Secret type (api_key, password, jwt, etc.)
- Original pattern length (not the actual value)

Example log entry:

```json
{
  "level": "info",
  "component": "redactor",
  "file": "src/config.js",
  "line": 42,
  "type": "api_key",
  "length": 32,
  "message": "Redacted sensitive data"
}
```

## Performance Impact

Redaction adds minimal overhead:

- **Pattern matching**: Regex operations on source text
- **Comment removal**: Single-pass string manipulation
- **Typical impact**: <1% of total scan time

Benchmarks on 1000-line files show <10ms redaction time.

## Security Trade-offs

### What's Protected

✅ **Actual secret values** are replaced with placeholders
✅ **No secrets sent to OpenAI** or stored in logs
✅ **Audit trail** of what was redacted and where

### What's Not Protected

⚠️ **Code structure** is preserved (variable names, function calls)
⚠️ **Context around secrets** may reveal patterns
⚠️ **Redaction is heuristic** - may miss novel secret formats

### Trust Model

The redactor assumes:

1. **OpenAI's data handling**: We trust OpenAI not to store/train on inputs (per their API terms)
2. **Local processing**: Redaction happens locally before transmission
3. **Best effort**: Redaction is not cryptographically guaranteed - use with appropriate risk awareness

**Recommendation**: Don't scan production code with real secrets. Use DeepGuard on:
- Development environments
- Test codebases
- Code with placeholder secrets
- Pre-production staging

## Examples

### API Key Redaction

```javascript
// Original
const config = {
  apiKey: "sk_live_abcd1234efgh5678ijkl"
};

// Redacted
const config = {
  [REDACTED_API_KEY]
};
```

### Password Redaction

```python
# Original
database = {
    'password': 'SuperSecret123',
    'host': 'localhost'
}

// Redacted
database = {
    [REDACTED_PASSWORD],
    'host': 'localhost'
}
```

### Connection String Redaction

```javascript
// Original
const dbUrl = "postgresql://admin:dbpass456@db.example.com/app";

// Redacted
const dbUrl = "[REDACTED_CONNECTION_STRING]";
```

### JWT Token Redaction

```javascript
// Original
const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

// Redacted
const token = "[REDACTED_JWT_TOKEN]";
```

## Testing

Run redactor tests:

```bash
go test ./internal/redactor/ -v
```

Test specific pattern:

```bash
go test ./internal/redactor/ -run TestRedactAWSKeys -v
```

## Future Enhancements

Potential improvements (not currently implemented):

- Custom pattern configuration (user-defined secrets)
- Redaction reporting in scan output
- Configurable redaction levels (aggressive vs minimal)
- Pattern learning from user feedback
- Integration with secret scanning tools (git-secrets, trufflehog)

## References

- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [GitHub Secret Scanning Patterns](https://docs.github.com/en/code-security/secret-scanning/secret-scanning-patterns)
- [OpenAI API Data Usage Policy](https://openai.com/policies/api-data-usage-policies)
