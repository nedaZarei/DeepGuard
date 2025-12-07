# DeepGuard

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-TBD-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/Build-Passing-success)](https://github.com/Neda-Zarei/deep-guard)

**Fast, AI-powered vulnerability scanner for modern applications**

DeepGuard is a Go-based security scanner that detects vulnerabilities in JavaScript/TypeScript, Python, and Java codebases using AI-powered analysis. It keeps scans fast (<10 minutes) and affordable (<$3 per repository) while providing framework-aware detection.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [Understanding Reports](#understanding-reports)
- [Framework Support](#framework-support)
- [Suppressing False Positives](#suppressing-false-positives)
- [Cost & Performance](#cost--performance)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)
- [How It Works](#how-it-works)
- [Project Structure](#project-structure)

---

## Quick Start

Get started in 3 commands:

```bash
# 1. Set your OpenAI API key
export OPENAI_API_KEY=sk-...

# 2. Build DeepGuard
CGO_ENABLED=1 go build -o deepguard ./cmd/deepguard

# 3. Scan your project
./deepguard scan --path ./your-project --languages js,ts
```

**Sample Output:**

```
DeepGuard Security Scanner - v1.0.0

SCAN METADATA
────────────────────────────────────────────────────────────────────────────────
Target Path                                                  ./your-project
Languages                                                    javascript, typescript
Frameworks                                                   express, @prisma/client
Model Used                                                   gpt-4o

SCAN RESULTS
────────────────────────────────────────────────────────────────────────────────
Total Findings                                               12

  By Severity:
    Critical:                                                8
    High:                                                    4

  Top Vulnerability Types:
    Sql Injection:                                           10
    Xss:                                                     2

SCAN SUMMARY
────────────────────────────────────────────────────────────────────────────────
Total Cost                                                   $2.47
Duration                                                     3m 45s
────────────────────────────────────────────────────────────────────────────────

✅ Report saved to: ./reports/scan-20250107-143022.json
```

---

## Installation

### Prerequisites

- **Go 1.21+** (for local installation)
- **GCC/Clang** (for CGO support required by Tree-sitter)
- **OpenAI API Key** ([Get one here](https://platform.openai.com/api-keys))

### Option 1: Go Install

```bash
# Install from source (requires Go 1.21+)
go install github.com/Neda-Zarei/deep-guard/cmd/deepguard@latest

# Set your API key
export OPENAI_API_KEY=sk-...

# Verify installation
deepguard version
```

### Option 2: Build from Source

```bash
# Clone repository
git clone https://github.com/Neda-Zarei/deep-guard.git
cd deep-guard

# Install dependencies
go mod download

# Build (CGO required for Tree-sitter)
CGO_ENABLED=1 go build -o deepguard ./cmd/deepguard

# Run
./deepguard scan --path ./your-project
```

### Option 3: Docker (Recommended for CI/CD)

```bash
# Clone repository
git clone https://github.com/Neda-Zarei/deep-guard.git
cd deep-guard

# Build Docker image
docker-compose build

# Run scan
docker-compose run --rm deepguard scan --path /workspace --languages js,ts
```

**Docker one-liner:**

```bash
docker run --rm \
  -v /path/to/project:/workspace:ro \
  -v $(pwd)/reports:/app/reports \
  -e OPENAI_API_KEY=$OPENAI_API_KEY \
  -e DEEPGUARD_BUDGET_CAP=3.0 \
  deepguard:latest scan --path /workspace
```

### Platform-Specific Setup

**macOS:**
```bash
# Install Xcode Command Line Tools (for GCC)
xcode-select --install

# Install Go
brew install go
```

**Linux (Debian/Ubuntu):**
```bash
# Install build tools
sudo apt-get update
sudo apt-get install build-essential golang-1.21
```

**Windows:**
```bash
# Install MinGW-w64 for GCC
# Download from: https://www.mingw-w64.org/

# Or use TDM-GCC
# Download from: https://jmeubank.github.io/tdm-gcc/
```

### API Key Setup

DeepGuard requires an OpenAI API key. Set it via environment variable:

```bash
# Temporary (current session only)
export OPENAI_API_KEY=sk-...

# Permanent (add to ~/.bashrc or ~/.zshrc)
echo 'export OPENAI_API_KEY=sk-...' >> ~/.bashrc
source ~/.bashrc
```

---

## Configuration

DeepGuard supports three configuration methods with the following precedence:

**CLI Flags > Environment Variables > Config File > Defaults**

### CLI Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--path` | Directory to scan | `./` |
| `--output` | Report output directory | `./reports` |
| `--languages` | Comma-separated languages | `js,ts,python,java` |
| `--config` | Path to config file | `./.deepguard.yaml` |
| `--verbose` | Enable verbose logging | `false` |
| `--help` | Show help message | - |

**Example:**

```bash
deepguard scan \
  --path ./src \
  --output ./security-reports \
  --languages js,ts \
  --verbose
```

### Config File (.deepguard.yaml)

Create a `.deepguard.yaml` file in your project root:

```yaml
# Target directory to scan
scan_path: "./src"

# Output directory for reports
output_dir: "./reports/"

# Languages to scan (js, ts, python, java)
languages:
  - js
  - ts
  - python

# OpenAI model (gpt-4o or gpt-4o-mini)
openai_model: "gpt-4o"

# Maximum cost per scan in USD
budget_cap: 3.0

# Minimum confidence score (0.0-1.0)
# Findings below this threshold are filtered out
confidence_threshold: 0.5

# Enable verbose logging
verbose: false
```

### Environment Variables

All configuration options can be set via environment variables with the `DEEPGUARD_` prefix:

```bash
export DEEPGUARD_OUTPUT_DIR=./reports
export DEEPGUARD_OPENAI_MODEL=gpt-4o-mini
export DEEPGUARD_BUDGET_CAP=5.0
export DEEPGUARD_CONFIDENCE_THRESHOLD=0.5
export DEEPGUARD_VERBOSE=true
```

**Full Environment Variable Reference:**

| Environment Variable | Config File Key | CLI Flag | Description |
|---------------------|-----------------|----------|-------------|
| `OPENAI_API_KEY` | - | - | OpenAI API key (required) |
| `DEEPGUARD_OUTPUT_DIR` | `output_dir` | `--output` | Report output directory |
| `DEEPGUARD_OPENAI_MODEL` | `openai_model` | - | Model to use (gpt-4o/gpt-4o-mini) |
| `DEEPGUARD_BUDGET_CAP` | `budget_cap` | - | Max cost in USD |
| `DEEPGUARD_CONFIDENCE_THRESHOLD` | `confidence_threshold` | - | Min confidence (0.0-1.0) |
| `DEEPGUARD_VERBOSE` | `verbose` | `--verbose` | Enable verbose logging |

---

## Understanding Reports

DeepGuard generates both terminal summaries and detailed JSON reports.

### Terminal Output

The terminal displays a formatted summary:

```
SCAN METADATA
────────────────────────────────────────────────────────────────────────────────
Target Path                                                  ./your-project
Languages                                                    javascript, typescript
Frameworks                                                   express, @prisma/client
Model Used                                                   gpt-4o

SCAN RESULTS
────────────────────────────────────────────────────────────────────────────────
Total Findings                                               12

  By Severity:
    Critical:                                                8    ← Immediate action required
    High:                                                    4    ← Fix soon

  Top Vulnerability Types:
    Sql Injection:                                           10
    Xss:                                                     2

SCAN SUMMARY
────────────────────────────────────────────────────────────────────────────────
Total Cost                                                   $2.47
Duration                                                     3m 45s
```

### JSON Report

Detailed findings are saved to `./reports/scan-YYYYMMDD-HHMMSS.json`:

```json
{
  "scan_metadata": {
    "timestamp": "2025-01-07T14:30:00+03:30",
    "target_path": "./your-project",
    "languages": ["javascript", "typescript"],
    "frameworks": ["express", "@prisma/client"],
    "model_used": "gpt-4o",
    "total_cost": 2.47,
    "scan_duration_seconds": 225
  },
  "findings": [
    {
      "id": "VULN-001",
      "type": "sql_injection",
      "severity": "critical",
      "confidence": 0.95,
      "file": "src/routes/user.js",
      "line": 42,
      "column": 15,
      "function_name": "getUserById",
      "message": "SQL injection vulnerability: User input directly concatenated into query",
      "recommendation": "Use parameterized queries or an ORM with prepared statements",
      "code_snippet": "const query = 'SELECT * FROM users WHERE id = ' + userId;"
    }
  ],
  "summary": {
    "total_findings": 12,
    "by_severity": {
      "critical": 8,
      "high": 4,
      "medium": 0,
      "low": 0
    },
    "by_type": {
      "sql_injection": 10,
      "xss": 2
    }
  }
}
```

### Finding Fields Explained

| Field | Description |
|-------|-------------|
| `id` | Unique identifier for this finding |
| `type` | Vulnerability type (e.g., `sql_injection`, `xss`, `path_traversal`) |
| `severity` | Risk level: `critical`, `high`, `medium`, `low` |
| `confidence` | AI confidence score (0.0-1.0) - higher is more certain |
| `file` | Path to vulnerable file (relative to scan path) |
| `line` | Line number where vulnerability occurs |
| `function_name` | Function/method containing the vulnerability |
| `message` | Human-readable description of the issue |
| `recommendation` | How to fix the vulnerability |
| `code_snippet` | Excerpt of vulnerable code |

### Confidence Scores

DeepGuard uses AI confidence scores to indicate detection certainty:

- **0.9-1.0**: Very high confidence - likely a real vulnerability
- **0.7-0.9**: High confidence - worth investigating
- **0.5-0.7**: Medium confidence - may be a false positive
- **<0.5**: Low confidence - filtered out by default (adjust with `confidence_threshold`)

---

## Framework Support

DeepGuard automatically detects frameworks in your project and provides framework-specific vulnerability analysis.

### Supported Frameworks

#### JavaScript/TypeScript ✅ Available Now

| Framework | Detection Method | Vulnerability Patterns |
|-----------|-----------------|------------------------|
| **Express** | `package.json` dependencies | SQLi via `req.query`/`req.params`, XSS in templates, path traversal |
| **Prisma** | `package.json` dependencies | Unsafe `$queryRaw`/`$executeRaw`, dynamic table/column names |
| **Sequelize** | `package.json` dependencies | Raw query concatenation, dynamic WHERE clauses |

#### Python 🚧 Coming in M2

| Framework | Detection Method | Planned Support |
|-----------|-----------------|-----------------|
| Django | `requirements.txt` | SQLi in raw queries, XSS in templates, CSRF issues |
| Flask | `requirements.txt` | SQLi, XSS, insecure session handling |
| SQLAlchemy | `requirements.txt` | Raw SQL vulnerabilities, connection security |

#### Java 🚧 Coming in M2

| Framework | Detection Method | Planned Support |
|-----------|-----------------|-----------------|
| Spring Boot | `pom.xml`/`build.gradle` | SQLi in JPA/JDBC, XXE, deserialization |
| JPA/Hibernate | Maven/Gradle | Native query vulnerabilities, HQL injection |

### Framework Detection

DeepGuard automatically detects frameworks by scanning:

- **JavaScript/TypeScript**: `package.json` dependencies
- **Python**: `requirements.txt`, `Pipfile`, `pyproject.toml`
- **Java**: `pom.xml`, `build.gradle`

**Example detection output:**

```
Detected frameworks:
  - javascript: express, @prisma/client, sequelize
  - typescript: express, @prisma/client
```

### Framework-Aware Analysis

When frameworks are detected, DeepGuard:

1. **Loads framework-specific vulnerability patterns** from the knowledge base
2. **Includes framework hints in LLM prompts** (e.g., "Check for req.query concatenation in Express routes")
3. **Adjusts confidence scores** based on framework-specific patterns
4. **Provides framework-specific recommendations** (e.g., "Use Prisma's type-safe queries instead of $queryRaw")

---

## Suppressing False Positives

DeepGuard supports inline comment suppression for false positives.

### Syntax by Language

**JavaScript/TypeScript/Java:**
```javascript
// deepguard:ignore
const query = buildQuery(userInput); // This is actually safe

// Or suppress the next line:
// deepguard:ignore-next-line
db.query(query);
```

**Python:**
```python
# deepguard:ignore
query = build_query(user_input)  # This is sanitized elsewhere

# Or suppress the next line:
# deepguard:ignore-next-line
cursor.execute(query)
```

### Best Practices

Always add a justification comment explaining why the suppression is safe:

```javascript
// deepguard:ignore - userId is validated as integer in middleware
const query = `SELECT * FROM users WHERE id = ${userId}`;
```

**When to suppress:**
- ✅ Input is validated/sanitized elsewhere
- ✅ Code is in a test file with mock data
- ✅ Vulnerability is intentional (e.g., penetration testing tools)

**When NOT to suppress:**
- ❌ "It probably won't be exploited"
- ❌ "We'll fix it later"
- ❌ "Too hard to refactor right now"

### Example: Suppressing Test Code

```javascript
// Test file with intentionally vulnerable code samples
describe('SQL injection detection', () => {
  it('should detect basic SQLi', () => {
    // deepguard:ignore - test sample, not production code
    const vulnQuery = `SELECT * FROM users WHERE id = ${userId}`;
    expect(detectSQLi(vulnQuery)).toBe(true);
  });
});
```

---

## Cost & Performance

DeepGuard is designed to keep scans fast and affordable.

### Cost Expectations

**Typical repository scan costs:**
- **Small repo** (1-5k lines): $0.50-$1.00
- **Medium repo** (5-20k lines): $1.00-$2.50
- **Large repo** (20-50k lines): $2.50-$3.00

**Cost control mechanisms:**
1. **Budget cap**: Default $3.00 per scan (configurable)
2. **Model fallback**: Switches from `gpt-4o` to `gpt-4o-mini` when approaching budget
3. **Token budget enforcement**: Limits KB retrieval to prevent token overuse

### Performance Expectations

**Scan duration:**
- **Small repo**: 1-3 minutes
- **Medium repo**: 3-7 minutes
- **Large repo**: 7-10 minutes

**Factors affecting performance:**
- Number of files/functions analyzed
- OpenAI API response time
- Framework complexity (more frameworks = more targeted analysis)

### Model Fallback

DeepGuard automatically switches models to stay within budget:

```
1. Start with gpt-4o (high accuracy)
2. Monitor cost during scan
3. If approaching $3 cap → switch to gpt-4o-mini
4. Continue with cost-efficient model
```

**Override model selection:**

```bash
# Force gpt-4o-mini for maximum cost savings
export DEEPGUARD_OPENAI_MODEL=gpt-4o-mini

# Increase budget for large repos
export DEEPGUARD_BUDGET_CAP=10.0
```

### Cost Optimization Tips

**Reduce costs by:**

1. **Narrowing language scope:**
   ```bash
   # Scan only JavaScript/TypeScript
   deepguard scan --path . --languages js,ts
   ```

2. **Excluding test directories** (add to `.deepguard.yaml`):
   ```yaml
   exclude_patterns:
     - "**/test/**"
     - "**/tests/**"
     - "**/__tests__/**"
     - "**/*.test.js"
     - "**/*.spec.ts"
   ```

3. **Using lower confidence threshold** (fewer false positives = fewer tokens):
   ```bash
   export DEEPGUARD_CONFIDENCE_THRESHOLD=0.7  # Default: 0.5
   ```

### Token Usage Tracking

DeepGuard displays token usage in terminal output:

```
SCAN SUMMARY
────────────────────────────────────────────────────────────────────────────────
Total Cost                                                   $2.47
Duration                                                     3m 45s
Token Usage                                                  ~125k tokens
Model                                                        gpt-4o
────────────────────────────────────────────────────────────────────────────────
```

---

## Examples

### Basic Scan

Scan current directory with all supported languages:

```bash
./deepguard scan --path .
```

### Language-Specific Scan

Scan only JavaScript and TypeScript files:

```bash
./deepguard scan --path ./src --languages js,ts
```

### Custom Output Directory

Save reports to a custom location:

```bash
./deepguard scan --path . --output ./security-reports/
```

### Verbose Mode

Enable detailed logging for debugging:

```bash
./deepguard scan --path . --verbose
```

**Sample verbose output:**

```
{"level":"info","component":"discovery","message":"Starting framework detection"}
{"level":"debug","component":"parser","language":"javascript","message":"Parsing file: src/app.js"}
{"level":"debug","component":"chunker","message":"Extracted 12 code chunks"}
{"level":"info","component":"analyzer","message":"Analyzing chunk 1/12"}
```

### Scan with Config File

Create `.deepguard.yaml`:

```yaml
scan_path: "./src"
languages: ["js", "ts"]
output_dir: "./security-reports"
budget_cap: 5.0
confidence_threshold: 0.7
```

Run scan:

```bash
./deepguard scan
```

### CI/CD Integration

**GitHub Actions example:**

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'

      - name: Install DeepGuard
        run: |
          git clone https://github.com/Neda-Zarei/deep-guard.git
          cd deep-guard
          CGO_ENABLED=1 go build -o deepguard ./cmd/deepguard

      - name: Run Security Scan
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
          DEEPGUARD_BUDGET_CAP: 3.0
        run: |
          ./deep-guard/deepguard scan --path . --languages js,ts

      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: ./reports/*.json
```

### Docker Example

```bash
# Build image
docker-compose build

# Scan with environment variables
docker-compose run --rm \
  -e DEEPGUARD_BUDGET_CAP=5.0 \
  -e DEEPGUARD_VERBOSE=true \
  deepguard scan --path /workspace --languages js,ts
```

---

## Troubleshooting

### Common Issues

#### 1. "OPENAI_API_KEY not set"

**Problem:** API key environment variable is missing.

**Solution:**
```bash
export OPENAI_API_KEY=sk-your-key-here
```

Verify it's set:
```bash
echo $OPENAI_API_KEY
```

#### 2. "CGO is not enabled"

**Problem:** Tree-sitter requires CGO support.

**Solution:**
```bash
CGO_ENABLED=1 go build -o deepguard ./cmd/deepguard
```

#### 3. "gcc: command not found"

**Problem:** C compiler not installed (required for CGO).

**Solutions:**
- **macOS**: `xcode-select --install`
- **Linux**: `sudo apt-get install build-essential`
- **Windows**: Install MinGW-w64 or TDM-GCC

#### 4. "Permission denied" when running binary

**Problem:** Binary doesn't have execute permissions.

**Solution:**
```bash
chmod +x deepguard
./deepguard scan --path .
```

#### 5. "Failed to parse file"

**Problem:** Syntax errors in source code or unsupported language features.

**Solutions:**
- Verify code compiles/runs normally
- Check if language/version is supported
- Use `--verbose` to see detailed parsing errors
- Report parsing issues on GitHub

#### 6. "Budget cap exceeded"

**Problem:** Scan cost exceeded configured budget.

**Solutions:**
- Increase budget: `export DEEPGUARD_BUDGET_CAP=10.0`
- Use cheaper model: `export DEEPGUARD_OPENAI_MODEL=gpt-4o-mini`
- Narrow scan scope: `--languages js,ts` instead of all languages

#### 7. High number of false positives

**Problem:** Too many low-confidence findings.

**Solutions:**
- Increase confidence threshold: `export DEEPGUARD_CONFIDENCE_THRESHOLD=0.7`
- Review findings manually - some may be legitimate
- Use inline suppression for known false positives
- Report patterns to improve knowledge base

### Getting Help

**Before reporting issues:**
1. Run with `--verbose` to see detailed logs
2. Check if your issue is listed above
3. Verify you're using the latest version: `./deepguard version`

**Report bugs:**
- GitHub Issues: https://github.com/Neda-Zarei/deep-guard/issues
- Include: DeepGuard version, OS, Go version, error message, verbose logs

**Feature requests:**
- GitHub Discussions: https://github.com/Neda-Zarei/deep-guard/discussions

---

## How It Works

DeepGuard combines traditional static analysis with AI-powered detection:

### 1. Code Parsing
Uses Tree-sitter to parse source code into Abstract Syntax Trees (ASTs), extracting function-level chunks for analysis.

### 2. Framework Detection
Scans dependency files (`package.json`, `requirements.txt`, `pom.xml`) to identify frameworks and libraries in use.

### 3. Pattern Retrieval
Searches a local vulnerability knowledge base using BM25 ranking to find relevant vulnerability patterns for each code chunk.

### 4. AI Analysis
Sends code chunks to GPT-4o with:
- Framework-specific prompts
- Retrieved vulnerability patterns
- Language-specific guidance

### 5. Result Aggregation
Collects findings, filters by confidence threshold, and generates both terminal summaries and detailed JSON reports.

### Technology Stack

- **Language**: Go 1.21+
- **Code Parsing**: Tree-sitter (multi-language AST parsing)
- **Search**: Bleve (BM25 ranking for vulnerability pattern retrieval)
- **AI**: OpenAI GPT-4o / GPT-4o-mini
- **Logging**: zerolog (structured JSON logging)
- **Configuration**: Viper (multi-source config management)
- **CLI**: Cobra (command-line interface framework)

---

## Project Structure

```
deep-guard/
├── cmd/
│   └── deepguard/              # Main application entry point
├── internal/                   # Private application code
│   ├── chunker/               # AST-based code chunking
│   ├── config/                # Configuration management
│   ├── discovery/             # Framework detection
│   ├── kb/                    # Vulnerability knowledge base
│   ├── llm/                   # OpenAI integration
│   ├── logger/                # Structured logging
│   ├── parser/                # Tree-sitter parsing
│   ├── report/                # Report generation
│   └── testing/               # Golden test framework
├── test-samples/              # Test code samples
│   └── js-ts-sqli/           # JS/TS SQL injection samples
├── scripts/                   # Utility scripts
├── .deepguard/               # Runtime artifacts (gitignored)
├── reports/                  # Scan reports (gitignored)
├── docker-compose.yml        # Docker Compose configuration
├── Dockerfile                # Docker image definition
└── README.md                 # This file
```

---

## Contributing

We welcome contributions! 

**Areas for contribution:**
- Adding new vulnerability patterns to the knowledge base
- Improving framework detection
- Adding support for new languages/frameworks
- Improving documentation
- Reporting bugs and false positives

---

## Acknowledgments

- **Tree-sitter** - Multi-language parsing library
- **Bleve** - Full-text search and indexing
- **OpenAI** - GPT-4o language models
- **Go Community** - Excellent tooling and libraries

---

**Built with ❤️ for secure code**
