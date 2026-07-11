# DeepGuard

[![CI](https://github.com/Neda-Zarei/deep-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/Neda-Zarei/deep-guard/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**AI-powered static vulnerability scanner for multi-language codebases**

DeepGuard is a Go-based security scanner that detects vulnerabilities in JavaScript/TypeScript, Python, Java, and C/C++ projects. It combines Tree-sitter AST parsing with BM25 knowledge-base retrieval and GPT-4o analysis to produce structured, line-level vulnerability reports.

> This tool was developed as a Master's thesis prototype at Amirkabir University of Technology (AUT).
> Supervisor: Dr. Hamidreza Shahriari.

---

## How It Works

DeepGuard runs a 7-stage pipeline on the target directory:

```
File Discovery → Framework Detection → AST Parsing (Tree-sitter)
    → Function Chunking → BM25 KB Retrieval → LLM Analysis (13 templates)
    → Post-processing → JSON Report
```

1. **File Discovery** — walks the directory, filters by language and `.deepguardignore`
2. **Framework Detection** — reads `package.json`, `requirements.txt`, `pom.xml`, etc.
3. **AST Parsing** — Tree-sitter parses each file into a syntax tree
4. **Function Chunking** — extracts function-level code chunks with absolute line numbers
5. **BM25 Retrieval** — queries a local Bleve index to find relevant KB entries per chunk per vuln type
6. **LLM Analysis** — sends each (chunk, vuln-type, KB context) triple to GPT-4o with a structured prompt; 13 templates × N chunks in parallel across 5 workers
7. **Post-processing** — applies confidence threshold, inline suppression, deduplication, and writes the JSON report

---

## Quick Start

```bash
# 1. Set your OpenAI API key
export OPENAI_API_KEY=sk-...

# 2. Build DeepGuard (CGO required for Tree-sitter)
CGO_ENABLED=1 go build -o deepguard ./cmd/deepguard

# 3. Scan a project
./deepguard scan --path ./your-project --languages js,ts
```

**Sample output:**

```
Discovered 8 files:
  typescript: 5 files
  javascript: 3 files

Parsing files...
Extracted 46 chunks from 8 files

Running vulnerability analysis (this may take a while)...

Scan complete!
  Findings:  49 (critical: 28, high: 19, medium: 2, low: 0)
  Duration:  5m05s
  Cost:      $1.6723
  Report:    ./reports/scan-20260710-143022.json
```

---

## Installation

### Prerequisites

- **Go 1.21+**
- **GCC or Clang** (CGO is required for Tree-sitter)
- **OpenAI API key** ([platform.openai.com/api-keys](https://platform.openai.com/api-keys))

### Build from Source

```bash
git clone https://github.com/Neda-Zarei/deep-guard.git
cd deep-guard
go mod download
CGO_ENABLED=1 go build -o deepguard ./cmd/deepguard
./deepguard version
```

**macOS:** `xcode-select --install` installs the required compiler.  
**Linux:** `sudo apt-get install build-essential golang-1.21`

---

## Language & Vulnerability Support

### JavaScript / TypeScript — full support

Framework detection reads `package.json`. Framework-specific patterns are injected into each prompt.

| Framework | Detected via | Extra guidance in prompts |
|-----------|-------------|--------------------------|
| Express | `package.json` | `req.query` / `req.params` injection, path traversal |
| Prisma | `package.json` | `$queryRaw` / `$executeRaw` misuse |
| Sequelize | `package.json` | raw query concatenation |

**Vulnerability templates:** SQL injection, XSS, command injection, SSRF, path traversal, broken authentication, insecure cryptography, insecure deserialization, XXE

### Python / Java — web vulnerability support

Framework detection reads `requirements.txt` / `pom.xml`. The same 9 web-vulnerability templates run, with generic (non-framework-specific) prompts. Framework-aware prompt tuning for Django, Flask, Spring Boot is listed as future work.

### C / C++ — memory safety support

**Vulnerability templates:** buffer overflow, format string, use-after-free, integer overflow

---

## Configuration

Priority order: **CLI flags → environment variables → config file → defaults**

### CLI flags

```bash
./deepguard scan \
  --path ./src \                    # required: directory to scan
  --output ./reports \              # default: ./reports/
  --languages js,ts \               # default: js,ts,python,java
  --confidence-threshold 0.5 \      # default: 0.5
  --verbose
```

### Config file (`.deepguard.yaml`)

```yaml
scan_path: "./src"
output_dir: "./reports/"
languages: [js, ts]
openai_model: "gpt-4o"        # primary model
budget_cap: 5.0               # USD; switches to gpt-4o-mini at 60% of cap
confidence_threshold: 0.5
verbose: false
```

### Environment variables

```bash
export OPENAI_API_KEY=sk-...
export DEEPGUARD_OPENAI_MODEL=gpt-4o-mini
export DEEPGUARD_BUDGET_CAP=5.0
export DEEPGUARD_CONFIDENCE_THRESHOLD=0.7
export DEEPGUARD_VERBOSE=true
```

---

## Reports

DeepGuard writes a timestamped JSON report to `./reports/scan-YYYYMMDD-HHMMSS.json`:

```json
{
  "scan_metadata": {
    "timestamp": "2026-07-10T14:30:22Z",
    "target_path": "./your-project",
    "languages": ["javascript", "typescript"],
    "frameworks": ["express", "prisma"],
    "model_used": "gpt-4o",
    "total_cost": 1.6723,
    "scan_duration_seconds": 305,
    "filtering": {
      "enabled": true,
      "threshold_used": 0.5,
      "total_findings": 218,
      "filtered_findings": 169,
      "kept_findings": 49
    }
  },
  "findings": [
    {
      "id": "a1b2c3d4-sql_injection-42",
      "type": "sql_injection",
      "severity": "critical",
      "confidence": 0.97,
      "file": "src/routes/user.ts",
      "line": 42,
      "function_name": "getUserById",
      "message": "User input directly concatenated into SQL query via template literal",
      "recommendation": "Use parameterized queries or a type-safe ORM method"
    }
  ],
  "summary": {
    "total_findings": 49,
    "by_severity": { "critical": 28, "high": 19, "medium": 2, "low": 0 },
    "by_type": { "sql_injection": 42, "xss": 4, "path_traversal": 3 }
  }
}
```

### Confidence scores

Each finding carries a confidence score (0–1) from the model:

| Range | Meaning |
|-------|---------|
| 0.9–1.0 | Very high — almost certainly a real vulnerability |
| 0.7–0.9 | High — worth investigating |
| 0.5–0.7 | Medium — possible false positive |
| < 0.5 | Filtered out by default |

The default threshold of 0.5 was chosen as the midpoint of the [0,1] range. Systematic sensitivity analysis across thresholds is left as future work.

---

## Cost & Budget Control

DeepGuard includes a `FallbackManager` that monitors cumulative spend and switches models automatically:

| Phase | Model | Trigger |
|-------|-------|---------|
| Start | `gpt-4o` | — |
| Approaching cap | `gpt-4o-mini` | cost > 60% of `budget_cap` |
| Hard stop | scan terminates | cost ≥ `budget_cap` |

**Observed costs on benchmark data:**

| Dataset | Files | Chunks | Cost | Duration |
|---------|-------|--------|------|----------|
| JS/TS SQLi benchmark (8 files) | 8 | 46 | $1.67 | ~305 s |
| DVNA (Node.js real-world app) | 22 | ~65 | $0.72 | ~189 s |

---

## Suppressing False Positives

Add `// deepguard:ignore` on or above the relevant line:

```javascript
// deepguard:ignore - userId validated as integer in auth middleware
const query = `SELECT * FROM users WHERE id = ${userId}`;
```

```python
# deepguard:ignore-next-line
cursor.execute(raw_query)
```

---

## Auxiliary Commands

Beyond scanning, DeepGuard provides three auxiliary LLM-powered commands:

```bash
# Generate JSDoc / docstrings for all functions in a directory
./deepguard doc --path ./src --output ./docs/

# Generate unit test stubs for undocumented functions
./deepguard testgen --path ./src --output ./tests/

# Generate fix suggestions for an existing scan report
./deepguard fix --report ./reports/scan-20260710-143022.json --output ./fixes/
```

---

## Evaluation Results

Evaluated on two datasets:

### JS/TS SQLi benchmark (`clean-bench-v3`)

42 hand-labelled SQL injection instances across 8 TypeScript files, compared against SonarQube and Semgrep.

| Tool | TP | FP | FN | Precision | Recall | F1 |
|------|----|----|-----|-----------|--------|----|
| **DeepGuard** | **42** | **13** | **0** | **0.764** | **1.000** | **0.866** |
| SonarQube | 0 | 0 | 42 | — | 0.000 | 0.000 |
| Semgrep | 0 | 0 | 42 | — | 0.000 | 0.000 |

*FP breakdown: 13 SQLi findings at incorrect line numbers (cross-line resolution errors); 0 cross-type false positives on the type-constrained benchmark.*

### DVNA (real-world Node.js app)

5 CVEs from the Damn Vulnerable Node Application, type-constrained evaluation.

| Metric | Value |
|--------|-------|
| CVE recall (type-agnostic) | 5/5 = 1.000 |
| Type-constrained TP | 4 |
| Type-constrained FP | 19 |
| Type-constrained FN | 1 |
| Precision | 0.174 |
| F1 | 0.286 |

---

## CI/CD Integration

**GitHub Actions example:**

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: '1.21'

      - name: Build DeepGuard
        run: CGO_ENABLED=1 go build -o deepguard ./cmd/deepguard

      - name: Run Security Scan
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
          DEEPGUARD_BUDGET_CAP: 3.0
        run: ./deepguard scan --path . --languages js,ts

      - name: Upload Report
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: ./reports/*.json
```

---

## Project Structure

```
deep-guard/
├── cmd/deepguard/          # CLI entry point (scan, doc, testgen, fix, kb, version)
├── internal/
│   ├── budget/             # FallbackManager: cost monitoring, model switching
│   ├── cache/              # Result caching layer
│   ├── chunker/            # AST-based function-level code chunking
│   ├── config/             # Configuration (Viper, env vars, YAML, flags)
│   ├── discovery/          # File walker + framework detector
│   ├── integration/        # End-to-end integration tests
│   ├── kb/                 # Knowledge base: schema, Bleve index, 19 KB entries
│   ├── llm/                # OpenAI client, prompt templates (13 vuln types)
│   ├── logger/             # Structured zerolog wrapper
│   ├── orchestrator/       # Worker pool (5 workers), per-type analysis coordinator
│   ├── parser/             # Tree-sitter parser (JS/TS/Python/Java/C/C++)
│   ├── rag/                # BM25 retriever (Bleve), result caching
│   ├── redactor/           # Secret detection and redaction before LLM calls
│   ├── report/             # JSON report schema and writer
│   ├── reporting/          # Confidence filtering, inline suppression
│   └── suppression/        # deepguard:ignore comment parser
├── scripts/
│   ├── smoke-test.sh               # Pattern-based smoke tests (no API required)
│   ├── sonar_comparison.py         # SonarQube vs DeepGuard comparison
│   ├── codexglue_evaluation.py     # CodeXGLUE C/C++ defect detection evaluation
│   └── scalability.py              # Scalability metrics across repo sizes
├── test-samples/           # Labelled vulnerable code for evaluation
├── reports/
│   └── evaluation-metrics/ # Committed benchmark results (JSON)
├── .github/workflows/ci.yml
├── go.mod
└── README.md
```

---

## Troubleshooting

**`OPENAI_API_KEY not set`** — `export OPENAI_API_KEY=sk-...`

**`CGO is not enabled`** — prefix your build command with `CGO_ENABLED=1`

**`gcc: command not found`** — macOS: `xcode-select --install` · Linux: `sudo apt-get install build-essential`

**High false positive count** — raise the confidence threshold: `--confidence-threshold 0.7`

**Budget cap exceeded before scan finishes** — increase cap: `export DEEPGUARD_BUDGET_CAP=10.0`, or narrow scope with `--languages js,ts`

---

## Technology Stack

| Component | Library |
|-----------|---------|
| Language | Go 1.21+ |
| AST parsing | [Tree-sitter](https://tree-sitter.github.io/) (go-tree-sitter) |
| Full-text search | [Bleve](https://blevesearch.com/) (BM25) |
| LLM | OpenAI GPT-4o / GPT-4o-mini |
| CLI | [Cobra](https://github.com/spf13/cobra) |
| Config | [Viper](https://github.com/spf13/viper) |
| Logging | [zerolog](https://github.com/rs/zerolog) |

---

## Acknowledgements

- [Tree-sitter](https://tree-sitter.github.io/) — multi-language parsing
- [Bleve](https://blevesearch.com/) — embedded BM25 search
- [OpenAI](https://openai.com/) — GPT-4o language models
- OWASP Top 10 (2021) and CWE taxonomy for vulnerability classification
