# DeepGuard v1

**Fast, AI-powered vulnerability scanner for modern applications**

## Overview

DeepGuard is a Go-based security vulnerability scanner that leverages artificial intelligence to detect security issues in your codebase. It targets JavaScript/TypeScript, Python, and Java applications with a focus on speed and cost-efficiency—keeping scans under 10 minutes and $3 per repository.

## How It Works

DeepGuard combines traditional static analysis techniques with AI-powered pattern recognition:

1. **Code Parsing**: Uses Tree-sitter to parse source code into function-level chunks
2. **Pattern Matching**: Retrieves relevant vulnerability patterns from a local knowledge base using BM25 search
3. **AI Analysis**: Sends code chunks to GPT-4o for context-aware security analysis
4. **Framework Detection**: Automatically detects frameworks (Express, Django, Spring) to provide targeted prompts
5. **Cost Optimization**: Falls back to gpt-4o-mini if budget caps are exceeded

## Technology Stack

- **Language**: Go 1.21+
- **Code Parsing**: Tree-sitter (multi-language support)
- **Search**: Bleve (BM25 ranking for vulnerability pattern retrieval)
- **AI**: OpenAI GPT-4o / GPT-4o-mini
- **Project Structure**: Standard Go layout (cmd/, internal/, pkg/)

## Project Structure

```
DeepGuard/
├── cmd/
│   └── deepguard/          # Main application entry point
├── internal/               # Private application code
├── pkg/                    # Public library code (future external use)
├── .deepguard/            # Runtime artifacts (gitignored)
├── reports/               # Scan output directory (gitignored)
└── README.md
```

## Installation

### Prerequisites

- **Docker & Docker Compose** (recommended) OR
- **Go 1.21+** with GCC/build tools (for CGO support required by Tree-sitter)

### Option 1: Docker (Recommended)

Docker provides the easiest setup with all dependencies pre-configured:

```bash
# Clone the repository
git clone https://github.com/Neda-Zarei/deep-guard.git
cd deep-guard

# Build the Docker image
docker-compose build

# Run a scan
docker-compose run --rm deepguard scan --path /workspace --languages js,ts,python,java
```

### Option 2: Local Installation

**Requirements:**
- Go 1.21 or higher
- GCC (for CGO support)
  - **Linux**: `sudo apt-get install build-essential` (Debian/Ubuntu)
  - **macOS**: Install Xcode Command Line Tools
  - **Windows**: Install MinGW-w64 or TDM-GCC

```bash
# Clone the repository
git clone https://github.com/Neda-Zarei/deep-guard.git
cd deep-guard

# Install dependencies
go mod download

# Build the application (CGO required for Tree-sitter)
CGO_ENABLED=1 go build -o deepguard ./cmd/deepguard

# Run the scanner
./deepguard scan --path ./your-project
```

## Usage

### Docker Usage

**Basic scan with Docker Compose:**

```bash
# Edit docker-compose.yml to configure your project path and settings
# Then run:
docker-compose up deepguard
```

**One-off scan with custom options:**

```bash
docker run --rm \
  -v /path/to/your/project:/workspace:ro \
  -v $(pwd)/reports:/app/reports \
  -e DEEPGUARD_OPENAI_MODEL=gpt-4o \
  -e DEEPGUARD_BUDGET_CAP=3.0 \
  deepguard:latest scan --path /workspace --languages js,ts,python
```

**Interactive mode:**

```bash
docker-compose --profile interactive run --rm deepguard-interactive
# Inside container:
deepguard scan --path /workspace --verbose
```

### CLI Usage

**Available Commands:**

```bash
# Display help
deepguard --help

# Scan a project
deepguard scan --path ./my-project --languages js,ts,python,java

# Scan with custom output directory
deepguard scan --path ./my-project --output ./security-reports

# Scan with verbose logging
deepguard scan --path ./my-project --verbose

# Filter by specific languages
deepguard scan --path ./my-project --languages js,python

# Display version information
deepguard version

# Validate knowledge base (for KB contributors)
deepguard kb validate
```

### Configuration

DeepGuard supports multiple configuration sources (priority order):

1. **CLI flags** (highest priority)
2. **Environment variables** (prefix: `DEEPGUARD_`)
3. **Config file** (`.deepguard.yaml`)
4. **Default values**

**Example `.deepguard.yaml`:**

```yaml
# Target directory to scan
scan_path: "./src"

# Output directory for reports
output_dir: "./reports/"

# Languages to scan
languages:
  - js
  - ts
  - python
  - java

# OpenAI model (gpt-4o or gpt-4o-mini)
openai_model: "gpt-4o"

# Maximum cost per scan (USD)
budget_cap: 3.0

# Minimum confidence score (0.0-1.0)
confidence_threshold: 0.5

# Enable verbose logging
verbose: false
```

**Environment Variables:**

```bash
export DEEPGUARD_OUTPUT_DIR=./reports
export DEEPGUARD_OPENAI_MODEL=gpt-4o-mini
export DEEPGUARD_BUDGET_CAP=5.0
export DEEPGUARD_VERBOSE=true
```

### Docker Environment Variables

Set in `docker-compose.yml` or pass with `-e`:

```yaml
environment:
  - DEEPGUARD_OUTPUT_DIR=/app/reports
  - DEEPGUARD_OPENAI_MODEL=gpt-4o
  - DEEPGUARD_BUDGET_CAP=3.0
  - DEEPGUARD_CONFIDENCE_THRESHOLD=0.5
  - DEEPGUARD_VERBOSE=false
  - OPENAI_API_KEY=your-api-key-here
```

## Contributing

_Coming soon_

## License

_To be determined_
