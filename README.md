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

_Coming soon_

## Usage

_Coming soon_

## Contributing

_Coming soon_

## License

_To be determined_
