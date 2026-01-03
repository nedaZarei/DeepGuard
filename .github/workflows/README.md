# GitHub Actions CI Workflow

This directory contains the GitHub Actions workflow configuration for DeepGuard's continuous integration pipeline.

## CI Workflow (`ci.yml`)

The CI workflow automatically runs on:
- **Push events** to `main` and `develop` branches
- **Pull requests** targeting `main` and `develop` branches

### Workflow Steps

1. **Checkout code** - Checks out the repository code
2. **Set up Go** - Installs Go 1.21 with dependency caching enabled
3. **Download dependencies** - Fetches Go module dependencies
4. **Check formatting** - Verifies all Go code is properly formatted with `gofmt`
5. **Run go vet** - Performs static analysis to catch suspicious constructs
6. **Validate Knowledge Base** - Validates KB YAML schema and checks for duplicate IDs
7. **Run tests with coverage** - Executes unit tests with race detection and generates coverage report
8. **Upload coverage report** - Uploads `coverage.out` as a workflow artifact (7-day retention)
9. **Build binary** - Compiles the DeepGuard binary for linux-amd64
10. **Upload binary artifact** - Uploads the compiled binary as a workflow artifact (7-day retention)
11. **Display build info** - Shows binary details and version information

### Environment Requirements

- **Go Version**: 1.21+
- **CGO**: Enabled (required for Tree-sitter integration)
- **Platform**: Ubuntu latest (linux-amd64)

### Artifacts

The workflow produces two artifacts:

1. **coverage-report** - Code coverage data (`coverage.out`)
   - Retention: 7 days
   - Format: Go coverage profile

2. **deepguard-linux-amd64** - Compiled binary
   - Retention: 7 days
   - Architecture: linux-amd64
   - Can be downloaded and tested from workflow run page

### Quality Checks

The workflow enforces the following quality standards:

- ✅ All code must be formatted with `gofmt -s`
- ✅ No issues reported by `go vet`
- ✅ Knowledge Base YAML files must be valid and have no duplicate IDs
- ✅ All unit tests must pass
- ✅ Race conditions are detected and prevented
- ✅ Binary must compile successfully

### Viewing Results

1. Navigate to the **Actions** tab in the GitHub repository
2. Select the CI workflow run you want to inspect
3. View the step-by-step execution log
4. Download artifacts from the workflow run page

### Local Testing

To verify your changes will pass CI before pushing:

```bash
# Check formatting
gofmt -s -l .

# Format all files
gofmt -s -w .

# Run go vet
go vet ./...

# Validate Knowledge Base
CGO_ENABLED=1 go run ./cmd/deepguard kb validate --kb-path ./internal/kb/data/

# Run tests with coverage
CGO_ENABLED=1 go test -v -race -coverprofile=coverage.out -covermode=atomic ./...

# Build binary
CGO_ENABLED=1 go build -o deepguard ./cmd/deepguard

# Test binary
./deepguard version
```

### Troubleshooting

**Formatting failures:**
- Run `gofmt -s -w .` to auto-format all Go files
- Commit the formatted changes

**Go vet warnings:**
- Review the reported issues
- Fix suspicious constructs or add justification comments

**KB validation failures:**
- Check YAML syntax in `internal/kb/data/*.yaml` files
- Ensure all required fields are present (id, title, description, code_patterns)
- Verify IDs are lowercase alphanumeric with hyphens only
- Check for duplicate IDs across all KB files
- Ensure code_patterns contains at least one entry

**Test failures:**
- Review test output for specific failing tests
- Run tests locally with `-v` flag for verbose output
- Ensure CGO_ENABLED=1 is set for Tree-sitter tests

**Build failures:**
- Check for compilation errors in the output
- Verify all dependencies are properly vendored
- Ensure go.mod and go.sum are up to date
