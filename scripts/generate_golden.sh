#!/bin/bash
# Script to generate golden test file from actual DeepGuard scan results
# This should be run manually when updating expected findings

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SAMPLES_DIR="$PROJECT_ROOT/test-samples/js-ts-sqli"
GOLDEN_FILE="$SAMPLES_DIR/expected-findings.json"
TEMP_GOLDEN="$SAMPLES_DIR/expected-findings.json.new"

echo "=== DeepGuard Golden File Generator ==="
echo ""
echo "This script generates a golden test file from actual scan results."
echo "WARNING: This will create a NEW golden file that must be manually reviewed!"
echo ""
echo "Project root: $PROJECT_ROOT"
echo "Samples dir:  $SAMPLES_DIR"
echo "Golden file:  $GOLDEN_FILE"
echo ""

# Check if samples directory exists
if [ ! -d "$SAMPLES_DIR" ]; then
    echo "❌ Error: Test samples directory not found: $SAMPLES_DIR"
    exit 1
fi

# Build DeepGuard binary
echo "📦 Building DeepGuard..."
cd "$PROJECT_ROOT"
if ! CGO_ENABLED=1 go build -o deepguard ./cmd/deepguard; then
    echo "❌ Error: Failed to build DeepGuard"
    exit 1
fi
echo "✅ Build successful"
echo ""

# Run scan on test samples
echo "🔍 Running scan on test samples..."
SCAN_OUTPUT="$PROJECT_ROOT/reports/scan-$(date +%Y%m%d-%H%M%S).json"

# Set environment variables for scan
export DEEPGUARD_OUTPUT_DIR="$PROJECT_ROOT/reports"
export DEEPGUARD_VERBOSE=true

if ! ./deepguard scan --path "$SAMPLES_DIR" --languages javascript,typescript; then
    echo "❌ Error: Scan failed"
    exit 1
fi

# Find the most recent scan report
LATEST_REPORT=$(ls -t "$PROJECT_ROOT/reports"/scan-*.json 2>/dev/null | head -1)

if [ -z "$LATEST_REPORT" ]; then
    echo "❌ Error: No scan report found in $PROJECT_ROOT/reports/"
    exit 1
fi

echo "✅ Scan complete: $LATEST_REPORT"
echo ""

# Transform scan report to golden file format
echo "🔄 Transforming scan results to golden format..."

# Use jq to transform the report (if available)
if command -v jq &> /dev/null; then
    cat "$LATEST_REPORT" | jq '{
        description: "Golden test file for JS/TS SQL injection detection",
        scan_metadata: {
            target_path: "test-samples/js-ts-sqli/",
            vulnerability_type: "sql_injection",
            confidence_threshold: 0.5,
            total_expected_findings: (.findings | length)
        },
        expected_findings: [
            .findings[] | {
                file: (.file | split("/") | last),
                line: .line,
                type: .type,
                severity: .severity,
                confidence_min: (.confidence - 0.1),
                pattern: "auto-generated",
                description: .message,
                code_pattern: .code_snippet
            }
        ],
        severity_breakdown: .summary.by_severity,
        framework_breakdown: {
            express: 0,
            prisma: 0,
            sequelize: 0,
            typescript: 0
        }
    }' > "$TEMP_GOLDEN"

    echo "✅ Transformation complete"
else
    echo "⚠️  Warning: jq not found, using raw scan output"
    cp "$LATEST_REPORT" "$TEMP_GOLDEN"
fi

echo ""
echo "=== Manual Review Required ==="
echo ""
echo "A new golden file has been generated at:"
echo "  $TEMP_GOLDEN"
echo ""
echo "Please review the file and verify:"
echo "  1. All expected vulnerabilities are included"
echo "  2. No false positives in the findings"
echo "  3. Confidence thresholds are appropriate"
echo "  4. Severity levels are correct"
echo "  5. Pattern descriptions are meaningful"
echo ""
echo "To replace the current golden file, run:"
echo "  mv \"$TEMP_GOLDEN\" \"$GOLDEN_FILE\""
echo ""
echo "Or to compare with current golden file:"
echo "  diff \"$GOLDEN_FILE\" \"$TEMP_GOLDEN\""
echo ""
echo "✅ Generation complete"
