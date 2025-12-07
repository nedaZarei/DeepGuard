# DeepGuard Golden Test Framework

This package provides golden test infrastructure for validating DeepGuard's vulnerability detection against expected results.

## Overview

Golden tests compare actual scan results against a "golden file" containing expected findings. This ensures:
- No false negatives (all expected vulnerabilities are detected)
- Confidence thresholds are met
- Detection remains stable across code changes

## Components

### `golden_comparator.go`
Core comparison logic that:
- Loads golden files with expected findings
- Compares actual scan results against expectations
- Handles fuzzy line matching (±2 lines tolerance for AST changes)
- Reports missing findings, confidence mismatches, and unexpected high-severity results

### `golden_test.go`
Test harness that:
- Loads golden file from `test-samples/js-ts-sqli/expected-findings.json`
- Runs DeepGuard scan (or loads existing results)
- Compares results and reports failures

## Running Golden Tests

### Run all golden tests
```bash
go test ./internal/testing/ -v
```

### Skip golden tests (for CI without API key)
```bash
SKIP_GOLDEN_TESTS=1 go test ./internal/testing/ -v
```

### Run in short mode (skips golden tests)
```bash
go test ./internal/testing/ -short
```

## Golden File Format

Golden files are JSON documents in this format:

```json
{
  "description": "Golden test file for JS/TS SQL injection detection",
  "scan_metadata": {
    "target_path": "test-samples/js-ts-sqli/",
    "vulnerability_type": "sql_injection",
    "confidence_threshold": 0.5,
    "total_expected_findings": 42
  },
  "expected_findings": [
    {
      "file": "express-routes.js",
      "line": 19,
      "type": "sql_injection",
      "severity": "critical",
      "confidence_min": 0.7,
      "pattern": "req.query concatenation",
      "description": "Direct concatenation of req.query.id into SELECT query",
      "code_pattern": "query = 'SELECT * FROM users WHERE id = ' + userId"
    }
  ]
}
```

## Updating Golden Files

When expected results change (e.g., after improving detection), regenerate golden files:

```bash
./scripts/generate_golden.sh
```

This will:
1. Build DeepGuard
2. Run scan on test samples
3. Generate new golden file at `test-samples/js-ts-sqli/expected-findings.json.new`
4. Prompt for manual review

**Important**: Always manually review new golden files before committing!

## Comparison Rules

### Matching Logic
A finding matches an expected result if:
- **File name** matches (basename comparison, handles path differences)
- **Type** matches exactly (e.g., `sql_injection`)
- **Severity** matches (case-insensitive)
- **Line number** is within ±2 lines (tolerance for AST changes)

### Success Criteria
Test passes if:
- ✅ All expected findings are detected (no false negatives)
- ✅ All confidence scores meet minimum thresholds
- ⚠️ Unexpected high/critical findings logged as warnings (not failures)

## Example Output

```
=== Golden Test Comparison Results ===
Expected findings: 42
Actual findings:   45
Matched:           42
Missing:           0
Extra (high/crit): 3
Confidence issues: 0
Status:            PASS ✅
======================================

⚠️  Unexpected High/Critical Findings:
  1. express-routes.js:55 (sql_injection, high, 0.75 confidence)
     Message: Potential SQL injection in ORDER BY clause

✅ All expected findings detected with sufficient confidence!
```

## Integration with CI

Add to `.github/workflows/ci.yml`:

```yaml
- name: Run Golden Tests
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
  run: go test ./internal/testing/ -v -timeout 10m
```

For CI without API access, skip golden tests:
```yaml
- name: Run Unit Tests
  run: SKIP_GOLDEN_TESTS=1 go test ./internal/testing/ -v
```

## Maintenance

### When to Update Golden Files
- After adding new vulnerability patterns
- After improving detection accuracy
- After fixing false negatives
- After changing AST extraction logic

### Review Checklist
Before committing updated golden files:
- [ ] All findings are legitimate vulnerabilities
- [ ] No false positives in expected results
- [ ] Confidence thresholds are realistic (0.5-0.9 range)
- [ ] Severity levels match OWASP standards
- [ ] Pattern descriptions are clear and accurate

## Troubleshooting

### "Missing expected finding"
- Verify the vulnerability still exists in sample code
- Check if line numbers changed (should be within ±2)
- Confirm detection logic is working correctly
- Review LLM prompts for the vulnerability type

### "Confidence threshold mismatch"
- Check if confidence_min in golden file is too high
- Review LLM responses for this finding
- Consider adjusting threshold if consistently below expected

### "Unexpected high/critical finding"
- Review if it's a legitimate vulnerability not in golden file
- Check if it's a false positive (improve detection)
- Add to golden file if legitimate
