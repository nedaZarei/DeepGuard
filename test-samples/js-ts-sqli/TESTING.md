# JS/TS SQLi Golden Test Documentation

## Overview

This directory contains comprehensive test samples for validating DeepGuard's JavaScript/TypeScript SQL injection detection capabilities through golden testing.

## Test Structure

### Sample Files (10 files, 724 lines)
- **express-routes.js** - 4 Express SQLi vulnerabilities
- **express-complex.js** - 6 complex Express patterns
- **prisma-service.js** - 7 Prisma raw query vulnerabilities
- **prisma-unsafe.js** - 5 advanced Prisma patterns
- **sequelize-models.js** - 5 Sequelize vulnerabilities
- **sequelize-dynamic.js** - 6 dynamic Sequelize patterns
- **typescript-express.ts** - 4 TypeScript Express vulnerabilities
- **typescript-prisma.ts** - 8 TypeScript Prisma vulnerabilities

### Golden File
- **expected-findings.json** - Documents all 45 expected SQLi vulnerabilities

## Expected Results

### Total Findings: 45 SQL Injection Vulnerabilities

**By Framework:**
- Express: 10 findings
- Prisma: 14 findings
- Sequelize: 12 findings
- TypeScript: 9 findings (additional typed variants)

**By Severity:**
- Critical: 34 vulnerabilities
- High: 11 vulnerabilities

## Golden Test Usage

### Run the Golden Test

```bash
# From project root
go test ./internal/testing/ -v -run TestJSTSSQLiGolden
```

### Expected Test Behavior

**Currently (before full scan integration):**
- Test loads golden file successfully ✅
- Reports 45 expected findings ✅
- Reports 0 actual findings (no scan run yet) ⚠️
- Lists all 45 missing findings ✅
- Test FAILS (expected until scan orchestrator is complete) ❌

**After scan integration:**
- Test will run full scan on this directory
- Compare actual findings against golden file
- Report any missing findings (false negatives)
- Report unexpected high/critical findings (false positives)
- Test PASSES if all expected findings detected ✅

### Skipping Golden Tests

For CI environments without API access:

```bash
SKIP_GOLDEN_TESTS=1 go test ./internal/testing/ -v
```

Or use short mode:

```bash
go test ./internal/testing/ -short
```

## Validation Criteria

### Matching Logic

A finding matches an expected result if:
1. **File** - Basename matches (e.g., `express-routes.js`)
2. **Type** - Exact match (e.g., `sql_injection`)
3. **Severity** - Case-insensitive match (e.g., `critical`)
4. **Line** - Within ±2 lines of expected (tolerates AST changes)

### Success Criteria

Golden test passes if:
- ✅ All 45 expected findings are detected (0 false negatives)
- ✅ All confidence scores ≥ minimum threshold
- ⚠️ Unexpected findings logged but don't fail test

## Updating Expected Findings

### When to Update

Update `expected-findings.json` when:
- Adding new vulnerability patterns to samples
- Fixing existing sample code
- Improving detection that finds new vulnerabilities
- Changing AST extraction (verify line numbers)

### How to Update

#### Option 1: Manual Update
Edit `expected-findings.json` directly to add/remove/modify expected findings.

#### Option 2: Automated Generation
```bash
# Run scan and generate new golden file
./scripts/generate_golden.sh

# Review the generated file
cat test-samples/js-ts-sqli/expected-findings.json.new

# If correct, replace current file
mv test-samples/js-ts-sqli/expected-findings.json.new \
   test-samples/js-ts-sqli/expected-findings.json
```

**Important:** Always manually review generated golden files before committing!

## Common Issues

### "metadata total_expected_findings doesn't match actual count"

The count in `scan_metadata.total_expected_findings` must match the number of objects in the `expected_findings` array.

**Fix:**
```bash
# Count findings
grep -c '"file":' test-samples/js-ts-sqli/expected-findings.json

# Update total_expected_findings to match
```

### "False negatives detected: X expected findings not detected"

This means the scan didn't find all expected vulnerabilities.

**Possible causes:**
1. Scan hasn't been run yet (no actual results)
2. Detection logic not working for this pattern
3. LLM prompt needs improvement
4. Sample code changed but golden file not updated

**Fix:**
- Verify sample code still has the vulnerability
- Check detection logic for this pattern type
- Review LLM prompts
- Re-run scan and check results

### "Confidence threshold mismatch"

Finding was detected but with lower confidence than expected.

**Fix:**
- Lower `confidence_min` in golden file if too aggressive
- Improve LLM prompts to increase confidence
- Review knowledge base entries for this pattern

## Integration with Full Scan

Once the scan orchestrator is complete, the golden test will:

1. **Discover** - Detect Express, Prisma, Sequelize frameworks
2. **Parse** - Process all .js and .ts files with tree-sitter
3. **Chunk** - Extract function-level code chunks
4. **Analyze** - Send chunks to LLM with SQLi prompts
5. **Compare** - Match findings against golden file
6. **Report** - Detailed pass/fail with missing/extra findings

## Example Test Output (After Integration)

```
=== RUN   TestJSTSSQLiGolden
    golden_test.go:30: Loaded golden file with 45 expected findings

=== Golden Test Comparison Results ===
Expected findings: 45
Actual findings:   47
Matched:           45
Missing:           0
Extra (high/crit): 2
Confidence issues: 0
Status:            PASS ✅
======================================

⚠️  Unexpected High/Critical Findings:
  1. express-complex.js:82 (sql_injection, high, 0.65 confidence)
     Message: Potential SQL injection in dynamic query
  2. sequelize-models.js:53 (sql_injection, high, 0.62 confidence)
     Message: Unsanitized input in WHERE clause

✅ All expected findings detected with sufficient confidence!
--- PASS: TestJSTSSQLiGolden (45.2s)
PASS
```

## Files Reference

| File | Purpose | Line Count |
|------|---------|------------|
| `expected-findings.json` | Golden test expectations | 473 lines |
| `express-routes.js` | Basic Express SQLi patterns | 76 lines |
| `express-complex.js` | Advanced Express patterns | 109 lines |
| `prisma-service.js` | Prisma service methods | 74 lines |
| `prisma-unsafe.js` | Advanced Prisma patterns | 76 lines |
| `sequelize-models.js` | Sequelize model queries | 87 lines |
| `sequelize-dynamic.js` | Dynamic Sequelize queries | 87 lines |
| `typescript-express.ts` | TypeScript Express routes | 117 lines |
| `typescript-prisma.ts` | TypeScript Prisma service | 132 lines |
| `package.json` | Framework dependencies | 22 lines |
| `tsconfig.json` | TypeScript configuration | 18 lines |
| `README.md` | Vulnerability documentation | 280 lines |
| `TESTING.md` | This file | - |

## Maintenance

### Pre-commit Checklist
- [ ] All sample files are syntactically valid
- [ ] Golden file count matches actual findings
- [ ] Severity breakdown is accurate
- [ ] All expected findings have clear descriptions
- [ ] Confidence thresholds are realistic (0.5-0.9)
- [ ] No false positives in expected findings

### Review Process
When updating golden files:
1. Run generation script
2. Diff against current golden file
3. Verify all new findings are legitimate
4. Check for removed findings (might indicate regression)
5. Update documentation if patterns change
6. Commit with detailed explanation
