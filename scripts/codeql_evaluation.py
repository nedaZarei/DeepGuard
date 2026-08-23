#!/usr/bin/env python3
"""
CodeQL evaluation on clean-bench-v3.

Steps:
1. Create a CodeQL database from the benchmark JS/TS files
2. Run the JS/TS SQL injection query pack
3. Parse the SARIF output
4. Compare against expected-findings.json with ±20 line tolerance
5. Write results to reports/evaluation-metrics/codeql-metrics.json

Prerequisites:
  brew install codeql
  codeql pack download codeql/javascript-queries

Run:
  python3 scripts/codeql_evaluation.py
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT  = Path(__file__).parent.parent
BENCHMARK  = REPO_ROOT / "test-samples/js-ts-sqli-clean"
GOLDEN     = REPO_ROOT / "test-samples/js-ts-sqli-clean/expected-findings.json"
OUTPUT     = REPO_ROOT / "reports/evaluation-metrics/codeql-metrics.json"
LINE_TOLERANCE = 20


def run(cmd: list, cwd=None, check=True) -> subprocess.CompletedProcess:
    print(f"  $ {' '.join(str(c) for c in cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    if result.stdout:
        print(result.stdout[:500])
    if result.returncode != 0:
        print("STDERR:", result.stderr[:500])
        if check:
            raise RuntimeError(f"Command failed: {' '.join(str(c) for c in cmd)}")
    return result


def check_codeql():
    result = subprocess.run(["codeql", "version"], capture_output=True, text=True)
    if result.returncode != 0:
        print("ERROR: CodeQL CLI not found. Install with: brew install codeql")
        sys.exit(1)
    version = result.stdout.strip().split("\n")[0]
    print(f"CodeQL: {version}")
    return True


def create_database(db_path: Path, source_root: Path) -> bool:
    """Create a CodeQL JavaScript database from the benchmark directory."""
    if db_path.exists():
        import shutil
        shutil.rmtree(db_path)

    print(f"\n[1/3] Creating CodeQL database at {db_path}...")
    result = run([
        "codeql", "database", "create",
        str(db_path),
        "--language=javascript",
        f"--source-root={source_root}",
        "--overwrite",
    ], check=False)
    return result.returncode == 0


def run_queries(db_path: Path, sarif_out: Path) -> bool:
    """Run the built-in JS security-and-quality query suite."""
    print(f"\n[2/3] Running CodeQL SQL injection queries...")
    # Use the built-in security queries for JS/TS
    result = run([
        "codeql", "database", "analyze",
        str(db_path),
        "javascript-security-and-quality",     # built-in suite
        "--format=sarifv2.1.0",
        f"--output={sarif_out}",
        "--rerun",
    ], check=False)

    if result.returncode != 0:
        # Fall back to just the sql-injection query
        print("  Trying sql-injection query directly...")
        result = run([
            "codeql", "database", "analyze",
            str(db_path),
            "codeql/javascript-queries:Security/CWE-089",
            "--format=sarifv2.1.0",
            f"--output={sarif_out}",
            "--rerun",
        ], check=False)

    return result.returncode == 0


def parse_sarif(sarif_path: Path) -> list:
    """Extract findings from SARIF output."""
    with open(sarif_path) as f:
        sarif = json.load(f)

    findings = []
    for run_entry in sarif.get("runs", []):
        rules = {r["id"]: r for r in run_entry.get("tool", {}).get("driver", {}).get("rules", [])}
        for result in run_entry.get("results", []):
            rule_id = result.get("ruleId", "")
            # Filter to SQL injection rules
            sqli_keywords = ["sql", "injection", "CWE-089", "SqlInjection"]
            is_sqli = any(k.lower() in rule_id.lower() for k in sqli_keywords)

            for loc in result.get("locations", []):
                uri = loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
                line = loc.get("physicalLocation", {}).get("region", {}).get("startLine", 0)
                findings.append({
                    "rule_id": rule_id,
                    "file": os.path.basename(uri),
                    "line": line,
                    "is_sqli": is_sqli,
                    "message": result.get("message", {}).get("text", ""),
                })

    return findings


def evaluate(expected: list, actual_findings: list, tolerance: int) -> dict:
    """Compare CodeQL findings against golden file."""
    sqli_findings = [f for f in actual_findings if f["is_sqli"]]
    all_findings  = actual_findings

    matched = set()
    tp = 0
    for exp in expected:
        for i, act in enumerate(sqli_findings):
            if i in matched:
                continue
            if (os.path.basename(exp["file"]) == os.path.basename(act["file"])
                    and abs(exp["line"] - act["line"]) <= tolerance):
                tp += 1
                matched.add(i)
                break

    fn = len(expected) - tp
    fp = len(sqli_findings) - tp
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec  = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1   = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0

    return {
        "tool": "CodeQL (javascript-security-and-quality)",
        "total_findings": len(all_findings),
        "sqli_findings": len(sqli_findings),
        "type_constrained": {
            "TP": tp, "FP": fp, "FN": fn,
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
        },
        "all_rules_found": list({f["rule_id"] for f in all_findings}),
        "sqli_rules_found": list({f["rule_id"] for f in sqli_findings}),
        "line_tolerance": tolerance,
    }


def main():
    check_codeql()

    with open(GOLDEN) as f:
        golden = json.load(f)
    expected = golden["expected_findings"]
    print(f"Expected findings: {len(expected)}")

    with tempfile.TemporaryDirectory() as tmp:
        db_path   = Path(tmp) / "codeql-db"
        sarif_out = Path(tmp) / "results.sarif"

        db_ok = create_database(db_path, BENCHMARK)
        if not db_ok:
            print("ERROR: Database creation failed. Check CodeQL installation.")
            sys.exit(1)

        qr_ok = run_queries(db_path, sarif_out)
        if not qr_ok or not sarif_out.exists():
            # Still write a result showing 0 findings with error note
            print("WARNING: Query run failed or produced no output.")
            result = {
                "tool": "CodeQL",
                "error": "Query execution failed — see logs",
                "type_constrained": {"TP": 0, "FP": 0, "FN": len(expected),
                                     "precision": 0, "recall": 0, "f1": 0},
            }
        else:
            print(f"\n[3/3] Parsing SARIF results from {sarif_out}...")
            findings = parse_sarif(sarif_out)
            result = evaluate(expected, findings, LINE_TOLERANCE)

    # Print summary
    print("\n" + "=" * 60)
    print("CODEQL RESULTS ON clean-bench-v3")
    print("=" * 60)
    tc = result.get("type_constrained", {})
    print(f"Total findings:      {result.get('total_findings', 'N/A')}")
    print(f"SQLi findings:       {result.get('sqli_findings', 'N/A')}")
    print(f"TP: {tc.get('TP')}  FP: {tc.get('FP')}  FN: {tc.get('FN')}")
    print(f"Precision: {tc.get('precision')}  Recall: {tc.get('recall')}  F1: {tc.get('f1')}")
    if result.get("sqli_rules_found"):
        print(f"SQLi rules triggered: {result['sqli_rules_found']}")
    else:
        print("SQLi rules triggered: none")

    print("\n--- COMPARISON TABLE ---")
    print(f"{'Tool':<35} {'F1':>6}  {'Recall':>7}  {'Precision':>10}")
    print("-" * 65)
    comparison = [
        ("SonarQube Community",     0.000, 0.000, 0.000),
        ("Semgrep p/sql-injection",  0.000, 0.000, 0.000),
        ("CodeQL",                   tc.get('f1', 0), tc.get('recall', 0), tc.get('precision', 0)),
        ("DeepGuard (type-constr.)", 0.866, 1.000, 0.764),
        ("Zero-shot GPT-4o",         0.866, 1.000, 0.764),
    ]
    for name, f1, rec, prec in comparison:
        print(f"  {name:<33} {f1:>6.3f}  {rec:>7.3f}  {prec:>10.3f}")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nSaved to {OUTPUT}")


if __name__ == "__main__":
    main()
