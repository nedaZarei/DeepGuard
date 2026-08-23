#!/usr/bin/env python3
"""
Snyk Code evaluation on clean-bench-v3.

Snyk Code uses ML-based SAST (not just rule matching).
This is an agentic/AI tool comparison for the paper.

Prerequisites:
  npm install -g snyk
  snyk auth          (free account at snyk.io)

Run:
  python3 scripts/snyk_evaluation.py
"""

import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT  = Path(__file__).parent.parent
BENCHMARK  = REPO_ROOT / "test-samples/js-ts-sqli-clean"
GOLDEN     = REPO_ROOT / "test-samples/js-ts-sqli-clean/expected-findings.json"
OUTPUT     = REPO_ROOT / "reports/evaluation-metrics/snyk-metrics.json"
LINE_TOLERANCE = 20


def check_snyk():
    result = subprocess.run(["snyk", "--version"], capture_output=True, text=True)
    if result.returncode != 0:
        print("ERROR: Snyk CLI not found. Install with: npm install -g snyk")
        sys.exit(1)
    print(f"Snyk: {result.stdout.strip()}")


def run_snyk_code(target: Path) -> dict:
    """Run snyk code test and return JSON output."""
    print(f"\nRunning: snyk code test {target} --json")
    result = subprocess.run(
        ["snyk", "code", "test", str(target), "--json"],
        capture_output=True, text=True
    )
    # snyk exits non-zero when vulnerabilities are found — that's expected
    if result.stdout:
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            print("WARNING: Could not parse Snyk JSON output")
            print("Output:", result.stdout[:300])
    if result.stderr:
        print("STDERR:", result.stderr[:300])
    return {}


def parse_snyk_findings(snyk_output: dict) -> list:
    """Extract findings from Snyk Code JSON output."""
    findings = []
    runs = snyk_output.get("runs", [])
    for run in runs:
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            message = result.get("message", {}).get("text", "")
            for loc in result.get("locations", []):
                uri = loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
                line = loc.get("physicalLocation", {}).get("region", {}).get("startLine", 0)
                severity = result.get("level", "warning")
                findings.append({
                    "rule_id": rule_id,
                    "file": os.path.basename(uri),
                    "line": line,
                    "severity": severity,
                    "message": message,
                    "is_sqli": "sql" in rule_id.lower() or "injection" in rule_id.lower()
                               or "sql" in message.lower(),
                })
    return findings


def evaluate(expected: list, findings: list, tolerance: int) -> dict:
    sqli = [f for f in findings if f["is_sqli"]]

    matched = set()
    tp = 0
    for exp in expected:
        for i, act in enumerate(sqli):
            if i in matched:
                continue
            if (os.path.basename(exp["file"]) == os.path.basename(act["file"])
                    and abs(exp["line"] - act["line"]) <= tolerance):
                tp += 1
                matched.add(i)
                break

    fn = len(expected) - tp
    fp = len(sqli) - tp
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec  = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1   = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0

    return {
        "tool": "Snyk Code (ML-based SAST)",
        "total_findings": len(findings),
        "sqli_findings": len(sqli),
        "type_constrained": {
            "TP": tp, "FP": fp, "FN": fn,
            "precision": round(prec, 4),
            "recall":    round(rec, 4),
            "f1":        round(f1, 4),
        },
        "rules_triggered": list({f["rule_id"] for f in findings}),
        "line_tolerance": tolerance,
    }


def main():
    check_snyk()

    with open(GOLDEN) as f:
        golden = json.load(f)
    expected = golden["expected_findings"]
    print(f"Expected findings: {len(expected)}")

    snyk_output = run_snyk_code(BENCHMARK)

    if not snyk_output:
        print("\nNo output from Snyk. Check authentication: snyk auth")
        result = {
            "tool": "Snyk Code",
            "error": "No output — run 'snyk auth' first",
            "type_constrained": {"TP": 0, "FP": 0, "FN": len(expected),
                                 "precision": 0, "recall": 0, "f1": 0},
        }
    else:
        findings = parse_snyk_findings(snyk_output)
        result = evaluate(expected, findings, LINE_TOLERANCE)

    print("\n" + "=" * 60)
    print("SNYK CODE RESULTS ON clean-bench-v3")
    print("=" * 60)
    tc = result.get("type_constrained", {})
    print(f"Total findings: {result.get('total_findings', 'N/A')}")
    print(f"SQLi findings:  {result.get('sqli_findings', 'N/A')}")
    print(f"TP: {tc.get('TP')}  FP: {tc.get('FP')}  FN: {tc.get('FN')}")
    print(f"Precision: {tc.get('precision')}  Recall: {tc.get('recall')}  F1: {tc.get('f1')}")
    if result.get("rules_triggered"):
        print(f"Rules: {result['rules_triggered']}")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nSaved to {OUTPUT}")


if __name__ == "__main__":
    main()
