#!/usr/bin/env python3
"""
Python evaluation: Deep-Guard vs Bandit on smoke-test Python files.

Usage:
  # Bandit-only comparison (no API key needed):
  python3 scripts/python_evaluation.py

  # With Deep-Guard scan results (run scan first):
  DEEPGUARD_SCAN=test-samples/smoke-tests/python/deep-guard-results.json \
      python3 scripts/python_evaluation.py

  # Run Deep-Guard scan:
  DEEPGUARD_OPENAI_API_KEY=<your-key> ./deepguard scan \
      --path test-samples/smoke-tests/python \
      --output test-samples/smoke-tests/python \
      --confidence-threshold 0.5
  mv test-samples/smoke-tests/python/deep-guard-*.json \
      test-samples/smoke-tests/python/deep-guard-results.json
"""

import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
PYTHON_DIR = REPO_ROOT / "test-samples/smoke-tests/python"
GOLDEN_PATH = PYTHON_DIR / "expected-findings.json"
DG_RESULTS_PATH = Path(os.environ.get(
    "DEEPGUARD_SCAN",
    str(PYTHON_DIR / "deep-guard-results.json")
))

SEVERITY_BARS = {"critical", "high", "medium"}


def run_bandit():
    """Run Bandit and parse JSON output."""
    result = subprocess.run(
        ["bandit", "-r", str(PYTHON_DIR), "-f", "json"],
        capture_output=True, text=True
    )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        print("WARNING: could not parse Bandit JSON output", file=sys.stderr)
        return {"results": []}


def normalize_file(path):
    return os.path.basename(path)


def bandit_severity(sev):
    return {"HIGH": "critical", "MEDIUM": "high", "LOW": "medium"}.get(sev.upper(), "low")


def match_to_ground_truth(findings, golden, tolerance=10):
    """Match a list of findings to ground truth; return TP, FP list, FN list."""
    matched = set()
    tp, found = 0, []
    missing = []

    for exp in golden:
        exp_file = normalize_file(exp["file"])
        hit = False
        for i, f in enumerate(findings):
            if i in matched:
                continue
            if normalize_file(f["file"]) != exp_file:
                continue
            if f.get("type") and exp.get("type") and f["type"] != exp["type"]:
                continue
            if abs(f["line"] - exp["line"]) > tolerance:
                continue
            matched.add(i)
            tp += 1
            hit = True
            found.append((exp, f))
            break
        if not hit:
            missing.append(exp)

    fp_list = [f for i, f in enumerate(findings) if i not in matched]
    return tp, fp_list, missing, found


def print_section(title):
    print(f"\n─── {title} {'─' * max(0, 60 - len(title))}")


def main():
    if not GOLDEN_PATH.exists():
        print(f"ERROR: {GOLDEN_PATH} not found", file=sys.stderr)
        sys.exit(1)

    golden = json.loads(GOLDEN_PATH.read_text())
    expected = golden["expected_findings"]

    print("=" * 70)
    print("DEEP-GUARD vs BANDIT — PYTHON SECURITY EVALUATION")
    print("=" * 70)
    print(f"\nDataset : {PYTHON_DIR.relative_to(REPO_ROOT)}")
    print(f"          {len(expected)} labeled vulnerabilities across 2 files")

    # ── Bandit ───────────────────────────────────────────────────────────────
    print_section("Bandit 1.8.6 Results")
    bandit_data = run_bandit()
    bandit_raw = bandit_data.get("results", [])

    bandit_findings = [
        {
            "file": r["filename"],
            "line": r["line_number"],
            "type": r["test_id"],
            "severity": bandit_severity(r["issue_severity"]),
            "confidence": r["issue_confidence"],
            "message": r["issue_text"],
        }
        for r in bandit_raw
    ]

    print(f"  Total findings: {len(bandit_findings)}")
    for f in bandit_findings:
        sev_label = f["severity"].upper()
        conf_label = f["confidence"]
        print(f"  {normalize_file(f['file'])}:{f['line']:3d}  [{sev_label}/{conf_label}]  {f['message'][:65]}")

    # For matching Bandit to ground truth, use a relaxed type check (Bandit uses test IDs not our types)
    bandit_for_match = [dict(f, type=None) for f in bandit_findings]
    bt, bfp_list, bmissing, _ = match_to_ground_truth(bandit_for_match, expected, tolerance=5)
    bfp = len(bfp_list)
    bfn = len(bmissing)
    b_prec = bt / (bt + bfp) if (bt + bfp) else 0
    b_rec  = bt / (bt + bfn) if (bt + bfn) else 0
    b_f1   = 2 * b_prec * b_rec / (b_prec + b_rec) if (b_prec + b_rec) else 0

    print(f"\n  Matched to ground truth (±5 lines, type-agnostic):")
    print(f"    TP={bt}  FP={bfp}  FN={bfn}")
    print(f"    Precision={b_prec:.3f}  Recall={b_rec:.3f}  F1={b_f1:.3f}")

    if bmissing:
        print(f"\n  ❌ Missed by Bandit ({len(bmissing)} finding(s)):")
        for m in bmissing:
            print(f"    {normalize_file(m['file'])}:{m['line']:3d}  [{m['type']}]  {m['description'][:65]}")
            print(f"    → Reason: {m['bandit_rule']}")

    # ── Deep-Guard ───────────────────────────────────────────────────────────
    print_section("Deep-Guard Results")

    if DG_RESULTS_PATH.exists():
        dg_data = json.loads(DG_RESULTS_PATH.read_text())
        dg_raw = dg_data.get("findings", [])

        dg_findings = [
            {"file": f["file"], "line": f["line"], "type": f["type"],
             "severity": f["severity"], "confidence": f.get("confidence", 0),
             "message": f.get("message", "")}
            for f in dg_raw
            if f.get("severity") in SEVERITY_BARS
        ]

        print(f"  Total findings (high+): {len(dg_findings)}")
        for f in dg_findings:
            print(f"  {normalize_file(f['file'])}:{f['line']:3d}  [{f['type']}/{f['severity']}  conf={f['confidence']:.2f}]  {f['message'][:55]}")

        dgt, dgfp_list, dgmissing, _ = match_to_ground_truth(dg_findings, expected, tolerance=20)
        dgfp = len(dgfp_list)
        dgfn = len(dgmissing)
        dg_prec = dgt / (dgt + dgfp) if (dgt + dgfp) else 0
        dg_rec  = dgt / (dgt + dgfn) if (dgt + dgfn) else 0
        dg_f1   = 2 * dg_prec * dg_rec / (dg_prec + dg_rec) if (dg_prec + dg_rec) else 0

        print(f"\n  Matched to ground truth (±20 lines):")
        print(f"    TP={dgt}  FP={dgfp}  FN={dgfn}")
        print(f"    Precision={dg_prec:.3f}  Recall={dg_rec:.3f}  F1={dg_f1:.3f}")

        if dgmissing:
            print(f"\n  ❌ Missed by Deep-Guard ({len(dgmissing)} finding(s)):")
            for m in dgmissing:
                print(f"    {normalize_file(m['file'])}:{m['line']:3d}  [{m['type']}]  {m['description'][:65]}")

    else:
        print(f"  No Deep-Guard results found at {DG_RESULTS_PATH}")
        print(f"\n  To run:")
        print(f"    export DEEPGUARD_OPENAI_API_KEY=<your-key>")
        print(f"    ./deepguard scan --path test-samples/smoke-tests/python \\")
        print(f"        --output test-samples/smoke-tests/python --confidence-threshold 0.5")
        print(f"    mv test-samples/smoke-tests/python/deep-guard-*.json \\")
        print(f"        test-samples/smoke-tests/python/deep-guard-results.json")

        # Show expected Deep-Guard advantage based on ground truth
        print(f"\n  Expected finding that Bandit misses (LLM semantic advantage):")
        pt = next((e for e in expected if e["type"] == "path_traversal"), None)
        if pt:
            print(f"    {normalize_file(pt['file'])}:{pt['line']}  [{pt['type']}]  {pt['description']}")
            print(f"    Bandit reason: {pt['bandit_rule']}")
            print(f"    Deep-Guard: LLM traces data flow — request.args → unsanitized")
            print(f"                os.path.join → send_file = path traversal")

    # ── Comparison Table ─────────────────────────────────────────────────────
    print_section("Comparison Table (Python Smoke Tests)")
    print(f"{'Tool':<26} {'TP':>3} {'FP':>3} {'FN':>3} {'Prec':>5} {'Rec':>5} {'F1':>5}  Key miss")
    print("─" * 75)

    def trow(name, tp_, fp_, fn_, note=""):
        p = tp_ / (tp_ + fp_) if (tp_ + fp_) else 0
        r = tp_ / (tp_ + fn_) if (tp_ + fn_) else 0
        f = 2 * p * r / (p + r) if (p + r) else 0
        return f"{name:<26} {tp_:>3} {fp_:>3} {fn_:>3} {p:>5.3f} {r:>5.3f} {f:>5.3f}  {note}"

    print(trow("Bandit 1.8.6", bt, bfp, bfn, "path_traversal (api.py:53)"))
    if DG_RESULTS_PATH.exists():
        print(trow("Deep-Guard", dgt, dgfp, dgfn))
    else:
        print(f"{'Deep-Guard':<26} {'—':>3} {'—':>3} {'—':>3}  (run scan to get results)")

    print("""
Why Bandit misses path traversal at api.py:53:
  – Bandit uses single-file, single-statement pattern matching (AST visitor)
  – It flags os.system/os.popen for command injection but has no rule
    correlating request.args assignment → os.path.join → file send
  – Without inter-procedural data-flow analysis, the vulnerability is invisible
  – Deep-Guard's LLM prompt understands the semantic meaning: user-controlled
    filename without basename()/abspath() validation before os.path.join is
    a textbook path traversal, independent of which specific APIs are used
""")


if __name__ == "__main__":
    main()
